// The preview pane, through `entry.read` (docs/M3.md §5.3): text (the first 64 KiB, then
// more), hex, or an image up to 16 MiB. The type comes from the extension, then the bytes.
import { FileQuestion } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import type { CmdError, EntryInfo } from "../../gen/commands";
import { type Tab, useArchives } from "../../lib/archives";
import {
  base64ToBytes,
  baseName,
  describeError,
  formatSize,
  formatTime,
  imageMime,
  looksLikeText,
  previewKind,
  sniffImage,
} from "../../lib/format";
import { useJobs } from "../../lib/jobs";

export const TEXT_CHUNK = 64 * 1024;
export const IMAGE_MAX = 16 * 1024 * 1024;

type Shown =
  | { kind: "loading" }
  | { kind: "text"; text: string; next?: number; lossy: boolean }
  | { kind: "hex"; bytes: Uint8Array; more: boolean }
  | { kind: "image"; src: string }
  | { kind: "too-big" }
  | { kind: "error"; error: CmdError };

/** Rows of 16 bytes: offset, hex, and the printable characters. */
export function hexLines(bytes: Uint8Array, start = 0): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.subarray(i, i + 16);
    const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${(start + i).toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join("\n");
}

function read(tab: Tab, entry: EntryInfo, args: { offset?: number; max_bytes: number; encoding: "text" | "hex" | "base64" }) {
  const password = useArchives.getState().tabs.find((t) => t.id === tab.id)?.password;
  return useJobs.getState().track(
    "entry.read",
    { archive: tab.path, index: entry.id ?? undefined, ...args, ...(password ? { password } : {}) },
    { title: `Reading ${baseName(entry.path)}`, quiet: true, tab: tab.id },
  );
}

function Body({ tab, entry }: { tab: Tab; entry: EntryInfo }) {
  const [shown, setShown] = useState<Shown>({ kind: "loading" });

  useEffect(() => {
    let live = true;
    const show = (s: Shown) => live && setShown(s);
    setShown({ kind: "loading" });
    const kind = previewKind(entry.path);
    const fail = (error: CmdError) => show({ kind: "error", error });
    if (kind === "image") {
      if ((entry.size ?? 0) > IMAGE_MAX) {
        show({ kind: "too-big" });
      } else {
        read(tab, entry, { max_bytes: IMAGE_MAX, encoding: "base64" }).then(
          (out) => show({ kind: "image", src: `data:${imageMime(entry.path)};base64,${out.data}` }),
          fail,
        );
      }
    } else if (kind === "text") {
      read(tab, entry, { max_bytes: TEXT_CHUNK, encoding: "text" }).then(
        (out) => show({ kind: "text", text: out.data, lossy: out.lossy, next: out.eof ? undefined : out.offset + out.bytes_read }),
        fail,
      );
    } else {
      // Unknown extension: one read, then decide from the bytes.
      read(tab, entry, { max_bytes: TEXT_CHUNK, encoding: "base64" }).then((out) => {
        const bytes = base64ToBytes(out.data);
        const mime = sniffImage(bytes);
        if (mime && out.eof) {
          show({ kind: "image", src: `data:${mime};base64,${out.data}` });
        } else if (mime && (entry.size ?? 0) <= IMAGE_MAX) {
          read(tab, entry, { max_bytes: IMAGE_MAX, encoding: "base64" }).then(
            (full) => show({ kind: "image", src: `data:${mime};base64,${full.data}` }),
            fail,
          );
        } else if (bytes.length > 0 && looksLikeText(bytes)) {
          const text = new TextDecoder().decode(bytes);
          show({ kind: "text", text, lossy: false, next: out.eof ? undefined : out.bytes_read });
        } else {
          show({ kind: "hex", bytes, more: !out.eof });
        }
      }, fail);
    }
    return () => {
      live = false;
    };
  }, [tab.id, tab.path, entry]);

  const more = (offset: number) => {
    read(tab, entry, { offset, max_bytes: TEXT_CHUNK, encoding: "text" }).then(
      (out) =>
        setShown((s) =>
          s.kind === "text"
            ? { kind: "text", text: s.text + out.data, lossy: s.lossy || out.lossy, next: out.eof ? undefined : out.offset + out.bytes_read }
            : s,
        ),
      (error: CmdError) => setShown({ kind: "error", error }),
    );
  };

  switch (shown.kind) {
    case "loading":
      return <p className="p-3 text-muted">Reading…</p>;
    case "too-big":
      return <p className="p-3 text-muted">This image is over 16 MiB, too large to preview. Extract it to open it.</p>;
    case "error": {
      const { code, message } = describeError(shown.error);
      return code === "Cancelled" ? (
        <p className="p-3 text-muted">The preview was cancelled.</p>
      ) : (
        <p className="selectable p-3 text-danger">
          {code}: {message}
        </p>
      );
    }
    case "image":
      return (
        <div className="flex min-h-0 flex-1 items-center justify-center overflow-auto bg-sunken p-3">
          <img src={shown.src} alt={baseName(entry.path)} className="max-h-full max-w-full object-contain" />
        </div>
      );
    case "hex":
      return (
        <div className="min-h-0 flex-1 overflow-auto">
          <pre className="selectable p-3 font-mono text-[11.5px] leading-[1.5]">{hexLines(shown.bytes)}</pre>
          {shown.more && <p className="px-3 pb-3 text-muted">Showing the first 64 KiB.</p>}
        </div>
      );
    case "text":
      return (
        <div className="min-h-0 flex-1 overflow-auto">
          <pre className="selectable p-3 font-mono text-[12px] leading-[1.55] break-words whitespace-pre-wrap">{shown.text}</pre>
          {shown.lossy && <p className="px-3 text-muted">Some bytes weren't UTF-8 and show as �.</p>}
          {shown.next !== undefined && (
            <div className="px-3 pb-3">
              <Button size="sm" onClick={() => more(shown.next as number)}>
                Load more
              </Button>
            </div>
          )}
        </div>
      );
  }
}

export function Preview({ tab }: { tab: Tab }) {
  const update = useArchives((s) => s.update);
  const entry = tab.preview;
  if (!entry || entry.kind === "dir") {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center text-muted">
        <FileQuestion className="size-6" />
        <p>Select a file to preview it.</p>
      </div>
    );
  }
  const header = (
    <div className="border-b border-rule px-3 py-2">
      <p className="truncate font-semibold" title={entry.path}>
        {baseName(entry.path)}
      </p>
      <p className="tabular text-[12px] text-muted">
        {[formatSize(entry.size), entry.method, formatTime(entry.modified)].filter(Boolean).join(", ")}
      </p>
    </div>
  );
  const solid = tab.info?.solid && tab.info.format !== "stream";
  return (
    <div className="flex h-full min-h-0 flex-col">
      {header}
      {solid && !tab.solidOk ? (
        <div className="flex flex-col gap-3 p-3">
          <p className="text-muted">
            This archive is solid: previewing a file decodes everything stored before it in its block, which can take a
            while.
          </p>
          <div>
            <Button size="sm" onClick={() => update(tab.id, { solidOk: true })}>
              Preview files
            </Button>
          </div>
        </div>
      ) : (
        <Body tab={tab} entry={entry} />
      )}
    </div>
  );
}
