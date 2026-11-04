// `formats.list`, fetched once: the Open dialog's filter, the create dialog's choices and the
// About page all read it.
import { useEffect, useState } from "react";
import type { FormatsListOutput, LevelRange } from "../gen/commands";
import { run } from "./engine";

let cached: Promise<FormatsListOutput> | undefined;

export function loadFormats(): Promise<FormatsListOutput> {
  cached ??= run("formats.list", {}).catch((e) => {
    cached = undefined;
    throw e;
  });
  return cached;
}

export function useFormats(): FormatsListOutput | undefined {
  const [formats, setFormats] = useState<FormatsListOutput>();
  useEffect(() => {
    let live = true;
    loadFormats().then(
      (f) => live && setFormats(f),
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);
  return formats;
}

/** Every extension BeeZip reads, for the Open dialog: `zip`, `7z`, `rar`, `tgz`, `001`… */
export function readableExtensions(f: FormatsListOutput): string[] {
  const all = new Set<string>(["001"]);
  for (const format of f.formats) if (format.caps.list) for (const e of format.extensions) all.add(e.replace(/^\./, ""));
  for (const codec of f.codecs) for (const e of codec.extensions) all.add(e.replace(/^\./, ""));
  return [...all].sort();
}

/** The codec a `tar.*` format compresses with: `tar.zst` → zstd's entry. */
export function codecOfTar(f: FormatsListOutput, format: string) {
  if (!format.startsWith("tar.")) return undefined;
  const ext = format.slice(4);
  return f.codecs.find((c) => c.extensions.some((e) => e.replace(/^\./, "") === ext));
}

/** The methods a format takes, and the level range of each. */
export function methodsOf(f: FormatsListOutput, format: string): { id: string; levels: LevelRange | null }[] {
  return f.formats.find((x) => x.id === format)?.methods ?? [];
}
