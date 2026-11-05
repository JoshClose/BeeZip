// How the page shows sizes, times and names, and how it guesses an entry's preview.
import type { CmdError } from "../gen/commands";

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

/** `1.5 MiB`, as the CLI writes it. */
export function formatSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "";
  let v = bytes;
  let unit = 0;
  while (v >= 1024 && unit < UNITS.length - 1) {
    v /= 1024;
    unit++;
  }
  if (unit === 0) return `${bytes} B`;
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${UNITS[unit]}`;
}

/** An RFC 3339 time in local time: `2026-11-03 14:05`. */
export function formatTime(rfc3339: string | null | undefined): string {
  if (!rfc3339) return "";
  const d = new Date(rfc3339);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function formatRate(bytesPerSecond: number | undefined): string {
  if (!bytesPerSecond || bytesPerSecond <= 0) return "";
  return `${formatSize(Math.round(bytesPerSecond))}/s`;
}

/** A rough time left: `8 s`, `3 min`, `1 h 5 min`. Empty when there's no sensible answer. */
export function formatDuration(seconds: number | undefined): string {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return "";
  const s = Math.max(1, Math.ceil(seconds));
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

export function formatCrc(crc: number | null | undefined): string {
  return crc === null || crc === undefined ? "" : crc.toString(16).padStart(8, "0");
}

/** The last part of a `/` or `\` path. */
export function baseName(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  const i = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  return i < 0 ? trimmed : trimmed.slice(i + 1);
}

/** The folder holding a file path, with Windows separators kept. */
export function parentDir(path: string): string {
  const i = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return i <= 0 ? path : path.slice(0, i);
}

/** Joins a folder and a name with the folder's own separator. */
export function joinPath(dir: string, name: string): string {
  if (!dir) return name;
  const sep = dir.includes("\\") || !dir.includes("/") ? "\\" : "/";
  return dir.endsWith("\\") || dir.endsWith("/") ? dir + name : dir + sep + name;
}

/** Whether two Windows paths name the same file: case and separators aside. */
export function samePath(a: string, b: string): boolean {
  const n = (p: string) => p.replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
  return n(a) === n(b);
}

/** An archive path's parent inside the archive: `a/b/c` → `a/b`, `a` → ``. */
export function archiveParent(path: string): string {
  const p = path.replace(/\/+$/, "");
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i);
}

/** An archive path as the engine normalises it: no `./`, no leading or trailing `/`. */
export function normalize(path: string): string {
  let p = path.replace(/\\/g, "/");
  for (;;) {
    if (p.startsWith("./")) p = p.slice(2);
    else if (p.startsWith("/")) p = p.slice(1);
    else break;
  }
  return p.replace(/\/+$/, "");
}

export function extension(name: string): string {
  const base = baseName(name).toLowerCase();
  const i = base.lastIndexOf(".");
  return i <= 0 ? "" : base.slice(i + 1);
}

const IMAGES: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  bmp: "image/bmp",
  ico: "image/x-icon",
  svg: "image/svg+xml",
};

const TEXT = new Set(
  (
    "txt md markdown rst log csv tsv json jsonc json5 xml html htm css scss less js mjs cjs ts tsx " +
    "jsx rs go py rb pl php java kt c h cc cpp hpp cs fs swift sh bash zsh fish ps1 psm1 bat cmd " +
    "toml yaml yml ini cfg conf properties env gitignore gitattributes editorconfig sql lua r " +
    "tex bib srt vtt nfo diz license readme makefile cmake gradle lock"
  ).split(" "),
);

export type PreviewKind = "image" | "text" | "sniff";

/** What the extension says an entry is; `sniff` means look at its first bytes. */
export function previewKind(name: string): PreviewKind {
  const ext = extension(name);
  if (ext in IMAGES) return "image";
  if (TEXT.has(ext)) return "text";
  const base = baseName(name).toLowerCase();
  if (TEXT.has(base)) return "text";
  return "sniff";
}

export function imageMime(name: string): string | undefined {
  return IMAGES[extension(name)];
}

/** An image type from the first bytes, or `undefined`. */
export function sniffImage(bytes: Uint8Array): string | undefined {
  const starts = (...sig: number[]) => sig.every((b, i) => bytes[i] === b);
  if (starts(0x89, 0x50, 0x4e, 0x47)) return "image/png";
  if (starts(0xff, 0xd8, 0xff)) return "image/jpeg";
  if (starts(0x47, 0x49, 0x46, 0x38)) return "image/gif";
  if (starts(0x52, 0x49, 0x46, 0x46) && bytes[8] === 0x57 && bytes[9] === 0x45) return "image/webp";
  if (starts(0x42, 0x4d)) return "image/bmp";
  if (starts(0x00, 0x00, 0x01, 0x00)) return "image/x-icon";
  return undefined;
}

/** Whether bytes look like text: valid UTF-8 without NULs. */
export function looksLikeText(bytes: Uint8Array): boolean {
  if (bytes.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    // A character cut off at the end of the sample isn't a reason to give up.
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, Math.max(0, bytes.length - 3)));
      return true;
    } catch {
      return false;
    }
  }
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** An error as the page shows it. */
export function describeError(err: unknown): { code: string; message: string } {
  const e = err as Partial<CmdError> | undefined;
  if (e && typeof e === "object" && typeof e.code === "string") {
    return { code: e.code, message: e.message ?? "" };
  }
  return { code: "Internal", message: String(err) };
}

export function isCancelled(err: unknown): boolean {
  return describeError(err).code === "Cancelled";
}
