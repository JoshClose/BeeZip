// Opening entries (docs/M5.md §8.3). A double-click or Enter on a file runs `entry.open`: an
// archive BeeZip reads opens in a new tab, a program asks first, anything else opens in its app.
// Rust notes each file opened in an app (src-tauri/src/opened.rs); when the window gets the
// focus back, it sends `entry-changed` for those that changed, and the page asks whether to put
// them back in their archive.
import { emit } from "@tauri-apps/api/event";
import { create } from "zustand";
import type { EntryInfo } from "../gen/commands";
import { archiveArgs, type Tab, useArchives } from "./archives";
import { relist } from "./edit";
import { archiveParent, baseName, extension, normalize } from "./format";
import { loadFormats, readableExtensions } from "./formats";
import { useJobs } from "./jobs";

/** A file opened in its app, from a tab's archive. */
export type OpenedFile = {
  /** The extracted file. */
  path: string;
  tab: string;
  /** The entry it came from, normalised. */
  entry: string;
  encrypted: boolean;
};

/** What Rust sends when an opened file changed. */
export type EntryChanged = { archive: string; entry: string; path: string };

/** "Run setup.exe from a.zip?", waiting for its answer. */
export type RunQuestion = { name: string; archive: string; answer: (run: boolean) => void };

type OpenedState = {
  /** By path, lower-cased. */
  files: Record<string, OpenedFile>;
  /** Files that changed, oldest first; the question shows for the first. */
  changed: OpenedFile[];
  asking?: RunQuestion;
};

export const useOpened = create<OpenedState>(() => ({ files: {}, changed: [] }));

/** Asks whether to run a program from an archive; true to run it. A second question answers
 * the first with no. */
export function askToRun(name: string, archive: string): Promise<boolean> {
  useOpened.getState().asking?.answer(false);
  return new Promise((resolve) => {
    const answer = (run: boolean) => {
      if (useOpened.getState().asking?.answer === answer) useOpened.setState({ asking: undefined });
      resolve(run);
    };
    useOpened.setState({ asking: { name, archive, answer } });
  });
}

const key = (path: string) => path.replace(/\//g, "\\").toLowerCase();

/** Extensions Windows runs rather than opens: programs, installers, scripts and shortcuts. */
const PROGRAMS = new Set(
  (
    "exe com scr pif cpl msi msp msix msixbundle appx appxbundle appinstaller application appref-ms " +
    "bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta msc jar reg lnk url scf inf"
  ).split(" "),
);

export function isProgram(name: string): boolean {
  return PROGRAMS.has(extension(name));
}

/** Whether a name ends with an extension BeeZip reads: `a.zip`, `b.tar.gz`, `c.7z.001`. */
export function readsAsArchive(name: string, extensions: string[]): boolean {
  const lower = baseName(name).toLowerCase();
  return extensions.some((e) => lower.endsWith(`.${e.toLowerCase()}`));
}

/** Entries above this size show their extraction in the jobs panel. */
const SHOW_OPENING = 16 * 1024 * 1024;

/** Opens a file entry of the tab's archive. Errors are thrown; a "no" to running a program
 * isn't one. */
export async function openEntry(tab: Tab, entry: EntryInfo): Promise<void> {
  const path = normalize(entry.path);
  const name = baseName(path);
  const meta = { title: `Opening ${name}`, quiet: (entry.size ?? 0) < SHOW_OPENING, tab: tab.id };
  let extensions: string[] = [];
  try {
    extensions = readableExtensions(await loadFormats());
  } catch {
    // Without the list, nothing opens as a tab.
  }
  if (readsAsArchive(name, extensions)) {
    const out = await useJobs.getState().track("entry.open", { archive: tab.path, entry: path, launch: false, ...archiveArgs(tab) }, meta);
    useArchives.getState().open(out.path);
    return;
  }
  if (isProgram(name) && !(await askToRun(name, tab.name))) return;
  const out = await useJobs.getState().track("entry.open", { archive: tab.path, entry: path, ...archiveArgs(tab) }, meta);
  // A name SafeFs had to change can't be put back under the entry's own name.
  if (baseName(out.path).toLowerCase() !== name.toLowerCase()) return;
  useOpened.setState((s) => ({
    files: { ...s.files, [key(out.path)]: { path: out.path, tab: tab.id, entry: path, encrypted: entry.encrypted } },
  }));
}

/** Rust says a file changed: ask about it, if its tab is still open. */
export function entryChanged(e: EntryChanged) {
  const file = useOpened.getState().files[key(e.path)];
  if (!file || !useArchives.getState().tabs.some((t) => t.id === file.tab)) return;
  useOpened.setState((s) => (s.changed.some((c) => key(c.path) === key(file.path)) ? s : { changed: [...s.changed, file] }));
}

function done(file: OpenedFile) {
  useOpened.setState((s) => ({ changed: s.changed.filter((c) => c !== file) }));
}

/** "Not now": the file stays noted, so a later change asks again. */
export function notNow(file: OpenedFile) {
  done(file);
}

/** `archive.add`'s arguments for putting a changed file back: into its entry's folder, over the
 * entry. An encrypted entry takes the tab's password; a plain one in an archive with encrypted
 * entries stays plain. */
export function updateArgs(tab: Tab, file: OpenedFile) {
  const dir = archiveParent(file.entry);
  const info = tab.info;
  const headers = info?.encrypted_headers ?? false;
  const { password, name_encoding } = archiveArgs(tab);
  return {
    archive: tab.path,
    inputs: [file.path],
    ...(dir ? { dir } : {}),
    overwrite: "always" as const,
    ...((file.encrypted || headers) && password ? { password } : {}),
    ...(!file.encrypted && !headers && info && info.encryption !== "none" ? { unencrypted: true } : {}),
    ...(name_encoding ? { name_encoding } : {}),
  };
}

/** "Update": the file replaces its entry. */
export async function updateEntry(file: OpenedFile): Promise<void> {
  done(file);
  const tab = useArchives.getState().tabs.find((t) => t.id === file.tab);
  if (!tab) return;
  await useJobs.getState().track("archive.add", updateArgs(tab, file), { title: `Updating ${baseName(file.entry)} in ${tab.name}`, tab: tab.id });
  relist(tab.id);
}

/** A closed tab's files are forgotten, here and in Rust. */
export function forgetTab(tab: string) {
  const { files, changed } = useOpened.getState();
  const gone = Object.entries(files).filter(([, f]) => f.tab === tab);
  if (gone.length === 0) return;
  const kept = Object.fromEntries(Object.entries(files).filter(([, f]) => f.tab !== tab));
  useOpened.setState({ files: kept, changed: changed.filter((c) => c.tab !== tab) });
  void emit("opened-forget", { paths: gone.map(([, f]) => f.path) }).catch(() => {});
}

// However a tab closes (its ×, Ctrl+W, the palette), its files go with it.
useArchives.subscribe((s, prev) => {
  for (const t of prev.tabs) if (!s.tabs.some((x) => x.id === t.id)) forgetTab(t.id);
});
