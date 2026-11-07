// Editing an open archive (docs/M5.md §8.1): whether it can be, and the edits themselves. Each
// runs as a job in the jobs panel; when it ends the tab lists again in the same folder, with the
// selection kept by path.
import type { ArchiveInfoOutput, ArchiveRemoveInput, EditOutput } from "../gen/commands";
import { archiveArgs, type Tab, useArchives } from "./archives";
import { archiveParent, baseName } from "./format";
import { useJobs } from "./jobs";

/** Why the tab's archive can't be edited, or `undefined` when it can. Until its info is in, it
 * can't be told, so the commands wait. */
export function editBlocked(tab: Pick<Tab, "info">): string | undefined {
  return blockedBy(tab.info);
}

export function blockedBy(info: ArchiveInfoOutput | undefined): string | undefined {
  if (!info) return "Reading the archive…";
  return info.not_editable ?? undefined;
}

/** What a tab's selection is, by path, so it can be found again after the archive changes. */
export type SelectionByPath = { all: boolean; paths: string[] };

/** What a tab's browser does for the palette: it has the rows. */
export type BrowserActions = {
  /** The selection, by path. */
  selection: () => SelectionByPath;
  /** Rename the focused or selected row in place. */
  rename: () => void;
  /** Delete the selection, once the person agrees. */
  remove: () => void;
};

const browsers = new Map<string, BrowserActions>();

/** The shown tab's browser registers itself; the returned function unregisters it. */
export function registerBrowser(tab: string, actions: BrowserActions): () => void {
  browsers.set(tab, actions);
  return () => {
    if (browsers.get(tab) === actions) browsers.delete(tab);
  };
}

export function browserOf(tab: string): BrowserActions | undefined {
  return browsers.get(tab);
}

export function selectionOf(tab: string): SelectionByPath {
  return browsers.get(tab)?.selection() ?? { all: false, paths: [] };
}

/** The tab lists again after an edit, in the same folder; `keep` is selected once its rows are
 * in (the selection before the edit, unless given). */
export function relist(id: string, keep?: SelectionByPath) {
  const sel = keep ?? selectionOf(id);
  useArchives.getState().update(id, (t) => ({
    version: t.version + 1,
    info: undefined,
    preview: undefined,
    selected: [],
    all: sel.all,
    anchor: undefined,
    focus: undefined,
    reselect: sel.all ? undefined : sel.paths,
  }));
}

/** Runs an edit on the tab's archive as a job; afterwards the tab lists again. */
export async function runEdit(
  tab: Tab,
  command: "archive.add" | "archive.remove" | "archive.rename",
  args: object,
  title: string,
  keep?: SelectionByPath,
): Promise<EditOutput> {
  // The three take the same output; their inputs are checked by the engine.
  const out = (await useJobs.getState().track(command, args as never, { title, tab: tab.id })) as EditOutput;
  relist(tab.id, keep);
  return out;
}

/** A path as a glob that matches only it: `*`, `?`, `[`, `]`, `{` and `}` in brackets. */
export function escapeGlob(path: string): string {
  return path.replace(/[*?[\]{}]/g, (c) => `[${c}]`);
}

/** `archive.remove`'s arguments for the selection: the paths, or with every row selected,
 * everything in the folder shown. */
export function removeArgs(tab: Tab, sel: SelectionByPath): ArchiveRemoveInput {
  const which = sel.all ? { glob: [tab.dir ? `${escapeGlob(tab.dir)}/**` : "*"] } : { entries: sel.paths };
  return { archive: tab.path, ...which, ...archiveArgs(tab) };
}

/** "Delete 3 items from a.zip?", or the one item's name. */
export function deleteQuestion(count: number, archive: string, one?: string): string {
  const what = count === 1 && one ? baseName(one) : `${count.toLocaleString()} ${count === 1 ? "item" : "items"}`;
  return `Delete ${what} from ${archive}?`;
}

/** Why a new name for an entry won't do, or `undefined`. A rename in place keeps the folder. */
export function checkName(name: string): string | undefined {
  const n = name.trim();
  if (!n) return "A name can't be empty.";
  if (/[\\/]/.test(n)) return "A name can't contain / or \\.";
  if (n === "." || n === "..") return `A name can't be ${n}.`;
  return undefined;
}

/** The entry's new path: the same folder, the new name. */
export function renamed(path: string, name: string): string {
  const parent = archiveParent(path);
  return parent ? `${parent}/${name.trim()}` : name.trim();
}
