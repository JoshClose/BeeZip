// The open archives, one tab each (docs/M3.md §5.2). A password typed for an archive is kept
// here, in memory only, and passed to later calls on it, as is the name encoding chosen for it
// (docs/M5.md §8.4).
import { create } from "zustand";
import type { ArchiveInfoOutput, EntryInfo, NameEncoding, SortKey } from "../gen/commands";
import { baseName } from "./format";

export type Tab = {
  id: string;
  path: string;
  name: string;
  /** The folder shown, normalised; `""` is the root. */
  dir: string;
  sort?: SortKey;
  reverse: boolean;
  password?: string;
  /** How its names are read; unset, the settings' default. */
  encoding?: NameEncoding;
  info?: ArchiveInfoOutput;
  /** Selected rows, by index in the current listing. */
  selected: number[];
  /** Every row is selected (Ctrl+A), however many there are. */
  all: boolean;
  /** The row Shift extends from, and the one the keyboard is on. */
  anchor?: number;
  focus?: number;
  /** The entry the preview pane shows. */
  preview?: EntryInfo;
  /** The person agreed to decode a solid block for previews. */
  solidOk: boolean;
  /** Bumped to list again (after a password, or Retry). */
  version: number;
};

type ArchivesState = {
  tabs: Tab[];
  active?: string;
  open: (path: string) => string;
  close: (id: string) => void;
  activate: (id: string) => void;
  update: (id: string, patch: Partial<Tab> | ((t: Tab) => Partial<Tab>)) => void;
  setDir: (id: string, dir: string) => void;
  setSort: (id: string, key: SortKey) => void;
  /** Reads the tab's names another way: it lists again from the top. */
  setEncoding: (id: string, encoding: NameEncoding | undefined) => void;
};

let nextTab = 1;

const sameFile = (a: string, b: string) => a.replace(/\//g, "\\").toLowerCase() === b.replace(/\//g, "\\").toLowerCase();

export const useArchives = create<ArchivesState>((set, get) => ({
  tabs: [],

  open(path) {
    const existing = get().tabs.find((t) => sameFile(t.path, path));
    if (existing) {
      set({ active: existing.id });
      return existing.id;
    }
    const tab: Tab = {
      id: `tab-${nextTab++}`,
      path,
      name: baseName(path),
      dir: "",
      reverse: false,
      selected: [],
      all: false,
      solidOk: false,
      version: 0,
    };
    set((s) => ({ tabs: [...s.tabs, tab], active: tab.id }));
    return tab.id;
  },

  close(id) {
    set((s) => {
      const i = s.tabs.findIndex((t) => t.id === id);
      const tabs = s.tabs.filter((t) => t.id !== id);
      const active = s.active === id ? (tabs[Math.min(i, tabs.length - 1)]?.id ?? undefined) : s.active;
      return { tabs, active };
    });
  },

  activate(id) {
    set({ active: id });
  },

  update(id, patch) {
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id ? { ...t, ...(typeof patch === "function" ? patch(t) : patch) } : t)),
    }));
  },

  setDir(id, dir) {
    get().update(id, { dir, selected: [], all: false, anchor: undefined, focus: undefined, preview: undefined });
  },

  setSort(id, key) {
    get().update(id, (t) => ({
      sort: key,
      reverse: t.sort === key ? !t.reverse : false,
      selected: [],
      all: false,
      anchor: undefined,
      focus: undefined,
    }));
  },

  setEncoding(id, encoding) {
    // Folder names change with the encoding, so the folder shown may no longer exist.
    get().update(id, (t) => ({
      encoding,
      dir: "",
      selected: [],
      all: false,
      anchor: undefined,
      focus: undefined,
      preview: undefined,
      info: undefined,
      version: t.version + 1,
    }));
  },
}));

/** What every command on a tab's archive passes: its password and name encoding, if set. Read
 * from the store when called, so a password typed since still applies. */
export function archiveArgs(tab: Pick<Tab, "id">): { password?: string; name_encoding?: NameEncoding } {
  const t = useArchives.getState().tabs.find((x) => x.id === tab.id);
  return {
    ...(t?.password ? { password: t.password } : {}),
    ...(t?.encoding ? { name_encoding: t.encoding } : {}),
  };
}

export function activeTab(s: Pick<ArchivesState, "tabs" | "active">): Tab | undefined {
  return s.tabs.find((t) => t.id === s.active);
}
