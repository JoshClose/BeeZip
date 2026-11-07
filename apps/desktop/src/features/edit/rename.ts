// Renaming one entry in place (docs/M5.md §8.1, §7.3): F2, the toolbar or the palette starts
// it on the focused row; the field saves with Enter.
import { archiveArgs, type Tab, useArchives } from "../../lib/archives";
import { checkName, editBlocked, renamed, runEdit } from "../../lib/edit";
import { baseName, describeError, normalize } from "../../lib/format";

/** Starts renaming row `index`, the entry at `path`, if the archive can be edited. */
export function startRename(tab: Tab, index: number, path: string | undefined) {
  if (path === undefined || editBlocked(tab)) return;
  useArchives.getState().update(tab.id, { renaming: { index, path: normalize(path), busy: false } });
}

export function cancelRename(tab: Pick<Tab, "id">) {
  useArchives.getState().update(tab.id, { renaming: undefined });
}

/** Saves the new name: `archive.rename`, then the tab lists again with the entry selected. A
 * refusal stays beside the field. */
export async function saveRename(tab: Tab, name: string): Promise<void> {
  const r = useArchives.getState().tabs.find((t) => t.id === tab.id)?.renaming;
  if (!r || r.busy) return;
  const set = (patch: Partial<typeof r> | undefined) =>
    useArchives.getState().update(tab.id, (t) => ({ renaming: patch && t.renaming ? { ...t.renaming, ...patch } : undefined }));
  if (name.trim() === baseName(r.path)) return set(undefined);
  const bad = checkName(name);
  if (bad) return set({ error: bad });
  const to = renamed(r.path, name);
  set({ busy: true, error: undefined });
  try {
    await runEdit(tab, "archive.rename", { archive: tab.path, from: r.path, to, ...archiveArgs(tab) }, `Renaming ${baseName(r.path)} in ${tab.name}`, {
      all: false,
      paths: [to],
    });
    set(undefined);
  } catch (e) {
    const { code, message } = describeError(e);
    set({ busy: false, error: code === "Cancelled" ? undefined : `${code}: ${message}` });
  }
}
