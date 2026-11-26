// Renaming one entry in place (docs/M5.md §8.1, §7.3): F2, the toolbar or the palette starts
// it on the focused row; the field saves with Enter. A signed .bhive loses its signatures, so it
// asks first and offers to sign again (docs/M14.md §11).
import { ask } from "@tauri-apps/plugin-dialog";
import { archiveArgs, type Tab, useArchives } from "../../lib/archives";
import { checkName, editBlocked, offerToSignAgain, renamed, runEdit } from "../../lib/edit";
import { baseName, describeError, normalize } from "../../lib/format";
import { dropsSignatures, signaturesOf } from "../../lib/signatures";

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
  const drops = dropsSignatures(signaturesOf(tab.info));
  if (drops && !(await ask(`Rename ${baseName(r.path)} to ${name.trim()}?\n\n${drops}`, { title: "BeeZip", kind: "warning", okLabel: "Rename", cancelLabel: "Cancel" }))) {
    return set({ busy: false });
  }
  try {
    await runEdit(tab, "archive.rename", { archive: tab.path, from: r.path, to, ...archiveArgs(tab) }, `Renaming ${baseName(r.path)} in ${tab.name}`, {
      all: false,
      paths: [to],
    });
    set(undefined);
    if (drops) offerToSignAgain(tab, "Renaming");
  } catch (e) {
    const { code, message } = describeError(e);
    set({ busy: false, error: code === "Cancelled" ? undefined : `${code}: ${message}` });
  }
}
