// Deleting from an archive (docs/M5.md §8.1): it can't be undone, so it asks first, in Windows'
// own dialog, and says when a .bhive's signatures go with it (docs/M14.md §11).
import { ask } from "@tauri-apps/plugin-dialog";
import type { Tab } from "../../lib/archives";
import { deleteQuestion, offerToSignAgain, removeArgs, runEdit, type SelectionByPath, selectionOf } from "../../lib/edit";
import { dropsSignatures, type Signature, signaturesOf } from "../../lib/signatures";
import { toastError } from "../../lib/toasts";

/** Asks "Delete 3 items from a.zip?"; true to go ahead. `sigs` are the signatures that drop. */
export function confirmDelete(count: number, archive: string, one?: string, sigs: Signature[] = []): Promise<boolean> {
  const drops = dropsSignatures(sigs);
  return ask(`${deleteQuestion(count, archive, one)}\n\nThis can't be undone.${drops ? `\n\n${drops}` : ""}`, {
    title: "BeeZip",
    kind: "warning",
    okLabel: "Delete",
    cancelLabel: "Cancel",
  });
}

/** Deletes the tab's selection, `count` rows, once the person agrees. */
export async function deleteSelection(tab: Tab, count: number, sel: SelectionByPath = selectionOf(tab.id)): Promise<void> {
  if (count === 0 || (!sel.all && sel.paths.length === 0)) return;
  const one = !sel.all && sel.paths.length === 1 ? sel.paths[0] : undefined;
  if (!(await confirmDelete(count, tab.name, one, signaturesOf(tab.info)))) return;
  try {
    await runEdit(tab, "archive.remove", removeArgs(tab, sel), `Deleting from ${tab.name}`, { all: false, paths: [] });
    offerToSignAgain(tab, "Deleting");
  } catch (e) {
    toastError(e, `Deleting from ${tab.name}`);
  }
}
