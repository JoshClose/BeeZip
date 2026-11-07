// Deleting from an archive (docs/M5.md §8.1): it can't be undone, so it asks first, in Windows'
// own dialog.
import { ask } from "@tauri-apps/plugin-dialog";
import type { Tab } from "../../lib/archives";
import { deleteQuestion, removeArgs, runEdit, type SelectionByPath, selectionOf } from "../../lib/edit";
import { toastError } from "../../lib/toasts";

/** Asks "Delete 3 items from a.zip?"; true to go ahead. */
export function confirmDelete(count: number, archive: string, one?: string): Promise<boolean> {
  return ask(`${deleteQuestion(count, archive, one)}\n\nThis can't be undone.`, {
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
  if (!(await confirmDelete(count, tab.name, one))) return;
  try {
    await runEdit(tab, "archive.remove", removeArgs(tab, sel), `Deleting from ${tab.name}`, { all: false, paths: [] });
  } catch (e) {
    toastError(e, `Deleting from ${tab.name}`);
  }
}
