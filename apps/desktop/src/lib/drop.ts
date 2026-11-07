// Files dropped on the window (docs/M3.md §5.4, docs/M5.md §8.2): where they land decides what
// happens to them.
import { activeTab, archiveArgs, type Tab, useArchives } from "./archives";
import { blockedBy } from "./edit";
import { run } from "./engine";
import { describeError } from "./format";
import { useJobs } from "./jobs";
import { useUi } from "./ui";

/** Whether BeeZip reads `path` as an archive (a compressed single file counts). */
export async function isArchive(path: string): Promise<boolean> {
  const d = await run("file.detect", { path });
  return d.format !== null;
}

/** Where a drop lands: an open archive's entries, or anywhere else (the welcome screen, the tab
 * strip, the toolbar…). */
export type DropZone = "entries" | "elsewhere";

/** The zone under a point, in CSS pixels. */
export function dropZone(x: number, y: number): DropZone {
  return document.elementFromPoint(x, y)?.closest("[data-drop=entries]") ? "entries" : "elsewhere";
}

/** The archive's info, to know whether it can be edited: the tab's, or read now. */
async function infoOf(tab: Tab) {
  return tab.info ?? useJobs.getState().track("archive.info", { archive: tab.path, ...archiveArgs(tab) }, { title: `Reading ${tab.name}`, quiet: true, tab: tab.id });
}

/** Dropped paths. On the entries of an archive that can be edited: the add dialog, into the
 * folder shown, which is the confirmation. On one that can't: a new archive, saying why.
 * Elsewhere, one archive opens, and anything else, or several, goes into a new archive. */
export async function dropPaths(paths: string[], zone: DropZone = "elsewhere") {
  if (paths.length === 0) return;
  const ui = useUi.getState();
  // A dialog that takes files takes these too.
  if (ui.dialog?.kind === "create" || ui.dialog?.kind === "add") {
    ui.show({ ...ui.dialog, inputs: paths });
    return;
  }
  const tab = activeTab(useArchives.getState());
  if (zone === "entries" && tab) {
    let blocked: string | undefined;
    try {
      blocked = blockedBy(await infoOf(tab));
    } catch (e) {
      blocked = `${tab.name} can't be read: ${describeError(e).message}`;
    }
    if (blocked) ui.show({ kind: "create", inputs: paths, note: blocked });
    else ui.show({ kind: "add", tab: tab.id, inputs: paths, dir: tab.dir });
    return;
  }
  if (paths.length === 1) {
    try {
      if (await isArchive(paths[0])) {
        useArchives.getState().open(paths[0]);
        return;
      }
    } catch {
      // Not readable as an archive: offer to pack it.
    }
  }
  ui.show({ kind: "create", inputs: paths });
}
