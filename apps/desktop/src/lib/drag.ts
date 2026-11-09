// Dragging entries out to Explorer (docs/M6.md §8.4), the page's half. A `dragstart` on the
// selected rows calls `startDrag`; Rust's `cmd_drag_out` (src-tauri/src/drag.rs) runs the OLE
// drag while the button is still down, and extracts only when a target takes the drop. The
// extraction comes back here as an ordinary job, on its own channel.
import { Channel, invoke } from "@tauri-apps/api/core";
import type { ArchiveExtractInput, EntryInfo, JobEvent } from "../gen/commands";
import { archiveArgs, type Tab } from "./archives";
import { baseName, describeError, formatSize, normalize } from "./format";
import { follow, type JobMeta, useJobs } from "./jobs";
import { toastError } from "./toasts";
import { useUi } from "./ui";

/** The most a drag extracts, by listed size. Explorer waits, unresponsive, until the
 * extraction ends, as it does with 7-Zip; past this, Extract… is the way out. */
export const DRAG_CAP = 2 * 1024 ** 3;

/** How a drag ended (drag.rs's `DragOutcome`). "failed": dropped, but the extraction failed,
 * which its job has already said. */
export type DragOutcome = "dropped" | "cancelled" | "failed";

/** `archive.extract`'s arguments for a drag; Rust sets `dest`, `smart`, `overwrite` and `dry_run`. */
export type DragArgs = Omit<ArchiveExtractInput, "dest" | "smart" | "overwrite" | "dry_run">;

/** What's dragged: every row of the folder shown, or these rows. */
export type DragSelection = { all: true } | { all: false; rows: EntryInfo[] };

let state: "idle" | "sizing" | "dragging" = "idle";

/** A drag-out is under way: drops on the window are its own, and are ignored (App.tsx). */
export function draggingOut(): boolean {
  return state === "dragging";
}

/** The archive paths a selection names, as Browser's `selectedPaths` gives them. */
function paths(tab: Tab, sel: DragSelection): string[] {
  if (sel.all) return tab.dir ? [tab.dir] : [];
  return sel.rows.map((e) => normalize(e.path));
}

/** The arguments for a drag of `sel`: the folder shown is stripped, so its items land at the top. */
export function dragArgs(tab: Tab, sel: DragSelection): DragArgs {
  const entries = paths(tab, sel);
  const strip = tab.dir ? tab.dir.split("/").length : 0;
  return {
    archive: tab.path,
    ...(entries.length > 0 ? { entries } : {}),
    ...(strip > 0 ? { strip_components: strip } : {}),
    ...archiveArgs(tab),
  };
}

/** What extracting `sel` writes, by the listing's sizes; it stops counting past `cap`. */
export async function listedSize(tab: Tab, sel: DragSelection, cap = DRAG_CAP): Promise<number> {
  const sizeOf = (dir: string) =>
    useJobs
      .getState()
      .track(
        "archive.list",
        { archive: tab.path, ...(dir ? { dir } : {}), flat: true, limit: 0, ...archiveArgs(tab) },
        { title: `Measuring ${tab.name}`, quiet: true, tab: tab.id },
      )
      .then((out) => out.size);
  if (sel.all) return sizeOf(tab.dir);
  let total = 0;
  const dirs: string[] = [];
  for (const e of sel.rows) {
    if (e.kind === "dir") dirs.push(normalize(e.path));
    else total += e.size ?? 0;
  }
  if (total > cap || dirs.length === 0) return total;
  const sizes = await Promise.all(dirs.map(sizeOf));
  return sizes.reduce((a, b) => a + b, total);
}

/** What the jobs panel calls the drop's extraction. */
function title(tab: Tab, sel: DragSelection): string {
  if (sel.all) return tab.dir ? `Extracting ${baseName(tab.dir)} from ${tab.name}` : `Extracting ${tab.name}`;
  if (sel.rows.length === 1) return `Extracting ${baseName(sel.rows[0].path)} from ${tab.name}`;
  return `Extracting ${sel.rows.length.toLocaleString()} items from ${tab.name}`;
}

/** Runs the drag: resolves when it's over, or `undefined` if it couldn't start. */
export async function dragOut(tab: Tab, sel: DragSelection): Promise<DragOutcome | undefined> {
  const args = dragArgs(tab, sel);
  const name = title(tab, sel);
  const meta: JobMeta = {
    title: name,
    tab: tab.id,
    onEvent: (e) => {
      // As the extract dialog does: Unsafe and Corrupt details are in the jobs panel; a
      // cancellation was asked for.
      if (e.type === "Failed" && describeError(e.error).code !== "Unsafe") toastError(e.error, name);
    },
  };
  const channel = new Channel<JobEvent>();
  channel.onmessage = follow("archive.extract", args, meta);
  state = "dragging";
  try {
    return await invoke<DragOutcome>("cmd_drag_out", { args, onEvent: channel });
  } catch (e) {
    toastError(e, "Dragging out");
    return undefined;
  } finally {
    state = "idle";
  }
}

/**
 * A `dragstart` on the selection: measured, then dragged, or, past the cap, offered to the
 * extract dialog instead. `"too-big"` when the dialog opened; `undefined` when nothing
 * happened (a drag already under way, nothing selected, or it couldn't start).
 */
export async function startDrag(tab: Tab, sel: DragSelection): Promise<DragOutcome | "too-big" | undefined> {
  if (state !== "idle") return undefined;
  if (!sel.all && sel.rows.length === 0) return undefined;
  state = "sizing";
  let size: number;
  try {
    size = await listedSize(tab, sel);
  } catch (e) {
    state = "idle";
    toastError(e, "Dragging out");
    return undefined;
  }
  if (size > DRAG_CAP) {
    state = "idle";
    useUi.getState().show({
      kind: "extract",
      tab: tab.id,
      entries: paths(tab, sel),
      note: `That's ${formatSize(size)}, more than the ${formatSize(DRAG_CAP)} a drag takes: Explorer would stop responding until it was all extracted. Extract it from here instead.`,
    });
    return "too-big";
  }
  return dragOut(tab, sel);
}
