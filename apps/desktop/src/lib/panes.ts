// The sizes of the panes whose edges resize them: the browser's folder tree and preview (the
// entries take what's left), and the jobs list's height. One set for every tab, kept in the
// page's local storage: a window's layout, not a setting for config.toml.
import { create } from "zustand";

export type Pane = "tree" | "preview";
export type Widths = Record<Pane, number>;

export const DEFAULT_WIDTHS: Widths = { tree: 208, preview: 320 };
export const MIN_WIDTHS: Widths = { tree: 120, preview: 200 };
/** The entries keep at least this much of the row. */
export const CONTENTS_MIN = 240;
/** A row narrower than this has no preview. */
export const PREVIEW_FROM = 1000;
/** Each edge is a 1 px rule. */
export const EDGE = 1;

/** The jobs list is no shorter than this once its edge is dragged. Until then (and after a
 * double-click on it) it fits its jobs, up to 38% of the window. */
export const JOBS_MIN = 64;
/** What's above the jobs (the tabs and the archive's view) keeps at least this much. */
export const JOBS_ABOVE_MIN = 200;
/** The jobs panel's status line, between its edge and the list. */
export const JOBS_HEADER = 32;

const KEY = "beezip.panes";

type Sizes = Widths & { jobs: number | null };

function load(): Sizes {
  const sizes: Sizes = { ...DEFAULT_WIDTHS, jobs: null };
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(KEY) ?? "null");
    if (!saved || typeof saved !== "object") return sizes;
    const number = (key: string) => {
      const v = (saved as Record<string, unknown>)[key];
      return typeof v === "number" && Number.isFinite(v) ? Math.round(v) : undefined;
    };
    for (const pane of ["tree", "preview"] as const) {
      const v = number(pane);
      if (v !== undefined) sizes[pane] = Math.max(MIN_WIDTHS[pane], v);
    }
    const jobs = number("jobs");
    if (jobs !== undefined) sizes.jobs = Math.max(JOBS_MIN, jobs);
  } catch {
    // Storage blocked or the value damaged: the defaults.
  }
  return sizes;
}

type PanesState = Sizes & {
  /** Sets a size while its edge moves; `save` keeps it. */
  resize: (pane: Pane | "jobs", size: number) => void;
  /** Puts a pane back to its default size, and keeps that. */
  reset: (pane: Pane | "jobs") => void;
  save: () => void;
};

export const usePanes = create<PanesState>((set, get) => ({
  ...load(),
  resize(pane, size) {
    const min = pane === "jobs" ? JOBS_MIN : MIN_WIDTHS[pane];
    set({ [pane]: Math.max(min, Math.round(size)) });
  },
  reset(pane) {
    set({ [pane]: pane === "jobs" ? null : DEFAULT_WIDTHS[pane] });
    get().save();
  },
  save() {
    const { tree, preview, jobs } = get();
    try {
      localStorage.setItem(KEY, JSON.stringify({ tree, preview, ...(jobs === null ? {} : { jobs }) }));
    } catch {
      // Not kept: the next start has the defaults.
    }
  },
}));

/** The room the two panes share in a row `row` px wide. */
function room(row: number, preview: boolean): number {
  return row - CONTENTS_MIN - EDGE * (preview ? 2 : 1);
}

/** The widths the panes get in a row `row` px wide (0 before it's measured): the ones asked for,
 * narrowed so the entries keep `CONTENTS_MIN`, the preview first, neither below its minimum. */
export function fit(want: Widths, row: number, preview: boolean): Widths {
  let tree = Math.max(MIN_WIDTHS.tree, want.tree);
  let side = Math.max(MIN_WIDTHS.preview, want.preview);
  if (row <= 0) return { tree, preview: side };
  let over = tree + (preview ? side : 0) - room(row, preview);
  if (over > 0 && preview) {
    const give = Math.min(over, side - MIN_WIDTHS.preview);
    side -= give;
    over -= give;
  }
  if (over > 0) tree = Math.max(MIN_WIDTHS.tree, tree - over);
  return { tree, preview: side };
}

/** The widest `pane` can be dragged to, beside the other pane as it's shown now. */
export function widest(pane: Pane, shown: Widths, row: number, preview: boolean): number {
  if (row <= 0) return 4096;
  const other = pane === "tree" ? (preview ? shown.preview : 0) : shown.tree;
  return Math.max(MIN_WIDTHS[pane], room(row, preview) - other);
}

/** The tallest the jobs list can be dragged to in a window column `column` px high (0 before
 * it's measured). The panel's CSS holds it to the same, so a narrower window shortens it. */
export function tallestJobs(column: number): number {
  if (column <= 0) return 4096;
  return Math.max(JOBS_MIN, column - JOBS_ABOVE_MIN - EDGE - JOBS_HEADER);
}
