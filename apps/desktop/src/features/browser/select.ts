// Selection in the entry table: click, Ctrl, Shift, the arrow keys and Ctrl+A.

export type Selection = { selected: number[]; all: boolean; anchor?: number; focus?: number };

export const NONE: Selection = { selected: [], all: false };

function range(a: number, b: number): number[] {
  const [lo, hi] = a <= b ? [a, b] : [b, a];
  return Array.from({ length: hi - lo + 1 }, (_, i) => lo + i);
}

export function isSelected(sel: Selection, set: Set<number>, index: number): boolean {
  return sel.all || set.has(index);
}

/** A click on row `index`: alone, with Ctrl to toggle it, with Shift to extend to it. */
export function click(sel: Selection, index: number, mods: { ctrl: boolean; shift: boolean }): Selection {
  if (mods.shift && sel.anchor !== undefined) {
    const span = range(sel.anchor, index);
    const selected = mods.ctrl ? [...new Set([...sel.selected, ...span])] : span;
    return { selected, all: false, anchor: sel.anchor, focus: index };
  }
  if (mods.ctrl) {
    const base = sel.all ? [] : sel.selected;
    const selected = base.includes(index) ? base.filter((i) => i !== index) : [...base, index];
    return { selected, all: false, anchor: index, focus: index };
  }
  return { selected: [index], all: false, anchor: index, focus: index };
}

/** The keyboard moves to `to`; with Shift the selection follows from the anchor. */
export function moveTo(sel: Selection, to: number, total: number, shift: boolean): Selection {
  if (total === 0) return NONE;
  const index = Math.max(0, Math.min(total - 1, to));
  if (shift) {
    const anchor = sel.anchor ?? sel.focus ?? index;
    return { selected: range(anchor, index), all: false, anchor, focus: index };
  }
  return { selected: [index], all: false, anchor: index, focus: index };
}

export function selectAll(sel: Selection): Selection {
  return { ...sel, selected: [], all: true };
}

export function count(sel: Selection, total: number): number {
  return sel.all ? total : sel.selected.length;
}
