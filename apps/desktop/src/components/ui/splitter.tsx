// A pane's edge, which resizes it (the WAI-ARIA window splitter): a 1 px rule with a wider grip
// to drag, arrow keys once focused, and a double-click for the pane's default size. A vertical
// edge sits between panes side by side and sets a width; a horizontal one sets a height.
import { type KeyboardEvent, type PointerEvent, useEffect, useRef, useState } from "react";
import { cn } from "../../lib/cn";

/** An arrow key's step, in CSS pixels. */
export const STEP = 16;

export function Splitter({
  label,
  size,
  min,
  max,
  side,
  orientation = "vertical",
  onResize,
  onDone,
  onReset,
  className,
}: {
  label: string;
  /** The pane's width (or height) as shown. */
  size: number;
  min: number;
  max: number;
  /** The pane is `before` the edge, left or above it (dragging right or down grows it), or
   * `after` it (dragging left or up does). */
  side: "before" | "after";
  orientation?: "vertical" | "horizontal";
  onResize: (size: number) => void;
  /** A drag or a key press is over: the size can be kept. */
  onDone: () => void;
  onReset: () => void;
  className?: string;
}) {
  const drag = useRef<{ id: number; at: number; size: number } | undefined>(undefined);
  const [dragging, setDragging] = useState(false);
  const vertical = orientation === "vertical";
  const sign = side === "before" ? 1 : -1;
  const clamp = (s: number) => Math.round(Math.min(max, Math.max(min, s)));
  const at = (e: PointerEvent) => (vertical ? e.clientX : e.clientY);

  // While dragging, the pointer keeps the resize arrows over whatever it crosses.
  useEffect(() => {
    if (!dragging) return;
    const root = document.documentElement;
    root.dataset.resizing = vertical ? "col" : "row";
    return () => {
      delete root.dataset.resizing;
    };
  }, [dragging, vertical]);

  const end = (e: PointerEvent<HTMLDivElement>) => {
    if (drag.current?.id !== e.pointerId) return;
    drag.current = undefined;
    setDragging(false);
    onDone();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const [less, more] = vertical ? ["ArrowLeft", "ArrowRight"] : ["ArrowUp", "ArrowDown"];
    const keys: Record<string, number | undefined> = {
      [less]: size - sign * STEP,
      [more]: size + sign * STEP,
      Home: min,
      End: max,
    };
    const to = keys[e.key];
    if (to === undefined) return;
    e.preventDefault();
    onResize(clamp(to));
    onDone();
  };

  return (
    <div
      role="separator"
      aria-orientation={orientation}
      aria-label={label}
      aria-valuenow={size}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      title={`${label} (double-click for the default ${vertical ? "width" : "height"})`}
      data-dragging={dragging || undefined}
      className={cn(
        "relative z-20 shrink-0 bg-rule outline-none before:absolute",
        // The grip: 3 px either side of the rule.
        vertical
          ? "w-px cursor-col-resize before:inset-y-0 before:-right-[3px] before:-left-[3px]"
          : "h-px cursor-row-resize before:inset-x-0 before:-top-[3px] before:-bottom-[3px]",
        "hover:bg-amber hover:shadow-[0_0_0_1px_var(--amber)] focus-visible:bg-amber focus-visible:shadow-[0_0_0_1px_var(--amber)]",
        "data-dragging:bg-amber data-dragging:shadow-[0_0_0_1px_var(--amber)]",
        className,
      )}
      onPointerDown={(e) => {
        if (e.button !== 0) return;
        // No text selection, and the keyboard focus stays where it was.
        e.preventDefault();
        e.currentTarget.setPointerCapture?.(e.pointerId);
        drag.current = { id: e.pointerId, at: at(e), size };
        setDragging(true);
      }}
      onPointerMove={(e) => {
        const d = drag.current;
        if (d?.id === e.pointerId) onResize(clamp(d.size + sign * (at(e) - d.at)));
      }}
      onPointerUp={end}
      onPointerCancel={end}
      onLostPointerCapture={end}
      onDoubleClick={onReset}
      onKeyDown={onKeyDown}
    />
  );
}
