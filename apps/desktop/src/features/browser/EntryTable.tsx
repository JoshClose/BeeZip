// The entry table: TanStack Virtual over pages of `archive.list` (docs/M3.md §5.2). Only the
// rows in view exist in the DOM, so a folder of a million entries scrolls like one of ten.
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, File, FileImage, FileText, Folder, Link2, Lock } from "lucide-react";
import { type KeyboardEvent, type MouseEvent, useEffect, useMemo, useRef } from "react";
import type { EntryInfo, SortKey } from "../../gen/commands";
import type { Renaming } from "../../lib/archives";
import { cn } from "../../lib/cn";
import { baseName, formatCrc, formatSize, formatTime, previewKind } from "../../lib/format";
import { RenameCell } from "../edit/RenameCell";
import { isSelected, type Selection } from "./select";

export const ROW_HEIGHT = 26;
const HEADER_HEIGHT = 28;

const COLUMNS: { key: SortKey; label: string; align?: "right" | "center" }[] = [
  { key: "name", label: "Name" },
  { key: "size", label: "Size", align: "right" },
  { key: "packed", label: "Packed", align: "right" },
  { key: "modified", label: "Modified" },
  { key: "method", label: "Method" },
  { key: "crc", label: "CRC" },
  { key: "encrypted", label: "Encrypted", align: "center" },
];

const GRID = "grid grid-cols-[minmax(9rem,1fr)_4.75rem_7.5rem_7.5rem_4.75rem_4.5rem_1.75rem] items-center gap-x-2.5 px-3";

export type EntryTableProps = {
  total: number;
  row: (index: number) => EntryInfo | undefined;
  ensure: (from: number, to: number) => void;
  sort?: SortKey;
  reverse: boolean;
  selection: Selection;
  onSort: (key: SortKey) => void;
  onClick: (index: number, e: MouseEvent) => void;
  onOpen: (index: number) => void;
  onKeyDown: (e: KeyboardEvent<HTMLDivElement>) => void;
  /** The row whose name is a field (docs/M5.md §8.1). */
  renaming?: Renaming;
  onRenameSave?: (name: string) => void;
  onRenameCancel?: () => void;
  /** For jsdom, which has no layout. */
  initialHeight?: number;
};

function EntryIcon({ entry }: { entry: EntryInfo }) {
  const cls = "size-4 shrink-0";
  if (entry.kind === "dir") return <Folder className={cn(cls, "text-amber")} />;
  if (entry.kind === "symlink" || entry.kind === "hardlink") return <Link2 className={cn(cls, "text-muted")} />;
  const kind = previewKind(entry.path);
  if (kind === "image") return <FileImage className={cn(cls, "text-muted")} />;
  if (kind === "text") return <FileText className={cn(cls, "text-muted")} />;
  return <File className={cn(cls, "text-muted")} />;
}

/** Packed size, with the share of the real size it takes as a thin amber fill. */
function Packed({ entry }: { entry: EntryInfo }) {
  if (entry.kind === "dir" || entry.packed_size === null) return null;
  const size = entry.size ?? 0;
  const share = size > 0 ? Math.min(1, entry.packed_size / size) : undefined;
  return (
    <span
      className="flex items-center justify-end gap-2"
      title={share === undefined ? undefined : `${Math.round(share * 100)}% of its size`}
    >
      <span className="tabular">{formatSize(entry.packed_size)}</span>
      <span className="h-1 w-8 shrink-0 overflow-hidden rounded-full bg-sunken" aria-hidden>
        {share !== undefined && <span className="block h-full bg-amber-fill" style={{ width: `${Math.max(4, share * 100)}%` }} />}
      </span>
    </span>
  );
}

function Cells({ entry, rename }: { entry: EntryInfo; rename?: { renaming: Renaming; onSave: (name: string) => void; onCancel: () => void } }) {
  const name = baseName(entry.path);
  return (
    <>
      <span className="flex min-w-0 items-center gap-2">
        <EntryIcon entry={entry} />
        {rename ? (
          <RenameCell path={rename.renaming.path} busy={rename.renaming.busy} error={rename.renaming.error} onSave={rename.onSave} onCancel={rename.onCancel} />
        ) : (
          <>
            <span className="truncate">{name}</span>
            {entry.target && entry.kind === "symlink" && <span className="truncate text-muted">→ {entry.target}</span>}
          </>
        )}
      </span>
      <span className="tabular text-right">{entry.kind === "dir" ? "" : formatSize(entry.size)}</span>
      <Packed entry={entry} />
      <span className="tabular truncate text-muted">{formatTime(entry.modified)}</span>
      {/* A folder's method and CRC are placeholders in its zip record. */}
      <span className="truncate text-muted">{entry.kind === "dir" ? "" : (entry.method ?? "")}</span>
      <span className="font-mono text-[12px] text-muted">{entry.kind === "dir" ? "" : formatCrc(entry.crc32)}</span>
      <span className="flex justify-center">{entry.encrypted && <Lock className="size-3.5 text-amber" aria-label="encrypted" />}</span>
    </>
  );
}

export function EntryTable(props: EntryTableProps) {
  const { total, row, ensure, sort, reverse, selection, onSort, onClick, onOpen, onKeyDown, renaming, onRenameSave, onRenameCancel } = props;
  const scroller = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: total,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 30,
    // The header sits above the rows inside the same scroller.
    scrollMargin: HEADER_HEIGHT,
    initialRect: { width: 900, height: props.initialHeight ?? 600 },
  });
  const items = virtualizer.getVirtualItems();
  const first = items[0]?.index;
  const last = items[items.length - 1]?.index;

  useEffect(() => {
    if (first !== undefined && last !== undefined) ensure(first, last);
  }, [first, last, ensure]);

  useEffect(() => {
    if (selection.focus !== undefined) virtualizer.scrollToIndex(selection.focus, { align: "auto" });
  }, [selection.focus, virtualizer]);

  const set = useMemo(() => new Set(selection.selected), [selection.selected]);

  return (
    <div
      ref={scroller}
      className="min-h-0 min-w-0 flex-1 overflow-auto outline-none focus-visible:outline-none"
      tabIndex={0}
      onKeyDown={onKeyDown}
      role="grid"
      aria-rowcount={total}
      aria-label="Entries"
      data-testid="entry-scroller"
    >
      <div className="min-w-[45rem]">
        <div
          className={cn(GRID, "sticky top-0 z-10 border-b border-rule bg-panel text-[12px] text-muted")}
          style={{ height: HEADER_HEIGHT }}
          role="row"
        >
          {COLUMNS.map((c) => {
            const active = sort === c.key;
            return (
              <button
                key={c.key}
                role="columnheader"
                aria-sort={active ? (reverse ? "descending" : "ascending") : "none"}
                className={cn(
                  "flex h-full items-center gap-1 truncate hover:text-ink",
                  c.align === "right" && "justify-end",
                  c.align === "center" && "justify-center",
                  active && "text-ink",
                )}
                onClick={() => onSort(c.key)}
                title={`Sort by ${c.label.toLowerCase()}`}
                tabIndex={-1}
              >
                {c.key === "encrypted" ? <Lock className="size-3.5" aria-label="Encrypted" /> : c.label}
                {active && (reverse ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />)}
              </button>
            );
          })}
        </div>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {items.map((item) => {
            const entry = row(item.index);
            const selected = isSelected(selection, set, item.index);
            return (
              <div
                key={item.key}
                role="row"
                aria-rowindex={item.index + 1}
                aria-selected={selected}
                className={cn(
                  GRID,
                  "absolute inset-x-0 cursor-default",
                  selected ? "bg-amber-wash" : "hover:bg-sunken",
                  selection.focus === item.index && "shadow-[inset_2px_0_0_var(--amber)]",
                )}
                style={{ height: ROW_HEIGHT, transform: `translateY(${item.start - HEADER_HEIGHT}px)` }}
                onMouseDown={(e) => {
                  if (e.button === 0) onClick(item.index, e);
                }}
                onDoubleClick={() => {
                  if (renaming?.index !== item.index) onOpen(item.index);
                }}
              >
                {entry ? (
                  <Cells
                    entry={entry}
                    rename={
                      renaming?.index === item.index && onRenameSave && onRenameCancel
                        ? { renaming, onSave: onRenameSave, onCancel: onRenameCancel }
                        : undefined
                    }
                  />
                ) : (
                  <span className="h-2 w-40 rounded bg-sunken" aria-label="Loading" />
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
