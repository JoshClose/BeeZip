// One archive's view: breadcrumb and actions, folder tree, entry table, preview.
import { open as pickFiles } from "@tauri-apps/plugin-dialog";
import { ArrowRightLeft, ArrowUp, ChevronRight, FilePlus2, FolderOutput, FolderPlus, Info, PencilLine, RotateCw, ShieldCheck, Trash2 } from "lucide-react";
import { type KeyboardEvent, type MouseEvent, type ReactNode, useCallback, useEffect, useRef } from "react";
import { SevenZipFix } from "../../components/SevenZipFix";
import { Button } from "../../components/ui/button";
import { Splitter } from "../../components/ui/splitter";
import type { EntryInfo } from "../../gen/commands";
import { archiveArgs, type Tab, useArchives } from "../../lib/archives";
import { startDrag } from "../../lib/drag";
import { editBlocked, registerBrowser, type SelectionByPath } from "../../lib/edit";
import { archiveParent, describeError, formatSize, normalize } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { openEntry } from "../../lib/opened";
import { fit, MIN_WIDTHS, PREVIEW_FROM, usePanes, widest } from "../../lib/panes";
import { needsSevenZip, useSevenZip } from "../../lib/sevenZip";
import { useSize } from "../../lib/size";
import { startup } from "../../lib/startup";
import { toastError, toastInfo } from "../../lib/toasts";
import { useUi } from "../../lib/ui";
import { deleteSelection } from "../edit/confirmDelete";
import { cancelRename, saveRename, startRename } from "../edit/rename";
import { Preview } from "../preview/Preview";
import { EntryTable } from "./EntryTable";
import { FolderTree } from "./FolderTree";
import { click, count, moveTo, NONE, type Selection, selectAll } from "./select";
import { useListing } from "./useListing";

/** The archive paths the selection names, for `archive.extract --entries`. */
export function selectedPaths(tab: Tab, loaded: Map<number, EntryInfo>): string[] {
  if (tab.all) return tab.dir ? [tab.dir] : [];
  return tab.selected
    .map((i) => loaded.get(i))
    .filter((e): e is EntryInfo => e !== undefined)
    .map((e) => normalize(e.path));
}

/** Picks files or a folder, then opens the add dialog with them, into the folder shown. */
export async function pickAndAdd(tab: Tab, directory: boolean) {
  const picked = await pickFiles({ multiple: true, directory, title: directory ? `Add a folder to ${tab.name}` : `Add files to ${tab.name}` });
  const inputs = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
  if (inputs.length > 0) useUi.getState().show({ kind: "add", tab: tab.id, inputs, dir: tab.dir });
}

/** A tab's entry, opened with its app or as a tab (docs/M5.md §8.3). */
export function openFile(tab: Tab, entry: EntryInfo) {
  openEntry(tab, entry).catch((e) => toastError(e, `Opening ${entry.path}`));
}

/** A disabled command still says why on hover: a disabled button gets no pointer events. */
function Why({ reason, children }: { reason?: string; children: ReactNode }) {
  return reason ? (
    <span title={reason} className="inline-flex">
      {children}
    </span>
  ) : (
    children
  );
}

/** Runs `archive.test` on a tab's archive, from the toolbar or the palette. */
export function testArchive(tab: Tab) {
  useJobs
    .getState()
    .track("archive.test", { archive: tab.path, ...archiveArgs(tab) }, { title: `Testing ${tab.name}`, tab: tab.id })
    .then(
      // A disk image read through 7-Zip stores no checksums: the note says what was checked.
      (out) =>
        toastInfo(
          `${tab.name} is OK`,
          `${out.entries.toLocaleString()} ${out.entries === 1 ? "entry" : "entries"}, ${formatSize(out.bytes)} checked.${out.note ? ` ${out.note}` : ""}`,
        ),
      (e) => toastError(e, `Testing ${tab.name}`),
    );
}

function Breadcrumb({ tab }: { tab: Tab }) {
  const setDir = useArchives((s) => s.setDir);
  const parts = tab.dir ? tab.dir.split("/") : [];
  return (
    <nav className="flex min-w-0 items-center gap-0.5" aria-label="Path">
      <Button size="icon" variant="ghost" disabled={!tab.dir} onClick={() => setDir(tab.id, archiveParent(tab.dir))} aria-label="Up one folder" title="Up one folder (Backspace)">
        <ArrowUp />
      </Button>
      <button className="truncate rounded px-1.5 py-0.5 font-semibold hover:bg-sunken" onClick={() => setDir(tab.id, "")}>
        {tab.name}
      </button>
      {parts.map((p, i) => (
        <span key={i} className="flex min-w-0 items-center gap-0.5">
          <ChevronRight className="size-3.5 shrink-0 text-muted" />
          <button className="truncate rounded px-1.5 py-0.5 hover:bg-sunken" onClick={() => setDir(tab.id, parts.slice(0, i + 1).join("/"))}>
            {p}
          </button>
        </span>
      ))}
    </nav>
  );
}

export function Browser({ tab }: { tab: Tab }) {
  const update = useArchives((s) => s.update);
  const setDir = useArchives((s) => s.setDir);
  const setSort = useArchives((s) => s.setSort);
  const show = useUi((s) => s.show);
  const listing = useListing(tab);
  const total = listing.total ?? 0;
  const ready = listing.total !== undefined;

  // 7-Zip arrived (docs/M6.md §3.8): a listing that failed without it lists again.
  const arrived = useSevenZip((s) => s.arrived);
  const seen = useRef(arrived);
  useEffect(() => {
    if (arrived === seen.current) return;
    seen.current = arrived;
    if (needsSevenZip(listing.error)) update(tab.id, (t) => ({ version: t.version + 1 }));
  }, [arrived, listing.error, tab.id, update]);

  // Info, for the solid-archive note and the status line, once the first page is in.
  useEffect(() => {
    if (!ready || tab.info) return;
    useJobs
      .getState()
      .track("archive.info", { archive: tab.path, ...archiveArgs(tab) }, { title: `Reading ${tab.name}`, quiet: true, tab: tab.id })
      .then((info) => update(tab.id, { info }), () => {});
  }, [ready, tab.id, tab.path, tab.name, tab.info, tab.password, tab.encoding, update]);

  const selection: Selection = { selected: tab.selected, all: tab.all, anchor: tab.anchor, focus: tab.focus };

  const apply = useCallback(
    (sel: Selection) => {
      // One file selected shows it; one folder clears the pane; several keep what it shows.
      const one = !sel.all && sel.selected.length === 1 ? listing.row(sel.selected[0]) : undefined;
      const preview = one ? (one.kind === "dir" ? undefined : one) : tab.preview;
      update(tab.id, { ...sel, preview, reselect: undefined, renaming: undefined });
    },
    [listing, tab.id, tab.preview, update],
  );

  // The selection by path, for an edit to find again afterwards.
  const byPath = useCallback((): SelectionByPath => {
    const t = useArchives.getState().tabs.find((x) => x.id === tab.id);
    if (!t) return { all: false, paths: [] };
    const rows = listing.loaded();
    const paths = t.selected.map((i) => rows.get(i)).filter((e): e is EntryInfo => e !== undefined).map((e) => normalize(e.path));
    return { all: t.all, paths };
  }, [listing, tab.id]);

  // After an edit, the listing comes back with the rows that were selected (docs/M5.md §8.1).
  useEffect(() => {
    if (!tab.reselect || !ready || listing.stale) return;
    const want = new Set(tab.reselect);
    const found = [...listing.loaded()].filter(([, e]) => want.has(normalize(e.path))).map(([i]) => i);
    const one = found.length === 1 ? listing.row(found[0]) : undefined;
    update(tab.id, {
      reselect: undefined,
      selected: found,
      anchor: found[0],
      focus: found[0],
      preview: one && one.kind !== "dir" ? one : undefined,
    });
  }, [tab.reselect, ready, listing, tab.id, update]);

  const blocked = editBlocked(tab);

  const open = (index: number) => {
    const e = listing.row(index);
    if (e?.kind === "dir") setDir(tab.id, normalize(e.path));
    else if (e) openFile(tab, e);
  };

  /** The row F2 and the toolbar rename: the focused one, else the one selected. */
  const renameRow = (): number | undefined => {
    if (selection.focus !== undefined && (tab.all || tab.selected.includes(selection.focus))) return selection.focus;
    return !tab.all && tab.selected.length === 1 ? tab.selected[0] : undefined;
  };
  const rename = () => {
    const i = renameRow();
    if (i !== undefined) startRename(tab, i, listing.row(i)?.path);
  };
  const remove = () => {
    if (!blocked) void deleteSelection(tab, count(selection, total), byPath());
  };

  const extract = () => show({ kind: "extract", tab: tab.id, entries: selectedPaths(tab, listing.loaded()) });

  // The palette's Rename, Delete and Extract, and Ctrl+E, act through the browser, which has the rows.
  const latest = useRef({ selection: byPath, rename, remove, extract });
  latest.current = { selection: byPath, rename, remove, extract };
  useEffect(
    () =>
      registerBrowser(tab.id, {
        selection: () => latest.current.selection(),
        rename: () => latest.current.rename(),
        remove: () => latest.current.remove(),
        extract: () => latest.current.extract(),
      }),
    [tab.id],
  );

  const onClick = (index: number, e: MouseEvent) => apply(click(selection, index, { ctrl: e.ctrlKey || e.metaKey, shift: e.shiftKey }));

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const at = selection.focus ?? -1;
    const page = 20;
    const go = (to: number) => {
      e.preventDefault();
      apply(moveTo(selection, to, total, e.shiftKey));
    };
    switch (e.key) {
      case "ArrowDown":
        return go(at + 1);
      case "ArrowUp":
        return go(Math.max(0, at - 1));
      case "PageDown":
        return go(at + page);
      case "PageUp":
        return go(at - page);
      case "Home":
        return go(0);
      case "End":
        return go(total - 1);
      case "Enter":
        e.preventDefault();
        if (at >= 0) open(at);
        return;
      case "Backspace":
        e.preventDefault();
        if (tab.dir) setDir(tab.id, archiveParent(tab.dir));
        return;
      case "Escape":
        return apply(NONE);
      case "a":
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          apply(selectAll(selection));
        }
        return;
      case "Delete":
        e.preventDefault();
        remove();
        return;
      case "F2":
        e.preventDefault();
        if (!blocked) rename();
        return;
    }
  };

  /** A `dragstart` on row `index`: the selection, as it is now, goes out to Explorer (docs/M6.md §8.4). */
  const dragOut = (index: number) => {
    const t = useArchives.getState().tabs.find((x) => x.id === tab.id);
    if (!t || !(t.all || t.selected.includes(index))) return;
    const rows = listing.loaded();
    const picked = t.selected.map((i) => rows.get(i)).filter((e): e is EntryInfo => e !== undefined);
    void startDrag(t, t.all ? { all: true } : { all: false, rows: picked });
  };
  // Explorer is Windows's; elsewhere rows don't drag.
  const canDrag = startup().platform === "windows";
  const selected = count(selection, total);

  // The panes' widths: the ones dragged to, narrowed to fit the row as it is now.
  const panes = usePanes();
  const [rowRef, { width: row }] = useSize<HTMLDivElement>();
  const hasPreview = row === 0 || row >= PREVIEW_FROM;
  const shown = fit(panes, row, hasPreview);

  let table;
  if (listing.error && !ready) {
    const { code, message } = describeError(listing.error);
    table = (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
        <p className="font-semibold">{code === "Cancelled" ? "Listing was cancelled." : `Couldn't open ${tab.name}`}</p>
        {code !== "Cancelled" && (
          <p className="selectable max-w-[60ch] text-muted">
            {code}: {message}
          </p>
        )}
        <div className="flex gap-2">
          <Button onClick={() => update(tab.id, (t) => ({ version: t.version + 1 }))}>
            <RotateCw /> List again
          </Button>
          <SevenZipFix error={listing.error} size="md" variant="primary" />
        </div>
      </div>
    );
  } else if (!ready) {
    table = <p className="p-4 text-muted">Opening {tab.name}…</p>;
  } else {
    table = (
      <EntryTable
        total={total}
        row={listing.row}
        ensure={listing.ensure}
        sort={tab.sort}
        reverse={tab.reverse}
        selection={selection}
        onSort={(key) => setSort(tab.id, key)}
        onClick={onClick}
        onOpen={open}
        onKeyDown={onKeyDown}
        onDragOut={canDrag ? dragOut : undefined}
        renaming={tab.renaming}
        onRenameSave={(name) => void saveRename(tab, name)}
        onRenameCancel={() => cancelRename(tab)}
      />
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-11 shrink-0 items-center justify-between gap-3 border-b border-rule px-2">
        <Breadcrumb tab={tab} />
        <div className="flex shrink-0 items-center gap-1.5">
          <Button variant="primary" onClick={extract} disabled={!ready} title="Extract (Ctrl+E)">
            <FolderOutput /> {selected > 0 ? `Extract ${selected === 1 ? "1 item" : `${selected.toLocaleString()} items`}` : "Extract all"}
          </Button>
          <Button onClick={() => testArchive(tab)} disabled={!ready} title="Test the archive's integrity">
            <ShieldCheck /> Test
          </Button>
          <Button size="icon" onClick={() => show({ kind: "info", tab: tab.id })} disabled={!ready} aria-label="Archive info" title="Archive info">
            <Info />
          </Button>
          <span className="mx-1 h-5 w-px bg-rule" aria-hidden />
          <Why reason={blocked}>
            <Button size="icon" onClick={() => void pickAndAdd(tab, false)} disabled={!!blocked} aria-label="Add files…" title="Add files…">
              <FilePlus2 />
            </Button>
          </Why>
          <Why reason={blocked}>
            <Button size="icon" onClick={() => void pickAndAdd(tab, true)} disabled={!!blocked} aria-label="Add folder…" title="Add folder…">
              <FolderPlus />
            </Button>
          </Why>
          <Why reason={blocked}>
            <Button size="icon" onClick={rename} disabled={!!blocked || renameRow() === undefined} aria-label="Rename" title="Rename (F2)">
              <PencilLine />
            </Button>
          </Why>
          <Why reason={blocked}>
            <Button size="icon" variant="danger" onClick={remove} disabled={!!blocked || selected === 0} aria-label="Delete" title="Delete (Del)">
              <Trash2 />
            </Button>
          </Why>
          <Button size="icon" onClick={() => show({ kind: "convert", tab: tab.id })} disabled={!ready} aria-label="Convert…" title="Convert to another format…">
            <ArrowRightLeft />
          </Button>
        </div>
      </div>
      <div ref={rowRef} className="flex min-h-0 flex-1">
        <aside className="min-w-0 shrink-0" style={{ width: shown.tree }}>
          {ready && <FolderTree tab={tab} ready={ready} />}
        </aside>
        <Splitter
          label="Resize the folder tree"
          size={shown.tree}
          min={MIN_WIDTHS.tree}
          max={widest("tree", shown, row, hasPreview)}
          side="before"
          onResize={(w) => panes.resize("tree", w)}
          onDone={panes.save}
          onReset={() => panes.reset("tree")}
        />
        <main
          data-drop="entries"
          className={`flex min-w-0 flex-1 flex-col bg-panel transition-opacity ${listing.stale ? "opacity-60" : ""}`}
          aria-busy={listing.stale}
        >
          {table}
        </main>
        {hasPreview && (
          <>
            <Splitter
              label="Resize the preview"
              size={shown.preview}
              min={MIN_WIDTHS.preview}
              max={widest("preview", shown, row, hasPreview)}
              side="after"
              onResize={(w) => panes.resize("preview", w)}
              onDone={panes.save}
              onReset={() => panes.reset("preview")}
            />
            <aside className="min-w-0 shrink-0" style={{ width: shown.preview }}>
              <Preview tab={tab} />
            </aside>
          </>
        )}
      </div>
      <div className="tabular flex h-6 shrink-0 items-center gap-4 border-t border-rule px-3 text-[12px] text-muted">
        <span>{ready ? `${total.toLocaleString()} ${total === 1 ? "item" : "items"}` : ""}</span>
        {selected > 0 && <span>{selected.toLocaleString()} selected</span>}
        {tab.info?.not_editable && (
          <span className="min-w-0 truncate" title={tab.info.not_editable}>
            Can't be edited: {tab.info.not_editable}
          </span>
        )}
        {tab.info && (
          <span className="ml-auto truncate">
            {tab.info.chain}, {formatSize(tab.info.size)} in {formatSize(tab.info.packed_size)}
            {tab.info.encryption !== "none" ? ", encrypted" : ""}
            {tab.info.solid ? ", solid" : ""}
          </span>
        )}
      </div>
    </div>
  );
}
