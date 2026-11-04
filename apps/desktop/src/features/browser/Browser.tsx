// One archive's view: breadcrumb and actions, folder tree, entry table, preview.
import { ArrowUp, ChevronRight, FolderOutput, Info, RotateCw, ShieldCheck } from "lucide-react";
import { type KeyboardEvent, type MouseEvent, useCallback, useEffect } from "react";
import { Button } from "../../components/ui/button";
import type { EntryInfo } from "../../gen/commands";
import { type Tab, useArchives } from "../../lib/archives";
import { archiveParent, describeError, formatSize, normalize } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { toastError, toastInfo } from "../../lib/toasts";
import { useUi } from "../../lib/ui";
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

/** Runs `archive.test` on a tab's archive, from the toolbar or the palette. */
export function testArchive(tab: Tab) {
  useJobs
    .getState()
    .track("archive.test", { archive: tab.path, ...(tab.password ? { password: tab.password } : {}) }, { title: `Testing ${tab.name}`, tab: tab.id })
    .then(
      (out) => toastInfo(`${tab.name} is OK`, `${out.entries} entries, ${formatSize(out.bytes)} checked.`),
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

  // Info, for the solid-archive note and the status line, once the first page is in.
  useEffect(() => {
    if (!ready || tab.info) return;
    useJobs
      .getState()
      .track("archive.info", { archive: tab.path, ...(tab.password ? { password: tab.password } : {}) }, { title: `Reading ${tab.name}`, quiet: true, tab: tab.id })
      .then((info) => update(tab.id, { info }), () => {});
  }, [ready, tab.id, tab.path, tab.name, tab.info, tab.password, update]);

  const selection: Selection = { selected: tab.selected, all: tab.all, anchor: tab.anchor, focus: tab.focus };

  const apply = useCallback(
    (sel: Selection) => {
      // One file selected shows it; one folder clears the pane; several keep what it shows.
      const one = !sel.all && sel.selected.length === 1 ? listing.row(sel.selected[0]) : undefined;
      const preview = one ? (one.kind === "dir" ? undefined : one) : tab.preview;
      update(tab.id, { ...sel, preview });
    },
    [listing, tab.id, tab.preview, update],
  );

  const open = (index: number) => {
    const e = listing.row(index);
    if (e?.kind === "dir") setDir(tab.id, normalize(e.path));
  };

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
    }
  };

  const extract = () => show({ kind: "extract", tab: tab.id, entries: selectedPaths(tab, listing.loaded()) });
  const selected = count(selection, total);

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
        <Button onClick={() => update(tab.id, (t) => ({ version: t.version + 1 }))}>
          <RotateCw /> List again
        </Button>
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
        </div>
      </div>
      <div className="flex min-h-0 flex-1">
        <aside className="w-52 shrink-0 border-r border-rule">{ready && <FolderTree tab={tab} ready={ready} />}</aside>
        <main className="flex min-w-0 flex-1 flex-col bg-panel">{table}</main>
        <aside className="w-80 shrink-0 border-l border-rule max-[1000px]:hidden">
          <Preview tab={tab} />
        </aside>
      </div>
      <div className="tabular flex h-6 shrink-0 items-center gap-4 border-t border-rule px-3 text-[12px] text-muted">
        <span>{ready ? `${total.toLocaleString()} ${total === 1 ? "item" : "items"}` : ""}</span>
        {selected > 0 && <span>{selected.toLocaleString()} selected</span>}
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
