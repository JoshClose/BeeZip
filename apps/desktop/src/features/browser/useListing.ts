// A tab's listing, fetched in pages of 1 000 as they scroll into view (docs/M3.md §5.2). The
// engine sorts and keeps each listing in its archive cache, so a page costs a lookup.
import { useCallback, useEffect, useRef, useState } from "react";
import type { CmdError, EntryInfo } from "../../gen/commands";
import { archiveArgs, type Tab } from "../../lib/archives";
import { useJobs } from "../../lib/jobs";

export const PAGE = 1000;

export type Listing = {
  /** `undefined` until the first page arrives. */
  total?: number;
  row: (index: number) => EntryInfo | undefined;
  /** Fetches the pages holding rows `from` to `to`, if they aren't here yet. */
  ensure: (from: number, to: number) => void;
  error?: CmdError;
  /** Rows by index, for the selection; only the loaded ones. */
  loaded: () => Map<number, EntryInfo>;
  /** The rows are the previous listing's, while this one loads. */
  stale: boolean;
};

type State = { key: string; total?: number; pages: Map<number, EntryInfo[]>; error?: CmdError };

export function listingKey(tab: Pick<Tab, "path" | "dir" | "sort" | "reverse" | "version" | "encoding">): string {
  return [tab.path, tab.dir, tab.sort ?? "", tab.reverse, tab.version, tab.encoding ?? ""].join("\n");
}

export function useListing(tab: Tab): Listing {
  const key = listingKey(tab);
  const [state, setState] = useState<State>({ key, pages: new Map() });
  const inflight = useRef(new Set<string>());
  const current = state.key === key ? state : { key, pages: new Map<number, EntryInfo[]>() };
  // Until a new listing's first page arrives (another folder, another sort), the last one stays
  // on screen rather than the table blinking out.
  const lastShown = useRef<State | undefined>(undefined);
  if (current.total !== undefined) lastShown.current = current;
  const stale =
    current.total === undefined && !current.error && lastShown.current?.key.startsWith(`${tab.path}\n`);
  const shown = stale && lastShown.current ? lastShown.current : current;

  const fetchPage = useCallback(
    (page: number) => {
      const id = `${key}\n${page}`;
      if (inflight.current.has(id)) return;
      inflight.current.add(id);
      // The password typed for this tab, if any, is read now rather than when the key was made.
      useJobs
        .getState()
        .track(
          "archive.list",
          {
            archive: tab.path,
            ...(tab.dir ? { dir: tab.dir } : {}),
            ...(tab.sort ? { sort: tab.sort, reverse: tab.reverse } : {}),
            offset: page * PAGE,
            limit: PAGE,
            ...archiveArgs(tab),
          },
          { title: `Listing ${tab.name}`, quiet: true, tab: tab.id },
        )
        .then(
          (out) => {
            setState((s) => {
              const base = s.key === key ? s : { key, pages: new Map<number, EntryInfo[]>() };
              const pages = new Map(base.pages);
              pages.set(page, out.entries);
              return { key, total: out.total, pages, error: undefined };
            });
          },
          (error: CmdError) => {
            setState((s) => ({ ...(s.key === key ? s : { key, pages: new Map() }), error }));
          },
        )
        .finally(() => inflight.current.delete(id));
    },
    // The key covers every input but the password, which is read when the page is fetched.
    [key],
  );

  useEffect(() => {
    if (state.key !== key) setState({ key, pages: new Map() });
    fetchPage(0);
  }, [key, fetchPage, state.key]);

  const ensure = useCallback(
    (from: number, to: number) => {
      if (current.total === undefined) return;
      const last = Math.min(to, current.total - 1);
      for (let p = Math.floor(Math.max(0, from) / PAGE); p <= Math.floor(last / PAGE); p++) {
        if (!current.pages.has(p)) fetchPage(p);
      }
    },
    [current.total, current.pages, fetchPage],
  );

  const row = useCallback(
    (index: number) => shown.pages.get(Math.floor(index / PAGE))?.[index % PAGE],
    [shown.pages],
  );

  const loaded = useCallback(() => {
    const out = new Map<number, EntryInfo>();
    for (const [p, rows] of current.pages) rows.forEach((r, i) => out.set(p * PAGE + i, r));
    return out;
  }, [current.pages]);

  return { total: shown.total, row, ensure, error: current.error, loaded, stale: Boolean(stale) };
}
