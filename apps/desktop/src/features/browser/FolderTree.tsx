// The folder tree: each level listed lazily with `kind: "dir"`, the first time it opens.
import { ChevronRight, Folder, FolderArchive } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import type { EntryInfo } from "../../gen/commands";
import { archiveArgs, type Tab, useArchives } from "../../lib/archives";
import { cn } from "../../lib/cn";
import { baseName, normalize } from "../../lib/format";
import { useJobs } from "../../lib/jobs";

type Level = EntryInfo[] | "loading" | "failed";

/** `a/b/c` → [``, `a`, `a/b`]: the folders to open to show `c`. */
export function ancestors(dir: string): string[] {
  if (!dir) return [];
  const parts = dir.split("/");
  return parts.map((_, i) => parts.slice(0, i).join("/"));
}

export function FolderTree({ tab, ready }: { tab: Tab; ready: boolean }) {
  const setDir = useArchives((s) => s.setDir);
  const [levels, setLevels] = useState<Map<string, Level>>(new Map());
  const [open, setOpen] = useState<Set<string>>(new Set([""]));
  const reset = `${tab.path}\n${tab.version}`;
  // Levels asked for since the last reset, and that reset, so a late answer is dropped.
  const requested = useRef(new Set<string>());
  const generation = useRef(reset);

  useEffect(() => {
    requested.current = new Set();
    generation.current = reset;
    setLevels(new Map());
    setOpen(new Set([""]));
  }, [reset]);

  const load = useCallback(
    (dir: string) => {
      if (requested.current.has(dir)) return;
      requested.current.add(dir);
      const gen = generation.current;
      setLevels((m) => new Map(m).set(dir, "loading"));
      useJobs
        .getState()
        .track(
          "archive.list",
          {
            archive: tab.path,
            ...(dir ? { dir } : {}),
            kind: "dir",
            sort: "name",
            ...archiveArgs(tab),
          },
          { title: `Listing ${tab.name}`, quiet: true, tab: tab.id },
        )
        .then(
          (out) => gen === generation.current && setLevels((l) => new Map(l).set(dir, out.entries)),
          () => gen === generation.current && setLevels((l) => new Map(l).set(dir, "failed")),
        );
    },
    [tab.id, tab.path, tab.name],
  );

  // The tree waits for the first page of the table, so an encrypted archive asks once.
  useEffect(() => {
    if (!ready) return;
    const want = ["", ...ancestors(tab.dir), ...(tab.dir ? [tab.dir] : [])];
    setOpen((o) => new Set([...o, ...want]));
    for (const d of want) load(d);
  }, [ready, tab.dir, load, reset]);

  const toggle = (dir: string) => {
    const next = new Set(open);
    if (next.has(dir)) next.delete(dir);
    else {
      next.add(dir);
      load(dir);
    }
    setOpen(next);
  };

  const node = (dir: string, name: string, depth: number, root = false) => {
    const level = levels.get(dir);
    const isOpen = open.has(dir);
    const empty = Array.isArray(level) && level.length === 0;
    return (
      <li key={dir || "/"} role="treeitem" aria-expanded={empty ? undefined : isOpen} aria-selected={tab.dir === dir}>
        <div
          className={cn(
            "flex h-[26px] cursor-default items-center gap-1 rounded-[4px] pr-2",
            tab.dir === dir ? "bg-amber-wash" : "hover:bg-sunken",
          )}
          style={{ paddingLeft: 4 + depth * 14 }}
          onClick={() => setDir(tab.id, dir)}
        >
          <button
            className={cn("rounded p-0.5 text-muted hover:text-ink", empty && "invisible")}
            onClick={(e) => {
              e.stopPropagation();
              toggle(dir);
            }}
            aria-label={isOpen ? `Close ${name}` : `Open ${name}`}
            tabIndex={-1}
          >
            <ChevronRight className={cn("size-3.5 transition-transform", isOpen && "rotate-90")} />
          </button>
          {root ? <FolderArchive className="size-4 shrink-0 text-amber" /> : <Folder className="size-4 shrink-0 text-amber" />}
          <span className="truncate">{name}</span>
        </div>
        {isOpen && Array.isArray(level) && level.length > 0 && (
          <ul role="group">
            {level.map((e) => {
              const path = normalize(e.path);
              return node(path, baseName(path), depth + 1);
            })}
          </ul>
        )}
        {isOpen && level === "failed" && (
          <p className="text-muted" style={{ paddingLeft: 26 + depth * 14 }}>
            Couldn't list this folder.
          </p>
        )}
      </li>
    );
  };

  return (
    <nav className="h-full overflow-auto p-1.5" aria-label="Folders">
      <ul role="tree">{node("", tab.name, 0, true)}</ul>
    </nav>
  );
}
