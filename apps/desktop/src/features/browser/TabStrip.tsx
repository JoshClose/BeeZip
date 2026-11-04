// One tab per open archive, with the app's actions at the right.
import { Command, FilePlus2, FolderOpen, Info, X } from "lucide-react";
import { Button } from "../../components/ui/button";
import { useArchives } from "../../lib/archives";
import { cn } from "../../lib/cn";
import { useUi } from "../../lib/ui";

export function TabStrip({ onOpen, onNew }: { onOpen: () => void; onNew: () => void }) {
  const tabs = useArchives((s) => s.tabs);
  const active = useArchives((s) => s.active);
  const activate = useArchives((s) => s.activate);
  const close = useArchives((s) => s.close);
  const show = useUi((s) => s.show);
  const setPalette = useUi((s) => s.setPalette);

  return (
    <header className="flex h-10 shrink-0 items-end gap-1 border-b border-rule bg-sunken px-2">
      <div className="flex min-w-0 flex-1 items-end gap-0.5 overflow-x-auto" role="tablist" aria-label="Open archives">
        {tabs.map((t) => (
          <div
            key={t.id}
            role="tab"
            aria-selected={t.id === active}
            tabIndex={0}
            title={t.path}
            onClick={() => activate(t.id)}
            onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && activate(t.id)}
            onAuxClick={(e) => e.button === 1 && close(t.id)}
            className={cn(
              "group flex h-8 max-w-56 min-w-0 cursor-default items-center gap-2 rounded-t-[6px] border border-b-0 pr-1 pl-3",
              t.id === active ? "border-rule bg-paper" : "border-transparent text-muted hover:bg-paper/60 hover:text-ink",
            )}
          >
            <span className="truncate">{t.name}</span>
            <button
              className="rounded p-0.5 opacity-60 hover:bg-sunken hover:opacity-100"
              onClick={(e) => {
                e.stopPropagation();
                close(t.id);
              }}
              aria-label={`Close ${t.name}`}
              tabIndex={-1}
            >
              <X className="size-3.5" />
            </button>
          </div>
        ))}
      </div>
      <div className="flex shrink-0 items-center gap-1 pb-1">
        <Button size="sm" variant="ghost" onClick={onOpen} title="Open an archive (Ctrl+O)">
          <FolderOpen /> Open
        </Button>
        <Button size="sm" variant="ghost" onClick={onNew} title="New archive (Ctrl+N)">
          <FilePlus2 /> New archive
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setPalette(true)} title="All commands (Ctrl+K)">
          <Command /> Commands
        </Button>
        <Button size="icon" variant="ghost" onClick={() => show({ kind: "about" })} aria-label="About BeeZip" title="About BeeZip">
          <Info />
        </Button>
      </div>
    </header>
  );
}
