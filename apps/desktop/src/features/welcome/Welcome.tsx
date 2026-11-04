// Shown with no archive open: open one, start a new one, or drop files.
import { FilePlus2, FolderOpen } from "lucide-react";
import { Button } from "../../components/ui/button";
import { cn } from "../../lib/cn";

/** A honeycomb cell, the drop target's outline. */
function Cell({ active }: { active: boolean }) {
  return (
    <svg viewBox="0 0 120 104" className="h-24 w-28" aria-hidden>
      <polygon
        points="30,2 90,2 118,52 90,102 30,102 2,52"
        fill={active ? "var(--amber-wash)" : "none"}
        stroke="var(--amber-fill)"
        strokeWidth="2.5"
        strokeDasharray={active ? undefined : "7 6"}
        strokeLinejoin="round"
      />
      <path d="M60 30v38M44 52l16 16 16-16" stroke="var(--amber)" strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Welcome({ dragging, onOpen, onNew }: { dragging: boolean; onOpen: () => void; onNew: () => void }) {
  return (
    <div className="flex flex-1 items-center justify-center p-8">
      <div
        className={cn(
          "flex w-full max-w-[34rem] flex-col items-start gap-5 rounded-[10px] border p-8 transition-colors",
          dragging ? "border-amber-fill bg-amber-wash/40" : "border-transparent",
        )}
      >
        <Cell active={dragging} />
        <div>
          <h1 className="text-[22px] leading-tight font-semibold">{dragging ? "Drop to open" : "Drop files here"}</h1>
          <p className="mt-1.5 max-w-[46ch] text-muted">
            Drop an archive to browse it, or files and folders to pack them into a new one. BeeZip reads zip, 7z, RAR, tar
            and compressed files, split archives included.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="primary" onClick={onOpen}>
            <FolderOpen /> Open archive…
          </Button>
          <Button onClick={onNew}>
            <FilePlus2 /> New archive…
          </Button>
        </div>
        <p className="text-[12px] text-muted">Ctrl+K lists every command.</p>
      </div>
    </div>
  );
}
