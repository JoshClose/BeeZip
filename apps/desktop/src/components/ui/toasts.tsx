import { X } from "lucide-react";
import { useToasts } from "../../lib/toasts";
import { cn } from "../../lib/cn";

export function Toasts() {
  const toasts = useToasts((s) => s.toasts);
  const dismiss = useToasts((s) => s.dismiss);
  return (
    <div className="pointer-events-none fixed right-4 bottom-12 z-[60] flex w-[22rem] flex-col gap-2" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={cn(
            "pointer-events-auto flex items-start gap-2 rounded-[6px] border bg-panel px-3 py-2 shadow-[0_6px_20px_rgba(0,0,0,0.18)]",
            t.tone === "error" ? "border-danger/40" : "border-rule",
          )}
        >
          <div className="min-w-0 flex-1">
            <p className={cn("font-semibold", t.tone === "error" && "text-danger")}>{t.title}</p>
            {t.body && <p className="selectable break-words text-muted">{t.body}</p>}
          </div>
          <button className="rounded p-0.5 text-muted hover:text-ink" onClick={() => dismiss(t.id)} aria-label="Dismiss">
            <X className="size-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}
