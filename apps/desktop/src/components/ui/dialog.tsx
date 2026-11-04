import { Dialog as Radix } from "radix-ui";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

/** A modal dialog: a title, a body, and a row of actions at the bottom. */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  className,
  dismissable = true,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  className?: string;
  /** Prompts can't be dismissed by clicking outside; they need an answer. */
  dismissable?: boolean;
}) {
  return (
    <Radix.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <Radix.Portal>
        <Radix.Overlay className="fixed inset-0 z-40 bg-black/30" />
        <Radix.Content
          onPointerDownOutside={(e) => !dismissable && e.preventDefault()}
          onInteractOutside={(e) => !dismissable && e.preventDefault()}
          className={cn(
            "fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] w-[34rem] max-w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 flex-col",
            "rounded-[8px] border border-rule bg-panel shadow-[0_12px_40px_rgba(0,0,0,0.25)]",
            className,
          )}
        >
          <div className="flex items-start justify-between gap-4 px-5 pt-4 pb-2">
            <div>
              <Radix.Title className="text-[15px] font-semibold">{title}</Radix.Title>
              {description ? (
                <Radix.Description className="mt-0.5 text-muted">{description}</Radix.Description>
              ) : (
                <Radix.Description className="sr-only">{title}</Radix.Description>
              )}
            </div>
            {dismissable && (
              <Radix.Close className="rounded p-1 text-muted hover:bg-sunken hover:text-ink" aria-label="Close" tabIndex={-1}>
                <X className="size-4" />
              </Radix.Close>
            )}
          </div>
          <div className="min-h-0 flex-1 overflow-auto px-5 py-2">{children}</div>
          {footer && <div className="flex flex-wrap items-center justify-end gap-2 border-t border-rule px-5 py-3">{footer}</div>}
        </Radix.Content>
      </Radix.Portal>
    </Radix.Root>
  );
}
