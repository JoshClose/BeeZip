// Renaming in place (docs/M5.md §8.1): the name becomes a field. Enter saves, Escape cancels,
// and an error (a `Conflict`, say) shows beside it until the name changes.
import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import { baseName } from "../../lib/format";

export function RenameCell({
  path,
  busy,
  error,
  onSave,
  onCancel,
}: {
  path: string;
  busy: boolean;
  error?: string;
  onSave: (name: string) => void;
  onCancel: () => void;
}) {
  const original = baseName(path);
  const [name, setName] = useState(original);
  const [shown, setShown] = useState(error);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => setShown(error), [error]);

  // The name without its extension is selected, as Explorer does.
  useEffect(() => {
    const el = input.current;
    if (!el) return;
    el.focus();
    const dot = original.lastIndexOf(".");
    el.setSelectionRange(0, dot > 0 ? dot : original.length);
  }, [original]);

  // A disabled field loses the focus; after a refusal it gets it back, to try another name.
  useEffect(() => {
    if (!busy) input.current?.focus();
  }, [busy]);

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    // The table's keys (arrows, Delete, Enter) mustn't reach it while typing.
    e.stopPropagation();
    if (e.key === "Enter") {
      e.preventDefault();
      if (!busy) onSave(name);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onCancel();
    }
  };

  return (
    <span className="flex min-w-0 flex-1 items-center gap-2" onMouseDown={(e) => e.stopPropagation()} onDoubleClick={(e) => e.stopPropagation()}>
      <input
        ref={input}
        aria-label={`New name for ${original}`}
        aria-invalid={shown ? true : undefined}
        className="h-[22px] min-w-0 flex-1 rounded-[3px] border border-amber bg-panel px-1 text-[13px] outline-none disabled:opacity-60"
        value={name}
        disabled={busy}
        onChange={(e) => {
          setName(e.target.value);
          setShown(undefined);
        }}
        onKeyDown={onKeyDown}
        onBlur={() => {
          if (!busy) onCancel();
        }}
      />
      {shown && (
        <span role="alert" className="selectable max-w-[50%] shrink truncate text-[12px] text-danger" title={shown}>
          {shown}
        </span>
      )}
    </span>
  );
}
