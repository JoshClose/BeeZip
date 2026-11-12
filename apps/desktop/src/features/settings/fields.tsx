// The settings page's fields (docs/M4.md §7.4). Each saves as soon as it changes; text waits
// until typing pauses or the field loses focus. An error shows under the field it belongs to.
import { RotateCcw } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Field, Input, Select, Textarea } from "../../components/ui/input";
import { cn } from "../../lib/cn";

/** How long text waits after the last keystroke before it saves. */
export const TEXT_DELAY_MS = 600;

export function Section({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-3 border-b border-rule py-4 first:pt-1 last:border-b-0">
      <div>
        <h3 className="text-[13px] font-semibold">{title}</h3>
        {description && <p className="text-[12px] text-muted">{description}</p>}
      </div>
      {children}
    </section>
  );
}

/** A field, with its error underneath. */
export function Setting({
  label,
  hint,
  htmlFor,
  error,
  children,
}: {
  label: string;
  hint?: string;
  htmlFor?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <Field label={label} hint={hint} htmlFor={htmlFor}>
      {children}
      {error && (
        <p role="alert" className="selectable text-[12px] text-danger">
          {error}
        </p>
      )}
    </Field>
  );
}

/** Calls `commit` once typing pauses, or at once on blur; `flush` sends what's pending. */
function useDelayedCommit<T>(commit: (value: T) => void) {
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const pending = useRef<{ value: T } | undefined>(undefined);
  const latest = useRef(commit);
  latest.current = commit;
  const flush = () => {
    clearTimeout(timer.current);
    const p = pending.current;
    pending.current = undefined;
    if (p) latest.current(p.value);
  };
  const schedule = (value: T) => {
    pending.current = { value };
    clearTimeout(timer.current);
    timer.current = setTimeout(flush, TEXT_DELAY_MS);
  };
  // Leaving the page still saves the last edit.
  useEffect(() => () => flush(), []);
  return { schedule, flush, isPending: () => pending.current !== undefined };
}

/** A whole number. Empty puts the setting back to its default (`null`). */
export function NumberSetting({
  id,
  value,
  min = 0,
  placeholder,
  onCommit,
  className,
}: {
  id: string;
  value: number | null;
  min?: number;
  placeholder?: string;
  onCommit: (value: number | null) => void;
  className?: string;
}) {
  const [text, setText] = useState(value === null ? "" : String(value));
  const { schedule, flush, isPending } = useDelayedCommit(onCommit);
  // A saved value comes back from the engine; don't overwrite what's still being typed.
  useEffect(() => {
    if (!isPending()) setText(value === null ? "" : String(value));
  }, [value]);
  return (
    <Input
      id={id}
      inputMode="numeric"
      className={cn("w-36", className)}
      value={text}
      placeholder={placeholder}
      onChange={(e) => {
        const t = e.target.value.trim();
        setText(e.target.value);
        if (t === "") schedule(null);
        else if (/^\d+$/.test(t) && Number(t) >= min) schedule(Number(t));
      }}
      onBlur={flush}
    />
  );
}

/** One path. Empty sets it back to its default (`null`). */
export function PathSetting({
  id,
  value,
  placeholder,
  onCommit,
}: {
  id: string;
  value: string | null;
  placeholder?: string;
  onCommit: (value: string | null) => void;
}) {
  const [text, setText] = useState(value ?? "");
  const { schedule, flush, isPending } = useDelayedCommit(onCommit);
  useEffect(() => {
    if (!isPending()) setText(value ?? "");
  }, [value]);
  return (
    <Input
      id={id}
      className="min-w-0 flex-1"
      value={text}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => {
        setText(e.target.value);
        const t = e.target.value.trim();
        schedule(t === "" ? null : t);
      }}
      onBlur={flush}
    />
  );
}

/** One path per line. */
export function PathsSetting({ id, value, onCommit }: { id: string; value: string[]; onCommit: (value: string[]) => void }) {
  const [text, setText] = useState(value.join("\n"));
  const { schedule, flush, isPending } = useDelayedCommit(onCommit);
  useEffect(() => {
    if (!isPending()) setText(value.join("\n"));
  }, [value]);
  return (
    <Textarea
      id={id}
      rows={2}
      value={text}
      placeholder="None"
      onChange={(e) => {
        setText(e.target.value);
        schedule(
          e.target.value
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(Boolean),
        );
      }}
      onBlur={flush}
    />
  );
}

export function ChoiceSetting<T extends string>({
  id,
  value,
  options,
  onCommit,
}: {
  id: string;
  value: T;
  options: { id: T; label: string }[];
  onCommit: (value: T) => void;
}) {
  return (
    <Select id={id} className="w-80 max-w-full" value={value} onChange={(e) => onCommit(e.target.value as T)}>
      {options.map((o) => (
        <option key={o.id} value={o.id}>
          {o.label}
        </option>
      ))}
    </Select>
  );
}

export function CheckSetting({
  checked,
  label,
  disabled,
  onCommit,
}: {
  checked: boolean;
  label: string;
  disabled?: boolean;
  onCommit: (value: boolean) => void;
}) {
  return (
    <div className="pt-1">
      <Checkbox checked={checked} onChange={onCommit} label={label} disabled={disabled} />
    </div>
  );
}

/**
 * Buttons side by side, one of them chosen: a radio group, so Tab reaches the chosen one and
 * the arrow keys move the choice.
 */
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { id: T; label: string }[];
  onChange: (value: T) => void;
}) {
  const move = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    const at = options.findIndex((o) => o.id === value);
    const next = options[(at + step + options.length) % options.length];
    onChange(next.id);
    e.currentTarget.querySelector<HTMLElement>(`[data-id="${next.id}"]`)?.focus();
  };
  return (
    <div role="radiogroup" aria-label={label} onKeyDown={move} className="flex w-fit rounded-[5px] border border-rule bg-paper p-0.5">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          role="radio"
          data-id={o.id}
          aria-checked={o.id === value}
          tabIndex={o.id === value ? 0 : -1}
          onClick={() => o.id !== value && onChange(o.id)}
          className={cn(
            "h-7 rounded-[4px] px-3 text-[13px] text-muted hover:text-ink",
            o.id === value && "bg-panel font-semibold text-ink shadow-[0_1px_2px_rgba(0,0,0,0.12)]",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/**
 * A `[levels]` name's level: a slider, dimmed at its own default until one is set, with what
 * it applies to underneath.
 */
export function LevelSetting({
  name,
  range,
  own,
  applies,
  others,
  value,
  error,
  onCommit,
}: {
  name: string;
  /** The levels everything it applies to takes. */
  range: { min: number; max: number };
  own: number;
  applies: string;
  /** The formats whose own default differs, shown while none is set. */
  others: string | null;
  value: number | undefined;
  error?: string;
  onCommit: (value: number | null) => void;
}) {
  const [shown, setShown] = useState(value);
  const { schedule, flush, isPending } = useDelayedCommit(onCommit);
  useEffect(() => {
    if (!isPending()) setShown(value);
  }, [value]);
  const id = `level-${name}`;
  return (
    <div className="grid grid-cols-[9rem_1fr] items-start gap-x-3">
      <label htmlFor={id} className="leading-7 text-muted">
        {name}
      </label>
      <div className="flex flex-col gap-0.5">
        <div className="flex h-7 items-center gap-3">
          <input
            id={id}
            type="range"
            min={range.min}
            max={range.max}
            value={shown ?? own}
            aria-describedby={`${id}-applies`}
            onChange={(e) => {
              setShown(Number(e.target.value));
              schedule(Number(e.target.value));
            }}
            onPointerUp={flush}
            onKeyUp={flush}
            className={cn("w-48 accent-[var(--amber)]", shown === undefined && "opacity-60")}
          />
          <span className={cn("tabular w-20 text-[12px]", shown === undefined && "text-muted")}>{shown === undefined ? `${own} (default)` : shown}</span>
          {shown !== undefined && (
            <Button
              size="sm"
              variant="ghost"
              aria-label={`Put ${name} back to its default`}
              title={others ? "Back to the defaults" : `Back to the default, ${own}`}
              onClick={() => {
                setShown(undefined);
                onCommit(null);
              }}
            >
              <RotateCcw />
            </Button>
          )}
        </div>
        <p id={`${id}-applies`} className="text-[12px] text-muted">
          {applies}
          {shown === undefined && others && ` ${others}`}
        </p>
        {error && (
          <p role="alert" className="selectable text-[12px] text-danger">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
