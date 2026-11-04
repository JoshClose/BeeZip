import { Checkbox as Radix } from "radix-ui";
import { Check } from "lucide-react";
import { useId } from "react";

export function Checkbox({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex items-center gap-2">
      <Radix.Root
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(v) => onChange(v === true)}
        className="flex size-4 shrink-0 items-center justify-center rounded-[3px] border border-rule bg-panel data-[state=checked]:border-amber data-[state=checked]:bg-amber disabled:opacity-50"
      >
        <Radix.Indicator>
          <Check className="size-3 text-paper" strokeWidth={3} />
        </Radix.Indicator>
      </Radix.Root>
      <label htmlFor={id} className={disabled ? "text-muted" : undefined}>
        {label}
      </label>
    </div>
  );
}
