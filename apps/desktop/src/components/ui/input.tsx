import type { InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { cn } from "../../lib/cn";

const field =
  "rounded-[5px] border border-rule bg-panel px-2 text-[13px] text-ink placeholder:text-muted " +
  "focus-visible:outline-2 focus-visible:outline-amber disabled:opacity-50";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(field, "h-8 min-w-0", className)} {...props} />;
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(field, "min-h-16 py-1.5", className)} {...props} />;
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cn(field, "h-8 pr-6", className)} {...props} />;
}

/** A labelled row in a dialog's form. */
export function Field({
  label,
  hint,
  htmlFor,
  children,
}: {
  label: string;
  hint?: string;
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[9rem_1fr] items-start gap-x-3 gap-y-0.5">
      <label htmlFor={htmlFor} className="pt-1.5 text-muted">
        {label}
      </label>
      <div className="flex min-w-0 flex-col gap-1">
        {children}
        {hint && <p className="text-[12px] text-muted">{hint}</p>}
      </div>
    </div>
  );
}
