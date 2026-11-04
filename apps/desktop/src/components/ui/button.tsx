import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes } from "react";
import { cn } from "../../lib/cn";

const button = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-[5px] text-[13px] " +
    "transition-colors disabled:pointer-events-none disabled:opacity-45 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "border border-rule bg-panel text-ink hover:bg-sunken",
        primary: "bg-amber text-paper hover:brightness-110 font-semibold",
        ghost: "text-ink hover:bg-sunken",
        danger: "border border-rule bg-panel text-danger hover:bg-sunken",
      },
      size: {
        md: "h-8 px-3",
        sm: "h-7 px-2",
        icon: "size-7",
      },
    },
    defaultVariants: { variant: "default", size: "md" },
  },
);

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof button>;

export function Button({ className, variant, size, type = "button", ...props }: ButtonProps) {
  return <button type={type} className={cn(button({ variant, size }), className)} {...props} />;
}
