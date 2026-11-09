// Short messages in the corner: errors with their code, and confirmations.
import { create } from "zustand";
import { describeError, isCancelled } from "./format";

/** `error` is the command's error a toast shows: one that needs 7-Zip gets its button. */
export type Toast = { id: number; tone: "error" | "info"; title: string; body?: string; error?: unknown };

type ToastState = {
  toasts: Toast[];
  push: (toast: Omit<Toast, "id">) => void;
  dismiss: (id: number) => void;
};

let next = 1;

export const useToasts = create<ToastState>((set) => ({
  toasts: [],
  push(toast) {
    const id = next++;
    set((s) => ({ toasts: [...s.toasts.slice(-4), { ...toast, id }] }));
    setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), toast.tone === "error" ? 10_000 : 5_000);
  },
  dismiss(id) {
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  },
}));

/** Shows a command's error, except a cancellation, which the person asked for. */
export function toastError(err: unknown, context?: string): void {
  if (isCancelled(err)) return;
  const { code, message } = describeError(err);
  useToasts.getState().push({ tone: "error", title: context ? `${context}: ${code}` : code, body: message, error: err });
}

export function toastInfo(title: string, body?: string): void {
  useToasts.getState().push({ tone: "info", title, body });
}
