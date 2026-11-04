// Which dialog is open. One at a time; prompts are separate and sit above them.
import { create } from "zustand";
import type { CmdError } from "../gen/commands";

export type DialogState =
  | { kind: "extract"; tab: string; entries: string[] }
  | { kind: "create"; inputs: string[] }
  | { kind: "about" }
  | { kind: "info"; tab: string }
  | { kind: "form"; command: string }
  | { kind: "report"; title: string; error: CmdError };

type UiState = {
  dialog?: DialogState;
  palette: boolean;
  show: (dialog: DialogState) => void;
  closeDialog: () => void;
  setPalette: (open: boolean) => void;
};

export const useUi = create<UiState>((set) => ({
  palette: false,
  show(dialog) {
    set({ dialog, palette: false });
  },
  closeDialog() {
    set({ dialog: undefined });
  },
  setPalette(palette) {
    set({ palette });
  },
}));
