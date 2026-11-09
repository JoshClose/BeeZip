// Which dialog is open. One at a time; prompts are separate and sit above them.
import { create } from "zustand";
import type { CmdError } from "../gen/commands";

export type DialogState =
  /** `note` says why it opened: a drag-out too big to drag (docs/M6.md §8.4). */
  | { kind: "extract"; tab: string; entries: string[]; note?: string }
  /** `note` says why the files go into a new archive: the open one can't take them. */
  | { kind: "create"; inputs: string[]; note?: string }
  /** Files to add to a tab's archive, into its folder `dir` (docs/M5.md §8.1). */
  | { kind: "add"; tab: string; inputs: string[]; dir: string }
  /** The create dialog's convert mode, for a tab's archive (§8.5). */
  | { kind: "convert"; tab: string }
  | { kind: "about" }
  | { kind: "info"; tab: string }
  | { kind: "encoding"; tab: string }
  | { kind: "form"; command: string }
  | { kind: "report"; title: string; error: CmdError }
  | { kind: "settings" }
  /** The Benchmark dialog, offering `file` as its sample (docs/M6.md §7). */
  | { kind: "bench"; file?: string };

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
