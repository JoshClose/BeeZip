// Updates (docs/M6.md §8.2): the check and the install run in Rust (src-tauri/src/update.rs);
// this store holds what the banner and About show.
import { Channel, invoke } from "@tauri-apps/api/core";
import { create } from "zustand";

/** What a check found (update.rs `Checked`). */
export type Checked =
  | { status: "off"; reason: string }
  | { status: "up_to_date"; version: string }
  | {
      status: "available";
      version: string;
      current: string;
      notes_url: string;
      /** A portable copy's new zip: such a copy doesn't install updates, so the banner links to it. */
      download_url?: string;
    };

/** How an install is going (update.rs `Progress`). */
export type Progress =
  | { stage: "downloading"; done: number; total: number | null }
  | { stage: "waiting"; jobs: number }
  | { stage: "installing" };

type UpdateState = {
  /** The newest check's answer. */
  checked?: Checked;
  /** A check is running. */
  checking: boolean;
  /** The banner was closed for this session. */
  dismissed: boolean;
  /** An install is under way. */
  progress?: Progress;
  /** Why the last check or install failed. */
  error?: string;
  /** Checks for an update: `force` (About's button) asks whatever the setting and the day. */
  check: (force: boolean) => Promise<void>;
  /** Downloads and installs the update found; BeeZip restarts. */
  install: () => Promise<void>;
  dismiss: () => void;
};

export const useUpdate = create<UpdateState>((set, get) => ({
  checking: false,
  dismissed: false,
  async check(force) {
    if (get().checking) return;
    set({ checking: true, error: undefined });
    try {
      const checked = await invoke<Checked>("cmd_update_check", { force });
      set({ checked, dismissed: get().dismissed && !force });
    } catch (e) {
      set({ error: String(e) });
    } finally {
      set({ checking: false });
    }
  },
  async install() {
    if (get().progress) return;
    const channel = new Channel<Progress>();
    channel.onmessage = (progress) => set({ progress });
    set({ progress: { stage: "downloading", done: 0, total: null }, error: undefined });
    try {
      // Resolves only if it fails: on success BeeZip exits and the installer restarts it.
      await invoke("cmd_update_install", { onProgress: channel });
    } catch (e) {
      set({ error: String(e) });
    }
    set({ progress: undefined });
  },
  dismiss() {
    set({ dismissed: true });
  },
}));
