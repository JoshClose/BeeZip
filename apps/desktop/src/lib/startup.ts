import { invoke } from "@tauri-apps/api/core";
import type { Step, Theme } from "../gen/commands";

/** A dialog the main window opens by itself, for a click on Explorer's menu (src-tauri/src/open.rs). */
export type OpenDialog = { dialog: "extract" | "create"; paths: string[] };

/** A job window's work (src-tauri/src/job.rs): the steps of one click on Explorer's menu. */
export type JobStartup = {
  steps: Step[];
  /** `[jobs] close_when_done`: the window closes itself after a clean success. */
  close_when_done: boolean;
};

/** What Rust puts in `window.__BEEZIP__` before the page's scripts run (src-tauri/src/open.rs). */
export type Startup = {
  /** Archives to open, absolute. */
  paths: string[];
  /** How "Copy as CLI" starts its line. */
  cli: string;
  /** Problems with config.toml. */
  warnings: string[];
  /** `[desktop] theme`, which the window opened with. */
  theme: Theme;
  /** A dialog to open at once (main window). */
  dialog?: OpenDialog;
  /** Set in a job window, which shows only its job (docs/M4.md §6.3). */
  job?: JobStartup;
};

declare global {
  interface Window {
    __BEEZIP__?: Startup;
  }
}

export function startup(): Startup {
  return { paths: [], cli: "beezip", warnings: [], theme: "system", ...window.__BEEZIP__ };
}

/** Archives and a dialog forwarded before the main window listened (src-tauri/src/open.rs). */
export type Launched = { paths: string[]; dialog: OpenDialog | null };

/**
 * Tells Rust the page now listens for `open-paths` and `open-dialog`, and takes what a second
 * BeeZip.exe forwarded before that (docs/M6.md §8.1).
 */
export function launched(): Promise<Launched> {
  return invoke<Launched>("cmd_launched");
}
