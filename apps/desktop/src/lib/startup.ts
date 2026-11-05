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
