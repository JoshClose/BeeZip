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
  /** Rust's `std::env::consts::OS`: the page leaves out what this platform doesn't have (docs/M6.md §8.3). */
  platform: "windows" | "macos" | "linux" | (string & {});
  /** Running from the Microsoft Store package: the Store updates BeeZip and provides its menu (docs/M12.md §3). */
  store?: boolean;
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
  return { paths: [], cli: "beezip", warnings: [], theme: "system", platform: "windows", store: false, ...window.__BEEZIP__ };
}

/**
 * Tells Rust once the page's first frame with content is on its surface. On Windows a window,
 * the main one or a job's, is kept off the screen until then, so it comes up with BeeZip in it,
 * not as an empty rectangle while WebView2 starts (src-tauri/src/reveal.rs). Where the browser doesn't time its
 * paints, it tells at once. A failure is left alone: Rust shows the window after a second anyway.
 */
export function ready(): void {
  const tell = () => {
    void Promise.resolve()
      .then(() => invoke("cmd_ready"))
      .catch(() => {});
  };
  if (typeof PerformanceObserver === "undefined" || !PerformanceObserver.supportedEntryTypes?.includes("paint")) {
    tell();
    return;
  }
  new PerformanceObserver((list, observer) => {
    if (list.getEntriesByName("first-contentful-paint").length === 0) return;
    observer.disconnect();
    tell();
  }).observe({ type: "paint", buffered: true });
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
