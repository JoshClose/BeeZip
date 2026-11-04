/** What Rust puts in `window.__BEEZIP__` before the page's scripts run (src-tauri/src/open.rs). */
export type Startup = {
  /** Files `BeeZip.exe` was started with, absolute. */
  paths: string[];
  /** How "Copy as CLI" starts its line. */
  cli: string;
  /** Problems with config.toml. */
  warnings: string[];
};

declare global {
  interface Window {
    __BEEZIP__?: Startup;
  }
}

export function startup(): Startup {
  return window.__BEEZIP__ ?? { paths: [], cli: "beezip", warnings: [] };
}
