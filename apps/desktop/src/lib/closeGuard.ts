// Closing a window with jobs running asks first, then waits for them to remove their partial
// files (docs/M3.md §5.6). The main window and the job windows both use it.
import { getCurrentWindow } from "@tauri-apps/api/window";
import { ask } from "@tauri-apps/plugin-dialog";
import { useEffect } from "react";
import { cancel } from "./engine";
import { useJobs } from "./jobs";

/** How long closing waits for cancelled jobs, as quitting does in Rust. */
const WAIT_MS = 10_000;

/** `verb` says what closing does: the main window quits, a job window closes. */
export function useCloseGuard(verb: "quit" | "close") {
  useEffect(() => {
    const win = getCurrentWindow();
    const unlisten = win.onCloseRequested(async (event) => {
      const running = Object.values(useJobs.getState().jobs).filter((j) => j.status === "running" && !j.quiet);
      if (running.length === 0) return;
      event.preventDefault();
      const n = running.length;
      const ok = await ask(`${n} ${n === 1 ? "job is" : "jobs are"} running. Cancel ${n === 1 ? "it" : "them"} and ${verb}?`, {
        title: "BeeZip",
        kind: "warning",
        okLabel: `Cancel and ${verb}`,
        cancelLabel: "Keep working",
      });
      if (!ok) return;
      await Promise.all(running.map((j) => cancel(j.id).catch(() => false)));
      const deadline = Date.now() + WAIT_MS;
      while (Date.now() < deadline && Object.values(useJobs.getState().jobs).some((j) => j.status === "running")) {
        await new Promise((r) => setTimeout(r, 50));
      }
      await win.destroy();
    });
    return () => void unlisten.then((f) => f());
  }, [verb]);
}
