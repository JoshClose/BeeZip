// 7-Zip for the formats BeeZip leaves to it (docs/M6.md §3.8): what `formats.list` says about
// it, the install or update that `seven_zip.install` runs with winget, and what follows when it
// arrives: listings that failed without it list again.
import { openUrl } from "@tauri-apps/plugin-opener";
import { create } from "zustand";
import type { SevenZipFix, SevenZipStatus } from "../gen/commands";
import { describeError } from "./format";
import { forgetFormats, loadFormats } from "./formats";
import { useJobs } from "./jobs";
import { startup } from "./startup";
import { toastError, toastInfo } from "./toasts";

export const DOWNLOAD_URL = "https://7-zip.org/download.html";

/** Whether an error is a missing, old or unusable 7-Zip. RAR in a build without it is also
 * `BackendUnavailable`, so the message decides: 7-Zip's always names it. */
export function needsSevenZip(err: unknown): boolean {
  if (!err) return false;
  const { code, message } = describeError(err);
  return code === "BackendUnavailable" && message.includes("7-Zip");
}

/** The button's words for a fix. */
export function fixLabel(fix: SevenZipFix): string {
  return { install: "Install 7-Zip", update: "Update 7-Zip", download: "Get 7-Zip…" }[fix];
}

/** What to do on the download page, on this platform. */
export function downloadHint(min = "25.01"): string {
  const platform = startup().platform;
  if (platform === "linux") {
    return `Take 7-Zip ${min} or newer for Linux from 7-zip.org: 7-Zip's own 7zz, since distributions' packages are usually older. Put 7zz on PATH, or choose it in Settings → 7-Zip.`;
  }
  if (platform === "macos") {
    return `Take 7-Zip ${min} or newer for macOS from 7-zip.org, and put its 7zz on PATH, or choose it in Settings → 7-Zip.`;
  }
  return `Install 7-Zip ${min} or newer from 7-zip.org. BeeZip finds it as soon as it's installed.`;
}

type SevenZipState = {
  /** What `formats.list` said last; `undefined` until asked. */
  status?: SevenZipStatus;
  /** An install or update is running. */
  installing: boolean;
  /** Counts the times 7-Zip arrived: a listing that failed without it lists again. */
  arrived: number;
};

export const useSevenZip = create<SevenZipState>(() => ({ installing: false, arrived: 0 }));

let asking: Promise<SevenZipStatus | undefined> | undefined;

/** Asks `formats.list` again; callers at the same time share one ask. */
export function refreshSevenZip(): Promise<SevenZipStatus | undefined> {
  asking ??= (async () => {
    forgetFormats();
    try {
      const status = (await loadFormats()).seven_zip;
      useSevenZip.setState({ status });
      return status;
    } catch {
      return undefined;
    } finally {
      asking = undefined;
    }
  })();
  return asking;
}

/** Runs a fix: winget installs or updates 7-Zip as a job, or the download page opens. */
export async function fixSevenZip(fix: SevenZipFix): Promise<void> {
  if (fix === "download") {
    await openUrl(DOWNLOAD_URL).catch(() => {});
    toastInfo("Get 7-Zip from its download page", downloadHint(useSevenZip.getState().status?.min_version));
    return;
  }
  if (useSevenZip.getState().installing) return;
  useSevenZip.setState({ installing: true });
  const title = fix === "update" ? "Updating 7-Zip" : "Installing 7-Zip";
  try {
    const out = await useJobs.getState().track("seven_zip.install", {}, { title });
    forgetFormats();
    const status = out.status;
    useSevenZip.setState((s) => ({ status, arrived: status.name ? s.arrived + 1 : s.arrived }));
    if (status.name) {
      const done = { installed: "installed", updated: "updated", none: "is ready" }[out.action];
      toastInfo(`${status.name} ${done}`, `BeeZip opens NSIS installers and CramFS images with ${status.path ?? "it"}.`);
    } else {
      toastInfo("7-Zip is installed, but BeeZip doesn't use it", `${status.problem ?? "Its settings"}: change that in Settings → 7-Zip.`);
    }
  } catch (e) {
    // A declined administrator prompt is a cancel: its job's line says so, without a toast.
    toastError(e, title);
    void refreshSevenZip();
  } finally {
    useSevenZip.setState({ installing: false });
  }
}
