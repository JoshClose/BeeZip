// Installing 7-Zip from wherever opening an archive failed without it (docs/M6.md §3.8): the tab,
// toasts, the jobs list, the job window from Explorer's menu, and Settings.
import { openUrl } from "@tauri-apps/plugin-opener";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SevenZipFix } from "../components/SevenZipFix";
import { Toasts } from "../components/ui/toasts";
import { Browser } from "../features/browser/Browser";
import { JobWindow, type RunStep } from "../features/job/JobWindow";
import { cancelledText, JobsPanel, outputSummary } from "../features/jobs/JobsPanel";
import { SevenZipSettings } from "../features/settings/SevenZipSettings";
import type { ArchiveExtractOutput, CmdError, EntryInfo, FormatsListOutput, JobEvent, SevenZipInstallOutput, SevenZipStatus } from "../gen/commands";
import { useArchives } from "../lib/archives";
import { useJobs } from "../lib/jobs";
import { DOWNLOAD_URL, needsSevenZip, useSevenZip } from "../lib/sevenZip";
import { toastError, useToasts } from "../lib/toasts";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn(async () => {}), revealItemInDir: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true), open: vi.fn(async () => null), save: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ emit: vi.fn(async () => {}), listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
const win = {
  destroy: vi.fn(async () => {}),
  setTitle: vi.fn(async (_title: string) => {}),
  onCloseRequested: vi.fn(async () => () => {}),
  scaleFactor: vi.fn(async () => 1),
  innerSize: vi.fn(async () => ({ toLogical: (_scale: number) => ({ width: 480, height: 260 }) })),
  setSize: vi.fn(async (_size: { width: number; height: number }) => {}),
};
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => win }));

const WIM = String.raw`C:\images\boot.wim`;
const SEVEN_ZIP = String.raw`C:\Program Files\7-Zip\7z.exe`;

const missing = (fix: SevenZipStatus["fix"], problem = "not found"): SevenZipStatus => ({
  name: null,
  path: null,
  found_in: null,
  problem,
  min_version: "25.01",
  fix,
});
const found: SevenZipStatus = { name: "7-Zip 26.06", path: SEVEN_ZIP, found_in: "registry", problem: null, min_version: "25.01", fix: null };

const noSevenZip: CmdError = {
  code: "BackendUnavailable",
  message: "Opening this WIM image needs 7-Zip 25.01 or newer. Install it from 7-zip.org, or set its path in Settings.",
};
const noRar: CmdError = { code: "BackendUnavailable", message: "this build of BeeZip reads no RAR archives (built without the `rar` feature)" };

/** What `formats.list` says about 7-Zip now; the fake install changes it. */
let status: SevenZipStatus;

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((res) => (resolve = res));
  return { promise, resolve };
}

/** A fake `seven_zip.install` that waits for `done`, reporting winget's lines meanwhile. */
function installs(done: Promise<void>, action: SevenZipInstallOutput["action"] = "installed") {
  fake.handlers.set("seven_zip.install", async (_args, emit) => {
    emit({ type: "Log", level: "Info", message: "Found 7-Zip [7zip.7zip] Version 26.06" } as JobEvent);
    emit({ type: "Progress", bytes_done: 0, bytes_total: null, entries_done: 0, entries_total: null, current: "Downloading https://github.com/ip7z/7zip/…" } as JobEvent);
    await done;
    status = found;
    return { action, status: found } satisfies SevenZipInstallOutput;
  });
}

beforeEach(() => {
  fake.reset();
  status = missing("install");
  fake.handlers.set("formats.list", () => ({ formats: [], codecs: [], create: [], seven_zip: status }) as unknown as FormatsListOutput);
  useSevenZip.setState({ status: undefined, installing: false, arrived: 0 });
  useJobs.setState({ jobs: {}, order: [] });
  useToasts.setState({ toasts: [] });
  useArchives.setState({ tabs: [], active: undefined });
  vi.mocked(openUrl).mockClear();
  win.destroy.mockClear();
});

describe("what the page says", () => {
  it("tells 7-Zip's errors from the others", () => {
    expect(needsSevenZip(noSevenZip)).toBe(true);
    expect(needsSevenZip(noRar)).toBe(false);
    expect(needsSevenZip({ code: "Corrupt", message: "7-Zip says: Data Error" })).toBe(false);
    expect(needsSevenZip(undefined)).toBe(false);
  });

  it("says a test of one entry in the singular", () => {
    expect(outputSummary("archive.test", { archive: "a.zip", entries: 1, bytes: 10 })).toBe("The 1 entry is OK (10 B read)");
    expect(outputSummary("archive.test", { archive: "a.zip", entries: 3, bytes: 10 })).toBe("All 3 entries are OK (10 B read)");
  });

  it("says what an install did", () => {
    const out = (action: SevenZipInstallOutput["action"], s: SevenZipStatus) => outputSummary("seven_zip.install", { action, status: s });
    expect(out("installed", found)).toBe(`Installed 7-Zip 26.06 at ${SEVEN_ZIP}`);
    expect(out("updated", found)).toBe(`Updated to 7-Zip 26.06 at ${SEVEN_ZIP}`);
    expect(out("none", found)).toBe(`7-Zip 26.06 at ${SEVEN_ZIP} is new enough; nothing to do`);
    expect(out("installed", missing(null, "turned off in Settings"))).toBe("Installed 7-Zip, but BeeZip doesn't use it: turned off in Settings");
    // A cancelled install's line is its last warning.
    const declined = "The administrator prompt was declined, so 7-Zip wasn't installed.";
    expect(cancelledText({ command: "seven_zip.install", logs: [{ level: "Info", message: "Found" }, { level: "Warn", message: declined }] })).toBe(declined);
    expect(cancelledText({ command: "seven_zip.install", logs: [] })).toBe("Cancelled. 7-Zip wasn't installed.");
    expect(cancelledText({ command: "archive.extract", logs: [] })).toMatch(/^Cancelled\. Files/);
  });
});

describe("the button", () => {
  it("names the fix formats.list gives, and nothing for another error", async () => {
    status = missing("update", `7-Zip 23.01 at ${SEVEN_ZIP} is too old`);
    const { rerender } = render(<SevenZipFix error={noSevenZip} />);
    expect(await screen.findByRole("button", { name: /Update 7-Zip/ })).toBeInTheDocument();

    rerender(<SevenZipFix error={noRar} />);
    expect(screen.queryByRole("button")).toBeNull();

    // Turned off, or a path set in Settings: there's nothing to install.
    status = missing(null, "turned off in Settings");
    rerender(<SevenZipFix error={{ ...noSevenZip }} />);
    await waitFor(() => expect(screen.queryByRole("button")).toBeNull());
  });

  it("opens the download page where there's no winget", async () => {
    status = missing("download");
    render(
      <>
        <SevenZipFix error={noSevenZip} />
        <Toasts />
      </>,
    );
    await userEvent.setup().click(await screen.findByRole("button", { name: /Get 7-Zip/ }));
    expect(openUrl).toHaveBeenCalledWith(DOWNLOAD_URL);
    expect(screen.getByText("Get 7-Zip from its download page")).toBeInTheDocument();
    expect(fake.calls.some((c) => c.name === "seven_zip.install")).toBe(false);
  });

  it("is in an error toast", async () => {
    render(<Toasts />);
    toastError(noSevenZip, "Testing boot.wim");
    expect(await screen.findByRole("button", { name: /Install 7-Zip/ })).toBeInTheDocument();
  });
});

describe("a tab that needs 7-Zip", () => {
  function Live({ id }: { id: string }) {
    const tab = useArchives((s) => s.tabs.find((t) => t.id === id));
    return tab ? <Browser tab={tab} /> : null;
  }

  it("installs it, says so, and lists again", async () => {
    const listed: EntryInfo = { id: 1, path: "Windows", kind: "dir", size: null, packed_size: null, modified: null, crc32: null, method: null, encrypted: false, target: null };
    fake.handlers.set("archive.list", () => {
      if (!status.name) throw noSevenZip;
      return { entries: [listed], total: 1, offset: 0, dir: "" };
    });
    const done = deferred<void>();
    installs(done.promise);
    const id = useArchives.getState().open(WIM);
    render(
      <>
        <Live id={id} />
        <JobsPanel />
        <Toasts />
      </>,
    );
    expect(await screen.findByText("Couldn't open boot.wim")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Install 7-Zip/ }));

    // While winget runs: the button waits, and the jobs list shows winget's line.
    expect(await screen.findByRole("button", { name: /Installing 7-Zip/ })).toBeDisabled();
    expect(await screen.findByRole("region", { name: "Jobs" })).toHaveTextContent("Installing 7-Zip");
    expect(screen.getByText(/Downloading https:\/\/github\.com/)).toBeInTheDocument();

    done.resolve();
    expect(await screen.findByText("7-Zip 26.06 installed")).toBeInTheDocument();
    expect(await screen.findByText("Windows")).toBeInTheDocument();
    // Listed again once: the tab's version went up by one.
    expect(useArchives.getState().tabs[0].version).toBe(1);
    expect(useSevenZip.getState().arrived).toBe(1);
  });

  it("a declined administrator prompt leaves the line in the jobs list, and no error toast", async () => {
    const declined = "The administrator prompt was declined, so 7-Zip wasn't installed.";
    fake.handlers.set("seven_zip.install", (_args, emit) => {
      emit({ type: "Log", level: "Warn", message: declined } as JobEvent);
      throw { code: "Cancelled", message: declined };
    });
    render(
      <>
        <SevenZipFix error={noSevenZip} />
        <JobsPanel />
        <Toasts />
      </>,
    );
    await userEvent.setup().click(await screen.findByRole("button", { name: /Install 7-Zip/ }));
    expect(await screen.findByText(declined, { selector: "p" })).toBeInTheDocument();
    expect(useToasts.getState().toasts).toEqual([]);
    expect(await screen.findByRole("button", { name: /Install 7-Zip/ })).toBeEnabled();
  });
});

describe("Settings → 7-Zip", () => {
  it("looks for 7-Zip afresh rather than showing what an earlier ask found", async () => {
    // An earlier ask found 7-Zip; it has gone since.
    useSevenZip.setState({ status: found });
    status = missing("install");
    const answer = deferred<void>();
    fake.handlers.set("formats.list", async () => {
      await answer.promise;
      return { formats: [], codecs: [], create: [], seven_zip: status } as unknown as FormatsListOutput;
    });
    render(<SevenZipSettings config={{ path: null, enabled: true }} errors={{}} save={vi.fn()} />);
    expect(screen.getByText("Looking for 7-Zip…")).toBeInTheDocument();
    expect(screen.queryByText(/Using 7-Zip/)).toBeNull();

    answer.resolve();
    expect(await screen.findByText(/No 7-Zip to use/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Install 7-Zip/ })).toBeInTheDocument();
  });
});

describe("the job window", () => {
  const step: RunStep = {
    kind: "run",
    title: "Extracting boot.wim",
    command: "archive.extract",
    args: { archive: WIM, dest: String.raw`C:\images`, smart: true },
  };
  const extracted: ArchiveExtractOutput = {
    dest: String.raw`C:\images\boot`,
    files: 3,
    dirs: 1,
    links: 0,
    bytes: 2048,
    skipped: [],
    skipped_total: 0,
    renamed: [],
    renamed_total: 0,
    unsafe_total: 0,
    dry_run: false,
    plan: null,
  };

  it("installs 7-Zip with its progress, then tries the step again", async () => {
    fake.handlers.set("archive.extract", () => {
      if (!status.name) throw noSevenZip;
      return extracted;
    });
    const done = deferred<void>();
    installs(done.promise);
    render(<JobWindow job={{ steps: [step], close_when_done: false }} />);
    expect(await screen.findByRole("heading", { name: "Extracting boot.wim failed" })).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Install 7-Zip/ }));

    // The install's progress shows in the window, under its own title, with Cancel.
    expect(await screen.findByText(/Downloading https:\/\/github\.com/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Installing 7-Zip" })).toBeInTheDocument();
    expect(document.querySelector(".comb-mark")).toHaveAttribute("data-state", "running");
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument();

    done.resolve();
    await user.click(await screen.findByRole("button", { name: /Try again/ }));
    expect(await screen.findByRole("heading", { name: "Done" })).toBeInTheDocument();
    expect(screen.getByText(/Extracted 3 files/)).toBeInTheDocument();
    expect(fake.calls.filter((c) => c.name === "archive.extract")).toHaveLength(2);
  });

  it("shows why an install failed, since the window has no toasts", async () => {
    fake.handlers.set("archive.extract", () => {
      throw noSevenZip;
    });
    fake.handlers.set("seven_zip.install", () => {
      throw { code: "Io", message: "winget couldn't download 7-Zip's installer. Check the internet connection, then try again." };
    });
    render(<JobWindow job={{ steps: [step], close_when_done: false }} />);
    await userEvent.setup().click(await screen.findByRole("button", { name: /Install 7-Zip/ }));
    expect(await screen.findByText(/Io: winget couldn't download/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Install 7-Zip/ })).toBeEnabled();
  });
});
