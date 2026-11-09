import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { About } from "../features/about/About";
import { UpdateBanner } from "../features/update/UpdateBanner";
import { newJob, useJobs } from "../lib/jobs";
import { type Progress, useUpdate } from "../lib/updates";

// The channel the install reports through: the test plays Rust's part.
let channel: { onmessage?: (p: Progress) => void } | undefined;
vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {
    onmessage?: (p: Progress) => void;
    constructor() {
      // eslint-disable-next-line @typescript-eslint/no-this-alias
      channel = this;
    }
  },
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn(async () => {}) }));
vi.mock("../lib/engine", () => import("./fakeEngine"));

const available = { status: "available", version: "0.1.1", current: "0.1.0", notes_url: "https://github.com/JoshClose/BeeZip/releases/tag/v0.1.1" } as const;

beforeEach(() => {
  vi.mocked(invoke).mockReset();
  useUpdate.setState({ checked: undefined, checking: false, dismissed: false, progress: undefined, error: undefined });
  useJobs.setState({ jobs: {}, order: [] });
  channel = undefined;
});

describe("updates", () => {
  it("shows nothing until a check finds a newer version", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({ status: "up_to_date", version: "0.1.0" });
    render(<UpdateBanner />);
    await act(() => useUpdate.getState().check(false));
    expect(invoke).toHaveBeenCalledWith("cmd_update_check", { force: false });
    expect(screen.queryByRole("status", { name: "Update" })).toBeNull();

    vi.mocked(invoke).mockResolvedValueOnce(available);
    await act(() => useUpdate.getState().check(true));
    expect(invoke).toHaveBeenLastCalledWith("cmd_update_check", { force: true });
    expect(screen.getByRole("status", { name: "Update" })).toHaveTextContent("BeeZip 0.1.1 is available.");
    await userEvent.click(screen.getByRole("button", { name: "What's new" }));
    expect(openUrl).toHaveBeenCalledWith(available.notes_url);
  });

  it("waits for running jobs, and reports the install's progress", async () => {
    useUpdate.setState({ checked: available });
    useJobs.setState({ jobs: { 7: newJob(7, "archive.extract", {}, { title: "Extract a.zip" }, 0) }, order: [7] });
    render(<UpdateBanner />);
    const button = screen.getByRole("button", { name: "Update when the jobs finish" });

    let finish: (v: unknown) => void = () => {};
    vi.mocked(invoke).mockImplementationOnce(() => new Promise((_resolve, reject) => (finish = (e) => reject(e))));
    await userEvent.click(button);
    expect(invoke).toHaveBeenCalledWith("cmd_update_install", { onProgress: channel });
    act(() => channel?.onmessage?.({ stage: "downloading", done: 50, total: 200 }));
    expect(screen.getByText("Downloading… 25%")).toBeInTheDocument();
    act(() => channel?.onmessage?.({ stage: "waiting", jobs: 1 }));
    expect(screen.getByText("Waiting for a job to finish…")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Update/ })).toBeNull();

    // A failure comes back as a message, and the button again.
    await act(async () => finish("The update to 0.1.1 couldn't be downloaded: offline"));
    await waitFor(() => expect(screen.getByText(/couldn't be downloaded: offline/)).toBeInTheDocument());
    useJobs.setState({ jobs: {}, order: [] });
    expect(await screen.findByRole("button", { name: "Update and restart" })).toBeInTheDocument();
  });

  it("links a portable copy to the new zip instead of installing it", async () => {
    const zip = "https://github.com/JoshClose/BeeZip/releases/download/v0.1.1/BeeZip_0.1.1_x64-portable.zip";
    useUpdate.setState({ checked: { ...available, download_url: zip } });
    render(<UpdateBanner />);
    expect(screen.queryByRole("button", { name: /Update/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Download" }));
    expect(openUrl).toHaveBeenCalledWith(zip);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("can be put off for the session", async () => {
    useUpdate.setState({ checked: available });
    render(<UpdateBanner />);
    await userEvent.click(screen.getByRole("button", { name: "Not now" }));
    expect(screen.queryByRole("status", { name: "Update" })).toBeNull();
  });
});

describe("About", () => {
  it("checks for updates now, and says what it found", async () => {
    vi.mocked(invoke).mockResolvedValueOnce({ status: "up_to_date", version: "0.1.0" });
    render(<About onClose={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(invoke).toHaveBeenCalledWith("cmd_update_check", { force: true });
    expect(await screen.findByText("BeeZip 0.1.0 is the newest version.")).toBeInTheDocument();

    vi.mocked(invoke).mockResolvedValueOnce(available);
    await userEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(await screen.findByText("BeeZip 0.1.1 is available: the banner above the tabs installs it.")).toBeInTheDocument();
    vi.mocked(invoke).mockResolvedValueOnce({ ...available, download_url: "https://example.com/BeeZip.zip" });
    await userEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(await screen.findByText("BeeZip 0.1.1 is available: the banner above the tabs downloads it.")).toBeInTheDocument();

    vi.mocked(invoke).mockResolvedValueOnce({ status: "off", reason: "This build of BeeZip doesn't look for updates." });
    await userEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(await screen.findByText("This build of BeeZip doesn't look for updates.")).toBeInTheDocument();
  });
});
