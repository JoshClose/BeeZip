// The jobs panel when there's a lot to show: the edge that makes it taller, a log in full,
// Copy, and the whole text of a line cut short on hover.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { JobsPanel, jobText, LOG_SHOWN, outputSummary } from "../features/jobs/JobsPanel";
import { type JobRecord, newJob, useJobs } from "../lib/jobs";
import { usePanes } from "../lib/panes";
import { useToasts } from "../lib/toasts";

vi.mock("../lib/engine", () => import("./fakeEngine"));

const LONG = "Extracting a-very-long-archive-name-that-does-not-fit-the-panel-at-all.tar.zst";

function job(id: number, patch: Partial<JobRecord>): JobRecord {
  return { ...newJob(id, "archive.extract", {}, { title: `Job ${id}` }, 0), ...patch };
}

function show(...records: JobRecord[]) {
  useJobs.setState({ jobs: Object.fromEntries(records.map((r) => [r.id, r])), order: records.map((r) => r.id) });
  render(<JobsPanel />);
}

const warnings = (n: number) => Array.from({ length: n }, (_, i) => ({ level: "Warn" as const, message: `skipped file-${i}` }));

beforeEach(() => {
  localStorage.clear();
  usePanes.setState({ tree: 208, preview: 320, jobs: null });
  useToasts.setState({ toasts: [] });
});

describe("a job as text", () => {
  it("says a test of one entry in the singular", () => {
    expect(outputSummary("archive.test", { archive: "a.zip", entries: 1, bytes: 10 })).toBe("The 1 entry is OK (10 B read)");
    expect(outputSummary("archive.test", { archive: "a.zip", entries: 3, bytes: 10 })).toBe("All 3 entries are OK (10 B read)");
  });

  it("has its title, how it ended and its whole log", () => {
    const failed = job(1, { status: "failed", error: { code: "Corrupt", message: "bad CRC in b.txt" }, logs: [{ level: "Info", message: "Waiting" }, ...warnings(2)] });
    expect(jobText(failed)).toBe("Job 1\nCorrupt: bad CRC in b.txt\n\nWaiting\nWarning: skipped file-0\nWarning: skipped file-1");
    expect(jobText(job(2, { status: "cancelled" }))).toBe("Job 2\nCancelled.");
    expect(jobText(job(3, { logs: warnings(1) }))).toBe("Job 3\n\nWarning: skipped file-0");
    const done = job(4, { status: "finished", command: "archive.test", output: { entries: 2, bytes: 10, note: null } as never });
    expect(jobText(done)).toBe("Job 4\nAll 2 entries are OK (10 B read)");
  });
});

describe("the jobs panel", () => {
  it("shows a log in the list itself, its first lines when it's very long", () => {
    show(job(1, { status: "failed", error: { code: "Corrupt", message: "bad CRC" }, logs: warnings(LOG_SHOWN + 500) }));
    fireEvent.click(screen.getByRole("button", { name: `Log (${LOG_SHOWN + 500})` }));
    const log = screen.getByRole("list", { name: "Job 1: log" });
    // No box of its own to scroll: the jobs list is the one scroller.
    expect(log.className).not.toMatch(/overflow|max-h/);
    expect(within(log).getByText("skipped file-0")).toBeInTheDocument();
    expect(within(log).getByText(`skipped file-${LOG_SHOWN - 1}`)).toBeInTheDocument();
    expect(within(log).queryByText(`skipped file-${LOG_SHOWN}`)).toBeNull();
    expect(log).toHaveTextContent("500 more lines: Copy takes the whole log.");
  });

  it("copies a job, its whole log included", async () => {
    const record = job(1, { status: "failed", error: { code: "Corrupt", message: "bad CRC" }, logs: warnings(LOG_SHOWN + 5) });
    show(record);
    const write = vi.mocked(navigator.clipboard.writeText);
    write.mockClear();
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
    expect(write).toHaveBeenCalledWith(jobText(record));
    expect(write.mock.calls[0][0]).toContain(`Warning: skipped file-${LOG_SHOWN + 4}`);
  });

  it("says so when the clipboard refuses", async () => {
    show(job(1, { status: "failed", error: { code: "Corrupt", message: "bad CRC" } }));
    vi.mocked(navigator.clipboard.writeText).mockRejectedValueOnce(new Error("no focus"));
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(useToasts.getState().toasts.map((t) => t.title)).toEqual(["Couldn't reach the clipboard"]));
  });

  it("has Copy only where there's an error or a log", () => {
    show(job(1, { status: "finished", command: "archive.test", output: { entries: 1, bytes: 1, note: null } as never }));
    expect(screen.queryByRole("button", { name: "Copy" })).toBeNull();
  });

  it("shows the whole of a line cut short on hover", () => {
    const current = "deep/folder/with/a/very/long/path/to/the/file/being/written/now.bin";
    show(job(1, { title: LONG, progress: { bytes_done: 1, bytes_total: 2, entries_done: 1, entries_total: 2, current } }));
    expect(screen.getAllByTitle(LONG).length).toBe(2); // the status line and the job's title
    expect(screen.getByTitle(current)).toHaveTextContent(current);
  });

  it("is made taller by its edge, which is kept, and fits its jobs again on a double-click", () => {
    show(job(1, { status: "failed", error: { code: "Corrupt", message: "bad CRC" } }));
    const list = screen.getByRole("list", { name: "Jobs list" });
    const edge = screen.getByRole("separator", { name: "Resize the jobs" });
    expect(edge).toHaveAttribute("aria-orientation", "horizontal");
    // Until dragged, it fits its jobs, up to 38% of the window.
    expect(list.style.height).toBe("");
    expect(list).toHaveClass("max-h-[38vh]");

    // The edge starts from the list's height as measured, which jsdom says is 0: a step up
    // gives the minimum. (The real app's steps are checked over DevTools.)
    fireEvent.keyDown(edge, { key: "ArrowUp" });
    expect(list.style.height).toBe("64px");
    expect(list).not.toHaveClass("max-h-[38vh]");
    expect(JSON.parse(localStorage.getItem("beezip.panes")!).jobs).toBe(64);

    fireEvent.doubleClick(edge);
    expect(list.style.height).toBe("");
    expect(list).toHaveClass("max-h-[38vh]");
    expect(JSON.parse(localStorage.getItem("beezip.panes")!).jobs).toBeUndefined();
  });

  it("has no edge while the list is hidden", () => {
    show(job(1, { status: "failed", error: { code: "Corrupt", message: "bad CRC" } }));
    fireEvent.click(screen.getByRole("button", { name: "Hide" }));
    expect(screen.queryByRole("separator")).toBeNull();
    expect(screen.queryByRole("list", { name: "Jobs list" })).toBeNull();
  });
});
