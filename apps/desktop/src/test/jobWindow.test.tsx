import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { argsFor, isClean, JobWindow, revealTarget, type RunStep } from "../features/job/JobWindow";
import type { ArchiveExtractOutput, JobEvent, Step } from "../gen/commands";
import { cancel } from "../lib/engine";
import { useJobs } from "../lib/jobs";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
const win = {
  destroy: vi.fn(async () => {}),
  setTitle: vi.fn(async (_title: string) => {}),
  onCloseRequested: vi.fn(async () => () => {}),
  scaleFactor: vi.fn(async () => 1.5),
  innerSize: vi.fn(async () => ({ toLogical: (_scale: number) => ({ width: 480, height: 260 }) })),
  setSize: vi.fn(async (_size: { width: number; height: number }) => {}),
};
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => win }));
vi.mock("@tauri-apps/plugin-opener", () => ({ revealItemInDir: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true) }));

const extracted = (patch: Partial<ArchiveExtractOutput> = {}): ArchiveExtractOutput => ({
  dest: String.raw`C:\dl`,
  files: 3,
  dirs: 0,
  links: 0,
  bytes: 2048,
  skipped: [],
  skipped_total: 0,
  renamed: [],
  renamed_total: 0,
  unsafe_total: 0,
  dry_run: false,
  plan: null,
  ...patch,
});

const extract = (name: string): RunStep => ({
  kind: "run",
  title: `Extracting ${name}`,
  command: "archive.extract",
  args: { archive: `C:\\dl\\${name}`, dest: String.raw`C:\dl`, smart: true },
});

const create: RunStep = {
  kind: "run",
  title: "Creating work.zip",
  command: "archive.create",
  args: { output: String.raw`C:\w\work.zip`, inputs: [String.raw`C:\w\a.txt`] },
  existing: { path: String.raw`C:\w\work.zip`, keep_both: String.raw`C:\w\work (1).zip` },
};

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function show(steps: Step[], closeWhenDone = true) {
  return render(<JobWindow job={{ steps, close_when_done: closeWhenDone }} />);
}

describe("the job window's helpers", () => {
  it("answers an existing archive by replacing it or writing beside it", () => {
    expect(argsFor(create)).toEqual(create.args);
    expect(argsFor(create, "replace")).toMatchObject({ overwrite: true, output: String.raw`C:\w\work.zip` });
    expect(argsFor(create, "keep-both")).toMatchObject({ output: String.raw`C:\w\work (1).zip` });
    expect(argsFor(create, "keep-both")).not.toHaveProperty("overwrite");
  });

  it("reveals the archive when files went beside it, else what was written", () => {
    expect(revealTarget(extract("a.zip"), extracted())).toBe(String.raw`C:\dl\a.zip`);
    expect(revealTarget(extract("a.zip"), extracted({ dest: String.raw`C:\dl\a` }))).toBe(String.raw`C:\dl\a`);
    expect(revealTarget(create, { path: String.raw`C:\w\work.zip`, volumes: null })).toBe(String.raw`C:\w\work.zip`);
    expect(revealTarget(create, { path: "x", volumes: ["x.001", "x.002"] })).toBe("x.001");
    expect(revealTarget({ ...extract("a.zip"), command: "archive.test" }, {})).toBeUndefined();
  });

  it("calls an extraction clean only when nothing was skipped or renamed", () => {
    expect(isClean(extract("a.zip"), extracted())).toBe(true);
    expect(isClean(extract("a.zip"), extracted({ skipped_total: 1 }))).toBe(false);
    expect(isClean(extract("a.zip"), extracted({ renamed_total: 2 }))).toBe(false);
    expect(isClean(create, {})).toBe(true);
  });
});

describe("the job window", () => {
  beforeEach(() => {
    fake.reset();
    useJobs.setState({ jobs: {}, order: [] });
    win.destroy.mockClear();
    win.setTitle.mockClear();
    win.setSize.mockClear();
    vi.mocked(revealItemInDir).mockClear();
    vi.mocked(cancel).mockReset().mockResolvedValue(true);
  });

  it("runs the steps in order with their progress, then closes itself", async () => {
    const first = deferred<ArchiveExtractOutput>();
    fake.handlers.set("archive.extract", (args, emit) => {
      if ((args as { archive: string }).archive.endsWith("a.zip")) {
        emit({ type: "Progress", bytes_done: 1024, bytes_total: 4096, entries_done: 1, entries_total: 3, current: "docs/readme.txt" } as JobEvent);
        return first.promise;
      }
      return extracted();
    });
    show([extract("a.zip"), extract("b.zip")]);

    expect(await screen.findByText("docs/readme.txt")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Extracting a.zip" })).toBeInTheDocument();
    expect(screen.getByText("1 of 2")).toBeInTheDocument();
    expect(screen.getByText("1.0 KiB of 4.0 KiB")).toBeInTheDocument();
    // The native title is the step's from the start, never a placeholder.
    expect(win.setTitle.mock.calls.map((c) => c[0])).toEqual(["Extracting a.zip"]);
    expect(fake.calls).toHaveLength(1);

    first.resolve(extracted());
    expect(await screen.findByRole("heading", { name: "Done" })).toBeInTheDocument();
    expect(fake.calls.map((c) => (c.args as { archive: string }).archive)).toEqual([String.raw`C:\dl\a.zip`, String.raw`C:\dl\b.zip`]);
    expect(screen.getAllByText(/Extracted 3 files/)).toHaveLength(2);

    await userEvent.setup().click(screen.getAllByRole("button", { name: /Open folder/ })[0]);
    expect(revealItemInDir).toHaveBeenCalledWith(String.raw`C:\dl\a.zip`);
    await waitFor(() => expect(win.destroy).toHaveBeenCalled(), { timeout: 3000 });
  });

  it("stays open after a success with skipped files, or when asked to", async () => {
    fake.handlers.set("archive.extract", () => extracted({ skipped_total: 1 }));
    const { unmount } = show([extract("a.zip")]);
    expect(await screen.findByRole("heading", { name: "Done" })).toBeInTheDocument();
    expect(screen.queryByText("Closing…")).toBeNull();
    unmount();

    fake.handlers.set("archive.extract", () => extracted());
    show([extract("a.zip")], false);
    expect(await screen.findByRole("heading", { name: "Done" })).toBeInTheDocument();
    expect(screen.queryByText("Closing…")).toBeNull();
    await new Promise((r) => setTimeout(r, 2200));
    expect(win.destroy).not.toHaveBeenCalled();
  });

  it("cancels the running step and the rest", async () => {
    const running = deferred<unknown>();
    fake.handlers.set("archive.extract", () => running.promise);
    vi.mocked(cancel).mockImplementation(async () => {
      running.reject({ code: "Cancelled", message: "cancelled" });
      return true;
    });
    show([extract("a.zip"), extract("b.zip")]);
    await screen.findByRole("heading", { name: "Extracting a.zip" });
    await waitFor(() => expect(Object.keys(useJobs.getState().jobs)).toHaveLength(1));
    await userEvent.setup().click(screen.getByRole("button", { name: "Cancel" }));

    expect(await screen.findByRole("heading", { name: "Cancelled" })).toBeInTheDocument();
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(fake.calls).toHaveLength(1);
    expect(screen.getAllByText(/^Cancelled\. Files it had started writing were removed\./)).toHaveLength(2);
    expect(win.destroy).not.toHaveBeenCalled();
  });

  it("asks for a password in the window", async () => {
    fake.handlers.set("archive.extract", async (_args, emit) => {
      emit({ type: "Prompt", id: 1, prompt: { kind: "Password", entry: null } });
      await waitFor(() => expect(fake.replies).toHaveLength(1));
      return extracted();
    });
    show([extract("secret.zip")], false);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Password"), "hunter2");
    expect(screen.getByText(/for this job only/)).toBeInTheDocument();
    // The window grows to fit the prompt.
    await waitFor(() => expect(win.setSize).toHaveBeenCalledWith(expect.objectContaining({ width: 640, height: 360 })));
    await user.click(screen.getByRole("button", { name: /Unlock/ }));
    expect(fake.replies[0]).toMatchObject({ prompt: 1, reply: { kind: "Password", password: "hunter2" } });
    expect(await screen.findByRole("heading", { name: "Done" })).toBeInTheDocument();
  });

  it.each([
    ["Replace", { overwrite: true, output: String.raw`C:\w\work.zip` }],
    ["Keep both", { output: String.raw`C:\w\work (1).zip` }],
  ])("asks about an archive that's there: %s", async (label, args) => {
    fake.handlers.set("archive.create", () => ({ path: "x", files: 1, bytes_in: 1, bytes_out: 1, ratio: 1, volumes: null }));
    show([create], false);
    expect(await screen.findByText("work.zip is already there")).toBeInTheDocument();
    expect(fake.calls).toHaveLength(0);
    await userEvent.setup().click(screen.getByRole("button", { name: label }));
    expect(await screen.findByRole("heading", { name: "Done" })).toBeInTheDocument();
    expect(fake.calls[0].args).toMatchObject(args);
  });

  it("skips an archive that's there when asked to", async () => {
    show([create], false);
    await userEvent.setup().click(await screen.findByRole("button", { name: "Skip" }));
    expect(await screen.findByText(/^Skipped/)).toBeInTheDocument();
    expect(fake.calls).toHaveLength(0);
  });

  it("shows failures, planned or not, and the report of an unsafe archive", async () => {
    fake.handlers.set("archive.extract", () => {
      throw { code: "Unsafe", message: "1 entry refused", details: { skipped: [{ path: "../x", reason: "traversal", refused: true }], skipped_total: 1 } };
    });
    show([{ kind: "failed", title: "gone.zip", error: { code: "NotFound", message: "`C:\\dl\\gone.zip` isn't there any more" } }, extract("bad.zip")]);
    expect(await screen.findByRole("heading", { name: "Done, with 2 of 2 failed" })).toBeInTheDocument();
    expect(screen.getByText(/NotFound: .*isn't there any more/)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Show report" }));
    expect(await screen.findByText("../x")).toBeInTheDocument();
    await waitFor(() => expect(win.setSize).toHaveBeenLastCalledWith(expect.objectContaining({ width: 760, height: 480 })));
    expect(win.destroy).not.toHaveBeenCalled();
  });
});
