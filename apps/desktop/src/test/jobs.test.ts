import { beforeEach, describe, expect, it, vi } from "vitest";
import type { JobEvent } from "../gen/commands";
import { applyEvent, newJob, nextPrompt, orderedJobs, useJobs } from "../lib/jobs";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));

describe("the jobs reducer", () => {
  const start = () => newJob(4, "archive.extract", { archive: "a.7z" }, { title: "Extracting a.7z" }, 1_000);

  it("follows a job from start to finish", () => {
    const events: [JobEvent, number][] = [
      [{ type: "Progress", bytes_done: 0, bytes_total: 4096, entries_done: 0, entries_total: 2, current: null }, 1_000],
      [{ type: "Progress", bytes_done: 2048, bytes_total: 4096, entries_done: 1, entries_total: 2, current: "b.txt" }, 2_000],
      [{ type: "Log", level: "Warn", message: "skipped `../x`" }, 2_100],
      [{ type: "Prompt", id: 1, prompt: { kind: "Overwrite", path: "C:\\out\\b.txt" } }, 2_200],
    ];
    let job = start();
    for (const [e, at] of events) job = applyEvent(job, e, at);
    expect(job.status).toBe("running");
    expect(job.progress?.current).toBe("b.txt");
    expect(job.rate).toBe(2048);
    expect(job.logs).toEqual([{ level: "Warn", message: "skipped `../x`" }]);
    expect(job.prompts).toEqual([{ id: 1, prompt: { kind: "Overwrite", path: "C:\\out\\b.txt" } }]);

    const done = applyEvent(job, { type: "Finished", output: { files: 2 } }, 3_000);
    expect(done.status).toBe("finished");
    expect(done.output).toEqual({ files: 2 });
    expect(done.prompts).toEqual([]);
    expect(done.ended).toBe(3_000);
    expect(job.status).toBe("running"); // the input is left alone
  });

  it("records failures and cancellations", () => {
    const failed = applyEvent(start(), { type: "Failed", error: { code: "Corrupt", message: "bad CRC" } }, 5);
    expect(failed.status).toBe("failed");
    expect(failed.error?.code).toBe("Corrupt");
    expect(applyEvent(start(), { type: "Cancelled" }, 5).status).toBe("cancelled");
  });

  it("shows the oldest job's oldest prompt first", () => {
    let a = newJob(1, "archive.extract", {}, { title: "a" }, 0);
    let b = newJob(2, "archive.extract", {}, { title: "b" }, 0);
    b = applyEvent(b, { type: "Prompt", id: 1, prompt: { kind: "Password", entry: null } }, 1);
    expect(nextPrompt([a, b])?.job.id).toBe(2);
    a = applyEvent(a, { type: "Prompt", id: 3, prompt: { kind: "Password", entry: "x" } }, 2);
    a = applyEvent(a, { type: "Prompt", id: 4, prompt: { kind: "Password", entry: "y" } }, 3);
    expect(nextPrompt([a, b])).toMatchObject({ job: { id: 1 }, pending: { id: 3 } });
    expect(nextPrompt([])).toBeUndefined();
  });
});

describe("the jobs store", () => {
  beforeEach(() => {
    fake.reset();
    useJobs.setState({ jobs: {}, order: [] });
  });

  it("answers a prompt, keeps a tab's password, and drops quiet jobs when they end", async () => {
    const passwords: [string, string][] = [];
    useJobs.setState({ onPassword: (tab, pw) => passwords.push([tab, pw]) });
    let release: () => void = () => {};
    fake.handlers.set("archive.list", (_args, emit) => {
      emit({ type: "Prompt", id: 1, prompt: { kind: "Password", entry: null } });
      return new Promise((r) => (release = () => r({ entries: [], total: 0, size: 0, offset: 0, has_more: false })));
    });
    const done = useJobs.getState().track("archive.list", { archive: "a.7z" }, { title: "Listing a.7z", quiet: true, tab: "tab-1" });
    await vi.waitFor(() => expect(nextPrompt(orderedJobs(useJobs.getState()))).toBeDefined());
    const asking = nextPrompt(orderedJobs(useJobs.getState()))!;
    await useJobs.getState().answer(asking.job.id, asking.pending.id, { kind: "Password", password: "beezip" });
    expect(fake.replies).toEqual([{ job: 1, prompt: 1, reply: { kind: "Password", password: "beezip" } }]);
    expect(passwords).toEqual([["tab-1", "beezip"]]);
    expect(nextPrompt(orderedJobs(useJobs.getState()))).toBeUndefined();
    release();
    await done;
    expect(useJobs.getState().order).toEqual([]);
  });

  it("keeps finished jobs until they are cleared", async () => {
    fake.handlers.set("archive.test", () => ({ archive: "a.zip", entries: 3, bytes: 10 }));
    await useJobs.getState().track("archive.test", { archive: "a.zip" }, { title: "Testing a.zip" });
    expect(orderedJobs(useJobs.getState()).map((j) => j.status)).toEqual(["finished"]);
    useJobs.getState().clearFinished();
    expect(useJobs.getState().order).toEqual([]);
  });
});
