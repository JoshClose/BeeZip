// The binding to `cmd_run`: what reaches Rust.
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { run } from "../lib/engine";

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {
    onmessage?: (event: unknown) => void;
  },
  invoke: vi.fn(async () => 1),
}));

beforeEach(() => {
  vi.mocked(invoke).mockClear();
});

describe("run", () => {
  it("says the job belongs to a tab as `forTab`, which Rust reads as `for_tab`, only when it does", () => {
    void run("archive.list", { archive: "a.bhive" }, undefined, true);
    void run("archive.list", { archive: "b.bhive" });
    void run("archive.list", { archive: "c.bhive" }, undefined, false);
    const sent = vi.mocked(invoke).mock.calls.map(([command, args]) => [command, args]);
    expect(sent.map(([command]) => command)).toEqual(["cmd_run", "cmd_run", "cmd_run"]);
    expect(sent[0][1]).toMatchObject({ name: "archive.list", args: { archive: "a.bhive" }, forTab: true });
    expect(sent[1][1]).not.toHaveProperty("forTab");
    expect(sent[2][1]).not.toHaveProperty("forTab");
    expect(Object.keys(sent[1][1] as object).sort()).toEqual(["args", "name", "onEvent"]);
  });
});
