import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { useArchives } from "../lib/archives";
import { fake } from "./fakeEngine";

// What happened, in order: listeners registered, then the drain (docs/M6.md §8.1).
const order: string[] = [];
vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {},
  invoke: vi.fn(async (cmd: string) => {
    order.push(cmd);
    if (cmd === "cmd_launched") return { paths: [String.raw`C:\dl\early.zip`], dialog: null };
    return { status: "off", reason: "test" };
  }),
}));
vi.mock("@tauri-apps/api/event", () => ({
  emit: vi.fn(async () => {}),
  listen: vi.fn(async (event: string) => {
    await new Promise((r) => setTimeout(r, 5));
    order.push(`listen ${event}`);
    return () => {};
  }),
}));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => ({ onCloseRequested: async () => () => {} }) }));
vi.mock("@tauri-apps/api/app", () => ({ setTheme: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true), open: vi.fn(async () => null) }));

beforeEach(() => {
  fake.reset();
  fake.handlers.set("file.detect", () => ({ format: "zip" }));
  useArchives.setState({ tabs: [], active: undefined });
  order.length = 0;
});

describe("launches forwarded while the window started", () => {
  it("are taken once the page listens, and open in tabs", async () => {
    render(<App />);
    await waitFor(() => expect(useArchives.getState().tabs.map((t) => t.path)).toEqual([String.raw`C:\dl\early.zip`]));
    expect(listen).toHaveBeenCalledWith("open-paths", expect.any(Function));
    const drained = order.indexOf("cmd_launched");
    expect(drained).toBeGreaterThan(order.indexOf("listen open-paths"));
    expect(drained).toBeGreaterThan(order.indexOf("listen open-dialog"));
    expect(invoke).toHaveBeenCalledWith("cmd_update_check", { force: false });
  });
});
