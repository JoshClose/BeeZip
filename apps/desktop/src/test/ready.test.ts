import { invoke } from "@tauri-apps/api/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ready } from "../lib/startup";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(async () => {}) }));

type Entry = { name: string };
type Callback = (list: { getEntriesByName: (name: string) => Entry[] }, observer: FakeObserver) => void;

// The browser's paint timing, by hand: `paint(name)` is a frame the browser has presented.
class FakeObserver {
  static supportedEntryTypes = ["paint"];
  static live: FakeObserver[] = [];
  options: unknown;
  constructor(private callback: Callback) {}
  observe(options: unknown) {
    this.options = options;
    FakeObserver.live.push(this);
  }
  disconnect() {
    FakeObserver.live = FakeObserver.live.filter((o) => o !== this);
  }
  paint(name: string) {
    this.callback({ getEntriesByName: (n) => (n === name ? [{ name }] : []) }, this);
  }
}

const told = () => vi.mocked(invoke).mock.calls.map((c) => c[0]);
const settle = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
  vi.mocked(invoke).mockClear();
  FakeObserver.live = [];
});
afterEach(() => vi.unstubAllGlobals());

describe("the page tells Rust when the window has something to show", () => {
  it("after its first frame with content, once", async () => {
    vi.stubGlobal("PerformanceObserver", FakeObserver);
    ready();
    const observer = FakeObserver.live[0];
    // Frames painted before the observer existed count too.
    expect(observer.options).toEqual({ type: "paint", buffered: true });
    await settle();
    expect(told()).toEqual([]);

    // The background alone isn't BeeZip yet.
    observer.paint("first-paint");
    await settle();
    expect(told()).toEqual([]);

    observer.paint("first-contentful-paint");
    await settle();
    expect(told()).toEqual(["cmd_ready"]);
    expect(FakeObserver.live).toEqual([]);
  });

  it("at once where the browser doesn't time its paints", async () => {
    vi.stubGlobal("PerformanceObserver", class extends FakeObserver {
      static supportedEntryTypes = ["resource"];
    });
    ready();
    await settle();
    expect(told()).toEqual(["cmd_ready"]);
    expect(FakeObserver.live).toEqual([]);

    vi.mocked(invoke).mockClear();
    vi.stubGlobal("PerformanceObserver", undefined);
    ready();
    await settle();
    expect(told()).toEqual(["cmd_ready"]);
  });

  it("and a refusal is left alone", async () => {
    vi.stubGlobal("PerformanceObserver", undefined);
    vi.mocked(invoke).mockRejectedValueOnce(new Error("not allowed"));
    ready();
    await settle();
    expect(told()).toEqual(["cmd_ready"]);
  });
});
