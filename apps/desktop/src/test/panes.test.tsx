// The resizable panes: how the browser's widths fit a row, how tall the jobs list may get, the
// edge that drags them, and keeping the sizes between starts.
import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Splitter, STEP } from "../components/ui/splitter";
import { CONTENTS_MIN, DEFAULT_WIDTHS, fit, JOBS_ABOVE_MIN, JOBS_HEADER, JOBS_MIN, MIN_WIDTHS, tallestJobs, usePanes, widest } from "../lib/panes";

const KEY = "beezip.panes";

describe("fitting the panes to a row", () => {
  it("gives what was asked when there's room, and before the row is measured", () => {
    expect(fit({ tree: 300, preview: 500 }, 1600, true)).toEqual({ tree: 300, preview: 500 });
    expect(fit({ tree: 300, preview: 500 }, 0, true)).toEqual({ tree: 300, preview: 500 });
  });

  it("narrows the preview first, then the tree, so the entries keep their minimum", () => {
    // Room for the panes: 1000 - 240 - two 1 px edges = 758.
    expect(fit({ tree: 300, preview: 600 }, 1000, true)).toEqual({ tree: 300, preview: 458 });
    expect(fit({ tree: 700, preview: 600 }, 1000, true)).toEqual({ tree: 558, preview: MIN_WIDTHS.preview });
    // Without the preview, the tree has the row but one edge.
    expect(fit({ tree: 900, preview: 600 }, 800, false)).toEqual({ tree: 800 - CONTENTS_MIN - 1, preview: 600 });
  });

  it("never goes below a pane's minimum, even in a row too narrow for both", () => {
    expect(fit({ tree: 10, preview: 10 }, 300, true)).toEqual(MIN_WIDTHS);
  });

  it("drags a pane only as far as leaves the entries their minimum", () => {
    const shown = { tree: 200, preview: 300 };
    expect(widest("tree", shown, 1200, true)).toBe(1200 - CONTENTS_MIN - 2 - 300);
    expect(widest("preview", shown, 1200, true)).toBe(1200 - CONTENTS_MIN - 2 - 200);
    expect(widest("tree", shown, 900, false)).toBe(900 - CONTENTS_MIN - 1);
  });

  it("lets the jobs list grow until what's above keeps its minimum", () => {
    expect(tallestJobs(800)).toBe(800 - JOBS_ABOVE_MIN - 1 - JOBS_HEADER);
    expect(tallestJobs(250)).toBe(JOBS_MIN);
    expect(tallestJobs(0)).toBeGreaterThan(1000);
  });
});

describe("the sizes kept", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.resetModules();
  });

  async function fresh() {
    return (await import("../lib/panes")).usePanes.getState();
  }

  it("start at the defaults, with the jobs list fitting its jobs", async () => {
    expect(await fresh()).toMatchObject({ ...DEFAULT_WIDTHS, jobs: null });
  });

  it("come back from the last start", async () => {
    localStorage.setItem(KEY, JSON.stringify({ tree: 333, preview: 444, jobs: 280 }));
    expect(await fresh()).toMatchObject({ tree: 333, preview: 444, jobs: 280 });
  });

  it("fall back to the defaults when damaged, one by one", async () => {
    localStorage.setItem(KEY, "{not json");
    expect(await fresh()).toMatchObject({ ...DEFAULT_WIDTHS, jobs: null });
    vi.resetModules();
    localStorage.setItem(KEY, JSON.stringify({ tree: "wide", preview: 5, jobs: 3 }));
    expect(await fresh()).toMatchObject({ tree: DEFAULT_WIDTHS.tree, preview: MIN_WIDTHS.preview, jobs: JOBS_MIN });
  });

  it("are kept on save, not while a drag moves", () => {
    usePanes.setState({ ...DEFAULT_WIDTHS, jobs: null });
    usePanes.getState().resize("tree", 250.4);
    expect(usePanes.getState().tree).toBe(250);
    expect(localStorage.getItem(KEY)).toBeNull();
    usePanes.getState().save();
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual({ tree: 250, preview: DEFAULT_WIDTHS.preview });
    usePanes.getState().resize("jobs", 10);
    usePanes.getState().save();
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual({ tree: 250, preview: DEFAULT_WIDTHS.preview, jobs: JOBS_MIN });
    usePanes.getState().reset("tree");
    usePanes.getState().reset("jobs");
    expect(JSON.parse(localStorage.getItem(KEY)!)).toEqual(DEFAULT_WIDTHS);
    expect(usePanes.getState().jobs).toBeNull();
  });
});

describe("a pane's edge", () => {
  function Edge({ side, done = () => {}, start = 300, orientation }: { side: "before" | "after"; done?: () => void; start?: number; orientation?: "vertical" | "horizontal" }) {
    const [size, setSize] = useState(start);
    return (
      <Splitter
        label="Resize"
        size={size}
        min={200}
        max={500}
        side={side}
        orientation={orientation}
        onResize={setSize}
        onDone={done}
        onReset={() => setSize(start)}
      />
    );
  }
  const edge = () => screen.getByRole("separator", { name: "Resize" });

  it("moves with the arrow keys, widening the pane on its side", () => {
    const done = vi.fn();
    render(<Edge side="before" done={done} />);
    fireEvent.keyDown(edge(), { key: "ArrowRight" });
    expect(edge()).toHaveAttribute("aria-valuenow", String(300 + STEP));
    fireEvent.keyDown(edge(), { key: "ArrowLeft" });
    fireEvent.keyDown(edge(), { key: "ArrowLeft" });
    expect(edge()).toHaveAttribute("aria-valuenow", String(300 - STEP));
    // Up and down are a horizontal edge's.
    fireEvent.keyDown(edge(), { key: "ArrowUp" });
    expect(edge()).toHaveAttribute("aria-valuenow", String(300 - STEP));
    expect(done).toHaveBeenCalledTimes(3);
  });

  it("widens a pane after it with the left arrow, and stops at its limits", () => {
    render(<Edge side="after" />);
    fireEvent.keyDown(edge(), { key: "ArrowLeft" });
    expect(edge()).toHaveAttribute("aria-valuenow", String(300 + STEP));
    fireEvent.keyDown(edge(), { key: "End" });
    expect(edge()).toHaveAttribute("aria-valuenow", "500");
    fireEvent.keyDown(edge(), { key: "ArrowLeft" });
    expect(edge()).toHaveAttribute("aria-valuenow", "500");
    fireEvent.keyDown(edge(), { key: "Home" });
    expect(edge()).toHaveAttribute("aria-valuenow", "200");
  });

  it("follows a drag, within its limits, and is done when the button comes up", () => {
    const done = vi.fn();
    render(<Edge side="before" done={done} />);
    fireEvent.pointerDown(edge(), { button: 0, pointerId: 1, clientX: 100 });
    expect(edge()).toHaveAttribute("data-dragging");
    expect(document.documentElement.dataset.resizing).toBe("col");
    fireEvent.pointerMove(edge(), { pointerId: 1, clientX: 150 });
    expect(edge()).toHaveAttribute("aria-valuenow", "350");
    fireEvent.pointerMove(edge(), { pointerId: 1, clientX: 900 });
    expect(edge()).toHaveAttribute("aria-valuenow", "500");
    // Back inside the limits, the edge is under the pointer again.
    fireEvent.pointerMove(edge(), { pointerId: 1, clientX: 80 });
    expect(edge()).toHaveAttribute("aria-valuenow", "280");
    expect(done).not.toHaveBeenCalled();
    fireEvent.pointerUp(edge(), { pointerId: 1, clientX: 80 });
    expect(done).toHaveBeenCalledOnce();
    expect(edge()).not.toHaveAttribute("data-dragging");
    expect(document.documentElement.dataset.resizing).toBeUndefined();
    // Moving afterwards does nothing.
    fireEvent.pointerMove(edge(), { pointerId: 1, clientX: 200 });
    expect(edge()).toHaveAttribute("aria-valuenow", "280");
  });

  it("goes back to the default size on a double-click", () => {
    render(<Edge side="after" />);
    fireEvent.keyDown(edge(), { key: "Home" });
    fireEvent.doubleClick(edge());
    expect(edge()).toHaveAttribute("aria-valuenow", "300");
  });

  it("lying across, follows the pointer up and down: dragging up grows the pane below", () => {
    render(<Edge side="after" orientation="horizontal" />);
    expect(edge()).toHaveAttribute("aria-orientation", "horizontal");
    fireEvent.keyDown(edge(), { key: "ArrowUp" });
    expect(edge()).toHaveAttribute("aria-valuenow", String(300 + STEP));
    fireEvent.keyDown(edge(), { key: "ArrowDown" });
    fireEvent.keyDown(edge(), { key: "ArrowRight" });
    expect(edge()).toHaveAttribute("aria-valuenow", "300");
    fireEvent.pointerDown(edge(), { button: 0, pointerId: 2, clientX: 10, clientY: 500 });
    expect(document.documentElement.dataset.resizing).toBe("row");
    fireEvent.pointerMove(edge(), { pointerId: 2, clientX: 400, clientY: 440 });
    expect(edge()).toHaveAttribute("aria-valuenow", "360");
    fireEvent.pointerUp(edge(), { pointerId: 2, clientY: 440 });
    expect(document.documentElement.dataset.resizing).toBeUndefined();
  });
});
