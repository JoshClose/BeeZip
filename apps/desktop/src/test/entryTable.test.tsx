import { fireEvent, render, screen } from "@testing-library/react";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { EntryInfo } from "../gen/commands";
import { EntryTable, ROW_HEIGHT } from "../features/browser/EntryTable";
import { click, moveTo, NONE, selectAll } from "../features/browser/select";

const MILLION = 1_000_000;

function fakeRow(i: number): EntryInfo {
  return {
    id: i,
    path: `folder/file-${i}.txt`,
    kind: "file",
    size: 1000 + i,
    packed_size: 400,
    modified: "2026-01-02T03:04:05Z",
    crc32: i,
    method: "Deflate",
    encrypted: i % 2 === 0,
    target: null,
  };
}

function renderTable(ensure = vi.fn()) {
  render(
    <EntryTable
      total={MILLION}
      row={fakeRow}
      ensure={ensure}
      reverse={false}
      selection={NONE}
      onSort={() => {}}
      onClick={() => {}}
      onOpen={() => {}}
      onKeyDown={() => {}}
      initialHeight={600}
    />,
  );
  return ensure;
}

describe("the entry table", () => {
  // TanStack Virtual sizes the viewport from clientWidth and clientHeight, which jsdom leaves at 0.
  const sizes = { clientHeight: 600, clientWidth: 900 };
  beforeAll(() => {
    for (const [k, v] of Object.entries(sizes)) Object.defineProperty(HTMLElement.prototype, k, { configurable: true, get: () => v });
  });
  afterAll(() => {
    for (const k of Object.keys(sizes)) delete (HTMLElement.prototype as unknown as Record<string, unknown>)[k];
  });

  it("renders a window of a million rows, not all of them", () => {
    const ensure = renderTable();
    expect(screen.getByRole("grid")).toHaveAttribute("aria-rowcount", String(MILLION));
    const rows = screen.getAllByRole("row").filter((r) => r.hasAttribute("aria-rowindex"));
    expect(rows.length).toBeGreaterThan(10);
    expect(rows.length).toBeLessThan(100);
    expect(screen.getByText("file-0.txt")).toBeInTheDocument();
    expect(screen.queryByText("file-999999.txt")).toBeNull();
    expect(ensure).toHaveBeenCalledWith(0, expect.any(Number));
  });

  it("fetches the rows that scroll into view", () => {
    const ensure = renderTable();
    const scroller = screen.getByTestId("entry-scroller");
    scroller.scrollTop = 500_000 * ROW_HEIGHT;
    fireEvent.scroll(scroller);
    expect(screen.getByText("file-500000.txt")).toBeInTheDocument();
    const [from, to] = ensure.mock.calls[ensure.mock.calls.length - 1];
    expect(from).toBeLessThanOrEqual(500_000);
    expect(to).toBeGreaterThan(500_000);
  });
});

describe("selection", () => {
  it("follows clicks, Ctrl, Shift and the keyboard", () => {
    let s = click(NONE, 5, { ctrl: false, shift: false });
    expect(s).toMatchObject({ selected: [5], anchor: 5, focus: 5 });
    s = click(s, 8, { ctrl: false, shift: true });
    expect(s.selected).toEqual([5, 6, 7, 8]);
    s = click(s, 6, { ctrl: true, shift: false });
    expect(s.selected).toEqual([5, 7, 8]);
    s = moveTo(s, 10, 9, false);
    // Clamped to the last row.
    expect(s).toMatchObject({ selected: [8], focus: 8 });
    s = moveTo(s, 6, 9, true);
    expect(s.selected).toEqual([6, 7, 8]);
    expect(selectAll(s).all).toBe(true);
  });
});
