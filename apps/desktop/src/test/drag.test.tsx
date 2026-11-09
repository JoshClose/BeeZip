// Dragging entries out to Explorer, the page's half (docs/M6.md §8.4): the arguments Rust
// gets, the 2 GiB cap, the drop's job, rows that drag the whole selection, and the window
// ignoring its own drag-out. The OLE drag itself needs a real mouse (docs/M6.md §12).
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { Browser } from "../features/browser/Browser";
import { EntryTable } from "../features/browser/EntryTable";
import { ExtractDialog } from "../features/extract/ExtractDialog";
import type { EntryInfo, JobEvent } from "../gen/commands";
import { type Tab, useArchives } from "../lib/archives";
import { DRAG_CAP, dragArgs, draggingOut, dragOut, startDrag } from "../lib/drag";
import { useJobs } from "../lib/jobs";
import { useToasts } from "../lib/toasts";
import { useUi } from "../lib/ui";
import { fake } from "./fakeEngine";

type Pending = { args: unknown; channel: { onmessage?: (e: JobEvent) => void }; settle: (v: unknown) => void; fail: (e: unknown) => void };

const tauri = vi.hoisted(() => ({
  drags: [] as Pending[],
  dropHandler: undefined as undefined | ((e: { payload: unknown }) => void),
}));

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {
    onmessage?: (e: unknown) => void;
  },
  invoke: vi.fn(async (cmd: string, payload?: { args: unknown; onEvent: Pending["channel"] }) => {
    if (cmd === "cmd_drag_out") {
      return new Promise((settle, fail) => tauri.drags.push({ args: payload?.args, channel: payload!.onEvent, settle, fail }));
    }
    if (cmd === "cmd_launched") return { paths: [], dialog: null };
    return { status: "off", reason: "test" };
  }),
}));
vi.mock("@tauri-apps/api/event", () => ({ emit: vi.fn(async () => {}), listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({
    onDragDropEvent: async (h: (e: { payload: unknown }) => void) => {
      tauri.dropHandler = h;
      return () => {};
    },
  }),
}));
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => ({ onCloseRequested: async () => () => {} }) }));
vi.mock("@tauri-apps/api/app", () => ({ setTheme: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true), open: vi.fn(async () => null), save: vi.fn() }));

const ZIP = String.raw`C:\work\a.zip`;
const GiB = 1024 ** 3;

const entry = (path: string, kind: EntryInfo["kind"] = "file", size: number | null = 10): EntryInfo => ({
  id: 1,
  path,
  kind,
  size: kind === "dir" ? null : size,
  packed_size: null,
  modified: null,
  crc32: null,
  method: null,
  encrypted: false,
  target: null,
});

/** The tab on a.zip, as `patch` says. `open` gives back the tab already open on a path. */
function openTab(patch: Partial<Tab> = {}): Tab {
  const id = useArchives.getState().open(ZIP);
  useArchives.getState().update(id, { dir: "", password: undefined, encoding: undefined, selected: [], all: false, ...patch });
  return useArchives.getState().tabs.find((t) => t.id === id)!;
}

/** The sizes `archive.list` gives for a folder (flat, limit 0). */
function sizes(byDir: Record<string, number>) {
  fake.handlers.set("archive.list", (args) => {
    const dir = (args as { dir?: string }).dir ?? "";
    return { entries: [], total: 0, size: byDir[dir] ?? 0, offset: 0, has_more: false };
  });
}

const lastDrag = () => tauri.drags[tauri.drags.length - 1];
const listCalls = () => fake.calls.filter((c) => c.name === "archive.list").map((c) => c.args);

beforeEach(() => {
  fake.reset();
  tauri.drags = [];
  useArchives.setState({ tabs: [], active: undefined });
  useJobs.setState({ jobs: {}, order: [] });
  useUi.setState({ dialog: undefined, palette: false });
  useToasts.setState({ toasts: [] });
  delete window.__BEEZIP__;
});

afterEach(async () => {
  // A drag left running would keep the next test from starting one.
  for (const d of tauri.drags) d.settle("cancelled");
  await act(async () => {});
});

describe("a drag's arguments", () => {
  it("name the selection, strip the folder shown, and carry the tab's password and encoding", () => {
    const tab = openTab({ dir: "docs/img", password: "pw", encoding: "cp932" });
    const rows = [entry("docs/img/a.png"), entry("docs/img/sub/", "dir")];
    expect(dragArgs(tab, { all: false, rows })).toEqual({
      archive: ZIP,
      entries: ["docs/img/a.png", "docs/img/sub"],
      strip_components: 2,
      password: "pw",
      name_encoding: "cp932",
    });
  });

  it("take the folder shown for everything in it, and the whole archive at the root", () => {
    expect(dragArgs(openTab({ dir: "docs" }), { all: true })).toEqual({ archive: ZIP, entries: ["docs"], strip_components: 1 });
    expect(dragArgs(openTab(), { all: true })).toEqual({ archive: ZIP });
    expect(dragArgs(openTab(), { all: false, rows: [entry("b.txt")] })).toEqual({ archive: ZIP, entries: ["b.txt"] });
  });
});

describe("starting a drag", () => {
  it("measures the folders, then drags while Rust runs it", async () => {
    sizes({ docs: 1000 });
    const tab = openTab();
    const started = startDrag(tab, { all: false, rows: [entry("b.txt"), entry("docs/", "dir")] });
    await waitFor(() => expect(tauri.drags).toHaveLength(1));
    expect(listCalls()).toEqual([{ archive: ZIP, dir: "docs", flat: true, limit: 0 }]);
    expect(lastDrag().args).toEqual({ archive: ZIP, entries: ["b.txt", "docs"] });
    expect(draggingOut()).toBe(true);
    // One drag at a time.
    expect(await startDrag(tab, { all: true })).toBeUndefined();
    expect(tauri.drags).toHaveLength(1);

    lastDrag().settle("dropped");
    expect(await started).toBe("dropped");
    expect(draggingOut()).toBe(false);
  });

  it("measures everything shown with one listing of the folder", async () => {
    sizes({ docs: 5, "": 7 });
    const started = startDrag(openTab({ dir: "docs" }), { all: true });
    await waitFor(() => expect(tauri.drags).toHaveLength(1));
    expect(listCalls()).toEqual([{ archive: ZIP, dir: "docs", flat: true, limit: 0 }]);
    lastDrag().settle("cancelled");
    expect(await started).toBe("cancelled");

    fake.calls = [];
    const root = startDrag(openTab(), { all: true });
    await waitFor(() => expect(tauri.drags).toHaveLength(2));
    expect(listCalls()).toEqual([{ archive: ZIP, flat: true, limit: 0 }]);
    lastDrag().settle("dropped");
    await root;
  });

  it("offers the extract dialog instead past 2 GiB, saying why", async () => {
    sizes({ big: 3 * GiB });
    const tab = openTab();
    expect(await startDrag(tab, { all: false, rows: [entry("b.txt"), entry("big", "dir")] })).toBe("too-big");
    expect(tauri.drags).toHaveLength(0);
    const dialog = useUi.getState().dialog;
    expect(dialog).toMatchObject({ kind: "extract", tab: tab.id, entries: ["b.txt", "big"] });
    expect(dialog?.kind === "extract" && dialog.note).toMatch(/^That's 3\.0 GiB, more than the 2\.0 GiB a drag takes/);
    expect(draggingOut()).toBe(false);

    // Files alone over the cap need no listing.
    fake.calls = [];
    expect(await startDrag(tab, { all: false, rows: [entry("huge.iso", "file", DRAG_CAP + 1), entry("docs", "dir")] })).toBe("too-big");
    expect(listCalls()).toEqual([]);
  });

  it("shows the note in the extract dialog", () => {
    render(<ExtractDialog tab={openTab()} entries={["big"]} note="That's 3.0 GiB, more than a drag takes." onClose={() => {}} />);
    expect(screen.getByRole("note")).toHaveTextContent("That's 3.0 GiB, more than a drag takes.");
    expect(screen.getByLabelText(/Selected entries \(1\)/)).toBeChecked();
  });

  it("drags nothing when nothing is selected", async () => {
    expect(await startDrag(openTab(), { all: false, rows: [] })).toBeUndefined();
    expect(tauri.drags).toHaveLength(0);
  });

  it("says why when the drag can't start", async () => {
    const started = dragOut(openTab(), { all: true });
    await waitFor(() => expect(tauri.drags).toHaveLength(1));
    lastDrag().fail({ code: "UnsupportedOperation", message: "not here" });
    expect(await started).toBeUndefined();
    expect(draggingOut()).toBe(false);
    expect(useToasts.getState().toasts).toMatchObject([{ tone: "error", title: "Dragging out: UnsupportedOperation", body: "not here" }]);
  });
});

describe("the drop's extraction", () => {
  it("is a job like any other, and its failure is a toast", async () => {
    const tab = openTab();
    const started = dragOut(tab, { all: false, rows: [entry("b.txt"), entry("c.txt")] });
    await waitFor(() => expect(tauri.drags).toHaveLength(1));
    const send = (e: JobEvent) => act(() => lastDrag().channel.onmessage?.(e));
    // Nothing shows before a drop starts the extraction.
    expect(useJobs.getState().order).toEqual([]);
    await send({ type: "Started", job: 77 });
    expect(useJobs.getState().jobs[77]).toMatchObject({ command: "archive.extract", title: "Extracting 2 items from a.zip", tab: tab.id, status: "running" });
    await send({ type: "Failed", error: { code: "Corrupt", message: "bad block", details: null } });
    expect(useJobs.getState().jobs[77].status).toBe("failed");
    expect(useToasts.getState().toasts).toMatchObject([{ title: "Extracting 2 items from a.zip: Corrupt", body: "bad block" }]);
    lastDrag().settle("failed");
    expect(await started).toBe("failed");
  });

  it("leaves Unsafe to the jobs panel and a cancellation unsaid", async () => {
    for (const end of [
      { type: "Failed", error: { code: "Unsafe", message: "1 entry was refused", details: null } },
      { type: "Cancelled" },
    ] as JobEvent[]) {
      const started = dragOut(openTab(), { all: false, rows: [entry("docs/b.txt")] });
      await waitFor(() => expect(tauri.drags.length).toBeGreaterThan(0));
      const d = lastDrag();
      await act(() => d.channel.onmessage?.({ type: "Started", job: 5 }));
      expect(useJobs.getState().jobs[5].title).toBe("Extracting b.txt from a.zip");
      await act(() => d.channel.onmessage?.(end));
      d.settle("failed");
      await started;
      tauri.drags = [];
    }
    expect(useToasts.getState().toasts).toEqual([]);
  });
});

describe("rows that drag", () => {
  const sizesOf = { clientHeight: 600, clientWidth: 900 };
  beforeAll(() => {
    for (const [k, v] of Object.entries(sizesOf)) Object.defineProperty(HTMLElement.prototype, k, { configurable: true, get: () => v });
  });
  afterAll(() => {
    for (const k of Object.keys(sizesOf)) delete (HTMLElement.prototype as unknown as Record<string, unknown>)[k];
  });

  const fakeRow = (i: number) => entry(`file-${i}.txt`);
  const rowOf = (i: number) => screen.getByText(`file-${i}.txt`).closest("[role=row]")!;

  function table(props: { selected: number[]; all?: boolean; onDragOut?: (i: number) => void; renaming?: number }) {
    const onClick = vi.fn();
    render(
      <EntryTable
        total={20}
        row={fakeRow}
        ensure={() => {}}
        reverse={false}
        selection={{ selected: props.selected, all: props.all ?? false, anchor: props.selected[0], focus: props.selected[0] }}
        onSort={() => {}}
        onClick={onClick}
        onOpen={() => {}}
        onKeyDown={() => {}}
        onDragOut={props.onDragOut}
        renaming={props.renaming === undefined ? undefined : { index: props.renaming, path: fakeRow(props.renaming).path, busy: false }}
        initialHeight={600}
      />,
    );
    return onClick;
  }

  it("keep a selection of several for a drag, and select one row on a plain click", () => {
    const onDragOut = vi.fn();
    const onClick = table({ selected: [1, 2], onDragOut });
    fireEvent.mouseDown(rowOf(1), { button: 0 });
    expect(onClick).not.toHaveBeenCalled();
    // fireEvent returns false when the handler prevented the default: WebView2's own drag.
    expect(fireEvent.dragStart(rowOf(1))).toBe(false);
    expect(onDragOut).toHaveBeenCalledWith(1);
    fireEvent.mouseUp(rowOf(1), { button: 0 });
    expect(onClick).not.toHaveBeenCalled();

    // No drag: the release selects the row alone.
    fireEvent.mouseDown(rowOf(2), { button: 0 });
    fireEvent.mouseUp(rowOf(2), { button: 0 });
    expect(onClick).toHaveBeenCalledTimes(1);
    expect(onClick.mock.calls[0][0]).toBe(2);

    // An unselected row, or Ctrl, acts on the press as before.
    fireEvent.mouseDown(rowOf(5), { button: 0 });
    fireEvent.mouseDown(rowOf(1), { button: 0, ctrlKey: true });
    expect(onClick.mock.calls.map((c) => c[0])).toEqual([2, 5, 1]);
  });

  it("wait for the release under Ctrl+A too, but not with one row selected", () => {
    const onClick = table({ selected: [], all: true, onDragOut: vi.fn() });
    fireEvent.mouseDown(rowOf(3), { button: 0 });
    expect(onClick).not.toHaveBeenCalled();
    fireEvent.mouseUp(rowOf(3), { button: 0 });
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("act on the press as before when they can't drag", () => {
    const onClick = table({ selected: [1, 2] });
    expect(rowOf(1)).not.toHaveAttribute("draggable");
    fireEvent.mouseDown(rowOf(1), { button: 0 });
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("leave out the row being renamed", () => {
    table({ selected: [1], onDragOut: vi.fn(), renaming: 1 });
    expect(rowOf(1)).toHaveAttribute("draggable", "false");
    expect(rowOf(0)).toHaveAttribute("draggable", "true");
  });

  describe("in the browser", () => {
    function Live({ id }: { id: string }) {
      const tab = useArchives((s) => s.tabs.find((t) => t.id === id));
      return tab ? <Browser tab={tab} /> : null;
    }

    beforeEach(() => {
      fake.handlers.set("archive.list", (args) => {
        const a = args as { flat?: boolean; limit?: number };
        if (a.flat) return { entries: [], total: 0, size: 100, offset: 0, has_more: false };
        const rows = [entry("docs", "dir"), entry("b.txt"), entry("c.txt")];
        return { entries: rows, total: rows.length, size: 20, offset: 0, has_more: false };
      });
      fake.handlers.set("archive.info", () => ({ size: 10, packed_size: 5, chain: "zip", encryption: "none", solid: false, not_editable: null }));
      fake.handlers.set("entry.read", () => ({ data: "", encoding: "text", bytes_read: 0, eof: true, offset: 0, size: 0 }));
    });

    it("drag the tab's selection on Windows", async () => {
      const tab = openTab({ selected: [0, 1], anchor: 0, focus: 1 });
      render(<Live id={tab.id} />);
      const row = (await screen.findByText("b.txt")).closest("[role=row]")!;
      expect(row).toHaveAttribute("draggable", "true");
      fireEvent.mouseDown(row, { button: 0 });
      fireEvent.dragStart(row);
      await waitFor(() => expect(tauri.drags).toHaveLength(1));
      expect(lastDrag().args).toEqual({ archive: ZIP, entries: ["docs", "b.txt"] });
      // The selection stayed as it was.
      expect(useArchives.getState().tabs[0].selected).toEqual([0, 1]);
    });

    it("don't drag off Windows", async () => {
      window.__BEEZIP__ = { paths: [], cli: "beezip", warnings: [], theme: "system", platform: "linux" };
      const tab = openTab();
      render(<Live id={tab.id} />);
      const row = (await screen.findByText("b.txt")).closest("[role=row]")!;
      expect(row).not.toHaveAttribute("draggable");
    });
  });
});

describe("the window during its own drag-out", () => {
  it("ignores what passes over it, and takes drops again afterwards", async () => {
    fake.handlers.set("file.detect", () => ({ format: null }));
    // jsdom has no layout: every point is over nothing in particular, the welcome screen.
    const elementFromPoint = vi.fn(() => null);
    Object.defineProperty(document, "elementFromPoint", { configurable: true, value: elementFromPoint });
    render(<App />);
    await waitFor(() => expect(tauri.dropHandler).toBeDefined());
    const event = (type: string) =>
      act(() => tauri.dropHandler?.({ payload: { type, paths: [String.raw`C:\Temp\BeeZip\drag-1`], position: { x: 1, y: 1 } } }));

    // A tab the window doesn't show, so the welcome screen stays and says what a drop would do.
    const hidden: Tab = { id: "hidden", path: ZIP, name: "a.zip", dir: "", reverse: false, selected: [], all: false, solidOk: false, version: 0 };
    const started = dragOut(hidden, { all: true });
    await waitFor(() => expect(tauri.drags).toHaveLength(1));
    await event("enter");
    expect(screen.getByText("Drop files here")).toBeInTheDocument();
    await event("drop");
    expect(fake.calls.filter((c) => c.name === "file.detect")).toEqual([]);
    expect(useUi.getState().dialog).toBeUndefined();
    expect(elementFromPoint).not.toHaveBeenCalled();

    lastDrag().settle("cancelled");
    await started;
    await event("enter");
    expect(screen.getByText("Drop to open")).toBeInTheDocument();
    await event("drop");
    await waitFor(() => expect(useUi.getState().dialog).toMatchObject({ kind: "create" }));
    delete (document as unknown as Record<string, unknown>).elementFromPoint;
  });
});
