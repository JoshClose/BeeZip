// Mismatches between the app and what it says, fixed before 0.1.0: Ctrl+E extracts the
// selection, the method dropdown names each format's own default, the level slider starts at
// `[levels]`, and the Extract dialog follows `[extract]`. (About's banner line: update.test.tsx.)
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { applies, CreateDialog, defaultLevel, defaultMethod } from "../features/create/CreateDialog";
import { ExtractDialog, extractArgs } from "../features/extract/ExtractDialog";
import type { ArchiveInfoOutput, EntryInfo, FormatsListOutput } from "../gen/commands";
import { useArchives } from "../lib/archives";
import { useJobs } from "../lib/jobs";
import { useUi } from "../lib/ui";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {},
  invoke: vi.fn(async (cmd: string) => (cmd === "cmd_launched" ? { paths: [], dialog: null } : { status: "off", reason: "test" })),
}));
vi.mock("@tauri-apps/api/event", () => ({ emit: vi.fn(async () => {}), listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => ({ onCloseRequested: async () => () => {} }) }));
vi.mock("@tauri-apps/api/app", () => ({ setTheme: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true), open: vi.fn(async () => null), save: vi.fn() }));

const ZIP = String.raw`C:\work\a.zip`;
const levels = (min: number, max: number, d: number) => ({ min, max, default: d });
const caps = { list: true, extract: true, create: true, append: false, delete: false, rename: false, encrypt: false, encrypt_headers: false, solid: false, volumes: false, random_access: true };
const format = (id: string, methods: { id: string; levels: ReturnType<typeof levels> | null }[]) => ({
  id,
  name: id,
  extensions: [`.${id}`],
  caps,
  methods,
  encryption: [],
  menu: true,
});
const formats = {
  formats: [
    format("zip", [{ id: "store", levels: null }, { id: "deflate", levels: levels(1, 9, 6) }]),
    format("7z", [{ id: "lzma2", levels: levels(0, 9, 5) }, { id: "copy", levels: null }]),
    format("cab", [{ id: "mszip", levels: null }, { id: "store", levels: null }]),
    format("squashfs", [{ id: "gzip", levels: levels(1, 9, 9) }, { id: "xz", levels: levels(0, 9, 6) }]),
    format("tar", []),
  ],
  codecs: [{ id: "zstd", name: "Zstandard", extensions: [".zst", ".tzst"], levels: levels(1, 22, 3), threads: true, detected: true }],
  create: ["zip", "7z", "cab", "squashfs", "tar.zst"],
} as unknown as FormatsListOutput;

// The settings: `[levels]` for deflate and zstd, and `[extract]` keeping both, with links.
const settings = {
  settings: {
    edit: { overwrite: "ask" },
    extract: { overwrite: "rename", links: true, mark_of_the_web: "copy", threads: 0 },
    levels: { deflate: 9, zstd: 19 },
  },
};

const entry = (path: string, id: number): EntryInfo => ({
  id,
  path,
  kind: "file",
  size: 10,
  packed_size: 5,
  modified: null,
  crc32: null,
  method: null,
  encrypted: false,
  target: null,
});

beforeEach(() => {
  fake.reset();
  fake.handlers.set("formats.list", () => formats);
  fake.handlers.set("settings.get", () => settings);
  useArchives.setState({ tabs: [], active: undefined });
  useJobs.setState({ jobs: {}, order: [] });
  useUi.setState({ dialog: undefined, palette: false });
});

describe("Ctrl+E", () => {
  it("extracts the selection, as the toolbar's Extract does, and everything without one", async () => {
    fake.handlers.set("archive.list", () => ({ entries: [entry("a.txt", 1), entry("b.txt", 2)], total: 2 }));
    fake.handlers.set("archive.info", () => ({ archive: ZIP, format: "zip", not_editable: null }) as unknown as ArchiveInfoOutput);
    render(<App />);
    const id = useArchives.getState().open(ZIP);
    expect(await screen.findByText("b.txt")).toBeInTheDocument();
    const user = userEvent.setup();

    useArchives.getState().update(id, { selected: [1], focus: 1, anchor: 1 });
    await user.keyboard("{Control>}e{/Control}");
    await waitFor(() => expect(useUi.getState().dialog).toEqual({ kind: "extract", tab: id, entries: ["b.txt"] }));

    useUi.setState({ dialog: undefined });
    useArchives.getState().update(id, { selected: [], focus: undefined, anchor: undefined });
    await user.keyboard("{Control>}e{/Control}");
    await waitFor(() => expect(useUi.getState().dialog).toEqual({ kind: "extract", tab: id, entries: [] }));
  });
});

describe("the create dialog", () => {
  it("names each format's own default method", async () => {
    expect([defaultMethod("zip"), defaultMethod("7z"), defaultMethod("cab"), defaultMethod("squashfs")]).toEqual(["deflate", "lzma2", "mszip", "gzip"]);
    render(<CreateDialog inputs={[String.raw`C:\work\src`]} onClose={() => {}} />);
    const user = userEvent.setup();
    const method = () => screen.getByLabelText("Method") as HTMLSelectElement;
    await user.selectOptions(await screen.findByLabelText("Format"), "cab");
    expect(method().options[0].text).toBe("mszip (default)");
    await user.selectOptions(screen.getByLabelText("Format"), "squashfs");
    expect(method().options[0].text).toBe("gzip (default)");
  });

  it("starts the level at the settings' [levels], and says so", async () => {
    render(<CreateDialog inputs={[String.raw`C:\work\src`]} onClose={() => {}} />);
    const user = userEvent.setup();
    const level = () => screen.getByLabelText("Level") as HTMLInputElement;
    // zip's deflate: 9 from the settings, not its own 6.
    expect(await screen.findByText("Default 9, from the settings.")).toBeInTheDocument();
    expect(level().value).toBe("9");
    // A compressed tar takes its codec's.
    await user.selectOptions(screen.getByLabelText("Format"), "tar.zst");
    expect(await screen.findByText("Default 19, from the settings.")).toBeInTheDocument();
    // 7z's lzma2 isn't in the settings: its own default.
    await user.selectOptions(screen.getByLabelText("Format"), "7z");
    expect(await screen.findByText("Default 5.")).toBeInTheDocument();
    expect(level().value).toBe("5");
  });

  it("looks levels up by method, or by codec for tar", () => {
    const zip = applies({ format: "zip", method: undefined }, formats);
    expect(zip.levelKey).toBe("deflate");
    expect(defaultLevel(zip, { deflate: 9 })).toEqual({ value: 9, configured: true });
    expect(defaultLevel(zip, {})).toEqual({ value: 6, configured: false });
    expect(applies({ format: "tar.zst", method: undefined }, formats).levelKey).toBe("zstd");
    expect(applies({ format: "cab", method: undefined }, formats).level).toBeNull();
  });
});

describe("the extract dialog", () => {
  it("follows [extract] until it's changed, and sends only what was changed", async () => {
    const id = useArchives.getState().open(ZIP);
    const tab = useArchives.getState().tabs.find((t) => t.id === id)!;
    render(<ExtractDialog tab={tab} entries={[]} onClose={() => {}} />);
    const overwrite = (await screen.findByLabelText("Existing files")) as HTMLSelectElement;
    await waitFor(() => expect(overwrite.options[0].text).toBe("As in the settings: Keep both (rename the new one)"));
    expect(overwrite.value).toBe("");
    const links = screen.getByRole("checkbox", { name: /Create symbolic links/ });
    await waitFor(() => expect(links).toBeChecked());

    const base = { dest: String.raw`C:\out`, selectedOnly: false, smart: true, password: "", strip: 0 };
    const left = extractArgs(ZIP, [], base);
    expect(left).not.toHaveProperty("overwrite");
    expect(left).not.toHaveProperty("links");
    expect(extractArgs(ZIP, [], { ...base, overwrite: "never", links: false })).toMatchObject({ overwrite: "never", links: false });
  });
});
