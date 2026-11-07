// Opening entries (docs/M5.md §8.3): archives as tabs, programs after a question, everything
// else in its app, and the question when an opened file changes.
import { emit } from "@tauri-apps/api/event";
import { ask } from "@tauri-apps/plugin-dialog";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ChangedPrompt } from "../features/edit/ChangedPrompt";
import { RunPrompt } from "../features/edit/RunPrompt";
import type { ArchiveInfoOutput, EntryInfo, FormatsListOutput } from "../gen/commands";
import { type Tab, useArchives } from "../lib/archives";
import { useJobs } from "../lib/jobs";
import { entryChanged, isProgram, openEntry, readsAsArchive, updateArgs, useOpened } from "../lib/opened";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true) }));
vi.mock("@tauri-apps/api/event", () => ({ emit: vi.fn(async () => {}), listen: vi.fn(async () => () => {}) }));

const ZIP = String.raw`C:\work\a.zip`;
const TEMP = String.raw`C:\Users\me\AppData\Local\Temp\BeeZip\open\0a1b2c3d`;

const formats = {
  formats: [{ id: "zip", name: "Zip", extensions: [".zip"], caps: { list: true }, methods: [], encryption: [] }],
  codecs: [{ id: "gzip", name: "gzip", extensions: [".gz", ".tgz"], levels: null, threads: false, detected: true }],
  create: ["zip"],
} as unknown as FormatsListOutput;

const info = (patch: Partial<ArchiveInfoOutput> = {}) => ({ encryption: "none", encrypted_headers: false, ...patch }) as ArchiveInfoOutput;

const file = (path: string, patch: Partial<EntryInfo> = {}): EntryInfo => ({
  id: 1,
  path,
  kind: "file",
  size: 10,
  packed_size: 5,
  modified: null,
  crc32: null,
  method: null,
  encrypted: false,
  target: null,
  ...patch,
});

function openTab(patch: Partial<Tab> = {}): Tab {
  const id = useArchives.getState().open(ZIP);
  useArchives.getState().update(id, { info: info(), ...patch });
  return useArchives.getState().tabs.find((t) => t.id === id)!;
}

/** `entry.open` extracts to a folder of its own and says where. */
function extracting() {
  fake.handlers.set("entry.open", (args) => {
    const a = args as { entry: string; launch?: boolean };
    return { path: `${TEMP}\\${a.entry.split("/").pop()}`, launched: a.launch !== false };
  });
}

beforeEach(() => {
  fake.reset();
  fake.handlers.set("formats.list", () => formats);
  extracting();
  useArchives.setState({ tabs: [], active: undefined });
  useJobs.setState({ jobs: {}, order: [] });
  useOpened.setState({ files: {}, changed: [] });
  vi.mocked(ask).mockReset().mockResolvedValue(true);
  vi.mocked(emit).mockClear();
});

describe("opening an entry", () => {
  it("knows programs and archives by their names", () => {
    for (const name of ["setup.exe", "INSTALL.MSI", "run.bat", "x.cmd", "a.ps1", "a.vbs", "a.js", "a.lnk", "a.scr"]) expect(isProgram(name), name).toBe(true);
    for (const name of ["readme.txt", "photo.jpg", "a.zip", "exe"]) expect(isProgram(name), name).toBe(false);
    expect(readsAsArchive("docs/inner.ZIP", ["zip", "gz"])).toBe(true);
    expect(readsAsArchive("b.tar.gz", ["zip", "gz"])).toBe(true);
    expect(readsAsArchive("report.docx", ["zip", "gz"])).toBe(false);
  });

  it("opens a file in its app, and notes it for the question", async () => {
    const tab = openTab({ encoding: "cp932" });
    await openEntry(tab, file("docs/readme.txt"));
    expect(fake.calls.find((c) => c.name === "entry.open")?.args).toEqual({ archive: ZIP, entry: "docs/readme.txt", name_encoding: "cp932" });
    expect(ask).not.toHaveBeenCalled();
    expect(Object.values(useOpened.getState().files)).toEqual([{ path: `${TEMP}\\readme.txt`, tab: tab.id, entry: "docs/readme.txt", encrypted: false }]);
  });

  it("opens an archive inside it as a new tab", async () => {
    const tab = openTab();
    await openEntry(tab, file("inner.zip"));
    expect(fake.calls.find((c) => c.name === "entry.open")?.args).toEqual({ archive: ZIP, entry: "inner.zip", launch: false });
    expect(useArchives.getState().tabs.map((t) => t.path)).toEqual([ZIP, `${TEMP}\\inner.zip`]);
    expect(useArchives.getState().active).not.toBe(tab.id);
    expect(useOpened.getState().files).toEqual({});
  });

  it("asks before running a program, with Cancel in front", async () => {
    const tab = openTab();
    const user = userEvent.setup();
    render(<RunPrompt />);
    const declined = openEntry(tab, file("bin/setup.exe"));
    expect(await screen.findByRole("heading", { name: "Run setup.exe from a.zip?" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await declined;
    expect(fake.calls.some((c) => c.name === "entry.open")).toBe(false);
    expect(screen.queryByRole("heading", { name: /^Run/ })).toBeNull();

    const ran = openEntry(tab, file("bin/setup.exe"));
    await user.click(await screen.findByRole("button", { name: /Run/ }));
    await ran;
    expect(fake.calls.find((c) => c.name === "entry.open")?.args).toEqual({ archive: ZIP, entry: "bin/setup.exe" });
    expect(ask).not.toHaveBeenCalled();
  });
});

describe("a changed entry", () => {
  const changed = { archive: ZIP, entry: "docs/readme.txt", path: `${TEMP}\\readme.txt` };

  it("asks whether to update the archive, and puts the file back in the entry's folder", async () => {
    fake.handlers.set("archive.add", () => ({ path: ZIP, replaced: 1 }));
    const tab = openTab();
    await openEntry(tab, file("docs/readme.txt"));
    render(<ChangedPrompt />);
    expect(screen.queryByText("readme.txt was changed")).toBeNull();

    entryChanged(changed);
    // Twice is still one question.
    entryChanged(changed);
    expect(await screen.findByText("readme.txt was changed")).toBeInTheDocument();
    expect(screen.getByText("Update it in a.zip?")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: /Update/ }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.add")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.add")?.args).toEqual({ archive: ZIP, inputs: [`${TEMP}\\readme.txt`], dir: "docs", overwrite: "always" });
    expect(screen.queryByText("readme.txt was changed")).toBeNull();
    // The tab lists again.
    await waitFor(() => expect(useArchives.getState().tabs[0].version).toBe(1));
  });

  it("does nothing on Not now, and asks again after the next change", async () => {
    const tab = openTab();
    await openEntry(tab, file("docs/readme.txt"));
    render(<ChangedPrompt />);
    entryChanged(changed);
    await userEvent.setup().click(await screen.findByRole("button", { name: "Not now" }));
    expect(screen.queryByText("readme.txt was changed")).toBeNull();
    expect(fake.calls.some((c) => c.name === "archive.add")).toBe(false);
    entryChanged(changed);
    expect(await screen.findByText("readme.txt was changed")).toBeInTheDocument();
  });

  it("takes the tab's password for an encrypted entry, and keeps a plain one plain", () => {
    const tab = openTab({ password: "pw", info: info({ encryption: "some" }) });
    const base = { path: `${TEMP}\\a.txt`, tab: tab.id, entry: "a.txt" };
    expect(updateArgs(tab, { ...base, encrypted: true })).toEqual({ archive: ZIP, inputs: [base.path], overwrite: "always", password: "pw" });
    expect(updateArgs(tab, { ...base, encrypted: false })).toEqual({ archive: ZIP, inputs: [base.path], overwrite: "always", unencrypted: true });
    // A 7z whose names are encrypted needs its password for any change.
    const headers = { ...tab, info: info({ encryption: "all", encrypted_headers: true }) };
    expect(updateArgs(headers, { ...base, encrypted: false })).toMatchObject({ password: "pw" });
    expect(updateArgs(headers, { ...base, encrypted: false })).not.toHaveProperty("unencrypted");
  });

  it("is forgotten with its tab, here and in Rust", async () => {
    const tab = openTab();
    await openEntry(tab, file("docs/readme.txt"));
    render(<ChangedPrompt />);
    useArchives.getState().close(tab.id);
    expect(emit).toHaveBeenCalledWith("opened-forget", { paths: [`${TEMP}\\readme.txt`] });
    expect(useOpened.getState().files).toEqual({});
    entryChanged(changed);
    expect(useOpened.getState().changed).toEqual([]);
    expect(screen.queryByText("readme.txt was changed")).toBeNull();
  });
});
