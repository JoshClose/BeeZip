// Editing in the browser (docs/M5.md §8.1, §8.2, §8.5): the add dialog, the delete
// confirmation, renaming in place, where drops go, the tab's encoding on every edit, converting.
import { ask } from "@tauri-apps/plugin-dialog";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { dropPaths, dropZone } from "../lib/drop";
import { Browser } from "../features/browser/Browser";
import { convertArgs, convertOutput, CreateDialog, type CreateForm } from "../features/create/CreateDialog";
import { AddDialog, addArgs, initialAdd } from "../features/edit/AddDialog";
import { deleteSelection } from "../features/edit/confirmDelete";
import type { ArchiveInfoOutput, EditOutput, EntryInfo, FormatsListOutput } from "../gen/commands";
import { archiveArgs, type Tab, useArchives } from "../lib/archives";
import { removeArgs } from "../lib/edit";
import { useJobs } from "../lib/jobs";
import { useUi } from "../lib/ui";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true), open: vi.fn(async () => null), save: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ emit: vi.fn(async () => {}), listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ onDragDropEvent: async () => () => {} }) }));
vi.mock("@tauri-apps/api/window", () => ({ getCurrentWindow: () => ({ onCloseRequested: async () => () => {} }) }));
vi.mock("@tauri-apps/api/app", () => ({ setTheme: vi.fn(async () => {}) }));

const ZIP = String.raw`C:\work\a.zip`;
const levels = (min: number, max: number, d: number) => ({ min, max, default: d });
const caps = { list: true, extract: true, create: true, append: true, delete: true, rename: true, encrypt: true, encrypt_headers: false, solid: false, volumes: true, random_access: true };
const formats: FormatsListOutput = {
  formats: [
    { id: "zip", name: "Zip", extensions: [".zip"], caps, methods: [{ id: "store", levels: null }, { id: "deflate", levels: levels(1, 9, 6) }], encryption: ["aes256", "zipcrypto"] },
    { id: "7z", name: "7z", extensions: [".7z"], caps: { ...caps, encrypt_headers: true, solid: true }, methods: [{ id: "lzma2", levels: levels(0, 9, 5) }], encryption: ["aes256"] },
    { id: "tar", name: "Tar", extensions: [".tar"], caps: { ...caps, encrypt: false }, methods: [], encryption: [] },
  ],
  codecs: [{ id: "zstd", name: "Zstandard", extensions: [".zst", ".tzst"], levels: levels(1, 22, 3), threads: true, detected: true }],
  create: ["zip", "7z", "tar", "tar.zst"],
};

const info = (patch: Partial<ArchiveInfoOutput> = {}): ArchiveInfoOutput =>
  ({
    archive: ZIP,
    format: "zip",
    chain: "zip",
    codecs: [],
    entries: 3,
    files: 2,
    dirs: 1,
    links: 0,
    size: 10,
    packed_size: 5,
    ratio: 0.5,
    methods: ["Deflate"],
    encryption: "none",
    solid: false,
    sfx: false,
    comment: null,
    volumes: [ZIP],
    solid_blocks: null,
    encrypted_headers: false,
    locked: false,
    recovery_record: false,
    not_editable: null,
    ...patch,
  }) as ArchiveInfoOutput;

const edited = (patch: Partial<EditOutput> = {}): EditOutput => ({
  path: ZIP,
  format: "zip",
  added: 0,
  replaced: 0,
  removed: 0,
  renamed: 0,
  skipped: 0,
  entries: 3,
  copied: 2,
  recompressed: 0,
  bytes_before: 100,
  bytes_after: 120,
  unencrypted: 0,
  dry_run: false,
  plan: null,
  ...patch,
});

const entry = (path: string, kind: EntryInfo["kind"] = "file", patch: Partial<EntryInfo> = {}): EntryInfo => ({
  id: 1,
  path,
  kind,
  size: kind === "dir" ? null : 10,
  packed_size: kind === "dir" ? null : 5,
  modified: null,
  crc32: null,
  method: null,
  encrypted: false,
  target: null,
  ...patch,
});

/** A fresh tab on `path` with this info. */
function openTab(path = ZIP, patch: Partial<Tab> = {}): Tab {
  const id = useArchives.getState().open(path);
  useArchives.getState().update(id, { info: info({ archive: path }), ...patch });
  return useArchives.getState().tabs.find((t) => t.id === id)!;
}

const tabNow = (id: string) => useArchives.getState().tabs.find((t) => t.id === id)!;

beforeEach(() => {
  fake.reset();
  fake.handlers.set("formats.list", () => formats);
  fake.handlers.set("settings.get", () => ({ settings: { edit: { overwrite: "rename" } } }));
  useArchives.setState({ tabs: [], active: undefined });
  useJobs.setState({ jobs: {}, order: [] });
  useUi.setState({ dialog: undefined, palette: false });
  vi.mocked(ask).mockReset().mockResolvedValue(true);
});

describe("the add dialog", () => {
  it("adds into the folder shown, and copies its command line", async () => {
    fake.handlers.set("cli.line", () => ({ line: "beezip add C:\\work\\a.zip C:\\in\\x.txt --dir docs", omitted: [] }));
    fake.handlers.set("archive.add", () => edited({ added: 1 }));
    const tab = openTab(ZIP, { dir: "docs", encoding: "cp932" });
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<AddDialog tab={tab} inputs={[String.raw`C:\in\x.txt`]} dir={tab.dir} onClose={onClose} />);

    expect(screen.getByRole("heading", { name: "Add to a.zip" })).toBeInTheDocument();
    expect(screen.getByLabelText("Into the folder")).toHaveValue("docs");
    // The default is named from the settings.
    expect(await screen.findByRole("option", { name: "As in the settings: Keep both, adding the new one as “name (1)”" })).toBeInTheDocument();
    expect(screen.getByLabelText("Encrypt the new files")).not.toBeChecked();

    await user.click(screen.getByRole("button", { name: /copy as cli/i }));
    expect(await screen.findByTestId("cli-line")).toHaveTextContent("beezip add");
    expect(fake.calls.find((c) => c.name === "cli.line")?.args).toMatchObject({
      command: "archive.add",
      args: { archive: ZIP, inputs: [String.raw`C:\in\x.txt`], dir: "docs", name_encoding: "cp932" },
    });

    await user.selectOptions(screen.getByLabelText("Already there"), "always");
    await user.selectOptions(screen.getByLabelText("Method"), "store");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(onClose).toHaveBeenCalled();
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.add")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.add")?.args).toEqual({
      archive: ZIP,
      inputs: [String.raw`C:\in\x.txt`],
      dir: "docs",
      overwrite: "always",
      method: "store",
      name_encoding: "cp932",
    });
    // Afterwards the tab lists again, in the same folder.
    await waitFor(() => expect(tabNow(tab.id).version).toBe(1));
    expect(tabNow(tab.id)).toMatchObject({ dir: "docs", info: undefined });
  });

  it("encrypts the new files of an encrypted archive, or adds them in the clear when told", async () => {
    const tab = openTab(ZIP);
    useArchives.getState().update(tab.id, { info: info({ encryption: "some" }) });
    const encrypted = tabNow(tab.id);
    const user = userEvent.setup();
    render(<AddDialog tab={encrypted} inputs={["C:\\in\\x.txt"]} dir="" onClose={() => {}} />);

    const box = screen.getByRole("checkbox", { name: "Encrypt the new files" });
    expect(box).toBeChecked();
    // It needs the password before it can add.
    expect(screen.getByRole("button", { name: "Add" })).toBeDisabled();
    await user.type(screen.getByLabelText("Password"), "pw");
    expect(screen.getByRole("button", { name: "Add" })).toBeEnabled();

    await user.click(box);
    expect(screen.getByText("The new files go in unencrypted, beside encrypted ones.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).toBeNull();
    expect(screen.getByRole("button", { name: "Add" })).toBeEnabled();

    // As arguments: the password, or `unencrypted`.
    const form = initialAdd(encrypted, ["C:\\in\\x.txt"], "");
    expect(form).toMatchObject({ encrypt: true, password: "" });
    expect(addArgs(encrypted, { ...form, password: "pw" }, formats)).toEqual({ archive: ZIP, inputs: ["C:\\in\\x.txt"], password: "pw" });
    expect(addArgs(encrypted, { ...form, password: "pw", encryption: "zipcrypto" }, formats)).toMatchObject({ encryption: "zipcrypto" });
    expect(addArgs(encrypted, { ...form, encrypt: false, password: "pw" }, formats)).toEqual({ archive: ZIP, inputs: ["C:\\in\\x.txt"], unencrypted: true });
  });

  it("gives a 7z with encrypted names its own password, and a tar none", () => {
    const sz = openTab("C:\\work\\b.7z", { password: "secret" });
    useArchives.getState().update(sz.id, { info: info({ format: "7z", encryption: "all", encrypted_headers: true }) });
    const t = tabNow(sz.id);
    const form = initialAdd(t, ["C:\\x"], "");
    expect(form).toMatchObject({ encrypt: true, password: "secret" });
    // Turning it off can't apply: the names stay encrypted with the archive's password.
    expect(addArgs(t, { ...form, encrypt: false }, formats)).toEqual({ archive: "C:\\work\\b.7z", inputs: ["C:\\x"], password: "secret" });

    const tar = openTab("C:\\work\\c.tar.zst");
    useArchives.getState().update(tar.id, { info: info({ format: "tar", codecs: ["zstd"] }) });
    expect(addArgs(tabNow(tar.id), { ...initialAdd(tabNow(tar.id), ["C:\\x"], "a/b/"), level: 19, password: "x", encrypt: true }, formats)).toEqual({
      archive: "C:\\work\\c.tar.zst",
      inputs: ["C:\\x"],
      dir: "a/b",
      level: 19,
    });
  });
});

describe("deleting", () => {
  it("asks first, then removes the selection", async () => {
    fake.handlers.set("archive.remove", () => edited({ removed: 3 }));
    const tab = openTab(ZIP, { dir: "docs", password: "pw" });
    vi.mocked(ask).mockResolvedValueOnce(false);
    await deleteSelection(tab, 3, { all: false, paths: ["docs/a", "docs/b", "docs/c"] });
    expect(ask).toHaveBeenCalledWith("Delete 3 items from a.zip?\n\nThis can't be undone.", expect.objectContaining({ okLabel: "Delete", kind: "warning" }));
    expect(fake.calls.filter((c) => c.name === "archive.remove")).toHaveLength(0);

    await deleteSelection(tab, 3, { all: false, paths: ["docs/a", "docs/b", "docs/c"] });
    expect(fake.calls.find((c) => c.name === "archive.remove")?.args).toEqual({ archive: ZIP, entries: ["docs/a", "docs/b", "docs/c"], password: "pw" });
    expect(tabNow(tab.id)).toMatchObject({ version: 1, dir: "docs", selected: [] });

    // One item is named; every row of a folder goes by a pattern, since not every row is loaded.
    await deleteSelection(tab, 1, { all: false, paths: ["docs/readme.txt"] });
    expect(vi.mocked(ask).mock.calls[2][0]).toMatch(/^Delete readme\.txt from a\.zip\?/);
    expect(removeArgs(tab, { all: true, paths: [] })).toMatchObject({ glob: ["docs/**"] });
    expect(removeArgs({ ...tab, dir: "" }, { all: true, paths: [] })).toMatchObject({ glob: ["*"] });
    expect(removeArgs({ ...tab, dir: "a[1]*" }, { all: true, paths: [] })).toMatchObject({ glob: ["a[[]1[]][*]/**"] });
  });
});

describe("the browser", () => {
  // TanStack Virtual sizes the viewport from clientWidth and clientHeight, which jsdom leaves at 0.
  const sizes = { clientHeight: 600, clientWidth: 900 };
  beforeAll(() => {
    for (const [k, v] of Object.entries(sizes)) Object.defineProperty(HTMLElement.prototype, k, { configurable: true, get: () => v });
  });
  afterAll(() => {
    for (const k of Object.keys(sizes)) delete (HTMLElement.prototype as unknown as Record<string, unknown>)[k];
  });

  let rows: EntryInfo[] = [];
  beforeEach(() => {
    rows = [entry("docs", "dir"), entry("b.txt"), entry("readme.txt")];
    fake.handlers.set("archive.list", (args) => {
      const dir = (args as { dir?: string }).dir;
      const list = dir ? [] : rows;
      return { entries: list, total: list.length, offset: 0, has_more: false };
    });
    fake.handlers.set("entry.read", () => ({ data: "", encoding: "text", bytes_read: 0, eof: true, offset: 0, size: 0 }));
    // After an edit the tab reads its info again, which says whether it can still be edited.
    fake.handlers.set("archive.info", () => info());
  });

  /** The tab's browser, following the store as App does. */
  function Live({ id }: { id: string }) {
    const tab = useArchives((s) => s.tabs.find((t) => t.id === id));
    return tab ? <Browser tab={tab} /> : null;
  }

  function showBrowser(patch: Partial<Tab> = {}) {
    const tab = openTab(ZIP, patch);
    render(<Live id={tab.id} />);
    return { id: tab.id, unsub: () => {} };
  }

  it("renames in place: Enter saves, a refusal shows beside it, Escape cancels", async () => {
    let fail = true;
    fake.handlers.set("archive.rename", (args) => {
      if (fail) throw { code: "Conflict", message: "`b.txt` is already in a.zip" };
      const to = (args as { to: string }).to;
      rows = [entry("docs", "dir"), entry("b.txt"), entry(to)];
      return edited({ renamed: 1 });
    });
    const { id, unsub } = showBrowser({ encoding: "cp932" });
    const user = userEvent.setup();
    const name = await screen.findByText("readme.txt");
    fireEvent.mouseDown(name.closest("[role=row]")!, { button: 0 });
    fireEvent.keyDown(screen.getByTestId("entry-scroller"), { key: "F2" });

    const field = await screen.findByLabelText("New name for readme.txt");
    expect(field).toHaveValue("readme.txt");
    await user.clear(field);
    await user.type(field, "b.txt{Enter}");
    expect(await screen.findByRole("alert")).toHaveTextContent("Conflict: `b.txt` is already in a.zip");
    expect(fake.calls.find((c) => c.name === "archive.rename")?.args).toEqual({ archive: ZIP, from: "readme.txt", to: "b.txt", name_encoding: "cp932" });

    // Another name goes through; the tab lists again with the renamed entry selected.
    fail = false;
    await waitFor(() => expect(screen.getByLabelText("New name for readme.txt")).toBeEnabled());
    await user.clear(screen.getByLabelText("New name for readme.txt"));
    await user.type(screen.getByLabelText("New name for readme.txt"), "notes.md{Enter}");
    expect(await within(screen.getByTestId("entry-scroller")).findByText("notes.md")).toBeInTheDocument();
    await waitFor(() => expect(tabNow(id).selected).toEqual([2]));
    expect(tabNow(id).renaming).toBeUndefined();
    expect(screen.queryByRole("textbox")).toBeNull();

    // Escape leaves it as it was.
    fireEvent.keyDown(screen.getByTestId("entry-scroller"), { key: "F2" });
    const again = await screen.findByLabelText("New name for notes.md");
    await user.type(again, "x{Escape}");
    expect(screen.queryByLabelText("New name for notes.md")).toBeNull();
    expect(fake.calls.filter((c) => c.name === "archive.rename")).toHaveLength(2);
    unsub();
  });

  it("deletes with the Delete key, after asking", async () => {
    fake.handlers.set("archive.remove", () => edited({ removed: 1 }));
    const { unsub } = showBrowser();
    const name = await screen.findByText("b.txt");
    fireEvent.mouseDown(name.closest("[role=row]")!, { button: 0 });
    fireEvent.keyDown(screen.getByTestId("entry-scroller"), { key: "Delete" });
    await waitFor(() => expect(ask).toHaveBeenCalledWith(expect.stringMatching(/^Delete b\.txt from a\.zip\?/), expect.anything()));
    await waitFor(() => expect(fake.calls.find((c) => c.name === "archive.remove")?.args).toEqual({ archive: ZIP, entries: ["b.txt"] }));
    unsub();
  });

  it("disables the edit commands of an archive that can't be edited, saying why", async () => {
    const why = "a.rar is a RAR archive, which BeeZip reads but never writes";
    const { unsub } = showBrowser({ info: info({ format: "rar", not_editable: why }) });
    await screen.findByText("b.txt");
    for (const label of ["Add files…", "Add folder…", "Rename", "Delete"]) {
      const button = screen.getByRole("button", { name: label });
      expect(button).toBeDisabled();
      expect(button.parentElement).toHaveAttribute("title", why);
    }
    expect(screen.getByRole("button", { name: "Convert…" })).toBeEnabled();
    expect(screen.getByText(`Can't be edited: ${why}`)).toBeInTheDocument();
    fireEvent.mouseDown(within(screen.getByTestId("entry-scroller")).getByText("b.txt").closest("[role=row]")!, { button: 0 });
    fireEvent.keyDown(screen.getByTestId("entry-scroller"), { key: "Delete" });
    fireEvent.keyDown(screen.getByTestId("entry-scroller"), { key: "F2" });
    expect(ask).not.toHaveBeenCalled();
    expect(screen.queryByRole("textbox")).toBeNull();
    unsub();
  });
});

describe("drops (docs/M5.md §8.2)", () => {
  it("go to the add dialog on an editable table, into the folder shown", async () => {
    const tab = openTab(ZIP, { dir: "docs" });
    await dropPaths(["C:\\in\\x.txt", "C:\\in\\other.zip"], "entries");
    expect(useUi.getState().dialog).toEqual({ kind: "add", tab: tab.id, inputs: ["C:\\in\\x.txt", "C:\\in\\other.zip"], dir: "docs" });
    // A second drop joins the open dialog.
    await dropPaths(["C:\\in\\y.txt"], "elsewhere");
    expect(useUi.getState().dialog).toMatchObject({ kind: "add", inputs: ["C:\\in\\y.txt"] });
  });

  it("go into a new archive, saying why, on one that can't be edited", async () => {
    const why = "a.7z.001 is split into volumes, and BeeZip doesn't edit split archives.";
    openTab("C:\\work\\a.7z.001", { info: info({ not_editable: why }) });
    await dropPaths(["C:\\in\\x.txt"], "entries");
    expect(useUi.getState().dialog).toEqual({ kind: "create", inputs: ["C:\\in\\x.txt"], note: why });
  });

  it("read the archive's info first when it isn't in yet", async () => {
    fake.handlers.set("archive.info", () => info({ not_editable: "x.zip is read-only" }));
    const id = useArchives.getState().open(ZIP);
    await dropPaths(["C:\\in\\x.txt"], "entries");
    expect(useUi.getState().dialog).toMatchObject({ kind: "create", note: "x.zip is read-only" });
    expect(tabNow(id).info).toBeUndefined();
  });

  it("elsewhere, open one archive or pack anything else, as before", async () => {
    fake.handlers.set("file.detect", (args) => ({ format: (args as { path: string }).path.endsWith(".zip") ? "zip" : null }));
    openTab(ZIP);
    await dropPaths(["C:\\in\\other.zip"], "elsewhere");
    expect(useArchives.getState().tabs.map((t) => t.path)).toEqual([ZIP, "C:\\in\\other.zip"]);
    expect(useUi.getState().dialog).toBeUndefined();
    await dropPaths(["C:\\in\\x.txt"], "elsewhere");
    expect(useUi.getState().dialog).toEqual({ kind: "create", inputs: ["C:\\in\\x.txt"] });
  });

  it("know the entry table from the rest of the window", () => {
    document.body.innerHTML = `<main data-drop="entries"><div id="row"></div></main><header id="tabs"></header>`;
    const at = vi.fn();
    document.elementFromPoint = at;
    at.mockReturnValueOnce(document.getElementById("row"));
    expect(dropZone(10, 10)).toBe("entries");
    at.mockReturnValueOnce(document.getElementById("tabs"));
    expect(dropZone(10, 10)).toBe("elsewhere");
    at.mockReturnValueOnce(null);
    expect(dropZone(10, 10)).toBe("elsewhere");
  });
});

describe("the tab's encoding (docs/M5.md §8.4) on edits", () => {
  it("goes with removing, renaming and adding, so paths match the names shown", () => {
    const tab = openTab(ZIP, { encoding: "cp866" });
    expect(archiveArgs(tab)).toEqual({ name_encoding: "cp866" });
    expect(removeArgs(tab, { all: false, paths: ["док"] })).toEqual({ archive: ZIP, entries: ["док"], name_encoding: "cp866" });
    expect(addArgs(tab, initialAdd(tab, ["C:\\x"], "док"), formats)).toMatchObject({ dir: "док", name_encoding: "cp866" });
  });
});

describe("converting (docs/M5.md §8.5)", () => {
  const form = (patch: Partial<CreateForm> = {}): CreateForm => ({
    inputs: [],
    output: "C:\\work\\a.7z",
    format: "7z",
    solid: true,
    password: "",
    encryption: "aes256",
    encryptHeaders: true,
    volumeSize: "",
    exclude: "",
    ...patch,
  });

  it("names the output after the source, with the new extension", () => {
    expect(convertOutput("C:\\work\\a.zip", "7z")).toBe("C:\\work\\a.7z");
    expect(convertOutput("C:\\work\\a.tar.gz", "zip")).toBe("C:\\work\\a.zip");
    expect(convertOutput("C:\\work\\a.7z.001", "zip")).toBe("C:\\work\\a.zip");
    expect(convertOutput("C:\\work\\a.part1.rar", "7z")).toBe("C:\\work\\a.7z");
    expect(convertOutput("C:\\work\\setup.exe", "zip")).toBe("C:\\work\\setup.zip");
  });

  it("passes the source's password and encoding, and the new archive's options", () => {
    const tab = openTab(ZIP, { password: "old", encoding: "cp932" });
    expect(convertArgs(tab, form({ password: "new", solid: false }), false, formats)).toEqual({
      archive: ZIP,
      output: "C:\\work\\a.7z",
      format: "7z",
      new_password: "new",
      solid: false,
      password: "old",
      name_encoding: "cp932",
    });
    expect(convertArgs(tab, form({ format: "tar.zst", output: "C:\\work\\a.tar.zst" }), true, formats)).toMatchObject({ format: "tar.zst", decrypt: true });
  });

  it("opens the create dialog in its convert mode, keeping encryption unless told", async () => {
    fake.handlers.set("cli.line", () => ({ line: "beezip convert C:\\work\\a.zip C:\\work\\a.7z", omitted: ["new_password"] }));
    fake.handlers.set("archive.convert", () => ({ path: "C:\\work\\a.7z", format: "7z", files: 2, dirs: 0, links: 0, bytes_in: 1, bytes_out: 1, ratio: 1, copied: 0, recompressed: 2, skipped: [], dry_run: false, plan: null, volumes: null }));
    const tab = openTab(ZIP);
    useArchives.getState().update(tab.id, { info: info({ encryption: "all" }) });
    const user = userEvent.setup();
    render(<CreateDialog inputs={[]} source={tabNow(tab.id)} onClose={() => {}} />);

    expect(screen.getByRole("heading", { name: "Convert a.zip" })).toBeInTheDocument();
    expect(screen.getByText(ZIP)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Inputs" })).toBeNull();
    expect(screen.getByLabelText("Save as")).toHaveValue("C:\\work\\a.7z");
    await waitFor(() => expect(screen.getByLabelText("Format")).toHaveValue("7z"));
    // Encrypted, with no password known: a new one, or the person's word.
    const go = screen.getByRole("button", { name: /Convert/ });
    expect(go).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: "Write a.zip's encrypted entries without a password" }));
    expect(go).toBeEnabled();

    await user.click(screen.getByRole("button", { name: /copy as cli/i }));
    expect(await screen.findByTestId("cli-line")).toHaveTextContent("beezip convert");
    expect(fake.calls.find((c) => c.name === "cli.line")?.args).toMatchObject({
      command: "archive.convert",
      args: { archive: ZIP, output: "C:\\work\\a.7z", format: "7z", decrypt: true },
    });
    await user.click(go);
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.convert")).toBe(true));

    // tar can't hold a password at all.
    const dialog = render(<CreateDialog inputs={[]} source={tabNow(tab.id)} onClose={() => {}} />);
    await user.selectOptions(within(dialog.baseElement).getAllByLabelText("Format").at(-1)!, "tar.zst");
    expect(within(dialog.baseElement).getByText("tar.zst can't be encrypted.")).toBeInTheDocument();
  });

  it("keeps the source's password for the new archive when it's known", () => {
    const tab = openTab(ZIP, { password: "pw" });
    useArchives.getState().update(tab.id, { info: info({ encryption: "some" }) });
    render(<CreateDialog inputs={[]} source={tabNow(tab.id)} onClose={() => {}} />);
    expect(screen.getByLabelText("Password")).toHaveValue("pw");
    expect(screen.queryByRole("checkbox", { name: /without a password/ })).toBeNull();
    expect(screen.getByRole("button", { name: /Convert/ })).toBeEnabled();
  });
});
