import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { open as pickFiles } from "@tauri-apps/plugin-dialog";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apartFrom, applies, type CreateForm, CreateDialog, createArgs, defaultLevel, defaultOutput, levelHint, levelLabel, levelNote, notReady, withFormat } from "../features/create/CreateDialog";
import { ownLevel } from "../features/edit/AddDialog";
import { levelTargets } from "../features/settings/Settings";
import type { FormatsListOutput } from "../gen/commands";
import { codecOfTar } from "../lib/formats";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

const levels = (min: number, max: number, d: number) => ({ min, max, default: d });
const caps = { list: true, extract: true, create: true, append: false, delete: false, rename: false, encrypt: true, encrypt_headers: false, solid: false, volumes: true, random_access: true };

// Enough of `formats.list` for the dialog.
const formats: FormatsListOutput = {
  formats: [
    {
      id: "bhive",
      name: "BeeZip",
      extensions: [".bhive"],
      caps: { ...caps, append: true, delete: true, rename: true, encrypt: false },
      methods: [],
      encryption: [],
      menu: true,
      levels: levels(0, 4, 2),
      level_names: ["none", "fast", "balanced", "high", "max"],
    },
    { id: "zip", name: "Zip", extensions: [".zip"], caps, methods: [{ id: "store", levels: null }, { id: "deflate", levels: levels(1, 9, 6) }, { id: "zstd", levels: levels(1, 22, 3) }], encryption: ["aes256", "zipcrypto"], menu: true, levels: null, level_names: [] },
    { id: "7z", name: "7z", extensions: [".7z"], caps: { ...caps, encrypt_headers: true, solid: true }, methods: [{ id: "lzma2", levels: levels(0, 9, 5) }, { id: "copy", levels: null }], encryption: ["aes256"], menu: true, levels: null, level_names: [] },
    { id: "tar", name: "Tar", extensions: [".tar"], caps: { ...caps, encrypt: false }, methods: [], encryption: [], menu: true, levels: null, level_names: [] },
    { id: "iso", name: "ISO image", extensions: [".iso"], caps: { ...caps, encrypt: false }, methods: [], encryption: [], menu: true, levels: null, level_names: [] },
    {
      id: "squashfs",
      name: "squashfs image",
      extensions: [".squashfs", ".sqfs", ".snap"],
      caps: { ...caps, encrypt: false },
      methods: [{ id: "gzip", levels: levels(1, 9, 9) }, { id: "xz", levels: levels(0, 9, 6) }, { id: "lz4", levels: null }],
      encryption: [], menu: true, levels: null, level_names: [],
    },
  ],
  codecs: [
    { id: "zstd", name: "Zstandard", extensions: [".zst", ".tzst"], levels: levels(1, 22, 3), threads: true, detected: true },
    { id: "gzip", name: "gzip", extensions: [".gz", ".tgz"], levels: levels(0, 9, 6), threads: false, detected: true },
  ],
  create: ["zip", "bhive", "7z", "tar", "tar.gz", "tar.zst", "iso", "squashfs"],
};

const form = (patch: Partial<CreateForm>): CreateForm => ({
  inputs: [String.raw`C:\work\src`],
  output: String.raw`C:\work\src.zip`,
  format: "zip",
  solid: true,
  password: "",
  encryption: "aes256",
  encryptHeaders: true,
  volumeSize: "",
  exclude: "",
  ...patch,
});

describe("the create dialog's arguments", () => {
  it("passes only what applies to the format", () => {
    expect(createArgs(form({}), formats)).toEqual({ output: String.raw`C:\work\src.zip`, inputs: [String.raw`C:\work\src`], format: "zip" });

    const sz = createArgs(
      form({ format: "7z", output: "C:\\work\\src.7z", method: "lzma2", level: 9, solid: false, password: "pw", encryptHeaders: false, volumeSize: "100m", exclude: "*.tmp\n\nnode_modules" }),
      formats,
    );
    expect(sz).toEqual({
      output: "C:\\work\\src.7z",
      inputs: [String.raw`C:\work\src`],
      format: "7z",
      method: "lzma2",
      level: 9,
      password: "pw",
      encrypt_headers: false,
      solid: false,
      exclude: ["*.tmp", "node_modules"],
      volume_size: "100m",
    });

    // A tar has no password, method or solid blocks; its codec has the level and threads.
    const tar = createArgs(form({ format: "tar.zst", method: "lzma2", password: "pw", solid: false, level: 19, threads: 4, volumeSize: "1048576" }), formats);
    expect(tar).toEqual({ output: String.raw`C:\work\src.zip`, inputs: [String.raw`C:\work\src`], format: "tar.zst", level: 19, threads: 4, volume_size: 1048576 });

    expect(createArgs(form({ password: "pw", encryption: "zipcrypto" }), formats)).toMatchObject({ password: "pw", encryption: "zipcrypto" });

    // squashfs takes its method's level and no password; an ISO takes neither, nor threads.
    const base = { output: String.raw`C:\work\src.zip`, inputs: [String.raw`C:\work\src`] };
    expect(createArgs(form({ format: "squashfs", method: "xz", level: 9, password: "pw" }), formats)).toEqual({ ...base, format: "squashfs", method: "xz", level: 9 });
    expect(createArgs(form({ format: "squashfs", level: 9 }), formats)).toEqual({ ...base, format: "squashfs", level: 9 });
    expect(createArgs(form({ format: "squashfs", method: "lz4", level: 9 }), formats)).toEqual({ ...base, format: "squashfs", method: "lz4" });
    expect(createArgs(form({ format: "iso", method: "xz", level: 9, threads: 4, password: "pw" }), formats)).toEqual({ ...base, format: "iso" });
  });

  it("gives a .bhive its level by name, no method, and its own password (docs/M13.md §4, docs/M14.md §5)", () => {
    const base = { output: String.raw`C:\work\src.zip`, inputs: [String.raw`C:\work\src`], format: "bhive" };
    expect(createArgs(form({ format: "bhive" }), formats)).toEqual(base);
    expect(createArgs(form({ format: "bhive", level: 3, method: "lzma2", password: "pw", solid: false, threads: 8 }), formats)).toEqual({ ...base, level: "high", threads: 8, password: "pw" });
    expect(createArgs(form({ format: "bhive", level: 0 }), formats)).toEqual({ ...base, level: "none" });

    const a = applies({ format: "bhive", method: undefined }, formats);
    expect(a).toMatchObject({ level: { min: 0, max: 4, default: 2 }, levelKey: "bhive", methods: [], password: false, protection: true, solid: false, threads: true });
    expect(levelLabel(a, 2)).toBe("Balanced");
    expect(levelNote(a, 4)).toBe("LZMA2: the smallest, the slowest");
    expect(levelHint(defaultLevel(a, {})!, levelLabel(a, 2))).toBe("Default Balanced.");
    expect(levelHint(defaultLevel(a, { bhive: 3 })!, levelLabel(a, 3))).toBe("Default High, from the settings.");
    // The others keep their numbers.
    const zip = applies({ format: "zip", method: undefined }, formats);
    expect(zip.levelNames).toEqual([]);
    expect(levelLabel(zip, 6)).toBe("6");
    expect(levelNote(zip, 6)).toBe("1 is fastest, 9 smallest");
    expect(withFormat(String.raw`C:\a\b.bhive`, "zip")).toBe(String.raw`C:\a\b.zip`);
  });

  it("starts an add at the level the .bhive was made at", () => {
    const names = ["none", "fast", "balanced", "high", "max"];
    const info = (properties: { level: string; name: string; value: string }[]) => ({ properties }) as never;
    expect(ownLevel(info([{ level: "bhive", name: "Level", value: "max" }]), names)).toBe(4);
    expect(ownLevel(info([{ level: "bhive", name: "Cells", value: "3" }]), names)).toBeUndefined();
    expect(ownLevel(info([{ level: "bhive", name: "Level", value: "max" }]), [])).toBeUndefined();
    expect(ownLevel(undefined, names)).toBeUndefined();
  });

  it("has `[levels] bhive` in the settings, by name", () => {
    const bhive = levelTargets(formats).find((l) => l.name === "bhive");
    expect(bhive).toEqual({
      name: "bhive",
      range: { min: 0, max: 4 },
      own: 2,
      applies: "For .bhive archives.",
      others: null,
      names: ["none", "fast", "balanced", "high", "max"],
    });
  });

  it("names the output after the inputs and the format", () => {
    expect(defaultOutput([String.raw`C:\a\report.pdf`], "zip")).toBe(String.raw`C:\a\report.zip`);
    expect(defaultOutput([String.raw`C:\a\x`, String.raw`C:\a\y`], "7z")).toBe(String.raw`C:\a\a.7z`);
    expect(withFormat(String.raw`C:\a\b.zip`, "tar.zst")).toBe(String.raw`C:\a\b.tar.zst`);
    expect(withFormat(String.raw`C:\a\b.tar.gz`, "7z")).toBe(String.raw`C:\a\b.7z`);
    expect(withFormat(String.raw`C:\a\core.7z`, "7z")).toBe(String.raw`C:\a\core.7z`);
    // M5's kinds: a cpio under a codec, `.Z` in either case, ar and cab.
    expect(withFormat(String.raw`C:\a\initrd.cpio.gz`, "tar.Z")).toBe(String.raw`C:\a\initrd.tar.Z`);
    expect(withFormat(String.raw`C:\a\b.tar.Z`, "cpio.lzo")).toBe(String.raw`C:\a\b.cpio.lzo`);
    expect(withFormat(String.raw`C:\a\b.taz`, "ar")).toBe(String.raw`C:\a\b.ar`);
    expect(withFormat(String.raw`C:\a\b.ar`, "cab")).toBe(String.raw`C:\a\b.cab`);
    // The disk images.
    expect(withFormat(String.raw`C:\a\b.cab`, "iso")).toBe(String.raw`C:\a\b.iso`);
    expect(withFormat(String.raw`C:\a\b.iso`, "squashfs")).toBe(String.raw`C:\a\b.squashfs`);
    expect(withFormat(String.raw`C:\a\b.sqfs`, "dmg")).toBe(String.raw`C:\a\b.dmg`);
    expect(withFormat(String.raw`C:\a\b.dmg`, "zip")).toBe(String.raw`C:\a\b.zip`);
    // Converting into the source's own format never offers the source's own path.
    expect(apartFrom(String.raw`C:\a\b.bhive`, String.raw`C:\A\B.bhive`)).toBe(String.raw`C:\A\B (1).bhive`);
    expect(apartFrom(String.raw`C:\a\b.tar.zst`, String.raw`C:\a\b.tar.zst`)).toBe(String.raw`C:\a\b (1).tar.zst`);
    expect(apartFrom(String.raw`C:\a\b.bhive`, String.raw`C:\a\b.zip`)).toBe(String.raw`C:\a\b.zip`);
  });

  it("finds the codec of a compressed tar or cpio, whatever the case", () => {
    const all: FormatsListOutput = {
      ...formats,
      codecs: [...formats.codecs, { id: "compress", name: "Unix compress (.Z)", extensions: [".z", ".taz"], levels: null, threads: false, detected: true }],
    };
    expect(codecOfTar(all, "tar.Z")?.id).toBe("compress");
    expect(codecOfTar(all, "cpio.gz")?.id).toBe("gzip");
    expect(codecOfTar(all, "cpio")).toBeUndefined();
    expect(codecOfTar(all, "cab")).toBeUndefined();
  });

  it("says why it can't create yet, first things first", () => {
    const ok = { inputs: [String.raw`C:\work\src`], output: String.raw`C:\work\src.zip`, format: "zip" };
    expect(notReady(ok)).toBeUndefined();
    expect(notReady({ ...ok, inputs: [], output: "" })).toBe("Add files or folders to pack.");
    expect(notReady({ ...ok, output: "  " })).toBe("Choose where to save it.");
    // Converting needs no inputs.
    expect(notReady({ ...ok, inputs: undefined })).toBeUndefined();
    expect(notReady({ ...ok, inputs: undefined, dropsEncryption: "a.zip", wayIn: "password" })).toBe(
      "a.zip is encrypted: give the new archive a password, or write its entries without one.",
    );
    expect(notReady({ ...ok, inputs: undefined, dropsEncryption: "a.zip", wayIn: "way in", format: "bhive" })).toBe(
      "a.zip is encrypted: give the new archive a way in, or write its entries without one.",
    );
    expect(notReady({ ...ok, inputs: undefined, dropsEncryption: "a.zip", format: "tar" })).toBe(
      "a.zip is encrypted and tar can't be: write its entries without a password, or choose another format.",
    );
    expect(notReady({ ...ok, format: "bhive", problem: "This PC opens it only on this computer." })).toBe("This PC opens it only on this computer.");
  });
});

describe("the create dialog", () => {
  beforeEach(() => {
    fake.reset();
    fake.handlers.set("formats.list", () => formats);
    fake.handlers.set("cli.line", () => ({ line: "beezip create C:\\work\\src.7z C:\\work\\src --format 7z", omitted: ["password"] }));
  });

  it("hides what doesn't apply, and copies its command line", async () => {
    const user = userEvent.setup();
    render(<CreateDialog inputs={[String.raw`C:\work\src`]} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole("option", { name: "tar.zst" })).toBeInTheDocument());
    expect(screen.getByLabelText("Save as")).toHaveValue(String.raw`C:\work\src.zip`);
    expect(screen.queryByText("Solid")).toBeNull();

    await user.selectOptions(screen.getByLabelText("Format"), "7z");
    expect(screen.getByLabelText("Save as")).toHaveValue(String.raw`C:\work\src.7z`);
    expect(screen.getByText("Solid")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Password"), "pw");
    expect(screen.getByText("Encrypt file names too")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /copy as cli/i }));
    expect(await screen.findByTestId("cli-line")).toHaveTextContent("beezip create C:\\work\\src.7z");
    expect(screen.getByText(/password is left out/i)).toBeInTheDocument();
    const call = fake.calls.find((c) => c.name === "cli.line");
    expect(call?.args).toEqual({
      command: "archive.create",
      args: { output: String.raw`C:\work\src.7z`, inputs: [String.raw`C:\work\src`], format: "7z", password: "pw" },
      program: "beezip",
    });
    // user-event puts its own clipboard in place; read it back.
    expect(await navigator.clipboard.readText()).toBe("beezip create C:\\work\\src.7z C:\\work\\src --format 7z");

    await user.selectOptions(screen.getByLabelText("Format"), "tar.zst");
    expect(screen.queryByLabelText("Password")).toBeNull();
    expect(screen.getByLabelText("Threads")).toBeInTheDocument();

    // A .bhive: five named levels, no method, its own Protection section.
    await user.selectOptions(screen.getByLabelText("Format"), "bhive");
    expect(screen.getByLabelText("Save as")).toHaveValue(String.raw`C:\work\src.bhive`);
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByText(/Make a recovery key/)).toBeInTheDocument();
    expect(screen.queryByText("Encrypt file names too")).toBeNull();
    expect(screen.queryByLabelText("Method")).toBeNull();
    const level = screen.getByLabelText("Level");
    expect(level).toHaveAttribute("max", "4");
    expect(level).toHaveAttribute("aria-valuetext", "Balanced");
    expect(screen.getByText("Default Balanced.")).toBeInTheDocument();
    expect(screen.getByText("zstd 6: quick and small")).toBeInTheDocument();
  });

  it("says why Create is disabled, and warns of a weak password without refusing it", async () => {
    const user = userEvent.setup();
    render(<CreateDialog inputs={[]} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole("option", { name: "bhive" })).toBeInTheDocument());
    const create = screen.getByRole("button", { name: "Create" });
    expect(create).toBeDisabled();
    expect(create).toHaveAccessibleDescription("Add files or folders to pack.");

    // A weak password is a warning in amber, not an error: it isn't why Create is disabled.
    await user.selectOptions(screen.getByLabelText("Format"), "bhive");
    await user.type(screen.getByLabelText("Password"), "summer2026");
    const strength = screen.getByRole("status");
    expect(strength).toHaveTextContent(/very weak/);
    expect(strength).toHaveClass("text-amber");
    expect(strength).not.toHaveClass("text-danger");
    expect(create).toHaveAccessibleDescription("Add files or folders to pack.");

    vi.mocked(pickFiles).mockResolvedValueOnce([String.raw`C:\work\src`]);
    await user.click(screen.getByRole("button", { name: /Add files/ }));
    await waitFor(() => expect(create).toBeEnabled());
    expect(create).not.toHaveAccessibleDescription();
    expect(screen.queryByText("Add files or folders to pack.")).toBeNull();
    expect(screen.getByLabelText("Save as")).toHaveValue(String.raw`C:\work\src.bhive`);

    await user.clear(screen.getByLabelText("Save as"));
    expect(create).toBeDisabled();
    expect(create).toHaveAccessibleDescription("Choose where to save it.");
  });
});
