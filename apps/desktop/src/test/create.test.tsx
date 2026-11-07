import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { type CreateForm, CreateDialog, createArgs, defaultOutput, withFormat } from "../features/create/CreateDialog";
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
    { id: "zip", name: "Zip", extensions: [".zip"], caps, methods: [{ id: "store", levels: null }, { id: "deflate", levels: levels(1, 9, 6) }, { id: "zstd", levels: levels(1, 22, 3) }], encryption: ["aes256", "zipcrypto"] },
    { id: "7z", name: "7z", extensions: [".7z"], caps: { ...caps, encrypt_headers: true, solid: true }, methods: [{ id: "lzma2", levels: levels(0, 9, 5) }, { id: "copy", levels: null }], encryption: ["aes256"] },
    { id: "tar", name: "Tar", extensions: [".tar"], caps: { ...caps, encrypt: false }, methods: [], encryption: [] },
  ],
  codecs: [
    { id: "zstd", name: "Zstandard", extensions: [".zst", ".tzst"], levels: levels(1, 22, 3), threads: true, detected: true },
    { id: "gzip", name: "gzip", extensions: [".gz", ".tgz"], levels: levels(0, 9, 6), threads: false, detected: true },
  ],
  create: ["zip", "7z", "tar", "tar.gz", "tar.zst"],
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
  });
});
