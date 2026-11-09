import { ask } from "@tauri-apps/plugin-dialog";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SettingsDialog } from "../features/settings/Settings";
import type { Config, SettingsGetOutput, ShellStatusOutput } from "../gen/commands";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/api/app", () => ({ setTheme: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openPath: vi.fn(async () => {}), revealItemInDir: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ ask: vi.fn(async () => true) }));

const settings: Config = {
  extract: { overwrite: "ask", links: false, mark_of_the_web: "all", threads: 0 },
  edit: { overwrite: "ask" },
  names: { encoding: "auto" },
  create: { threads: 0 },
  levels: {},
  stream: { codec: "zstd" },
  limits: { max_ratio: 10000, max_entries: 10000000, decoder_memory_mib: 1024, max_total_bytes: null },
  mcp: { roots: [], read_only: false },
  shell: {
    cascade: true,
    items: {
      open: true,
      "extract-here": true,
      "extract-folder": true,
      "extract-to": true,
      test: true,
      "add-zip": true,
      "add-7z": true,
      "add-tar-zst": true,
      "compress-to": true,
    },
  },
  jobs: { close_when_done: true },
  desktop: { theme: "system" },
  seven_zip: { path: null, enabled: true },
  updates: { check: true },
};

const got = (patch: Partial<Config> = {}): SettingsGetOutput => ({
  path: "C:\\Users\\me\\AppData\\Roaming\\BeeZip\\config.toml",
  exists: true,
  settings: { ...settings, ...patch },
  warnings: [],
  error: null,
});

const notInstalled = (patch: Partial<ShellStatusOutput> = {}): ShellStatusOutput => ({
  windows_build: 19045,
  developer_mode: false,
  mode: null,
  classic: null,
  package: null,
  app: null,
  hidden: [],
  cascade: true,
  problems: [],
  ...patch,
});

const installed = (cascade = true): ShellStatusOutput =>
  notInstalled({
    mode: "classic",
    app: "C:\\Users\\me\\AppData\\Local\\BeeZip\\BeeZip.exe",
    cascade,
    classic: {
      dll: "C:\\Users\\me\\AppData\\Local\\BeeZip\\beezip_shell_0.1.0.dll",
      dll_exists: true,
      cascade,
      verbs: cascade ? ["*\\shell\\BeeZip", "Directory\\shell\\BeeZip"] : ["*\\shell\\BeeZip.1-open"],
    },
  });

/** The Explorer menu section of a rendered settings page. */
async function explorer() {
  render(<SettingsDialog onClose={() => {}} />);
  const heading = await screen.findByRole("heading", { name: "Explorer menu" });
  return within(heading.closest("section")!);
}

const shellCalls = () => fake.calls.map((c) => c.name).filter((n) => n.startsWith("shell."));

describe("the settings page's Explorer menu section", () => {
  beforeEach(() => {
    fake.reset();
    vi.mocked(ask).mockReset();
    vi.mocked(ask).mockResolvedValue(true);
    fake.handlers.set("settings.get", () => got());
    fake.handlers.set("formats.list", () => ({ formats: [], codecs: [], create: [] }));
    fake.handlers.set("shell.status", () => notInstalled());
  });

  it("says when the menu isn't installed, and offers to install it", async () => {
    const section = await explorer();
    expect(await section.findByText("Not installed")).toBeInTheDocument();
    expect(section.getByRole("button", { name: "Install" })).toBeEnabled();
    expect(section.queryByRole("button", { name: "Remove" })).toBeNull();
    expect(section.queryByRole("button", { name: "Repair" })).toBeNull();
  });

  it("shows the installed layout, and each problem", async () => {
    fake.handlers.set("shell.status", () => ({
      ...installed(false),
      problems: ["the menu's DLL, C:\\x\\beezip_shell_0.1.0.dll, isn't there: `beezip shell install` puts it back"],
    }));
    const section = await explorer();
    expect(await section.findByText("Installed: items at the top level")).toBeInTheDocument();
    expect(section.getByText(/beezip_shell_0\.1\.0\.dll, isn't there/)).toBeInTheDocument();
    expect(section.getByRole("button", { name: "Repair" })).toBeEnabled();
    expect(section.getByRole("button", { name: "Remove" })).toBeEnabled();
    expect(section.queryByRole("button", { name: "Install" })).toBeNull();
  });

  it("names the submenu when it cascades", async () => {
    fake.handlers.set("shell.status", () => installed(true));
    const section = await explorer();
    expect(await section.findByText('Installed: a "BeeZip" submenu')).toBeInTheDocument();
  });

  it("is Windows-only elsewhere", async () => {
    fake.handlers.set("shell.status", () => {
      throw { code: "UnsupportedOperation", message: "Explorer's menu is only on Windows" };
    });
    const section = await explorer();
    expect(await section.findByText("Explorer's menu is only on Windows.")).toBeInTheDocument();
    expect(section.getByRole("button", { name: "Install" })).toBeDisabled();
    expect(section.getByRole("checkbox", { name: /submenu/ })).toBeDisabled();
    expect(section.getByRole("checkbox", { name: "Test archive" })).toBeDisabled();
  });

  it("installs once asked, then checks the menu again", async () => {
    let done = false;
    fake.handlers.set("shell.status", () => (done ? installed() : notInstalled()));
    fake.handlers.set("shell.install", () => {
      done = true;
      return { status: installed(), actions: ["registered the classic menu"], fallback: 'BeeZip is under "Show more options"' };
    });
    const user = userEvent.setup();
    const section = await explorer();
    await user.click(await section.findByRole("button", { name: "Install" }));
    expect(ask).toHaveBeenCalledWith(expect.stringMatching(/Add BeeZip to Explorer/), expect.objectContaining({ okLabel: "Install" }));
    expect(await section.findByText('Installed: a "BeeZip" submenu')).toBeInTheDocument();
    expect(section.getByText(/Show more options/)).toBeInTheDocument();
    expect(shellCalls().slice(-2)).toEqual(["shell.install", "shell.status"]);
    expect(fake.calls).toContainEqual({ name: "shell.install", args: {} });
  });

  it("does nothing when the question is declined", async () => {
    vi.mocked(ask).mockResolvedValue(false);
    const user = userEvent.setup();
    const section = await explorer();
    await user.click(await section.findByRole("button", { name: "Install" }));
    await waitFor(() => expect(ask).toHaveBeenCalled());
    expect(shellCalls()).not.toContain("shell.install");
  });

  it("repairs through shell.install", async () => {
    fake.handlers.set("shell.status", () => installed());
    fake.handlers.set("shell.install", () => ({ status: installed(), actions: [], fallback: null }));
    const user = userEvent.setup();
    const section = await explorer();
    await user.click(await section.findByRole("button", { name: "Repair" }));
    expect(ask).toHaveBeenCalledWith(expect.stringMatching(/again/), expect.objectContaining({ okLabel: "Repair" }));
    await waitFor(() => expect(shellCalls().slice(-2)).toEqual(["shell.install", "shell.status"]));
    expect(fake.calls).toContainEqual({ name: "shell.install", args: { mode: "classic" } });
  });

  it("repairs a development package as one", async () => {
    const dev = notInstalled({
      windows_build: 26300,
      developer_mode: true,
      mode: "modern",
      package: {
        full_name: "BeeZip_0.1.0.0_neutral__9vzn3qywa4gqa",
        development: true,
        external_location: "C:\\src\\BeeZip\\target\\shell\\",
        dll: "C:\\src\\BeeZip\\target\\shell\\beezip_shell_1.dll",
        dll_exists: true,
      },
    });
    fake.handlers.set("shell.status", () => dev);
    fake.handlers.set("shell.install", () => ({ status: dev, actions: [], fallback: null }));
    const user = userEvent.setup();
    const section = await explorer();
    expect(await section.findByText("Installed: Windows 11's menu, as a development package")).toBeInTheDocument();
    await user.click(section.getByRole("button", { name: "Repair" }));
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "shell.install", args: { mode: "modern", dev: true } }));
  });

  it("removes the menu once asked", async () => {
    let removed = false;
    fake.handlers.set("shell.status", () => (removed ? notInstalled() : installed()));
    fake.handlers.set("shell.uninstall", () => {
      removed = true;
      return { actions: ["removed *\\shell\\BeeZip"] };
    });
    const user = userEvent.setup();
    const section = await explorer();
    await user.click(await section.findByRole("button", { name: "Remove" }));
    expect(ask).toHaveBeenCalledWith(expect.stringMatching(/Remove BeeZip/), expect.objectContaining({ kind: "warning" }));
    expect(await section.findByText("Not installed")).toBeInTheDocument();
    expect(fake.calls).toContainEqual({ name: "shell.uninstall", args: {} });
  });

  it("shows a failed install beside the buttons", async () => {
    fake.handlers.set("shell.install", () => {
      throw { code: "NotFound", message: "there's no beezip_shell DLL in C:\\x; pass --dll" };
    });
    const user = userEvent.setup();
    const section = await explorer();
    await user.click(await section.findByRole("button", { name: "Install" }));
    expect(await section.findByRole("alert")).toHaveTextContent("there's no beezip_shell DLL");
  });

  it("hides an item through settings.set", async () => {
    fake.handlers.set("settings.set", () => ({
      ...got({ shell: { ...settings.shell, items: { ...settings.shell.items, test: false } } }),
      changed: ["shell.items.test"],
    }));
    const user = userEvent.setup();
    const section = await explorer();
    const box = section.getByRole("checkbox", { name: "Test archive" });
    expect(box).toBeChecked();
    await user.click(box);
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "shell.items.test": false } } }));
    await waitFor(() => expect(box).not.toBeChecked());
  });

  it("shows a refused item change beside the item", async () => {
    fake.handlers.set("settings.set", () => {
      throw { code: "Io", message: "config.toml is read-only" };
    });
    const user = userEvent.setup();
    const section = await explorer();
    await user.click(section.getByRole("checkbox", { name: "Compress to…" }));
    expect(await section.findByRole("alert")).toHaveTextContent("config.toml is read-only");
  });

  it("turns the submenu off through settings.set, and checks the menu again", async () => {
    fake.handlers.set("settings.set", () => ({
      ...got({ shell: { ...settings.shell, cascade: false } }),
      changed: ["shell.cascade"],
    }));
    const user = userEvent.setup();
    const section = await explorer();
    await section.findByText("Not installed");
    const before = shellCalls().length;
    await user.click(section.getByRole("checkbox", { name: 'Show the items in a "BeeZip" submenu' }));
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "shell.cascade": false } } }));
    await waitFor(() => expect(shellCalls().length).toBe(before + 1));
    expect(shellCalls().at(-1)).toBe("shell.status");
  });

  it("leaves the submenu to Windows 11's own menu", async () => {
    fake.handlers.set("shell.status", () => notInstalled({ mode: "modern" }));
    const section = await explorer();
    expect(await section.findByText("Installed: Windows 11's menu")).toBeInTheDocument();
    expect(section.getByRole("checkbox", { name: /submenu/ })).toBeDisabled();
    expect(section.getByRole("checkbox", { name: "Test archive" })).toBeEnabled();
  });
});
