import { setTheme } from "@tauri-apps/api/app";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { levelTargets, SettingsDialog } from "../features/settings/Settings";
import type { Config, FormatsListOutput, SettingsGetOutput } from "../gen/commands";
import { chooseTheme, themeActions, useTheme } from "../lib/settings";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/api/app", () => ({ setTheme: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openPath: vi.fn(async () => {}), revealItemInDir: vi.fn(async () => {}) }));

const settings: Config = {
  extract: { overwrite: "rename", links: false, mark_of_the_web: "all", threads: 0 },
  edit: { overwrite: "ask" },
  names: { encoding: "auto" },
  create: { threads: 0 },
  levels: { zstd: 19 },
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

const got = (patch: Partial<SettingsGetOutput> = {}): SettingsGetOutput => ({
  path: "C:\\Users\\me\\AppData\\Roaming\\BeeZip\\config.toml",
  exists: true,
  settings,
  warnings: [],
  error: null,
  ...patch,
});

const formats = {
  formats: [{ id: "zip", name: "ZIP", extensions: [".zip"], caps: {}, methods: [{ id: "deflate", levels: { min: 0, max: 9, default: 6 } }], encryption: [] }],
  codecs: [
    { id: "zstd", name: "Zstandard", extensions: [".zst"], levels: { min: 1, max: 22, default: 3 }, threads: true, detected: true },
    { id: "snappy", name: "Snappy", extensions: [".sz"], levels: null, threads: false, detected: true },
  ],
  create: ["zip"],
} as unknown as FormatsListOutput;

describe("the settings page", () => {
  beforeEach(() => {
    fake.reset();
    vi.mocked(setTheme).mockClear();
    useTheme.setState({ theme: "system" });
    fake.handlers.set("settings.get", () => got());
    fake.handlers.set("formats.list", () => formats);
  });

  it("shows what settings.get returns", async () => {
    render(<SettingsDialog onClose={() => {}} />);
    expect(await screen.findByLabelText("A file is already there")).toHaveValue("rename");
    expect(screen.getByText(/BeeZip\\config\.toml/)).toBeInTheDocument();
    expect(await screen.findByLabelText("zstd")).toHaveValue("19");
    expect(screen.getByLabelText("deflate")).toHaveValue("6");
    expect(screen.getByText("6, its own")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "System" })).toHaveAttribute("aria-checked", "true");
  });

  it("says which 7-Zip it found, and saves a path and the switch (docs/M6.md §3.7)", async () => {
    const found = { name: "7-Zip 26.00", path: "C:\\Program Files\\7-Zip\\7z.exe", found_in: "registry", problem: null, min_version: "25.01" };
    fake.handlers.set("formats.list", () => ({ ...formats, seven_zip: found }));
    fake.handlers.set("settings.set", (args) => {
      const set = (args as { set: Record<string, unknown> }).set;
      const key = Object.keys(set)[0].replace("seven_zip.", "");
      return { ...got(), settings: { ...settings, seven_zip: { ...settings.seven_zip, [key]: set[`seven_zip.${key}`] } }, changed: [`seven_zip.${key}`] };
    });
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    expect(await screen.findByText(/Using 7-Zip 26\.00/)).toBeInTheDocument();
    expect(screen.getByText(/found through 7-Zip's installation/)).toBeInTheDocument();

    // A path that isn't there: formats.list says so, and the page shows it.
    fake.handlers.set("formats.list", () => ({
      ...formats,
      seven_zip: { ...found, name: null, path: null, found_in: null, problem: "not found at D:\\7z.exe" },
    }));
    await user.type(screen.getByLabelText("7-Zip program"), "D:\\7z.exe");
    await user.tab();
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "seven_zip.path": "D:\\7z.exe" } } }));
    expect(await screen.findByText(/No 7-Zip to use: not found at D:\\7z\.exe/)).toBeInTheDocument();

    await user.click(screen.getByRole("checkbox", { name: "Open these formats through 7-Zip" }));
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "seven_zip.enabled": false } } }));
    expect(await screen.findByText(/Turned off/)).toBeInTheDocument();
  });

  it("turns the daily update check off (docs/M6.md §8.2)", async () => {
    fake.handlers.set("settings.set", () => ({ ...got(), settings: { ...settings, updates: { check: false } }, changed: ["updates.check"] }));
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    const box = await screen.findByRole("checkbox", { name: "When BeeZip starts, at most once a day" });
    expect(box).toBeChecked();
    await user.click(box);
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "updates.check": false } } }));
  });

  it("saves a change at once", async () => {
    fake.handlers.set("settings.set", (args) => {
      const set = (args as { set: Record<string, unknown> }).set;
      return { ...got(), settings: { ...settings, extract: { ...settings.extract, overwrite: set["extract.overwrite"] } }, changed: ["extract.overwrite"] };
    });
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    await user.selectOptions(await screen.findByLabelText("A file is already there"), "never");
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "extract.overwrite": "never" } } }));
    await waitFor(() => expect(screen.getByLabelText("A file is already there")).toHaveValue("never"));
  });

  it("has the editing default, [edit] overwrite (docs/M5.md §7.1)", async () => {
    fake.handlers.set("settings.set", () => ({ ...got(), settings: { ...settings, edit: { overwrite: "always" } }, changed: ["edit.overwrite"] }));
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    const field = await screen.findByLabelText("An entry is already there");
    expect(field).toHaveValue("ask");
    await user.selectOptions(field, "always");
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "edit.overwrite": "always" } } }));
    await waitFor(() => expect(screen.getByLabelText("An entry is already there")).toHaveValue("always"));
  });

  it("saves text when the field is left, and shows an error beside it", async () => {
    fake.handlers.set("settings.set", () => {
      throw { code: "InvalidArgs", message: "nothing was written: line 3" };
    });
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    // Extracting and creating each have a "Threads" field.
    const threads = (await screen.findAllByLabelText("Threads")).find((e) => e.id === "create-threads")!;
    await user.clear(threads);
    await user.type(threads, "4");
    await user.tab();
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "create.threads": 4 } } }));
    expect(await screen.findByRole("alert")).toHaveTextContent("nothing was written: line 3");
    expect(threads).toHaveValue("4");
  });

  it("turns off the job windows' closing", async () => {
    fake.handlers.set("settings.set", () => ({ ...got(), settings: { ...settings, jobs: { close_when_done: false } }, changed: ["jobs.close_when_done"] }));
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    const box = await screen.findByRole("checkbox", { name: /Close the window after a success/ });
    expect(box).toBeChecked();
    await user.click(box);
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "jobs.close_when_done": false } } }));
    await waitFor(() => expect(box).not.toBeChecked());
  });

  it("an empty limit goes back to its default", async () => {
    fake.handlers.set("settings.set", () => ({ ...got(), changed: [] }));
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    const ratio = await screen.findByLabelText("Expansion");
    await user.clear(ratio);
    await user.tab();
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "limits.max_ratio": null } } }));
  });

  it("switches the theme from the page", async () => {
    fake.handlers.set("settings.set", () => ({ ...got(), changed: ["desktop.theme"] }));
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    await user.click(screen.getByRole("radio", { name: "Dark" }));
    expect(setTheme).toHaveBeenCalledWith("dark");
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "desktop.theme": "dark" } } }));
    expect(screen.getByRole("radio", { name: "Dark" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("radio", { name: "Dark" })).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("radio", { name: "System" })).toHaveAttribute("tabindex", "-1");

    await user.keyboard("{ArrowLeft}");
    expect(setTheme).toHaveBeenLastCalledWith("light");
    expect(screen.getByRole("radio", { name: "Light" })).toHaveFocus();
  });

  it("shows why config.toml can't be used", async () => {
    fake.handlers.set("settings.get", () => got({ error: "config.toml: line 2: invalid type", warnings: ["config.toml: unknown key `x` ignored"] }));
    render(<SettingsDialog onClose={() => {}} />);
    expect(await screen.findByText(/line 2: invalid type/)).toBeInTheDocument();
    expect(screen.getByText(/unknown key `x` ignored/)).toBeInTheDocument();
  });

  it("lists every codec and method with levels once", () => {
    expect(levelTargets(formats).map((l) => l.name)).toEqual(["deflate", "zstd"]);
  });

  describe("off Windows (docs/M6.md §8.3)", () => {
    afterEach(() => {
      delete window.__BEEZIP__;
    });
    const page = async (platform: string) => {
      window.__BEEZIP__ = { paths: [], cli: "beezip", warnings: [], theme: "system", platform };
      render(<SettingsDialog onClose={() => {}} />);
      await screen.findByLabelText("A file is already there");
    };

    it("Windows has Explorer's menu, its job windows and the downloaded mark", async () => {
      await page("windows");
      expect(screen.getByRole("heading", { name: "Explorer menu" })).toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Job windows" })).toBeInTheDocument();
      expect(screen.getByLabelText("Downloaded mark")).toBeInTheDocument();
      expect(screen.getByText(/as Explorer does/)).toBeInTheDocument();
    });

    it("macOS has the mark as quarantine, and no Explorer", async () => {
      await page("macos");
      expect(screen.queryByRole("heading", { name: "Explorer menu" })).not.toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: "Job windows" })).not.toBeInTheDocument();
      expect(screen.getByLabelText("Downloaded mark")).toBeInTheDocument();
      expect(screen.getByText(/as Archive Utility does/)).toBeInTheDocument();
      expect(fake.calls.map((c) => c.name)).not.toContain("shell.status");
    });

    it("Linux has neither", async () => {
      await page("linux");
      expect(screen.queryByRole("heading", { name: "Explorer menu" })).not.toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: "Job windows" })).not.toBeInTheDocument();
      expect(screen.queryByLabelText("Downloaded mark")).not.toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Updates" })).toBeInTheDocument();
    });
  });
});

describe("the theme", () => {
  beforeEach(() => {
    fake.reset();
    vi.mocked(setTheme).mockClear();
    useTheme.setState({ theme: "light" });
  });

  it("applies at once, then saves", async () => {
    fake.handlers.set("settings.set", () => ({ ...got(), changed: ["desktop.theme"] }));
    await chooseTheme("system");
    expect(setTheme).toHaveBeenCalledWith(null);
    expect(fake.calls).toEqual([{ name: "settings.set", args: { set: { "desktop.theme": "system" } } }]);
    expect(useTheme.getState().theme).toBe("system");
  });

  it("comes back when saving fails", async () => {
    fake.handlers.set("settings.set", () => {
      throw { code: "Io", message: "disk full" };
    });
    await expect(chooseTheme("dark")).rejects.toMatchObject({ code: "Io" });
    expect(vi.mocked(setTheme).mock.calls).toEqual([["dark"], ["light"]]);
    expect(useTheme.getState().theme).toBe("light");
  });

  it("has a palette entry per theme, marking the current one", async () => {
    fake.handlers.set("settings.set", () => ({ ...got(), changed: ["desktop.theme"] }));
    const onError = vi.fn();
    const actions = themeActions("light", onError);
    expect(actions.map((a) => [a.label, a.hint])).toEqual([
      ["Theme: System", undefined],
      ["Theme: Light", "current"],
      ["Theme: Dark", undefined],
    ]);
    actions[2].run();
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "settings.set", args: { set: { "desktop.theme": "dark" } } }));
    expect(setTheme).toHaveBeenCalledWith("dark");
    expect(onError).not.toHaveBeenCalled();
  });
});
