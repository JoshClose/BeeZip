import { setTheme } from "@tauri-apps/api/app";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { levelTargets, SettingsDialog } from "../features/settings/Settings";
import type { Config, FormatsListOutput, SettingsGetOutput } from "../gen/commands";
import { chooseTheme, themeActions, useTheme } from "../lib/settings";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/api/app", () => ({ setTheme: vi.fn(async () => {}) }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openPath: vi.fn(async () => {}), revealItemInDir: vi.fn(async () => {}) }));

const settings: Config = {
  extract: { overwrite: "rename", links: false, mark_of_the_web: "all" },
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

  it("saves text when the field is left, and shows an error beside it", async () => {
    fake.handlers.set("settings.set", () => {
      throw { code: "InvalidArgs", message: "nothing was written: line 3" };
    });
    const user = userEvent.setup();
    render(<SettingsDialog onClose={() => {}} />);
    const threads = await screen.findByLabelText("Threads");
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
