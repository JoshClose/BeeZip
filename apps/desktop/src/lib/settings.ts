// config.toml through `settings.get` and `settings.set` (docs/M4.md §7), and the theme, which
// every window takes at once (§7.5).
import { setTheme } from "@tauri-apps/api/app";
import { create } from "zustand";
import type { SettingsGetOutput, SettingsSetOutput, Theme } from "../gen/commands";
import { run } from "./engine";
import { describeError } from "./format";
import { startup } from "./startup";

export function loadSettings(): Promise<SettingsGetOutput> {
  return run("settings.get", {});
}

/** Sets settings by dotted key (`extract.overwrite`); null puts one back to its default. */
export function saveSettings(set: Record<string, unknown>): Promise<SettingsSetOutput> {
  return run("settings.set", { set });
}

/** The theme the windows show now. */
export const useTheme = create<{ theme: Theme }>(() => ({ theme: startup().theme }));

/** Every window, and the ones opened later, take it; `null` follows Windows. */
function apply(theme: Theme): Promise<void> {
  return setTheme(theme === "system" ? null : theme);
}

/** Switches the theme at once, then saves it. If saving fails, the old theme comes back and the error is thrown. */
export async function chooseTheme(theme: Theme): Promise<void> {
  const previous = useTheme.getState().theme;
  useTheme.setState({ theme });
  await apply(theme);
  try {
    await saveSettings({ "desktop.theme": theme });
  } catch (e) {
    useTheme.setState({ theme: previous });
    await apply(previous).catch(() => {});
    throw e;
  }
}

export const THEMES: { id: Theme; label: string }[] = [
  { id: "system", label: "System" },
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
];

/** The palette's "Theme: …" entries; the current one says so. */
export function themeActions(current: Theme, onError: (e: unknown) => void) {
  return THEMES.map((t) => ({
    id: `theme-${t.id}`,
    label: `Theme: ${t.label}`,
    hint: t.id === current ? "current" : undefined,
    run: () => void chooseTheme(t.id).catch(onError),
  }));
}

/** A failure's message, whatever was thrown. */
export function errorMessage(e: unknown): string {
  return describeError(e).message;
}
