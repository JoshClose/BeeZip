// The window: tabs, the active archive (or Welcome), the jobs panel, and the dialogs.
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as pickFiles } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Toasts } from "./components/ui/toasts";
import { About } from "./features/about/About";
import { Browser, testArchive } from "./features/browser/Browser";
import { InfoDialog } from "./features/browser/InfoDialog";
import { TabStrip } from "./features/browser/TabStrip";
import { CreateDialog } from "./features/create/CreateDialog";
import { ExtractDialog } from "./features/extract/ExtractDialog";
import { JobsPanel } from "./features/jobs/JobsPanel";
import { ReportDialog } from "./features/jobs/ReportDialog";
import { loadCommands, Palette, type PaletteAction, takesOnlyArchive } from "./features/palette/Palette";
import { FormDialog } from "./features/palette/SchemaForm";
import { Prompts } from "./features/prompts/Prompts";
import { SettingsDialog } from "./features/settings/Settings";
import { Welcome } from "./features/welcome/Welcome";
import { activeTab, useArchives } from "./lib/archives";
import { useCloseGuard } from "./lib/closeGuard";
import { type GuiCommand, run } from "./lib/engine";
import { baseName } from "./lib/format";
import { loadFormats, readableExtensions } from "./lib/formats";
import { useJobs } from "./lib/jobs";
import { themeActions, useTheme } from "./lib/settings";
import { type OpenDialog, startup } from "./lib/startup";
import { toastError, toastInfo, useToasts } from "./lib/toasts";
import { useUi } from "./lib/ui";

/** Whether BeeZip reads `path` as an archive (a compressed single file counts). */
async function isArchive(path: string): Promise<boolean> {
  const d = await run("file.detect", { path });
  return d.format !== null;
}

/** Paths from the command line, a second instance, or the Open dialog: each archive in a tab. */
export async function openPaths(paths: string[]) {
  for (const path of paths) {
    try {
      if (await isArchive(path)) useArchives.getState().open(path);
      else useToasts.getState().push({ tone: "error", title: `${baseName(path)} isn't an archive`, body: "BeeZip can pack it into a new one: drop it on the window." });
    } catch (e) {
      toastError(e, baseName(path));
    }
  }
}

/** "Extract to…" and "Compress to…" from Explorer's menu (docs/M4.md §6.2). */
export async function openDialog(d: OpenDialog) {
  const ui = useUi.getState();
  if (d.dialog === "create") {
    ui.show({ kind: "create", inputs: d.paths });
    return;
  }
  const path = d.paths[0];
  if (!path) return;
  try {
    if (!(await isArchive(path))) {
      useToasts.getState().push({ tone: "error", title: `${baseName(path)} isn't an archive` });
      return;
    }
    const tab = useArchives.getState().open(path);
    ui.show({ kind: "extract", tab, entries: [] });
  } catch (e) {
    toastError(e, baseName(path));
  }
}

/** Dropped paths: one archive opens; anything else, or several, goes into a new archive. */
async function dropPaths(paths: string[]) {
  if (paths.length === 0) return;
  const ui = useUi.getState();
  if (ui.dialog?.kind === "create") {
    ui.show({ kind: "create", inputs: paths });
    return;
  }
  if (paths.length === 1) {
    try {
      if (await isArchive(paths[0])) {
        useArchives.getState().open(paths[0]);
        return;
      }
    } catch {
      // Not readable as an archive: offer to pack it.
    }
  }
  ui.show({ kind: "create", inputs: paths });
}

async function chooseArchives() {
  let extensions = ["zip", "7z", "rar", "tar", "gz", "tgz", "zst", "xz", "bz2", "001"];
  try {
    extensions = readableExtensions(await loadFormats());
  } catch {
    // The short list above will do.
  }
  const picked = await pickFiles({
    multiple: true,
    title: "Open archive",
    filters: [
      { name: "Archives", extensions },
      { name: "All files", extensions: ["*"] },
    ],
  });
  const list = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
  await openPaths(list);
}

let started = false;

export default function App() {
  const tabs = useArchives((s) => s.tabs);
  const activeId = useArchives((s) => s.active);
  const tab = useMemo(() => activeTab({ tabs, active: activeId }), [tabs, activeId]);
  const dialog = useUi((s) => s.dialog);
  const palette = useUi((s) => s.palette);
  const show = useUi((s) => s.show);
  const closeDialog = useUi((s) => s.closeDialog);
  const setPalette = useUi((s) => s.setPalette);
  const [dragging, setDragging] = useState(false);
  const [commands, setCommands] = useState<GuiCommand[]>([]);
  const theme = useTheme((s) => s.theme);
  const tabRef = useRef(tab);
  tabRef.current = tab;

  const newArchive = useCallback(() => show({ kind: "create", inputs: [] }), [show]);
  const openSettings = useCallback(() => show({ kind: "settings" }), [show]);
  const extract = useCallback(() => {
    const t = tabRef.current;
    if (t) show({ kind: "extract", tab: t.id, entries: [] });
  }, [show]);

  // Once per process (StrictMode mounts twice in development).
  useEffect(() => {
    useJobs.setState({ onPassword: (id, password) => useArchives.getState().update(id, { password }) });
    if (started) return;
    started = true;
    const s = startup();
    for (const w of s.warnings) toastInfo("config.toml", w);
    void openPaths(s.paths).then(() => s.dialog && openDialog(s.dialog));
    loadCommands().then(setCommands, () => {});
  }, []);

  useEffect(() => {
    if (commands.length === 0) loadCommands().then(setCommands, () => {});
  }, [commands.length]);

  // Paths a second BeeZip.exe forwards, and dialogs Explorer's menu asks for.
  useEffect(() => {
    const paths = listen<string[]>("open-paths", (e) => void openPaths(e.payload));
    const dialogs = listen<OpenDialog>("open-dialog", (e) => void openDialog(e.payload));
    return () => {
      void paths.then((f) => f());
      void dialogs.then((f) => f());
    };
  }, []);

  useEffect(() => {
    const unlisten = getCurrentWebview().onDragDropEvent((e) => {
      const p = e.payload;
      if (p.type === "enter" || p.type === "over") setDragging(true);
      else if (p.type === "leave") setDragging(false);
      else if (p.type === "drop") {
        setDragging(false);
        void dropPaths(p.paths);
      }
    });
    return () => void unlisten.then((f) => f());
  }, []);

  // Closing with jobs running asks first, then waits for them to remove their partial files.
  useCloseGuard("quit");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      const key = e.key.toLowerCase();
      const t = tabRef.current;
      if (key === "k") setPalette(!useUi.getState().palette);
      else if (key === "o") void chooseArchives();
      else if (key === "n") newArchive();
      else if (key === "e" && t) extract();
      else if (key === "w" && t) useArchives.getState().close(t.id);
      else if (key === ",") openSettings();
      else return;
      e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [extract, newArchive, openSettings, setPalette]);

  const actions: PaletteAction[] = [
    { id: "open", label: "Open archive…", hint: "Ctrl+O", run: () => void chooseArchives() },
    { id: "new", label: "New archive…", hint: "Ctrl+N", run: newArchive },
    ...(tab
      ? [
          { id: "extract", label: `Extract ${tab.name}…`, hint: "Ctrl+E", run: extract },
          { id: "test", label: `Test ${tab.name}`, run: () => testArchive(tab) },
          { id: "info", label: `Info on ${tab.name}`, run: () => show({ kind: "info", tab: tab.id }) },
          { id: "close", label: `Close ${tab.name}`, hint: "Ctrl+W", run: () => useArchives.getState().close(tab.id) },
        ]
      : []),
    { id: "settings", label: "Settings…", hint: "Ctrl+,", run: openSettings },
    ...themeActions(theme, (e) => toastError(e, "Theme")),
    { id: "about", label: "About BeeZip", run: () => show({ kind: "about" }) },
  ];

  const onCommand = (c: GuiCommand) => {
    if (c.name === "archive.extract" && tab) return extract();
    if (c.name === "archive.create") return newArchive();
    if (c.name === "archive.test" && tab) return testArchive(tab);
    if (c.name === "archive.info" && tab) return show({ kind: "info", tab: tab.id });
    if (takesOnlyArchive(c) && tab) {
      useJobs
        .getState()
        .track(c.name as "archive.test", { archive: tab.path, ...(tab.password ? { password: tab.password } : {}) }, { title: `${c.name} ${tab.name}`, tab: tab.id })
        .catch((e) => toastError(e, c.name));
      return;
    }
    show({ kind: "form", command: c.name });
  };

  const dialogTab = dialog && "tab" in dialog ? tabs.find((t) => t.id === dialog.tab) : undefined;
  const formCommand = dialog?.kind === "form" ? commands.find((c) => c.name === dialog.command) : undefined;

  return (
    <div className="flex h-full flex-col">
      <TabStrip onOpen={() => void chooseArchives()} onNew={newArchive} />
      {tab ? (
        <Browser key={tab.id} tab={tab} />
      ) : (
        <Welcome dragging={dragging} onOpen={() => void chooseArchives()} onNew={newArchive} onSettings={openSettings} />
      )}
      <JobsPanel />

      {tab && dragging && (
        <div className="pointer-events-none fixed inset-0 z-30 flex items-center justify-center bg-amber-wash/60">
          <p className="rounded-[8px] border border-amber-fill bg-panel px-5 py-3 text-[15px] font-semibold">
            Drop an archive to open it, or files to pack them
          </p>
        </div>
      )}

      {dialog?.kind === "extract" && dialogTab && <ExtractDialog tab={dialogTab} entries={dialog.entries} onClose={closeDialog} />}
      {dialog?.kind === "create" && <CreateDialog inputs={dialog.inputs} onClose={closeDialog} />}
      {dialog?.kind === "info" && dialogTab && <InfoDialog tab={dialogTab} onClose={closeDialog} />}
      {dialog?.kind === "about" && <About onClose={closeDialog} />}
      {dialog?.kind === "report" && <ReportDialog title={dialog.title} error={dialog.error} onClose={closeDialog} />}
      {dialog?.kind === "settings" && <SettingsDialog onClose={closeDialog} />}
      {formCommand && (
        <FormDialog
          command={formCommand}
          defaults={tab && "archive" in ((formCommand.input_schema.properties ?? {}) as object) ? { archive: tab.path } : {}}
          onClose={closeDialog}
        />
      )}

      <Palette open={palette} onOpenChange={setPalette} actions={actions} onCommand={onCommand} />
      <Prompts />
      <Toasts />
    </div>
  );
}
