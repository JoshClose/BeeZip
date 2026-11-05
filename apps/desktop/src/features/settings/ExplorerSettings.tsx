// The settings page's Explorer menu section (docs/M4.md §7.4): what `shell.status` reports,
// Install, Repair and Remove (each asked first, since they change Explorer), and `[shell]`'s
// settings, which the backend passes on to an installed menu itself.
import { ask } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import type { MenuItem, ShellConfig, ShellStatusOutput } from "../../gen/commands";
import { run } from "../../lib/engine";
import { describeError } from "../../lib/format";
import { CheckSetting, Section, Setting } from "./fields";

/** The menu's items in menu order, titled as Explorer shows them for `a.zip`. */
export const MENU_ITEMS: { id: MenuItem; label: string }[] = [
  { id: "open", label: "Open with BeeZip" },
  { id: "extract-here", label: "Extract here" },
  { id: "extract-folder", label: 'Extract to "a\\"' },
  { id: "extract-to", label: "Extract to…" },
  { id: "test", label: "Test archive" },
  { id: "add-zip", label: 'Add to "a.zip"' },
  { id: "add-7z", label: 'Add to "a.7z"' },
  { id: "add-tar-zst", label: 'Add to "a.tar.zst"' },
  { id: "compress-to", label: "Compress to…" },
];

type Status =
  | { state: "checking" }
  | { state: "known"; status: ShellStatusOutput }
  | { state: "unsupported" }
  | { state: "failed"; message: string };

/** The one-line summary of what is registered. */
export function statusLine(s: ShellStatusOutput): string {
  switch (s.mode) {
    case "classic":
      return s.classic?.cascade === false ? "Installed: items at the top level" : 'Installed: a "BeeZip" submenu';
    case "modern":
      return "Installed: Windows 11's menu";
    default:
      return "Not installed";
  }
}

const ACTIONS = {
  install: {
    question: "Add BeeZip to Explorer's right-click menu?",
    ok: "Install",
    kind: "info",
    command: "shell.install",
  },
  repair: {
    question: "Register BeeZip's Explorer menu again? This fixes a menu that has stopped working.",
    ok: "Repair",
    kind: "info",
    command: "shell.install",
  },
  remove: {
    question: "Remove BeeZip from Explorer's right-click menu? These settings stay, for when you install it again.",
    ok: "Remove",
    kind: "warning",
    command: "shell.uninstall",
  },
} as const;

type Action = keyof typeof ACTIONS;

export function ExplorerSettings({
  shell,
  errors,
  save,
}: {
  shell: ShellConfig;
  errors: Record<string, string>;
  save: (key: string, value: unknown) => void;
}) {
  const [status, setStatus] = useState<Status>({ state: "checking" });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();
  const [note, setNote] = useState<string>();

  const refresh = useCallback(async () => {
    try {
      setStatus({ state: "known", status: await run("shell.status", {}) });
    } catch (e) {
      const error = describeError(e);
      setStatus(error.code === "UnsupportedOperation" ? { state: "unsupported" } : { state: "failed", message: error.message });
    }
  }, []);

  // Again whenever `[shell]` changes: the backend re-registers the menu, so the line can change.
  const items = MENU_ITEMS.map((i) => shell.items[i.id]).join();
  useEffect(() => {
    void refresh();
  }, [refresh, shell.cascade, items]);

  const act = async (action: Action) => {
    const a = ACTIONS[action];
    const ok = await ask(a.question, { title: "BeeZip", kind: a.kind, okLabel: a.ok, cancelLabel: "Cancel" });
    if (!ok) return;
    setBusy(true);
    setActionError(undefined);
    setNote(undefined);
    try {
      if (a.command === "shell.install") {
        const out = await run("shell.install", {});
        setNote(out.fallback ?? undefined);
      } else {
        await run("shell.uninstall", {});
      }
    } catch (e) {
      setActionError(describeError(e).message);
    } finally {
      await refresh();
      setBusy(false);
    }
  };

  const unsupported = status.state === "unsupported";
  const known = status.state === "known" ? status.status : undefined;
  const installed = known?.mode != null;

  return (
    <Section title="Explorer menu" description="BeeZip's entries in Explorer's right-click menu, for your Windows account.">
      <Setting label="Menu">
        <div className="flex flex-col gap-1.5 pt-1">
          <p aria-live="polite">
            {status.state === "checking" && <span className="text-muted">Checking…</span>}
            {status.state === "unsupported" && <span className="text-muted">Explorer's menu is only on Windows.</span>}
            {status.state === "failed" && <span className="selectable text-danger">Couldn't check the menu: {status.message}</span>}
            {known && statusLine(known)}
          </p>
          {known && known.problems.length > 0 && (
            <ul className="selectable flex flex-col gap-0.5 text-[12px] text-danger">
              {known.problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}
          <div className="flex gap-2">
            {installed ? (
              <>
                <Button size="sm" disabled={busy} onClick={() => void act("repair")}>
                  Repair
                </Button>
                <Button size="sm" variant="danger" disabled={busy} onClick={() => void act("remove")}>
                  Remove
                </Button>
              </>
            ) : (
              <Button size="sm" variant="primary" disabled={busy || !known} onClick={() => void act("install")}>
                Install
              </Button>
            )}
          </div>
          {actionError && (
            <p role="alert" className="selectable text-[12px] text-danger">
              {actionError}
            </p>
          )}
          {note && <p className="text-[12px] text-muted">{note}</p>}
        </div>
      </Setting>
      <Setting
        label="Layout"
        hint={known?.mode === "modern" ? "Windows 11's own menu always shows a submenu." : "Off, each item is at the top of the menu."}
        error={errors["shell.cascade"]}
      >
        <CheckSetting
          checked={shell.cascade}
          label='Show the items in a "BeeZip" submenu'
          disabled={unsupported || known?.mode === "modern"}
          onCommit={(v) => save("shell.cascade", v)}
        />
      </Setting>
      <Setting label="Items" hint="Archive items show only for archives.">
        <div className="flex flex-col gap-1.5 pt-1">
          {MENU_ITEMS.map((i) => (
            <div key={i.id} className="flex flex-col gap-0.5">
              <Checkbox
                checked={shell.items[i.id]}
                label={i.label}
                disabled={unsupported}
                onChange={(v) => save(`shell.items.${i.id}`, v)}
              />
              {errors[`shell.items.${i.id}`] && (
                <p role="alert" className="selectable text-[12px] text-danger">
                  {errors[`shell.items.${i.id}`]}
                </p>
              )}
            </div>
          ))}
        </div>
      </Setting>
    </Section>
  );
}
