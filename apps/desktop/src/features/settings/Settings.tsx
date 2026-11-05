// The settings page (docs/M4.md §7.4): config.toml's settings, each saved as it changes. The
// Explorer section comes with the menu (PR 3), and the job windows' with them (PR 2).
import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";
import { FileCog, FolderOpen } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import type { CodecName, FormatsListOutput, LevelRange, MarkOfTheWeb, OverwritePolicy, SettingsGetOutput } from "../../gen/commands";
import { useFormats } from "../../lib/formats";
import { chooseTheme, errorMessage, loadSettings, saveSettings, THEMES, useTheme } from "../../lib/settings";
import { toastError } from "../../lib/toasts";
import { CheckSetting, ChoiceSetting, LevelSetting, NumberSetting, PathsSetting, Section, Segmented, Setting } from "./fields";

const OVERWRITE: { id: OverwritePolicy; label: string }[] = [
  { id: "ask", label: "Ask" },
  { id: "always", label: "Replace it" },
  { id: "newer", label: "Replace it if the archive's copy is newer" },
  { id: "rename", label: "Keep both, renaming the new one" },
  { id: "never", label: "Keep the existing file" },
];

const MOTW: { id: MarkOfTheWeb; label: string }[] = [
  { id: "all", label: "Keep it on the extracted files, as Explorer does" },
  { id: "none", label: "Leave it off" },
];

/** Every codec and method with levels, by the name `[levels]` takes. */
export function levelTargets(f: FormatsListOutput): { name: string; range: LevelRange }[] {
  const all = new Map<string, LevelRange>();
  for (const c of f.codecs) if (c.levels) all.set(c.id, c.levels);
  for (const format of f.formats) for (const m of format.methods) if (m.levels && !all.has(m.id)) all.set(m.id, m.levels);
  return [...all].map(([name, range]) => ({ name, range })).sort((a, b) => a.name.localeCompare(b.name));
}

function without(errors: Record<string, string>, key: string): Record<string, string> {
  const rest = { ...errors };
  delete rest[key];
  return rest;
}

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [data, setData] = useState<SettingsGetOutput>();
  const [loadError, setLoadError] = useState<string>();
  const [errors, setErrors] = useState<Record<string, string>>({});
  const theme = useTheme((s) => s.theme);
  const formats = useFormats();
  // One save at a time, in order, so a slow answer can't overwrite a newer one.
  const queue = useRef(Promise.resolve());

  useEffect(() => {
    let live = true;
    loadSettings().then(
      (d) => live && setData(d),
      (e) => live && setLoadError(errorMessage(e)),
    );
    return () => {
      live = false;
    };
  }, []);

  const save = useCallback((key: string, value: unknown) => {
    queue.current = queue.current.then(async () => {
      try {
        setData(await saveSettings({ [key]: value }));
        setErrors((e) => without(e, key));
      } catch (e) {
        setErrors((x) => ({ ...x, [key]: errorMessage(e) }));
      }
    });
  }, []);

  const pickTheme = (t: (typeof THEMES)[number]["id"]) => {
    setErrors((e) => without(e, "desktop.theme"));
    chooseTheme(t).catch((e) => setErrors((x) => ({ ...x, "desktop.theme": errorMessage(e) })));
  };

  const s = data?.settings;
  const codecs = (formats?.codecs.map((c) => c.id) ?? [s?.stream.codec ?? "zstd"]) as CodecName[];
  const levels = formats ? levelTargets(formats) : [];
  const path = data?.path ?? undefined;

  return (
    <Dialog
      open
      onClose={onClose}
      title="Settings"
      description="Changes are saved as you make them."
      className="w-[46rem]"
      footer={
        <>
          <span className="selectable mr-auto min-w-0 flex-1 truncate text-[12px] text-muted" title={path}>
            {path}
            {data && !data.exists && " (created when you change a setting)"}
          </span>
          <Button size="sm" disabled={!path || !data?.exists} onClick={() => path && openPath(path).catch((e) => toastError(e, "Opening config.toml"))}>
            <FileCog /> Open config.toml
          </Button>
          <Button size="sm" disabled={!path || !data?.exists} onClick={() => path && revealItemInDir(path).catch((e) => toastError(e, "Showing config.toml"))}>
            <FolderOpen /> Show in folder
          </Button>
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      {loadError && (
        <p role="alert" className="selectable pb-2 text-danger">
          Couldn't read the settings: {loadError}
        </p>
      )}
      {data?.error && (
        <p role="alert" className="selectable mb-1 rounded-[5px] border border-danger/40 px-3 py-2 text-[12px] text-danger">
          config.toml can't be used, so BeeZip uses the defaults until it's fixed. Changing a setting here fixes the file if it's still valid TOML.
          <br />
          {data.error}
        </p>
      )}
      {data && data.warnings.length > 0 && (
        <ul className="selectable mb-1 rounded-[5px] border border-rule bg-paper px-3 py-2 text-[12px] text-muted">
          {data.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}

      <Section title="Appearance">
        <Setting label="Theme" hint="System follows Windows' light or dark mode." error={errors["desktop.theme"]}>
          <Segmented label="Theme" value={theme} options={THEMES} onChange={pickTheme} />
        </Setting>
      </Section>

      {s && (
        <>
          <Section title="Extracting">
            <Setting label="A file is already there" htmlFor="extract-overwrite" error={errors["extract.overwrite"]}>
              <ChoiceSetting id="extract-overwrite" value={s.extract.overwrite} options={OVERWRITE} onCommit={(v) => save("extract.overwrite", v)} />
            </Setting>
            <Setting label="Links" hint="Off, an archive's symbolic and hard links are skipped." error={errors["extract.links"]}>
              <CheckSetting checked={s.extract.links} label="Create the links an archive holds" onCommit={(v) => save("extract.links", v)} />
            </Setting>
            <Setting
              label="Downloaded mark"
              htmlFor="extract-motw"
              hint="Windows warns before opening files marked as downloaded from the internet."
              error={errors["extract.mark_of_the_web"]}
            >
              <ChoiceSetting id="extract-motw" value={s.extract.mark_of_the_web} options={MOTW} onCommit={(v) => save("extract.mark_of_the_web", v)} />
            </Setting>
          </Section>

          <Section title="Creating">
            <Setting label="Threads" htmlFor="create-threads" hint="0 is one per core." error={errors["create.threads"]}>
              <NumberSetting id="create-threads" value={s.create.threads} placeholder="0" onCommit={(v) => save("create.threads", v)} />
            </Setting>
            <Setting
              label="Single-file codec"
              htmlFor="stream-codec"
              hint="What beezip compress uses when no codec is given."
              error={errors["stream.codec"]}
            >
              <ChoiceSetting
                id="stream-codec"
                value={s.stream.codec}
                options={codecs.map((c) => ({ id: c, label: c }))}
                onCommit={(v) => save("stream.codec", v)}
              />
            </Setting>
            {levels.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <p className="text-[12px] text-muted">
                  Default levels, for archives and files that don't name one. Each codec and method keeps its own until you set one.
                </p>
                {levels.map((l) => (
                  <LevelSetting
                    key={l.name}
                    name={l.name}
                    range={l.range}
                    value={s.levels[l.name]}
                    error={errors[`levels.${l.name}`]}
                    onCommit={(v) => save(`levels.${l.name}`, v)}
                  />
                ))}
              </div>
            )}
          </Section>

          <Section title="Limits" description="What stops zip bombs and runaway archives. Empty puts a limit back to its default.">
            <Setting label="Expansion" htmlFor="limits-ratio" hint="The most an archive may grow: unpacked size over packed size." error={errors["limits.max_ratio"]}>
              <NumberSetting id="limits-ratio" min={1} value={s.limits.max_ratio} onCommit={(v) => save("limits.max_ratio", v)} />
            </Setting>
            <Setting label="Entries" htmlFor="limits-entries" hint="The most entries an archive may hold." error={errors["limits.max_entries"]}>
              <NumberSetting id="limits-entries" min={1} value={s.limits.max_entries} onCommit={(v) => save("limits.max_entries", v)} />
            </Setting>
            <Setting label="Decoder memory" htmlFor="limits-memory" hint="In MiB, for each decoder." error={errors["limits.decoder_memory_mib"]}>
              <NumberSetting id="limits-memory" min={1} value={s.limits.decoder_memory_mib} onCommit={(v) => save("limits.decoder_memory_mib", v)} />
            </Setting>
            <Setting label="Total size" htmlFor="limits-total" hint="The most one job may unpack, in bytes." error={errors["limits.max_total_bytes"]}>
              <NumberSetting
                id="limits-total"
                min={1}
                value={s.limits.max_total_bytes}
                placeholder="Unlimited"
                onCommit={(v) => save("limits.max_total_bytes", v)}
              />
            </Setting>
          </Section>

          <Section title="MCP server" description="For beezip mcp, which AI assistants use. Its --root and --read-only flags win over these.">
            <Setting label="May write under" htmlFor="mcp-roots" hint="One folder per line. With none, assistants can read archives but write nothing." error={errors["mcp.roots"]}>
              <PathsSetting id="mcp-roots" value={s.mcp.roots} onCommit={(v) => save("mcp.roots", v.length > 0 ? v : null)} />
            </Setting>
            <Setting label="Read only" error={errors["mcp.read_only"]}>
              <CheckSetting checked={s.mcp.read_only} label="Offer only the commands that don't write" onCommit={(v) => save("mcp.read_only", v)} />
            </Setting>
          </Section>
        </>
      )}
    </Dialog>
  );
}
