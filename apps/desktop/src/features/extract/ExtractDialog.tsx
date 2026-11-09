// The extract dialog (docs/M3.md §5.3).
import { open as pickFolder } from "@tauri-apps/plugin-dialog";
import { FolderOutput, ListTree } from "lucide-react";
import { useMemo, useState } from "react";
import { SevenZipFix } from "../../components/SevenZipFix";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import { Field, Input, Select } from "../../components/ui/input";
import type { ArchiveExtractInput, ArchiveExtractOutput, NameEncoding, OverwritePolicy } from "../../gen/commands";
import type { Tab } from "../../lib/archives";
import { describeError, parentDir } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { toastError } from "../../lib/toasts";
import { CopyAsCli } from "../cli/CopyAsCli";

export type ExtractForm = {
  dest: string;
  selectedOnly: boolean;
  smart: boolean;
  overwrite: OverwritePolicy;
  links: boolean;
  password: string;
  strip: number;
};

/** The dialog's fields as `archive.extract` arguments; `encoding` is the tab's, which the selected paths are in. */
export function extractArgs(archive: string, entries: string[], f: ExtractForm, dryRun = false, encoding?: NameEncoding): ArchiveExtractInput {
  return {
    archive,
    ...(encoding ? { name_encoding: encoding } : {}),
    ...(f.selectedOnly && entries.length > 0 ? { entries } : {}),
    dest: f.dest,
    smart: f.smart,
    overwrite: f.overwrite,
    ...(f.links ? { links: true } : {}),
    ...(f.password ? { password: f.password } : {}),
    ...(f.strip > 0 ? { strip_components: f.strip } : {}),
    ...(dryRun ? { dry_run: true } : {}),
  };
}

const POLICIES: { value: OverwritePolicy; label: string }[] = [
  { value: "ask", label: "Ask each time" },
  { value: "always", label: "Replace" },
  { value: "newer", label: "Replace if the archive's copy is newer" },
  { value: "rename", label: "Keep both (rename the new one)" },
  { value: "never", label: "Skip" },
];

export function ExtractDialog({ tab, entries, note, onClose }: { tab: Tab; entries: string[]; note?: string; onClose: () => void }) {
  const track = useJobs((s) => s.track);
  const [form, setForm] = useState<ExtractForm>({
    dest: parentDir(tab.path),
    selectedOnly: entries.length > 0,
    smart: true,
    overwrite: "ask",
    links: false,
    password: tab.password ?? "",
    strip: 0,
  });
  const [plan, setPlan] = useState<ArchiveExtractOutput["plan"]>();
  const [planError, setPlanError] = useState<unknown>();
  const set = (patch: Partial<ExtractForm>) => {
    setForm((f) => ({ ...f, ...patch }));
    setPlan(undefined);
  };
  const args = useMemo(() => extractArgs(tab.path, entries, form, false, tab.encoding), [tab.path, entries, form, tab.encoding]);

  const browse = async () => {
    const dir = await pickFolder({ directory: true, defaultPath: form.dest, title: "Extract to" });
    if (typeof dir === "string") set({ dest: dir });
  };

  const extract = () => {
    track("archive.extract", args, { title: `Extracting ${tab.name}`, tab: tab.id }).catch((e) => {
      // Unsafe and Corrupt get their details in the jobs panel; others also show here.
      const { code } = describeError(e);
      if (code !== "Unsafe") toastError(e, `Extracting ${tab.name}`);
    });
    onClose();
  };

  const dryRun = async () => {
    setPlanError(undefined);
    try {
      const out = await track("archive.extract", extractArgs(tab.path, entries, form, true, tab.encoding), {
        title: `Planning ${tab.name}`,
        quiet: true,
        tab: tab.id,
      });
      setPlan(out.plan ?? []);
    } catch (e) {
      setPlanError(e);
    }
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Extract ${tab.name}`}
      className="w-[40rem]"
      footer={
        <>
          <CopyAsCli command="archive.extract" args={args} disabled={!form.dest} />
          <Button onClick={dryRun} disabled={!form.dest}>
            <ListTree /> Show plan
          </Button>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={extract} disabled={!form.dest}>
            <FolderOutput /> Extract
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        {note && (
          <p role="note" className="selectable rounded-[5px] border border-rule bg-paper px-3 py-2 text-[12px] text-muted">
            {note}
          </p>
        )}
        <Field label="Destination" htmlFor="dest">
          <div className="flex gap-2">
            <Input id="dest" className="flex-1" value={form.dest} onChange={(e) => set({ dest: e.target.value })} />
            <Button onClick={browse}>Browse…</Button>
          </div>
          <Checkbox
            checked={form.smart}
            onChange={(smart) => set({ smart })}
            label="Into a folder named after the archive, if it holds more than one item"
          />
        </Field>
        <Field label="Entries">
          <div className="flex flex-col gap-1.5 pt-1">
            <label className="flex items-center gap-2">
              <input type="radio" name="which" checked={!form.selectedOnly} onChange={() => set({ selectedOnly: false })} className="accent-[var(--amber)]" />
              All entries
            </label>
            <label className={entries.length === 0 ? "flex items-center gap-2 text-muted" : "flex items-center gap-2"}>
              <input
                type="radio"
                name="which"
                checked={form.selectedOnly}
                disabled={entries.length === 0}
                onChange={() => set({ selectedOnly: true })}
                className="accent-[var(--amber)]"
              />
              {entries.length === 0 ? "Selected entries (none selected)" : `Selected entries (${entries.length.toLocaleString()})`}
            </label>
          </div>
        </Field>
        <Field label="Existing files" htmlFor="overwrite">
          <Select id="overwrite" value={form.overwrite} onChange={(e) => set({ overwrite: e.target.value as OverwritePolicy })}>
            {POLICIES.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Password" htmlFor="password" hint="Only for encrypted entries.">
          <Input id="password" type="password" value={form.password} onChange={(e) => set({ password: e.target.value })} autoComplete="off" />
        </Field>
        <Field label="Strip folders" htmlFor="strip" hint="Drop this many leading folders from every path.">
          <Input
            id="strip"
            type="number"
            min={0}
            className="w-24"
            value={form.strip}
            onChange={(e) => set({ strip: Math.max(0, Number.parseInt(e.target.value, 10) || 0) })}
          />
        </Field>
        <Field label="Links">
          <div className="pt-1">
            <Checkbox checked={form.links} onChange={(links) => set({ links })} label="Create symbolic links that stay inside the destination" />
          </div>
        </Field>
        {planError !== undefined && (
          <div className="flex flex-col items-start gap-2">
            <p className="selectable text-danger">{`${describeError(planError).code}: ${describeError(planError).message}`}</p>
            <SevenZipFix error={planError} />
          </div>
        )}
        {plan && (
          <div className="rounded-[5px] border border-rule">
            <p className="border-b border-rule px-2 py-1 text-muted">
              {plan.length === 0 ? "Nothing would be extracted." : `${plan.length.toLocaleString()} entries would be written:`}
            </p>
            <ul className="selectable max-h-40 overflow-auto px-2 py-1 font-mono text-[12px]">
              {plan.slice(0, 500).map((p, i) => (
                <li key={i} className={p.skip ? "truncate text-muted" : "truncate"} title={p.skip ?? undefined}>
                  {p.to ?? p.path}
                  {p.skip ? ` (skipped: ${p.skip})` : ""}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Dialog>
  );
}
