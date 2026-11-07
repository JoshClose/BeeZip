// The create dialog (docs/M3.md §5.3). Fields that don't apply to the chosen format are hidden.
// In its convert mode (docs/M5.md §8.5) the source is an open archive rather than files.
import { open as pickFiles, save as pickOutput } from "@tauri-apps/plugin-dialog";
import { FilePlus2, FolderPlus, PackagePlus, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../../components/ui/input";
import type {
  ArchiveConvertInput,
  ArchiveCreateInput,
  ArchiveFormatName,
  EncryptionName,
  FormatsListOutput,
  LevelRange,
  MethodName,
} from "../../gen/commands";
import { archiveArgs, type Tab } from "../../lib/archives";
import { baseName, joinPath, parentDir } from "../../lib/format";
import { codecOfTar, methodsOf, useFormats } from "../../lib/formats";
import { useJobs } from "../../lib/jobs";
import { toastError } from "../../lib/toasts";
import { CopyAsCli } from "../cli/CopyAsCli";

export type CreateForm = {
  inputs: string[];
  output: string;
  format: ArchiveFormatName;
  method?: MethodName;
  level?: number;
  solid: boolean;
  threads?: number;
  password: string;
  encryption: EncryptionName;
  encryptHeaders: boolean;
  volumeSize: string;
  exclude: string;
};

/** What the chosen format and method take. */
export function applies(f: Pick<CreateForm, "format" | "method">, formats?: FormatsListOutput) {
  const methods = formats ? methodsOf(formats, f.format) : [];
  const codec = formats ? codecOfTar(formats, f.format) : undefined;
  const fallback = f.format === "7z" ? "lzma2" : f.format === "cab" ? "mszip" : f.format === "squashfs" ? "gzip" : "deflate";
  const method = methods.find((m) => m.id === (f.method ?? fallback));
  // zip's, 7z's and squashfs's levels are their methods'; a compressed tar's or cpio's, its codec's.
  const byMethod = f.format === "zip" || f.format === "7z" || f.format === "squashfs";
  const level: LevelRange | null = byMethod ? (method?.levels ?? null) : (codec?.levels ?? null);
  const archive = f.format === "zip" || f.format === "7z";
  const stored = f.method === "store" || f.method === "copy";
  return {
    methods,
    level,
    password: archive,
    encryption: f.format === "zip",
    solid: f.format === "7z",
    encryptHeaders: f.format === "7z",
    threads: f.format === "7z" || f.format === "zip" ? !stored : (codec?.threads ?? false),
  };
}

/** Archive extensions a name may already end with, longest first. */
const KNOWN = [
  ...["tar", "cpio"].flatMap((a) => ["gz", "bz2", "xz", "lzma", "lz", "zst", "lz4", "br", "sz", "z", "lzo"].map((c) => `${a}.${c}`)),
  ...["tgz", "tbz2", "txz", "tzst", "taz", "tzo", "zip", "7z", "tar", "cpio", "ar", "cab"],
  ...["iso", "squashfs", "sqfs", "snap", "dmg"],
];

/** The new archive's name for a format: `a.zip` → `a.7z`, `a.tar.gz` → `a.tar.zst`. */
export function withFormat(output: string, to: string): string {
  const lower = output.toLowerCase();
  const hit = KNOWN.find((k) => lower.endsWith(`.${k}`));
  const base = hit ? output.slice(0, output.length - hit.length - 1) : output;
  return `${base}.${to}`;
}

/** A converted archive's name: the source's, in its folder, with the new format's extension.
 * Volume sets (`a.7z.001`, `a.part1.rar`) and other extensions (`a.exe`) lose theirs too. */
export function convertOutput(source: string, to: string): string {
  const name = baseName(source);
  const lower = name.toLowerCase();
  const set = lower.match(/\.(?:part\d+\.rar|(?:7z|zip|tar)\.\d{3})$/);
  const hit = set ? set[0].slice(1) : KNOWN.find((k) => lower.endsWith(`.${k}`));
  const dot = name.lastIndexOf(".");
  const stem = hit ? name.slice(0, name.length - hit.length - 1) : dot > 0 ? name.slice(0, dot) : name;
  return joinPath(parentDir(source), `${stem}.${to}`);
}

/** The first format offered for converting: another than the source's own. */
export function convertFormat(source: string): ArchiveFormatName {
  return source.toLowerCase().endsWith(".zip") ? "7z" : "zip";
}

/** The convert mode's fields as `archive.convert` arguments: the new archive's options, the
 * source's password and name encoding, and `decrypt` when its encrypted entries are to be
 * written without one. */
export function convertArgs(source: Tab, f: CreateForm, decrypt: boolean, formats?: FormatsListOutput): ArchiveConvertInput {
  const { inputs: _, password, ...rest } = createArgs(f, formats);
  return {
    archive: source.path,
    ...rest,
    ...(password ? { new_password: password } : {}),
    ...(decrypt && !password ? { decrypt: true } : {}),
    ...archiveArgs(source),
  };
}

/** A first guess at the output: next to the first input, named after it or its folder. */
export function defaultOutput(inputs: string[], format: string): string {
  if (inputs.length === 0) return "";
  const first = inputs[0];
  const dir = parentDir(first);
  let name = inputs.length === 1 ? baseName(first) : baseName(dir) || "archive";
  const dot = name.lastIndexOf(".");
  if (inputs.length === 1 && dot > 0) name = name.slice(0, dot);
  return joinPath(dir, `${name}.${format}`);
}

/** The dialog's fields as `archive.create` arguments, with only the ones that apply. */
export function createArgs(f: CreateForm, formats?: FormatsListOutput): ArchiveCreateInput {
  const a = applies(f, formats);
  const exclude = f.exclude
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const volume = f.volumeSize.trim();
  return {
    output: f.output,
    inputs: f.inputs,
    format: f.format,
    ...(a.methods.length > 0 && f.method ? { method: f.method } : {}),
    ...(a.level && f.level !== undefined ? { level: f.level } : {}),
    ...(a.threads && f.threads !== undefined ? { threads: f.threads } : {}),
    ...(a.password && f.password ? { password: f.password } : {}),
    ...(a.encryption && f.password && f.encryption !== "aes256" ? { encryption: f.encryption } : {}),
    ...(a.encryptHeaders && f.password && !f.encryptHeaders ? { encrypt_headers: false } : {}),
    ...(a.solid && !f.solid ? { solid: false } : {}),
    ...(exclude.length > 0 ? { exclude } : {}),
    ...(volume ? { volume_size: /^\d+$/.test(volume) ? Number(volume) : volume } : {}),
  };
}

/** Files and folders to pack or add, with buttons to pick more. */
export function InputsField({ inputs, onChange }: { inputs: string[]; onChange: (inputs: string[]) => void }) {
  const addInputs = async (directory: boolean) => {
    const picked = await pickFiles({ multiple: true, directory, title: directory ? "Add folders" : "Add files" });
    const list = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
    if (list.length > 0) onChange([...inputs, ...list.filter((p) => !inputs.includes(p))]);
  };
  return (
    <Field label="Files and folders">
      <ul className="max-h-32 overflow-auto rounded-[5px] border border-rule bg-paper" aria-label="Inputs">
        {inputs.length === 0 && <li className="px-2 py-1.5 text-muted">Add files or folders, or drop them here.</li>}
        {inputs.map((p) => (
          <li key={p} className="flex items-center gap-2 px-2 py-1 hover:bg-sunken">
            <span className="selectable min-w-0 flex-1 truncate" title={p}>
              {p}
            </span>
            <button className="rounded p-0.5 text-muted hover:text-ink" onClick={() => onChange(inputs.filter((i) => i !== p))} aria-label={`Remove ${baseName(p)}`}>
              <X className="size-3.5" />
            </button>
          </li>
        ))}
      </ul>
      <div className="flex gap-2">
        <Button size="sm" onClick={() => addInputs(false)}>
          <FilePlus2 /> Add files…
        </Button>
        <Button size="sm" onClick={() => addInputs(true)}>
          <FolderPlus /> Add folder…
        </Button>
      </div>
    </Field>
  );
}

export function CreateDialog({
  inputs: given,
  onClose,
  note,
  source,
}: {
  inputs: string[];
  onClose: () => void;
  /** Why the files go into a new archive: the archive they were dropped on can't take them. */
  note?: string;
  /** Converting this tab's archive, rather than packing files. */
  source?: Tab;
}) {
  const formats = useFormats();
  const track = useJobs((s) => s.track);
  const convert = source !== undefined;
  const encryptedSource = convert && source.info !== undefined && source.info.encryption !== "none";
  const [form, setForm] = useState<CreateForm>(() => ({
    inputs: given,
    output: source ? convertOutput(source.path, convertFormat(source.path)) : defaultOutput(given, "zip"),
    format: source ? convertFormat(source.path) : "zip",
    solid: true,
    password: "",
    encryption: "aes256",
    encryptHeaders: true,
    volumeSize: "",
    exclude: "",
    // An encrypted source stays encrypted, with its own password if it's known.
    ...(encryptedSource && source.password ? { password: source.password } : {}),
  }));
  const [decrypt, setDecrypt] = useState(false);
  const set = (patch: Partial<CreateForm>) => setForm((f) => ({ ...f, ...patch }));

  // Files dropped while the dialog is open arrive as new `given` inputs.
  useEffect(() => {
    setForm((f) => {
      const inputs = [...f.inputs, ...given.filter((g) => !f.inputs.includes(g))];
      return { ...f, inputs, output: f.output || defaultOutput(inputs, f.format) };
    });
  }, [given]);

  const a = applies(form, formats);
  const args = useMemo(
    () => (source ? convertArgs(source, form, decrypt, formats) : createArgs(form, formats)),
    [source, form, decrypt, formats],
  );
  // Encryption is never dropped silently: an encrypted source needs a new password, or the
  // person's word that its entries may go without one.
  const keepsEncryption = !encryptedSource || (a.password && form.password.length > 0) || decrypt;
  const ready = (convert || form.inputs.length > 0) && form.output.trim().length > 0 && keepsEncryption;

  const setInputs = (inputs: string[]) => setForm((f) => ({ ...f, inputs, output: f.output || defaultOutput(inputs, f.format) }));

  const browseOutput = async () => {
    const ext = form.format.split(".").pop() ?? form.format;
    const path = await pickOutput({ defaultPath: form.output || undefined, filters: [{ name: form.format, extensions: [ext] }] });
    if (path) set({ output: path });
  };

  const setFormat = (format: ArchiveFormatName) =>
    setForm((f) => ({
      ...f,
      format,
      method: undefined,
      level: undefined,
      threads: undefined,
      output: f.output ? withFormat(f.output, format) : f.output,
    }));

  const create = () => {
    if (source) {
      const title = `Converting ${source.name} to ${baseName(form.output)}`;
      track("archive.convert", args as ArchiveConvertInput, { title, tab: source.id }).catch((e) => toastError(e, title));
    } else {
      track("archive.create", args as ArchiveCreateInput, { title: `Creating ${baseName(form.output)}` }).catch((e) =>
        toastError(e, `Creating ${baseName(form.output)}`),
      );
    }
    onClose();
  };

  const formatNames = formats?.create ?? ["zip", "7z", "tar"];
  const defaultMethod = form.format === "7z" ? "lzma2" : "deflate";

  return (
    <Dialog
      open
      onClose={onClose}
      title={source ? `Convert ${source.name}` : "New archive"}
      className="w-[42rem]"
      footer={
        <>
          <CopyAsCli command={source ? "archive.convert" : "archive.create"} args={args} disabled={!ready} />
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={create} disabled={!ready}>
            <PackagePlus /> {source ? "Convert" : "Create"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        {note && (
          <p role="note" className="selectable rounded-[5px] border border-rule bg-paper px-3 py-2 text-[12px] text-muted">
            {note}
            <br />
            The files go into a new archive instead.
          </p>
        )}
        {source ? (
          <Field label="Source">
            <p className="selectable truncate pt-1.5" title={source.path}>
              {source.path}
            </p>
          </Field>
        ) : (
          <InputsField inputs={form.inputs} onChange={setInputs} />
        )}
        <Field label="Save as" htmlFor="output">
          <div className="flex gap-2">
            <Input id="output" className="flex-1" value={form.output} onChange={(e) => set({ output: e.target.value })} />
            <Button onClick={browseOutput}>Browse…</Button>
          </div>
        </Field>
        <Field label="Format" htmlFor="format">
          <Select id="format" value={form.format} onChange={(e) => setFormat(e.target.value as ArchiveFormatName)} className="w-40">
            {formatNames.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </Select>
        </Field>
        {a.methods.length > 0 && (
          <Field label="Method" htmlFor="method">
            <Select
              id="method"
              className="w-40"
              value={form.method ?? ""}
              onChange={(e) => set({ method: (e.target.value || undefined) as MethodName | undefined, level: undefined })}
            >
              <option value="">{defaultMethod} (default)</option>
              {a.methods
                .filter((m) => m.id !== defaultMethod)
                .map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.id}
                  </option>
                ))}
            </Select>
          </Field>
        )}
        {a.level && (
          <Field label="Level" htmlFor="level" hint={form.level === undefined ? `Default ${a.level.default}.` : undefined}>
            <div className="flex items-center gap-3">
              <input
                id="level"
                type="range"
                min={a.level.min}
                max={a.level.max}
                value={form.level ?? a.level.default}
                onChange={(e) => set({ level: Number(e.target.value) })}
                className="w-56 accent-[var(--amber)]"
              />
              <span className="tabular w-6">{form.level ?? a.level.default}</span>
              <span className="text-[12px] text-muted">
                {a.level.min} is fastest, {a.level.max} smallest
              </span>
            </div>
          </Field>
        )}
        {a.solid && (
          <Field label="Solid">
            <div className="pt-1">
              <Checkbox checked={form.solid} onChange={(solid) => set({ solid })} label="Compress files together: smaller, but slower to read one file" />
            </div>
          </Field>
        )}
        {a.threads && (
          <Field label="Threads" htmlFor="threads" hint="Empty uses the config's setting; 0 is one per core.">
            <Input
              id="threads"
              type="number"
              min={0}
              className="w-24"
              value={form.threads ?? ""}
              onChange={(e) => set({ threads: e.target.value === "" ? undefined : Math.max(0, Number.parseInt(e.target.value, 10) || 0) })}
            />
          </Field>
        )}
        {a.password && (
          <Field label="Password" htmlFor="new-password" hint={form.password ? undefined : "Leave empty for no encryption."}>
            <Input id="new-password" type="password" autoComplete="new-password" value={form.password} onChange={(e) => set({ password: e.target.value })} />
            {form.password && a.encryption && (
              <Select aria-label="Encryption" value={form.encryption} onChange={(e) => set({ encryption: e.target.value as EncryptionName })} className="w-72">
                <option value="aes256">AES-256</option>
                <option value="zipcrypto">ZipCrypto (weak, for old tools)</option>
              </Select>
            )}
            {form.password && a.encryptHeaders && (
              <Checkbox checked={form.encryptHeaders} onChange={(encryptHeaders) => set({ encryptHeaders })} label="Encrypt file names too" />
            )}
          </Field>
        )}
        {encryptedSource && !(a.password && form.password) && (
          <Field label="Encryption">
            <div className="pt-1">
              <Checkbox checked={decrypt} onChange={setDecrypt} label={`Write ${source.name}'s encrypted entries without a password`} />
            </div>
            <p className="text-[12px] text-muted">
              {a.password ? "Or give the new archive a password above." : `${form.format} can't be encrypted.`}
            </p>
          </Field>
        )}
        <Field label="Split into volumes" htmlFor="volume" hint="A size such as 100m, 4g or 700MB. Empty for one file.">
          <Input id="volume" className="w-32" value={form.volumeSize} onChange={(e) => set({ volumeSize: e.target.value })} placeholder="None" />
        </Field>
        <Field label="Leave out" htmlFor="exclude" hint="One pattern per line, such as *.tmp or node_modules.">
          <Textarea id="exclude" value={form.exclude} onChange={(e) => set({ exclude: e.target.value })} rows={2} />
        </Field>
      </div>
    </Dialog>
  );
}
