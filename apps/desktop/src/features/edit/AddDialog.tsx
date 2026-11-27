// The add dialog (docs/M5.md §8.1): files for an open archive, the folder inside it they go
// into, what happens when an entry is already there, and the new files' method, level and
// password. Dropped files open it too (§8.2): it is the confirmation, so a stray drop changes
// nothing. Adding to a signed .bhive drops its signatures, so it says so and offers to sign
// again with your own keys that signed it (docs/M14.md §11).
import { FilePlus2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import { Field, Input, Select } from "../../components/ui/input";
import type {
  ArchiveAddInput,
  ArchiveFormatName,
  ArchiveInfoOutput,
  EncryptionName,
  FormatsListOutput,
  MethodName,
  OverwritePolicy,
} from "../../gen/commands";
import { archiveArgs, type Tab } from "../../lib/archives";
import { runEdit } from "../../lib/edit";
import { normalize } from "../../lib/format";
import { useFormats } from "../../lib/formats";
import { loadSettings } from "../../lib/settings";
import { ownSigners, signaturesOf } from "../../lib/signatures";
import { toastError } from "../../lib/toasts";
import { CopyAsCli } from "../cli/CopyAsCli";
import { SignWithField } from "../protection/ProtectionFields";
import { applies, defaultLevel, defaultMethod, InputsField, levelArg, levelHint, levelLabel, levelNote, useConfiguredLevels, WhyDisabled } from "../create/CreateDialog";

export type AddForm = {
  inputs: string[];
  /** The folder inside the archive, as typed. */
  dir: string;
  /** Unset, `[edit] overwrite` from the settings. */
  overwrite?: OverwritePolicy;
  method?: MethodName;
  level?: number;
  /** Encrypt the new files (zip, 7z). On for an archive with encrypted entries; off sends `unencrypted`. */
  encrypt: boolean;
  password: string;
  encryption: EncryptionName;
  /** Sign a .bhive again after adding: what `sign` takes. */
  sign?: string[];
};

export const EDIT_OVERWRITE: { id: OverwritePolicy; label: string }[] = [
  { id: "ask", label: "Ask each time" },
  { id: "always", label: "Replace the archive's entry" },
  { id: "newer", label: "Replace it if the file is newer" },
  { id: "rename", label: "Keep both, adding the new one as “name (1)”" },
  { id: "never", label: "Skip the file" },
];

/** The archive's format as the create dialog names them, for its methods and levels: `zip`,
 * `7z`, `tar`, `tar.zst`, `cpio.gz`… The name is `formats.list`'s, whose case may differ from the
 * codec's extension (`tar.Z`). */
export function editFormat(info: ArchiveInfoOutput | undefined, formats?: FormatsListOutput): ArchiveFormatName {
  if (!info) return "zip";
  const streams = info.format === "tar" || info.format === "cpio";
  if (!streams || info.codecs.length === 0) return info.format as ArchiveFormatName;
  const ext = formats?.codecs.find((c) => c.id === info.codecs[0])?.extensions[0]?.replace(/^\./, "");
  const want = `${info.format}.${ext}`;
  const name = ext ? formats?.create.find((c) => c.toLowerCase() === want.toLowerCase()) : undefined;
  return (name ?? info.format) as ArchiveFormatName;
}

/** The level a .bhive was made at, which an add keeps unless one is chosen: its place among
 * the format's named levels, from `archive.info`'s properties. */
export function ownLevel(info: ArchiveInfoOutput | undefined, names: string[]): number | undefined {
  const name = info?.properties?.find((p) => p.name === "Level")?.value;
  const at = name === undefined ? -1 : names.indexOf(name);
  return at < 0 ? undefined : at;
}

/** How the archive's own encryption shapes the new files'. */
export function encryptionOf(info: ArchiveInfoOutput | undefined) {
  return {
    /** Some or all of its entries are encrypted: new files are too, unless told otherwise. */
    encrypted: info !== undefined && info.encryption !== "none",
    /** A 7z whose names are encrypted: new files take its password, always. */
    headers: info?.encrypted_headers ?? false,
  };
}

export function initialAdd(tab: Tab, inputs: string[], dir: string): AddForm {
  const { encrypted, headers } = encryptionOf(tab.info);
  return {
    inputs,
    dir,
    encrypt: encrypted || headers,
    password: encrypted || headers ? (tab.password ?? "") : "",
    encryption: "aes256",
    // Your own keys that signed it sign again, unless the person takes them off.
    sign: ownSigners(signaturesOf(tab.info)),
  };
}

/** The dialog's fields as `archive.add` arguments, with only the ones that apply. An encrypted
 * .bhive's new files are sealed with its own key (docs/M14.md §3): nothing about encryption is
 * chosen, and the way in kept for its tab opens it, as a removal or rename does. */
export function addArgs(tab: Tab, f: AddForm, formats?: FormatsListOutput): ArchiveAddInput {
  const format = editFormat(tab.info, formats);
  const bhive = format === "bhive";
  const a = applies({ format, method: f.method }, formats);
  const { encrypted, headers } = encryptionOf(tab.info);
  const encrypt = a.password && (f.encrypt || headers);
  const kept = bhive ? archiveArgs(tab).password : undefined;
  const dir = normalize(f.dir.trim());
  return {
    archive: tab.path,
    inputs: f.inputs,
    ...(dir ? { dir } : {}),
    ...(f.overwrite ? { overwrite: f.overwrite } : {}),
    ...(a.methods.length > 0 && f.method ? { method: f.method } : {}),
    ...(a.level && f.level !== undefined ? { level: levelArg(a, f.level) } : {}),
    ...(encrypt && f.password ? { password: f.password } : kept ? { password: kept } : {}),
    ...(encrypt && a.encryption && f.password && f.encryption !== "aes256" ? { encryption: f.encryption } : {}),
    ...(encrypted && !encrypt && !bhive ? { unencrypted: true } : {}),
    ...(tab.encoding ? { name_encoding: tab.encoding } : {}),
    ...(bhive && f.sign && f.sign.length > 0 ? { sign: f.sign } : {}),
  };
}

/** Why the dialog can't add yet, said beside its button, or undefined when it can: it needs
 * files, and a password when the new files are encrypted. */
export function addNotReady(tab: Tab, f: AddForm, formats?: FormatsListOutput): string | undefined {
  const a = applies({ format: editFormat(tab.info, formats), method: f.method }, formats);
  const { headers } = encryptionOf(tab.info);
  if (f.inputs.length === 0) return "Add files or folders to put in it.";
  if (a.password && (f.encrypt || headers) && f.password.length === 0)
    return headers ? "Type the archive's password: its names are encrypted." : "Type a password for the new files, or don't encrypt them.";
  return undefined;
}

export function AddDialog({ tab, inputs: given, dir, onClose }: { tab: Tab; inputs: string[]; dir: string; onClose: () => void }) {
  const formats = useFormats();
  const [form, setForm] = useState<AddForm>(() => initialAdd(tab, given, dir));
  const [configured, setConfigured] = useState<OverwritePolicy>();
  const set = (patch: Partial<AddForm>) => setForm((f) => ({ ...f, ...patch }));

  // What the settings say about entries already there, to name the default.
  useEffect(() => {
    let live = true;
    loadSettings().then(
      (s) => live && setConfigured(s.settings.edit.overwrite),
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);

  // Files dropped while the dialog is open join the list.
  useEffect(() => {
    setForm((f) => ({ ...f, inputs: [...f.inputs, ...given.filter((g) => !f.inputs.includes(g))] }));
  }, [given]);

  const format = editFormat(tab.info, formats);
  const a = applies({ format, method: form.method }, formats);
  const levels = useConfiguredLevels();
  // A .bhive keeps the level it was made at; the others start at the settings' or their own.
  const kept = ownLevel(tab.info, a.levelNames);
  const shownLevel = kept === undefined ? defaultLevel(a, levels) : { value: kept, configured: false };
  const { encrypted, headers } = encryptionOf(tab.info);
  const args = useMemo(() => addArgs(tab, form, formats), [tab, form, formats]);
  const why = addNotReady(tab, form, formats);
  const ready = why === undefined;
  const methodDefault = defaultMethod(format);
  const configuredLabel = EDIT_OVERWRITE.find((o) => o.id === configured)?.label;
  const signed = signaturesOf(tab.info).length;

  const add = () => {
    const title = `Adding to ${tab.name}`;
    runEdit(tab, "archive.add", args, title).catch((e) => toastError(e, title));
    onClose();
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Add to ${tab.name}`}
      className="w-[42rem]"
      footer={
        <>
          <CopyAsCli command="archive.add" args={args} disabled={!ready} />
          <WhyDisabled id="add-why" why={why} />
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={add} disabled={!ready} aria-describedby={why ? "add-why" : undefined}>
            <FilePlus2 /> Add
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        <InputsField inputs={form.inputs} onChange={(inputs) => set({ inputs })} />
        <Field label="Into the folder" htmlFor="add-dir" hint="A folder inside the archive; empty for the top. It's made if it isn't there.">
          <Input id="add-dir" value={form.dir} onChange={(e) => set({ dir: e.target.value })} placeholder="The top of the archive" />
        </Field>
        <Field label="Already there" htmlFor="add-overwrite" hint="When the archive has an entry with a file's path.">
          <Select
            id="add-overwrite"
            value={form.overwrite ?? ""}
            onChange={(e) => set({ overwrite: (e.target.value || undefined) as OverwritePolicy | undefined })}
          >
            <option value="">{configuredLabel ? `As in the settings: ${configuredLabel}` : "As in the settings"}</option>
            {EDIT_OVERWRITE.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </Select>
        </Field>
        {a.methods.length > 0 && (
          <Field label="Method" htmlFor="add-method" hint="For the new files.">
            <Select
              id="add-method"
              className="w-40"
              value={form.method ?? ""}
              onChange={(e) => set({ method: (e.target.value || undefined) as MethodName | undefined, level: undefined })}
            >
              <option value="">{methodDefault} (default)</option>
              {a.methods
                .filter((m) => m.id !== methodDefault)
                .map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.id}
                  </option>
                ))}
            </Select>
          </Field>
        )}
        {a.level && shownLevel && (
          <Field
            label="Level"
            htmlFor="add-level"
            hint={
              format.startsWith("tar.")
                ? "The whole archive is compressed again at this level."
                : form.level !== undefined
                  ? undefined
                  : kept !== undefined
                    ? `The archive's own level, ${levelLabel(a, kept)}.`
                    : levelHint(shownLevel, levelLabel(a, shownLevel.value))
            }
          >
            <div className="flex items-center gap-3">
              <input
                id="add-level"
                type="range"
                min={a.level.min}
                max={a.level.max}
                value={form.level ?? shownLevel.value}
                aria-valuetext={levelLabel(a, form.level ?? shownLevel.value)}
                onChange={(e) => set({ level: Number(e.target.value) })}
                className="w-56 shrink-0 accent-[var(--amber)]"
              />
              <span className={a.levelNames.length > 0 ? "w-16 shrink-0" : "tabular w-6 shrink-0"}>{levelLabel(a, form.level ?? shownLevel.value)}</span>
              {a.levelNames.length > 0 && <span className="text-[12px] text-muted">{levelNote(a, form.level ?? shownLevel.value)}</span>}
            </div>
          </Field>
        )}
        {a.password && (
          <Field
            label="Password"
            htmlFor="add-password"
            hint={
              headers
                ? "The archive's names are encrypted, so new files take its password."
                : encrypted && !form.encrypt
                  ? "The new files go in unencrypted, beside encrypted ones."
                  : undefined
            }
          >
            <Checkbox
              checked={form.encrypt || headers}
              disabled={headers}
              onChange={(encrypt) => set({ encrypt })}
              label="Encrypt the new files"
            />
            {(form.encrypt || headers) && (
              <>
                <Input
                  id="add-password"
                  aria-label="Password"
                  type="password"
                  autoComplete="new-password"
                  value={form.password}
                  onChange={(e) => set({ password: e.target.value })}
                />
                {a.encryption && (
                  <Select aria-label="Encryption" value={form.encryption} onChange={(e) => set({ encryption: e.target.value as EncryptionName })} className="w-72">
                    <option value="aes256">AES-256</option>
                    <option value="zipcrypto">ZipCrypto (weak, for old tools)</option>
                  </Select>
                )}
              </>
            )}
          </Field>
        )}
        {format === "bhive" && encrypted && (
          <Field label="Protection">
            <p className="text-[12px] text-muted">The new files are encrypted like the rest, and the same ways in open them. Who can open this changes who can.</p>
          </Field>
        )}
        {format === "bhive" && (
          <SignWithField
            id="add-sign"
            value={form.sign ?? []}
            onChange={(sign) => set({ sign })}
            hint={
              signed > 0
                ? `Adding changes what's in it, so its ${signed === 1 ? "signature is" : `${signed} signatures are`} dropped. Sign it again here.`
                : "Sign the archive once the files are in."
            }
          />
        )}
      </div>
    </Dialog>
  );
}
