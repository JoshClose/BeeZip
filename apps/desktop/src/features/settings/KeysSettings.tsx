// Settings → Keys (docs/M14.md §6, §11): your keys (for opening archives and for signing them),
// your contacts' public keys, and the system's certificates. `keys.create`, `keys.import`,
// `keys.export` and `keys.delete` change them; the private keys stay sealed by the system.
import { ask, open as pickFile } from "@tauri-apps/plugin-dialog";
import { Copy, KeyRound, Plus, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../../components/ui/input";
import type { CertificateInfo, KeyInfo, KeyKindName } from "../../gen/commands";
import { describeError } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { useKeyring, useKeys } from "../../lib/keyring";
import { startup } from "../../lib/startup";
import { toastError, toastInfo } from "../../lib/toasts";
import { Section } from "./fields";

export const KEY_KINDS: { id: KeyKindName; label: string }[] = [
  { id: "post-quantum", label: "Opens archives, post-quantum (age1pq1…)" },
  { id: "classic", label: "Opens archives, classic (age1…), for older age tools" },
  { id: "signing", label: "Signs archives (bzsig1…)" },
];

const KIND_SHORT: Record<KeyKindName, string> = { "post-quantum": "Opens archives, post-quantum", classic: "Opens archives, classic", signing: "Signs archives" };

/** Where this system keeps your private keys (decision 14). */
export function sealedBy(platform: string): string {
  if (platform === "windows") return "Private keys are kept sealed by Windows for your account, and never leave this PC unless you back them up.";
  if (platform === "macos") return "Private keys are kept in your login Keychain, and never leave this Mac unless you back them up.";
  return "Private keys are kept in files only you can read, as age and ssh keep theirs.";
}

async function copyText(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text);
    toastInfo(`${what} copied`);
  } catch {
    toastInfo("Couldn't reach the clipboard", "Click the window and try again.");
  }
}

/** A key's private half, shown for a backup once the person has agreed. */
function BackupDialog({ name, text, onClose }: { name: string; text: string; onClose: () => void }) {
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Back up ${name}`}
      description="Anyone who has this can open what the key opens, or sign as you. Keep it offline, somewhere safe."
      className="w-[40rem]"
      footer={
        <>
          <Button onClick={() => void copyText(text, "The private key")}>
            <Copy /> Copy
          </Button>
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      <p data-testid="secret-key" className="selectable mb-2 max-h-40 overflow-auto rounded-[5px] border border-rule bg-paper px-3 py-2 font-mono text-[12px] break-all">
        {text}
      </p>
    </Dialog>
  );
}

function KeyRow({ k, onChanged }: { k: KeyInfo; onChanged: () => void }) {
  const [backup, setBackup] = useState<string>();
  const track = useJobs((s) => s.track);
  const exportKey = async (secret: boolean) => {
    try {
      const out = await track("keys.export", { name: k.name, ...(secret ? { secret: true } : {}) }, { title: `Exporting ${k.name}`, quiet: true });
      if (secret) setBackup(out.text);
      else await copyText(out.text, `${k.name}'s public key`);
    } catch (e) {
      toastError(e, `Exporting ${k.name}`);
    }
  };
  const backUp = async () => {
    const yes = await ask(`Show ${k.name}'s private key?\n\nAnyone who has it can open what it opens${k.kind === "signing" ? ", or sign as you" : ""}.`, {
      title: "BeeZip",
      kind: "warning",
      okLabel: "Show it",
      cancelLabel: "Cancel",
    });
    if (yes) await exportKey(true);
  };
  const remove = async () => {
    const what = k.own ? (k.kind === "signing" ? "You won't be able to sign as this key again." : "Archives only this key opens can't be opened any more.") : "Archives you make won't offer it.";
    if (!(await ask(`Delete ${k.name}?\n\n${what}`, { title: "BeeZip", kind: "warning", okLabel: "Delete", cancelLabel: "Cancel" }))) return;
    try {
      await track("keys.delete", { name: k.name }, { title: `Deleting ${k.name}` });
      onChanged();
    } catch (e) {
      toastError(e, `Deleting ${k.name}`);
    }
  };
  return (
    <li className="flex items-start gap-3 px-3 py-2">
      <KeyRound className="mt-0.5 size-4 shrink-0 text-muted" />
      <div className="min-w-0 flex-1">
        <p className="font-semibold">{k.name}</p>
        <p className="text-[12px] text-muted">
          {KIND_SHORT[k.kind]}
          {k.created > 0 ? `, added ${new Date(k.created * 1000).toLocaleDateString()}` : ""}
        </p>
        <p className="selectable font-mono text-[12px]">{k.fingerprint}</p>
        <p className="selectable truncate font-mono text-[11px] text-muted" title={k.public}>
          {k.public}
        </p>
      </div>
      <div className="flex shrink-0 gap-1">
        <Button size="sm" onClick={() => void exportKey(false)} aria-label={`Copy ${k.name}'s public key`} title="Copy the public key, to share">
          <Copy /> Copy
        </Button>
        {k.own && (
          <Button size="sm" onClick={() => void backUp()} aria-label={`Back up ${k.name}`} title="Show the private key, for a backup">
            Back up…
          </Button>
        )}
        <Button size="sm" variant="danger" onClick={() => void remove()} aria-label={`Delete ${k.name}`}>
          <Trash2 />
        </Button>
      </div>
      {backup && <BackupDialog name={k.name} text={backup} onClose={() => setBackup(undefined)} />}
    </li>
  );
}

function KeyList({ keys, empty, label, onChanged }: { keys: KeyInfo[]; empty: string; label: string; onChanged: () => void }) {
  if (keys.length === 0) return <p className="text-[12px] text-muted">{empty}</p>;
  return (
    <ul className="flex flex-col divide-y divide-rule rounded-[5px] border border-rule" aria-label={label}>
      {keys.map((k) => (
        <KeyRow key={k.name} k={k} onChanged={onChanged} />
      ))}
    </ul>
  );
}

function MakeKey({ onChanged }: { onChanged: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<KeyKindName>("post-quantum");
  const [error, setError] = useState<string>();
  const make = async () => {
    setError(undefined);
    try {
      const k = await useJobs.getState().track("keys.create", { name: name.trim(), ...(kind !== "post-quantum" ? { kind } : {}) }, { title: `Making ${name.trim()}` });
      setName("");
      onChanged();
      toastInfo(`${k.name} is ready`, kind === "signing" ? "Pick it under Sign with." : "Share its public key so others can encrypt to you.");
    } catch (e) {
      setError(describeError(e).message);
    }
  };
  return (
    <Field label="Make a key" htmlFor="key-name">
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) void make();
        }}
      >
        <Input id="key-name" className="w-48" placeholder="A name, such as Work" value={name} onChange={(e) => setName(e.target.value)} />
        <Select aria-label="What it's for" value={kind} onChange={(e) => setKind(e.target.value as KeyKindName)}>
          {KEY_KINDS.map((k) => (
            <option key={k.id} value={k.id}>
              {k.label}
            </option>
          ))}
        </Select>
        <Button size="sm" type="submit" disabled={!name.trim()}>
          <Plus /> Make
        </Button>
      </form>
      {error && (
        <p role="alert" className="selectable text-[12px] text-danger">
          {error}
        </p>
      )}
    </Field>
  );
}

function ImportKey({ onChanged }: { onChanged: () => void }) {
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const [file, setFile] = useState<string>();
  const [error, setError] = useState<string>();
  const ready = name.trim().length > 0 && (text.trim().length > 0 || file !== undefined);
  const choose = async () => {
    const picked = await pickFile({ multiple: false, title: "Add a key", filters: [{ name: "Keys", extensions: ["txt", "key", "age"] }, { name: "All files", extensions: ["*"] }] });
    const path = Array.isArray(picked) ? picked[0] : picked;
    if (path) {
      setFile(path);
      setText("");
    }
  };
  const add = async () => {
    setError(undefined);
    try {
      const k = await useJobs.getState().track("keys.import", { name: name.trim(), ...(file ? { file } : { text: text.trim() }) }, { title: `Adding ${name.trim()}` });
      setName("");
      setText("");
      setFile(undefined);
      onChanged();
      toastInfo(k.own ? `${k.name} is one of your keys` : `${k.name} is a contact`);
    } catch (e) {
      setError(describeError(e).message);
    }
  };
  return (
    <Field label="Add a key" htmlFor="import-name" hint="A public key (age1…, age1pq1…, bzsig1…) becomes a contact; a private key becomes yours. Certificates come from the system's stores or a file, where you encrypt.">
      <Input id="import-name" className="w-48" placeholder="Whose it is" value={name} onChange={(e) => setName(e.target.value)} />
      {file ? (
        <p className="selectable flex items-center gap-2 text-[12px]">
          {file}
          <Button size="sm" variant="ghost" onClick={() => setFile(undefined)}>
            Paste instead
          </Button>
        </p>
      ) : (
        <Textarea aria-label="Key" rows={2} className="font-mono text-[12px]" placeholder="Paste the key here" value={text} onChange={(e) => setText(e.target.value)} />
      )}
      <div className="flex gap-2">
        <Button size="sm" onClick={() => void choose()}>
          <Upload /> From a file…
        </Button>
        <Button size="sm" disabled={!ready} onClick={() => void add()}>
          <Plus /> Add
        </Button>
      </div>
      {error && (
        <p role="alert" className="selectable text-[12px] text-danger">
          {error}
        </p>
      )}
    </Field>
  );
}

const HOMES = { software: "here", "smart-card": "on a smart card", tpm: "in the TPM", file: "in a file" } as const;

/** What a certificate can do here, in a few words. */
export function certificateUse(c: CertificateInfo): string {
  const can = [c.can_encrypt && "encrypt to", c.can_sign && c.key !== undefined && "sign with"].filter(Boolean).join(" and ");
  const parts = [can ? `Can ${can}` : "Can't be used", c.key ? `its private key is ${HOMES[c.key]}` : "no private key here"];
  if (!c.trusted) parts.push("not trusted by the system");
  if (c.not_after * 1000 < Date.now()) parts.push("expired");
  return parts.join("; ");
}

function Certificates({ certificates, error }: { certificates: CertificateInfo[]; error?: string }) {
  const platform = startup().platform;
  if (error) return <p className="selectable text-[12px] text-danger">Couldn't list the certificates: {error}</p>;
  if (certificates.length === 0)
    return <p className="text-[12px] text-muted">{platform === "windows" ? "No certificates in Personal or Other People can encrypt or sign." : platform === "macos" ? "No certificates in your Keychain can encrypt or sign." : "Certificates come from files on Linux: pick one under People and keys."}</p>;
  return (
    <ul className="flex flex-col divide-y divide-rule rounded-[5px] border border-rule" aria-label="Certificates">
      {certificates.map((c) => (
        <li key={c.thumbprint} className="px-3 py-2">
          <p className="font-semibold">{c.subject}</p>
          <p className="text-[12px] text-muted">
            Issued by {c.issuer}, {c.algorithm}, until {new Date(c.not_after * 1000).toLocaleDateString()}
            {c.store ? `, in ${c.store === "other-people" ? "Other People" : "Personal"}` : ""}
          </p>
          <p className="text-[12px]">{certificateUse(c)}.</p>
          {c.refused && <p className="text-[12px] text-muted">Can't encrypt: {c.refused}</p>}
          <p className="selectable font-mono text-[11px] text-muted">{c.thumbprint}</p>
        </li>
      ))}
    </ul>
  );
}

export function KeysSettings() {
  const { keys = [], certificates = [], keysError, certificatesError } = useKeys();
  const reload = () => void useKeyring.getState().load(true);
  const yours = keys.filter((k) => k.own);
  const contacts = keys.filter((k) => !k.own);
  return (
    <>
      <Section title="Your keys" description={`Keys archives can be encrypted to, and keys that sign them. ${sealedBy(startup().platform)}`}>
        {keysError ? (
          <p className="selectable text-[12px] text-danger">Couldn't list your keys: {keysError}</p>
        ) : (
          <KeyList keys={yours} label="Your keys" empty="No keys yet." onChanged={reload} />
        )}
        <MakeKey onChanged={reload} />
      </Section>
      <Section title="Contacts" description="Other people's public keys, by name, to encrypt to and to know their signatures.">
        {!keysError && <KeyList keys={contacts} label="Contacts" empty="No contacts yet." onChanged={reload} />}
        <ImportKey onChanged={reload} />
      </Section>
      <Section title="Certificates" description="The certificates the system has that can encrypt archives or sign them.">
        <Certificates certificates={certificates} error={certificatesError} />
      </Section>
    </>
  );
}
