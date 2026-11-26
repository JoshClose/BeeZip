// A .bhive's Protection section, in the create, convert and "Who can open this" dialogs
// (docs/M14.md §8): a password with its strength and "Suggest one", a recovery key, people and
// keys (a pasted key, a contact, a certificate, a certificate file), This PC and a security key
// on Windows, and what it all means. And "Sign with", in create, convert and add (§11).
import { open as pickFiles } from "@tauri-apps/plugin-dialog";
import { Eye, EyeOff, FileKey, Plus, Sparkles, X } from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Field, Input, Select } from "../../components/ui/input";
import type { StrengthName, WayIn } from "../../gen/commands";
import { certificateWarning, signers, useKeys } from "../../lib/keyring";
import {
  checkProtection,
  encryptionKeys,
  parseRecipient,
  type ProtectionForm,
  type Recipient,
  recipientLabel,
  sameRecipient,
} from "../../lib/protection";
import { startup } from "../../lib/startup";
import { estimate, suggestPassphrase, useWordlist } from "../../lib/strength";

/** A password field with its strength line and "Suggest one" (docs/M14.md §5). */
export function NewPasswordField({
  id,
  label = "Password",
  value,
  onChange,
  hint = "Leave empty for no password.",
  strength,
  onStrength,
}: {
  id: string;
  label?: string;
  value: string;
  onChange: (password: string) => void;
  hint?: string;
  /** How hard it makes guessing; shown once there is a password. */
  strength?: StrengthName;
  onStrength?: (s: StrengthName) => void;
}) {
  const words = useWordlist();
  const wordSet = useMemo(() => new Set(words ?? []), [words]);
  const [visible, setVisible] = useState(false);
  const rating = value ? estimate(value, wordSet) : undefined;
  return (
    <Field label={label} htmlFor={id} hint={value ? undefined : hint}>
      <div className="flex items-center gap-2">
        <Input id={id} className="flex-1" type={visible ? "text" : "password"} autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} />
        <Button size="icon" onClick={() => setVisible(!visible)} aria-label={visible ? "Hide password" : "Show password"}>
          {visible ? <EyeOff /> : <Eye />}
        </Button>
        <Button
          size="sm"
          disabled={!words}
          title="Six random words: about 77 bits"
          onClick={() => {
            if (!words) return;
            onChange(suggestPassphrase(words));
            setVisible(true);
          }}
        >
          <Sparkles /> Suggest one
        </Button>
      </div>
      {rating && (
        <p role="status" className={`text-[12px] ${rating.weak ? "text-danger" : "text-muted"}`}>
          {rating.line}
        </p>
      )}
      {value && onStrength && (
        <Select aria-label="Guessing cost" className="w-96" value={strength ?? "standard"} onChange={(e) => onStrength(e.target.value as StrengthName)}>
          <option value="standard">Standard: about 0.3 s to open, needs 1 GiB of memory</option>
          <option value="strong">Strong: about 1 s to open, needs 2 GiB of memory</option>
        </Select>
      )}
    </Field>
  );
}

/** The chips of who it's encrypted to, each with a remove button. */
function Chips<T>({ items, label, onRemove, name }: { items: T[]; label: (t: T) => string; onRemove: (i: number) => void; name: string }) {
  if (items.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-1.5" aria-label={name}>
      {items.map((r, i) => (
        <li key={i} className="flex max-w-full items-center gap-1 rounded-[5px] border border-rule bg-paper py-0.5 pr-0.5 pl-2 text-[12px]">
          <span className="selectable min-w-0 truncate" title={label(r)}>
            {label(r)}
          </span>
          <button className="rounded p-0.5 text-muted hover:text-ink" onClick={() => onRemove(i)} aria-label={`Remove ${label(r)}`}>
            <X className="size-3.5" />
          </button>
        </li>
      ))}
    </ul>
  );
}

/** People and keys: paste a key, pick a contact or a certificate, or a certificate file. */
function RecipientsField({ id, recipients, onChange }: { id: string; recipients: Recipient[]; onChange: (r: Recipient[]) => void }) {
  const { keys = [], certificates = [] } = useKeys();
  const [text, setText] = useState("");
  const [error, setError] = useState<string>();
  const add = (r: Recipient) => {
    if (!recipients.some((x) => sameRecipient(x, r))) onChange([...recipients, r]);
  };
  const addText = () => {
    const r = parseRecipient(text, keys);
    if ("error" in r) return setError(r.error);
    setError(undefined);
    setText("");
    add(r);
  };
  const pickFile = async () => {
    const picked = await pickFiles({ multiple: true, title: "Encrypt to certificates", filters: [{ name: "Certificates", extensions: ["cer", "crt", "der", "pem"] }] });
    const list = picked === null ? [] : Array.isArray(picked) ? picked : [picked];
    for (const path of list) add({ kind: "certificate-file", path });
  };
  const contacts = encryptionKeys(keys);
  const encrypting = certificates.filter((c) => c.can_encrypt);
  const refused = certificates.filter((c) => !c.can_encrypt && c.refused);
  return (
    <Field label="People and keys" htmlFor={id} hint="Encrypt to someone's public key or certificate: they open it with their private key.">
      <Chips items={recipients} label={recipientLabel} onRemove={(i) => onChange(recipients.filter((_, j) => j !== i))} name="Encrypted to" />
      <form
        className="flex items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          addText();
        }}
      >
        <Input id={id} className="flex-1" placeholder="age1… or age1pq1…, or a contact's name" value={text} onChange={(e) => setText(e.target.value)} aria-label="Public key or contact" />
        <Button size="sm" type="submit" disabled={!text.trim()}>
          <Plus /> Add
        </Button>
      </form>
      {error && (
        <p role="alert" className="text-[12px] text-danger">
          {error}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {contacts.length > 0 && (
          <Select
            aria-label="Add a contact"
            value=""
            onChange={(e) => {
              const k = contacts.find((c) => c.name === e.target.value);
              if (k) add({ kind: "contact", name: k.name, postQuantum: k.kind === "post-quantum", own: k.own });
            }}
            className="w-56"
          >
            <option value="">Add a contact…</option>
            {contacts.map((k) => (
              <option key={k.name} value={k.name}>
                {k.own ? `${k.name} (yours)` : k.name}
              </option>
            ))}
          </Select>
        )}
        {encrypting.length + refused.length > 0 && (
          <Select
            aria-label="Add a certificate"
            value=""
            onChange={(e) => {
              const c = encrypting.find((x) => x.thumbprint === e.target.value);
              if (c) add({ kind: "certificate", thumbprint: c.thumbprint, subject: c.subject, warning: certificateWarning(c) });
            }}
            className="w-56"
          >
            <option value="">Add a certificate…</option>
            {encrypting.map((c) => (
              <option key={c.thumbprint} value={c.thumbprint}>
                {c.subject}
              </option>
            ))}
            {refused.map((c) => (
              <option key={c.thumbprint} value={c.thumbprint} disabled>
                {c.subject}: {c.refused}
              </option>
            ))}
          </Select>
        )}
        <Button size="sm" onClick={() => void pickFile()}>
          <FileKey /> Certificate file…
        </Button>
      </div>
    </Field>
  );
}

/**
 * The ways in beside the password: recovery key, people and keys, This PC and a security key,
 * then what the choice means: This PC alone refused, mixing warned of, quantum resistance said.
 * `existing` are the archive's ways in, when adding to them.
 */
export function ProtectionFields({
  id,
  value,
  onChange,
  password,
  existing,
}: {
  id: string;
  value: ProtectionForm;
  onChange: (p: ProtectionForm) => void;
  password: string;
  existing?: WayIn[];
}) {
  const windows = startup().platform === "windows";
  const set = (patch: Partial<ProtectionForm>) => onChange({ ...value, ...patch });
  const check = checkProtection(value, password, windows, existing);
  return (
    <>
      <Field label="Recovery key">
        <div className="pt-1">
          <Checkbox
            checked={value.recoveryKey}
            onChange={(recoveryKey) => set({ recoveryKey })}
            label="Make a recovery key: 48 digits that open it when everything else fails, shown once"
          />
        </div>
      </Field>
      <RecipientsField id={`${id}-to`} recipients={value.recipients} onChange={(recipients) => set({ recipients })} />
      {windows && (
        <>
          <Field label="This PC" htmlFor={value.thisPc ? `${id}-pin` : undefined}>
            <div className="pt-1">
              <Checkbox checked={value.thisPc} onChange={(thisPc) => set({ thisPc })} label="Let this PC open it, with a key in its TPM that never leaves it" />
            </div>
            {value.thisPc && (
              <>
                <Input
                  id={`${id}-pin`}
                  aria-label="PIN for This PC"
                  type="password"
                  autoComplete="off"
                  className="w-56"
                  placeholder="A PIN (optional)"
                  value={value.thisPcPin}
                  onChange={(e) => set({ thisPcPin: e.target.value })}
                />
                <p className="text-[12px] text-muted">The TPM guards a PIN against guessing. Without one, anyone signed in to this PC as you can open it.</p>
              </>
            )}
          </Field>
          <Field label="Security key">
            <div className="pt-1">
              <Checkbox
                checked={value.securityKey}
                onChange={(securityKey) => set({ securityKey })}
                label="Let a security key or Windows Hello open it: Windows asks for a touch"
              />
            </div>
          </Field>
        </>
      )}
      {(check.problem || check.warnings.length > 0 || check.quantum) && (
        <div className="flex flex-col gap-1 pl-[9.75rem] text-[12px]">
          {check.problem && (
            <p role="alert" className="text-danger">
              {check.problem}
            </p>
          )}
          {check.warnings.map((w) => (
            <p key={w} className="text-muted">
              {w}
            </p>
          ))}
          {check.quantum && <p className={check.postQuantum ? "text-muted" : "text-ink"}>{check.quantum}</p>}
        </div>
      )}
    </>
  );
}

/** "Sign with": your signing keys and the certificates that may sign, or a certificate file
 * with its key beside it (docs/M14.md §11). `value` is what `sign` takes. */
export function SignWithField({ id, value, onChange, hint }: { id: string; value: string[]; onChange: (sign: string[]) => void; hint?: string }) {
  const { keys, certificates } = useKeys();
  const options = signers(keys, certificates);
  const label = (v: string) => options.find((o) => o.id === v)?.label ?? v.split(/[\\/]/).pop() ?? v;
  const pickFile = async () => {
    const picked = await pickFiles({ multiple: false, title: "Sign with a certificate file", filters: [{ name: "Certificates with keys", extensions: ["pfx", "p12", "pem", "cer", "crt"] }] });
    const path = Array.isArray(picked) ? picked[0] : picked;
    if (path && !value.includes(path)) onChange([...value, path]);
  };
  return (
    <Field label="Sign with" htmlFor={id} hint={hint ?? "A signature shows who made it, and that nothing in it has changed since."}>
      <Chips items={value} label={label} onRemove={(i) => onChange(value.filter((_, j) => j !== i))} name="Signed with" />
      <div className="flex flex-wrap items-center gap-2">
        <Select
          id={id}
          value=""
          className="w-72"
          onChange={(e) => e.target.value && !value.includes(e.target.value) && onChange([...value, e.target.value])}
          disabled={options.length === 0}
        >
          <option value="">{options.length === 0 ? "No signing keys: make one in Settings" : value.length === 0 ? "Don't sign" : "Add a signer…"}</option>
          {options.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </Select>
        <Button size="sm" onClick={() => void pickFile()}>
          <FileKey /> Certificate file…
        </Button>
      </div>
    </Field>
  );
}
