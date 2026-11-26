// "Who can open this" for an encrypted .bhive (docs/M14.md §3, §8): its ways in, from
// `archive.protection`, with ways to add or remove and "New key" through `archive.protect`.
// Nothing is recompressed. New key rebuilds only the recipients the person confirms, and shows
// each one's key or certificate first, since the archive's descriptions of them are claims.
import { KeyRound, LockKeyhole, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import type { ArchiveProtectInput, ArchiveProtectionOutput, KeyInfo, WayIn } from "../../gen/commands";
import { archiveArgs, type Tab } from "../../lib/archives";
import { describeError } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { useKeys } from "../../lib/keyring";
import { addWaysArgs, checkProtection, NO_PROTECTION, type ProtectionForm, SLOT_NAMES } from "../../lib/protection";
import { startup } from "../../lib/startup";
import { NewPasswordField, ProtectionFields } from "./ProtectionFields";
import { showRecoveryKey } from "./RecoveryKey";

/** A way in, by what it is and what the writer called it. */
export function wayTitle(w: WayIn): string {
  return w.label && w.label !== SLOT_NAMES[w.kind] ? `${SLOT_NAMES[w.kind]}: ${w.label}` : SLOT_NAMES[w.kind];
}

/** Ways in that New key rebuilds from the archive's own description of them: someone's key or
 * certificate, which the person confirms first (docs/bhive.md §12.9). */
export function recipientWays(ways: WayIn[]): WayIn[] {
  return ways.filter((w) => w.recipient !== undefined && w.kind !== "password" && w.kind !== "recovery-key" && !w.machine_bound && w.kind !== "security-key");
}

/** The contact or key of yours a way in is to, matched by its public key. */
export function contactFor(w: WayIn, keys: KeyInfo[]): KeyInfo | undefined {
  return w.recipient === undefined ? undefined : keys.find((k) => k.public === w.recipient);
}

/** Whether removing these leaves a way in that works on another machine (decision 11). */
export function leavesPortable(ways: WayIn[], removing: number[]): boolean {
  return ways.some((w) => !removing.includes(w.slot) && !w.machine_bound);
}

/** The New key confirmation: each recipient's key or certificate, ticked when it's a contact. */
function NewKeyDialog({ ways, keys, onCancel, onConfirm }: { ways: WayIn[]; keys: KeyInfo[]; onCancel: () => void; onConfirm: (drop: number[]) => void }) {
  const recipients = recipientWays(ways);
  const [keep, setKeep] = useState<number[]>(() => recipients.filter((w) => contactFor(w, keys)).map((w) => w.slot));
  const drop = recipients.filter((w) => !keep.includes(w.slot)).map((w) => w.slot);
  const others = ways.filter((w) => !recipients.includes(w));
  return (
    <Dialog
      open
      onClose={onCancel}
      title="Make a new key"
      description="Every file is sealed again under a new key and every way in is rebuilt, so anyone who kept the old key can't open later versions."
      className="w-[42rem]"
      footer={
        <>
          <Button onClick={onCancel}>Cancel</Button>
          <Button variant="primary" disabled={!leavesPortable(ways, drop)} onClick={() => onConfirm(drop)}>
            <KeyRound /> Make a new key
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        {recipients.length > 0 && (
          <div>
            <p className="pb-1.5">Rebuild these people's ways in? The archive says who they are, but anyone who held its key could have changed that: check each key or certificate.</p>
            <ul className="flex flex-col gap-2" aria-label="Recipients">
              {recipients.map((w) => {
                const contact = contactFor(w, keys);
                return (
                  <li key={w.slot} className="rounded-[5px] border border-rule px-3 py-2">
                    <Checkbox
                      checked={keep.includes(w.slot)}
                      onChange={(on) => setKeep((k) => (on ? [...k, w.slot] : k.filter((s) => s !== w.slot)))}
                      label={contact ? `${wayTitle(w)}, ${contact.own ? "your key" : "your contact"} ${contact.name}` : wayTitle(w)}
                    />
                    {contact && <p className="pt-1 pl-6 font-mono text-[12px]">{contact.fingerprint}</p>}
                    <p className="selectable pt-1 pl-6 font-mono text-[11px] break-all text-muted">{w.recipient}</p>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
        <ul className="flex flex-col gap-0.5 text-[12px] text-muted">
          {others.some((w) => w.kind === "password") && <li>BeeZip asks for each password again.</li>}
          {others.some((w) => w.kind === "recovery-key") && <li>The recovery key is replaced by a new one, shown once: the old one stops working.</li>}
          {others.some((w) => w.kind === "security-key") && <li>Each security key needs a touch.</li>}
          {others.some((w) => w.machine_bound && w.kind !== "security-key") && <li>This PC may ask for its PIN.</li>}
        </ul>
        {!leavesPortable(ways, drop) && (
          <p role="alert" className="text-[12px] text-danger">
            Keep at least one way in that works on another machine.
          </p>
        )}
      </div>
    </Dialog>
  );
}

export function WhoCanOpenDialog({ tab, onClose }: { tab: Tab; onClose: () => void }) {
  const { keys = [] } = useKeys();
  const windows = startup().platform === "windows";
  const [state, setState] = useState<ArchiveProtectionOutput>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState(false);
  const [newKey, setNewKey] = useState(false);
  const [password, setPassword] = useState("");
  const [form, setForm] = useState<ProtectionForm>(NO_PROTECTION);

  useEffect(() => {
    let live = true;
    useJobs
      .getState()
      .track("archive.protection", { archive: tab.path, ...archiveArgs(tab) }, { title: `Reading who can open ${tab.name}`, quiet: true, tab: tab.id })
      .then(
        (out) => live && setState(out),
        (e) => live && setError(describeError(e).message),
      );
    return () => {
      live = false;
    };
  }, [tab]);

  const protect = async (args: Omit<ArchiveProtectInput, "archive" | "password">, title: string) => {
    setBusy(true);
    setError(undefined);
    try {
      const out = await useJobs.getState().track("archive.protect", { archive: tab.path, ...args, ...archiveArgs(tab) }, { title, tab: tab.id });
      setState({ encrypted: true, ways: out.ways, post_quantum: out.post_quantum });
      showRecoveryKey(tab.path, out);
      return true;
    } catch (e) {
      setError(describeError(e).message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const ways = state?.ways ?? [];
  const check = checkProtection(form, password, windows, ways);
  const remove = (w: WayIn) => void protect({ remove: [w.slot] }, `Removing a way into ${tab.name}`);
  const add = async () => {
    if (await protect(addWaysArgs(form, password, windows), `Adding ways into ${tab.name}`)) {
      setAdding(false);
      setPassword("");
      setForm(NO_PROTECTION);
    }
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Who can open ${tab.name}`}
      className="w-[44rem]"
      footer={
        <>
          <Button onClick={() => setNewKey(true)} disabled={!state || busy} title="Seal everything under a new key">
            <KeyRound /> New key…
          </Button>
          <span className="flex-1" />
          {adding ? (
            <>
              <Button onClick={() => setAdding(false)}>Cancel</Button>
              <Button variant="primary" disabled={busy || check.ways === 0 || !!check.problem} onClick={() => void add()}>
                <Plus /> Add
              </Button>
            </>
          ) : (
            <>
              <Button onClick={() => setAdding(true)} disabled={!state || busy}>
                <Plus /> Add a way in…
              </Button>
              <Button variant="primary" onClick={onClose}>
                Done
              </Button>
            </>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        {error && (
          <p role="alert" className="selectable text-danger">
            {error}
          </p>
        )}
        {!state && !error && <p className="text-muted">Reading…</p>}
        {state && (
          <>
            <ul className="flex flex-col divide-y divide-rule rounded-[5px] border border-rule" aria-label="Ways in">
              {ways.map((w) => {
                const contact = contactFor(w, keys);
                const last = !leavesPortable(ways, [w.slot]);
                return (
                  <li key={w.slot} className="flex items-start gap-3 px-3 py-2">
                    <LockKeyhole className="mt-0.5 size-4 shrink-0 text-muted" />
                    <div className="min-w-0 flex-1">
                      <p>
                        {wayTitle(w)}
                        {contact && <span className="text-muted"> ({contact.own ? "your key" : "contact"} {contact.name})</span>}
                      </p>
                      {w.recipient && (
                        <p className="selectable truncate font-mono text-[11px] text-muted" title={w.recipient}>
                          {w.recipient}
                        </p>
                      )}
                      <p className="text-[12px] text-muted">
                        {w.machine_bound ? "Only on this PC. " : ""}
                        {w.post_quantum ? "Post-quantum." : "Classic: a quantum computer could open it."}
                      </p>
                    </div>
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={busy || last}
                      title={last ? "The last way in that works on another machine stays" : undefined}
                      onClick={() => remove(w)}
                      aria-label={`Remove ${wayTitle(w)}`}
                    >
                      <Trash2 /> Remove
                    </Button>
                  </li>
                );
              })}
            </ul>
            <p className="text-[12px]">
              {state.post_quantum ? "Resists quantum computers: every way in is post-quantum." : "Doesn't resist quantum computers: some ways in use classic keys."}
            </p>
            <p className="text-[12px] text-muted">
              Removing a way in isn't taking it back: someone who opened the archive before could have kept its key. A new key shuts them out of later versions.
            </p>
          </>
        )}
        {adding && (
          <div className="flex flex-col gap-3 border-t border-rule pt-3">
            <NewPasswordField id="add-way-password" label="Add a password" value={password} onChange={setPassword} hint="Leave empty to add no password." strength={form.strength} onStrength={(strength) => setForm({ ...form, strength })} />
            <ProtectionFields id="add-way" value={form} onChange={setForm} password={password} existing={ways} />
          </div>
        )}
      </div>
      {newKey && state && (
        <NewKeyDialog
          ways={ways}
          keys={keys}
          onCancel={() => setNewKey(false)}
          onConfirm={(drop) => {
            setNewKey(false);
            void protect({ new_key: true, ...(drop.length > 0 ? { remove: drop } : {}) }, `Making a new key for ${tab.name}`);
          }}
        />
      )}
    </Dialog>
  );
}
