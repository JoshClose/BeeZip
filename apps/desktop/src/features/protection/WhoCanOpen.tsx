// "Who can open this" for an encrypted .bhive (docs/M14.md §3, §8): its ways in, from
// `archive.protection`, with ways to add or remove and "New key" through `archive.protect`.
// Nothing is recompressed. New key rebuilds only the recipients the person confirms, and shows
// each one's key or certificate first, since the archive's descriptions of them are claims.
import { ask } from "@tauri-apps/plugin-dialog";
import { KeyRound, LockKeyhole, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import type { ArchiveProtectInput, ArchiveProtectionOutput, KeyInfo, WayIn } from "../../gen/commands";
import { keptWayIn, type Tab, useArchives } from "../../lib/archives";
import { describeError } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { useKeys } from "../../lib/keyring";
import { addWaysArgs, checkProtection, contactFor, NO_PROTECTION, type ProtectionForm, wayFingerprint, wayKindName } from "../../lib/protection";
import { startup } from "../../lib/startup";
import { NewPasswordField, ProtectionFields } from "./ProtectionFields";
import { showRecoveryKey } from "./RecoveryKey";

/** A way in, by what it is and what the writer called it. */
export function wayTitle(w: WayIn): string {
  const kind = wayKindName(w);
  return w.label && w.label !== kind ? `${kind}: ${w.label}` : kind;
}

/** Ways in that New key rebuilds from the archive's own description of them: someone's key or
 * certificate, which the person confirms first (docs/bhive.md §12.9). */
export function recipientWays(ways: WayIn[]): WayIn[] {
  return ways.filter((w) => w.recipient !== undefined && w.kind !== "password" && w.kind !== "recovery-key" && !w.machine_bound && w.kind !== "security-key");
}

export { contactFor };

/** A way in that is a certificate's: what the archive says of it is only the subject. */
export function certificateWay(w: WayIn): boolean {
  return (w.kind === "rsa-certificate" || w.kind === "ec-p256" || w.kind === "ec-p384") && !w.machine_bound;
}

/** Whether removing these leaves a way in that works on another machine (decision 11). */
export function leavesPortable(ways: WayIn[], removing: number[]): boolean {
  return ways.some((w) => !removing.includes(w.slot) && !w.machine_bound);
}

/** What New key sends beside `new_key`: the slots to drop, the recipients the person confirmed
 * that aren't contacts or your keys, and the password the one password slot is rebuilt with. */
export type NewKeyChoice = { remove: number[]; confirm: number[]; password: string };

/** The New key confirmation: each recipient's key or certificate, ticked when it's a contact,
 * and the password again, since the old one can't be read back: the new key has one. */
function NewKeyDialog({ ways, keys, onCancel, onConfirm }: { ways: WayIn[]; keys: KeyInfo[]; onCancel: () => void; onConfirm: (choice: NewKeyChoice) => void }) {
  const recipients = recipientWays(ways);
  const [keep, setKeep] = useState<number[]>(() => recipients.filter((w) => contactFor(w, keys)).map((w) => w.slot));
  const [password, setPassword] = useState("");
  const passwords = ways.filter((w) => w.kind === "password");
  const drop = [...recipients.filter((w) => !keep.includes(w.slot)), ...(password ? [] : passwords)].map((w) => w.slot).sort((a, b) => a - b);
  const confirm = recipients.filter((w) => keep.includes(w.slot) && !contactFor(w, keys)).map((w) => w.slot);
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
          <Button variant="primary" disabled={!leavesPortable(ways, drop)} onClick={() => onConfirm({ remove: drop, confirm, password })}>
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
                const fingerprint = wayFingerprint(w) ?? contact?.fingerprint;
                return (
                  <li key={w.slot} className="rounded-[5px] border border-rule px-3 py-2">
                    <Checkbox
                      checked={keep.includes(w.slot)}
                      onChange={(on) => setKeep((k) => (on ? [...k, w.slot] : k.filter((s) => s !== w.slot)))}
                      label={contact ? `${wayTitle(w)}, ${contact.own ? "your key" : "your contact"} ${contact.name}` : wayTitle(w)}
                    />
                    {fingerprint && <p className="selectable pt-1 pl-6 font-mono text-[12px]">{fingerprint}</p>}
                    <p className="selectable pt-1 pl-6 font-mono text-[11px] break-all text-muted">{w.recipient}</p>
                    {certificateWay(w) && !fingerprint && (
                      <p className="pt-1 pl-6 text-[12px] text-muted">Only the certificate's subject is known here, as the archive says it: check with its owner before you rebuild it.</p>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        )}
        {passwords.length > 0 && (
          <NewPasswordField
            id="new-key-password"
            value={password}
            onChange={setPassword}
            hint={`Type its password again, or a new one: the old one can't be read back.${passwords.length > 1 ? ` It has ${passwords.length} passwords; the new key has one.` : ""} Leave it empty to remove the password.`}
          />
        )}
        <ul className="flex flex-col gap-0.5 text-[12px] text-muted">
          {others.some((w) => w.kind === "recovery-key") && <li>The recovery key is replaced by a new one, shown once: the old one stops working.</li>}
          {others.some((w) => w.kind === "security-key" && !w.machine_bound) && <li>Each security key needs a touch.</li>}
          {others.some((w) => w.kind === "security-key" && w.machine_bound) && <li>Windows Hello asks for your face, a fingerprint or its PIN.</li>}
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
  // archive.info reports the ways in of an encrypted .bhive it opened: no second read.
  const [state, setState] = useState<ArchiveProtectionOutput | undefined>(() => tab.info?.protection);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState(false);
  const [newKey, setNewKey] = useState(false);
  const [password, setPassword] = useState("");
  const [form, setForm] = useState<ProtectionForm>(NO_PROTECTION);

  // Read once for the archive, not on every change to its tab: a way in typed into this read's
  // own prompt is kept on the tab, and reading again would ask again.
  useEffect(() => {
    if (state) return;
    let live = true;
    useJobs
      .getState()
      .track("archive.protection", { archive: tab.path, ...keptWayIn(tab) }, { title: `Reading who can open ${tab.name}`, quiet: true, tab: tab.id })
      .then(
        (out) => live && setState(out),
        (e) => live && setError(describeError(e).message),
      );
    return () => {
      live = false;
    };
  }, [tab.id, tab.path]);

  const protect = async (args: Omit<ArchiveProtectInput, "archive" | "password">, title: string) => {
    setBusy(true);
    setError(undefined);
    try {
      const out = await useJobs.getState().track("archive.protect", { archive: tab.path, ...args, ...keptWayIn(tab) }, { title, tab: tab.id });
      const now = { encrypted: true, ways: out.ways, post_quantum: out.post_quantum };
      setState(now);
      const info = useArchives.getState().tabs.find((t) => t.id === tab.id)?.info;
      if (info) useArchives.getState().update(tab.id, { info: { ...info, protection: now } });
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
  const check = checkProtection(form, password, windows, ways, keys);
  const remove = async (w: WayIn) => {
    const sure = await ask(`Remove ${wayTitle(w)} from ${tab.name}?

It won't open the archive any more. Someone who opened it before could have kept its key: a new key shuts them out of later versions.`, {
      title: "BeeZip",
      kind: "warning",
      okLabel: "Remove",
      cancelLabel: "Cancel",
    });
    if (sure) await protect({ remove: [w.slot] }, `Removing a way into ${tab.name}`);
  };
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
                <Plus /> Add to the archive
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
                const fingerprint = wayFingerprint(w);
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
                      {fingerprint && <p className="selectable font-mono text-[11px] text-muted">{fingerprint}</p>}
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
                      onClick={() => void remove(w)}
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
          onConfirm={async ({ remove, confirm, password: again }) => {
            setNewKey(false);
            const args = { new_key: true, ...(again ? { add_password: again } : {}), ...(confirm.length > 0 ? { confirm } : {}), ...(remove.length > 0 ? { remove } : {}) };
            // The old password or recovery key kept for the tab no longer opens it; the new
            // password does.
            if (await protect(args, `Making a new key for ${tab.name}`)) useArchives.getState().update(tab.id, { password: again || undefined });
          }}
        />
      )}
    </Dialog>
  );
}
