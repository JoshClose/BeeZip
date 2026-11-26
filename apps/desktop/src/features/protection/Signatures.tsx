// A .bhive's signatures in the archive window (docs/M14.md §11): the line at its top, and the
// details behind it, with "Add to contacts" for a signer BeeZip doesn't know. Sign is in
// SignDialog.tsx.
import { BadgeCheck, ShieldAlert, ShieldX, UserPlus } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { Input } from "../../components/ui/input";
import { type Tab, useArchives } from "../../lib/archives";
import { useJobs } from "../../lib/jobs";
import { useKeyring } from "../../lib/keyring";
import { ALGORITHMS, type Signature, signaturesOf, signerPhrase, summarize } from "../../lib/signatures";
import { toastError, toastInfo } from "../../lib/toasts";

const STATUS: Record<Signature["status"], string> = {
  valid: "Valid",
  changed: "Doesn't match: the archive changed after it was signed",
  "unknown-algorithm": "Couldn't be checked: an algorithm BeeZip doesn't know",
  "not-checked": "Couldn't be checked",
};

/** The time a signer claims, as the person reads dates. */
function claimed(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString();
}

/** "Add to contacts": the signer's key or certificate, under a name, with `keys.import`. */
function AddContact({ sig, tab }: { sig: Signature; tab: Tab }) {
  const [name, setName] = useState(sig.signer === sig.fingerprint ? "" : sig.signer);
  const [busy, setBusy] = useState(false);
  if (!sig.public) return null;
  const add = async () => {
    setBusy(true);
    try {
      await useJobs.getState().track("keys.import", { name: name.trim(), text: sig.public }, { title: `Adding ${name.trim()} to your contacts` });
      await useKeyring.getState().load(true);
      // Read again, so the signature shows as a contact's.
      useArchives.getState().update(tab.id, { info: undefined });
      toastInfo(`${name.trim()} is a contact`, "Their signatures show their name from now on.");
    } catch (e) {
      toastError(e, "Adding the contact");
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="flex items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim()) void add();
      }}
    >
      <Input aria-label="Contact's name" placeholder="Their name" value={name} onChange={(e) => setName(e.target.value)} className="w-56" />
      <Button size="sm" type="submit" disabled={!name.trim() || busy}>
        <UserPlus /> Add to contacts
      </Button>
    </form>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[8rem_1fr] gap-3 py-0.5">
      <dt className="text-muted">{label}</dt>
      <dd className="selectable min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** Every signature, in full. */
export function SignatureDetails({ tab, sigs, onClose }: { tab: Tab; sigs: Signature[]; onClose: () => void }) {
  return (
    <Dialog open onClose={onClose} title={`Signatures on ${tab.name}`} className="w-[40rem]" footer={<Button onClick={onClose}>Close</Button>}>
      <ul className="flex flex-col gap-3 pb-2">
        {sigs.map((s, i) => (
          <li key={i} className="rounded-[5px] border border-rule px-3 py-2">
            <dl className="text-[13px]">
              <Row label="Signed by">{s.status === "valid" ? signerPhrase(s) : s.signer}</Row>
              <Row label="Status">
                <span className={s.status === "changed" ? "text-danger" : undefined}>{STATUS[s.status]}</span>
              </Row>
              {s.status === "valid" && s.trust === "unknown" && <Row label="Known">No: not your key, a contact's, or a certificate the system trusts</Row>}
              <Row label="Fingerprint">
                <span className="font-mono">{s.fingerprint}</span>
              </Row>
              {s.issuer && <Row label="Issued by">{s.issuer}</Row>}
              <Row label="Algorithm">
                {ALGORITHMS[s.algorithm]}
                {s.post_quantum ? ", post-quantum" : ""}
              </Row>
              {s.claimed_time !== undefined && <Row label="Signed at">{claimed(s.claimed_time)}, as the signer claims: not proved</Row>}
              {s.note && <Row label="Note">{s.note}</Row>}
            </dl>
            {s.status === "valid" && s.trust === "unknown" && (
              <div className="pt-2">
                <p className="pb-1.5 text-[12px] text-muted">Check the fingerprint with the signer, by phone or in person, before you add them.</p>
                <AddContact sig={s} tab={tab} />
              </div>
            )}
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

/** The line at the top of the archive window, for a signed archive. */
export function SignatureLine({ tab }: { tab: Tab }) {
  const [details, setDetails] = useState(false);
  const sigs = signaturesOf(tab.info);
  const summary = summarize(sigs);
  if (!summary) return null;
  const Icon = summary.tone === "good" ? BadgeCheck : summary.tone === "bad" ? ShieldX : ShieldAlert;
  const color = summary.tone === "bad" ? "text-danger" : "text-ink";
  const unknown = sigs.find((s) => s.status === "valid" && s.trust === "unknown");
  return (
    <div role="status" aria-label="Signature" className={`flex h-8 shrink-0 items-center gap-2 border-b border-rule px-3 text-[12px] ${color}`}>
      <Icon className={`size-4 shrink-0 ${summary.tone === "good" ? "text-amber" : ""}`} />
      <span className={`min-w-0 truncate ${summary.tone === "bad" ? "font-semibold" : ""}`}>{summary.text}</span>
      {unknown && <span className="shrink-0 font-mono text-muted">{unknown.fingerprint}</span>}
      <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setDetails(true)}>
        Details…
      </Button>
      {details && <SignatureDetails tab={tab} sigs={sigs} onClose={() => setDetails(false)} />}
    </div>
  );
}
