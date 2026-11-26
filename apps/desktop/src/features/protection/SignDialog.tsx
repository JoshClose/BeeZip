// Sign (docs/M14.md §11): add signatures to a .bhive with your keys or certificates, or remove
// some or all of them, with `archive.sign`. Changing who can open it keeps signatures; changing
// its files drops them.
import { Signature as SignIcon } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import { Field } from "../../components/ui/input";
import { keptWayIn, type Tab, useArchives } from "../../lib/archives";
import { relist } from "../../lib/edit";
import { describeError } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { ownSigners, signaturesOf, signerPhrase } from "../../lib/signatures";
import { SignWithField } from "./ProtectionFields";

/** Sign: add signatures with your keys or certificates, or remove some or all (`archive.sign`). */
export function SignDialog({ tab, initial = [], note, onClose }: { tab: Tab; initial?: string[]; note?: string; onClose: () => void }) {
  const sigs = signaturesOf(tab.info);
  const [sign, setSign] = useState<string[]>(initial);
  const [remove, setRemove] = useState<number[]>([]);
  const [error, setError] = useState<string>();
  const removeAll = sigs.length > 0 && remove.length === sigs.length;
  const ready = sign.length > 0 || remove.length > 0;
  const run = async () => {
    const title = sign.length > 0 ? `Signing ${tab.name}` : `Removing signatures from ${tab.name}`;
    setError(undefined);
    try {
      await useJobs.getState().track(
        "archive.sign",
        {
          archive: tab.path,
          ...(sign.length > 0 ? { sign } : {}),
          // By their place in archive.info's list, from 1.
          ...(removeAll ? { remove_all: true } : remove.length > 0 ? { remove: remove.map((i) => i + 1) } : {}),
          ...keptWayIn(tab),
        },
        { title, tab: tab.id },
      );
      useArchives.getState().update(tab.id, { info: undefined });
      relist(tab.id);
      onClose();
    } catch (e) {
      setError(describeError(e).message);
    }
  };
  const resign = ownSigners(sigs);
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Sign ${tab.name}`}
      description="A signature shows who made what's in it, and that nothing has changed since. Changing who can open it keeps signatures; changing its files drops them."
      className="w-[40rem]"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!ready} onClick={() => void run()}>
            <SignIcon /> {sign.length > 0 ? "Sign" : "Remove"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        {note && (
          <p role="note" className="rounded-[5px] border border-rule bg-paper px-3 py-2 text-[12px]">
            {note}
          </p>
        )}
        {sigs.length > 0 && (
          <Field label="Its signatures">
            <ul className="flex flex-col gap-1 pt-1" aria-label="Its signatures">
              {sigs.map((s, i) => (
                <li key={i}>
                  <Checkbox
                    checked={remove.includes(i)}
                    onChange={(on) => setRemove((r) => (on ? [...r, i] : r.filter((x) => x !== i)))}
                    label={`Remove ${s.status === "valid" ? signerPhrase(s) : s.signer}'s signature (${s.fingerprint})`}
                  />
                </li>
              ))}
            </ul>
          </Field>
        )}
        <SignWithField id="sign-with" value={sign} onChange={setSign} hint={resign.length > 0 ? `Already signed by your key ${resign.join(", ")}.` : undefined} />
        {error && (
          <p role="alert" className="selectable text-[12px] text-danger">
            {error}
          </p>
        )}
      </div>
    </Dialog>
  );
}
