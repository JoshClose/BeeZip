// The Unlock panel (docs/M14.md §8): an encrypted .bhive that none of your own keys opened asks
// for a way in. It lists the archive's ways in, a password and a recovery key to type, and a
// button for each key or device this machine has. BeeZip never touches a device (a PIN dialog,
// a touch, Windows Hello) unless the person chose it here.
import { Eye, EyeOff, KeyRound, LockKeyhole } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { Field, Input } from "../../components/ui/input";
import type { PromptReply, SlotKindName, UnlockWay } from "../../gen/commands";
import { formatRecoveryKey, recoveryKeyProblem, SLOT_NAMES } from "../../lib/protection";

/** What the button for a key or device here says. */
export function wayButton(kind: SlotKindName): string {
  switch (kind) {
    case "security-key":
      return "Use a security key or Windows Hello";
    case "ec-p256":
      return "Use This PC or your certificate";
    case "rsa-certificate":
    case "ec-p384":
      return "Use your certificate";
    case "public-key":
    case "post-quantum-key":
      return "Use your key";
    default:
      return `Use the ${SLOT_NAMES[kind].toLowerCase()}`;
  }
}

/** What may follow choosing a key or device. */
function wayNote(kind: SlotKindName): string | undefined {
  if (kind === "security-key") return "Windows asks for a touch, a PIN or your face.";
  if (kind === "ec-p256" || kind === "ec-p384" || kind === "rsa-certificate") return "Windows may ask for a PIN.";
  return undefined;
}

export function UnlockPrompt({
  ways,
  attempt,
  title,
  onReply,
  kept = true,
}: {
  ways: UnlockWay[];
  /** 0 the first time; more after a way in that didn't open it. */
  attempt: number;
  title: string;
  onReply: (reply: PromptReply) => void;
  /** What's typed is kept for the archive's tab; a job window has no tab. */
  kept?: boolean;
}) {
  const passwords = ways.some((w) => w.kind === "password");
  const recovery = ways.some((w) => w.kind === "recovery-key");
  const devices = ways.filter((w) => w.here && w.kind !== "password" && w.kind !== "recovery-key");
  const elsewhere = ways.filter((w) => !w.here && w.kind !== "password" && w.kind !== "recovery-key");
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [key, setKey] = useState("");
  const keyProblem = key ? recoveryKeyProblem(key) : undefined;
  const reply = (answer: Extract<PromptReply, { kind: "Unlock" }>["answer"]) => onReply({ kind: "Unlock", answer });
  const unlock = () => {
    if (password) reply({ way: "password", password });
    else if (key && !keyProblem) reply({ way: "recovery-key", key: formatRecoveryKey(key) });
  };
  const canUnlock = password.length > 0 || (key.length > 0 && !keyProblem);

  return (
    <Dialog
      open
      dismissable={false}
      onClose={() => onReply({ kind: "Cancel" })}
      title="Unlock"
      description={`${title}: the archive is encrypted.`}
      className="w-[38rem]"
      footer={
        <>
          <Button onClick={() => onReply({ kind: "Cancel" })}>Cancel</Button>
          {(passwords || recovery) && (
            <Button variant="primary" onClick={unlock} disabled={!canUnlock}>
              <KeyRound /> Unlock
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        {attempt > 0 && (
          <p role="alert" className="text-danger">
            That didn't open it. Try again, or another way in.
          </p>
        )}
        {passwords && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (password) unlock();
            }}
          >
            <Field label="Password" htmlFor="unlock-password">
              <div className="flex items-center gap-2">
                <Input
                  id="unlock-password"
                  autoFocus
                  className="flex-1"
                  type={visible ? "text" : "password"}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (e.target.value) setKey("");
                  }}
                />
                <Button size="icon" onClick={() => setVisible(!visible)} aria-label={visible ? "Hide password" : "Show password"}>
                  {visible ? <EyeOff /> : <Eye />}
                </Button>
              </div>
            </Field>
          </form>
        )}
        {recovery && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (key && !keyProblem) unlock();
            }}
          >
            <Field label="Recovery key" htmlFor="unlock-recovery" hint={keyProblem ? undefined : "48 digits, in 8 groups of 6."}>
              <Input
                id="unlock-recovery"
                className="font-mono"
                inputMode="numeric"
                autoComplete="off"
                spellCheck={false}
                placeholder="000000-000000-000000-000000-000000-000000-000000-000000"
                value={key}
                onChange={(e) => {
                  setKey(formatRecoveryKey(e.target.value));
                  if (e.target.value) setPassword("");
                }}
              />
              {keyProblem && key.replace(/\D/g, "").length >= 6 && <p className="text-[12px] text-danger">{keyProblem}</p>}
            </Field>
          </form>
        )}
        {devices.length > 0 && (
          <Field label="On this machine">
            <ul className="flex flex-col gap-1.5">
              {devices.map((w) => (
                <li key={w.slot} className="flex items-center gap-3">
                  <Button onClick={() => reply({ way: "slot", slot: w.slot })}>
                    <LockKeyhole /> {wayButton(w.kind)}
                  </Button>
                  <span className="text-[12px] text-muted">{wayNote(w.kind)}</span>
                </li>
              ))}
            </ul>
          </Field>
        )}
        {elsewhere.length > 0 && (
          <Field label="Other ways in">
            <ul className="pt-1.5 text-[12px] text-muted" aria-label="Other ways in">
              {elsewhere.map((w) => (
                <li key={w.slot}>{SLOT_NAMES[w.kind]}: not on this machine</li>
              ))}
            </ul>
          </Field>
        )}
        <p className="text-[12px] text-muted">
          {kept ? "BeeZip keeps what you type in memory for this archive until you close it, and never saves it." : "BeeZip uses what you type for this job only, and never saves it."}
        </p>
      </div>
    </Dialog>
  );
}
