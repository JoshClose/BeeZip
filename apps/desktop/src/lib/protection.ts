// A .bhive's protection as the dialogs build it (docs/M14.md §4, §5, §8): the ways in, the
// arguments `archive.create`, `archive.convert` and `archive.protect` take for them, and the
// checks and warnings the dialogs show. Pure, so the tests see what the dialogs do.
import type { ArchiveCreateInput, ArchiveProtectInput, KeyInfo, SlotKindName, StrengthName, WayIn } from "../gen/commands";

/** A .bhive with ways in: "Who can open this" applies to it. */
export function encryptedBhive(info: { format: string; encryption: string } | undefined): boolean {
  return info?.format === "bhive" && info.encryption !== "none";
}

/** Someone the archive is encrypted to. */
export type Recipient =
  /** A public key pasted in: `age1…` or `age1pq1…`. */
  | { kind: "key"; text: string }
  /** A contact's key, or one of yours, from Settings → Keys, by name. */
  | { kind: "contact"; name: string; postQuantum: boolean; own: boolean }
  /** A certificate in the system's stores, by thumbprint. */
  | { kind: "certificate"; thumbprint: string; subject: string; warning?: string }
  /** A certificate file: `.cer`, `.crt`, `.der` or `.pem`. */
  | { kind: "certificate-file"; path: string };

export type ProtectionForm = {
  strength: StrengthName;
  recoveryKey: boolean;
  recipients: Recipient[];
  thisPc: boolean;
  thisPcPin: string;
  securityKey: boolean;
};

export const NO_PROTECTION: ProtectionForm = { strength: "standard", recoveryKey: false, recipients: [], thisPc: false, thisPcPin: "", securityKey: false };

/** What each kind of way in is called. */
export const SLOT_NAMES: Record<SlotKindName, string> = {
  password: "Password",
  "recovery-key": "Recovery key",
  "public-key": "Public key",
  "post-quantum-key": "Post-quantum public key",
  "rsa-certificate": "RSA certificate",
  "ec-p256": "EC certificate or This PC (P-256)",
  "ec-p384": "EC certificate (P-384)",
  "security-key": "Security key or Windows Hello",
};

/** Ways in a quantum computer couldn't open (docs/M14.md §1): passwords, recovery keys,
 * post-quantum keys and security keys. */
export function slotPostQuantum(kind: SlotKindName): boolean {
  return kind === "password" || kind === "recovery-key" || kind === "post-quantum-key" || kind === "security-key";
}

/** `age1pq1…` is post-quantum, `age1…` classic; anything else isn't a public key. */
export function publicKeyKind(text: string): "post-quantum" | "classic" | undefined {
  const t = text.trim().toLowerCase();
  if (t.startsWith("age1pq1")) return "post-quantum";
  if (t.startsWith("age1") && t.length > 8) return "classic";
  return undefined;
}

/** Keys an archive can be encrypted to: contacts' and your own, not signing keys. */
export function encryptionKeys(keys: KeyInfo[]): KeyInfo[] {
  return keys.filter((k) => k.kind !== "signing");
}

/** What the person typed into "Public key or contact": a key, a contact's name, or why neither. */
export function parseRecipient(text: string, keys: KeyInfo[]): Recipient | { error: string } {
  const t = text.trim();
  if (!t) return { error: "Paste a public key, or type a contact's name." };
  if (/^AGE-SECRET-KEY-|^BZSIG-SECRET-KEY-/i.test(t)) return { error: "That's a private key: anyone who has it can open what it opens. Paste the public key (age1…) instead." };
  if (/^bzsig1/i.test(t)) return { error: "That's a signing key (bzsig1…): it checks signatures, and archives can't be encrypted to it." };
  const byText = encryptionKeys(keys).find((k) => k.public === t);
  if (byText) return { kind: "contact", name: byText.name, postQuantum: byText.kind === "post-quantum", own: byText.own };
  if (publicKeyKind(t)) return { kind: "key", text: t };
  const byName = encryptionKeys(keys).find((k) => k.name.toLowerCase() === t.toLowerCase());
  if (byName) return { kind: "contact", name: byName.name, postQuantum: byName.kind === "post-quantum", own: byName.own };
  return { error: "Not a public key (age1… or age1pq1…) or a contact's name." };
}

/** Two recipients that are the same person's key. */
export function sameRecipient(a: Recipient, b: Recipient): boolean {
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case "key":
      return a.text === (b as typeof a).text;
    case "contact":
      return a.name === (b as typeof a).name;
    case "certificate":
      return a.thumbprint === (b as typeof a).thumbprint;
    case "certificate-file":
      return a.path === (b as typeof a).path;
  }
}

/** How a recipient is shown in its chip. */
export function recipientLabel(r: Recipient): string {
  switch (r.kind) {
    case "key":
      return r.text.length > 28 ? `${r.text.slice(0, 16)}…${r.text.slice(-8)}` : r.text;
    case "contact":
      return r.own ? `${r.name} (yours)` : r.name;
    case "certificate":
      return r.subject;
    case "certificate-file": {
      const parts = r.path.split(/[\\/]/);
      return parts[parts.length - 1] || r.path;
    }
  }
}

function recipientPostQuantum(r: Recipient): boolean {
  if (r.kind === "key") return publicKeyKind(r.text) === "post-quantum";
  if (r.kind === "contact") return r.postQuantum;
  return false; // every certificate is classic
}

/** The `to` and `to_cert` arguments: keys and contacts' names, thumbprints and files. */
export function recipientArgs(recipients: Recipient[]): { to?: string[]; to_cert?: string[] } {
  const to = recipients.flatMap((r) => (r.kind === "key" ? [r.text] : r.kind === "contact" ? [r.name] : []));
  const certs = recipients.flatMap((r) => (r.kind === "certificate" ? [r.thumbprint] : r.kind === "certificate-file" ? [r.path] : []));
  return { ...(to.length > 0 ? { to } : {}), ...(certs.length > 0 ? { to_cert: certs } : {}) };
}

type ProtectionArgs = Pick<ArchiveCreateInput, "recovery_key" | "to" | "to_cert" | "this_pc" | "this_pc_pin" | "security_key" | "strength">;

/** The protection fields as `archive.create` and `archive.convert` take them, beside the
 * password (which goes in `password` or `new_password`). Only what is set. */
export function protectionArgs(p: ProtectionForm, password: string, windows = true): ProtectionArgs {
  return {
    ...(p.recoveryKey ? { recovery_key: true } : {}),
    ...recipientArgs(p.recipients),
    ...(windows && p.thisPc ? { this_pc: true } : {}),
    ...(windows && p.thisPc && p.thisPcPin ? { this_pc_pin: p.thisPcPin } : {}),
    ...(windows && p.securityKey ? { security_key: true } : {}),
    ...(password && p.strength !== "standard" ? { strength: p.strength } : {}),
  };
}

/** The same, as ways to add with `archive.protect`. */
export function addWaysArgs(p: ProtectionForm, password: string, windows = true): Omit<ArchiveProtectInput, "archive"> {
  const { strength, ...rest } = protectionArgs(p, password, windows);
  return { ...(password ? { add_password: password } : {}), ...rest, ...(strength ? { strength } : {}) };
}

export type ProtectionCheck = {
  /** How many ways in the form adds. */
  ways: number;
  /** Why it can't go ahead: This PC alone (docs/M14.md decision 11). */
  problem?: string;
  /** Things to know that don't stop it. */
  warnings: string[];
  /** Whether it resists quantum computers, once there is a way in. */
  quantum?: string;
  postQuantum?: boolean;
};

/** What the dialogs say about the ways in chosen. `existing` are the archive's ways when adding. */
export function checkProtection(p: ProtectionForm, password: string, windows = true, existing: WayIn[] = []): ProtectionCheck {
  const thisPc = windows && p.thisPc;
  const securityKey = windows && p.securityKey;
  const ways = (password ? 1 : 0) + (p.recoveryKey ? 1 : 0) + p.recipients.length + (thisPc ? 1 : 0) + (securityKey ? 1 : 0);
  const warnings: string[] = [];
  const portable = password !== "" || p.recoveryKey || p.recipients.length > 0 || existing.some((w) => !w.machine_bound);
  let problem: string | undefined;
  if (thisPc && !portable) problem = "This PC opens it only on this computer. Add a password, a recovery key or someone's key too, so it can be opened elsewhere.";
  if (securityKey && !portable && !thisPc)
    warnings.push("If Windows offers Windows Hello rather than a security key, it opens only on this PC: a password or a recovery key as well is safer.");
  const others = p.recipients.some((r) => !(r.kind === "contact" && r.own));
  const hasPassword = password !== "" || existing.some((w) => w.kind === "password");
  if (hasPassword && others && (password !== "" || p.recipients.length > 0))
    warnings.push("Anyone who can open this could also make an archive your password opens.");
  for (const r of p.recipients) if (r.kind === "certificate" && r.warning) warnings.push(`${r.subject}: ${r.warning}`);
  if (ways + existing.length === 0) return { ways, problem, warnings };
  const classic = [
    ...p.recipients.filter((r) => !recipientPostQuantum(r)).map(recipientLabel),
    ...(thisPc ? ["This PC"] : []),
    ...existing.filter((w) => !w.post_quantum).map((w) => w.label ?? SLOT_NAMES[w.kind]),
  ];
  const postQuantum = classic.length === 0;
  const quantum = postQuantum
    ? "Resists quantum computers: every way in is post-quantum."
    : `Doesn't resist quantum computers: ${classic.length === 1 ? `${classic[0]} uses` : `${classic.slice(0, -1).join(", ")} and ${classic[classic.length - 1]} use`} classic keys.`;
  return { ways, problem, warnings, quantum, postQuantum };
}

/** A recovery key's 48 digits, in their 8 groups of 6 (docs/bhive.md §12.5): any separators,
 * and as much as has been typed. */
export function formatRecoveryKey(input: string): string {
  const digits = input.replace(/\D/g, "").slice(0, 48);
  return (digits.match(/.{1,6}/g) ?? []).join("-");
}

/** Why a typed recovery key can't be right, or undefined: 48 digits, each group of 6 a multiple
 * of 11 below 720,896, so a typo shows before anything is tried. */
export function recoveryKeyProblem(input: string): string | undefined {
  const digits = input.replace(/\D/g, "");
  if (digits.length !== 48) return `A recovery key has 48 digits; this has ${digits.length}.`;
  const groups = digits.match(/.{6}/g) ?? [];
  const bad = groups.findIndex((g) => Number(g) % 11 !== 0 || Number(g) >= 720896);
  return bad >= 0 ? `Group ${bad + 1} (${groups[bad]}) has a typo.` : undefined;
}
