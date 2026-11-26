// A .bhive's signatures as the page shows them (docs/M14.md §11): the line at the top of the
// archive window, the add dialog's "sign again", and the question before extracting an archive
// that changed after it was signed.
import type { ArchiveInfoOutput, SignatureAlgorithmName, SignatureReport } from "../gen/commands";

/** A signature, as `archive.info` and `archive.test` report it. */
export type Signature = SignatureReport;

/** `archive.info`'s signatures: none for an unsigned archive or another format. */
export function signaturesOf(info: Pick<ArchiveInfoOutput, "signatures"> | undefined): Signature[] {
  return info?.signatures ?? [];
}

/** What "Add to contacts" adds: a signer's `bzsig1…` key, or its certificate (PEM), which
 * `keys.import` keeps as a contact, known by the whole certificate. */
export function contactKey(s: Signature): string | undefined {
  const p = s.public;
  return p?.startsWith("bzsig1") || p?.startsWith("-----BEGIN CERTIFICATE-----") ? p : undefined;
}

/** The name "Add to contacts" suggests: a certificate's subject, without what BeeZip adds to
 * an unknown one's ("(self-signed)", "(issued by …)"); nothing for a key, which only has its
 * fingerprint. */
export function suggestedName(s: Signature): string {
  if (s.signer === s.fingerprint) return "";
  for (const suffix of [" (self-signed)", ...(s.issuer ? [` (issued by ${s.issuer})`] : [])]) {
    if (s.signer.endsWith(suffix)) return s.signer.slice(0, -suffix.length);
  }
  return s.signer;
}

export const ALGORITHMS: Record<SignatureAlgorithmName, string> = {
  "ml-dsa65-ed25519": "BeeZip signing key (ML-DSA-65 and Ed25519)",
  "rsa-pss": "RSA-PSS",
  "rsa-pkcs1": "RSA PKCS #1 v1.5",
  "ecdsa-p256": "ECDSA P-256",
  "ecdsa-p384": "ECDSA P-384",
  unknown: "an algorithm BeeZip doesn't know",
};

/** "a", "a and b", "a, b and c". */
function names(items: string[]): string {
  return items.length < 2 ? (items[0] ?? "") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/** The subject of an unknown signer's certificate: shown beside "an unknown signer", never in
 * its place, since anyone can make a certificate with any subject (§11). */
export function unknownSubject(s: Signature): string | undefined {
  return s.trust === "unknown" && s.issuer && s.signer && s.signer !== s.fingerprint ? s.signer : undefined;
}

/** Whom a valid signature is from, as a phrase. */
export function signerPhrase(s: Signature): string {
  switch (s.trust) {
    case "yours":
      return `${s.signer} (you)`;
    case "contact":
    case "trusted":
      return s.signer;
    case "expired":
      return `${s.signer}, whose certificate has expired`;
    case "revoked":
      return `${s.signer}, whose certificate was revoked`;
    default:
      return "an unknown signer";
  }
}

export type SignatureSummary = {
  tone: "good" | "warn" | "bad";
  text: string;
};

/** The archive window's signature line, or undefined for an unsigned archive. */
export function summarize(sigs: Signature[]): SignatureSummary | undefined {
  if (sigs.length === 0) return undefined;
  const changed = sigs.filter((s) => s.status === "changed");
  if (changed.length > 0) return { tone: "bad", text: "Changed after it was signed" };
  const valid = sigs.filter((s) => s.status === "valid");
  if (valid.length === 0) return { tone: "warn", text: sigs.length === 1 ? "Signed, but the signature couldn't be checked" : "Signed, but the signatures couldn't be checked" };
  const known = valid.filter((s) => s.trust === "yours" || s.trust === "contact" || s.trust === "trusted");
  const tone = known.length === valid.length ? "good" : "warn";
  const unchecked = sigs.length - valid.length;
  const text = `Signed by ${names(valid.map(signerPhrase))}${unchecked > 0 ? `; ${unchecked} more couldn't be checked` : ""}`;
  return { tone, text };
}

/** A signature failed or a cell differs from its digest: the desktop asks before extracting
 * (docs/M14.md decision 26). */
export function changedSinceSigned(info: ArchiveInfoOutput | undefined): boolean {
  return signaturesOf(info).some((s) => s.status === "changed");
}

/** Your own signing keys that signed it: what an edit offers to sign again with (§11). */
export function ownSigners(sigs: Signature[]): string[] {
  return [...new Set(sigs.filter((s) => s.status === "valid" && s.trust === "yours").map((s) => s.signer))];
}

/** What an edit's question says about the signatures it drops (§11), or "" for an unsigned
 * archive: BeeZip offers to sign again when the signer's key is here. */
export function dropsSignatures(sigs: Signature[]): string {
  if (sigs.length === 0) return "";
  const which = sigs.length === 1 ? "Its signature is" : `Its ${sigs.length} signatures are`;
  const own = ownSigners(sigs);
  return own.length > 0
    ? `${which} dropped too. BeeZip then offers to sign it again with your key ${names(own)}.`
    : `${which} dropped too: only ${sigs.length === 1 ? "its signer" : "its signers"} can sign it again.`;
}
