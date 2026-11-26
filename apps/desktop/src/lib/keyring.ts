// Your keys, your contacts' and the system's certificates (docs/M14.md §6): `keys.list` and
// `certificates.list`, read once when a dialog first needs them and again after a change in
// Settings → Keys. A failure leaves the lists empty and says why where they are shown.
import { useEffect } from "react";
import { create } from "zustand";
import type { CertificateInfo, KeyInfo } from "../gen/commands";
import { describeError } from "./format";
import { useJobs } from "./jobs";

type KeyringState = {
  keys?: KeyInfo[];
  certificates?: CertificateInfo[];
  keysError?: string;
  certificatesError?: string;
  loading: boolean;
  /** Reads both lists, unless they are already here and `again` isn't set. */
  load: (again?: boolean) => Promise<void>;
};

let inflight: Promise<void> | undefined;

export const useKeyring = create<KeyringState>((set, get) => ({
  loading: false,

  load(again = false) {
    const s = get();
    if (!again && s.keys !== undefined && s.certificates !== undefined) return Promise.resolve();
    if (inflight && !again) return inflight;
    set({ loading: true });
    const track = useJobs.getState().track;
    const keys = track("keys.list", {}, { title: "Reading your keys", quiet: true }).then(
      (out) => set({ keys: out.keys, keysError: undefined }),
      (e) => set({ keys: [], keysError: describeError(e).message }),
    );
    const certificates = track("certificates.list", { purpose: "all" }, { title: "Reading your certificates", quiet: true }).then(
      (out) => set({ certificates: out.certificates, certificatesError: undefined }),
      (e) => set({ certificates: [], certificatesError: describeError(e).message }),
    );
    inflight = Promise.all([keys, certificates]).then(() => {
      inflight = undefined;
      set({ loading: false });
    });
    return inflight;
  },
}));

/** The lists, read when the component first shows. */
export function useKeys(): KeyringState {
  const state = useKeyring();
  useEffect(() => {
    void useKeyring.getState().load();
  }, []);
  return state;
}

/** A certificate's warning, when it can encrypt but something about it is off: encryption
 * doesn't depend on trust, so these are allowed (docs/M14.md §4). */
export function certificateWarning(c: CertificateInfo, now = Date.now()): string | undefined {
  if (c.not_after * 1000 < now) return "its certificate has expired, which doesn't stop it opening the archive";
  if (!c.trusted) return "the system doesn't trust its certificate, which doesn't stop it opening the archive";
  return undefined;
}

/** Your signing keys and the certificates whose keys are here and may sign: what "Sign with" offers. */
export function signers(keys: KeyInfo[] = [], certificates: CertificateInfo[] = []): { id: string; label: string }[] {
  return [
    ...keys.filter((k) => k.own && k.kind === "signing").map((k) => ({ id: k.name, label: `${k.name} (your signing key)` })),
    ...certificates.filter((c) => c.can_sign && c.key !== undefined).map((c) => ({ id: c.thumbprint, label: `${c.subject} (certificate)` })),
  ];
}
