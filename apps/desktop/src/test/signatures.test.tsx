import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Browser } from "../features/browser/Browser";
import { deleteSelection } from "../features/edit/confirmDelete";
import { saveRename } from "../features/edit/rename";
import { SignDialog } from "../features/protection/SignDialog";
import { SignatureLine } from "../features/protection/Signatures";
import type { ArchiveInfoOutput, KeyInfo } from "../gen/commands";
import { type Tab, useArchives } from "../lib/archives";
import { useKeyring } from "../lib/keyring";
import { useUi } from "../lib/ui";
import { changedSinceSigned, ownSigners, type Signature, signaturesOf, summarize } from "../lib/signatures";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(async () => null), save: vi.fn(), ask: vi.fn(async () => true) }));
vi.mock("@tauri-apps/api/event", () => ({ emit: vi.fn(async () => {}), listen: vi.fn(async () => () => {}) }));

const base: Signature = { algorithm: "ml-dsa65-ed25519", status: "valid", trust: "yours", signer: "Mine", fingerprint: "VCPC-QSVP-2XKC-VCIZ", post_quantum: true };
const unknown: Signature = { ...base, trust: "unknown", signer: "VCPC-QSVP-2XKC-VCIZ", public: "bzsig1stranger", claimed_time: 1_780_000_000 };
const cert: Signature = { algorithm: "rsa-pss", status: "valid", trust: "trusted", signer: "CN=Ann Example", issuer: "CN=Corp CA", fingerprint: "AAAA-BBBB-CCCC-DDDD", post_quantum: false };

const info = (signatures: Signature[]) => ({ format: "bhive", encryption: "none", signatures }) as unknown as ArchiveInfoOutput;
const tab = (signatures: Signature[]): Tab => ({ id: "tab-1", path: String.raw`C:\work\a.bhive`, name: "a.bhive", dir: "", reverse: false, selected: [], all: false, solidOk: false, version: 0, info: info(signatures) });

const keys: KeyInfo[] = [{ name: "Mine", kind: "signing", public: "bzsig1mine", fingerprint: "VCPC-QSVP-2XKC-VCIZ", own: true, created: 0 }];

beforeEach(() => {
  fake.reset();
  fake.handlers.set("keys.list", () => ({ keys }));
  fake.handlers.set("certificates.list", () => ({ certificates: [] }));
  useKeyring.setState({ keys: undefined, certificates: undefined, keysError: undefined, certificatesError: undefined, loading: false });
  useArchives.setState({ tabs: [], active: undefined });
});

describe("what the signature line says (docs/M14.md §11)", () => {
  it("names known signers, and says when it can't", () => {
    expect(summarize([])).toBeUndefined();
    expect(summarize([base])).toEqual({ tone: "good", text: "Signed by Mine (you)" });
    expect(summarize([base, cert])).toEqual({ tone: "good", text: "Signed by Mine (you) and CN=Ann Example" });
    expect(summarize([unknown])).toEqual({ tone: "warn", text: "Signed by an unknown signer" });
    expect(summarize([{ ...cert, trust: "expired" }])?.text).toBe("Signed by CN=Ann Example, whose certificate has expired");
    expect(summarize([{ ...cert, trust: "revoked" }])?.tone).toBe("warn");
    expect(summarize([{ ...base, status: "not-checked", trust: undefined }])).toEqual({ tone: "warn", text: "Signed, but the signature couldn't be checked" });
    expect(summarize([base, { ...cert, status: "unknown-algorithm", trust: undefined }])?.text).toBe("Signed by Mine (you); 1 more couldn't be checked");
    // One that fails outweighs the rest.
    expect(summarize([base, { ...cert, status: "changed", trust: undefined }])).toEqual({ tone: "bad", text: "Changed after it was signed" });
  });

  it("reads `archive.info`'s signatures, which PR 0 left out of its type", () => {
    expect(signaturesOf(undefined)).toEqual([]);
    expect(signaturesOf({ format: "zip" } as ArchiveInfoOutput)).toEqual([]);
    expect(signaturesOf(info([base]))).toEqual([base]);
    expect(changedSinceSigned(info([base]))).toBe(false);
    expect(changedSinceSigned(info([{ ...base, status: "changed" }]))).toBe(true);
    expect(ownSigners([base, base, cert, unknown, { ...base, status: "changed", signer: "Old" }])).toEqual(["Mine"]);
  });

  it("shows nothing for an unsigned archive", () => {
    const { container } = render(<SignatureLine tab={tab([])} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows a changed archive in red", () => {
    render(<SignatureLine tab={tab([{ ...base, status: "changed", trust: undefined }])} />);
    expect(screen.getByRole("status", { name: "Signature" })).toHaveTextContent("Changed after it was signed");
    expect(screen.getByRole("status", { name: "Signature" })).toHaveClass("text-danger");
  });

  it("shows an unknown signer's fingerprint, and adds them to contacts from the details", async () => {
    const user = userEvent.setup();
    const t = tab([unknown, cert]);
    useArchives.setState({ tabs: [t], active: t.id });
    fake.handlers.set("keys.import", (args) => ({ ...keys[0], ...(args as object), own: false }));
    render(<SignatureLine tab={t} />);
    const line = screen.getByRole("status", { name: "Signature" });
    expect(line).toHaveTextContent("Signed by an unknown signer and CN=Ann Example");
    expect(line).toHaveTextContent("VCPC-QSVP-2XKC-VCIZ");
    await user.click(screen.getByRole("button", { name: "Details…" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("Issued byCN=Corp CA");
    expect(dialog).toHaveTextContent("RSA-PSS");
    expect(dialog).toHaveTextContent(/as the signer claims: not proved/);
    expect(dialog).toHaveTextContent(/Check the fingerprint with the signer/);
    await user.type(within(dialog).getByLabelText("Contact's name"), "Stranger");
    await user.click(within(dialog).getByRole("button", { name: /Add to contacts/ }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "keys.import")).toBe(true));
    expect(fake.calls.find((c) => c.name === "keys.import")?.args).toEqual({ name: "Stranger", text: "bzsig1stranger" });
    // The archive is read again, so the signature shows as a contact's.
    await waitFor(() => expect(useArchives.getState().tabs[0].info).toBeUndefined());
  });
});

describe("an unknown signer's certificate (docs/M14.md §11)", () => {
  it("shows its subject beside \"an unknown signer\", in the line and the details", async () => {
    const user = userEvent.setup();
    const stranger: Signature = { ...cert, trust: "unknown", signer: "CN=Someone Else", issuer: "CN=Nobody's CA" };
    render(<SignatureLine tab={tab([stranger])} />);
    const line = screen.getByRole("status", { name: "Signature" });
    expect(line).toHaveTextContent("Signed by an unknown signer");
    expect(line).toHaveTextContent("certificate for CN=Someone Else");
    await user.click(screen.getByRole("button", { name: "Details…" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("Signed byan unknown signer");
    expect(dialog).toHaveTextContent("Certificate forCN=Someone Else, as the certificate says");
    expect(dialog).toHaveTextContent("Issued byCN=Nobody's CA");
    expect(dialog).toHaveTextContent("AAAA-BBBB-CCCC-DDDD");
  });
});

describe("Sign", () => {
  it("opens with your keys ticked after an edit, and sends no name encoding", async () => {
    const user = userEvent.setup();
    const t = { ...tab([]), password: "pw", encoding: "cp866" as const };
    useArchives.setState({ tabs: [t], active: t.id });
    fake.handlers.set("archive.sign", () => ({ signatures: [base] }));
    render(<SignDialog tab={t} initial={["Mine"]} note="Deleting dropped its signatures. Sign it again?" onClose={() => {}} />);
    expect(screen.getByRole("note")).toHaveTextContent("Deleting dropped its signatures. Sign it again?");
    await user.click(screen.getByRole("button", { name: "Sign" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.sign")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.sign")?.args).toEqual({ archive: t.path, sign: ["Mine"], password: "pw" });
  });

  it("signs with your key", async () => {
    const user = userEvent.setup();
    const t = tab([]);
    useArchives.setState({ tabs: [t], active: t.id });
    fake.handlers.set("archive.sign", () => ({ signatures: [base] }));
    const onClose = vi.fn();
    render(<SignDialog tab={t} onClose={onClose} />);
    expect(screen.getByRole("button", { name: /^Sign$|^Remove$/ })).toBeDisabled();
    await waitFor(() => expect(screen.getByRole("option", { name: "Mine (your signing key)" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Sign with"), "Mine");
    await user.click(screen.getByRole("button", { name: "Sign" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(fake.calls.find((c) => c.name === "archive.sign")?.args).toEqual({ archive: t.path, sign: ["Mine"] });
    expect(useArchives.getState().tabs[0].info).toBeUndefined();
  });

  it("removes one signature by its place, or all of them", async () => {
    const user = userEvent.setup();
    const t = tab([base, cert]);
    fake.handlers.set("archive.sign", () => ({ signatures: [] }));
    const { unmount } = render(<SignDialog tab={t} onClose={() => {}} />);
    await user.click(screen.getByText(/Remove CN=Ann Example's signature/));
    await user.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.sign")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.sign")?.args).toEqual({ archive: t.path, remove: [1] });
    unmount();

    fake.calls = [];
    render(<SignDialog tab={t} onClose={() => {}} />);
    await user.click(screen.getByText(/Remove Mine \(you\)'s signature/));
    await user.click(screen.getByText(/Remove CN=Ann Example's signature/));
    await user.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.sign")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.sign")?.args).toEqual({ archive: t.path, remove_all: true });
  });

  it("says why it couldn't sign", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.sign", () => {
      throw { code: "UnsupportedOperation", message: "archive.sign is not built yet (docs/M14.md)" };
    });
    render(<SignDialog tab={tab([base])} onClose={() => {}} />);
    await user.click(screen.getByText(/Remove Mine/));
    await user.click(screen.getByRole("button", { name: "Remove" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("archive.sign is not built yet");
  });
});

describe("the archive window", () => {
  function Live({ id }: { id: string }) {
    const t = useArchives((st) => st.tabs.find((x) => x.id === id));
    return t ? <Browser tab={t} /> : null;
  }

  it("has a signature line, Who can open this and Sign for a .bhive", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.list", () => ({ entries: [], total: 0, offset: 0, has_more: false }));
    const t = { ...tab([base]), info: { ...info([base]), encryption: "all", chain: "bhive", size: 1, packed_size: 1, not_editable: null } as ArchiveInfoOutput };
    useArchives.setState({ tabs: [t], active: t.id });
    render(<Live id={t.id} />);
    expect(screen.getByRole("status", { name: "Signature" })).toHaveTextContent("Signed by Mine (you)");
    await user.click(screen.getByRole("button", { name: "Who can open this" }));
    expect(useUi.getState().dialog).toEqual({ kind: "protection", tab: t.id });
    await user.click(screen.getByRole("button", { name: "Sign…" }));
    expect(useUi.getState().dialog).toEqual({ kind: "sign", tab: t.id });
  });

  it("has neither for a zip, and no Who can open this for an unencrypted .bhive", () => {
    fake.handlers.set("archive.list", () => ({ entries: [], total: 0, offset: 0, has_more: false }));
    const zip = { ...tab([]), id: "tab-2", info: { ...info([]), format: "zip", chain: "zip", size: 1, packed_size: 1, not_editable: null } as ArchiveInfoOutput };
    const plain = { ...tab([]), id: "tab-3", info: { ...info([]), chain: "bhive", size: 1, packed_size: 1, not_editable: null } as ArchiveInfoOutput };
    useArchives.setState({ tabs: [zip, plain], active: zip.id });
    const { unmount } = render(<Live id={zip.id} />);
    expect(screen.queryByRole("button", { name: "Sign…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Who can open this" })).toBeNull();
    unmount();
    render(<Live id={plain.id} />);
    expect(screen.getByRole("button", { name: "Sign…" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Who can open this" })).toBeNull();
  });
});

describe("deleting from a signed .bhive", () => {
  it("says its signatures drop", async () => {
    const { ask } = await import("@tauri-apps/plugin-dialog");
    const { confirmDelete } = await import("../features/edit/confirmDelete");
    await confirmDelete(1, "a.bhive", "x.txt", [base, cert]);
    expect(vi.mocked(ask).mock.lastCall?.[0]).toBe(
      "Delete x.txt from a.bhive?\n\nThis can't be undone.\n\nIts 2 signatures are dropped too. BeeZip then offers to sign it again with your key Mine.",
    );
    await confirmDelete(1, "a.bhive", "x.txt", [cert]);
    expect(vi.mocked(ask).mock.lastCall?.[0]).toBe("Delete x.txt from a.bhive?\n\nThis can't be undone.\n\nIts signature is dropped too: only its signer can sign it again.");
    await confirmDelete(1, "a.zip", "x.txt");
    expect(vi.mocked(ask).mock.lastCall?.[0]).toBe("Delete x.txt from a.zip?\n\nThis can't be undone.");
  });

  it("offers Sign afterwards, with your key ticked", async () => {
    const edited = { path: String.raw`C:\work\a.bhive`, added: 0, replaced: 0, removed: 1, renamed: 0, copied: 0, recompressed: 0, skipped: 0, unencrypted: 0, bytes_before: 1, bytes_after: 1, dry_run: false, plan: null };
    fake.handlers.set("archive.remove", () => edited);
    const t = tab([base, cert]);
    useArchives.setState({ tabs: [t], active: t.id });
    useUi.setState({ dialog: undefined });
    await deleteSelection(t, 1, { all: false, paths: ["x.txt"] });
    expect(fake.calls.some((c) => c.name === "archive.remove")).toBe(true);
    expect(useUi.getState().dialog).toEqual({ kind: "sign", tab: t.id, sign: ["Mine"], note: "Deleting dropped its signatures. Sign it again?" });

    // Signed by others only: nothing to offer.
    useUi.setState({ dialog: undefined });
    const theirs = { ...tab([cert]), id: "tab-2" };
    useArchives.setState({ tabs: [theirs], active: theirs.id });
    await deleteSelection(theirs, 1, { all: false, paths: ["x.txt"] });
    expect(useUi.getState().dialog).toBeUndefined();
  });
});

describe("renaming in a signed .bhive (docs/M14.md §11)", () => {
  const edited = { path: String.raw`C:\work\a.bhive`, added: 0, replaced: 0, removed: 0, renamed: 1, copied: 0, recompressed: 0, skipped: 0, unencrypted: 0, bytes_before: 1, bytes_after: 1, dry_run: false, plan: null };

  it("asks first, then offers Sign", async () => {
    const { ask } = await import("@tauri-apps/plugin-dialog");
    fake.handlers.set("archive.rename", () => edited);
    fake.handlers.set("archive.list", () => ({ entries: [], total: 0, offset: 0, has_more: false }));
    const t = { ...tab([base]), renaming: { index: 0, path: "x.txt", busy: false } };
    useArchives.setState({ tabs: [t], active: t.id });
    useUi.setState({ dialog: undefined });

    vi.mocked(ask).mockResolvedValueOnce(false);
    await saveRename(t, "y.txt");
    expect(vi.mocked(ask).mock.lastCall?.[0]).toBe("Rename x.txt to y.txt?\n\nIts signature is dropped too. BeeZip then offers to sign it again with your key Mine.");
    expect(fake.calls.some((c) => c.name === "archive.rename")).toBe(false);
    expect(useArchives.getState().tabs[0].renaming).toEqual({ index: 0, path: "x.txt", busy: false, error: undefined });

    await saveRename(t, "y.txt");
    expect(fake.calls.find((c) => c.name === "archive.rename")?.args).toEqual({ archive: t.path, from: "x.txt", to: "y.txt" });
    expect(useUi.getState().dialog).toEqual({ kind: "sign", tab: t.id, sign: ["Mine"], note: "Renaming dropped its signatures. Sign it again?" });
  });

  it("doesn't ask in an unsigned archive", async () => {
    const { ask } = await import("@tauri-apps/plugin-dialog");
    vi.mocked(ask).mockClear();
    fake.handlers.set("archive.rename", () => edited);
    const t = { ...tab([]), renaming: { index: 0, path: "x.txt", busy: false } };
    useArchives.setState({ tabs: [t], active: t.id });
    useUi.setState({ dialog: undefined });
    await saveRename(t, "y.txt");
    expect(ask).not.toHaveBeenCalled();
    expect(fake.calls.some((c) => c.name === "archive.rename")).toBe(true);
    expect(useUi.getState().dialog).toBeUndefined();
  });
});
