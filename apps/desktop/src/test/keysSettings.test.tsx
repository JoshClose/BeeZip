import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ask, open } from "@tauri-apps/plugin-dialog";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { certificateUse, contactCertificate, KeysSettings, sealedBy } from "../features/settings/KeysSettings";
import type { CertificateInfo, KeyInfo } from "../gen/commands";
import { certificateWarning, signers, useKeyring } from "../lib/keyring";
import { encryptionKeys } from "../lib/protection";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(async () => null), save: vi.fn(), ask: vi.fn(async () => true) }));

const keys: KeyInfo[] = [
  { name: "Home", kind: "post-quantum", public: "age1pq1home", fingerprint: "HOME-HOME-HOME-HOME", own: true, created: 1_780_000_000 },
  { name: "Signing", kind: "signing", public: "bzsig1me", fingerprint: "SIGN-SIGN-SIGN-SIGN", own: true, created: 1_780_000_000 },
  { name: "Ann", kind: "classic", public: "age1ann", fingerprint: "ANNN-ANNN-ANNN-ANNN", own: false, created: 0 },
];
const certificates: CertificateInfo[] = [
  { thumbprint: "AB12", subject: "CN=Me at work", issuer: "CN=Corp CA", not_after: 4102444800, algorithm: "rsa-2048", store: "personal", key: "smart-card", can_encrypt: true, can_sign: true, trusted: true },
  { thumbprint: "CD34", subject: "CN=Old", issuer: "CN=Old CA", not_after: 1_000_000_000, algorithm: "ec-p256", store: "other-people", can_encrypt: false, can_sign: true, refused: "an ECDSA-only key can't agree keys", trusted: false },
];

beforeEach(() => {
  fake.reset();
  vi.mocked(ask).mockReset().mockResolvedValue(true);
  vi.mocked(open).mockReset().mockResolvedValue(null);
  fake.handlers.set("keys.list", () => ({ keys }));
  fake.handlers.set("certificates.list", () => ({ certificates }));
  useKeyring.setState({ keys: undefined, certificates: undefined, keysError: undefined, certificatesError: undefined, loading: false });
});

describe("reading your keys", () => {
  it("keeps the latest load's lists when an earlier one ends later", async () => {
    let release!: () => void;
    const slow = new Promise<void>((r) => (release = r));
    let calls = 0;
    fake.handlers.set("keys.list", async () => {
      calls++;
      if (calls === 1) {
        await slow;
        return { keys: [keys[0]] };
      }
      return { keys };
    });
    const first = useKeyring.getState().load(true);
    const second = useKeyring.getState().load(true);
    await second;
    expect(useKeyring.getState().keys).toEqual(keys);
    release();
    await first;
    expect(useKeyring.getState().keys).toEqual(keys);
    expect(useKeyring.getState().loading).toBe(false);
  });
});

describe("Settings → Keys (docs/M14.md §6)", () => {
  it("lists your keys, your contacts and the certificates", async () => {
    render(<KeysSettings />);
    const yours = await screen.findByRole("list", { name: "Your keys" });
    expect(within(yours).getAllByRole("listitem")).toHaveLength(2);
    expect(yours).toHaveTextContent("HomeOpens archives, post-quantum");
    expect(yours).toHaveTextContent("SIGN-SIGN-SIGN-SIGN");
    const contacts = screen.getByRole("list", { name: "Contacts" });
    expect(contacts).toHaveTextContent("Ann");
    // A contact's private key isn't here to back up.
    expect(within(contacts).queryByRole("button", { name: /Back up/ })).toBeNull();
    const certs = screen.getByRole("list", { name: "Certificates" });
    expect(certs).toHaveTextContent("Can encrypt to and sign with; its private key is on a smart card.");
    expect(certs).toHaveTextContent("Can't be used; no private key here; not trusted by the system; expired.");
    expect(certs).toHaveTextContent("Can't encrypt: an ECDSA-only key can't agree keys");
    expect(fake.calls.find((c) => c.name === "certificates.list")?.args).toEqual({ purpose: "all" });
  });

  it("makes a key of the kind chosen", async () => {
    const user = userEvent.setup();
    fake.handlers.set("keys.create", (args) => ({ ...keys[1], ...(args as object) }));
    render(<KeysSettings />);
    await screen.findByRole("list", { name: "Your keys" });
    await user.type(screen.getByLabelText("Make a key"), "Work");
    await user.click(screen.getByRole("button", { name: "Make" }));
    await waitFor(() => expect(fake.calls.filter((c) => c.name === "keys.create")).toHaveLength(1));
    expect(fake.calls.find((c) => c.name === "keys.create")?.args).toEqual({ name: "Work" });
    await user.type(screen.getByLabelText("Make a key"), "Signer");
    await user.selectOptions(screen.getByLabelText("What it's for"), "signing");
    await user.click(screen.getByRole("button", { name: "Make" }));
    await waitFor(() => expect(fake.calls.filter((c) => c.name === "keys.create")).toHaveLength(2));
    expect(fake.calls.filter((c) => c.name === "keys.create")[1].args).toEqual({ name: "Signer", kind: "signing" });
    // The lists are read again after each change.
    await waitFor(() => expect(fake.calls.filter((c) => c.name === "keys.list").length).toBeGreaterThanOrEqual(3));
  });

  it("adds a pasted key or a file, and says why it couldn't", async () => {
    const user = userEvent.setup();
    let fail = true;
    fake.handlers.set("keys.import", (args) => {
      if (fail) throw { code: "InvalidArgs", message: "not a key BeeZip knows" };
      return { ...keys[2], ...(args as object) };
    });
    render(<KeysSettings />);
    await screen.findByRole("list", { name: "Contacts" });
    await user.type(screen.getByLabelText("Add a key or certificate"), "Bob");
    await user.type(screen.getByLabelText("Key"), "  age1bob  ");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not a key BeeZip knows");
    expect(fake.calls.find((c) => c.name === "keys.import")?.args).toEqual({ name: "Bob", text: "age1bob" });

    fail = false;
    vi.mocked(open).mockResolvedValueOnce(String.raw`C:\keys\bob.cer`);
    await user.click(screen.getByRole("button", { name: /From a file/ }));
    expect(await screen.findByText(String.raw`C:\keys\bob.cer`)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(fake.calls.filter((c) => c.name === "keys.import")).toHaveLength(2));
    expect(fake.calls.filter((c) => c.name === "keys.import")[1].args).toEqual({ name: "Bob", file: String.raw`C:\keys\bob.cer` });
  });

  it("copies a public key, backs up a private one after asking, and deletes after asking", async () => {
    const user = userEvent.setup();
    fake.handlers.set("keys.export", (args) => ({ text: (args as { secret?: boolean }).secret ? "AGE-SECRET-KEY-PQ-1HOME" : "age1pq1home" }));
    fake.handlers.set("keys.delete", (args) => ({ deleted: (args as { name: string }).name }));
    render(<KeysSettings />);
    await screen.findByRole("list", { name: "Your keys" });

    await user.click(screen.getByRole("button", { name: "Copy Home's public key" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "keys.export")).toBe(true));
    expect(await navigator.clipboard.readText()).toBe("age1pq1home");

    vi.mocked(ask).mockResolvedValueOnce(false);
    await user.click(screen.getByRole("button", { name: "Back up Home" }));
    expect(ask).toHaveBeenCalledWith(expect.stringMatching(/Anyone who has it can open what it opens/), expect.anything());
    expect(fake.calls.filter((c) => c.name === "keys.export")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Back up Home" }));
    expect(await screen.findByTestId("secret-key")).toHaveTextContent("AGE-SECRET-KEY-PQ-1HOME");
    expect(fake.calls.filter((c) => c.name === "keys.export")[1].args).toEqual({ name: "Home", secret: true });
    await user.click(screen.getByRole("button", { name: "Done" }));

    vi.mocked(ask).mockResolvedValueOnce(false);
    await user.click(screen.getByRole("button", { name: "Delete Ann" }));
    expect(fake.calls.some((c) => c.name === "keys.delete")).toBe(false);
    await user.click(screen.getByRole("button", { name: "Delete Ann" }));
    await waitFor(() => expect(fake.calls.find((c) => c.name === "keys.delete")?.args).toEqual({ name: "Ann" }));
  });

  it("offers certificate files, and lists a certificate contact by its subject and dates", async () => {
    const user = userEvent.setup();
    const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const bob: KeyInfo = { name: "Bob", kind: "certificate", public: pem, fingerprint: "BOBB-BOBB-BOBB-BOBB", own: false, created: 1_780_000_000, subject: "CN=Bob", issuer: "CN=Corp CA", not_after: 4102444800 };
    const signsOnly: KeyInfo = { ...bob, name: "Eve", subject: "CN=Eve", issuer: "CN=Eve", not_after: 1_000_000_000, refused: "it is an ECDSA certificate" };
    fake.handlers.set("keys.list", () => ({ keys: [...keys, bob, signsOnly] }));
    fake.handlers.set("keys.export", () => ({ text: pem }));
    fake.handlers.set("keys.import", (args) => ({ ...bob, ...(args as object) }));
    render(<KeysSettings />);
    const contacts = await screen.findByRole("list", { name: "Contacts" });
    expect(contacts).toHaveTextContent("BobCertificate");
    expect(contacts).toHaveTextContent(`CN=Bob, issued by CN=Corp CA, until ${new Date(4102444800 * 1000).toLocaleDateString()}`);
    expect(contacts).toHaveTextContent("BOBB-BOBB-BOBB-BOBB");
    // Its PEM isn't shown as a key line, and an expired one that only signs says so.
    expect(contacts).not.toHaveTextContent("BEGIN CERTIFICATE");
    expect(contacts).toHaveTextContent("CN=Eve, self-signed, expired");
    expect(contacts).toHaveTextContent("archives can't be encrypted to it: it is an ECDSA certificate");
    await user.click(screen.getByRole("button", { name: "Copy Bob's certificate" }));
    await waitFor(() => expect(fake.calls.find((c) => c.name === "keys.export")?.args).toEqual({ name: "Bob" }));
    expect(await navigator.clipboard.readText()).toBe(pem);

    // "From a file" offers certificates, and the file is sent as it is.
    vi.mocked(open).mockResolvedValueOnce(String.raw`C:\keys\carol.crt`);
    await user.type(screen.getByLabelText("Add a key or certificate"), "Carol");
    await user.click(screen.getByRole("button", { name: /From a file/ }));
    const picker = vi.mocked(open).mock.calls[0][0];
    expect(picker?.filters?.[0].extensions).toEqual(expect.arrayContaining(["cer", "crt", "der", "pem"]));
    await user.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(fake.calls.find((c) => c.name === "keys.import")?.args).toEqual({ name: "Carol", file: String.raw`C:\keys\carol.crt` }));

    // A certificate contact is offered to encrypt to, unless it can't be.
    expect(encryptionKeys([...keys, bob, signsOnly]).map((k) => k.name)).toEqual(["Home", "Ann", "Bob"]);
    expect(contactCertificate({ ...bob, issuer: "CN=Bob" }, 0)).toBe(`CN=Bob, self-signed, until ${new Date(4102444800 * 1000).toLocaleDateString()}`);
  });

  it("says why the lists couldn't be read", async () => {
    fake.handlers.set("keys.list", () => {
      throw { code: "UnsupportedOperation", message: "keys.list is not built yet (docs/M14.md)" };
    });
    render(<KeysSettings />);
    expect(await screen.findByText(/Couldn't list your keys: keys.list is not built yet/)).toBeInTheDocument();
  });

  it("offers your signing keys and the certificates that may sign, and warns of odd ones", () => {
    expect(signers(keys, certificates)).toEqual([
      { id: "Signing", label: "Signing (your signing key)" },
      { id: "AB12", label: "CN=Me at work (certificate)" },
    ]);
    expect(certificateWarning(certificates[0])).toBeUndefined();
    expect(certificateWarning(certificates[1])).toMatch(/expired/);
    expect(certificateWarning({ ...certificates[0], trusted: false })).toMatch(/doesn't trust/);
    expect(certificateUse(certificates[1])).toBe("Can't be used; no private key here; not trusted by the system; expired");
    expect(sealedBy("windows")).toMatch(/sealed by Windows/);
    expect(sealedBy("macos")).toMatch(/Keychain/);
    expect(sealedBy("linux")).toMatch(/only you can read/);
  });
});
