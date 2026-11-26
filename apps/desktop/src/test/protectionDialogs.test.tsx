import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CreateDialog } from "../features/create/CreateDialog";
import { AddDialog, addArgs, initialAdd } from "../features/edit/AddDialog";
import { ExtractDialog } from "../features/extract/ExtractDialog";
import { printSheet, RecoveryKeyDialog, recoveryText, useRecoveryKeys } from "../features/protection/RecoveryKey";
import type { ArchiveInfoOutput, CertificateInfo, FormatsListOutput, KeyInfo } from "../gen/commands";
import { type Tab, useArchives } from "../lib/archives";
import { useKeyring } from "../lib/keyring";
import type { Signature } from "../lib/signatures";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(async () => null), save: vi.fn(), ask: vi.fn(async () => true) }));
const invoke = vi.hoisted(() => vi.fn(async (..._args: unknown[]) => null as unknown));
vi.mock("@tauri-apps/api/core", () => ({ invoke, Channel: class {} }));

const caps = { list: true, extract: true, create: true, append: true, delete: true, rename: true, encrypt: true, encrypt_headers: true, solid: false, volumes: false, random_access: true };
const formats: FormatsListOutput = {
  formats: [
    { id: "bhive", name: "BeeZip", extensions: [".bhive"], caps, methods: [], encryption: [], menu: true, levels: { min: 0, max: 4, default: 2 }, level_names: ["none", "fast", "balanced", "high", "max"] },
    { id: "zip", name: "Zip", extensions: [".zip"], caps, methods: [{ id: "deflate", levels: { min: 1, max: 9, default: 6 } }], encryption: ["aes256", "zipcrypto"], menu: true, levels: null, level_names: [] },
    { id: "7z", name: "7z", extensions: [".7z"], caps, methods: [{ id: "lzma2", levels: { min: 0, max: 9, default: 5 } }], encryption: ["aes256"], menu: true, levels: null, level_names: [] },
  ],
  codecs: [],
  create: ["zip", "bhive", "7z"],
};

const PQ = `age1pq1${"q".repeat(60)}`;
const keys: KeyInfo[] = [
  { name: "Ann", kind: "post-quantum", public: `${PQ}ann`, fingerprint: "AAAA-BBBB-CCCC-DDDD", own: false, created: 0 },
  { name: "Mine", kind: "signing", public: "bzsig1mine", fingerprint: "SIGN-SIGN-SIGN-SIGN", own: true, created: 0 },
];
const certificates: CertificateInfo[] = [
  { thumbprint: "AB12", subject: "CN=Bob", issuer: "CN=Corp CA", not_after: 4102444800, algorithm: "rsa-2048", store: "other-people", can_encrypt: true, can_sign: false, trusted: true },
  { thumbprint: "CD34", subject: "CN=Carol", issuer: "CN=Corp CA", not_after: 4102444800, algorithm: "ec-p256", store: "other-people", can_encrypt: false, can_sign: true, refused: "an ECDSA-only key can't agree keys", trusted: true },
  { thumbprint: "EF56", subject: "CN=Me at work", issuer: "CN=Corp CA", not_after: 4102444800, algorithm: "rsa-2048", store: "personal", key: "software", can_encrypt: true, can_sign: true, trusted: true },
];

const KEY = "000011-000022-000033-000044-000055-000066-000077-720885";

function info(patch: Partial<ArchiveInfoOutput> & { signatures?: Signature[] } = {}): ArchiveInfoOutput {
  return {
    archive: String.raw`C:\work\a.bhive`,
    format: "bhive",
    chain: "bhive",
    codecs: [],
    entries: 1,
    files: 1,
    dirs: 0,
    links: 0,
    size: 10,
    packed_size: 5,
    ratio: 0.5,
    methods: [],
    encryption: "none",
    solid: false,
    sfx: false,
    comment: null,
    volumes: [],
    solid_blocks: null,
    encrypted_headers: false,
    locked: false,
    recovery_record: false,
    not_editable: null,
    levels: [],
    properties: [{ level: "bhive", name: "Level", value: "balanced" }],
    notes: [],
    ...patch,
  } as ArchiveInfoOutput;
}

const tab = (patch: Partial<Tab> = {}): Tab => ({ id: "tab-1", path: String.raw`C:\work\a.bhive`, name: "a.bhive", dir: "", reverse: false, selected: [], all: false, solidOk: false, version: 0, info: info(), ...patch });

const mine: Signature = { algorithm: "ml-dsa65-ed25519", status: "valid", trust: "yours", signer: "Mine", fingerprint: "SIGN-SIGN-SIGN-SIGN", post_quantum: true };

beforeEach(() => {
  fake.reset();
  invoke.mockReset();
  fake.handlers.set("formats.list", () => formats);
  fake.handlers.set("settings.get", () => ({ settings: { levels: {}, edit: { overwrite: "ask" }, extract: { overwrite: "ask", links: true } } }));
  fake.handlers.set("keys.list", () => ({ keys }));
  fake.handlers.set("certificates.list", () => ({ certificates }));
  useKeyring.setState({ keys: undefined, certificates: undefined, keysError: undefined, certificatesError: undefined, loading: false });
  useRecoveryKeys.setState({ queue: [] });
});

describe("the create dialog's Protection section (docs/M14.md §8)", () => {
  it("rates the password, suggests one, and sends every way in", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.create", (args) => ({ path: (args as { output: string }).output, format: "bhive", recovery_key: KEY }));
    render(
      <>
        <CreateDialog inputs={[String.raw`C:\work\src`]} onClose={() => {}} />
        <RecoveryKeyDialog />
      </>,
    );
    await waitFor(() => expect(screen.getByRole("option", { name: "bhive" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Format"), "bhive");

    const password = screen.getByLabelText("Password");
    await user.type(password, "summer2026");
    expect(screen.getByRole("status")).toHaveTextContent(/very weak/);
    await waitFor(() => expect(screen.getByRole("button", { name: /Suggest one/ })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: /Suggest one/ }));
    const suggested = (password as HTMLInputElement).value;
    expect(suggested.split("-")).toHaveLength(6);
    expect(password).toHaveAttribute("type", "text");
    expect(screen.getByRole("status")).toHaveTextContent(/strong\./);
    await user.selectOptions(screen.getByLabelText("Guessing cost"), "strong");

    await user.click(screen.getByText(/Make a recovery key/));
    // A contact, a pasted key, a certificate; a certificate that can't encrypt says why.
    await waitFor(() => expect(screen.getByLabelText("Add a contact")).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Add a contact"), "Ann");
    await user.type(screen.getByLabelText("Public key or contact"), "AGE-SECRET-KEY-1ABC");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/That's a private key/);
    await user.clear(screen.getByLabelText("Public key or contact"));
    await user.type(screen.getByLabelText("Public key or contact"), "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p{Enter}");
    expect(screen.getByRole("option", { name: /CN=Carol: an ECDSA-only key/ })).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Add a certificate"), "AB12");
    expect(within(screen.getByRole("list", { name: "Encrypted to" })).getAllByRole("listitem")).toHaveLength(3);
    expect(screen.getByText(/could also make an archive your password opens/)).toBeInTheDocument();
    expect(screen.getByText(/Doesn't resist quantum computers: age1ql3z7hjy54pw…aqmcac8p and CN=Bob use classic keys/)).toBeInTheDocument();

    await user.click(screen.getByText(/Let this PC open it/));
    await user.type(screen.getByLabelText("PIN for This PC"), "2468");
    await user.click(screen.getByText(/Let a security key/));
    await user.selectOptions(screen.getByLabelText("Sign with"), "Mine");

    await user.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.create")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.create")?.args).toEqual({
      output: String.raw`C:\work\src.bhive`,
      inputs: [String.raw`C:\work\src`],
      format: "bhive",
      password: suggested,
      recovery_key: true,
      to: ["Ann", "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
      to_cert: ["AB12"],
      this_pc: true,
      this_pc_pin: "2468",
      security_key: true,
      strength: "strong",
      sign: ["Mine"],
    });
    // The recovery key the create made, shown once.
    expect(await screen.findByTestId("recovery-key")).toHaveTextContent(KEY);
  });

  it("won't make an archive only this PC opens (decision 11)", async () => {
    const user = userEvent.setup();
    render(<CreateDialog inputs={[String.raw`C:\work\src`]} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole("option", { name: "bhive" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Format"), "bhive");
    await user.click(screen.getByText(/Let this PC open it/));
    expect(screen.getByRole("alert")).toHaveTextContent(/only on this computer/);
    expect(screen.getByRole("button", { name: "Create" })).toBeDisabled();
    await user.click(screen.getByText(/Make a recovery key/));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Create" })).toBeEnabled();
  });

  it("points from zip's and 7z's encryption to .bhive (decision 1)", async () => {
    const user = userEvent.setup();
    render(<CreateDialog inputs={[String.raw`C:\work\src`]} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole("option", { name: "bhive" })).toBeInTheDocument());
    expect(screen.queryByText(/A .bhive hides everything/)).toBeNull();
    await user.type(screen.getByLabelText("Password"), "pw");
    expect(screen.getByRole("note")).toHaveTextContent(/Zip's encryption leaves names, sizes and dates readable/);
    await user.selectOptions(screen.getByLabelText("Format"), "7z");
    expect(screen.getByRole("note")).toHaveTextContent(/7z's encryption doesn't notice changed bytes/);
    await user.click(screen.getByRole("button", { name: /Use .bhive/ }));
    expect(screen.getByLabelText("Format")).toHaveValue("bhive");
    expect(screen.getByLabelText("Save as")).toHaveValue(String.raw`C:\work\src.bhive`);
    expect(screen.getByLabelText("Password")).toHaveValue("pw");
  });

  it("converts into an encrypted .bhive with `new_password` and shows its recovery key", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.convert", (args) => ({ path: (args as { output: string }).output, format: "bhive", recovery_key: KEY }));
    const source = tab({ path: String.raw`C:\work\a.zip`, name: "a.zip", info: info({ format: "zip", chain: "zip", encryption: "all" }), password: "old" });
    render(
      <>
        <CreateDialog inputs={[]} source={source} onClose={() => {}} />
        <RecoveryKeyDialog />
      </>,
    );
    await waitFor(() => expect(screen.getByRole("option", { name: "bhive" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Format"), "bhive");
    await user.clear(screen.getByLabelText("Password"));
    // An encrypted source needs a way in, or the person's word.
    expect(screen.getByRole("button", { name: "Convert" })).toBeDisabled();
    expect(screen.getByText(/Or give the new archive a way in above/)).toBeInTheDocument();
    await user.click(screen.getByText(/Make a recovery key/));
    expect(screen.getByRole("button", { name: "Convert" })).toBeEnabled();
    await user.type(screen.getByLabelText("Password"), "new one");
    await user.click(screen.getByRole("button", { name: "Convert" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.convert")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.convert")?.args).toMatchObject({ archive: source.path, format: "bhive", new_password: "new one", recovery_key: true });
    expect(await screen.findByTestId("recovery-key")).toHaveTextContent(KEY);
  });
});

describe("the recovery key, shown once", () => {
  it("copies, saves and prints, and closes once it was kept", async () => {
    const user = userEvent.setup();
    const print = vi.spyOn(window, "print").mockImplementation(() => {
      // While it prints, the sheet with the key is the only thing on paper.
      expect(document.documentElement).toHaveClass("printing");
      expect(document.querySelector(".print-sheet")).toHaveTextContent(KEY);
      window.dispatchEvent(new Event("afterprint"));
    });
    render(<RecoveryKeyDialog />);
    act(() => useRecoveryKeys.getState().show(String.raw`C:\work\a.bhive`, KEY));
    expect(screen.getByText(/BeeZip shows it this once/)).toBeInTheDocument();
    const done = screen.getByRole("button", { name: "Done" });
    expect(done).toBeDisabled();

    await user.click(screen.getByRole("button", { name: /Copy/ }));
    expect(await navigator.clipboard.readText()).toBe(KEY);
    expect(screen.getByRole("status")).toHaveTextContent(/Copied/);
    expect(done).toBeEnabled();

    invoke.mockResolvedValueOnce(String.raw`D:\safe\a recovery key.txt`);
    await user.click(screen.getByRole("button", { name: /Save/ }));
    expect(invoke).toHaveBeenCalledWith("cmd_save_text", { name: "a recovery key.txt", text: recoveryText(String.raw`C:\work\a.bhive`, KEY) });
    expect(await screen.findByText(/Saved to D:\\safe\\a recovery key.txt/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Print/ }));
    expect(print).toHaveBeenCalledOnce();
    expect(document.documentElement).not.toHaveClass("printing");
    expect(document.querySelector(".print-sheet")).toBeNull();

    await user.click(done);
    expect(screen.queryByTestId("recovery-key")).toBeNull();
    print.mockRestore();
  });

  it("closes after \"I've written it down\", and shows the next one", async () => {
    const user = userEvent.setup();
    render(<RecoveryKeyDialog />);
    act(() => {
      useRecoveryKeys.getState().show("a.bhive", KEY);
      useRecoveryKeys.getState().show("b.bhive", "111111");
    });
    await user.click(screen.getByText("I've written it down"));
    await user.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.getByTestId("recovery-key")).toHaveTextContent("111111");
    expect(screen.getByRole("button", { name: "Done" })).toBeDisabled();
  });

  it("prints a sheet left by an earlier print only once", () => {
    const print = vi.spyOn(window, "print").mockImplementation(() => {});
    printSheet("one", ["1"]);
    printSheet("two", ["2"]);
    expect(document.querySelectorAll(".print-sheet")).toHaveLength(1);
    window.dispatchEvent(new Event("afterprint"));
    expect(document.querySelectorAll(".print-sheet")).toHaveLength(0);
    print.mockRestore();
  });
});

describe("adding to a signed .bhive (docs/M14.md §11)", () => {
  it("says the signatures drop, and signs again with your own key", async () => {
    const t = tab({ info: info({ signatures: [mine, { ...mine, trust: "contact", signer: "Ann" }] }) });
    expect(initialAdd(t, ["x"], "").sign).toEqual(["Mine"]);
    expect(addArgs(t, initialAdd(t, [String.raw`C:\x`], ""), formats)).toMatchObject({ sign: ["Mine"] });
    expect(addArgs(t, { ...initialAdd(t, [String.raw`C:\x`], ""), sign: [] }, formats)).not.toHaveProperty("sign");
    // Not a .bhive: no signing.
    const zip = tab({ path: "a.zip", info: info({ format: "zip", chain: "zip" }) });
    expect(addArgs(zip, { ...initialAdd(zip, ["x"], ""), sign: ["Mine"] }, formats)).not.toHaveProperty("sign");

    render(<AddDialog tab={t} inputs={[String.raw`C:\x`]} dir="" onClose={() => {}} />);
    expect(await screen.findByText(/its 2 signatures are dropped/)).toBeInTheDocument();
    await waitFor(() => expect(within(screen.getByRole("list", { name: "Signed with" })).getByText("Mine (your signing key)")).toBeInTheDocument());
  });
});

describe("adding to an encrypted .bhive (docs/M14.md §3)", () => {
  it("opens it with the way in kept for its tab, and never sends `unencrypted`", async () => {
    const t = tab({ info: info({ encryption: "all" }), password: "honey", encoding: "cp866" });
    useArchives.setState({ tabs: [t], active: t.id });
    const form = initialAdd(t, [String.raw`C:\x.txt`], "");
    expect(addArgs(t, form, formats)).toEqual({ archive: t.path, inputs: [String.raw`C:\x.txt`], password: "honey", name_encoding: "cp866" });
    // Unlocked with a recovery key: that's what goes.
    useArchives.getState().update(t.id, { password: KEY });
    expect(addArgs(t, form, formats)).toMatchObject({ password: KEY });
    expect(addArgs(t, form, formats)).not.toHaveProperty("unencrypted");
    // Nothing kept yet: the add asks for a way in itself.
    useArchives.getState().update(t.id, { password: undefined });
    expect(addArgs(t, form, formats)).toEqual({ archive: t.path, inputs: [String.raw`C:\x.txt`], name_encoding: "cp866" });

    render(<AddDialog tab={t} inputs={[String.raw`C:\x.txt`]} dir="" onClose={() => {}} />);
    expect(await screen.findByText(/The new files are encrypted like the rest/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).toBeNull();
  });
});

describe("converting an encrypted archive into a .bhive (docs/M14.md §8)", () => {
  it("sends `decrypt` only while the new archive has no way in", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.convert", (args) => ({ path: (args as { output: string }).output, format: "bhive", recovery_key: KEY }));
    const source = tab({ path: String.raw`C:\work\a.zip`, name: "a.zip", info: info({ format: "zip", chain: "zip", encryption: "all" }), password: "old" });
    render(<CreateDialog inputs={[]} source={source} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByRole("option", { name: "bhive" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Format"), "bhive");
    await user.clear(screen.getByLabelText("Password"));
    await user.click(screen.getByText(/encrypted entries without a password/));
    // A way in after all: the checkbox goes, and so does `decrypt`.
    await user.click(screen.getByText(/Make a recovery key/));
    expect(screen.queryByText(/encrypted entries without a password/)).toBeNull();
    await user.click(screen.getByRole("button", { name: "Convert" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.convert")).toBe(true));
    const args = fake.calls.find((c) => c.name === "archive.convert")?.args;
    expect(args).toMatchObject({ archive: source.path, format: "bhive", recovery_key: true });
    expect(args).not.toHaveProperty("decrypt");
  });
});

describe("extracting an archive that changed after it was signed (decision 26)", () => {
  it("asks first", async () => {
    const user = userEvent.setup();
    const t = tab({ info: info({ signatures: [{ ...mine, status: "changed", trust: undefined }] }) });
    render(<ExtractDialog tab={t} entries={[]} onClose={() => {}} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/changed after it was signed/);
    const extract = screen.getByRole("button", { name: "Extract" });
    expect(extract).toBeDisabled();
    await user.click(screen.getByText("Extract it anyway"));
    expect(extract).toBeEnabled();
  });

  it("doesn't ask when the signatures check", () => {
    render(<ExtractDialog tab={tab({ info: info({ signatures: [mine] }) })} entries={[]} onClose={() => {}} />);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Extract" })).toBeEnabled();
  });
});
