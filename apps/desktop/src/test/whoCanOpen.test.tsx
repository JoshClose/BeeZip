import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ask } from "@tauri-apps/plugin-dialog";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RecoveryKeyDialog, useRecoveryKeys } from "../features/protection/RecoveryKey";
import { contactFor, leavesPortable, recipientWays, WhoCanOpenDialog, wayTitle } from "../features/protection/WhoCanOpen";
import type { ArchiveInfoOutput, KeyInfo, WayIn } from "../gen/commands";
import { type Tab, useArchives } from "../lib/archives";
import { useKeyring } from "../lib/keyring";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(async () => null), save: vi.fn(), ask: vi.fn(async () => true) }));

const ANN = `age1pq1${"a".repeat(60)}`;
const STRANGER = `age1pq1${"s".repeat(60)}`;
const ways: WayIn[] = [
  { slot: 0, kind: "password", label: "Password", machine_bound: false, post_quantum: true },
  { slot: 1, kind: "post-quantum-key", label: "Ann", recipient: ANN, machine_bound: false, post_quantum: true },
  { slot: 2, kind: "post-quantum-key", label: "Ann's laptop", recipient: STRANGER, machine_bound: false, post_quantum: true },
  { slot: 3, kind: "rsa-certificate", recipient: "CN=Bob", machine_bound: false, post_quantum: false },
  { slot: 4, kind: "ec-p256", label: "This PC", machine_bound: true, post_quantum: false },
];
const keys: KeyInfo[] = [{ name: "Ann", kind: "post-quantum", public: ANN, fingerprint: "ANNN-ANNN-ANNN-ANNN", own: false, created: 0 }];

const tab: Tab = {
  id: "tab-1",
  path: String.raw`C:\work\a.bhive`,
  name: "a.bhive",
  dir: "",
  reverse: false,
  selected: [],
  all: false,
  solidOk: false,
  version: 0,
  password: "pw",
  info: { format: "bhive", encryption: "all" } as ArchiveInfoOutput,
};

beforeEach(() => {
  fake.reset();
  fake.handlers.set("keys.list", () => ({ keys }));
  fake.handlers.set("certificates.list", () => ({ certificates: [] }));
  fake.handlers.set("archive.protection", () => ({ encrypted: true, ways, post_quantum: false }));
  useKeyring.setState({ keys: undefined, certificates: undefined, keysError: undefined, certificatesError: undefined, loading: false });
  useArchives.setState({ tabs: [tab], active: tab.id });
  useRecoveryKeys.setState({ queue: [] });
});

describe("who can open an encrypted .bhive (docs/M14.md §3, §8)", () => {
  it("knows recipients, contacts and the last portable way in", () => {
    expect(wayTitle(ways[0])).toBe("Password");
    expect(wayTitle(ways[1])).toBe("Post-quantum public key: Ann");
    expect(wayTitle(ways[3])).toBe("RSA certificate");
    expect(recipientWays(ways).map((w) => w.slot)).toEqual([1, 2, 3]);
    expect(contactFor(ways[1], keys)?.name).toBe("Ann");
    expect(contactFor(ways[2], keys)).toBeUndefined();
    expect(leavesPortable(ways, [0, 1, 2])).toBe(true);
    expect(leavesPortable(ways, [0, 1, 2, 3])).toBe(false);
  });

  it("lists the ways in, with the archive's password, and removes one", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.protect", () => ({ ways: ways.filter((w) => w.slot !== 3), post_quantum: false }));
    render(<WhoCanOpenDialog tab={tab} onClose={() => {}} />);
    const list = await screen.findByRole("list", { name: "Ways in" });
    expect(fake.calls.find((c) => c.name === "archive.protection")?.args).toEqual({ archive: tab.path, password: "pw" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(5);
    expect(list).toHaveTextContent("Post-quantum public key: Ann (contact Ann)");
    expect(list).toHaveTextContent("Only on this PC.");
    expect(screen.getByText(/Doesn't resist quantum computers/)).toBeInTheDocument();
    expect(screen.getByText(/Removing a way in isn't taking it back/)).toBeInTheDocument();
    // It asks first.
    vi.mocked(ask).mockResolvedValueOnce(false);
    await user.click(screen.getByRole("button", { name: "Remove RSA certificate" }));
    expect(ask).toHaveBeenCalledWith(expect.stringMatching(/^Remove RSA certificate from a\.bhive\?/), expect.anything());
    expect(fake.calls.some((c) => c.name === "archive.protect")).toBe(false);
    await user.click(screen.getByRole("button", { name: "Remove RSA certificate" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.protect")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.protect")?.args).toEqual({ archive: tab.path, remove: [3], password: "pw" });
    await waitFor(() => expect(within(screen.getByRole("list", { name: "Ways in" })).getAllByRole("listitem")).toHaveLength(4));
  });

  it("keeps the last way in that works elsewhere", async () => {
    fake.handlers.set("archive.protection", () => ({ encrypted: true, ways: [ways[0], ways[4]], post_quantum: false }));
    render(<WhoCanOpenDialog tab={tab} onClose={() => {}} />);
    expect(await screen.findByRole("button", { name: "Remove Password" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove This PC" })).toBeEnabled();
  });

  it("adds a password and a recovery key, and shows the new key once", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.protect", () => ({ ways, post_quantum: false, recovery_key: "000011" }));
    render(
      <>
        <WhoCanOpenDialog tab={tab} onClose={() => {}} />
        <RecoveryKeyDialog />
      </>,
    );
    await user.click(await screen.findByRole("button", { name: /Add a way in/ }));
    const add = screen.getByRole("button", { name: "Add to the archive" });
    expect(add).toBeDisabled();
    await user.type(screen.getByLabelText("Add a password"), "a second password");
    await user.click(screen.getByText(/Make a recovery key/));
    await user.click(add);
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.protect")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.protect")?.args).toEqual({ archive: tab.path, add_password: "a second password", recovery_key: true, password: "pw" });
    expect(await screen.findByTestId("recovery-key")).toHaveTextContent("000011");
  });

  it("makes a new key, rebuilding only the recipients confirmed (docs/bhive.md §12.9)", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.protect", () => ({ ways, post_quantum: false }));
    render(<WhoCanOpenDialog tab={tab} onClose={() => {}} />);
    await user.click(await screen.findByRole("button", { name: /New key/ }));
    const confirm = await screen.findByRole("dialog", { name: "Make a new key" });
    const recipients = within(confirm).getByRole("list", { name: "Recipients" });
    // Each recipient's key or certificate is shown; a contact's comes ticked, with its fingerprint.
    expect(within(recipients).getAllByRole("listitem")).toHaveLength(3);
    expect(recipients).toHaveTextContent("ANNN-ANNN-ANNN-ANNN");
    expect(recipients).toHaveTextContent(STRANGER);
    expect(within(confirm).getByRole("checkbox", { name: /Ann, your contact Ann/ })).toBeChecked();
    expect(within(confirm).getByRole("checkbox", { name: /Ann's laptop/ })).not.toBeChecked();
    expect(confirm).toHaveTextContent("This PC may ask for its PIN.");
    // The old password can't be read back: it is typed again for the one new password slot.
    expect(confirm).toHaveTextContent(/Type its password again, or a new one/);
    await user.type(within(confirm).getByLabelText("Password"), "the new one");
    // A recipient that isn't a contact is rebuilt only when confirmed.
    await user.click(within(confirm).getByRole("checkbox", { name: "RSA certificate" }));
    await user.click(within(confirm).getByRole("button", { name: /Make a new key/ }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.protect")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.protect")?.args).toEqual({ archive: tab.path, new_key: true, add_password: "the new one", confirm: [3], remove: [2], password: "pw" });
    // The tab keeps the new password, since the old one no longer opens it.
    await waitFor(() => expect(useArchives.getState().tabs[0].password).toBe("the new one"));
  });

  it("removes the password with a new key when none is typed", async () => {
    const user = userEvent.setup();
    fake.handlers.set("archive.protect", () => ({ ways: ways.slice(1), post_quantum: false }));
    render(<WhoCanOpenDialog tab={tab} onClose={() => {}} />);
    await user.click(await screen.findByRole("button", { name: /New key/ }));
    const confirm = await screen.findByRole("dialog", { name: "Make a new key" });
    await user.click(within(confirm).getByRole("button", { name: /Make a new key/ }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.protect")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.protect")?.args).toEqual({ archive: tab.path, new_key: true, remove: [0, 2, 3], password: "pw" });
    await waitFor(() => expect(useArchives.getState().tabs[0].password).toBeUndefined());
  });

  it("names This PC and Windows Hello by where they work", () => {
    expect(wayTitle({ slot: 5, kind: "security-key", machine_bound: true, post_quantum: true })).toBe("Windows Hello");
    expect(wayTitle({ slot: 6, kind: "security-key", machine_bound: false, post_quantum: true })).toBe("Security key");
    expect(wayTitle(ways[4])).toBe("This PC");
    expect(wayTitle({ slot: 7, kind: "ec-p256", recipient: "CN=Bob", machine_bound: false, post_quantum: false })).toBe("EC certificate (P-256)");
  });

  it("passes only the way in, not a name encoding, and reads once though the tab changes", async () => {
    const user = userEvent.setup();
    const t = { ...tab, encoding: "cp866" as const };
    useArchives.setState({ tabs: [t], active: t.id });
    fake.handlers.set("archive.protect", () => ({ ways, post_quantum: false }));
    const { rerender } = render(<WhoCanOpenDialog tab={t} onClose={() => {}} />);
    await screen.findByRole("list", { name: "Ways in" });
    expect(fake.calls.find((c) => c.name === "archive.protection")?.args).toEqual({ archive: t.path, password: "pw" });
    // A way in typed into the read's own prompt is kept on the tab: a new tab object.
    useArchives.getState().update(t.id, { password: "typed" });
    rerender(<WhoCanOpenDialog tab={useArchives.getState().tabs[0]} onClose={() => {}} />);
    expect(fake.calls.filter((c) => c.name === "archive.protection")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Remove RSA certificate" }));
    await waitFor(() => expect(fake.calls.some((c) => c.name === "archive.protect")).toBe(true));
    expect(fake.calls.find((c) => c.name === "archive.protect")?.args).toEqual({ archive: t.path, remove: [3], password: "typed" });
  });

  it("warns when a password joins someone else's key (decision 12)", async () => {
    const user = userEvent.setup();
    render(<WhoCanOpenDialog tab={tab} onClose={() => {}} />);
    await user.click(await screen.findByRole("button", { name: /Add a way in/ }));
    await user.type(screen.getByLabelText("Add a password"), "another one");
    expect(await screen.findByText(/could also make an archive your password opens/)).toBeInTheDocument();
  });

  it("shows a way in's fingerprint when the engine gives one, and says when a certificate has none", async () => {
    const user = userEvent.setup();
    const withPrint = [...ways.slice(0, 2), { ...ways[2], fingerprint: "SSSS-TTTT-RRRR-AAAA" } as WayIn, ways[3], ways[4]];
    fake.handlers.set("archive.protection", () => ({ encrypted: true, ways: withPrint, post_quantum: false }));
    render(<WhoCanOpenDialog tab={tab} onClose={() => {}} />);
    expect(await screen.findByRole("list", { name: "Ways in" })).toHaveTextContent("SSSS-TTTT-RRRR-AAAA");
    await user.click(screen.getByRole("button", { name: /New key/ }));
    const confirm = await screen.findByRole("dialog", { name: "Make a new key" });
    expect(confirm).toHaveTextContent("SSSS-TTTT-RRRR-AAAA");
    expect(within(confirm).getAllByText(/Only the certificate's subject is known here/)).toHaveLength(1);
    // Matched by its fingerprint, a contact's way in comes ticked.
    expect(contactFor(withPrint[2], [{ ...keys[0], name: "Sam", public: "age1other", fingerprint: "SSSS-TTTT-RRRR-AAAA" }])?.name).toBe("Sam");
  });

  it("takes the ways in from archive.info when it has them, and keeps them there after a change", async () => {
    const user = userEvent.setup();
    const t: Tab = { ...tab, info: { ...tab.info, protection: { encrypted: true, ways, post_quantum: false } } as ArchiveInfoOutput };
    useArchives.setState({ tabs: [t], active: t.id });
    fake.handlers.set("archive.protect", () => ({ ways: ways.filter((w) => w.slot !== 3), post_quantum: false }));
    render(<WhoCanOpenDialog tab={t} onClose={() => {}} />);
    expect(screen.getByRole("list", { name: "Ways in" })).toHaveTextContent("RSA certificate");
    expect(fake.calls.some((c) => c.name === "archive.protection")).toBe(false);
    await user.click(screen.getByRole("button", { name: "Remove RSA certificate" }));
    await waitFor(() => expect(useArchives.getState().tabs[0].info?.protection?.ways).toHaveLength(4));
  });

  it("says why it can't read the ways in", async () => {
    fake.handlers.set("archive.protection", () => {
      throw { code: "UnsupportedOperation", message: "archive.protection is not built yet (docs/M14.md)" };
    });
    render(<WhoCanOpenDialog tab={tab} onClose={() => {}} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("not built yet");
    expect(screen.getByRole("button", { name: /Add a way in/ })).toBeDisabled();
  });
});
