import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { PasswordPrompt, Prompts } from "../features/prompts/Prompts";
import { UnlockPrompt } from "../features/protection/UnlockPrompt";
import type { JobEvent, UnlockWay } from "../gen/commands";
import { useArchives } from "../lib/archives";
import { keptSecret, useJobs } from "../lib/jobs";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));

const KEY = "000011-000022-000033-000044-000055-000066-000077-720885";

const ways: UnlockWay[] = [
  { slot: 0, kind: "password", here: false },
  { slot: 1, kind: "recovery-key", here: false },
  { slot: 2, kind: "ec-p256", here: true },
  { slot: 3, kind: "security-key", here: true },
  { slot: 4, kind: "rsa-certificate", here: false },
  { slot: 5, kind: "post-quantum-key", here: false },
];

const KEPT = "BeeZip keeps this archive unlocked until you close its tab, and never saves what you type.";

beforeEach(() => {
  fake.reset();
  useJobs.setState({ jobs: {}, order: [] });
  useArchives.setState({ tabs: [], active: undefined });
});

describe("the Unlock panel (docs/M14.md §8)", () => {
  it("replies with a password", async () => {
    const user = userEvent.setup();
    const onReply = vi.fn();
    render(<UnlockPrompt ways={ways} attempt={0} title="Opening a.bhive" onReply={onReply} />);
    expect(screen.getByText("Opening a.bhive: the archive is encrypted.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
    const input = screen.getByLabelText("Password");
    expect(input).toHaveAttribute("type", "password");
    await user.type(input, "hunter2");
    await user.click(screen.getByRole("button", { name: "Show password" }));
    expect(input).toHaveAttribute("type", "text");
    await user.click(input);
    await user.keyboard("{Enter}");
    expect(onReply).toHaveBeenCalledWith({ kind: "Unlock", answer: { way: "password", password: "hunter2" } });
  });

  it("takes a recovery key in groups, and finds a typo before trying it", async () => {
    const user = userEvent.setup();
    const onReply = vi.fn();
    render(<UnlockPrompt ways={ways} attempt={0} title="t" onReply={onReply} />);
    const input = screen.getByLabelText("Recovery key");
    await user.type(input, KEY.replace(/-/g, "").replace("000033", "000034"));
    expect(input).toHaveValue(KEY.replace("000033", "000034"));
    expect(screen.getByText("Group 3 (000034) has a typo.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unlock" })).toBeDisabled();
    await user.clear(input);
    await user.type(input, KEY.replace(/-/g, " "));
    expect(input).toHaveValue(KEY);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(onReply).toHaveBeenCalledWith({ kind: "Unlock", answer: { way: "recovery-key", key: KEY } });
  });

  it("offers a button for each key or device here, and lists the others", async () => {
    const user = userEvent.setup();
    const onReply = vi.fn();
    render(<UnlockPrompt ways={ways} attempt={0} title="t" onReply={onReply} />);
    await user.click(screen.getByRole("button", { name: /Use a security key or Windows Hello/ }));
    expect(onReply).toHaveBeenLastCalledWith({ kind: "Unlock", answer: { way: "slot", slot: 3 } });
    await user.click(screen.getByRole("button", { name: /Use This PC or your certificate/ }));
    expect(onReply).toHaveBeenLastCalledWith({ kind: "Unlock", answer: { way: "slot", slot: 2 } });
    const others = screen.getByRole("list", { name: "Other ways in" });
    expect(others).toHaveTextContent("RSA certificate: not on this machine");
    expect(others).toHaveTextContent("Post-quantum public key: not on this machine");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onReply).toHaveBeenLastCalledWith({ kind: "Cancel" });
  });

  it("says when a way in didn't open it, and shows only what the archive has", () => {
    render(<UnlockPrompt ways={[{ slot: 0, kind: "security-key", here: true }]} attempt={1} title="t" onReply={() => {}} kept={false} />);
    expect(screen.getByRole("alert")).toHaveTextContent("That didn't open it");
    expect(screen.queryByLabelText("Password")).toBeNull();
    expect(screen.queryByLabelText("Recovery key")).toBeNull();
    expect(screen.queryByRole("button", { name: "Unlock" })).toBeNull();
    expect(screen.getByText(/for this job only/)).toBeInTheDocument();
  });
});

describe("an Unlock prompt from a job", () => {
  it("shows the panel, and keeps what was typed for the tab", async () => {
    const user = userEvent.setup();
    const kept: [string, string][] = [];
    useJobs.setState({ onPassword: (tab, password) => kept.push([tab, password]) });
    let emit: (e: JobEvent) => void = () => {};
    fake.handlers.set("archive.list", (_args, e) => {
      emit = e;
      return new Promise(() => {});
    });
    render(<Prompts />);
    void useJobs.getState().track("archive.list", { archive: "a.bhive" }, { title: "Listing a.bhive", tab: "tab-1" });
    await waitFor(() => expect(fake.calls).toHaveLength(1));
    act(() => emit({ type: "Prompt", id: 7, prompt: { kind: "Unlock", ways, attempt: 0 } }));
    await user.type(screen.getByLabelText("Recovery key"), KEY);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    await waitFor(() => expect(fake.replies).toEqual([{ job: 1, prompt: 7, reply: { kind: "Unlock", answer: { way: "recovery-key", key: KEY } } }]));
    expect(kept).toEqual([["tab-1", KEY]]);
    expect(screen.queryByLabelText("Recovery key")).toBeNull();
  });

  it("keeps passwords and recovery keys, not a chosen device", () => {
    expect(keptSecret({ kind: "Password", password: "p" })).toBe("p");
    expect(keptSecret({ kind: "Unlock", answer: { way: "password", password: "q" } })).toBe("q");
    expect(keptSecret({ kind: "Unlock", answer: { way: "recovery-key", key: KEY } })).toBe(KEY);
    expect(keptSecret({ kind: "Unlock", answer: { way: "slot", slot: 2 } })).toBeUndefined();
    expect(keptSecret({ kind: "Cancel" })).toBeUndefined();
  });
});

describe("an archive kept unlocked for its tab (docs/M14.md §8)", () => {
  it("says so, whichever way in opens it, and a job window says it doesn't", () => {
    const { unmount } = render(<UnlockPrompt ways={ways} attempt={0} title="t" onReply={() => {}} />);
    expect(screen.getByText(KEPT)).toBeInTheDocument();
    unmount();
    // A device alone: nothing is typed, and the archive still stays unlocked.
    const devices = render(<UnlockPrompt ways={[{ slot: 0, kind: "security-key", here: true }]} attempt={0} title="t" onReply={() => {}} />);
    expect(screen.getByText(KEPT)).toBeInTheDocument();
    devices.unmount();
    const password = render(<PasswordPrompt entry={null} title="t" onReply={() => {}} />);
    expect(screen.getByText(KEPT)).toBeInTheDocument();
    password.unmount();
    render(<PasswordPrompt entry={null} title="t" onReply={() => {}} kept={false} />);
    expect(screen.queryByText(KEPT)).toBeNull();
    expect(screen.getByText(/for this job only/)).toBeInTheDocument();
  });

  it("locks the archive again when its tab closes", async () => {
    const a = String.raw`C:\work\a.bhive`;
    const b = String.raw`C:\work\b.bhive`;
    const ta = useArchives.getState().open(a);
    const tb = useArchives.getState().open(b);
    // The same file again is the same tab.
    expect(useArchives.getState().open("c:/work/A.bhive")).toBe(ta);
    useArchives.getState().close(ta);
    await waitFor(() => expect(fake.locked).toEqual([a]));
    expect(useArchives.getState().tabs.map((t) => t.id)).toEqual([tb]);
    // A tab that isn't there locks nothing.
    useArchives.getState().close(ta);
    useArchives.getState().close("tab-none");
    useArchives.getState().close(tb);
    await waitFor(() => expect(fake.locked).toEqual([a, b]));
    expect(useArchives.getState().tabs).toEqual([]);
  });
});
