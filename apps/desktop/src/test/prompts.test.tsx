import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { OverwritePrompt, PasswordPrompt } from "../features/prompts/Prompts";

describe("the overwrite prompt", () => {
  it.each([
    ["Replace", { kind: "Overwrite", choice: "Replace" }],
    ["Replace all", { kind: "Overwrite", choice: "ReplaceAll" }],
    ["Skip", { kind: "Overwrite", choice: "Skip" }],
    ["Skip all", { kind: "Overwrite", choice: "SkipAll" }],
    ["Keep both", { kind: "Overwrite", choice: "Rename" }],
    ["Cancel", { kind: "Cancel" }],
  ])("%s replies %j", async (label, reply) => {
    const onReply = vi.fn();
    render(<OverwritePrompt path={String.raw`C:\out\a.txt`} title="Extracting a.7z" onReply={onReply} />);
    expect(screen.getByText(String.raw`C:\out\a.txt`)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: label }));
    expect(onReply).toHaveBeenCalledWith(reply);
  });

  it("names the archive when the path is an entry in it (docs/M5.md §7.1)", () => {
    render(<OverwritePrompt path="docs/a.txt" archive={String.raw`C:\work\a.zip`} title="Adding to a.zip" onReply={() => {}} />);
    expect(screen.getByRole("heading", { name: "a.txt is already in a.zip" })).toBeInTheDocument();
    expect(screen.getByText(/adds it under a new name/)).toBeInTheDocument();
  });

  it("treats Escape as Cancel", async () => {
    const onReply = vi.fn();
    render(<OverwritePrompt path="x" title="t" onReply={onReply} />);
    await userEvent.setup().keyboard("{Escape}");
    expect(onReply).toHaveBeenCalledWith({ kind: "Cancel" });
  });
});

describe("the password prompt", () => {
  it("names the entry, shows the password on request, and replies with it", async () => {
    const user = userEvent.setup();
    const onReply = vi.fn();
    render(<PasswordPrompt entry="docs/secret.txt" title="Reading a.7z" onReply={onReply} />);
    expect(screen.getByText(/“secret.txt” is encrypted/)).toBeInTheDocument();
    const input = screen.getByLabelText("Password");
    expect(input).toHaveAttribute("type", "password");
    await user.type(input, "hunter2");
    await user.click(screen.getByRole("button", { name: "Show password" }));
    expect(input).toHaveAttribute("type", "text");
    await user.click(input);
    await user.keyboard("{Enter}");
    expect(onReply).toHaveBeenCalledWith({ kind: "Password", password: "hunter2" });
  });
});
