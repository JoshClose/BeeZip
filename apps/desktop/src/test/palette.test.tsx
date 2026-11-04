import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Palette, paletteFilter, resetCommands, takesOnlyArchive } from "../features/palette/Palette";
import type { GuiCommand } from "../lib/engine";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));

const command = (name: string, description: string, props: string[]): GuiCommand => ({
  name,
  description,
  effect: "ReadOnly",
  surfaces: { cli: true, gui: true, mcp: true },
  cli: null,
  input_schema: { type: "object", properties: Object.fromEntries(props.map((p) => [p, { type: "string" }])) },
});

describe("the palette", () => {
  beforeEach(() => {
    fake.reset();
    resetCommands();
    fake.commands = [
      command("archive.test", "Test an archive's integrity.", ["archive", "password"]),
      command("stream.compress", "Compress one file with a single-stream codec.", ["input", "codec"]),
      command("formats.list", "List the archive formats and codecs.", []),
    ];
  });

  it("lists the app's actions and every command", async () => {
    const run = vi.fn();
    const onCommand = vi.fn();
    render(
      <Palette open onOpenChange={() => {}} actions={[{ id: "open", label: "Open archive…", hint: "Ctrl+O", run }]} onCommand={onCommand} />,
    );
    expect(screen.getByText("Open archive…")).toBeInTheDocument();
    expect(await screen.findByText("stream.compress")).toBeInTheDocument();
    expect(screen.getByText("archive.test")).toBeInTheDocument();
    expect(screen.getByText("formats.list")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/type a command/i), "compress");
    expect(screen.queryByText("archive.test")).toBeNull();
    await user.click(screen.getByText("stream.compress"));
    expect(onCommand).toHaveBeenCalledWith(expect.objectContaining({ name: "stream.compress" }));
  });

  it("matches every typed word, as a substring", () => {
    expect(paletteFilter("archive.test Test an archive", "test")).toBe(0.5);
    expect(paletteFilter("archive.test Test an archive", "archive test")).toBe(1);
    expect(paletteFilter("formats.list List the formats", "test")).toBe(0);
  });

  it("runs archive-only commands on the current tab", () => {
    expect(takesOnlyArchive(fake.commands[0])).toBe(true);
    expect(takesOnlyArchive(fake.commands[1])).toBe(false);
    expect(takesOnlyArchive(fake.commands[2])).toBe(false);
  });
});
