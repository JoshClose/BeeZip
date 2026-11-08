import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { InfoDialog } from "../features/browser/InfoDialog";
import { extractArgs } from "../features/extract/ExtractDialog";
import type { ArchiveInfoOutput } from "../gen/commands";
import { archiveArgs, useArchives } from "../lib/archives";
import { fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));

const info: ArchiveInfoOutput = {
  path: "C:\\a.zip",
  format: "zip",
  chain: "zip",
  codecs: [],
  size: 10,
  packed_size: 5,
  ratio: 0.5,
  entries: 2,
  files: 1,
  dirs: 1,
  links: 0,
  methods: ["Deflate"],
  encryption: "none",
  encrypted_headers: false,
  solid: false,
  solid_blocks: null,
  sfx: false,
  volumes: ["C:\\a.zip"],
  locked: false,
  recovery_record: false,
  comment: null,
  backend: null,
  levels: [],
  properties: [],
  notes: [],
} as unknown as ArchiveInfoOutput;

const tab = () => useArchives.getState().tabs[0];

describe("the name encoding (docs/M5.md §8.4)", () => {
  beforeEach(() => {
    fake.reset();
    useArchives.setState({ tabs: [], active: undefined });
    useArchives.getState().open("C:\\a.zip");
  });

  it("goes with every command on the tab once chosen", () => {
    expect(archiveArgs(tab())).toEqual({});
    useArchives.getState().update(tab().id, { dir: "docs", selected: [1], version: 3 });
    useArchives.getState().setEncoding(tab().id, "cp932");
    // The folder names change with it, so the tab lists again from the top.
    expect(tab()).toMatchObject({ encoding: "cp932", dir: "", selected: [], version: 4 });
    useArchives.getState().update(tab().id, { password: "pw" });
    expect(archiveArgs(tab())).toEqual({ password: "pw", name_encoding: "cp932" });
    useArchives.getState().setEncoding(tab().id, undefined);
    expect(archiveArgs(tab())).toEqual({ password: "pw" });
  });

  it("is passed to extracting, so the selected paths match", () => {
    const form = { dest: "C:\\out", selectedOnly: true, smart: true, overwrite: "ask" as const, links: false, password: "", strip: 0 };
    expect(extractArgs("C:\\a.zip", ["日本語"], form, false, "cp932")).toMatchObject({ name_encoding: "cp932", entries: ["日本語"] });
    expect(extractArgs("C:\\a.zip", [], form)).not.toHaveProperty("name_encoding");
  });

  it("can be chosen in the info dialog, which reads the archive again", async () => {
    fake.handlers.set("archive.info", (args) => ({ ...info, comment: (args as { name_encoding?: string }).name_encoding ?? "auto" }));
    const user = userEvent.setup();
    const { rerender } = render(<InfoDialog tab={tab()} onClose={() => {}} />);
    expect(await screen.findByText("auto")).toBeInTheDocument();
    const select = screen.getByLabelText("Name encoding");
    expect(select).toHaveValue("");
    await user.selectOptions(select, "cp932");
    expect(tab().encoding).toBe("cp932");
    rerender(<InfoDialog tab={tab()} onClose={() => {}} />);
    await waitFor(() => expect(fake.calls).toContainEqual({ name: "archive.info", args: { archive: "C:\\a.zip", name_encoding: "cp932" } }));
    expect(await screen.findByText("cp932")).toBeInTheDocument();
    expect(screen.getByLabelText("Name encoding")).toHaveValue("cp932");
  });
});
