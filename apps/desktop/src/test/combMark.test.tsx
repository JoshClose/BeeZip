// The job window's comb: which mark a command gets, and what each draws.
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CombMark, markKind } from "../components/CombMark";

describe("the comb mark", () => {
  it("shows what comes out, what goes in, or a test", () => {
    expect(markKind("archive.extract")).toBe("extract");
    expect(markKind("stream.decompress")).toBe("extract");
    for (const c of ["archive.create", "archive.add", "archive.convert", "stream.compress"]) expect(markKind(c)).toBe("compress");
    expect(markKind("archive.test")).toBe("test");
    expect(markKind("")).toBe("test");
  });

  it("draws six cells and the one that moves, or the whole comb for a test", () => {
    const { container, rerender } = render(<CombMark kind="extract" state="running" />);
    const svg = () => container.querySelector("svg")!;
    expect(svg().querySelectorAll(".comb-fixed")).toHaveLength(6);
    expect(svg().querySelectorAll(".comb-cell polygon")).toHaveLength(1);
    expect(svg().querySelector(".comb-slot")).toBeNull();
    expect(svg()).toHaveAttribute("aria-hidden", "true");

    // Compressing shows the gap the cell goes into while it runs, and not once it's in.
    rerender(<CombMark kind="compress" state="running" />);
    expect(svg().querySelector(".comb-slot")).not.toBeNull();
    rerender(<CombMark kind="compress" state="done" />);
    expect(svg().querySelector(".comb-slot")).toBeNull();
    expect(svg()).toHaveAttribute("data-state", "done");

    rerender(<CombMark kind="test" state="running" />);
    expect(svg().querySelectorAll(".comb-fixed")).toHaveLength(7);
    expect(svg().querySelector(".comb-cell")).toBeNull();
  });
});
