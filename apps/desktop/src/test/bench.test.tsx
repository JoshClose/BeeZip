import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { BenchChart, cellLabel } from "../features/bench/BenchChart";
import { BenchDialog, benchArgs } from "../features/bench/BenchDialog";
import type { BenchCell, BenchRunOutput, JobEvent } from "../gen/commands";
import { applyEvent, newJob, useJobs } from "../lib/jobs";
import { cancel, fake } from "./fakeEngine";

vi.mock("../lib/engine", () => import("./fakeEngine"));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(async () => null) }));

const cell = (patch: Partial<BenchCell>): BenchCell => ({
  codec: "zstd",
  level: 3,
  threads: 1,
  packed_bytes: 2_500_000,
  ratio: 0.3,
  compress_mbps: 250,
  decompress_mbps: 900,
  compress_mem: 20 << 20,
  decompress_mem: 2 << 20,
  ms: 45,
  error: null,
  ...patch,
});

const output = (cells: BenchCell[], patch: Partial<BenchRunOutput> = {}): BenchRunOutput => ({
  sample: { source: "built-in", bytes: 8 << 20 },
  cpus: 8,
  cells,
  total_ms: 1234,
  cancelled: false,
  ...patch,
});

const partial = (c: BenchCell): JobEvent => ({ type: "Partial", output: c as never });

describe("the benchmark dialog", () => {
  beforeEach(() => {
    fake.reset();
    cancel.mockReset().mockResolvedValue(true);
    useJobs.setState({ jobs: {}, order: [] });
  });

  it("builds its arguments", () => {
    expect(benchArgs({ useFile: false, file: "C:\\a.iso", grid: "default" })).toEqual({ grid: "default" });
    expect(benchArgs({ useFile: true, file: "C:\\a.iso", grid: "full" })).toEqual({ sample: "C:\\a.iso", grid: "full" });
  });

  it("shows each cell as it arrives, then the totals", async () => {
    const cells = [cell({ codec: "lz4", level: null }), cell({ codec: "zstd", level: 19, ratio: 0.22, compress_mbps: 4 })];
    let finish!: () => void;
    const gate = new Promise<void>((r) => (finish = r));
    fake.handlers.set("bench.run", async (_args, emit) => {
      emit({ type: "Progress", bytes_done: 10, bytes_total: 100, entries_done: 0, entries_total: 2, current: "lz4, compressing" });
      emit(partial(cells[0]));
      await gate;
      emit(partial(cells[1]));
      return output(cells);
    });
    const user = userEvent.setup();
    render(<BenchDialog onClose={() => {}} />);
    await user.click(screen.getByRole("button", { name: /run/i }));

    // The first cell is in the table and the chart before the run ends.
    const table = screen.getByRole("table");
    expect(await within(table).findByText("lz4")).toBeInTheDocument();
    expect(within(table).queryByText("zstd")).toBeNull();
    expect(screen.getByTestId("bench-point-0")).toBeInTheDocument();
    expect(screen.getByText("Cell 1 of 2: lz4, compressing")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();

    finish();
    expect(await screen.findByText("2 cells in 1.2 s, on 8 logical CPUs.")).toBeInTheDocument();
    expect(within(table).getByText("zstd")).toBeInTheDocument();
    expect(within(table).getByText("22.0%")).toBeInTheDocument();
    expect(fake.calls).toEqual([{ name: "bench.run", args: { grid: "default" } }]);
  });

  it("runs on a file with another grid", async () => {
    fake.handlers.set("bench.run", async () => output([], { sample: { source: "C:\\big.iso", bytes: 8 << 20 } }));
    const user = userEvent.setup();
    render(<BenchDialog file="C:\big.iso" onClose={() => {}} />);
    await user.click(screen.getByLabelText(/a file/i));
    expect(screen.getByLabelText("File")).toHaveValue("C:\\big.iso");
    await user.selectOptions(screen.getByLabelText("Cells"), "full");
    await user.click(screen.getByRole("button", { name: /run/i }));
    await screen.findByText(/0 cells in/);
    expect(fake.calls[0].args).toEqual({ sample: "C:\\big.iso", grid: "full" });
  });

  it("cancels, and keeps the cells that finished", async () => {
    const first = cell({ codec: "gzip", level: 6 });
    let stopped!: () => void;
    const stop = new Promise<void>((r) => (stopped = r));
    cancel.mockImplementation(async () => {
      stopped();
      return true;
    });
    fake.handlers.set("bench.run", async (_args, emit) => {
      emit(partial(first));
      await stop;
      return output([first], { cancelled: true });
    });
    const user = userEvent.setup();
    render(<BenchDialog onClose={() => {}} />);
    await user.click(screen.getByRole("button", { name: /run/i }));
    await within(screen.getByRole("table")).findByText("gzip");
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(cancel).toHaveBeenCalledWith(1);
    expect(await screen.findByText("Cancelled after 1 cell, 1.2 s.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /run/i })).toBeEnabled();
  });

  it("cancels the run when it closes", async () => {
    fake.handlers.set("bench.run", () => new Promise(() => {}));
    const user = userEvent.setup();
    const { unmount } = render(<BenchDialog onClose={() => {}} />);
    await user.click(screen.getByRole("button", { name: /run/i }));
    await screen.findByRole("button", { name: /cancel/i });
    unmount();
    expect(cancel).toHaveBeenCalledWith(1);
  });

  it("shows a failed run's error", async () => {
    fake.handlers.set("bench.run", async () => {
      throw { code: "NotFound", message: "reading C:\\gone.bin: not found" };
    });
    const user = userEvent.setup();
    render(<BenchDialog onClose={() => {}} />);
    await user.click(screen.getByRole("button", { name: /run/i }));
    expect(await screen.findByText("NotFound: reading C:\\gone.bin: not found")).toBeInTheDocument();
  });
});

describe("the benchmark chart", () => {
  const cells = [
    cell({ codec: "gzip", level: 1, ratio: 0.4, compress_mbps: 300 }),
    cell({ codec: "gzip", level: 9, ratio: 0.33, compress_mbps: 20 }),
    cell({ codec: "zstd", level: 3, threads: 8, compress_mbps: 900 }),
    cell({ codec: "lz4", level: null, ratio: 0.55, compress_mbps: 600, error: "the round trip doesn't match the sample from byte 7" }),
  ];

  it("plots the cells that passed and lists all of them", () => {
    render(<BenchChart cells={cells} cpus={8} />);
    expect(screen.getByTestId("bench-point-0")).toBeInTheDocument();
    expect(screen.getByTestId("bench-point-2")).toBeInTheDocument();
    // A failed cell has no point, only its row.
    expect(screen.queryByTestId("bench-point-3")).toBeNull();
    expect(screen.getByText("Failed: the round trip doesn't match the sample from byte 7")).toBeInTheDocument();
    const rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(rows).toHaveLength(5);
    expect(within(rows[3]).getByText("all")).toBeInTheDocument();
    expect(screen.getByText(/compression speed, mb\/s/i)).toBeInTheDocument();
    // Levels are labelled where a codec has several.
    const chart = screen.getByTestId("bench-chart");
    expect(within(chart).getByText("9")).toBeInTheDocument();
  });

  it("puts decompression speed across on the switch", async () => {
    const user = userEvent.setup();
    render(<BenchChart cells={cells} cpus={8} />);
    await user.click(screen.getByRole("button", { name: "Decompression speed" }));
    expect(screen.getByRole("button", { name: "Decompression speed" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText(/^decompression speed, mb\/s/i)).toBeInTheDocument();
  });

  it("shows the memory on hover", async () => {
    const user = userEvent.setup();
    render(<BenchChart cells={cells} cpus={8} />);
    await user.hover(screen.getByTestId("bench-point-2"));
    const tip = screen.getByRole("tooltip");
    expect(within(tip).getByText("zstd -3, all threads")).toBeInTheDocument();
    expect(within(tip).getByText(/compressing: 900 MB\/s, 20 MiB of memory/i)).toBeInTheDocument();
    await user.unhover(screen.getByTestId("bench-point-2"));
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("names cells for people", () => {
    expect(cellLabel(cell({ codec: "xz", level: 6, threads: 4 }), 8)).toBe("xz -6, 4 threads");
    expect(cellLabel(cell({ codec: "lz4", level: null }), 8)).toBe("lz4");
  });
});

describe("partial output", () => {
  beforeEach(() => {
    fake.reset();
    useJobs.setState({ jobs: {}, order: [] });
  });

  it("reaches the job's listener and leaves the record alone", async () => {
    const job = newJob(1, "bench.run", {}, { title: "Benchmark" }, 0);
    expect(applyEvent(job, partial(cell({})), 1)).toBe(job);

    const seen: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    fake.handlers.set("bench.run", async (_args, emit) => {
      emit(partial(cell({})));
      await gate;
      return output([]);
    });
    const done = useJobs.getState().track("bench.run", {}, { title: "Benchmark", quiet: true, onEvent: (e) => seen.push(e.type) });
    // A quiet job stays until it ends, whatever comes before.
    await waitFor(() => expect(seen).toContain("Partial"));
    expect(useJobs.getState().jobs[1]?.status).toBe("running");
    release();
    await done;
    expect(seen).toEqual(["Started", "Partial", "Finished"]);
    expect(useJobs.getState().jobs[1]).toBeUndefined();
  });
});
