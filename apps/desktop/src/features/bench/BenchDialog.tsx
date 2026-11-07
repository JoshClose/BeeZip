// The Benchmark dialog (docs/M6.md §7): `bench.run` on a file or the built-in sample, its
// cells arriving in the chart as each finishes.
import { open as pickFile } from "@tauri-apps/plugin-dialog";
import { Gauge, Square } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { Field, Input, Select } from "../../components/ui/input";
import type { BenchCell, BenchGridName, BenchRunInput, BenchRunOutput, JobId, Progress } from "../../gen/commands";
import { describeError } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { CopyAsCli } from "../cli/CopyAsCli";
import { BenchChart } from "./BenchChart";

const GRIDS: { value: BenchGridName; label: string }[] = [
  { value: "default", label: "The common codecs and levels (about 10 seconds)" },
  { value: "full", label: "Every codec at every level (a few minutes)" },
  { value: "threads", label: "zstd and xz on 1, 4 and all threads (64 MiB, about a minute)" },
];

export type BenchForm = { useFile: boolean; file: string; grid: BenchGridName };

export function benchArgs(f: BenchForm): BenchRunInput {
  return { ...(f.useFile && f.file ? { sample: f.file } : {}), grid: f.grid };
}

type Run =
  | { state: "idle" }
  | { state: "running"; progress?: Progress }
  | { state: "done"; output: BenchRunOutput }
  | { state: "failed"; message: string };

export function BenchDialog({ file, onClose }: { file?: string; onClose: () => void }) {
  const [form, setForm] = useState<BenchForm>({ useFile: false, file: file ?? "", grid: "default" });
  const [run, setRun] = useState<Run>({ state: "idle" });
  const [cells, setCells] = useState<BenchCell[]>([]);
  const job = useRef<JobId | undefined>(undefined);
  const live = useRef(true);
  const args = benchArgs(form);
  const running = run.state === "running";

  // A run doesn't outlive its dialog.
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
      if (job.current !== undefined) void useJobs.getState().cancel(job.current);
    };
  }, []);

  const start = () => {
    setCells([]);
    setRun({ state: "running" });
    useJobs
      .getState()
      .track("bench.run", args, {
        title: "Benchmark",
        quiet: true,
        onEvent: (e) => {
          if (!live.current) return;
          if (e.type === "Started") job.current = e.job;
          else if (e.type === "Partial") setCells((c) => [...c, e.output as BenchCell]);
          else if (e.type === "Progress") setRun((r) => (r.state === "running" ? { state: "running", progress: e } : r));
        },
      })
      .then(
        (output) => {
          if (!live.current) return;
          setCells(output.cells);
          setRun({ state: "done", output });
        },
        (e) => {
          if (!live.current) return;
          const { code, message } = describeError(e);
          setRun({ state: "failed", message: `${code}: ${message}` });
        },
      )
      .finally(() => {
        job.current = undefined;
      });
  };

  const stop = () => {
    if (job.current !== undefined) void useJobs.getState().cancel(job.current);
  };

  const browse = async () => {
    const picked = await pickFile({ multiple: false, directory: false, title: "Benchmark on a file" });
    if (typeof picked === "string") setForm((f) => ({ ...f, useFile: true, file: picked }));
  };

  // Until the output says, the page's own count of logical CPUs: the same number.
  const cpus = run.state === "done" ? run.output.cpus : navigator.hardwareConcurrency || 1;

  return (
    <Dialog
      open
      onClose={onClose}
      title="Benchmark"
      description="Each codec compresses and decompresses a sample in memory. Nothing is written."
      className="w-[52rem]"
      footer={
        <>
          <CopyAsCli command="bench.run" args={args} disabled={form.useFile && !form.file} />
          <Button onClick={onClose}>Close</Button>
          {running ? (
            <Button variant="danger" onClick={stop}>
              <Square /> Cancel
            </Button>
          ) : (
            <Button variant="primary" onClick={start} disabled={form.useFile && !form.file}>
              <Gauge /> Run
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        <Field label="Sample">
          <div className="flex flex-col gap-1.5 pt-1">
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="sample"
                checked={!form.useFile}
                disabled={running}
                onChange={() => setForm((f) => ({ ...f, useFile: false }))}
                className="accent-[var(--amber)]"
              />
              BeeZip's own: 8 MiB of text, JSON, code, binary tables and random bytes
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="sample"
                checked={form.useFile}
                disabled={running}
                onChange={() => setForm((f) => ({ ...f, useFile: true }))}
                className="accent-[var(--amber)]"
              />
              A file, read as 16 slices across it
            </label>
            {form.useFile && (
              <div className="flex gap-2 pl-6">
                <Input
                  aria-label="File"
                  className="flex-1"
                  value={form.file}
                  disabled={running}
                  onChange={(e) => setForm((f) => ({ ...f, file: e.target.value }))}
                />
                <Button onClick={browse} disabled={running}>
                  Browse…
                </Button>
              </div>
            )}
          </div>
        </Field>
        <Field label="Cells" htmlFor="bench-grid">
          <Select
            id="bench-grid"
            value={form.grid}
            disabled={running}
            onChange={(e) => setForm((f) => ({ ...f, grid: e.target.value as BenchGridName }))}
          >
            {GRIDS.map((g) => (
              <option key={g.value} value={g.value}>
                {g.label}
              </option>
            ))}
          </Select>
        </Field>
        <Status run={run} />
        <BenchChart cells={cells} cpus={cpus} />
      </div>
    </Dialog>
  );
}

function Status({ run }: { run: Run }) {
  if (run.state === "idle") return null;
  if (run.state === "failed") return <p className="selectable text-danger">{run.message}</p>;
  if (run.state === "done") {
    const { output } = run;
    const n = output.cells.length;
    const what = `${n} ${n === 1 ? "cell" : "cells"}`;
    const secs = (output.total_ms / 1000).toFixed(1);
    const failed = output.cells.filter((c) => c.error !== null).length;
    return (
      <p role="status" className={failed > 0 ? "text-danger" : "text-muted"}>
        {output.cancelled ? `Cancelled after ${what}, ${secs} s.` : `${what} in ${secs} s, on ${output.cpus} logical CPUs.`}
        {failed > 0 && ` ${failed} failed.`}
      </p>
    );
  }
  const p = run.progress;
  const share = p?.bytes_total ? Math.round((100 * p.bytes_done) / p.bytes_total) : 0;
  return (
    <div className="flex flex-col gap-1">
      <p role="status" className="text-muted">
        {p?.entries_total ? `Cell ${Math.min(p.entries_done + 1, p.entries_total)} of ${p.entries_total}: ${p.current ?? ""}` : "Preparing the sample…"}
      </p>
      <div role="progressbar" aria-valuenow={share} aria-valuemin={0} aria-valuemax={100} aria-label="Benchmark" className="h-1.5 overflow-hidden rounded-full bg-sunken">
        <div className="h-full bg-amber-fill" style={{ width: `${share}%` }} />
      </div>
    </div>
  );
}
