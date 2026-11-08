// The jobs panel (docs/M3.md §5.3): a status line until something runs, then each job with its
// progress, Cancel, its log and its result. Finished jobs stay until cleared.
import { ChevronDown, ChevronUp, CircleAlert, CircleCheck, CircleSlash, LoaderCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "../../components/ui/button";
import type {
  ArchiveConvertOutput,
  ArchiveCreateOutput,
  ArchiveExtractOutput,
  ArchiveTestOutput,
  EditOutput,
  StreamCompressOutput,
} from "../../gen/commands";
import { cn } from "../../lib/cn";
import { baseName, formatRate, formatSize } from "../../lib/format";
import { type JobRecord, orderedJobs, useJobs } from "../../lib/jobs";
import { useUi } from "../../lib/ui";

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** One line saying what a finished job did. */
export function summary(job: JobRecord): string {
  return outputSummary(job.command, job.output);
}

/** An edit's line, as the CLI says it (docs/M5.md §7.4): "Added 3 files to a.zip (12 entries
 * copied as they were); 1.2 MiB → 1.4 MiB". */
export function editSummary(o: EditOutput): string {
  const name = baseName(o.path);
  if (o.dry_run) return `Would change ${plural(o.plan?.length ?? 0, "entry", "entries")} in ${name}`;
  // The last part's preposition goes before the name.
  const parts: [string, string][] = [];
  if (o.added) parts.push([`added ${plural(o.added, "file")}`, "to"]);
  if (o.replaced) parts.push([`replaced ${plural(o.replaced, "entry", "entries")}`, "in"]);
  if (o.removed) parts.push([`removed ${plural(o.removed, "entry", "entries")}`, "from"]);
  if (o.renamed) parts.push([`renamed ${plural(o.renamed, "entry", "entries")}`, "in"]);
  let s = "";
  if (parts.length === 0) s = `Nothing changed in ${name}`;
  else {
    const said = `${parts.map((p) => p[0]).join(", ")} ${parts[parts.length - 1][1]} ${name}`;
    s = said[0].toUpperCase() + said.slice(1);
  }
  const notes = [
    o.copied === 1 ? "1 entry copied as it was" : o.copied > 1 ? `${o.copied.toLocaleString()} entries copied as they were` : "",
    o.recompressed ? `${plural(o.recompressed, "entry", "entries")} recompressed` : "",
    o.skipped ? `${plural(o.skipped, "file")} skipped` : "",
    o.unencrypted ? `${plural(o.unencrypted, "new file")} not encrypted` : "",
  ].filter(Boolean);
  if (notes.length) s += ` (${notes.join(", ")})`;
  if (parts.length) s += `; ${formatSize(o.bytes_before)} → ${formatSize(o.bytes_after)}`;
  return s;
}

/** One line saying what a command's output says it did. */
export function outputSummary(command: string, out: unknown): string {
  switch (command) {
    case "archive.extract": {
      const o = out as ArchiveExtractOutput;
      if (o.dry_run) return `Would extract ${o.plan?.length ?? 0} entries to ${o.dest}`;
      const extra = [o.skipped_total && `${o.skipped_total} skipped`, o.renamed_total && `${o.renamed_total} renamed`].filter(Boolean);
      return `Extracted ${plural(o.files, "file")}, ${formatSize(o.bytes)}, to ${o.dest}${extra.length ? ` (${extra.join(", ")})` : ""}`;
    }
    case "archive.create": {
      const o = out as ArchiveCreateOutput;
      if (o.dry_run) return `Would add ${o.plan?.length ?? 0} entries`;
      const parts = o.volumes ? `${o.volumes.length} volumes` : baseName(o.path);
      return `Wrote ${parts}: ${plural(o.files, "file")}, ${formatSize(o.bytes_in)} packed to ${formatSize(o.bytes_out)} (${Math.round(o.ratio * 100)}%)`;
    }
    case "archive.test": {
      const o = out as ArchiveTestOutput;
      return `All ${plural(o.entries, "entry", "entries")} are OK (${formatSize(o.bytes)} read)${o.note ? `. ${o.note}` : ""}`;
    }
    case "archive.add":
    case "archive.remove":
    case "archive.rename":
      return editSummary(out as EditOutput);
    case "archive.convert": {
      const o = out as ArchiveConvertOutput;
      if (o.dry_run) return `Would write ${o.plan?.length ?? 0} entries`;
      const parts = o.volumes ? `${o.volumes.length} volumes` : baseName(o.path);
      const skipped = o.skipped.length ? `; ${plural(o.skipped.length, "entry", "entries")} it can't hold left out` : "";
      return `Wrote ${parts}: ${plural(o.files, "file")}, ${formatSize(o.bytes_in)} to ${formatSize(o.bytes_out)}${skipped}`;
    }
    case "entry.open":
      return `Opened ${(out as { path: string }).path}`;
    case "stream.compress":
    case "stream.decompress": {
      const o = out as StreamCompressOutput;
      return `Wrote ${o.output}`;
    }
    default: {
      const text = JSON.stringify(out);
      return text.length > 160 ? `${text.slice(0, 160)}…` : text;
    }
  }
}

export function Bar({ job }: { job: JobRecord }) {
  const p = job.progress;
  const share = p?.bytes_total ? Math.min(1, p.bytes_done / p.bytes_total) : undefined;
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-sunken"
      role="progressbar"
      aria-valuenow={share === undefined ? undefined : Math.round(share * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className={cn("h-full bg-amber-fill", share === undefined && "w-1/3 animate-pulse")}
        style={share === undefined ? undefined : { width: `${share * 100}%` }}
      />
    </div>
  );
}

function JobRow({ job }: { job: JobRecord }) {
  const cancel = useJobs((s) => s.cancel);
  const show = useUi((s) => s.show);
  const [logs, setLogs] = useState(false);
  const p = job.progress;
  const numbers = p
    ? [
        p.bytes_total ? `${formatSize(p.bytes_done)} of ${formatSize(p.bytes_total)}` : formatSize(p.bytes_done),
        p.entries_total ? `${p.entries_done} of ${p.entries_total} entries` : p.entries_done ? `${p.entries_done} entries` : "",
        formatRate(job.rate),
      ].filter(Boolean)
    : [];
  const icon = {
    running: <LoaderCircle className="size-4 animate-spin text-amber" />,
    finished: <CircleCheck className="size-4 text-ok" />,
    failed: <CircleAlert className="size-4 text-danger" />,
    cancelled: <CircleSlash className="size-4 text-muted" />,
  }[job.status];
  const error = job.error;
  return (
    <li className="flex flex-col gap-1 border-b border-rule px-3 py-2 last:border-b-0">
      <div className="flex items-center gap-2">
        {icon}
        <span className="min-w-0 flex-1 truncate font-semibold">{job.title}</span>
        {job.logs.length > 0 && (
          <Button size="sm" variant="ghost" onClick={() => setLogs(!logs)}>
            {logs ? "Hide log" : `Log (${job.logs.length})`}
          </Button>
        )}
        {job.status === "running" && (
          <Button size="sm" onClick={() => cancel(job.id)}>
            Cancel
          </Button>
        )}
      </div>
      {job.status === "running" && (
        <>
          <Bar job={job} />
          <div className="tabular flex gap-4 text-[12px] text-muted">
            {numbers.map((n) => (
              <span key={n}>{n}</span>
            ))}
            {p?.current && <span className="min-w-0 flex-1 truncate text-right">{p.current}</span>}
          </div>
        </>
      )}
      {job.status === "finished" && <p className="selectable text-muted">{summary(job)}</p>}
      {job.status === "cancelled" && <p className="text-muted">Cancelled. Files it had started writing were removed.</p>}
      {job.status === "failed" && error && (
        <div className="flex items-start gap-2">
          <p className="selectable min-w-0 flex-1 text-danger">
            {error.code}: {error.message}
          </p>
          {error.code === "Unsafe" && (
            <Button size="sm" onClick={() => show({ kind: "report", title: job.title, error })}>
              Show report
            </Button>
          )}
        </div>
      )}
      {logs && (
        <ul className="selectable max-h-32 overflow-auto rounded bg-sunken px-2 py-1 font-mono text-[11.5px]">
          {job.logs.map((l, i) => (
            <li key={i} className={l.level === "Warn" ? "text-amber" : "text-muted"}>
              {l.message}
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function JobsPanel() {
  const jobsMap = useJobs((s) => s.jobs);
  const order = useJobs((s) => s.order);
  const clearFinished = useJobs((s) => s.clearFinished);
  const jobs = useMemo(() => orderedJobs({ jobs: jobsMap, order }).filter((j) => !j.quiet), [jobsMap, order]);
  const running = jobs.filter((j) => j.status === "running");
  const [open, setOpen] = useState(false);
  const seen = useRef(0);

  // Opens when a job starts; the person can close it again.
  useEffect(() => {
    if (jobs.length > seen.current) setOpen(true);
    seen.current = jobs.length;
  }, [jobs.length]);

  const latest = running[running.length - 1];
  const status =
    running.length === 0
      ? jobs.length === 0
        ? "No jobs"
        : `${jobs.length} finished ${jobs.length === 1 ? "job" : "jobs"}`
      : running.length === 1
        ? latest.title
        : `${running.length} jobs running`;
  const share = latest?.progress?.bytes_total
    ? Math.round((100 * latest.progress.bytes_done) / latest.progress.bytes_total)
    : undefined;

  return (
    <section className="shrink-0 border-t border-rule bg-paper" aria-label="Jobs">
      <div className="flex h-8 items-center gap-3 px-3">
        {running.length > 0 && <LoaderCircle className="size-3.5 animate-spin text-amber" />}
        <span className="min-w-0 truncate">{status}</span>
        {share !== undefined && <span className="tabular text-muted">{share}%</span>}
        <span className="flex-1" />
        {jobs.some((j) => j.status !== "running") && (
          <Button size="sm" variant="ghost" onClick={clearFinished}>
            Clear finished
          </Button>
        )}
        {jobs.length > 0 && (
          <Button size="sm" variant="ghost" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? <ChevronDown /> : <ChevronUp />} {open ? "Hide" : "Show"}
          </Button>
        )}
      </div>
      {open && jobs.length > 0 && (
        <ul className="max-h-[38vh] overflow-auto border-t border-rule bg-panel">
          {[...jobs].reverse().map((j) => (
            <JobRow key={j.id} job={j} />
          ))}
        </ul>
      )}
    </section>
  );
}
