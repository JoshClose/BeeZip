// The jobs panel (docs/M3.md §5.3): a status line until something runs, then each job with its
// progress, Cancel, its log and its result. Finished jobs stay until cleared.
import { Check, ChevronDown, ChevronUp, CircleAlert, CircleCheck, CircleSlash, Copy, LoaderCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { SevenZipFix } from "../../components/SevenZipFix";
import { Button } from "../../components/ui/button";
import { Splitter } from "../../components/ui/splitter";
import type {
  ArchiveConvertOutput,
  ArchiveCreateOutput,
  ArchiveExtractOutput,
  ArchiveTestOutput,
  EditOutput,
  SevenZipInstallOutput,
  StreamCompressOutput,
} from "../../gen/commands";
import { cn } from "../../lib/cn";
import { baseName, formatRate, formatSize } from "../../lib/format";
import { type JobRecord, orderedJobs, useJobs } from "../../lib/jobs";
import { JOBS_ABOVE_MIN, JOBS_HEADER, JOBS_MIN, tallestJobs, usePanes } from "../../lib/panes";
import { useSize } from "../../lib/size";
import { toastInfo } from "../../lib/toasts";
import { useUi } from "../../lib/ui";

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** One line saying what a finished job did. */
export function summary(job: JobRecord): string {
  return outputSummary(job.command, job.output);
}

/** What a cancelled job's line says. Installing 7-Zip writes no files of BeeZip's: its last
 * warning says what happened (the administrator prompt declined, or winget stopped). */
export function cancelledText(job: Pick<JobRecord, "command" | "logs">): string {
  if (job.command === "seven_zip.install") {
    return [...job.logs].reverse().find((l) => l.level === "Warn")?.message ?? "Cancelled. 7-Zip wasn't installed.";
  }
  return "Cancelled. Files it had started writing were removed.";
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
      const ok = o.entries === 1 ? "The 1 entry is OK" : `All ${plural(o.entries, "entry", "entries")} are OK`;
      return `${ok} (${formatSize(o.bytes)} read)${o.note ? `. ${o.note}` : ""}`;
    }
    case "seven_zip.install": {
      const o = out as SevenZipInstallOutput;
      const { name, path, problem } = o.status;
      if (!name) {
        const done = { installed: "Installed 7-Zip", updated: "Updated 7-Zip", none: "7-Zip is installed and new enough" }[o.action];
        return `${done}, but BeeZip doesn't use it: ${problem ?? "its settings"}`;
      }
      if (o.action === "installed") return `Installed ${name} at ${path}`;
      if (o.action === "updated") return `Updated to ${name} at ${path}`;
      return `${name} at ${path} is new enough; nothing to do`;
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

/** A log longer than this shows its first lines; Copy takes all of it. */
export const LOG_SHOWN = 1000;

/** A job as text, for the clipboard: its title, how it ended, and its whole log. */
export function jobText(job: JobRecord): string {
  const outcome =
    job.status === "finished"
      ? summary(job)
      : job.status === "failed" && job.error
        ? `${job.error.code}: ${job.error.message}`
        : job.status === "cancelled"
          ? "Cancelled."
          : undefined;
  const log = job.logs.map((l) => (l.level === "Warn" ? `Warning: ${l.message}` : l.message));
  return [job.title, ...(outcome ? [outcome] : []), ...(log.length ? ["", ...log] : [])].join("\n");
}

/** Copies a job's text; says "Copied" for a moment, or why it couldn't. */
function CopyJob({ job }: { job: JobRecord }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(jobText(job));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // The clipboard refuses a window without focus; the text can still be selected.
      toastInfo("Couldn't reach the clipboard", "Select the job's text and copy it instead.");
    }
  };
  return (
    <Button size="sm" variant="ghost" onClick={() => void copy()} title="Copy the job's title, result and log">
      {copied ? <Check /> : <Copy />} {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function JobRow({ job }: { job: JobRecord }) {
  const cancel = useJobs((s) => s.cancel);
  const show = useUi((s) => s.show);
  const [logs, setLogs] = useState(false);
  const p = job.progress;
  const numbers = p
    ? [
        p.bytes_total ? `${formatSize(p.bytes_done)} of ${formatSize(p.bytes_total)}` : p.bytes_done ? formatSize(p.bytes_done) : "",
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
        <span className="min-w-0 flex-1 truncate font-semibold" title={job.title}>
          {job.title}
        </span>
        {(job.error || job.logs.length > 0) && <CopyJob job={job} />}
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
            {p?.current && (
              <span className="min-w-0 flex-1 truncate text-right" title={p.current}>
                {p.current}
              </span>
            )}
          </div>
        </>
      )}
      {job.status === "finished" && <p className="selectable text-muted">{summary(job)}</p>}
      {job.status === "cancelled" && <p className="text-muted">{cancelledText(job)}</p>}
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
          <SevenZipFix error={error} />
        </div>
      )}
      {/* In full: the jobs list is the one scroller, and its edge makes it taller. */}
      {logs && (
        <ul className="selectable rounded bg-sunken px-2 py-1 font-mono text-[11.5px] break-words" aria-label={`${job.title}: log`}>
          {job.logs.slice(0, LOG_SHOWN).map((l, i) => (
            <li key={i} className={l.level === "Warn" ? "text-amber" : "text-muted"}>
              {l.message}
            </li>
          ))}
          {job.logs.length > LOG_SHOWN && (
            <li className="pt-1 font-sans text-muted">
              {(job.logs.length - LOG_SHOWN).toLocaleString()} more {job.logs.length - LOG_SHOWN === 1 ? "line" : "lines"}: Copy takes the
              whole log.
            </li>
          )}
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

  // The list's height: dragged to, or fitting its jobs until then. The window column is measured
  // for how tall it may get; the section's max-height holds it to the same as the window shrinks.
  const panes = usePanes();
  const [columnRef, column] = useSize<HTMLElement>(true);
  const [listRef, list] = useSize<HTMLUListElement>();
  const listed = open && jobs.length > 0;

  return (
    <section
      ref={columnRef}
      className="flex shrink-0 flex-col bg-paper"
      style={{ maxHeight: `calc(100% - ${JOBS_ABOVE_MIN}px)` }}
      aria-label="Jobs"
    >
      {listed ? (
        <Splitter
          label="Resize the jobs"
          orientation="horizontal"
          size={list.height}
          min={JOBS_MIN}
          max={tallestJobs(column.height)}
          side="after"
          onResize={(h) => panes.resize("jobs", h)}
          onDone={panes.save}
          onReset={() => panes.reset("jobs")}
        />
      ) : (
        <div className="h-px shrink-0 bg-rule" />
      )}
      <div className="flex shrink-0 items-center gap-3 px-3" style={{ height: JOBS_HEADER }}>
        {running.length > 0 && <LoaderCircle className="size-3.5 animate-spin text-amber" />}
        <span className="min-w-0 truncate" title={status}>
          {status}
        </span>
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
      {listed && (
        <ul
          ref={listRef}
          className={cn("min-h-0 overflow-auto border-t border-rule bg-panel", panes.jobs === null && "max-h-[38vh]")}
          style={panes.jobs === null ? undefined : { height: panes.jobs }}
          aria-label="Jobs list"
        >
          {[...jobs].reverse().map((j) => (
            <JobRow key={j.id} job={j} />
          ))}
        </ul>
      )}
    </section>
  );
}
