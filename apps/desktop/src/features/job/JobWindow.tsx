// The job window (docs/M4.md §6.3): one click on Explorer's menu. Its steps run one after
// another, with progress, Cancel and M3's prompts; then the result, "Open folder", and, after a
// clean success, it closes itself.
import { LogicalSize } from "@tauri-apps/api/dpi";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { CircleAlert, CircleCheck, CircleSlash, FolderOpen, LoaderCircle } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import type { ArchiveExtractOutput, ArchiveCreateOutput, CmdError, CommandName, Existing, Step } from "../../gen/commands";
import { useCloseGuard } from "../../lib/closeGuard";
import { baseName, formatDuration, formatRate, formatSize, isCancelled, parentDir, samePath } from "../../lib/format";
import { type JobRecord, orderedJobs, useJobs } from "../../lib/jobs";
import type { JobStartup } from "../../lib/startup";
import { Bar, outputSummary } from "../jobs/JobsPanel";
import { ReportDialog } from "../jobs/ReportDialog";
import { Prompts } from "../prompts/Prompts";

export type RunStep = Extract<Step, { kind: "run" }>;

/** How long a clean success stays on screen before the window closes. */
export const CLOSE_AFTER_MS = 2000;

/** The room M3's dialogs need, in logical pixels: a prompt's buttons on one row, the report's list. */
export const PROMPT_SIZE = [640, 360] as const;
export const REPORT_SIZE = [760, 480] as const;

/** Makes the window at least `width` × `height`. It never shrinks: the person may have sized it. */
async function growTo(width: number, height: number) {
  const win = getCurrentWindow();
  const size = (await win.innerSize()).toLogical(await win.scaleFactor());
  if (size.width >= width && size.height >= height) return;
  await win.setSize(new LogicalSize(Math.max(size.width, width), Math.max(size.height, height)));
}

export type Outcome =
  | { status: "pending" }
  | { status: "asking" }
  | { status: "running" }
  | { status: "done"; output: unknown }
  | { status: "failed"; error: CmdError }
  | { status: "skipped" }
  | { status: "cancelled" };

/** The answer about an archive that's already there. */
export type ExistingChoice = "replace" | "keep-both" | "skip" | "cancel";

/** A run step's arguments after that answer: replace it, or write the free name beside it. */
export function argsFor(step: RunStep, choice?: ExistingChoice): Record<string, unknown> {
  const args = { ...(step.args as Record<string, unknown>) };
  if (choice === "replace") args.overwrite = true;
  if (choice === "keep-both" && step.existing) args.output = step.existing.keep_both;
  return args;
}

/** What "Open folder" shows: the folder files went into (or the archive, when they went beside it), or the archive written. */
export function revealTarget(step: RunStep, output: unknown): string | undefined {
  if (step.command === "archive.extract") {
    const dest = (output as ArchiveExtractOutput).dest;
    const archive = (step.args as { archive?: string }).archive;
    if (archive && samePath(dest, parentDir(archive))) return archive;
    return dest;
  }
  if (step.command === "archive.create") {
    const o = output as ArchiveCreateOutput;
    return o.volumes?.[0] ?? o.path;
  }
  return undefined;
}

/** Whether a finished step lets the window close itself: nothing was skipped or renamed. */
export function isClean(step: RunStep, output: unknown): boolean {
  if (step.command !== "archive.extract") return true;
  const o = output as ArchiveExtractOutput;
  return o.skipped_total === 0 && o.renamed_total === 0 && o.unsafe_total === 0;
}

function initial(steps: Step[]): Outcome[] {
  return steps.map((s) => (s.kind === "failed" ? { status: "failed", error: s.error } : { status: "pending" }));
}

/** Runs the steps once, in order, and reports each one's outcome. */
function useSteps(steps: Step[]) {
  const track = useJobs((s) => s.track);
  const [outcomes, setOutcomes] = useState<Outcome[]>(() => initial(steps));
  const [current, setCurrent] = useState<number>();
  const [finished, setFinished] = useState(false);
  const answer = useRef<(c: ExistingChoice) => void>(undefined);
  const stopped = useRef(false);
  const started = useRef(false);

  const set = useCallback((i: number, o: Outcome) => setOutcomes((all) => all.map((x, j) => (j === i ? o : x))), []);

  useEffect(() => {
    // Once, however often React mounts the window (StrictMode does twice in development).
    if (started.current) return;
    started.current = true;
    void (async () => {
      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        if (step.kind !== "run") continue;
        if (stopped.current) {
          set(i, { status: "cancelled" });
          continue;
        }
        setCurrent(i);
        let choice: ExistingChoice | undefined;
        if (step.existing) {
          set(i, { status: "asking" });
          choice = await new Promise<ExistingChoice>((resolve) => (answer.current = resolve));
          answer.current = undefined;
          if (choice === "skip") {
            set(i, { status: "skipped" });
            continue;
          }
          if (choice === "cancel") {
            stopped.current = true;
            set(i, { status: "cancelled" });
            continue;
          }
        }
        set(i, { status: "running" });
        try {
          const output = await track(step.command as CommandName, argsFor(step, choice) as never, { title: step.title });
          set(i, { status: "done", output });
        } catch (e) {
          if (isCancelled(e)) {
            stopped.current = true;
            set(i, { status: "cancelled" });
          } else {
            set(i, { status: "failed", error: e as CmdError });
          }
        }
      }
      setCurrent(undefined);
      setFinished(true);
    })();
  }, [steps, set, track]);

  const cancelAll = useCallback(() => {
    stopped.current = true;
    if (answer.current) answer.current("cancel");
    for (const job of Object.values(useJobs.getState().jobs)) {
      if (job.status === "running") void useJobs.getState().cancel(job.id);
    }
  }, []);

  const choose = useCallback((c: ExistingChoice) => answer.current?.(c), []);

  return { outcomes, current, finished, cancelAll, choose };
}

function ExistingPrompt({ existing, onChoose }: { existing: Existing; onChoose: (c: ExistingChoice) => void }) {
  return (
    <Dialog
      open
      dismissable={false}
      onClose={() => onChoose("cancel")}
      title={`${baseName(existing.path)} is already there`}
      description={parentDir(existing.path)}
      footer={
        <>
          <Button onClick={() => onChoose("skip")}>Skip</Button>
          <span className="flex-1" />
          <Button onClick={() => onChoose("keep-both")}>Keep both</Button>
          <Button variant="primary" onClick={() => onChoose("replace")}>
            Replace
          </Button>
        </>
      }
    >
      <p className="pb-1 text-[12px] text-muted">“Keep both” writes {baseName(existing.keep_both)} beside it.</p>
    </Dialog>
  );
}

function Progress({ job }: { job: JobRecord }) {
  const p = job.progress;
  const left = p?.bytes_total && job.rate ? (p.bytes_total - p.bytes_done) / job.rate : undefined;
  const numbers = p
    ? [
        p.bytes_total ? `${formatSize(p.bytes_done)} of ${formatSize(p.bytes_total)}` : formatSize(p.bytes_done),
        formatRate(job.rate),
        left !== undefined && formatDuration(left) ? `${formatDuration(left)} left` : "",
      ].filter(Boolean)
    : [];
  return (
    <div className="flex flex-col gap-1.5 px-4 pb-2">
      <Bar job={job} />
      <div className="tabular flex gap-3 text-[12px] text-muted">
        {numbers.map((n) => (
          <span key={n}>{n}</span>
        ))}
      </div>
      <p className="selectable truncate font-mono text-[11.5px] text-muted" title={p?.current ?? undefined}>
        {p?.current ?? " "}
      </p>
    </div>
  );
}

const ICONS = {
  done: <CircleCheck className="size-4 shrink-0 text-ok" />,
  failed: <CircleAlert className="size-4 shrink-0 text-danger" />,
  cancelled: <CircleSlash className="size-4 shrink-0 text-muted" />,
  skipped: <CircleSlash className="size-4 shrink-0 text-muted" />,
  running: <LoaderCircle className="size-4 shrink-0 animate-spin text-amber" />,
};

function Row({ step, outcome, onReport }: { step: Step; outcome: Outcome; onReport: (title: string, error: CmdError) => void }) {
  const title = step.kind === "run" || step.kind === "failed" ? step.title : "";
  let detail = "";
  let reveal: string | undefined;
  if (outcome.status === "done" && step.kind === "run") {
    detail = outputSummary(step.command, outcome.output);
    reveal = revealTarget(step, outcome.output);
  } else if (outcome.status === "failed") detail = `${outcome.error.code}: ${outcome.error.message}`;
  else if (outcome.status === "cancelled") detail = "Cancelled. Files it had started writing were removed.";
  else if (outcome.status === "skipped") detail = "Skipped: the archive was left as it was.";
  else return null;
  return (
    <li className="flex items-start gap-2 border-t border-rule py-2 first:border-t-0">
      {ICONS[outcome.status]}
      <div className="min-w-0 flex-1">
        <p className="truncate font-semibold">{title}</p>
        <p className={`selectable break-words ${outcome.status === "failed" ? "text-danger" : "text-muted"}`}>{detail}</p>
      </div>
      {reveal && (
        <Button size="sm" onClick={() => void revealItemInDir(reveal).catch(() => {})}>
          <FolderOpen /> Open folder
        </Button>
      )}
      {outcome.status === "failed" && outcome.error.code === "Unsafe" && (
        <Button size="sm" onClick={() => onReport(title, outcome.error)}>
          Show report
        </Button>
      )}
    </li>
  );
}

/** What the header says. */
function heading(steps: Step[], outcomes: Outcome[], current: number | undefined, finished: boolean): string {
  if (!finished) {
    // Before the first step starts, its title: the one Rust gave the window.
    const step = steps[current ?? steps.findIndex((s) => s.kind === "run")];
    return step?.kind === "run" ? step.title : "BeeZip";
  }
  const all = outcomes.length;
  const count = (s: Outcome["status"]) => outcomes.filter((o) => o.status === s).length;
  if (count("done") === all) return "Done";
  if (count("cancelled") > 0) return "Cancelled";
  if (all === 1 && outcomes[0].status === "failed") return `${(steps[0] as { title: string }).title} failed`;
  if (count("failed") > 0) return `Done, with ${count("failed")} of ${all} failed`;
  return "Done";
}

export function JobWindow({ job }: { job: JobStartup }) {
  const steps = job.steps;
  const { outcomes, current, finished, cancelAll, choose } = useSteps(steps);
  const [report, setReport] = useState<{ title: string; error: CmdError }>();
  const jobs = useJobs((s) => s.jobs);
  const order = useJobs((s) => s.order);
  const running = useMemo(() => orderedJobs({ jobs, order }).find((j) => j.status === "running"), [jobs, order]);
  const close = useCallback(() => void getCurrentWindow().destroy().catch(() => {}), []);
  useCloseGuard("close");

  const runSteps = steps.filter((s) => s.kind === "run").length;
  const position = current === undefined ? undefined : steps.slice(0, current + 1).filter((s) => s.kind === "run").length;
  const title = heading(steps, outcomes, current, finished);
  const step = current === undefined ? undefined : steps[current];
  const asking = step?.kind === "run" && outcomes[current ?? -1]?.status === "asking" ? step.existing : undefined;

  // The native title follows the step that runs. One call at a time: two in flight can land
  // in either order.
  const titled = useRef(Promise.resolve());
  useEffect(() => {
    const text = title === "Done" && steps.length === 1 && steps[0].kind === "run" ? steps[0].title : title;
    titled.current = titled.current.then(() => getCurrentWindow().setTitle(text)).catch(() => {});
  }, [title, steps]);

  // A prompt or the report gets the room it needs; the window starts small.
  const prompting = useJobs((s) => Object.values(s.jobs).some((j) => j.prompts.length > 0));
  const [needW, needH] = report ? REPORT_SIZE : prompting || asking ? PROMPT_SIZE : [0, 0];
  useEffect(() => {
    if (needW > 0) void growTo(needW, needH).catch(() => {});
  }, [needW, needH]);

  // A clean success closes the window, unless the person asked to keep it.
  const clean =
    finished && job.close_when_done && steps.every((s, i) => s.kind === "run" && outcomes[i].status === "done" && isClean(s, (outcomes[i] as { output: unknown }).output));
  useEffect(() => {
    if (!clean) return;
    const timer = setTimeout(close, CLOSE_AFTER_MS);
    return () => clearTimeout(timer);
  }, [clean, close]);

  const icon = finished
    ? ICONS[outcomes.every((o) => o.status === "done") ? "done" : outcomes.some((o) => o.status === "failed") ? "failed" : "cancelled"]
    : ICONS.running;

  return (
    <div className="flex h-full flex-col bg-paper">
      <header className="flex items-center gap-2 px-4 pt-3 pb-2">
        {icon}
        <h1 className="min-w-0 flex-1 truncate text-[15px] font-semibold">{title}</h1>
        {!finished && runSteps > 1 && position !== undefined && (
          <span className="tabular shrink-0 text-muted">
            {position} of {runSteps}
          </span>
        )}
      </header>
      {!finished && running && <Progress job={running} />}
      <ul className="min-h-0 flex-1 overflow-auto px-4" aria-label="Results">
        {steps.map((s, i) => (
          <Row key={i} step={s} outcome={outcomes[i]} onReport={(t, e) => setReport({ title: t, error: e })} />
        ))}
      </ul>
      <footer className="flex items-center justify-end gap-2 border-t border-rule bg-panel px-4 py-2.5">
        {clean && <span className="mr-auto text-[12px] text-muted">Closing…</span>}
        {finished ? (
          <Button variant="primary" onClick={close}>
            Close
          </Button>
        ) : (
          <Button onClick={cancelAll}>Cancel</Button>
        )}
      </footer>
      {asking && <ExistingPrompt existing={asking} onChoose={choose} />}
      {report && <ReportDialog title={report.title} error={report.error} onClose={() => setReport(undefined)} />}
      <Prompts />
    </div>
  );
}
