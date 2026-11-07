// Every job the page starts, with its events (docs/M3.md §5.1). Quick jobs (listing a page,
// reading a preview) are `quiet`: the jobs panel hides them, but their prompts still show.
import { create } from "zustand";
import type {
  CmdError,
  CommandMap,
  CommandName,
  JobEvent,
  JobId,
  JsonValue,
  LogLevel,
  Progress,
  Prompt,
  PromptReply,
} from "../gen/commands";
import { cancel, respond, run } from "./engine";

export type JobStatus = "running" | "finished" | "failed" | "cancelled";

export type PendingPrompt = { id: number; prompt: Prompt };

export type JobRecord = {
  id: JobId;
  command: string;
  /** What the jobs panel calls it: "Extracting a.7z". */
  title: string;
  args: unknown;
  quiet: boolean;
  /** The tab whose archive the job reads, so a password typed for it can be kept. */
  tab?: string;
  status: JobStatus;
  progress?: Progress;
  /** Bytes per second, smoothed. */
  rate?: number;
  logs: { level: LogLevel; message: string }[];
  output?: JsonValue;
  error?: CmdError;
  /** Unanswered prompts, oldest first. */
  prompts: PendingPrompt[];
  started: number;
  ended?: number;
  /** The last progress sample, for the rate. */
  sample?: { at: number; bytes: number };
};

export type JobMeta = {
  title: string;
  quiet?: boolean;
  tab?: string;
  /** Sees every event of the job as it comes, the `Partial` pieces of its output included. */
  onEvent?: (event: JobEvent) => void;
};

/** A new record, as the `Started` event makes it. */
export function newJob(id: JobId, command: string, args: unknown, meta: JobMeta, now: number): JobRecord {
  return {
    id,
    command,
    title: meta.title,
    args,
    quiet: meta.quiet ?? false,
    tab: meta.tab,
    status: "running",
    logs: [],
    prompts: [],
    started: now,
  };
}

/** One event applied to a job. Pure, so the panel and the tests see the same thing. */
export function applyEvent(job: JobRecord, event: JobEvent, now: number): JobRecord {
  switch (event.type) {
    case "Started":
      return job;
    case "Progress": {
      const { type: _, ...progress } = event;
      let { rate, sample } = job;
      if (sample && now > sample.at) {
        const instant = ((progress.bytes_done - sample.bytes) * 1000) / (now - sample.at);
        rate = rate === undefined ? instant : rate * 0.7 + instant * 0.3;
      }
      sample = { at: now, bytes: progress.bytes_done };
      return { ...job, progress, rate, sample };
    }
    case "Log":
      return { ...job, logs: [...job.logs, { level: event.level, message: event.message }] };
    case "Prompt":
      return { ...job, prompts: [...job.prompts, { id: event.id, prompt: event.prompt }] };
    case "Partial":
      // Only the job's own listener (`JobMeta.onEvent`) wants these.
      return job;
    case "Finished":
      return { ...job, status: "finished", output: event.output, prompts: [], ended: now };
    case "Failed":
      return { ...job, status: "failed", error: event.error, prompts: [], ended: now };
    case "Cancelled":
      return { ...job, status: "cancelled", prompts: [], ended: now };
  }
}

/** The prompt to show: the oldest unanswered one, from the job that started first. */
export function nextPrompt(jobs: JobRecord[]): { job: JobRecord; pending: PendingPrompt } | undefined {
  for (const job of jobs) {
    if (job.prompts.length > 0) return { job, pending: job.prompts[0] };
  }
  return undefined;
}

type JobsState = {
  jobs: Record<JobId, JobRecord>;
  /** Job ids, oldest first. */
  order: JobId[];
  /** Called with a password typed into a tab's prompt. */
  onPassword?: (tab: string, password: string) => void;
  track: <K extends CommandName>(
    name: K,
    args: CommandMap[K]["input"],
    meta: JobMeta,
  ) => Promise<CommandMap[K]["output"]>;
  answer: (job: JobId, prompt: number, reply: PromptReply) => Promise<void>;
  cancel: (job: JobId) => Promise<void>;
  clearFinished: () => void;
};

export const useJobs = create<JobsState>((set, get) => ({
  jobs: {},
  order: [],

  track(name, args, meta) {
    let id: JobId | undefined;
    return run(name, args, (event) => {
      meta.onEvent?.(event);
      const now = Date.now();
      if (event.type === "Started") {
        id = event.job;
        const job = newJob(event.job, name, args, meta, now);
        set((s) => ({ jobs: { ...s.jobs, [job.id]: job }, order: [...s.order, job.id] }));
        return;
      }
      if (id === undefined) return;
      const key = id;
      set((s) => {
        const job = s.jobs[key];
        if (!job) return s;
        const jobs = { ...s.jobs, [key]: applyEvent(job, event, now) };
        // Quiet jobs leave no trace once they end.
        const ended = event.type === "Finished" || event.type === "Failed" || event.type === "Cancelled";
        if (job.quiet && ended) {
          delete jobs[key];
          return { jobs, order: s.order.filter((j) => j !== key) };
        }
        return { jobs };
      });
    });
  },

  async answer(job, prompt, reply) {
    const record = get().jobs[job];
    if (record?.tab && reply.kind === "Password") get().onPassword?.(record.tab, reply.password);
    set((s) => {
      const j = s.jobs[job];
      if (!j) return s;
      return { jobs: { ...s.jobs, [job]: { ...j, prompts: j.prompts.filter((p) => p.id !== prompt) } } };
    });
    try {
      await respond(job, prompt, reply);
    } catch {
      // The job ended meanwhile (cancelled); nothing is waiting.
    }
  },

  async cancel(job) {
    await cancel(job);
  },

  clearFinished() {
    set((s) => {
      const jobs = { ...s.jobs };
      const order = s.order.filter((id) => {
        if (jobs[id]?.status === "running") return true;
        delete jobs[id];
        return false;
      });
      return { jobs, order };
    });
  },
}));

/** Jobs in the order they started. */
export function orderedJobs(s: Pick<JobsState, "jobs" | "order">): JobRecord[] {
  return s.order.map((id) => s.jobs[id]).filter((j): j is JobRecord => j !== undefined);
}

export function runningCount(s: Pick<JobsState, "jobs">): number {
  return Object.values(s.jobs).filter((j) => j.status === "running").length;
}
