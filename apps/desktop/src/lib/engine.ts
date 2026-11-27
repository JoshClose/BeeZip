// The only hand-written binding to the Rust engine. Types come from ../gen/commands.ts, which
// `cargo xtask codegen` generates from the command registry.
import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  CmdError,
  CommandInfo,
  CommandMap,
  CommandName,
  JobEvent,
  JobId,
  PromptReply,
} from "../gen/commands";

export type { CmdError, CommandInfo, CommandName, JobEvent, JobId };

/** A JSON schema, as schemars writes it. */
export type JsonSchema = { [key: string]: unknown };

/** A command the page may run, with the schema the palette builds its form from. */
export type GuiCommand = CommandInfo & { input_schema: JsonSchema };

/**
 * Runs a command and resolves with its output, or rejects with a `CmdError`.
 * `onEvent` sees every job event as it happens; `Started`, with the job id, comes first.
 * `forTab`: the job belongs to a tab of the main window, so an encrypted archive it unlocks
 * stays unlocked until the tab closes (docs/M14.md §8). Without it, the job opens archives
 * from what tabs kept unlocked, and keeps nothing.
 */
export function run<K extends CommandName>(
  name: K,
  args: CommandMap[K]["input"],
  onEvent?: (event: JobEvent) => void,
  forTab?: boolean,
): Promise<CommandMap[K]["output"]> {
  return new Promise((resolve, reject) => {
    const channel = new Channel<JobEvent>();
    channel.onmessage = (event) => {
      onEvent?.(event);
      switch (event.type) {
        case "Finished":
          resolve(event.output as CommandMap[K]["output"]);
          break;
        case "Failed":
          reject(event.error);
          break;
        case "Cancelled":
          reject({ code: "Cancelled", message: "cancelled" } satisfies CmdError);
          break;
      }
    };
    // Tauri camelCases Rust argument names: `on_event` is `onEvent` here, `for_tab` `forTab`.
    invoke<JobId>("cmd_run", { name, args, onEvent: channel, ...(forTab ? { forTab: true } : {}) }).catch(reject);
  });
}

/** Requests cancellation of a running job, and answers its pending prompt with `Cancel`. */
export function cancel(job: JobId): Promise<boolean> {
  return invoke<boolean>("cmd_cancel", { job });
}

/** Answers a job's `Prompt` event. */
export function respond(job: JobId, prompt: number, reply: PromptReply): Promise<void> {
  return invoke<void>("cmd_respond", { job, prompt, reply });
}

/** The commands the desktop app can run. */
export function listCommands(): Promise<GuiCommand[]> {
  return invoke<GuiCommand[]>("cmd_list");
}

/** Locks the archive at `path` again: what unlocked it for this window's jobs is wiped from
 * memory, so the next job on it asks again (docs/M14.md §8). Resolves with how many ways in
 * were forgotten. */
export function lock(path: string): Promise<number> {
  return invoke<number>("cmd_lock", { path });
}
