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
} from "../gen/commands";

export type { CmdError, CommandInfo, CommandName, JobEvent, JobId };

/**
 * Runs a command and resolves with its output, or rejects with a `CmdError`.
 * `onEvent` sees every job event, including progress, as it happens.
 */
export function run<K extends CommandName>(
  name: K,
  args: CommandMap[K]["input"],
  onEvent?: (event: JobEvent) => void,
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
    // Tauri camelCases Rust argument names: `on_event` is `onEvent` here.
    invoke<JobId>("cmd_run", { name, args, onEvent: channel }).catch(reject);
  });
}

/** Requests cancellation of a running job. `false` if it already ended. */
export function cancel(job: JobId): Promise<boolean> {
  return invoke<boolean>("cmd_cancel", { job });
}

/** The commands the desktop app can run. */
export function listCommands(): Promise<CommandInfo[]> {
  return invoke<CommandInfo[]>("cmd_list");
}
