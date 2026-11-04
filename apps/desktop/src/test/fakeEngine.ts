// A stand-in for ../lib/engine: tests register a handler per command and see every call.
// Use it with `vi.mock("../lib/engine", () => import("./fakeEngine"))`.
import { vi } from "vitest";
import type { JobEvent, PromptReply } from "../gen/commands";
import type { GuiCommand } from "../lib/engine";

type Handler = (args: unknown, emit: (e: JobEvent) => void) => unknown | Promise<unknown>;

export const fake = {
  handlers: new Map<string, Handler>(),
  calls: [] as { name: string; args: unknown }[],
  replies: [] as { job: number; prompt: number; reply: PromptReply }[],
  commands: [] as GuiCommand[],
  nextJob: 1,
  reset() {
    this.handlers.clear();
    this.calls = [];
    this.replies = [];
    this.commands = [];
    this.nextJob = 1;
  },
};

export const run = vi.fn(async (name: string, args: unknown, onEvent?: (e: JobEvent) => void) => {
  fake.calls.push({ name, args });
  const job = fake.nextJob++;
  const emit = (e: JobEvent) => onEvent?.(e);
  emit({ type: "Started", job });
  const handler = fake.handlers.get(name);
  try {
    if (!handler) throw { code: "NotFound", message: `no fake for ${name}` };
    const output = await handler(args, emit);
    emit({ type: "Finished", output: output as never });
    return output;
  } catch (error) {
    emit({ type: "Failed", error: error as never });
    throw error;
  }
});

export const cancel = vi.fn(async () => true);

export const respond = vi.fn(async (job: number, prompt: number, reply: PromptReply) => {
  fake.replies.push({ job, prompt, reply });
});

export const listCommands = vi.fn(async () => fake.commands);
