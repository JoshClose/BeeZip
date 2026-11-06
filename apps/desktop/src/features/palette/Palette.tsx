// The command palette (Ctrl+K), built with cmdk: the app's actions, then every registry
// command the GUI may run, from `cmd_list`.
import { Command } from "cmdk";
import { Search } from "lucide-react";
import { useEffect, useState } from "react";
import { type GuiCommand, listCommands } from "../../lib/engine";

export type PaletteAction = { id: string; label: string; hint?: string; run: () => void };

let commandsCache: Promise<GuiCommand[]> | undefined;

/** The registry's commands, fetched once. */
export function loadCommands(): Promise<GuiCommand[]> {
  commandsCache ??= listCommands().catch((e) => {
    commandsCache = undefined;
    throw e;
  });
  return commandsCache;
}

/** Forgets the fetched commands; for tests. */
export function resetCommands() {
  commandsCache = undefined;
}

/** Commands whose only inputs are the archive (and its password and name encoding) run on the current tab. */
export function takesOnlyArchive(c: GuiCommand): boolean {
  const props = Object.keys((c.input_schema.properties ?? {}) as object);
  return props.includes("archive") && props.every((p) => p === "archive" || p === "password" || p === "name_encoding");
}

/** Matches when every typed word appears in the item; names that start with the search rank first. */
export function paletteFilter(value: string, search: string): number {
  const v = value.toLowerCase();
  const words = search.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.every((w) => v.includes(w))) return 0;
  return v.startsWith(words[0] ?? "") ? 1 : 0.5;
}

const item =
  "flex h-9 cursor-default items-center gap-3 rounded-[5px] px-2.5 data-[selected=true]:bg-amber-wash aria-disabled:opacity-50";

export function Palette({
  open,
  onOpenChange,
  actions,
  onCommand,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  actions: PaletteAction[];
  onCommand: (command: GuiCommand) => void;
}) {
  const [commands, setCommands] = useState<GuiCommand[]>([]);
  useEffect(() => {
    if (!open) return;
    loadCommands().then(setCommands, () => {});
  }, [open]);

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Commands"
      filter={paletteFilter}
      overlayClassName="fixed inset-0 z-40 bg-black/30"
      contentClassName="fixed top-[14vh] left-1/2 z-50 w-[36rem] max-w-[calc(100vw-2rem)] -translate-x-1/2 overflow-hidden rounded-[8px] border border-rule bg-panel shadow-[0_12px_40px_rgba(0,0,0,0.25)]"
    >
      <div className="flex items-center gap-2 border-b border-rule px-3">
        <Search className="size-4 text-muted" />
        <Command.Input placeholder="Type a command or action…" className="h-11 flex-1 bg-transparent outline-none placeholder:text-muted" />
      </div>
      <Command.List className="max-h-[50vh] overflow-auto p-1.5">
        <Command.Empty className="px-3 py-6 text-center text-muted">No command matches.</Command.Empty>
        <Command.Group heading="BeeZip" className="[&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-[12px] [&_[cmdk-group-heading]]:text-muted">
          {actions.map((a) => (
            <Command.Item
              key={a.id}
              value={a.label}
              className={item}
              onSelect={() => {
                onOpenChange(false);
                a.run();
              }}
            >
              <span className="flex-1">{a.label}</span>
              {a.hint && <kbd className="text-[12px] text-muted">{a.hint}</kbd>}
            </Command.Item>
          ))}
        </Command.Group>
        <Command.Group heading="Commands" className="[&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-[12px] [&_[cmdk-group-heading]]:text-muted">
          {commands.map((c) => (
            <Command.Item
              key={c.name}
              value={`${c.name} ${c.description.split("\n")[0]}`}
              className={item}
              onSelect={() => {
                onOpenChange(false);
                onCommand(c);
              }}
            >
              <span className="w-36 shrink-0 font-semibold">{c.name}</span>
              <span className="truncate text-muted">{c.description.split(/\.\s|\n/)[0]}</span>
            </Command.Item>
          ))}
        </Command.Group>
      </Command.List>
    </Command.Dialog>
  );
}
