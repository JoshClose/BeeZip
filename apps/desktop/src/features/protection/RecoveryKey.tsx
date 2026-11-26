// A new recovery key, shown once (docs/M14.md §8): after creating or converting an archive with
// one, or adding one in "Who can open this". BeeZip never stores it, so the dialog offers Copy,
// Save and Print, and closes once the person has kept it one way or another.
import { invoke } from "@tauri-apps/api/core";
import { Copy, Printer, Save } from "lucide-react";
import { useState } from "react";
import { create } from "zustand";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import { baseName } from "../../lib/format";
import { toastError } from "../../lib/toasts";

type Shown = { archive: string; key: string };

type RecoveryState = {
  /** Oldest first; the dialog shows the first. */
  queue: Shown[];
  show: (archive: string, key: string) => void;
  done: () => void;
};

export const useRecoveryKeys = create<RecoveryState>((set) => ({
  queue: [],
  show(archive, key) {
    set((s) => ({ queue: [...s.queue, { archive, key }] }));
  },
  done() {
    set((s) => ({ queue: s.queue.slice(1) }));
  },
}));

/** Shows the recovery key a command returned, if it made one. */
export function showRecoveryKey(archive: string, out: { recovery_key?: string }) {
  if (out.recovery_key) useRecoveryKeys.getState().show(archive, out.recovery_key);
}

/** What Save writes and Print prints. */
export function recoveryText(archive: string, key: string): string {
  return [
    `BeeZip recovery key for ${baseName(archive)}`,
    "",
    key,
    "",
    `It opens ${archive} when every other way in fails.`,
    "Anyone who has it can open the archive: keep it somewhere safe, away from the archive.",
    "",
  ].join("\n");
}

/** Prints `lines` alone: the page is hidden while a sheet with them is printed. */
export function printSheet(title: string, lines: string[]) {
  // One left from a print whose afterprint never came: it shows only on paper, so it waited.
  for (const old of document.querySelectorAll(".print-sheet")) old.remove();
  const sheet = document.createElement("div");
  sheet.className = "print-sheet";
  const h = document.createElement("h1");
  h.textContent = title;
  sheet.append(h);
  for (const line of lines) {
    const p = document.createElement("p");
    p.textContent = line;
    sheet.append(p);
  }
  document.body.append(sheet);
  document.documentElement.classList.add("printing");
  const cleanup = () => {
    document.documentElement.classList.remove("printing");
    sheet.remove();
    window.removeEventListener("afterprint", cleanup);
  };
  window.addEventListener("afterprint", cleanup);
  window.print();
}

export function RecoveryKeyDialog() {
  const shown = useRecoveryKeys((s) => s.queue[0]);
  const done = useRecoveryKeys((s) => s.done);
  const [kept, setKept] = useState<string>();
  const [noted, setNoted] = useState(false);
  const [error, setError] = useState<string>();
  if (!shown) return null;
  const { archive, key } = shown;
  const name = baseName(archive);
  const stem = name.replace(/\.bhive$/i, "");
  const finish = () => {
    setKept(undefined);
    setNoted(false);
    setError(undefined);
    done();
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(key);
      setKept("Copied. Paste it somewhere safe before you copy anything else.");
      setError(undefined);
    } catch {
      setError("Couldn't reach the clipboard. Select the key and copy it.");
    }
  };
  const save = async () => {
    try {
      const path = await invoke<string | null>("cmd_save_text", { name: `${stem} recovery key.txt`, text: recoveryText(archive, key) });
      if (path) {
        setKept(`Saved to ${path}. Keep the file somewhere other than beside the archive.`);
        setError(undefined);
      }
    } catch (e) {
      toastError(e, "Saving the recovery key");
    }
  };
  const print = () => {
    printSheet(`BeeZip recovery key for ${name}`, [key, `It opens ${archive} when every other way in fails.`, "Anyone who has it can open the archive: keep it somewhere safe."]);
    setKept("Sent to the printer. Keep the page somewhere safe.");
  };

  return (
    <Dialog
      open
      dismissable={false}
      onClose={() => {}}
      title="Your recovery key"
      description={`It opens ${name} when every other way in fails. BeeZip shows it this once and doesn't keep it.`}
      className="w-[40rem]"
      footer={
        <>
          <Button onClick={() => void copy()}>
            <Copy /> Copy
          </Button>
          <Button onClick={() => void save()}>
            <Save /> Save…
          </Button>
          <Button onClick={print}>
            <Printer /> Print…
          </Button>
          <span className="flex-1" />
          <Button variant="primary" disabled={!kept && !noted} onClick={finish}>
            Done
          </Button>
        </>
      }
    >
      <p data-testid="recovery-key" className="selectable my-2 rounded-[5px] border border-rule bg-paper px-3 py-3 text-center font-mono text-[15px] tracking-wide break-all">
        {key}
      </p>
      <p className="pb-2 text-[12px] text-muted">Anyone who has it can open the archive. Keep it away from the archive: on paper, or in a password manager.</p>
      {kept && (
        <p role="status" className="pb-2 text-[12px]">
          {kept}
        </p>
      )}
      {error && (
        <p role="alert" className="pb-2 text-[12px] text-danger">
          {error}
        </p>
      )}
      <div className="pb-2">
        <Checkbox checked={noted} onChange={setNoted} label="I've written it down" />
      </div>
    </Dialog>
  );
}
