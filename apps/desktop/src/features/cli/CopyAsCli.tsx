// "Copy as CLI" on every dialog: the `beezip …` line `cli.line` builds, copied.
import { Check, Terminal } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import type { CliLineOutput } from "../../gen/commands";
import { run } from "../../lib/engine";
import { describeError } from "../../lib/format";
import { startup } from "../../lib/startup";

export async function cliLine(command: string, args: object): Promise<CliLineOutput> {
  return run("cli.line", { command, args: args as Record<string, unknown>, program: startup().cli });
}

export function CopyAsCli({ command, args, disabled }: { command: string; args: object; disabled?: boolean }) {
  const [shown, setShown] = useState<CliLineOutput>();
  const [error, setError] = useState<string>();
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    setError(undefined);
    let out: CliLineOutput;
    try {
      out = await cliLine(command, args);
      setShown(out);
    } catch (e) {
      const { code, message } = describeError(e);
      setError(`${code}: ${message}`);
      return;
    }
    try {
      await navigator.clipboard.writeText(out.line);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // The clipboard refuses a window without focus; the line is there to select.
      setError("Couldn't reach the clipboard. Select the line above and copy it.");
    }
  };

  // In a dialog's footer: the button at the left, and the line on a row of its own above.
  return (
    <>
      <div className="mr-auto">
        <Button size="sm" variant="ghost" onClick={copy} disabled={disabled} title="Copy the beezip command that does the same">
          {copied ? <Check /> : <Terminal />} {copied ? "Copied" : "Copy as CLI"}
        </Button>
      </div>
      {shown && (
        <div className="order-first mb-1 basis-full rounded-[5px] bg-sunken px-2 py-1.5" data-testid="cli-line">
          <code className="selectable block font-mono text-[12px] break-all">{shown.line}</code>
          {shown.omitted.length > 0 && (
            <p className="mt-1 text-[12px] text-muted">The password is left out; the command asks for it.</p>
          )}
        </div>
      )}
      {error && <p className="order-first basis-full text-[12px] text-danger">{error}</p>}
    </>
  );
}
