// Password and overwrite prompts (docs/M3.md §5.3): modal, one at a time, queued when several
// jobs ask. Each answer goes back through `cmd_respond`.
import { Eye, EyeOff, KeyRound } from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { Input } from "../../components/ui/input";
import type { OverwriteChoice, PromptReply } from "../../gen/commands";
import { baseName } from "../../lib/format";
import { nextPrompt, orderedJobs, useJobs } from "../../lib/jobs";

export function PasswordPrompt({
  entry,
  title,
  onReply,
  kept = true,
}: {
  entry: string | null;
  title: string;
  onReply: (reply: PromptReply) => void;
  /** The password is kept for the archive's tab. A job window has no tab, so it isn't. */
  kept?: boolean;
}) {
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const submit = () => onReply({ kind: "Password", password });
  return (
    <Dialog
      open
      dismissable={false}
      onClose={() => onReply({ kind: "Cancel" })}
      title="Password needed"
      description={entry ? `${title}: “${baseName(entry)}” is encrypted.` : `${title}: the archive is encrypted.`}
      footer={
        <>
          <Button onClick={() => onReply({ kind: "Cancel" })}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={password.length === 0}>
            <KeyRound /> Unlock
          </Button>
        </>
      }
    >
      <form
        className="flex items-center gap-2 pb-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (password) submit();
        }}
      >
        <Input
          autoFocus
          aria-label="Password"
          type={visible ? "text" : "password"}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="flex-1"
        />
        <Button size="icon" onClick={() => setVisible(!visible)} aria-label={visible ? "Hide password" : "Show password"}>
          {visible ? <EyeOff /> : <Eye />}
        </Button>
      </form>
      <p className="pb-1 text-[12px] text-muted">
        {kept ? "BeeZip keeps it in memory for this archive until you close it, and never saves it." : "BeeZip uses it for this job only, and never saves it."}
      </p>
    </Dialog>
  );
}

const CHOICES: { choice: OverwriteChoice; label: string }[] = [
  { choice: "Replace", label: "Replace" },
  { choice: "ReplaceAll", label: "Replace all" },
  { choice: "Skip", label: "Skip" },
  { choice: "SkipAll", label: "Skip all" },
  { choice: "Rename", label: "Keep both" },
];

export function OverwritePrompt({
  path,
  archive,
  title,
  onReply,
}: {
  path: string;
  /** Set when adding to an archive: `path` is an entry in it (docs/M5.md §7.1). */
  archive?: string;
  title: string;
  onReply: (reply: PromptReply) => void;
}) {
  return (
    <Dialog
      open
      dismissable={false}
      onClose={() => onReply({ kind: "Cancel" })}
      title={archive ? `${baseName(path)} is already in ${baseName(archive)}` : "A file with this name exists"}
      description={title}
      className="w-[38rem]"
      footer={
        <>
          <Button onClick={() => onReply({ kind: "Cancel" })}>Cancel</Button>
          <span className="flex-1" />
          {CHOICES.map((c) => (
            <Button
              key={c.choice}
              variant={c.choice === "Replace" ? "primary" : "default"}
              onClick={() => onReply({ kind: "Overwrite", choice: c.choice })}
            >
              {c.label}
            </Button>
          ))}
        </>
      }
    >
      <p className="selectable pb-2 break-all">{path}</p>
      <p className="pb-1 text-[12px] text-muted">
        {archive
          ? "“Replace” puts the new file in its place; “Keep both” adds it under a new name, such as “name (1).txt”."
          : "“Keep both” extracts it under a new name, such as “name (1).txt”."}
      </p>
    </Dialog>
  );
}

/** The prompt in front, if any job is asking. */
export function Prompts() {
  const jobs = useJobs((s) => s.jobs);
  const order = useJobs((s) => s.order);
  const answer = useJobs((s) => s.answer);
  const next = useMemo(() => nextPrompt(orderedJobs({ jobs, order })), [jobs, order]);
  if (!next) return null;
  const { job, pending } = next;
  const reply = (r: PromptReply) => void answer(job.id, pending.id, r);
  const key = `${job.id}-${pending.id}`;
  return pending.prompt.kind === "Password" ? (
    <PasswordPrompt key={key} entry={pending.prompt.entry} title={job.title} onReply={reply} kept={job.tab !== undefined} />
  ) : (
    <OverwritePrompt key={key} path={pending.prompt.path} archive={pending.prompt.archive} title={job.title} onReply={reply} />
  );
}
