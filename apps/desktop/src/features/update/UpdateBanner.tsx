// The banner a new version shows (docs/M6.md §8.2): its version, a link to its release notes,
// and "Update and restart". Nothing downloads before that click, and while jobs run the update
// waits for them rather than cancelling them. A portable copy doesn't install updates: its
// banner's Download opens the new zip in the browser instead.
import { openUrl } from "@tauri-apps/plugin-opener";
import { X } from "lucide-react";
import { Button } from "../../components/ui/button";
import { runningCount, useJobs } from "../../lib/jobs";
import { type Progress, useUpdate } from "../../lib/updates";

function progressText(p: Progress): string {
  switch (p.stage) {
    case "downloading":
      return p.total ? `Downloading… ${Math.floor((p.done / p.total) * 100)}%` : "Downloading…";
    case "waiting":
      return p.jobs === 1 ? "Waiting for a job to finish…" : `Waiting for ${p.jobs} jobs to finish…`;
    case "installing":
      return "Installing; BeeZip restarts…";
  }
}

export function UpdateBanner() {
  const checked = useUpdate((s) => s.checked);
  const dismissed = useUpdate((s) => s.dismissed);
  const progress = useUpdate((s) => s.progress);
  const error = useUpdate((s) => s.error);
  const install = useUpdate((s) => s.install);
  const dismiss = useUpdate((s) => s.dismiss);
  const running = useJobs(runningCount);
  if (checked?.status !== "available" || (dismissed && !progress)) return null;
  const download = checked.download_url;

  return (
    <div role="status" aria-label="Update" className="flex items-center gap-3 border-b border-rule bg-amber-wash px-3 py-1.5 text-[13px]">
      <span className="font-semibold">BeeZip {checked.version} is available.</span>
      <button type="button" className="text-amber underline-offset-2 hover:underline" onClick={() => void openUrl(checked.notes_url)}>
        What's new
      </button>
      {error && <span className="text-danger">{error}</span>}
      <span className="flex-1" />
      {download ? (
        <Button variant="primary" size="sm" onClick={() => void openUrl(download)}>
          Download
        </Button>
      ) : progress ? (
        <span className="text-muted">{progressText(progress)}</span>
      ) : (
        <Button variant="primary" size="sm" onClick={() => void install()}>
          {running > 0 ? "Update when the jobs finish" : "Update and restart"}
        </Button>
      )}
      {!progress && (
        <Button variant="ghost" size="icon" aria-label="Not now" title="Not now" onClick={dismiss}>
          <X />
        </Button>
      )}
    </div>
  );
}
