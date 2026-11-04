// The report of an extraction that met unsafe entries: what was skipped, and what renamed.
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import type { ArchiveExtractOutput, CmdError } from "../../gen/commands";

export function ReportDialog({ title, error, onClose }: { title: string; error: CmdError; onClose: () => void }) {
  const report = (error.details ?? {}) as Partial<ArchiveExtractOutput>;
  const skipped = report.skipped ?? [];
  const renamed = report.renamed ?? [];
  return (
    <Dialog
      open
      onClose={onClose}
      title="Entries that weren't extracted as stored"
      description={`${title}: ${error.message}`}
      className="w-[44rem]"
      footer={<Button onClick={onClose}>Close</Button>}
    >
      {skipped.length > 0 && (
        <>
          <h3 className="mt-1 mb-1 font-semibold">Skipped ({report.skipped_total ?? skipped.length})</h3>
          <ul className="selectable mb-3 flex flex-col gap-1">
            {skipped.map((s, i) => (
              <li key={i}>
                <code className="font-mono text-[12px]">{s.path}</code>
                <span className="text-muted">: {s.reason}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {renamed.length > 0 && (
        <>
          <h3 className="mb-1 font-semibold">Renamed ({report.renamed_total ?? renamed.length})</h3>
          <ul className="selectable flex flex-col gap-1">
            {renamed.map((r, i) => (
              <li key={i}>
                <code className="font-mono text-[12px]">{r.from}</code> <span className="text-muted">became</span>{" "}
                <code className="font-mono text-[12px]">{r.to}</code>
              </li>
            ))}
          </ul>
        </>
      )}
      {skipped.length === 0 && renamed.length === 0 && <p className="text-muted">The report is empty.</p>}
    </Dialog>
  );
}
