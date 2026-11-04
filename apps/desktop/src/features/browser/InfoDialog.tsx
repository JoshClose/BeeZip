// `archive.info` for a tab's archive.
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import type { ArchiveInfoOutput, CmdError } from "../../gen/commands";
import { type Tab, useArchives } from "../../lib/archives";
import { describeError, formatSize } from "../../lib/format";
import { useJobs } from "../../lib/jobs";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-3 border-t border-rule py-1.5 first:border-t-0">
      <dt className="text-muted">{label}</dt>
      <dd className="selectable min-w-0 break-words">{children}</dd>
    </div>
  );
}

export function InfoDialog({ tab, onClose }: { tab: Tab; onClose: () => void }) {
  const update = useArchives((s) => s.update);
  const [info, setInfo] = useState<ArchiveInfoOutput | undefined>(tab.info);
  const [error, setError] = useState<CmdError>();
  useEffect(() => {
    if (info) return;
    useJobs
      .getState()
      .track("archive.info", { archive: tab.path, ...(tab.password ? { password: tab.password } : {}) }, { title: `Reading ${tab.name}`, quiet: true, tab: tab.id })
      .then((i) => {
        setInfo(i);
        update(tab.id, { info: i });
      }, setError);
  }, [info, tab, update]);

  const encryption = { none: "None", some: "Some entries", all: "Every entry" };
  return (
    <Dialog open onClose={onClose} title={tab.name} description={tab.path} className="w-[38rem]" footer={<Button onClick={onClose}>Close</Button>}>
      {error && <p className="selectable text-danger">{`${describeError(error).code}: ${describeError(error).message}`}</p>}
      {!info && !error && <p className="text-muted">Reading…</p>}
      {info && (
        <dl className="pb-2">
          <Row label="Format">{info.chain}</Row>
          <Row label="Entries">
            {info.entries.toLocaleString()}: {info.files.toLocaleString()} files, {info.dirs.toLocaleString()} folders, {info.links.toLocaleString()} links
          </Row>
          <Row label="Size">
            {formatSize(info.size)} in {formatSize(info.packed_size)} ({Math.round(info.ratio * 100)}%)
          </Row>
          {info.methods.length > 0 && <Row label="Methods">{info.methods.join(", ")}</Row>}
          <Row label="Encryption">
            {encryption[info.encryption]}
            {info.encrypted_headers ? ", names included" : ""}
          </Row>
          <Row label="Solid">
            {info.solid ? "Yes" : "No"}
            {info.solid_blocks !== null ? ` (${info.solid_blocks} blocks)` : ""}
          </Row>
          {info.sfx && <Row label="Self-extracting">Yes</Row>}
          {info.volumes.length > 1 && (
            <Row label="Volumes">
              <ul>
                {info.volumes.map((v) => (
                  <li key={v}>{v}</li>
                ))}
              </ul>
            </Row>
          )}
          {info.locked && <Row label="Locked">Yes, against changes</Row>}
          {info.recovery_record && <Row label="Recovery record">Yes</Row>}
          {info.comment && (
            <Row label="Comment">
              <pre className="font-sans whitespace-pre-wrap">{info.comment}</pre>
            </Row>
          )}
        </dl>
      )}
    </Dialog>
  );
}
