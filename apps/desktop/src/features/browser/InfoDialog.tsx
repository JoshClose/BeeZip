// `archive.info` for a tab's archive, and the encoding its names are read in.
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import type { ArchiveInfoOutput, CmdError } from "../../gen/commands";
import { archiveArgs, type Tab, useArchives } from "../../lib/archives";
import { describeError, formatSize } from "../../lib/format";
import { useJobs } from "../../lib/jobs";
import { ENCODING_HINT, EncodingSelect } from "./EncodingSelect";

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
  // What this dialog fetched, for the encoding it was fetched with: choosing another reads the
  // archive's comment again.
  const encoding = tab.encoding ?? "";
  const [fetched, setFetched] = useState<{ encoding: string; info: ArchiveInfoOutput }>();
  const [error, setError] = useState<CmdError>();
  const info = tab.info ?? (fetched?.encoding === encoding ? fetched.info : undefined);
  useEffect(() => {
    if (info) return;
    let live = true;
    setError(undefined);
    useJobs
      .getState()
      .track("archive.info", { archive: tab.path, ...archiveArgs(tab) }, { title: `Reading ${tab.name}`, quiet: true, tab: tab.id })
      .then(
        (i) => {
          if (!live) return;
          setFetched({ encoding, info: i });
          update(tab.id, { info: i });
        },
        (e) => live && setError(e),
      );
    return () => {
      live = false;
    };
  }, [info, encoding, tab, update]);

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
      <div className="grid grid-cols-[10rem_1fr] gap-3 border-t border-rule pt-2 pb-1">
        <label htmlFor="info-encoding" className="pt-1.5 text-muted">
          Name encoding
        </label>
        <div className="flex min-w-0 flex-col gap-1">
          <EncodingSelect tab={tab} id="info-encoding" />
          <p className="text-[12px] text-muted">{ENCODING_HINT}</p>
        </div>
      </div>
    </Dialog>
  );
}
