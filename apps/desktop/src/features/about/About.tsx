// About BeeZip: the version, the formats, the licenses and the third-party notices, which Vite
// imports from the repository at build time.
import { useEffect, useState } from "react";
import notices from "../../../../../THIRD_PARTY_NOTICES.md?raw";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import type { AppVersionOutput } from "../../gen/commands";
import { run } from "../../lib/engine";
import { useFormats } from "../../lib/formats";

function yes(v: boolean) {
  return v ? "Yes" : "";
}

export function About({ onClose }: { onClose: () => void }) {
  const [version, setVersion] = useState<AppVersionOutput>();
  const formats = useFormats();
  useEffect(() => {
    run("app.version", {}).then(setVersion, () => {});
  }, []);

  return (
    <Dialog open onClose={onClose} title="About BeeZip" className="w-[46rem]" footer={<Button onClick={onClose}>Close</Button>}>
      <div className="flex flex-col gap-4 pb-2">
        <p>
          {version ? (
            <>
              BeeZip {version.version}, {version.platform}, {version.profile} build
              {version.commit ? `, commit ${version.commit.slice(0, 12)}` : ""}.
            </>
          ) : (
            "BeeZip"
          )}{" "}
          Licensed under MIT or Apache-2.0, at your choice.
        </p>
        <section>
          <h3 className="mb-1.5 font-semibold">Formats</h3>
          <table className="w-full text-left">
            <thead className="text-[12px] text-muted">
              <tr>
                <th className="py-1 font-normal">Format</th>
                <th className="font-normal">Read</th>
                <th className="font-normal">Create</th>
                <th className="font-normal">Encrypt</th>
                <th className="font-normal">Volumes</th>
              </tr>
            </thead>
            <tbody>
              {formats?.formats.map((f) => (
                <tr key={f.id} className="border-t border-rule">
                  <td className="py-1">{f.name}</td>
                  <td>{yes(f.caps.list)}</td>
                  <td>{yes(f.caps.create)}</td>
                  <td>{yes(f.caps.encrypt)}</td>
                  <td>{yes(f.caps.volumes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {formats && (
            <p className="mt-1.5 text-muted">Codecs: {formats.codecs.map((c) => c.name).join(", ")}.</p>
          )}
        </section>
        <section>
          <h3 className="mb-1.5 font-semibold">Third-party notices</h3>
          <pre className="selectable max-h-72 overflow-auto rounded-[5px] bg-sunken p-3 font-mono text-[11.5px] whitespace-pre-wrap">{notices}</pre>
        </section>
      </div>
    </Dialog>
  );
}
