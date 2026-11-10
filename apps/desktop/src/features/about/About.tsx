// About BeeZip: the version and "Check for updates", the formats, the licenses and the
// third-party notices, which Vite imports from the repository at build time.
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import type { AppVersionOutput } from "../../gen/commands";
import { run } from "../../lib/engine";
import { useFormats } from "../../lib/formats";
import { useUpdate } from "../../lib/updates";

function yes(v: boolean) {
  return v ? "Yes" : "";
}

// The notices are some 400 KB: a chunk of their own, loaded when the page opens (docs/M6.md §9.1).
function Notices() {
  const [text, setText] = useState<string>();
  useEffect(() => {
    import("../../../../../THIRD_PARTY_NOTICES.md?raw").then(
      (m) => setText(m.default),
      () => setText("The notices couldn't be loaded. THIRD_PARTY_NOTICES.md is next to BeeZip.exe."),
    );
  }, []);
  return (
    <pre className="selectable max-h-72 overflow-auto rounded-[5px] bg-sunken p-3 font-mono text-[11.5px] whitespace-pre-wrap">{text ?? "Loading…"}</pre>
  );
}

/** "Check for updates": asks GitHub now, whatever the setting and the day (docs/M6.md §8.2). */
function UpdateCheck() {
  const checked = useUpdate((s) => s.checked);
  const checking = useUpdate((s) => s.checking);
  const error = useUpdate((s) => s.error);
  const check = useUpdate((s) => s.check);
  const [asked, setAsked] = useState(false);
  let answer = "";
  if (checking) answer = "Checking…";
  else if (asked && error) answer = error;
  else if (asked && checked?.status === "up_to_date") answer = `BeeZip ${checked.version} is the newest version.`;
  else if (asked && checked?.status === "available")
    answer = `BeeZip ${checked.version} is available: the banner below the tabs ${checked.download_url ? "downloads" : "installs"} it.`;
  else if (asked && checked?.status === "off") answer = checked.reason;
  return (
    <div className="flex items-center gap-3">
      <Button
        size="sm"
        disabled={checking}
        onClick={() => {
          setAsked(true);
          void check(true);
        }}
      >
        Check for updates
      </Button>
      <span role="status" aria-label="Update check" className="text-muted">
        {answer}
      </span>
    </div>
  );
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
        <UpdateCheck />
        <section>
          <h3 className="mb-1.5 font-semibold">Formats</h3>
          <table className="w-full text-left">
            <thead className="text-[12px] text-muted">
              <tr>
                <th className="py-1 font-normal">Format</th>
                <th className="font-normal">Read</th>
                <th className="font-normal">Create</th>
                <th className="font-normal">Encrypt</th>
              </tr>
            </thead>
            <tbody>
              {formats?.formats.map((f) => (
                <tr key={f.id} className="border-t border-rule">
                  <td className="py-1">{f.name}</td>
                  <td>{yes(f.caps.list)}</td>
                  <td>{yes(f.caps.create)}</td>
                  <td>{yes(f.caps.encrypt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {formats && (
            <p className="mt-1.5 text-muted">
              Codecs: {formats.codecs.map((c) => c.name).join(", ")}. Every format can be split into volumes
              (&ldquo;a.zip.001&rdquo;&hellip;), and a split archive opens from any of its parts.
            </p>
          )}
        </section>
        <section>
          <h3 className="mb-1.5 font-semibold">Third-party notices</h3>
          <Notices />
        </section>
      </div>
    </Dialog>
  );
}
