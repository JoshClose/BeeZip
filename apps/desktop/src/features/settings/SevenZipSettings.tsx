// The settings page's 7-Zip section (docs/M6.md §3.7, §3.8): which 7-Zip BeeZip runs for WIM, MSI
// and the disk images, where it was found, a button to install or update it, a path to choose
// another, and a switch to turn it off.
import { open as pickFile } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "lucide-react";
import { useEffect, useState } from "react";
import { SevenZipFix } from "../../components/SevenZipFix";
import { Button } from "../../components/ui/button";
import type { SevenZipConfig, SevenZipStatus } from "../../gen/commands";
import { refreshSevenZip, useSevenZip } from "../../lib/sevenZip";
import { startup } from "../../lib/startup";
import { CheckSetting, PathSetting, Section, Setting } from "./fields";

const FOUND_IN: Record<string, string> = {
  settings: "the path set here",
  registry: "7-Zip's installation",
  PATH: "PATH",
  "Program Files": "Program Files",
};

/** What `formats.list` says about 7-Zip, asked again whenever the settings change; an install
 * updates it too. */
function useStatus(config: SevenZipConfig): SevenZipStatus | undefined {
  // "Looking for 7-Zip…" until this ask answers, rather than what an earlier one found.
  const [asked, setAsked] = useState(false);
  useEffect(() => {
    let live = true;
    setAsked(false);
    void refreshSevenZip().finally(() => live && setAsked(true));
    return () => {
      live = false;
    };
  }, [config.path, config.enabled]);
  const status = useSevenZip((s) => s.status);
  return asked ? status : undefined;
}

/** What to do when there's no 7-Zip to use. */
function advice(status: SevenZipStatus): string {
  const min = status.min_version;
  switch (status.fix) {
    case "install":
      return ` Install 7-Zip ${min} or newer, or choose its 7z.exe below.`;
    case "update":
      return ` Update it to ${min} or newer, or choose a newer 7z.exe below.`;
    default:
      return startup().platform === "windows"
        ? ` Install 7-Zip ${min} or newer from 7-zip.org, or choose its 7z.exe below.`
        : ` Get 7-Zip's own 7zz ${min} or newer from 7-zip.org (distributions' packages are usually older), or choose it below.`;
  }
}

export function SevenZipSettings({
  config,
  errors,
  save,
}: {
  config: SevenZipConfig;
  errors: Record<string, string>;
  save: (key: string, value: unknown) => void;
}) {
  const status = useStatus(config);
  const browse = async () => {
    const file = await pickFile({
      title: "Choose 7-Zip's console program",
      defaultPath: config.path ?? status?.path ?? undefined,
      filters: [{ name: "7-Zip (7z.exe)", extensions: ["exe"] }],
    });
    if (typeof file === "string") save("seven_zip.path", file);
  };
  return (
    <Section
      title="7-Zip"
      description="BeeZip opens WIM images, MSI and NSIS installers, CHM files and disk images (VHD, VHDX, VMDK, QCOW2, VDI, FAT, NTFS, ext, HFS+, APFS) through an installed 7-Zip."
    >
      <div className="flex items-start gap-3">
        <p role="status" className="selectable min-w-0 flex-1 text-[12px]">
          {!status ? (
            <span className="text-muted">Looking for 7-Zip…</span>
          ) : status.name ? (
            <>
              Using {status.name}
              <span className="text-muted">
                {" "}
                at {status.path}
                {status.found_in && `, found through ${FOUND_IN[status.found_in] ?? status.found_in}`}.
              </span>
            </>
          ) : (
            <span className="text-danger">
              {config.enabled ? "No 7-Zip to use" : "Turned off"}
              {status.problem && config.enabled && `: ${status.problem}`}.{config.enabled && advice(status)}
            </span>
          )}
        </p>
        {status && !status.name && <SevenZipFix />}
      </div>
      <Setting label="7-Zip program" htmlFor="seven-zip-path" hint="Empty finds it: 7-Zip's installation, then PATH, then Program Files." error={errors["seven_zip.path"]}>
        <div className="flex gap-2">
          <PathSetting id="seven-zip-path" value={config.path} placeholder="Find it" onCommit={(v) => save("seven_zip.path", v)} />
          <Button size="sm" onClick={() => browse().catch(() => {})}>
            <FolderOpen /> Browse…
          </Button>
        </div>
      </Setting>
      <Setting label="Use 7-Zip" error={errors["seven_zip.enabled"]}>
        <CheckSetting checked={config.enabled} label="Open these formats through 7-Zip" onCommit={(v) => save("seven_zip.enabled", v)} />
      </Setting>
    </Section>
  );
}
