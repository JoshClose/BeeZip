// The settings page's 7-Zip section (docs/M6.md §3.7): which 7-Zip BeeZip runs for WIM, MSI and
// the disk images, where it was found, a path to choose another, and a switch to turn it off.
import { open as pickFile } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "../../components/ui/button";
import type { SevenZipConfig, SevenZipStatus } from "../../gen/commands";
import { run } from "../../lib/engine";
import { forgetFormats } from "../../lib/formats";
import { CheckSetting, PathSetting, Section, Setting } from "./fields";

const FOUND_IN: Record<string, string> = {
  settings: "the path set here",
  registry: "7-Zip's installation",
  PATH: "PATH",
  "Program Files": "Program Files",
};

/** What `formats.list` says about 7-Zip, asked again whenever the settings change. */
function useSevenZip(config: SevenZipConfig): SevenZipStatus | undefined {
  const [status, setStatus] = useState<SevenZipStatus>();
  useEffect(() => {
    let live = true;
    forgetFormats();
    run("formats.list", {}).then(
      (f) => live && setStatus(f.seven_zip),
      () => {},
    );
    return () => {
      live = false;
    };
  }, [config.path, config.enabled]);
  return status;
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
  const status = useSevenZip(config);
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
      <p role="status" className="selectable text-[12px]">
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
            {status.problem && config.enabled && `: ${status.problem}`}.
            {config.enabled && ` Install 7-Zip ${status.min_version} or newer from 7-zip.org, or choose its 7z.exe below.`}
          </span>
        )}
      </p>
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
