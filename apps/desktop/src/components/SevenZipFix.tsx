// "Install 7-Zip", "Update 7-Zip" or "Get 7-Zip…" (docs/M6.md §3.8): beside an error that says
// 7-Zip is missing or too old, and in Settings → 7-Zip.
import { Download, LoaderCircle } from "lucide-react";
import { useEffect } from "react";
import { fixLabel, fixSevenZip, needsSevenZip, refreshSevenZip, useSevenZip } from "../lib/sevenZip";
import { Button } from "./ui/button";

/**
 * The fix `formats.list` names, asked again when this appears: 7-Zip may have come or gone
 * since. Given an `error`, it shows only for 7-Zip's. Nothing shows when there's no fix: 7-Zip
 * is there, turned off, or set to a path in Settings.
 */
export function SevenZipFix({
  error,
  size = "sm",
  variant = "default",
  className,
}: {
  error?: unknown;
  size?: "sm" | "md";
  variant?: "default" | "primary";
  className?: string;
}) {
  const wanted = error === undefined || needsSevenZip(error);
  const fix = useSevenZip((s) => s.status?.fix);
  const installing = useSevenZip((s) => s.installing);
  useEffect(() => {
    if (wanted) void refreshSevenZip();
  }, [wanted]);
  if (!wanted) return null;
  if (installing) {
    return (
      <Button size={size} variant={variant} className={className} disabled>
        <LoaderCircle className="animate-spin" /> {fix === "update" ? "Updating 7-Zip…" : "Installing 7-Zip…"}
      </Button>
    );
  }
  if (!fix) return null;
  return (
    <Button
      size={size}
      variant={variant}
      className={className}
      onClick={() => void fixSevenZip(fix)}
      title={fix === "download" ? "Opens 7-Zip's download page" : "winget downloads 7-Zip's own installer and checks it; Windows then asks for administrator rights"}
    >
      <Download /> {fixLabel(fix)}
    </Button>
  );
}
