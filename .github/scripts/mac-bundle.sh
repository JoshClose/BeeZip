#!/usr/bin/env bash
# CI's checks of the macOS app and disk image that `cargo xtask dist --debug` built (docs/M6.md
# §9.7, §8.3). Nobody here has a Mac, so this is where they're seen working:
# - the app's and the CLI's signatures, and what Info.plist declares;
# - the CLI inside the app;
# - files opened the way Finder opens them (`open -a`, an Apple event, RunEvent::Opened), with
#   BeeZip not running and then running: the debug build says on stderr where each went, and the
#   page takes them (open.rs `trace`);
# - the disk image.
# It stops only the BeeZip it started, by that process's id.
set -euo pipefail
bundle=$(cd "${1:?usage: mac-bundle.sh <target/dist/PROFILE/bundle>}" && pwd)
app="$bundle/macos/BeeZip.app"   # absolute: `open -a` takes a path only when it is
dmg=$(find "$bundle/dmg" -name 'BeeZip_*_aarch64.dmg' | head -n 1)
fixture="$PWD/tests/fixtures/thirdparty/7z-deflate.zip"
[ -d "$app" ] && [ -f "$dmg" ] && [ -f "$fixture" ] || { echo "::error::missing: $app, $dmg or $fixture"; exit 1; }
fail() { echo "::error::$*"; exit 1; }

echo "== signatures"
codesign --verify --deep --strict --verbose=2 "$app"
codesign -dv "$app" 2>&1 | grep -E '^(Identifier|Format|CodeDirectory|Signature|Sealed)'
codesign -dv "$app/Contents/MacOS/bin/beezip" 2>&1 | grep -E '^(Identifier|Format|CodeDirectory|Signature)'

echo "== Info.plist"
plist="$app/Contents/Info.plist"
[ "$(plutil -extract CFBundleExecutable raw "$plist")" = BeeZip ] || fail "CFBundleExecutable isn't BeeZip"
plutil -extract CFBundleIdentifier raw "$plist"
plutil -convert json -o "$RUNNER_TEMP/info.json" "$plist"
python3 - "$RUNNER_TEMP/info.json" <<'EOF'
import json, sys
info = json.load(open(sys.argv[1]))
types = info.get("CFBundleDocumentTypes", [])
exts = {e for t in types for e in t.get("CFBundleTypeExtensions", [])}
utis = {u for t in types for u in t.get("LSItemContentTypes", [])}
print(f"{len(types)} document types; content types: {sorted(utis)}")
print(f"extensions: {' '.join(sorted(exts))}")
for want in ["zip", "7z", "rar", "tar", "gz", "xz", "zst", "xar", "arj"]:
    assert want in exts, f"{want} isn't associated"
for owned in ["dmg", "iso", "pkg", "mpkg"]:
    assert owned not in exts, f"{owned} is macOS's"
for uti in ["public.zip-archive", "org.7-zip.7-zip-archive", "public.tar-archive"]:
    assert uti in utis, f"{uti} isn't declared"
zip = next(t for t in types if "zip" in t.get("CFBundleTypeExtensions", []))
assert zip.get("CFBundleTypeName") == "ZIP archive", zip
EOF

echo "== the CLI inside the app"
cli="$app/Contents/MacOS/bin/beezip"
"$cli" --version
"$cli" list "$fixture" | head -n 5

echo "== files opened as Finder opens them"
work=$(mktemp -d)
printf '[updates]\ncheck = false\n' > "$work/config.toml"
log="$work/app.log"
: > "$log"
cp "$fixture" "$work/second.zip"
exe="$app/Contents/MacOS/BeeZip"
# Waits for a line of BeeZip's trace matching $1.
wait_for() {
  for _ in $(seq 1 120); do
    grep -qE "$1" "$log" && return 0
    sleep 0.5
  done
  echo "--- BeeZip said:"; cat "$log"
  fail "BeeZip never said: $1"
}
# BeeZip isn't running: macOS starts it, then hands it the file (RunEvent::Opened at startup).
open -a "$app" --env "BEEZIP_CONFIG=$work/config.toml" --stdout "$log" --stderr "$log" "$fixture"
wait_for "macOS asked to open .*7z-deflate\.zip"
wait_for "(the page took|sent to the page: ).*7z-deflate\.zip"
pid=$(pgrep -f -- "$exe" | head -n 1 || true)
[ -n "$pid" ] || fail "BeeZip isn't running"
echo "BeeZip is running as $pid"
# It's running: the next file goes to the same process.
open -a "$app" "$work/second.zip"
wait_for "sent to the page: .*second\.zip"
[ "$(pgrep -f -- "$exe" | wc -l | tr -d ' ')" = 1 ] || fail "a second BeeZip started"
echo "--- BeeZip said:"; cat "$log"
osascript -e 'tell application id "app.beezip.desktop" to quit' || true
for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$pid" 2>/dev/null; then
  echo "BeeZip didn't quit when asked; stopping $pid"
  kill "$pid"
fi

echo "== the disk image"
mnt="$work/mnt"
mkdir "$mnt"
hdiutil attach -nobrowse -readonly -mountpoint "$mnt" "$dmg" > /dev/null
trap 'hdiutil detach "$mnt" > /dev/null 2>&1 || true' EXIT
[ -d "$mnt/BeeZip.app" ] || fail "the disk image has no BeeZip.app"
[ -L "$mnt/Applications" ] || fail "the disk image has no Applications link"
codesign --verify --deep --strict "$mnt/BeeZip.app"
ls -la "$mnt"
du -sh "$app" "$dmg"
echo "macOS bundle checks passed"
