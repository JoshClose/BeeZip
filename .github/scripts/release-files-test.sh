#!/usr/bin/env bash
# release-files.sh on made-up artifacts (CI's Linux job), so release.yml's choice of files is
# checked before a tag needs it: before 1.0.0 the Windows installer and its latest.json entry
# go, and the portable zip and the other platforms stay; from 1.0.0 everything stays; platforms
# naming different versions stop it; without any latest.json nothing is written.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "::error::$*"; exit 1; }

# The three platforms' artifacts for version $2, as release.yml downloads them, in $1.
artifacts() {
  local d=$1 v=$2
  local base="https://github.com/JoshClose/BeeZip/releases/download/v$v"
  mkdir -p "$d/windows" "$d/linux" "$d/macos"
  for f in "BeeZip_${v}_x64-setup.exe" "BeeZip_${v}_x64-setup.exe.sig" \
    "BeeZip_${v}_x64-portable.zip" "BeeZip_${v}_x64-portable.zip.sig"; do
    echo x > "$d/windows/$f"
  done
  jq -n --arg v "$v" --arg b "$base" '{version: $v, notes: "n", pub_date: "2026-11-09T00:00:00Z",
    platforms: {"windows-x86_64-nsis": {signature: "s1", url: "\($b)/BeeZip_\($v)_x64-setup.exe"},
                "windows-x86_64-portable": {signature: "s2", url: "\($b)/BeeZip_\($v)_x64-portable.zip"}}}' \
    > "$d/windows/latest.json"
  for f in "beezip_${v}_amd64.deb" "beezip_${v}_amd64.deb.sig"; do echo x > "$d/linux/$f"; done
  jq -n --arg v "$v" --arg b "$base" '{version: $v, notes: "n", pub_date: "2026-11-09T00:00:00Z",
    platforms: {"linux-x86_64-deb": {signature: "s3", url: "\($b)/beezip_\($v)_amd64.deb"}}}' \
    > "$d/linux/latest.json"
  for f in "BeeZip_${v}_aarch64.dmg" "BeeZip_${v}_aarch64.app.tar.gz" "BeeZip_${v}_aarch64.app.tar.gz.sig"; do
    echo x > "$d/macos/$f"
  done
  jq -n --arg v "$v" --arg b "$base" '{version: $v, notes: "n", pub_date: "2026-11-09T00:00:00Z",
    platforms: {"darwin-aarch64-app": {signature: "s4", url: "\($b)/BeeZip_\($v)_aarch64.app.tar.gz"}}}' \
    > "$d/macos/latest.json"
}

# Before 1.0.0: no installer.
artifacts "$work/early" 0.2.0
bash "$here/release-files.sh" "$work/early" 0.2.0 "$work/early.json" > /dev/null
[ -z "$(find "$work/early" -name '*-setup.exe*')" ] || fail "0.2.0 kept the installer"
[ -f "$work/early/windows/BeeZip_0.2.0_x64-portable.zip" ] || fail "0.2.0 lost the portable zip"
[ -f "$work/early/windows/BeeZip_0.2.0_x64-portable.zip.sig" ] || fail "0.2.0 lost the portable zip's .sig"
keys=$(jq -c '.platforms | keys' "$work/early.json")
[ "$keys" = '["darwin-aarch64-app","linux-x86_64-deb","windows-x86_64-portable"]' ] \
  || fail "0.2.0's latest.json names $keys"
[ "$(jq -r '.version + " " + .pub_date' "$work/early.json")" = "0.2.0 2026-11-09T00:00:00Z" ] \
  || fail "0.2.0's latest.json lost its version or date"

# From 1.0.0: everything.
artifacts "$work/one" 1.0.0
bash "$here/release-files.sh" "$work/one" 1.0.0 "$work/one.json" > /dev/null
[ -f "$work/one/windows/BeeZip_1.0.0_x64-setup.exe" ] || fail "1.0.0 lost the installer"
keys=$(jq -c '.platforms | keys' "$work/one.json")
[ "$keys" = '["darwin-aarch64-app","linux-x86_64-deb","windows-x86_64-nsis","windows-x86_64-portable"]' ] \
  || fail "1.0.0's latest.json names $keys"

# Platforms built from different versions.
artifacts "$work/mixed" 0.2.0
jq '.version = "0.1.9"' "$work/mixed/linux/latest.json" > "$work/l.json"
mv "$work/l.json" "$work/mixed/linux/latest.json"
if bash "$here/release-files.sh" "$work/mixed" 0.2.0 "$work/mixed.json" > /dev/null; then
  fail "latest.json files of different versions were merged"
fi

# No updater key: no latest.json anywhere, and none written.
artifacts "$work/nokey" 0.2.0
find "$work/nokey" -name latest.json -delete
bash "$here/release-files.sh" "$work/nokey" 0.2.0 "$work/nokey.json" > /dev/null
[ ! -e "$work/nokey.json" ] || fail "a latest.json was written without any"

echo "release-files.sh: all ok"
