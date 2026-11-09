#!/usr/bin/env bash
# The files a release carries (release.yml's `release` job), from the platforms' artifacts in
# <dir>. Before 1.0.0 the Windows installer and its .sig are taken out: until then Windows gets
# the portable zip only. The platforms' latest.json files are merged into <out>, naming only the
# files left. With no latest.json (no updater key), <out> isn't written.
#
# Usage: release-files.sh <dir> <version> <out>
set -euo pipefail
dir=$1
version=$2
out=$3

if [ "${version%%.*}" -eq 0 ]; then
  find "$dir" \( -name '*-setup.exe' -o -name '*-setup.exe.sig' \) -print -delete
fi

mapfile -t parts < <(find "$dir" -name latest.json | sort)
if [ ${#parts[@]} -eq 0 ]; then
  echo "no updater manifest: the release has no updater signature"
  exit 0
fi
jq -e -s 'map(.version) | unique | length == 1' "${parts[@]}" > /dev/null \
  || { echo "::error::the platforms' latest.json name different versions"; exit 1; }
names=$(find "$dir" -type f ! -name latest.json -printf '%f\n' | jq -R . | jq -s -c .)
jq -s --argjson names "$names" \
  '.[0] + {platforms: (map(.platforms) | add | with_entries(select(.value.url | split("/") | last | IN($names[]))))}' \
  "${parts[@]}" > "$out"
cat "$out"
