#!/usr/bin/env bash
# The release notes for one version: its section of CHANGELOG.md, without the `## X.Y.Z` line
# (release.yml's `release` job puts it under the platform notes). Fails when the changelog has no
# section for the version, so a release never goes out without saying what's new.
#
# Usage: changelog-notes.sh <CHANGELOG.md> <version>
set -euo pipefail
changelog=$1
version=$2

notes=$(awk -v v="$version" '
  /^## / { if (found) exit; if ($2 == v) { found = 1; next } }
  found { print }
' "$changelog")
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "::error::CHANGELOG.md has no section for $version: add \"## $version\" with what's new, and tag again" >&2
  exit 1
fi
# Wrapped lines joined, since GitHub shows a newline in release notes as a line break: an item's
# indented continuation onto the item, and a paragraph's lines onto one.
printf '%s\n' "$notes" | sed -e '/./,$!d' | awk '
  /^ +[^ ]/ && prev != "" { sub(/^ +/, ""); prev = prev " " $0; next }
  /^[^-#[:space:]]/ && prev ~ /^[^-#[:space:]]/ { prev = prev " " $0; next }
  { if (started) print prev; prev = $0; started = 1 }
  END { if (started) print prev }
'
