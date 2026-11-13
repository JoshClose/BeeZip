#!/bin/bash
# BeeZip's own installer as an NSIS sample (docs/M6.md §10, docs/M10.md §7): BeeZip detects it,
# lists it, tests it and extracts it with its own reader, and gets the same files as `7z x`, and
# the uninstaller, which 7-Zip may leave out. Run from the repository after
# `cargo xtask dist --debug`.
set -euo pipefail

setup=$(find target/dist/debug/bundle/nsis -name '*-setup.exe' | head -n 1)
[ -n "$setup" ] || { echo "no installer under target/dist/debug/bundle/nsis" >&2; exit 1; }
beezip=target/debug/beezip.exe
seven='/c/Program Files/7-Zip/7z.exe'
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export BEEZIP_CONFIG="$work/config.toml"

"$beezip" detect "$setup" | tee "$work/detect.txt"
grep -q ': nsis' "$work/detect.txt" || { echo "not detected as an NSIS installer" >&2; exit 1; }
"$beezip" list --flat "$setup"
"$beezip" info "$setup"
"$beezip" test "$setup"
"$beezip" x "$setup" -o "$work/beezip" --overwrite always
"$seven" x -sns- -y -o"$work/7z" "$setup" > /dev/null

# The uninstaller: BeeZip rebuilds it as WriteUninstaller writes it, and it's an NSIS
# uninstaller. 7-Zip leaves it out of some of BeeZip's installers (its guess at the instruction
# layout marks one of Tauri's instructions bad) and writes it from others, such as CI's: where
# 7-Zip writes it, the two must be the same file.
un="$work/beezip/uninstall.exe"
[ -f "$un" ] || { echo "no uninstall.exe" >&2; exit 1; }
"$beezip" info "$un" | tee "$work/un.txt"
grep -q 'nsis kind: uninstaller' "$work/un.txt" || { echo "uninstall.exe isn't an NSIS uninstaller" >&2; exit 1; }
[ -e "$work/7z/uninstall.exe" ] || rm "$un"

hashes() { (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum); }
diff <(hashes "$work/beezip") <(hashes "$work/7z")
if find "$work/beezip" -name '.beezip-7z-*' | grep -q .; then
    echo "the staging folder was left behind" >&2
    exit 1
fi
echo "BeeZip's installer extracts as 7-Zip extracts it: $(hashes "$work/beezip" | wc -l) files"
