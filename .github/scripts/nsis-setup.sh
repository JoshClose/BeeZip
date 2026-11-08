#!/bin/bash
# BeeZip's own installer as an NSIS sample (docs/M6.md §10): BeeZip detects it, lists it, tests
# it and extracts it through 7-Zip (staged, since 7-Zip only estimates an NSIS file's size), and
# gets the same files as `7z x`. Run from the repository after `cargo xtask dist --debug`.
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

hashes() { (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum); }
diff <(hashes "$work/beezip") <(hashes "$work/7z")
if find "$work/beezip" -name '.beezip-7z-*' | grep -q .; then
    echo "the staging folder was left behind" >&2
    exit 1
fi
echo "BeeZip's installer extracts as 7-Zip extracts it: $(hashes "$work/beezip" | wc -l) files"
