#!/bin/bash
# CI's macOS job (docs/M5.md §10): the ISO and DMG BeeZip wrote on the Linux job, checked by
# macOS itself. Each image is attached read-only and every file's SHA-256 compared with
# hashes.json (names compared in NFC: HFS+ shows them decomposed). A DMG is also checked by
# `hdiutil verify` (its checksums) and `fsck_hfs -n` (the volume), attached without mounting.
#
#   bash .github/scripts/mac-images.sh <folder with t.iso, t.dmg and hashes.json>
set -euo pipefail

dir="$1"
want="$dir/hashes.json"
[ -f "$want" ] || { echo "no $want" >&2; exit 1; }
sw_vers
checked=0

# Every file under $1 with its SHA-256, as JSON keyed by NFC path, against $2.
compare() {
    python3 -I - "$1" "$2" <<'PY'
import hashlib, json, os, sys, unicodedata
root, want = sys.argv[1], json.load(open(sys.argv[2], encoding="utf-8"))
got = {}
for d, _, files in os.walk(root):
    for f in files:
        p = os.path.join(d, f)
        rel = unicodedata.normalize("NFC", os.path.relpath(p, root).replace(os.sep, "/"))
        if not rel.startswith("tree/"):
            continue
        with open(p, "rb") as fh:
            got[rel[len("tree/"):]] = hashlib.sha256(fh.read()).hexdigest()
if got != want:
    for k in sorted(set(got) | set(want)):
        if got.get(k) != want.get(k):
            print(f"  {k}: got {got.get(k)}, want {want.get(k)}")
    sys.exit(f"{root}: the files differ")
print(f"  {len(got)} files match")
PY
}

for img in "$dir"/*.iso "$dir"/*.dmg; do
    [ -f "$img" ] || continue
    echo "== $(basename "$img")"
    case "$img" in
    *.dmg)
        hdiutil verify "$img"
        # The volume's device: the line of `hdiutil attach` that names an HFS+ partition (the
        # whole disk, for an image without a partition map).
        out="$(hdiutil attach -readonly -nobrowse -nomount "$img")"
        echo "$out"
        dev="$(echo "$out" | awk '/Apple_HFS/ { print $1; exit }')"
        disk="$(echo "$out" | awk 'NR == 1 { print $1 }')"
        [ -n "$dev" ] || { echo "no HFS+ volume in $img" >&2; exit 1; }
        fsck_hfs -n "$dev"
        hdiutil detach "$disk"
        ;;
    esac
    mnt="$(mktemp -d)"
    hdiutil attach -readonly -nobrowse -mountpoint "$mnt" "$img"
    status=0
    compare "$mnt" "$want" || status=$?
    hdiutil detach "$mnt" || hdiutil detach -force "$mnt"
    [ "$status" -eq 0 ] || exit "$status"
    checked=$((checked + 1))
done
[ "$checked" -ge 2 ] || { echo "only $checked images checked" >&2; exit 1; }
echo "checked $checked images"
