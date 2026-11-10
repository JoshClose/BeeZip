#!/bin/bash
# Makes tests/fixtures/thirdparty/ext/ (docs/M7.md §10): small ext images with the features BeeZip's
# own ext reader must handle, each checked by crates/beezip-core/src/format/volume/ext.rs's tests.
# Run it from the repository, in make-7z.sh's container (Ubuntu 24.04, e2fsprogs 1.47.0):
#
#   MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/tests/fixtures:/fixtures" beezip-fixtures-7z \
#       bash /fixtures/make-ext.sh
#
# - inline.img: inline_data. Small files in i_block, one running on into the system.data
#   attribute, folders inline (in i_block alone, and running on) and in blocks, a symlink of 80
#   bytes in inline data.
# - casefold.img: casefold, with a casefolded folder (made by debugfs: mke2fs can't).
# - metabg.img: meta_bg without resize_inode, 256 blocks to a group so that 17 groups make two
#   meta groups; folders are spread over the groups, some in the second meta group.
# - journal.img (ext4, metadata_csum, journal checksum v3, 64-bit tags) and journal-ext3.img
#   (ext3, classic tags, block maps): a journal that needs recovery, left by debugfs. Transaction
#   1 rewrites readme.txt's block, 2 rewrites other.txt's, 3 revokes other.txt's, so once
#   replayed readme.txt is "JOURNALED-BLOCK" and other.txt is unchanged. What e2fsck replays is
#   printed at the end, as the ground truth.
# - times.img: 256-byte inodes with times before 1970 and after 2038 (epoch bits), with
#   nanoseconds, set by debugfs since mke2fs drops the epoch bits.
# - encrypt.img: encrypt, with fscrypt's flag (the flag only: debugfs can't encrypt) on a folder,
#   a file and a symlink.
#
# mke2fs and debugfs run under a frozen libfaketime clock (2026-01-01), with fixed UUIDs, hash
# seeds and file times, so a rerun writes the same bytes.
set -euo pipefail
export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
E=1767225600 # 2026-01-01T00:00:00Z
faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
    NO_FAKE_STAT=1)
out=/fixtures/thirdparty/ext
mkdir -p "$out" /work
rm -f "$out"/*.img
u() { printf '6d7a6970-6265-457a-8970-0000000007%02d' "$1"; }
rand() { python3 -I -c 'import random,sys; sys.stdout.buffer.write(random.Random(int(sys.argv[1])).randbytes(int(sys.argv[2])))' "$@"; }
dfs() { "${faked[@]}" debugfs -w -f - "$1" >/dev/null 2>&1; }
# mke2fs -d copies each file's change time from the clock libfaketime doesn't reach: every inode
# reachable from the root gets 2026-01-01 instead.
ctimes() { # image
    python3 -I - "$1" "$E" <<'PY' | "${faked[@]}" debugfs -w -f - "$1" >/dev/null 2>&1
import re, subprocess, sys
img, e = sys.argv[1:3]
seen, todo = {2}, [2]
while todo:
    listing = subprocess.run(['debugfs', '-R', f'ls -l <{todo.pop()}>', img], capture_output=True, check=True)
    for line in listing.stdout.decode('utf-8', 'replace').split('\n'):
        m = re.match(r'^\s*(\d+)\s+(\d+) \(\d+\)', line)
        if m and int(m.group(1)) not in seen:
            seen.add(int(m.group(1)))
            if int(m.group(2), 8) & 0o170000 == 0o040000:
                todo.append(int(m.group(1)))
print('\n'.join(f'sif <{i}> ctime @{e}' for i in sorted(seen)))
PY
}
mk() { # name size dir n mke2fs-args...
    local name=$1 size=$2 dir=$3 n=$4
    shift 4
    find "$dir" -exec touch -h -d "@$E" {} +
    # One -E only: a second replaces the first. `ext` adds to it.
    "${faked[@]}" mke2fs -q -F -b 1024 -U "$(u "$n")" -E "hash_seed=$(u "$n"),root_owner=0:0${ext:-}" "$@" \
        -d "$dir" "$out/$name" "$size"
    ctimes "$out/$name"
}
ino() { debugfs -R "ls -l $2" "$1" 2>/dev/null | awk -v n="$3" '$NF == n { print $1 }'; }

# inline_data.
I=/work/inline
mkdir -p "$I/dir-small" "$I/dir-mid" "$I/dir-many"
printf 'tiny\n' > "$I/tiny.txt"
python3 -I -c 'import sys; sys.stdout.write("m" * 99 + "\n")' > "$I/medium.txt"
rand 1 5000 > "$I/big.bin"
printf 'a\n' > "$I/dir-small/a.txt"
for i in 1 2 3 4 5 6; do printf '%s\n' "$i" > "$I/dir-mid/file-$i.txt"; done
for i in $(seq -w 1 40); do printf '%s\n' "$i" > "$I/dir-many/entry-$i.txt"; done
ln -s tiny.txt "$I/short-link"
ln -s "$(python3 -I -c 'print("l/" * 39 + "xy", end="")')" "$I/long-link"
mk inline.img 512K "$I" 1 -t ext4 -O inline_data,^has_journal -I 256 -N 128 -L BeeZipInline
# A folder running on into system.data, as the kernel lets one that outgrows i_block do (e2fsprogs
# moves it to a block instead): two more entries for dir-small, to inodes made for them.
printf 'spilled\n' > /work/spill.txt
dfs "$out/inline.img" <<EOF
write /work/spill.txt /spill-1.txt
write /work/spill.txt /spill-2.txt
EOF
python3 -I - "$(ino "$out/inline.img" / spill-1.txt)" "$(ino "$out/inline.img" / spill-2.txt)" \
    > /work/sysdata <<'PY'
import struct, sys
a, b = (int(x) for x in sys.argv[1:3])
first = struct.pack('<IHBB', a, 20, 11, 1) + b'spill-1.txt' + b'\0'
second = struct.pack('<IHBB', b, 20, 11, 1) + b'spill-2.txt' + b'\0'
sys.stdout.buffer.write(first + second)
PY
dfs "$out/inline.img" <<EOF
unlink /spill-1.txt
unlink /spill-2.txt
ea_set -f /work/sysdata /dir-small system.data
sif /dir-small size 100
sif /spill-1.txt mtime @$E
EOF

# casefold.
C=/work/casefold
mkdir -p "$C"
printf 'plain\n' > "$C/plain.txt"
printf 'folded\n' > /work/folded.txt
ext=,encoding=utf8 mk casefold.img 256K "$C" 2 -t ext4 -O casefold,^has_journal -I 256 -N 64
dfs "$out/casefold.img" <<EOF
mkdir /Folded
sif /Folded flags 0x40080000
write /work/folded.txt /Folded/MixedCase.TXT
sif /Folded mtime @$E
sif /Folded/MixedCase.TXT mtime @$E
EOF

# meta_bg over two meta groups: 17 groups of 8 inodes, and enough files that the last ones are
# in group 16, whose descriptor is in the second meta group.
M=/work/metabg
mkdir -p "$M"
for i in $(seq -w 0 23); do
    mkdir "$M/d$i"
    printf 'file %s\n' "$i" > "$M/d$i/f.txt"
done
for i in $(seq -w 0 71); do printf 'more %s\n' "$i" > "$M/d23/more-$i.txt"; done
rand 2 1048576 > "$M/big.bin"
mk metabg.img 4352K "$M" 3 -t ext4 -O meta_bg,^resize_inode,^has_journal -g 256 -N 136 -I 256

# Journals that need recovery.
J=/work/journal
mkdir -p "$J"
printf 'Hello, BeeZip!\n' > "$J/readme.txt"
printf 'other\n' > "$J/other.txt"
printf 'kept\n' > "$J/kept.txt"
python3 -I -c 'import sys; d=b"JOURNALED-BLOCK\n"; sys.stdout.buffer.write(d * 64)' > /work/jblock
python3 -I -c 'import sys; d=b"REVOKED-BLOCK\n\n\n"; sys.stdout.buffer.write(d * 64)' > /work/rblock
mk journal.img 2M "$J" 4 -t ext4 -I 256 -N 64
mk journal-ext3.img 2M "$J" 5 -t ext3 -I 128 -N 64
for j in journal journal-ext3; do
    img="$out/$j.img"
    r=$(debugfs -R "bmap /readme.txt 0" "$img" 2>/dev/null)
    o=$(debugfs -R "bmap /other.txt 0" "$img" 2>/dev/null)
    csum=$([ "$j" = journal ] && echo -c || true)
    dfs "$img" <<EOF
jo $csum
jw -b $r /work/jblock
jw -b $o /work/rblock
jw -r $o /dev/null
jc
EOF
done

# Times before 1970 and after 2038, with nanoseconds (extra = nanoseconds << 2 | epoch).
T=/work/times
mkdir -p "$T"
for f in old future y2038; do printf '%s\n' "$f" > "$T/$f.txt"; done
mk times.img 256K "$T" 6 -t ext4 -O ^has_journal -I 256 -N 64
dfs "$out/times.img" <<EOF
sif /old.txt mtime @-315619200
sif /old.txt mtime_extra 1000000000
sif /old.txt crtime @-315619200
sif /old.txt crtime_extra 4
sif /future.txt mtime @4102444800
sif /future.txt mtime_extra 2000000001
sif /future.txt atime @4102444801
sif /future.txt atime_extra 1
sif /future.txt ctime @4102444802
sif /future.txt ctime_extra 5
sif /y2038.txt mtime @2147483648
sif /y2038.txt mtime_extra 1
EOF

# fscrypt's flag: on a folder (with extents), a file (with extents) and a fast symlink.
X=/work/encrypt
mkdir -p "$X/secret"
printf 'hidden\n' > "$X/secret/inside.txt"
printf 'locked\n' > "$X/locked.bin"
printf 'open\n' > "$X/open.txt"
ln -s open.txt "$X/locked-link"
mk encrypt.img 256K "$X" 7 -t ext4 -O encrypt,^has_journal -I 256 -N 64
dfs "$out/encrypt.img" <<EOF
sif /secret flags 0x80800
sif /locked.bin flags 0x80800
sif /locked-link flags 0x800
EOF

# What the tests rely on.
for f in "$out"/*.img; do
    echo "== $(basename "$f"): $(dumpe2fs -h "$f" 2>/dev/null | grep -E '^Filesystem features' | cut -d: -f2)"
done
echo "== inline.img"
for p in /tiny.txt /medium.txt /dir-small /dir-mid /dir-many /long-link; do
    printf '%s: ' "$p"
    debugfs -R "stat $p" "$out/inline.img" 2>/dev/null | grep -oE 'Flags: 0x[0-9a-f]+|Size of inline data: [0-9]+' | tr '\n' ' '
    echo
done
debugfs -R "ls /dir-small" "$out/inline.img" 2>/dev/null
echo "== metabg.img: inodes per group, and the last folder's inodes"
dumpe2fs -h "$out/metabg.img" 2>/dev/null | grep -E 'Inodes per group|Block count|Blocks per group|Group count|First meta'
debugfs -R "ls -l /d23" "$out/metabg.img" 2>/dev/null | awk '{print $1, $NF}' | tail -4 | tr '\n' ' '
echo
for j in journal journal-ext3; do
    cp "$out/$j.img" /work/replayed.img
    e2fsck -fy /work/replayed.img >/dev/null 2>&1 || true
    for p in /readme.txt /other.txt /kept.txt; do
        echo "== $j.img replayed by e2fsck: $p $(debugfs -R "cat $p" /work/replayed.img 2>/dev/null | sha256sum | cut -c1-64)"
    done
done
echo "== times.img"
for p in /old.txt /future.txt /y2038.txt; do
    debugfs -R "stat $p" "$out/times.img" 2>/dev/null | grep -E 'time:'
done
chown -R "${HOST_IDS:-0:0}" "$out"
/usr/bin/ls -la "$out"
