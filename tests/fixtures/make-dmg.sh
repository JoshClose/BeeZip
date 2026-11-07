#!/bin/bash
# Makes the DMG fixtures (docs/M5.md §10) on macOS, which nobody here has: run by
# .github/workflows/make-dmg.yml on GitHub's macos-latest runner, as
#
#   bash tests/fixtures/make-dmg.sh OUT
#
# OUT (the workflow's artifact) gets:
#   dmg/*.dmg           the images, for tests/fixtures/thirdparty/dmg/
#   dmg-manifest.json   their records, to merge into tests/fixtures/manifest.json
#   udif.json           each image's trailer and partition tables as hdiutil wrote them, with
#                       its checksums worked out again here
#   tools.txt           sw_vers, hdiutil's frameworks, afsctool's version, what was skipped
#   beezip-check.txt    hdiutil imageinfo, verify, fsck_hfs and a read-only attach of an image
#                       BeeZip wrote (tests/fixtures/malicious/traversal.dmg)
#
# The tree is BeeZip's own, so the images hold no app's binaries: text, fixed pseudo-random bytes,
# an empty file, a Unicode name, a folder two deep, an executable, a symlink and a compressible
# file of several 64 KiB blocks, with fixed times. It's imaged as HFS+ and APFS in UDZO, UDBZ,
# ULFO, ULMO and UDRO (`hdiutil create -srcfolder`), and as HFS+ without a partition map, with the
# old Apple partition map, and in UDCO (ADC) where hdiutil still makes it. Two more images, HFS+
# and APFS, hold Apple-compressed files (decmpfs): made read-write, filled with `ditto` and
# `ditto --hfsCompression`, with `afsctool -c -T ZLIB|LZVN|LZFSE` where afsctool is installed
# (small files land inline, large ones in the resource fork), and a hard link, then converted to
# UDZO.
#
# The records come from the images, each attached read-only: every file's size, SHA-256, mode
# and time, every link's target, and each compressed file's decmpfs type and size, read with
# XATTR_SHOWCOMPRESSION. Paths are from the volume's root, as BeeZip lists them; HFS+'s names are
# composed (NFC), as BeeZip lists them. What macOS hides (the journal, HFS+'s private folders)
# isn't in the records, though BeeZip lists it.
#
# Written for macOS's /bin/bash 3.2 and python3. Every step that macOS may refuse (a format it no
# longer makes, afsctool missing) is skipped and noted in tools.txt rather than failing the run.
set -euo pipefail

out="${1:?usage: make-dmg.sh OUT}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
# The devices attached, one per line, so they're detached however the script ends.
: > "$work/mounts"
cleanup() {
    while read -r dev; do
        [ -n "$dev" ] && hdiutil detach -force "$dev" >/dev/null 2>&1 || true
    done < "$work/mounts"
    rm -rf "$work"
}
trap cleanup EXIT

export LC_ALL=en_US.UTF-8 TZ=UTC
stamp=202601010000 # touch -t: 2026-01-01T00:00:00Z

mkdir -p "$out/dmg"
out="$(cd "$out" && pwd)"
: > "$work/commands.tsv"
tools="$out/tools.txt"
{
    sw_vers
    echo
    uname -a
    echo
    hdiutil info | sed -n '1,4p'
} > "$tools"

note() {
    echo "$*" | tee -a "$tools" >&2
}

# hdiutil now and then fails with a busy resource on CI's runners: try three times.
retry() {
    local n
    for n in 1 2 3; do
        if "$@"; then
            return 0
        fi
        echo "retrying ($n): $*" >&2
        sleep 5
    done
    return 1
}

# Reads `hdiutil attach -plist`: the mount point (empty with -nomount), then the whole disk.
cat > "$work/attached.py" <<'PY'
import plistlib, sys
ents = plistlib.load(open(sys.argv[1], 'rb'))['system-entities']
print(next((e['mount-point'] for e in ents if 'mount-point' in e), ''))
print(min((e['dev-entry'] for e in ents), key=len))
PY

# attach ARGS... IMAGE: attaches it, and sets $mnt and $dev.
attach() {
    local plist="$work/attach.plist"
    retry hdiutil attach -nobrowse -noautoopen -noverify -plist "$@" > "$plist" || return 1
    python3 -I -B "$work/attached.py" "$plist" > "$work/attached.txt" || return 1
    mnt="$(sed -n 1p "$work/attached.txt")"
    dev="$(sed -n 2p "$work/attached.txt")"
    echo "$dev" >> "$work/mounts"
}

detach() {
    retry hdiutil detach "$1" >/dev/null
    grep -vxF "$1" "$work/mounts" > "$work/mounts.left" || true
    mv "$work/mounts.left" "$work/mounts"
}

# The tree, and the files to compress.
python3 -I -B - "$work" <<'PY'
import os, random, sys
work = sys.argv[1]
tree = os.path.join(work, 'tree')
os.makedirs(os.path.join(tree, 'sub', 'nested'))
def put(rel, data, mode=0o644):
    p = os.path.join(tree, rel)
    with open(p, 'wb') as f:
        f.write(data)
    os.chmod(p, mode)
put('readme.txt', b"BeeZip's DMG fixtures, made by tests/fixtures/make-dmg.sh on GitHub's macOS runner.\n" * 20)
put('empty.txt', b'')
put('random.bin', random.Random(42).randbytes(70_000))
put('Ünïcödé café 日本.txt', 'non-ASCII names\n'.encode())
put('sub/nested/deep.txt', b'a file two folders down\n')
put('tool.sh', b'#!/bin/sh\necho BeeZip\n', 0o755)
put('blocks.txt', b''.join(b'line %06d of a file of several 64 KiB blocks\n' % i for i in range(7000)))
os.symlink('readme.txt', os.path.join(tree, 'link-to-readme'))
comp = os.path.join(work, 'comp')
os.makedirs(comp)
with open(os.path.join(comp, 'small.txt'), 'wb') as f:
    f.write(b'a small file, which compresses into the attribute\n' * 40)
with open(os.path.join(comp, 'large.txt'), 'wb') as f:
    f.write(b''.join(b'%06d: a large file, which compresses into the resource fork\n' % i for i in range(4000)))
PY
find "$work/tree" "$work/comp" -exec touch -h -t "$stamp" {} +

# image NAME HDIUTIL-ARGS...: runs hdiutil with OUT/dmg/NAME last, and records the command.
image() {
    local name="$1"
    shift
    rm -f "$out/dmg/$name"
    if retry hdiutil "$@" "$out/dmg/$name" >/dev/null; then
        printf '%s\thdiutil %s %s\n' "$name" "$*" "$name" | sed "s|$work/||g" >> "$work/commands.tsv"
    else
        rm -f "$out/dmg/$name"
        note "skipped $name: hdiutil $* failed"
    fi
}

for fs in HFS+ APFS; do
    tag="$(echo "$fs" | tr 'A-Z' 'a-z' | tr -d '+')"
    vol="BeeZip $(echo "$fs" | tr -d '+')"
    for fmt in UDZO UDBZ ULFO ULMO UDRO; do
        image "$tag-$(echo "$fmt" | tr 'A-Z' 'a-z').dmg" create -quiet -srcfolder "$work/tree" \
            -volname "$vol" -fs "$fs" -format "$fmt"
    done
done
image hfs-none-udzo.dmg create -quiet -srcfolder "$work/tree" -volname "BeeZip HFS" -fs HFS+ \
    -format UDZO -layout NONE
image hfs-apm-udzo.dmg create -quiet -srcfolder "$work/tree" -volname "BeeZip HFS" -fs HFS+ \
    -format UDZO -layout SPUD
image hfs-udco.dmg create -quiet -srcfolder "$work/tree" -volname "BeeZip HFS" -fs HFS+ \
    -format UDCO

# Apple-compressed files, written into a read-write image and converted to UDZO.
if command -v afsctool >/dev/null; then
    afsctool 2>&1 | sed -n '1,2p' >> "$tools" || true
    have_afsctool=1
else
    note "afsctool isn't installed: only ditto --hfsCompression's own type is made"
    have_afsctool=0
fi
for fs in HFS+ APFS; do
    tag="$(echo "$fs" | tr 'A-Z' 'a-z' | tr -d '+')"
    rw="$work/$tag-rw.dmg"
    retry hdiutil create -quiet -size 32m -fs "$fs" -volname "BeeZip $(echo "$fs" | tr -d '+') decmpfs" \
        -layout GPTSPUD -type UDIF "$rw"
    attach "$rw"
    ditto "$work/tree" "$mnt/plain"
    ln "$mnt/plain/readme.txt" "$mnt/plain/hard-readme"
    ditto --hfsCompression "$work/comp" "$mnt/ditto"
    if [ "$have_afsctool" = 1 ]; then
        for t in ZLIB LZVN LZFSE; do
            ditto "$work/comp" "$mnt/$t"
            afsctool -c -T "$t" "$mnt/$t/small.txt" "$mnt/$t/large.txt" \
                || note "afsctool -c -T $t failed on $fs"
        done
    fi
    find "$mnt" -mindepth 1 -not -path "$mnt/.*" -exec touch -h -t "$stamp" {} + 2>/dev/null || true
    sync
    detach "$dev"
    image "$tag-decmpfs-udzo.dmg" convert -quiet "$rw" -format UDZO -o
done

# The records: each image attached read-only and walked.
for img in "$out"/dmg/*.dmg; do
    name="$(basename "$img")"
    # With owners on, files show the owners the volume gives them, not the user mounting it.
    attach -readonly -owners on "$img"
    # sudo: .fseventsd and .Trashes are root's.
    sudo python3 -I -B - "$mnt" "$work/walk-$name.json" <<'PY'
import ctypes, hashlib, json, os, stat, sys, unicodedata
mnt, dest = sys.argv[1:3]
# (Off macOS, where the script's logic is tried against stub tools, there's no decmpfs.)
libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True) if sys.platform == 'darwin' else None
if libc:
    libc.getxattr.restype = ctypes.c_ssize_t
    libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                              ctypes.c_uint32, ctypes.c_int]
XATTR_NOFOLLOW, XATTR_SHOWCOMPRESSION, UF_COMPRESSED = 0x0001, 0x0020, 0x20
fstype = os.popen(f'diskutil info -plist "{mnt}" | plutil -extract FilesystemType raw -o - - 2>/dev/null').read().strip()


def decmpfs(path):
    opts = XATTR_NOFOLLOW | XATTR_SHOWCOMPRESSION
    n = libc.getxattr(path.encode(), b'com.apple.decmpfs', None, 0, 0, opts)
    if n < 16:
        return None
    buf = ctypes.create_string_buffer(n)
    n = libc.getxattr(path.encode(), b'com.apple.decmpfs', buf, n, 0, opts)
    raw = buf.raw[:n]
    if raw[:4] != b'fpmc':
        return {'magic': raw[:4].hex()}
    return {'type': int.from_bytes(raw[4:8], 'little'), 'size': int.from_bytes(raw[8:16], 'little'),
            'attribute_bytes': n}


def show(rel):
    return unicodedata.normalize('NFC', rel) if fstype.startswith('hfs') else rel


entries, dirs = [], []
for top, dnames, fnames in os.walk(mnt):
    dnames.sort()
    for d in list(dnames):
        p = os.path.join(top, d)
        rel = os.path.relpath(p, mnt)
        if os.path.islink(p):
            dnames.remove(d)
            fnames.append(d)
            continue
        dirs.append(show(rel))
    for f in sorted(fnames):
        p = os.path.join(top, f)
        rel = show(os.path.relpath(p, mnt))
        st = os.lstat(p)
        common = {'path': rel, 'mode': oct(st.st_mode & 0o7777), 'mtime': int(st.st_mtime),
                  'uid': st.st_uid, 'gid': st.st_gid}
        if stat.S_ISLNK(st.st_mode):
            entries.append({'kind': 'symlink', 'target': os.readlink(p), **common})
            continue
        if not stat.S_ISREG(st.st_mode):
            entries.append({'kind': 'other', **common})
            continue
        h = hashlib.sha256()
        with open(p, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                h.update(chunk)
        e = {'kind': 'file', 'size': st.st_size, 'sha256': h.hexdigest(), **common,
             'nlink': st.st_nlink}
        if libc and st.st_flags & UF_COMPRESSED:
            e['decmpfs'] = decmpfs(p)
        entries.append(e)
json.dump({'filesystem': fstype, 'entries': entries, 'dirs': dirs}, open(dest, 'w'),
          ensure_ascii=False, indent=1)
PY
    detach "$dev"
done

# The manifest fragment and udif.json.
python3 -I -B - "$out" "$work" <<'PY'
import bz2, glob, json, lzma, os, plistlib, platform, subprocess, sys, zlib
out, work = sys.argv[1:3]
macos = subprocess.run(['sw_vers', '-productVersion'], capture_output=True, text=True).stdout.strip()
build = subprocess.run(['sw_vers', '-buildVersion'], capture_output=True, text=True).stdout.strip()
producer = f'hdiutil on macOS {macos} ({build}), GitHub macos-latest'
commands = dict(l.rstrip('\n').split('\t', 1) for l in open(os.path.join(work, 'commands.tsv')) if '\t' in l)

be32 = lambda b, a: int.from_bytes(b[a:a + 4], 'big')
be64 = lambda b, a: int.from_bytes(b[a:a + 8], 'big')
DECODERS = {
    0x80000005: zlib.decompress,
    0x80000006: bz2.decompress,
    0x80000008: lzma.decompress,
    0x00000001: lambda b: b,
}


def checksum(b, at):
    return {'type': be32(b, at), 'bits': be32(b, at + 4), 'value': f'{be32(b, at + 8):08X}'}


def udif(path):
    data = open(path, 'rb').read()
    k = data[-512:]
    koly = {
        'version': be32(k, 4), 'header_size': be32(k, 8), 'flags': be32(k, 12),
        'running_data_fork_offset': be64(k, 16), 'data_fork_offset': be64(k, 24),
        'data_fork_length': be64(k, 32), 'rsrc_fork_offset': be64(k, 40),
        'rsrc_fork_length': be64(k, 48), 'segment_number': be32(k, 56),
        'segment_count': be32(k, 60), 'segment_id': k[64:80].hex(),
        'data_checksum': checksum(k, 80), 'xml_offset': be64(k, 216), 'xml_length': be64(k, 224),
        'master_checksum': checksum(k, 352), 'image_variant': be32(k, 488),
        'sector_count': be64(k, 492),
    }
    df = data[koly['data_fork_offset']:koly['data_fork_offset'] + koly['data_fork_length']]
    koly['data_fork_crc32_here'] = f'{zlib.crc32(df):08X}'
    xml = data[koly['xml_offset']:koly['xml_offset'] + koly['xml_length']]
    plist = plistlib.loads(xml)
    rf = plist.get('resource-fork', {})
    parts, sums = [], b''
    for e in rf.get('blkx', []):
        m = e['Data']
        runs, kinds = [], {}
        for i in range(be32(m, 200)):
            r = m[204 + 40 * i:244 + 40 * i]
            runs.append((be32(r, 0), be64(r, 8), be64(r, 16), be64(r, 24), be64(r, 32)))
            kinds[f'{be32(r, 0):08X}'] = kinds.get(f'{be32(r, 0):08X}', 0) + 1
        part = {
            'Name': e.get('Name'), 'CFName': e.get('CFName'), 'ID': e.get('ID'),
            'Attributes': e.get('Attributes'), 'first_sector': be64(m, 8), 'sectors': be64(m, 16),
            'data_offset': be64(m, 24), 'buffers_needed': be32(m, 32),
            'block_descriptors': f'{be32(m, 36):08X}', 'checksum': checksum(m, 64),
            'chunks': be32(m, 200), 'chunk_types': kinds,
            'largest_chunk_sectors': max([r[2] for r in runs if r[0] not in (0x7FFFFFFE, 0xFFFFFFFF)] or [0]),
        }
        sums += m[72:76]
        # The partition's CRC32, worked out here when its codecs are python's: of every chunk
        # but the ignored ones (type 2), and of all its sectors.
        try:
            skip, every = 0, 0
            for kind, sector, count, off, length in runs:
                if kind in (0x7FFFFFFE, 0xFFFFFFFF) or count == 0:
                    continue
                if kind in (0, 2):
                    raw = bytes(count * 512)
                else:
                    at = koly['data_fork_offset'] + be64(m, 24) + off
                    raw = DECODERS[kind](data[at:at + length]).ljust(count * 512, b'\0')
                every = zlib.crc32(raw, every)
                if kind != 2:
                    skip = zlib.crc32(raw, skip)
            part['crc32_without_ignored_here'] = f'{skip:08X}'
            part['crc32_of_all_here'] = f'{every:08X}'
        except KeyError:
            part['crc32_here'] = 'a codec python lacks'
        parts.append(part)
    koly['master_crc32_of_partition_crcs_here'] = f'{zlib.crc32(sums):08X}'
    return {'koly': koly, 'resources': sorted(rf), 'other_plist_keys': sorted(k for k in plist if k != 'resource-fork'),
            'partitions': parts}


records, layouts = [], {}
for path in sorted(glob.glob(os.path.join(out, 'dmg', '*.dmg'))):
    name = os.path.basename(path)
    layouts[name] = udif(path)
    walk = json.load(open(os.path.join(work, f'walk-{name}.json')))
    fs = 'APFS' if name.startswith('apfs') else 'HFS+'
    entries = [e for e in walk['entries'] if e['kind'] in ('file', 'symlink')]
    records.append({
        'file': 'dmg/' + name, 'producer': producer, 'command': commands.get(name, ''),
        'chain': 'dmg', 'password': None, 'utc_mtimes': True,
        'hardlinks': sum(1 for e in entries if e.get('nlink', 1) > 1),
        'symlinks': sum(1 for e in entries if e['kind'] == 'symlink'),
        'filesystem': fs, 'mounted_as': walk['filesystem'],
        'note': 'Entries are what macOS shows on the volume, attached read-only, from its root; '
                'HFS+ names composed (NFC). The journal and HFS+ private folders are hidden by macOS.',
        'entries': entries, 'dirs': walk['dirs'],
        'others': [e for e in walk['entries'] if e['kind'] == 'other'],
    })
json.dump({'fixtures': records}, open(os.path.join(out, 'dmg-manifest.json'), 'w'),
          ensure_ascii=False, indent=2)
json.dump(layouts, open(os.path.join(out, 'udif.json'), 'w'), indent=2)
PY

# An image BeeZip wrote, checked by macOS: the lead's CI does this for every image BeeZip writes.
check="$out/beezip-check.txt"
beezip="$repo/tests/fixtures/malicious/traversal.dmg"
{
    echo "== $beezip"
    shasum -a 256 "$beezip"
    echo "== hdiutil imageinfo"
    hdiutil imageinfo "$beezip" 2>&1 || echo "imageinfo failed: $?"
    echo "== hdiutil verify"
    hdiutil verify "$beezip" 2>&1 || echo "verify failed: $?"
    echo "== fsck_hfs -n on the unmounted device"
    if attach -readonly -nomount "$beezip"; then
        sudo fsck_hfs -n -f "$dev" 2>&1 || echo "fsck_hfs failed: $?"
        detach "$dev" || true
    else
        echo "attach -nomount failed"
    fi
    echo "== attached read-only"
    if attach -readonly "$beezip"; then
        diskutil info "$mnt" 2>&1 | sed -n '1,40p' || true
        ls -laR "$mnt" 2>&1 || true
        find "$mnt" -type f -not -path "$mnt/.*" -exec shasum -a 256 {} + 2>&1 || true
        detach "$dev" || true
    else
        echo "attach failed"
    fi
} > "$check" 2>&1 || true

du -sh "$out" "$out"/dmg/* >&2
