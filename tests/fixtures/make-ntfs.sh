#!/bin/bash
# Makes tests/fixtures/thirdparty/ntfs/ and the NTFS images of tests/fixtures/malicious/ for
# BeeZip's own NTFS reader (docs/M7.md §6, §10). Run it from the repository, with Docker running,
# in WSL or Git Bash:
#
#   bash tests/fixtures/make-ntfs.sh
#
# The images are made in make-7z.sh's container (make-7z.Dockerfile, beezip-fixtures-7z), which
# runs this script again with --inside; it needs FUSE for ntfs-3g. Tools: mkntfs and ntfs-3g
# 2022.10.3, libfaketime 0.9.10 and python3 3.12, as for make-7z.sh. Deterministic: mkntfs and
# ntfs-3g run under a frozen libfaketime clock, the data comes from seeded Random()s, and the
# damaged images are edits of the committed thirdparty/7zip/ntfs.img.
#
# thirdparty/ntfs/rich.img (2 MiB, clusters of 4 KiB): the spike's rich.img cut down
# (target/m7-spikes/ntfs/scripts/make-rich.sh). LZNT1 files in compressed/ (text, random bytes,
# both mixed, and one with a hole); sparse.bin, 8 MiB with three islands of 8 KiB (7-Zip 26.00
# says Data Error); a folder of 200 files, whose index has three levels; a file with 61 names in
# links/ and one with 41 streams, both with attribute lists; DOS 8.3 names; Case.txt and case.txt;
# a symlink relative and one absolute, a junction, a WSL symlink and a WOF file with its
# WofCompressedData stream; ntfs-3g's Interix symlinks, FIFO and character device; a deleted
# file; encrypted.bin with EFS's flags set (no real EFS stream); a path 30 folders deep ending in
# a name of 255 characters; streams.txt's time to 100 ns.
#
# thirdparty/ntfs/frag.img (1.5 MiB, clusters of 512 bytes): frag-a.bin and frag-b.bin, written
# 512 bytes at a time in turn, 400 pieces each, so that each one's runs fill more than a record and
# are split into pieces over extension records; compressed/text.txt in units of 8 KiB.
#
# thirdparty/ntfs/empty-nonres.img (1.25 MiB, clusters of 4 KiB): empty.bin's data and
# after.txt's stream `empty` are empty and non-resident, with no runs and a last VCN of -1, as
# Windows writes `$Extend/$RmMetadata/$Repair` and empty files on every volume it formats (ntfs-3g
# keeps an empty value resident, so the attributes are rewritten once it's unmounted); after.txt
# comes after empty.bin in the folder.
#
# malicious/ntfs-*.img, each refused cleanly or read within limits (crates/beezip-core/tests/
# malicious/ntfs.rs); all but ntfs-sparse-100g.img are thirdparty/7zip/ntfs.img edited:
#   ntfs-mft-recursion.img  $MFT's first record: its data has no runs, and an attribute list in
#                           place of its name names an unnamed $DATA in record 1. fstool 0.5.2
#                           recurses finding $MFT until its stack overflows (the spike's repro).
#   ntfs-sparse-100g.img    one sparse file of 100 GiB (107 374 182 400 bytes) and safe.txt.
#   ntfs-short-attr.img     `with space.txt`'s record ends in a resident attribute of 16 bytes,
#                           too short for its own header: fstool's AttributeIter reads past the
#                           record and panics.
#   ntfs-dir-cycle.img      `sub/nested`'s one name, deep.txt, points at the root folder, its key
#                           marked as a folder (the spike's repro).
#   ntfs-index-loop.img     the root folder's index block points at itself.
#   ntfs-index-4g.img       the root folder's index blocks are 0xFFFFF000 bytes (the spike's repro).
#   ntfs-dup-data.img       random.bin has a resident unnamed $DATA of 5 bytes after its own.
#   ntfs-alist-foreign.img  mtime.txt's attribute list names random.bin's record for its data.
#   ntfs-truncated.img      the image cut after $MFT's first eight records (the spike's repro).
set -euo pipefail

faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
    NO_FAKE_STAT=1)

# ---------------------------------------------------------------------------------------------
# In the container (root).
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    out=/fixtures/thirdparty/ntfs
    mal=/fixtures/malicious
    mkdir -p "$out" /mnt/n

    pid=
    mount_ntfs() {
        "${faked[@]}" ntfs-3g -o streams_interface=windows,no_detach "$1" /mnt/n &
        pid=$!
        for _ in $(seq 100); do
            mountpoint -q /mnt/n && break
            kill -0 "$pid" && sleep 0.1
        done
        mountpoint -q /mnt/n
    }
    umount_ntfs() {
        umount /mnt/n
        wait "$pid"
    }
    volume() { # image size cluster label
        rm -f "$1"
        truncate -s "$2" "$1"
        "${faked[@]}" mkntfs -q -F -Q -s 512 -c "$3" -p 0 -H 255 -S 63 -L "$4" "$1" >/dev/null 2>&1
    }

    volume "$out/rich.img" 2M 4096 BeeZipRich
    mount_ntfs "$out/rich.img"
    python3 -I - /mnt/n <<'PY'
import os, random, struct, sys
M = sys.argv[1]
rnd = random.Random(7)

def attrib(path):
    return struct.unpack('>I', os.getxattr(path, 'system.ntfs_attrib_be'))[0]

# Files made in a compressed folder are LZNT1-compressed (clusters of 4 KiB, units of 64 KiB).
os.mkdir(f'{M}/compressed')
os.setxattr(f'{M}/compressed', 'system.ntfs_attrib_be',
            struct.pack('>I', attrib(f'{M}/compressed') | 0x800))
text = b''.join(b'line %06d of some very compressible text\n' % i for i in range(5000))
open(f'{M}/compressed/text.txt', 'wb').write(text)
open(f'{M}/compressed/random.bin', 'wb').write(rnd.randbytes(40000))
mixed = bytearray()
for i in range(4):
    mixed += rnd.randbytes(20000) if i % 2 else b'A' * 70000
open(f'{M}/compressed/mixed.bin', 'wb').write(mixed)
with open(f'{M}/compressed/sparse-compressed.bin', 'wb') as f:
    f.write(b'start' * 1000)
    f.seek(3 << 20)
    f.write(b'end' * 1000)

# A sparse file with islands.
with open(f'{M}/sparse.bin', 'wb') as f:
    for at in (0, 1 << 20, 5 << 20):
        f.seek(at)
        f.write(rnd.randbytes(8192))
    f.truncate(8 << 20)

# A folder whose index has three levels.
os.mkdir(f'{M}/big')
for i in range(200):
    open(f'{M}/big/file-with-a-longish-name-{i:05d}.txt', 'wb').write(b'%d\n' % i)

# Many names with long names: an attribute list of $FILE_NAMEs.
os.mkdir(f'{M}/links')
open(f'{M}/links/target.txt', 'wb').write(b'linked\n')
for i in range(60):
    os.link(f'{M}/links/target.txt',
            f'{M}/links/' + 'hard-link-number-%03d-' % i + 'x' * 60 + '.txt')

# Many streams: an attribute list of $DATAs.
open(f'{M}/streams.txt', 'wb').write(b'main\n')
for i in range(40):
    open(f'{M}/streams.txt:stream{i:02d}', 'wb').write(b'stream %d ' % i * 20)
open(f'{M}/streams.txt:big', 'wb').write(rnd.randbytes(20000))

# DOS 8.3 names.
open(f'{M}/A long file name.txt', 'wb').write(b'dos name\n')
os.setxattr(f'{M}/A long file name.txt', 'system.ntfs_dos_name', b'ALONGF~1.TXT')
os.mkdir(f'{M}/Long Folder Name')
os.setxattr(f'{M}/Long Folder Name', 'system.ntfs_dos_name', b'LONGFO~1')
open(f'{M}/Long Folder Name/inner.txt', 'wb').write(b'inner\n')

# Names that differ only in case (POSIX namespace).
open(f'{M}/Case.txt', 'wb').write(b'upper\n')
open(f'{M}/case.txt', 'wb').write(b'lower\n')

# Reparse points.
def reparse(path, tag, body, folder=False):
    if folder:
        os.mkdir(path)
    else:
        open(path, 'wb').close()
    os.setxattr(path, 'system.ntfs_reparse_data', struct.pack('<IHH', tag, len(body), 0) + body)
def names(subst, prnt, extra=b''):
    s = subst.encode('utf-16-le') + b'\0\0'
    p = prnt.encode('utf-16-le') + b'\0\0'
    return struct.pack('<HHHH', 0, len(s) - 2, len(s), len(p) - 2) + extra + s + p
os.mkdir(f'{M}/target-dir')
open(f'{M}/target-dir/in.txt', 'wb').write(b'in\n')
reparse(f'{M}/symlink-rel', 0xA000000C,
        names('target-dir\\in.txt', 'target-dir\\in.txt', struct.pack('<I', 1)))
reparse(f'{M}/symlink-abs', 0xA000000C,
        names('\\??\\C:\\Windows\\win.ini', 'C:\\Windows\\win.ini', struct.pack('<I', 0)))
reparse(f'{M}/junction', 0xA0000003, names('\\??\\C:\\Users', 'C:\\Users'), folder=True)
reparse(f'{M}/lx-symlink', 0xA000001D, struct.pack('<I', 2) + b'target-dir/in.txt')
# WOF: version 1, the file provider (2), its version 1 and LZX (1).
reparse(f'{M}/wof.dll', 0x80000017, struct.pack('<IIII', 1, 2, 1, 1))
open(f'{M}/wof.dll:WofCompressedData', 'wb').write(b'not really LZX ' * 4)

# Interix links and specials, as ntfs-3g makes them itself.
os.symlink('target-dir/in.txt', f'{M}/interix-link')
os.symlink('target-dir', f'{M}/interix-dirlink')
os.mkfifo(f'{M}/interix-fifo')
os.mknod(f'{M}/interix-chr', 0o20644, os.makedev(1, 3))

# Made and removed.
open(f'{M}/deleted.txt', 'wb').write(b'gone\n' * 100)
os.remove(f'{M}/deleted.txt')

# Marked encrypted once unmounted.
open(f'{M}/encrypted.bin', 'wb').write(b'not really encrypted\n' * 300)

# A deep path and a name of 255 characters.
d = M
for i in range(30):
    d = f'{d}/d{i:02d}'
    os.mkdir(d)
open(f'{d}/' + 'n' * 251 + '.txt', 'wb').write(b'deep\n')

# A time to 100 ns.
os.utime(f'{M}/streams.txt', ns=(1715000000123456789, 1715000000123456789))
PY
    sync
    umount_ntfs

    # EFS: the encrypted flag on encrypted.bin's $DATA and $STANDARD_INFORMATION.
    python3 -I - "$out/rich.img" <<'PY'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, 'rb').read())
name = 'encrypted.bin'.encode('utf-16-le')
def fix(rec, undo):
    usa_off, usa_n = struct.unpack_from('<HH', rec, 4)
    for i in range(1, usa_n):
        at = i * 512 - 2
        if undo:
            rec[at:at + 2] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
        else:
            rec[usa_off + 2 * i:usa_off + 2 * i + 2] = rec[at:at + 2]
            rec[at:at + 2] = rec[usa_off:usa_off + 2]
done = False
for at in range(0, len(data), 1024):
    if data[at:at + 4] != b'FILE':
        continue
    rec = bytearray(data[at:at + 1024])
    fix(rec, True)
    if name not in rec:
        continue
    off = struct.unpack_from('<H', rec, 0x14)[0]
    while off + 8 <= len(rec):
        ty, ln = struct.unpack_from('<II', rec, off)
        if ty == 0xFFFFFFFF or ln == 0:
            break
        if ty == 0x80 and rec[off + 9] == 0:
            struct.pack_into('<H', rec, off + 12, struct.unpack_from('<H', rec, off + 12)[0] | 0x4000)
        if ty == 0x10:
            fa = off + struct.unpack_from('<H', rec, off + 0x14)[0] + 0x20
            struct.pack_into('<I', rec, fa, struct.unpack_from('<I', rec, fa)[0] | 0x4000)
        off += ln
    fix(rec, False)
    data[at:at + 1024] = rec
    done = True
    break
assert done
open(path, 'wb').write(data)
PY

    volume "$out/frag.img" 1536K 512 BeeZipFrag
    mount_ntfs "$out/frag.img"
    python3 -I - /mnt/n <<'PY'
import os, struct, sys
M = sys.argv[1]
a = open(f'{M}/frag-a.bin', 'wb')
b = open(f'{M}/frag-b.bin', 'wb')
for i in range(400):
    for f, tag in ((a, b'a'), (b, b'b')):
        f.write((b'frag-%s %05d ' % (tag, i) * 64)[:512])
        f.flush()
        os.fsync(f.fileno())
a.close()
b.close()
os.mkdir(f'{M}/compressed')
attrib = struct.unpack('>I', os.getxattr(f'{M}/compressed', 'system.ntfs_attrib_be'))[0]
os.setxattr(f'{M}/compressed', 'system.ntfs_attrib_be', struct.pack('>I', attrib | 0x800))
open(f'{M}/compressed/text.txt', 'wb').write(
    b''.join(b'line %06d of some very compressible text\n' % i for i in range(1000)))
PY
    sync
    umount_ntfs

    volume "$out/empty-nonres.img" 1280K 4096 BeeZipEmpty
    mount_ntfs "$out/empty-nonres.img"
    python3 -I - /mnt/n <<'PY'
import sys
M = sys.argv[1]
open(f'{M}/empty.bin', 'wb').close()
open(f'{M}/after.txt', 'wb').write(b'after the empty one\n')
open(f'{M}/after.txt:empty', 'wb').close()
PY
    sync
    umount_ntfs
    # Every empty resident $DATA becomes non-resident: starting VCN 0, last VCN -1, sizes 0 and
    # a run list of just its end.
    python3 -I - "$out/empty-nonres.img" <<'PY'
import struct, sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
cs = struct.unpack_from('<H', d, 11)[0] * d[13]
mft = struct.unpack_from('<Q', d, 0x30)[0] * cs
REC = 1024

def fix(r, undo):
    off, n = struct.unpack_from('<HH', r, 4)
    for i in range(1, n):
        t = i * 512 - 2
        if undo:
            r[t:t + 2] = r[off + 2 * i:off + 2 * i + 2]
        else:
            r[off + 2 * i:off + 2 * i + 2] = r[t:t + 2]
            r[t:t + 2] = r[off:off + 2]

def nonresident(name_len, name, ident):
    name_off = 0x40
    runs = (name_off + 2 * name_len + 7) & ~7
    a = bytearray(runs + 8)
    struct.pack_into('<IIBBHHH', a, 0, 0x80, len(a), 1, name_len, name_off, 0, ident)
    struct.pack_into('<QqHH', a, 0x10, 0, -1, runs, 0)
    struct.pack_into('<QQQ', a, 0x28, 0, 0, 0)
    a[name_off:name_off + 2 * name_len] = name
    return bytes(a)

changed = []
for n in range(64, 128):  # ntfs-3g gives new files records from 64
    at = mft + n * REC
    if at + REC > len(d) or d[at:at + 4] != b'FILE' or not d[at + 0x16] & 1:
        continue
    r = bytearray(d[at:at + REC])
    fix(r, True)
    first = struct.unpack_from('<H', r, 0x14)[0]
    parts, off, fname = [], first, None
    while True:
        ty, ln = struct.unpack_from('<II', r, off)
        if ty == 0xFFFFFFFF:
            break
        a = bytes(r[off:off + ln])
        if ty == 0x30:
            v = struct.unpack_from('<H', a, 0x14)[0]
            fname = a[v + 66:v + 66 + 2 * a[v + 64]].decode('utf-16-le')
        if ty == 0x80 and a[8] == 0 and struct.unpack_from('<I', a, 0x10)[0] == 0:
            name_len, name_off = a[9], struct.unpack_from('<H', a, 10)[0]
            a = nonresident(name_len, a[name_off:name_off + 2 * name_len],
                            struct.unpack_from('<H', a, 14)[0])
            changed.append((fname, n))
        parts.append(a)
        off += ln
    body = b''.join(parts) + b'\xff\xff\xff\xff' + bytes(4)
    assert first + len(body) <= struct.unpack_from('<I', r, 0x1C)[0]
    r[first:first + len(body)] = body
    struct.pack_into('<I', r, 0x18, first + len(body))
    fix(r, False)
    d[at:at + REC] = r
assert sorted(c[0] for c in changed) == ['after.txt', 'empty.bin'], changed
open(path, 'wb').write(d)
PY

    volume "$mal/ntfs-sparse-100g.img" 1280K 4096 BeeZipSparse
    mount_ntfs "$mal/ntfs-sparse-100g.img"
    printf 'safe\n' > /mnt/n/safe.txt
    python3 -I - /mnt/n <<'PY'
import sys
with open(sys.argv[1] + '/sparse-100g.bin', 'wb') as f:
    f.write(b'start\n')
    f.seek(107374182400 - 4)
    f.write(b'end\n')
PY
    sync
    umount_ntfs

    python3 -I - /fixtures/thirdparty/7zip/ntfs.img "$mal" <<'PY'
import os, struct, sys
base, mal = sys.argv[1], sys.argv[2]
REC = 1024

def unfix(b):
    off, n = struct.unpack_from('<HH', b, 4)
    for i in range(1, n):
        t = i * 512 - 2
        assert b[t:t + 2] == b[off:off + 2]
        b[t:t + 2] = b[off + 2 * i:off + 2 * i + 2]

def refix(b):
    off, n = struct.unpack_from('<HH', b, 4)
    for i in range(1, n):
        t = i * 512 - 2
        b[off + 2 * i:off + 2 * i + 2] = b[t:t + 2]
        b[t:t + 2] = b[off:off + 2]

def attrs(r):
    """(offset, type, length, non-resident) of each attribute, and where the end marker is."""
    out = []
    at = struct.unpack_from('<H', r, 0x14)[0]
    while True:
        ty, ln = struct.unpack_from('<II', r, at)
        if ty == 0xFFFFFFFF:
            return out, at
        out.append((at, ty, ln, r[at + 8]))
        at += ln

def resident(ty, value, ident, name=''):
    n = name.encode('utf-16-le')
    off = (0x18 + len(n) + 7) & ~7
    ln = (off + len(value) + 7) & ~7
    a = bytearray(ln)
    struct.pack_into('<IIBBHHH', a, 0, ty, ln, 0, len(name), 0x18, 0, ident)
    struct.pack_into('<IH', a, 0x10, len(value), off)
    a[0x18:0x18 + len(n)] = n
    a[off:off + len(value)] = value
    return bytes(a)

class Image:
    def __init__(self):
        self.d = bytearray(open(base, 'rb').read())
        self.cs = struct.unpack_from('<H', self.d, 11)[0] * self.d[13]
        self.mft = struct.unpack_from('<Q', self.d, 0x30)[0] * self.cs

    def at(self, n):
        at = self.mft + n * REC
        assert self.d[at:at + 4] == b'FILE' and struct.unpack_from('<I', self.d, at + 0x2C)[0] == n
        return at

    def edit(self, n, fn):
        at = self.at(n)
        r = bytearray(self.d[at:at + REC])
        unfix(r)
        fn(r)
        refix(r)
        self.d[at:at + REC] = r

    def record(self, n):
        r = bytearray(self.d[self.at(n):self.at(n) + REC])
        unfix(r)
        return r

    def find(self, parent, name):
        """The record whose $FILE_NAME is `name` in folder `parent`."""
        want = name.encode('utf-16-le')
        for n in range(16, 128):
            try:
                r = self.record(n)
            except AssertionError:
                continue
            if not struct.unpack_from('<H', r, 0x16)[0] & 1:
                continue
            for at, ty, ln, nonres in attrs(r)[0]:
                if ty == 0x30:
                    v = at + struct.unpack_from('<H', r, at + 0x14)[0]
                    if (struct.unpack_from('<Q', r, v)[0] & 0xFFFFFFFFFFFF == parent
                            and r[v + 66:v + 66 + 2 * r[v + 64]] == want):
                        return n
        raise KeyError(name)

    def root_block(self, fn):
        """Edits the root folder's first index block."""
        r = self.record(5)
        for at, ty, ln, nonres in attrs(r)[0]:
            if ty == 0xA0:
                runs = at + struct.unpack_from('<H', r, at + 0x20)[0]
                h = r[runs]
                assert h & 0x0F == 1
                lcn = int.from_bytes(r[runs + 2:runs + 2 + (h >> 4)], 'little', signed=True)
        at = lcn * self.cs
        b = bytearray(self.d[at:at + 4096])
        assert b[:4] == b'INDX'
        unfix(b)
        fn(b)
        refix(b)
        self.d[at:at + 4096] = b

    def write(self, name, data=None):
        with open(os.path.join(mal, name), 'wb') as f:
            f.write(self.d if data is None else data)

def rewrite(r, attributes):
    """Lays `attributes` (bytes each) out in record `r` from its first attribute on."""
    at = struct.unpack_from('<H', r, 0x14)[0]
    body = b''.join(attributes) + b'\xff\xff\xff\xff' + bytes(4)
    assert at + len(body) <= struct.unpack_from('<I', r, 0x1C)[0]
    r[at:at + len(body)] = body
    struct.pack_into('<I', r, 0x18, at + len(body))

# $MFT's data without runs, and an attribute list (in its $FILE_NAME's place) naming record 1.
img = Image()
def mft0(r):
    for at, ty, ln, nonres in attrs(r)[0]:
        if ty == 0x80 and nonres:
            r[at + struct.unpack_from('<H', r, at + 0x20)[0]] = 0
        if ty == 0x30 and not nonres:
            v = at + struct.unpack_from('<H', r, at + 0x14)[0]
            assert struct.unpack_from('<I', r, at + 0x10)[0] >= 0x20
            struct.pack_into('<I', r, at, 0x20)
            r[v:v + 0x20] = struct.pack('<IHBBQQH', 0x80, 0x20, 0, 0x1A, 0, 1, 0) + bytes(6)
            struct.pack_into('<I', r, at + 0x10, 0x20)
img.edit(0, mft0)
img.write('ntfs-mft-recursion.img')

# A resident attribute of 16 bytes at the record's end, after one that pads up to it.
img = Image()
def short(r):
    found, end = attrs(r)
    pad = REC - 16 - end
    assert pad >= 0x18 and pad % 8 == 0
    rewrite(r, [r[a:a + ln] for a, _, ln, _ in found])
    r[end:end + pad] = resident(0x100, b'', 0x20)[:0x18] + bytes(pad - 0x18)
    struct.pack_into('<I', r, end + 4, pad)
    r[REC - 16:REC] = struct.pack('<IIBBHHH', 0x40, 16, 0, 0, 0, 0, 0x21)
    struct.pack_into('<I', r, 0x18, REC)
img.edit(img.find(5, 'with space.txt'), short)
img.write('ntfs-short-attr.img')

# sub/nested's only name points at the root folder, its key marked as a folder's.
img = Image()
def nested(r):
    for at, ty, ln, nonres in attrs(r)[0]:
        if ty == 0x90:
            v = at + struct.unpack_from('<H', r, at + 0x14)[0]
            e = v + 0x10 + struct.unpack_from('<I', r, v + 0x10)[0]
            struct.pack_into('<Q', r, e, 5 | (5 << 48))
            struct.pack_into('<I', r, e + 0x10 + 0x38, 0x10000000)
img.edit(img.find(img.find(5, 'sub'), 'nested'), nested)
img.write('ntfs-dir-cycle.img')

# The root's index block: its end marker gets a child, the block itself.
img = Image()
def loop(b):
    e = 0x18 + struct.unpack_from('<I', b, 0x18)[0]
    end = 0x18 + struct.unpack_from('<I', b, 0x1C)[0]
    while True:
        ln, _, flags = struct.unpack_from('<HHI', b, e + 8)
        if flags & 2:
            break
        e += ln
    assert e + ln == end and struct.unpack_from('<I', b, 0x20)[0] >= end - 0x18 + 8
    struct.pack_into('<HHI', b, e + 8, ln + 8, 0, flags | 1)
    struct.pack_into('<Q', b, e + ln, struct.unpack_from('<Q', b, 0x10)[0])
    struct.pack_into('<I', b, 0x1C, end - 0x18 + 8)
img.root_block(loop)
img.write('ntfs-index-loop.img')

# The root's index blocks are 0xFFFFF000 bytes.
img = Image()
def huge(r):
    for at, ty, ln, nonres in attrs(r)[0]:
        if ty == 0x90:
            struct.pack_into('<I', r, at + struct.unpack_from('<H', r, at + 0x14)[0] + 8, 0xFFFFF000)
img.edit(5, huge)
img.write('ntfs-index-4g.img')

# random.bin's data twice: a resident unnamed $DATA after its own.
img = Image()
def dup(r):
    found, end = attrs(r)
    rewrite(r, [r[a:a + ln] for a, _, ln, _ in found] + [resident(0x80, b'short', 0x22)])
img.edit(img.find(5, 'random.bin'), dup)
img.write('ntfs-dup-data.img')

# mtime.txt's attribute list names random.bin's record for its data.
img = Image()
victim = img.find(5, 'random.bin')
def foreign(r):
    found, end = attrs(r)
    entry = struct.pack('<IHBBQQH', 0x80, 0x20, 0, 0x1A, 0, victim | (1 << 48), 0) + bytes(6)
    parts = [r[a:a + ln] for a, _, ln, _ in found]
    rewrite(r, parts[:1] + [resident(0x20, entry, 0x23)] + parts[1:])
img.edit(img.find(5, 'mtime.txt'), foreign)
img.write('ntfs-alist-foreign.img')

# Cut after $MFT's first eight records.
img = Image()
img.write('ntfs-truncated.img', img.d[:img.mft + 8 * REC])
PY
    chown -R "${HOST_IDS:-0:0}" "$out" "$mal"/ntfs-*.img || true
    exit 0
fi

# ---------------------------------------------------------------------------------------------
# On the host.
here="$(cd "$(dirname "$0")" && pwd)"
command -v docker >/dev/null
# Docker Desktop on Windows takes `C:/…` from Git Bash; WSL's paths go as they are.
host() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
docker image inspect beezip-fixtures-7z >/dev/null 2>&1 ||
    docker build -q -t beezip-fixtures-7z - < "$here/make-7z.Dockerfile" >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm --device /dev/fuse --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined -e HOST_IDS="$(id -u):$(id -g)" \
    -v "$(host "$here"):/fixtures" beezip-fixtures-7z bash /fixtures/make-ntfs.sh --inside
