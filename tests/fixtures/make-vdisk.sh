#!/bin/bash
# Makes tests/fixtures/thirdparty/vdisk/ and the virtual disks of tests/fixtures/malicious/ for
# BeeZip's own VMDK, QCOW2 and VDI readers (docs/M8.md §3.3-3.5, §9). Run it from the repository,
# with Docker running, in WSL or Git Bash:
#
#   bash tests/fixtures/make-vdisk.sh
#
# The images are made in make-7z.sh's container (make-7z.Dockerfile, beezip-fixtures-7z), which
# runs this script again with --inside. Tools: qemu-img and qemu-io 8.2.2, sfdisk 2.39.3, mkfs.fat
# 4.2 and mtools 4.0.43, libfaketime 0.9.10, python3 3.12. What qemu-img can't make is crafted by
# the Python below from the formats' public descriptions: VMware's Virtual Disk Format 5.0 (VMDK
# descriptors, hosted sparse and stream-optimized extents), the VDI header as public documentation
# describes it, qemu's docs/interop/qcow2.txt (header bits).
#
# Deterministic: a rerun writes the same bytes. The disks' contents come from seeded Random()s,
# mkfs.fat --invariant and mtools with SOURCE_DATE_EPOCH, sfdisk with fixed ids; qemu-img and
# qemu-io run under a frozen libfaketime clock (snapshots record the time). What they draw at random
# is fixed afterwards: every VMDK's CID (6d7a00nn; each child is made after its parent's is fixed,
# and its own is fixed after every write, since qemu draws a new one on a disk's first write) and
# every VDI's uuids (6d7a6970-6265-457a-8970-000000000nnn, as make-7z.sh fixes them). The LUKS
# image is cut after its header's cluster: BeeZip refuses it there, and LUKS's salts are random.
#
# thirdparty/vdisk/ holds, beside expected.tsv:
#   disk.img            the 256 KiB raw disk the small images hold: GPT (fixed ids), one partition
#                       `data` (sectors 64-447), FAT12 with readme.txt, random.bin (24 KiB,
#                       Random(8)) and sub/nested.txt; sectors 156-478 are zeros, so every format
#                       has holes. It's also the raw backing file of q-child-raw and others.
#   v-*.vmdk            qemu-img: monolithicSparse (v-sparse), compat6, zeroed_grain with
#                       `write -z` over a hole (v-zg: zeroed-grain entries), monolithicFlat,
#                       twoGbMaxExtentSparse, twoGbMaxExtentFlat, streamOptimized (qemu's layout:
#                       the grain directory at the start, no footer); a child of v-sparse, a
#                       grandchild, a child of the flat disk; v-vmfs.vmdk, the flat disk's
#                       descriptor as ESXi writes it (createType vmfs, extent VMFS). Crafted:
#                       v-vmware.vmdk (VMware's stream layout: grain directory after the grains,
#                       footer, end-of-stream marker), v-bare.vmdk (a hosted sparse extent with no
#                       descriptor, grains of 4 KiB, over a 3 MiB disk so it has two grain tables),
#                       v-multi.vmdk (FLAT at an offset, ZERO, NOACCESS, VMFS, FLAT again in the
#                       first file, SPARSE: their files v-multi-*). v-refuse-*.vmdk are refused:
#                       vmfsSparse, seSparse and raw device map extents, grains compressed
#                       without markers, compressed with method 2.
#   q-*.qcow2           qemu-img: v3 (default), v2 (compat=0.10), deflate (-c), zstd, 512-byte
#                       clusters (eight L2 tables), refcount_bits=1 and 64, zero clusters in v3
#                       (`write -z` keeping and unmapping clusters, `discard`) and in v2; backing
#                       files: a child of q-v3, a child of disk.img (raw), three deep, a child
#                       larger than its backing file, a child of v-sparse.vmdk and of d-dyn.vdi,
#                       q-child-sniff (disk.img with no format recorded: sniffed raw); two internal
#                       snapshots with writes between (q-snap); extended L2 alone, with -c, and
#                       over disk.img with 2 KiB writes; data files raw and not (q-data*.bin);
#                       encrypted with AES and with LUKS (cut after the header's cluster), QCOW
#                       version 1 (q-v1.qcow), all refused. Crafted: the dirty and corrupt bits
#                       (q-dirty, q-corrupt), an unknown incompatible bit and compression type
#                       (refused). To stay small, the images have 4 KiB clusters but q-v3,
#                       q-deflate, q-zstd and q-el2 (qemu-img's default 64 KiB), q-c512, and
#                       q-el2-child and q-el2-deflate (16 KiB, the least extended L2 allows).
#   d-*.vdi             qemu-img: dynamic (d-dyn) and static (d-fixed). Crafted with VirtualBox's
#                       0x190 header: d-vbox (64 KiB blocks stored out of order, one discarded,
#                       some free), d-2m (a block of 2 MiB, the file ending with the disk 256 KiB
#                       into it), d-odd (fixed, not whole blocks long), d-base.vdi and the
#                       differencing chain in Snapshots/ as VirtualBox lays it out ({...411} a
#                       child of d-base, {...421} its child), {...431} whose parent changed after
#                       it was made, {...441} an orphan; d-extra (extra bytes before each block)
#                       and d-undo (an undo image), both refused.
#   b-*.{vmdk,qcow2}    a 5 GiB disk (and 1,536 bytes) of zeros but five 1-4 KiB patterns: at its
#                       start, across a grain table's end (32 MiB), 2^31 and 2^32 (the ends of
#                       qemu-img's 2 GiB twoGbMaxExtentSparse extents), and in the part of a grain
#                       at its end: qemu-img's QCOW2 of 4 KiB clusters (b-c4k); crafted, and each
#                       checked against qemu-img, the twoGbMaxExtentSparse disk split as qemu-img
#                       splits it, its extents with grains of 4 KiB (b-split; qemu-img's own write
#                       1.4 MB of grain tables), and VMware's stream layout (b-vmware). Each is one
#                       raw file in BeeZip, whose claim (5 GiB from its 30-450 KB) the ratio limit
#                       refuses.
#   z.vmdk, z-deflate.qcow2  a FAT16 volume (100 MiB) holding zeros.bin, 80 MiB of zeros that the
#                       images keep as holes: past the ratio limit's 64 MiB grace if the ratio
#                       counted the images' bytes (docs/M8.md §3.7).
#
# expected.tsv: each image opened (not the files they name), what opening and reading it gives
# (`read`, or the error kind), its virtual size, the SHA-256 of its virtual disk, and a digest the
# tests read quickly: SHA-256 over each 64 KiB-aligned chunk of the disk that isn't all zeros,
# each preceded by its offset as 8 bytes little-endian, then the disk's size the same way. Both
# come from `qemu-img convert -O raw`, run from the image's folder (`qemu`), or are right by
# construction where qemu-img can't read the image or reads it wrong (`crafted`): qemu-img 8.2.2
# drops a VMDK's ZERO extents, can't open a bare sparse extent, a VDI of blocks other than 1 MiB or
# a differencing VDI. Each crafted VMDK qemu-img does read is checked against it here.
#
# malicious/vdisk-*, each refused cleanly or read within limits (crates/beezip-core/tests/
# malicious/vdisk.rs):
#   vdisk-loop-a.qcow2, vdisk-loop-b.qcow2   each the other's backing file (qemu-img never ends)
#   vdisk-self.qcow2                         its own backing file
#   vdisk-json.qcow2, vdisk-nbd.qcow2,       backing files json:{...} (qemu-img reads /etc/passwd),
#   vdisk-unc.qcow2                          nbd://localhost:10809/x and \\server\share\base.qcow2
#   vdisk-device.vmdk                        a FLAT extent \\.\PhysicalDrive0
#   vdisk-vmdk-self.vmdk                     a child disk whose parent is itself
#   vdisk-vdi-a.vdi, vdisk-vdi-b.vdi         differencing VDIs, each the other's parent by uuid
#   vdisk-grain-1g.vmdk                      grains of 1 GiB (rust-img-vmdk 0.5.1 allocates one)
#   vdisk-2t.qcow2, vdisk-zero-2t.vmdk       2 TiB of nothing: an empty QCOW2, a ZERO extent
set -euo pipefail

E=1767225600 # 2026-01-01T00:00:00Z
faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
    NO_FAKE_STAT=1)

# ---------------------------------------------------------------------------------------------
# In the container (root).
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC SOURCE_DATE_EPOCH=$E
    out=/fixtures/thirdparty/vdisk
    mal=/fixtures/malicious
    W=/work
    rm -rf "$out" "$W"
    mkdir -p "$out/Snapshots" "$W" "$mal"
    rm -f "$mal"/vdisk-*

    cat > "$W/craft.py" <<'PY'
"""The images qemu-img can't make, and the fixes to what it draws at random (see make-vdisk.sh)."""
import hashlib, os, random, re, struct, sys, uuid, zlib

SECTOR = 512
CHUNK = 1 << 16


class Disk:
    """A virtual disk: `size` bytes of zeros but the (offset, bytes) segments, which don't overlap."""

    def __init__(self, size, segs):
        self.size = size
        self.segs = sorted(segs)

    def read(self, off, n):
        out = bytearray(n)
        for s, d in self.segs:
            a, b = max(off, s), min(off + n, s + len(d))
            if a < b:
                out[a - off:b - off] = d[a - s:b - s]
        return bytes(out)

    def sub(self, start, n):
        """Its `n` bytes from `start`, as a disk."""
        segs = []
        for s, d in self.segs:
            a, b = max(s, start), min(s + len(d), start + n)
            if a < b:
                segs.append((a - start, d[a - s:b - s]))
        return Disk(n, segs)

    def touched(self, unit):
        """The indices of the `unit`-sized pieces any segment reaches."""
        out = set()
        for s, d in self.segs:
            out.update(range(s // unit, (s + len(d) - 1) // unit + 1))
        return sorted(i for i in out if i * unit < self.size)

    def bytes(self):
        return self.read(0, self.size)


def digests(chunks, size):
    """(SHA-256, digest) of a disk given as (offset, bytes) pieces in order, holes between."""
    full, sparse = hashlib.sha256(), hashlib.sha256()
    pos = 0
    zero = bytes(1 << 20)
    for off, data in chunks:
        while pos < off:
            k = min(len(zero), off - pos)
            full.update(zero[:k])
            pos += k
        full.update(data)
        for i in range(0, len(data), CHUNK):
            c = data[i:i + CHUNK]
            if c.count(0) != len(c):
                sparse.update(struct.pack('<Q', off + i) + c)
        pos = off + len(data)
    while pos < size:
        k = min(len(zero), size - pos)
        full.update(zero[:k])
        pos += k
    sparse.update(struct.pack('<Q', size))
    return full.hexdigest(), sparse.hexdigest()


def disk_digests(disk):
    return digests([(i * CHUNK, disk.read(i * CHUNK, min(CHUNK, disk.size - i * CHUNK)))
                    for i in disk.touched(CHUNK)], disk.size)


def file_digests(path):
    """Of a raw file, its holes skipped (qemu-img writes them sparse)."""
    size = os.path.getsize(path)
    chunks = set()
    with open(path, 'rb') as f:
        fd = f.fileno()
        pos = 0
        while pos < size:
            try:
                data = os.lseek(fd, pos, os.SEEK_DATA)
            except OSError:
                break
            hole = os.lseek(fd, data, os.SEEK_HOLE)
            chunks.update(range(data // CHUNK, (hole - 1) // CHUNK + 1))
            pos = hole
        pieces = []
        for i in sorted(chunks):
            f.seek(i * CHUNK)
            pieces.append((i * CHUNK, f.read(min(CHUNK, size - i * CHUNK))))
    return digests(pieces, size)


def expect(outdir, name, outcome, size='-', sums=('-', '-'), how='-'):
    with open(os.path.join(outdir, 'expected.tsv'), 'a', newline='') as f:
        f.write(f'{name}\t{outcome}\t{size}\t{sums[0]}\t{sums[1]}\t{how}\n')


def fixed_uuid(n):
    return uuid.UUID(f'6d7a6970-6265-457a-8970-{n:012x}')


def pattern(seed, n):
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(n))


# ---- VMDK ----

def descriptor_place(data):
    """Where a VMDK's descriptor is: (start, end) in the file."""
    if data[:4] == b'KDMV':
        off, size = struct.unpack_from('<QQ', data, 28)
        return off * SECTOR, (off + size) * SECTOR
    return 0, len(data)


def set_keys(path, **keys):
    """Sets descriptor keys (CID=, parentCID=, parentFileNameHint=) in place."""
    data = bytearray(open(path, 'rb').read())
    a, b = descriptor_place(data)
    text = bytes(data[a:b]).rstrip(b'\0')
    for k, v in keys.items():
        line = f'{k}={v}'.encode()
        text, count = re.subn(rb'(?m)^' + k.encode() + rb'=.*$', line, text)
        if not count:
            text = re.sub(rb'(?m)^(parentCID=.*)$', rb'\1\n' + line, text, count=1)
    if data[:4] == b'KDMV':
        assert len(text) <= b - a, path
        data[a:b] = text + bytes(b - a - len(text))
    else:
        data = bytearray(text)
    open(path, 'wb').write(data)


def sparse_header(capacity, grain, desc_off, desc_size, gd, over, version=1, flags=1, compress=0):
    h = bytearray(SECTOR)
    struct.pack_into('<4sIIQQQQIQQQ', h, 0, b'KDMV', version, flags, capacity, grain, desc_off,
                     desc_size, 512, 0, gd, over)
    h[73:77] = b'\n \r\n'
    struct.pack_into('<H', h, 77, compress)
    return h


def hosted_sparse(disk, grain=8):
    """A hosted sparse extent (version 1) of `disk`, no descriptor, no redundant directory, and
    grain tables only where it has grains (the directory's other entries 0)."""
    assert disk.size % SECTOR == 0
    cap = disk.size // SECTOR
    gb = grain * SECTOR
    gts = -(-(-(-cap // grain)) // 512)
    full = [g for g in disk.touched(gb) if any(disk.read(g * gb, gb))]
    used = sorted({g // 512 for g in full})
    gd_sec = 1
    gd_secs = -(-gts * 4 // SECTOR)
    gt_sec = gd_sec + gd_secs
    over = -(-(gt_sec + 4 * len(used)) // grain) * grain
    gd = bytearray(gd_secs * SECTOR)
    gt = bytearray(len(used) * 4 * SECTOR)
    for i, t in enumerate(used):
        struct.pack_into('<I', gd, 4 * t, gt_sec + 4 * i)
    body = bytearray()
    at = over
    for g in full:
        struct.pack_into('<I', gt, 2048 * used.index(g // 512) + 4 * (g % 512), at)
        body += disk.read(g * gb, gb)
        at += grain
    out = sparse_header(cap, grain, 0, 0, gd_sec, over) + gd + gt
    out += bytes(over * SECTOR - len(out))
    return bytes(out + body)


def split(spec, out, ext, cid):
    """A twoGbMaxExtentSparse disk as qemu-img splits one, its extents hosted sparse ones of 4 KiB
    grains with grain tables only where there are grains (qemu-img writes them all, twice)."""
    disk, ext = eval_disk(spec), int(ext)
    base = os.path.basename(out)[:-len('.vmdk')]
    lines = []
    for i, start in enumerate(range(0, disk.size, ext)):
        part = disk.sub(start, min(ext, disk.size - start))
        name = f'{base}-s{i + 1:03}.vmdk'
        open(os.path.join(os.path.dirname(out), name), 'wb').write(hosted_sparse(part, grain=8))
        lines.append(f'RW {part.size // SECTOR} SPARSE "{name}"\n')
    desc = (f'# Disk DescriptorFile\nversion=1\nCID={int(cid, 16):08x}\nparentCID=ffffffff\n'
            'createType="twoGbMaxExtentSparse"\n\n# Extent description\n' + ''.join(lines)
            + '\n# The Disk Data Base\n#DDB\n\nddb.adapterType = "ide"\n')
    open(out, 'w', newline='\n').write(desc)
    expect(os.path.dirname(out) or '.', os.path.basename(out), 'read', disk.size,
           disk_digests(disk), 'crafted')


def vmware_stream(disk, name, cid, grain=128):
    """A stream-optimized extent as VMware writes one (Virtual Disk Format 5.0): header with the
    grain directory "at the end", the embedded descriptor, the grains (deflate behind markers),
    each grain table behind its marker after its grains, the directory, the footer, the end."""
    cap = disk.size // SECTOR
    gb = grain * SECTOR
    grains = -(-cap // grain)
    gts = -(-grains // 512)
    desc = (f'# Disk DescriptorFile\nversion=1\nCID={cid:08x}\nparentCID=ffffffff\n'
            f'createType="streamOptimized"\n\n# Extent description\nRDONLY {cap} SPARSE "{name}"\n\n'
            '# The Disk Data Base\n#DDB\n\nddb.adapterType = "lsilogic"\nddb.virtualHWVersion = "4"\n'
            ).encode()
    desc_secs = -(-len(desc) // SECTOR) + 1
    over = 1 + desc_secs
    head = lambda gd: sparse_header(cap, grain, 1, desc_secs, gd, over, version=3,
                                    flags=0x30001, compress=1)
    out = bytearray(head(0xFFFFFFFFFFFFFFFF) + desc + bytes(desc_secs * SECTOR - len(desc)))
    marker = lambda val, size, kind: struct.pack('<QII', val, size, kind) + bytes(SECTOR - 16)
    gd = [0] * gts
    touched = disk.touched(gb)
    for t in range(gts):
        entries = [0] * 512
        for g in (g for g in touched if g // 512 == t):
            chunk = disk.read(g * gb, gb)
            if not any(chunk):
                continue
            comp = zlib.compress(chunk, 9)
            rec = struct.pack('<QI', g * grain, len(comp)) + comp
            rec += bytes(-len(rec) % SECTOR)
            entries[g % 512] = len(out) // SECTOR
            out += rec
        if any(entries):
            out += marker(4, 0, 1)
            gd[t] = len(out) // SECTOR
            out += struct.pack('<512I', *entries)
    gd_secs = -(-gts * 4 // SECTOR)
    out += marker(gd_secs, 0, 2)
    gd_at = len(out) // SECTOR
    out += struct.pack(f'<{gts}I', *gd) + bytes(gd_secs * SECTOR - gts * 4)
    out += marker(1, 0, 3)
    out += head(gd_at)
    out += marker(0, 0, 0)
    return bytes(out)


def multi(raw, outdir):
    """v-multi.vmdk: extents of every type BeeZip reads, over disk.img."""
    data = open(raw, 'rb').read()
    sectors = len(data) // SECTOR
    zero = lambda a, b: not any(data[a * SECTOR:b * SECTOR])
    # FLAT a (3 sectors at 7 of v-multi-a.bin), ZERO (32), NOACCESS (28), VMFS b (193 at 0 of
    # v-multi-b.bin), FLAT a again (44 at 11), SPARSE c (the rest, grains of 8 KiB).
    assert zero(3, 63)
    a = b'\xEE' * 7 * SECTOR + data[:3 * SECTOR] + b'\xEE' * SECTOR + data[256 * SECTOR:300 * SECTOR]
    open(os.path.join(outdir, 'v-multi-a.bin'), 'wb').write(a)
    open(os.path.join(outdir, 'v-multi-b.bin'), 'wb').write(data[63 * SECTOR:256 * SECTOR])
    c = Disk((sectors - 300) * SECTOR, [(0, data[300 * SECTOR:])])
    open(os.path.join(outdir, 'v-multi-c.vmdk'), 'wb').write(hosted_sparse(c, grain=16))
    lines = [
        'RW 3 FLAT "v-multi-a.bin" 7', 'RDONLY 32 ZERO', 'NOACCESS 28 FLAT "v-multi-a.bin" 0',
        'RW 193 VMFS "v-multi-b.bin"', 'RW 44 FLAT "v-multi-a.bin" 11',
        f'RW {sectors - 300} SPARSE "v-multi-c.vmdk"',
    ]
    def desc(lines, kind='custom'):
        return ('# Disk DescriptorFile\nversion=1\nencoding="UTF-8"\nCID=6d7a0010\n'
                f'parentCID=ffffffff\ncreateType="{kind}"\n\n# Extent description\n'
                + ''.join(l + '\n' for l in lines)
                + '\n# The Disk Data Base\n#DDB\n\nddb.adapterType = "ide"\n')
    open(os.path.join(outdir, 'v-multi.vmdk'), 'w', newline='\n').write(desc(lines))
    expect(outdir, 'v-multi.vmdk', 'read', len(data), disk_digests(Disk(len(data), [(0, data)])),
           'crafted')
    # For qemu-img, which drops ZERO extents, doesn't know NOACCESS or the type `custom`: the
    # same disk with both read from a flat file of zeros (checked against disk.img, then deleted).
    open(os.path.join(outdir, 'v-multi-z.bin'), 'wb').write(bytes(60 * SECTOR))
    check = [lines[0], 'RW 32 FLAT "v-multi-z.bin" 0', 'RW 28 FLAT "v-multi-z.bin" 32'] + lines[3:]
    open(os.path.join(outdir, 'v-multi-check.vmdk'), 'w', newline='\n').write(
        desc(check, 'twoGbMaxExtentSparse'))


def bare(raw, out):
    """v-bare.vmdk: a hosted sparse extent with no descriptor, grains of 4 KiB, over a 3 MiB disk
    whose last segment crosses its first grain table's end (2 MiB)."""
    data = open(raw, 'rb').read()
    disk = Disk(3 << 20, [(0, data), ((2 << 20) - 1536, pattern(21, 3072))])
    open(out, 'wb').write(hosted_sparse(disk, grain=8))
    expect(os.path.dirname(out), os.path.basename(out), 'read', disk.size, disk_digests(disk),
           'crafted')


def vmware(spec, out, cid):
    disk = eval_disk(spec)
    open(out, 'wb').write(vmware_stream(disk, os.path.basename(out), int(cid, 16)))
    expect(os.path.dirname(out), os.path.basename(out), 'read', disk.size, disk_digests(disk),
           'crafted')


def vmdk_header(path, field, value):
    data = bytearray(open(path, 'rb').read())
    at = {'flags': (8, '<I'), 'grain': (20, '<Q'), 'compress': (77, '<H')}[field]
    struct.pack_into(at[1], data, at[0], int(value, 0))
    open(path, 'wb').write(data)


# ---- The big disk ----

def big_disk():
    """5 GiB and 1,536 bytes of zeros but small patterns across awkward places."""
    size = (5 << 30) + 1536
    return Disk(size, [
        (0, pattern(30, 4096)),
        ((32 << 20) - 512, pattern(31, 1024)),   # a grain table's end (64 KiB grains)
        ((1 << 31) - 512, pattern(33, 1024)),    # 2^31, the first 2 GiB extent's end
        ((1 << 32) - 512, pattern(34, 1024)),    # 2^32, the second's
        (size - 1024, pattern(35, 1024)),        # the disk's end, in a part of a grain
    ])


def eval_disk(spec):
    if spec == 'big':
        return big_disk()
    data = open(spec, 'rb').read()
    return Disk(len(data), [(0, data)])


def write_big(path):
    disk = big_disk()
    with open(path, 'wb') as f:
        f.truncate(disk.size)
        for off, data in disk.segs:
            f.seek(off)
            f.write(data)


# ---- QCOW2 ----

def qcow_or(path, at, bits):
    data = bytearray(open(path, 'rb').read(4096))
    v = struct.unpack_from('>Q', data, at)[0] | int(bits, 0)
    with open(path, 'r+b') as f:
        f.seek(at)
        f.write(struct.pack('>Q', v))


def qcow_ext_type(path, old, new):
    """Gives the header extension of type `old` type `new`, which readers skip: an image that
    records no backing format, as qemu-img made them before it had to."""
    data = bytearray(open(path, 'rb').read(1 << 16))
    at = struct.unpack_from('>I', data, 100)[0]
    while True:
        t, n = struct.unpack_from('>II', data, at)
        assert t, f'no extension {old}'
        if t == int(old, 0):
            with open(path, 'r+b') as f:
                f.seek(at)
                f.write(struct.pack('>I', int(new, 0)))
            return
        at += 8 + -(-n // 8) * 8


def qcow_byte(path, at, value):
    with open(path, 'r+b') as f:
        f.seek(int(at, 0))
        f.write(bytes([int(value, 0)]))


# ---- VDI ----

def vdi_ids(path, create, modify, linkage='0', pmodify='0'):
    data = bytearray(open(path, 'rb').read())
    for i, n in enumerate((create, modify, linkage, pmodify)):
        n = int(n, 16)
        data[392 + 16 * i:408 + 16 * i] = fixed_uuid(n).bytes_le if n else bytes(16)
    open(path, 'wb').write(data)


def vdi_image(blocks, size, block=1 << 20, kind=1, extra=0, order=None, header=0x190,
              ids=(1, 2, 0, 0), version=0x00010001):
    """A VDI 1.1 image as VirtualBox lays one out: header, block map at 512, blocks. `blocks`
    maps a block number to its bytes or to 'zero' (0xFFFFFFFE); the others are free
    (0xFFFFFFFF). `order` is the order the data blocks are stored in."""
    count = -(-size // block)
    off_blocks = 512
    off_data = off_blocks + -(-count * 4 // 512) * 512
    stored = [b for b in sorted(blocks) if blocks[b] != 'zero'] if order is None else order
    bmap = [0xFFFFFFFF] * count
    for b, v in blocks.items():
        if v == 'zero':
            bmap[b] = 0xFFFFFFFE
    body = bytearray()
    for slot, b in enumerate(stored):
        bmap[b] = slot
        payload = blocks[b] + bytes(block - len(blocks[b]))
        body += b'\xAB' * extra + payload
    h = bytearray(off_blocks)
    text = b'<<< Oracle VM VirtualBox Disk Image >>>\n'
    h[:len(text)] = text
    struct.pack_into('<III', h, 64, 0xBEDA107F, version, header)
    struct.pack_into('<II', h, 76, kind, 0)
    h[84:84 + 19] = b'BeeZip test fixture'
    struct.pack_into('<II', h, 340, off_blocks, off_data)
    struct.pack_into('<IIII', h, 348, 0, 0, 0, 512)
    struct.pack_into('<QIIII', h, 368, size, block, extra, count, len(stored))
    for i, n in enumerate(ids):
        if n:
            h[392 + 16 * i:408 + 16 * i] = fixed_uuid(n).bytes_le
    if header >= 0x190:
        struct.pack_into('<IIII', h, 456, 0, 0, 0, 512)
    out = bytes(h) + b''.join(struct.pack('<I', x) for x in bmap)
    out += bytes(off_data - len(out))
    return out + bytes(body)


def vdis(raw, outdir):
    data = open(raw, 'rb').read()
    k64 = 1 << 16
    put = lambda name, img: open(os.path.join(outdir, name), 'wb').write(img)
    note = lambda name, disk: expect(outdir, name, 'read', len(disk), disk_digests(
        Disk(len(disk), [(0, disk)])), 'crafted')
    # 512 KiB in blocks of 64 KiB: disk.img's four (the third is all zeros, so discarded), then
    # free blocks but the seventh; stored seventh first, then backwards.
    disk = bytearray(8 * k64)
    disk[:len(data)] = data
    disk[6 * k64:7 * k64] = pattern(40, k64)
    disk = bytes(disk)
    blocks = {i: disk[i * k64:(i + 1) * k64] for i in (0, 1, 3, 6)}
    blocks[2] = 'zero'
    assert not any(disk[2 * k64:3 * k64])
    put('d-vbox.vdi', vdi_image(blocks, len(disk), block=k64, order=[6, 3, 1, 0], ids=(0x310, 0x311, 0, 0)))
    note('d-vbox.vdi', disk)
    # A block of 2 MiB holding disk.img, the file ending with the disk 256 KiB into it
    # (VirtualBox would store the block whole).
    img = vdi_image({0: data}, len(data), block=2 << 20, ids=(0x320, 0x321, 0, 0))
    put('d-2m.vdi', img[:len(img) - (2 << 20) + len(data)])
    note('d-2m.vdi', data)
    # A fixed image of 64 KiB blocks, 12,800 bytes into its fifth.
    odd = data + pattern(41, 12800)
    put('d-odd.vdi', vdi_image({i: odd[i * k64:(i + 1) * k64] for i in range(5)}, len(odd),
                               block=k64, kind=2, ids=(0x330, 0x331, 0, 0)))
    note('d-odd.vdi', odd)
    # Refused: extra bytes before each block; an undo image.
    put('d-extra.vdi', vdi_image({0: data[:512]}, 4096, block=512, extra=512, ids=(0x340, 0x341, 0, 0)))
    expect(outdir, 'd-extra.vdi', 'UnsupportedOperation')
    put('d-undo.vdi', vdi_image({0: data[:512]}, 4096, block=512, kind=3, ids=(0x350, 0x351, 0, 0)))
    expect(outdir, 'd-undo.vdi', 'UnsupportedOperation')
    # A differencing chain as VirtualBox lays one out: the base beside the VM, the children in
    # Snapshots/ named by their uuids. Child: block 2 new, block 3 discarded, the rest the base's.
    # Grandchild: block 0 rewritten (4 KiB of random.bin changed).
    put('d-base.vdi', vdi_image(blocks, len(disk), block=k64, ids=(0x401, 0x402, 0, 0)))
    note('d-base.vdi', disk)
    snaps = os.path.join(outdir, 'Snapshots')
    child = bytearray(disk)
    child[2 * k64:3 * k64] = b'\xC7' * k64
    child[3 * k64:4 * k64] = bytes(k64)
    child = bytes(child)
    name = lambda n: os.path.join('Snapshots', '{%s}.vdi' % fixed_uuid(n))
    put(name(0x411), vdi_image({2: child[2 * k64:3 * k64], 3: 'zero'}, len(disk), block=k64,
                               kind=4, ids=(0x411, 0x412, 0x401, 0x402)))
    note(name(0x411).replace('\\', '/'), child)
    gchild = child[:53248] + b'\xD8' * 4096 + child[57344:]
    put(name(0x421), vdi_image({0: gchild[:k64]}, len(disk), block=k64, kind=4,
                               ids=(0x421, 0x422, 0x411, 0x412)))
    note(name(0x421).replace('\\', '/'), gchild)
    # Its parent changed after it was made (uuidParentModify isn't the base's uuidModify); an
    # orphan, whose parent is nowhere.
    put(name(0x431), vdi_image({2: child[2 * k64:3 * k64]}, len(disk), block=k64, kind=4,
                               ids=(0x431, 0x432, 0x401, 0x499)))
    expect(outdir, name(0x431).replace('\\', '/'), 'NotFound')
    put(name(0x441), vdi_image({2: child[2 * k64:3 * k64]}, len(disk), block=k64, kind=4,
                               ids=(0x441, 0x442, 0x4FF, 0x4FE)))
    expect(outdir, name(0x441).replace('\\', '/'), 'NotFound')


def vdi_loop(outdir):
    """Two differencing VDIs, each the other's parent by uuid."""
    for name, ids in (('vdisk-vdi-a.vdi', (0x501, 0x502, 0x511, 0)),
                      ('vdisk-vdi-b.vdi', (0x511, 0x512, 0x501, 0))):
        img = vdi_image({0: b'\x5A' * 512}, 4096, block=512, kind=4, ids=ids)
        open(os.path.join(outdir, name), 'wb').write(img)


if __name__ == '__main__':
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == 'keys':
        set_keys(args[0], **dict(a.split('=', 1) for a in args[1:]))
    elif cmd == 'multi':
        multi(*args)
    elif cmd == 'bare':
        bare(*args)
    elif cmd == 'vmware':
        vmware(*args)
    elif cmd == 'split':
        split(*args)
    elif cmd == 'vmdk-header':
        vmdk_header(*args)
    elif cmd == 'big':
        write_big(args[0])
    elif cmd == 'qcow-or':
        qcow_or(args[0], int(args[1], 0), args[2])
    elif cmd == 'qcow-ext-type':
        qcow_ext_type(*args)
    elif cmd == 'qcow-byte':
        qcow_byte(*args)
    elif cmd == 'vdi-ids':
        vdi_ids(*args)
    elif cmd == 'vdis':
        vdis(*args)
    elif cmd == 'vdi-loop':
        vdi_loop(*args)
    elif cmd == 'expect':
        expect(*args)
    elif cmd == 'expect-raw':
        # name, raw file, how: qemu-img's reading of the image.
        expect(os.path.dirname(args[0]) or '.', os.path.basename(args[0]), 'read',
               os.path.getsize(args[1]), file_digests(args[1]), 'qemu')
    elif cmd == 'digests':
        print(*file_digests(args[0]))
    else:
        raise SystemExit(f'unknown command {cmd}')
PY
    C() { python3 -I "$W/craft.py" "$@"; }
    q() { "${faked[@]}" qemu-img "$@"; }
    io() { "${faked[@]}" qemu-io "$@" >/dev/null; }
    # Each VMDK's content id, fixed: qemu-img draws one when it makes a disk, and qemu-io a new
    # one on a disk's first write.
    cid() { C keys "$1" "CID=$2" "${@:3}"; }

    # ---- disk.img ----
    T=$W/tree
    mkdir -p "$T/sub"
    printf 'Hello from a virtual disk.\n' > "$T/readme.txt"
    printf 'nested\n' > "$T/sub/nested.txt"
    python3 -I -c 'import random, sys; r = random.Random(8); open(sys.argv[1], "wb").write(bytes(r.getrandbits(8) for _ in range(24576)))' "$T/random.bin"
    find "$T" -exec touch -h -d @$E {} +
    mkfs.fat --invariant -i 6d7a6970 -F 12 -n BEEZIP -C "$W/fat.img" 192 >/dev/null
    mcopy -i "$W/fat.img" -s -m "$T/readme.txt" "$T/random.bin" "$T/sub" ::/
    cd "$out"
    truncate -s 256K disk.img
    sfdisk -q disk.img <<'EOF'
label: gpt
label-id: 6D7A6970-6265-457A-8970-000000000500
first-lba: 34
start=64, size=384, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=6D7A6970-6265-457A-8970-000000000501, name="data"
EOF
    dd if="$W/fat.img" of=disk.img bs=512 seek=64 conv=notrunc status=none

    # ---- VMDK ----
    c() { q convert -f raw -O "$@"; }
    c vmdk -o subformat=monolithicSparse disk.img v-sparse.vmdk && cid v-sparse.vmdk 6d7a0001
    c vmdk -o subformat=monolithicSparse,compat6=on disk.img v-compat6.vmdk && cid v-compat6.vmdk 6d7a0002
    c vmdk -o subformat=monolithicSparse,zeroed_grain=on disk.img v-zg.vmdk
    io -f vmdk -c 'write -z 131072 65536' v-zg.vmdk && cid v-zg.vmdk 6d7a0003
    c vmdk -o subformat=monolithicFlat disk.img v-flat.vmdk && cid v-flat.vmdk 6d7a0004
    c vmdk -o subformat=twoGbMaxExtentSparse disk.img v-2gs.vmdk && cid v-2gs.vmdk 6d7a0005
    c vmdk -o subformat=twoGbMaxExtentFlat disk.img v-2gf.vmdk && cid v-2gf.vmdk 6d7a0006
    c vmdk -o subformat=streamOptimized disk.img v-stream.vmdk && cid v-stream.vmdk 6d7a0007
    # Children: parentFileNameHint and parentCID. Writes go where disk.img is zeros or random.bin
    # is, so the FAT volume stays whole.
    q create -q -f vmdk -b v-sparse.vmdk -F vmdk v-child.vmdk && cid v-child.vmdk 6d7a0008
    io -f vmdk -c 'write -P 0xc1 65536 4096' -c 'write -P 0xc2 140000 30000' v-child.vmdk
    cid v-child.vmdk 6d7a0008
    q create -q -f vmdk -b v-child.vmdk -F vmdk v-gchild.vmdk && cid v-gchild.vmdk 6d7a0009
    io -f vmdk -c 'write -P 0xd1 66048 512' -c 'write -z 140000 4096' v-gchild.vmdk
    cid v-gchild.vmdk 6d7a0009
    q create -q -f vmdk -b v-flat.vmdk -F vmdk v-child-flat.vmdk && cid v-child-flat.vmdk 6d7a000a
    io -f vmdk -c 'write -P 0xe1 196608 8192' v-child-flat.vmdk
    cid v-child-flat.vmdk 6d7a000a
    # ESXi's descriptor over the flat file.
    sed -e 's/createType="monolithicFlat"/createType="vmfs"/' -e 's/ FLAT "v-flat-flat.vmdk" 0/ VMFS "v-flat-flat.vmdk"/' \
        -e 's/^CID=.*/CID=6d7a000b/' v-flat.vmdk > v-vmfs.vmdk
    # Crafted: several extent types; a bare sparse extent; VMware's stream layout.
    C multi disk.img .
    qemu-img compare -q -f raw -F vmdk disk.img v-multi-check.vmdk
    rm v-multi-check.vmdk v-multi-z.bin
    C bare disk.img v-bare.vmdk
    C vmware disk.img v-vmware.vmdk 6d7a000c
    qemu-img compare -q -f raw -F vmdk disk.img v-vmware.vmdk
    # Refused.
    refuse() { # name createType type
        printf '# Disk DescriptorFile\nversion=1\nCID=6d7a00%s\nparentCID=ffffffff\ncreateType="%s"\n\n# Extent description\nRW 512 %s "%s"\n' \
            "$4" "$2" "$3" "${1%.vmdk}-x.vmdk" > "$1"
        C expect . "$1" UnsupportedOperation
    }
    refuse v-refuse-vmfssparse.vmdk vmfsSparse VMFSSPARSE 20
    refuse v-refuse-sesparse.vmdk seSparse SESPARSE 21
    refuse v-refuse-rdm.vmdk vmfsRawDeviceMap VMFSRDM 22
    # Cut after the descriptor: BeeZip refuses them from the header.
    head -c 65536 v-stream.vmdk > v-refuse-nomarkers.vmdk && C vmdk-header v-refuse-nomarkers.vmdk flags 0x10003
    cid v-refuse-nomarkers.vmdk 6d7a0023
    C expect . v-refuse-nomarkers.vmdk UnsupportedOperation
    head -c 65536 v-stream.vmdk > v-refuse-method.vmdk && C vmdk-header v-refuse-method.vmdk compress 2
    cid v-refuse-method.vmdk 6d7a0024
    C expect . v-refuse-method.vmdk UnsupportedOperation

    # ---- VDI ----
    c vdi disk.img d-dyn.vdi && C vdi-ids d-dyn.vdi 360 361
    c vdi -o static=on disk.img d-fixed.vdi && C vdi-ids d-fixed.vdi 362 363
    C vdis disk.img .

    # ---- QCOW2 ----
    k4=cluster_size=4096
    c qcow2 disk.img q-v3.qcow2
    c qcow2 -o $k4,compat=0.10 disk.img q-v2.qcow2
    c qcow2 -c disk.img q-deflate.qcow2
    c qcow2 -c -o compression_type=zstd disk.img q-zstd.qcow2
    c qcow2 -o cluster_size=512 disk.img q-c512.qcow2
    c qcow2 -o $k4,refcount_bits=1 disk.img q-rc1.qcow2
    c qcow2 -o $k4,refcount_bits=64 disk.img q-rc64.qcow2
    # Zero clusters: one kept allocated (its offset must never be read), one unmapped, one
    # discarded; and in a v2 image, where qemu has no zero flag.
    c qcow2 -o $k4 disk.img q-zero.qcow2
    io -f qcow2 -c 'write -z 61440 8192' -c 'write -z -u 245760 4096' -c 'discard 253952 4096' q-zero.qcow2
    c qcow2 -o $k4,compat=0.10 disk.img q-zero-v2.qcow2
    io -f qcow2 -c 'write -z 61440 8192' q-zero-v2.qcow2
    # Backing files.
    q create -q -f qcow2 -o $k4 -b q-v3.qcow2 -F qcow2 q-child.qcow2
    io -f qcow2 -c 'write -P 0xa1 65536 4096' -c 'write -P 0xa2 140000 30000' q-child.qcow2
    q create -q -f qcow2 -o $k4 -b disk.img -F raw q-child-raw.qcow2
    io -f qcow2 -c 'write -P 0xa3 66000 3000' q-child-raw.qcow2
    q create -q -f qcow2 -o $k4 -b q-child.qcow2 -F qcow2 q-gchild.qcow2
    io -f qcow2 -c 'write -P 0xa4 66048 512' -c 'write -z 140000 65536' q-gchild.qcow2
    q create -q -f qcow2 -o $k4 -b disk.img -F raw q-child-big.qcow2 1M
    io -f qcow2 -c 'write -P 0xa5 600000 4096' q-child-big.qcow2
    q create -q -f qcow2 -o $k4 -b v-sparse.vmdk -F vmdk q-child-vmdk.qcow2
    io -f qcow2 -c 'write -P 0xa6 65536 8192' q-child-vmdk.qcow2
    q create -q -f qcow2 -o $k4 -b d-dyn.vdi -F vdi q-child-vdi.qcow2
    io -f qcow2 -c 'write -P 0xa7 65536 8192' q-child-vdi.qcow2
    q create -q -f qcow2 -o $k4 -b disk.img -F raw q-child-sniff.qcow2
    io -f qcow2 -c 'write -P 0xa8 65536 4096' q-child-sniff.qcow2
    C qcow-ext-type q-child-sniff.qcow2 0xE2792ACA 0x6E6F6E65
    # Internal snapshots: the image changes after each.
    c qcow2 -o $k4 disk.img q-snap.qcow2
    q snapshot -c first q-snap.qcow2
    io -f qcow2 -c 'write -P 0xb1 65536 8192' -c 'write -z 200704 4096' q-snap.qcow2
    q snapshot -c second q-snap.qcow2
    io -f qcow2 -c 'write -P 0xb2 150000 1000' q-snap.qcow2
    # Extended L2 entries: alone (with a zeroed subcluster), compressed, and over disk.img with
    # writes of 2 KiB (one subcluster) so a cluster is part this image's, part disk.img's.
    c qcow2 -o extended_l2=on disk.img q-el2.qcow2
    io -f qcow2 -c 'write -z 70000 4096' q-el2.qcow2
    c qcow2 -c -o cluster_size=16384,extended_l2=on disk.img q-el2-deflate.qcow2
    q create -q -f qcow2 -o cluster_size=16384,extended_l2=on -b disk.img -F raw q-el2-child.qcow2
    io -f qcow2 -c 'write -P 0xb3 55296 2048' -c 'write -P 0xb4 133120 6144' -c 'write -z 200704 2048' q-el2-child.qcow2
    # External data files, raw (guest offset = host offset) and not.
    q create -q -f qcow2 -o $k4,data_file=q-data-raw.bin,data_file_raw=on q-data-raw.qcow2 256K
    q convert -n -f raw -O qcow2 disk.img q-data-raw.qcow2
    q create -q -f qcow2 -o $k4,data_file=q-data.bin q-data.qcow2 256K
    q convert -n -f raw -O qcow2 disk.img q-data.qcow2
    # Header bits, crafted: dirty (lazy refcounts), corrupt; refused: an unknown incompatible
    # bit, compression type 2.
    c qcow2 -o $k4 disk.img q-dirty.qcow2 && C qcow-or q-dirty.qcow2 72 1
    c qcow2 -o $k4 disk.img q-corrupt.qcow2 && C qcow-or q-corrupt.qcow2 72 2
    c qcow2 -o $k4 disk.img q-refuse-bit.qcow2 && C qcow-or q-refuse-bit.qcow2 72 0x20
    C expect . q-refuse-bit.qcow2 UnsupportedOperation
    c qcow2 -o $k4 disk.img q-refuse-ctype.qcow2 && C qcow-or q-refuse-ctype.qcow2 72 8 && C qcow-byte q-refuse-ctype.qcow2 104 2
    C expect . q-refuse-ctype.qcow2 UnsupportedOperation
    # Refused: encryption; QCOW version 1.
    q convert --object secret,id=s0,data=beezip -f raw -O qcow2 -o $k4,encrypt.format=aes,encrypt.key-secret=s0 disk.img q-aes.qcow2
    C expect . q-aes.qcow2 UnsupportedOperation
    q convert --object secret,id=s0,data=beezip -f raw -O qcow2 -o encrypt.format=luks,encrypt.key-secret=s0,encrypt.iter-time=10 disk.img q-luks.qcow2
    truncate -s 64K q-luks.qcow2
    C expect . q-luks.qcow2 UnsupportedOperation
    c qcow disk.img q-v1.qcow
    C expect . q-v1.qcow UnsupportedOperation

    # ---- The big disk ----
    # qemu-img's twoGbMaxExtentSparse extents are 2 GiB: b-split's are cut where its are.
    q create -q -f vmdk -o subformat=twoGbMaxExtentSparse "$W/probe.vmdk" 5G
    ext=$(sed -n 's/^RW \([0-9]*\) SPARSE.*/\1/p' "$W/probe.vmdk" | head -n 1)
    [ "$ext" = 4194304 ]
    big=$W/big.img
    C big "$big"
    c qcow2 -o $k4 "$big" b-c4k.qcow2
    C split big b-split.vmdk $((ext * 512)) 6d7a0031
    qemu-img compare -q -f raw -F vmdk "$big" b-split.vmdk
    C vmware big b-vmware.vmdk 6d7a0033
    qemu-img compare -q -f raw -F vmdk "$big" b-vmware.vmdk
    rm -f "$big"

    # ---- The zero-filled file ----
    head -c 83886080 /dev/zero > "$W/zeros.bin"
    touch -d @$E "$W/zeros.bin"
    mkfs.fat --invariant -i 6d7a6971 -F 16 -s 32 -n ZEROS -C "$W/zeros.img" 102400 >/dev/null
    mcopy -i "$W/zeros.img" -m "$W/zeros.bin" ::/
    c vmdk -o subformat=monolithicSparse "$W/zeros.img" z.vmdk && cid z.vmdk 6d7a0040
    c qcow2 -c -o $k4 "$W/zeros.img" z-deflate.qcow2
    rm -f "$W/zeros.img" "$W/zeros.bin"

    # ---- What qemu-img reads ----
    for f in v-sparse v-compat6 v-zg v-flat v-2gs v-2gf v-stream v-child v-gchild v-child-flat v-vmfs \
             q-v3 q-v2 q-deflate q-zstd q-c512 q-rc1 q-rc64 q-zero q-zero-v2 q-child q-child-raw \
             q-gchild q-child-big q-child-vmdk q-child-vdi q-child-sniff q-snap q-el2 q-el2-deflate \
             q-el2-child q-data-raw q-data q-dirty q-corrupt d-dyn d-fixed \
             b-c4k z z-deflate; do
        for e in vmdk qcow2 vdi; do [ -f "$f.$e" ] && f=$f.$e && break; done
        rm -f "$W/o.raw"
        qemu-img convert -O raw "$f" "$W/o.raw"
        C expect-raw "$f" "$W/o.raw"
    done
    rm -f "$W/o.raw"
    for f in *.vmdk *.qcow2 *.qcow *.vdi Snapshots/*.vdi; do
        case "$f" in v-multi-c.vmdk|v-2gs-s*.vmdk|v-flat-flat.vmdk|v-2gf-f*.vmdk|b-split-s*.vmdk) continue;; esac
        cut -f1 expected.tsv | grep -qxF "$f" || { echo "no expectation for $f" >&2; exit 1; }
    done
    sort -o expected.tsv expected.tsv
    sed -i '1i file\toutcome\tsize\tsha256\tdigest\thow' expected.tsv

    # ---- The malicious images ----
    cd "$mal"
    small() { q create -q -f qcow2 -o $k4 "$1" 64K; }
    small vdisk-loop-a.qcow2 && small vdisk-loop-b.qcow2
    q rebase -u -f qcow2 -b vdisk-loop-b.qcow2 -F qcow2 vdisk-loop-a.qcow2
    q rebase -u -f qcow2 -b vdisk-loop-a.qcow2 -F qcow2 vdisk-loop-b.qcow2
    small vdisk-self.qcow2 && q rebase -u -f qcow2 -b vdisk-self.qcow2 -F qcow2 vdisk-self.qcow2
    small vdisk-json.qcow2
    q rebase -u -f qcow2 -b 'json:{"file.driver":"file","file.filename":"/etc/passwd"}' -F raw vdisk-json.qcow2
    small vdisk-nbd.qcow2 && q rebase -u -f qcow2 -b 'nbd://localhost:10809/x' -F raw vdisk-nbd.qcow2
    small vdisk-unc.qcow2 && q rebase -u -f qcow2 -b '\\server\share\base.qcow2' -F qcow2 vdisk-unc.qcow2
    printf '# Disk DescriptorFile\nversion=1\nCID=6d7a0050\nparentCID=ffffffff\ncreateType="fullDevice"\n\n# Extent description\nRW 4096 FLAT "\\\\.\\PhysicalDrive0" 0\n' \
        > vdisk-device.vmdk
    cp "$out/v-child.vmdk" vdisk-vmdk-self.vmdk
    C keys vdisk-vmdk-self.vmdk CID=6d7a0051 parentCID=6d7a0051 parentFileNameHint='"vdisk-vmdk-self.vmdk"'
    C vdi-loop .
    cp "$out/v-stream.vmdk" vdisk-grain-1g.vmdk && C vmdk-header vdisk-grain-1g.vmdk grain 0x200000
    q create -q -f qcow2 vdisk-2t.qcow2 2T
    printf '# Disk DescriptorFile\nversion=1\nCID=6d7a0052\nparentCID=ffffffff\ncreateType="custom"\n\n# Extent description\nRW 4294967296 ZERO\n' \
        > vdisk-zero-2t.vmdk
    chown -R "${HOST_IDS:-0:0}" "$out" "$mal"/vdisk-* || true
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
MSYS_NO_PATHCONV=1 docker run --rm -e HOST_IDS="$(id -u):$(id -g)" \
    -v "$(host "$here"):/fixtures" beezip-fixtures-7z bash /fixtures/make-vdisk.sh --inside
