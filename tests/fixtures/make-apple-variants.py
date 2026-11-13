"""Makes tests/fixtures/thirdparty/apple/ (docs/M11.md §6.3): HFS+ and APFS volumes in the
layouts real Macs write and fstool 0.5.2 didn't read, crafted from the committed bare volumes
thirdparty/7zip/dmg-hfs.hfs and dmg-apfs.apfs (make-7z.sh took them out of make-dmg.sh's DMGs):

  hfs-catalog-overflow.hfs.xz  dmg-hfs.hfs with its catalog file's 20 blocks moved apart, one
                               extent each: eight in the volume header, twelve in two records of
                               the extents-overflow file (as a long-used volume's catalog is)
  apfs-sealed.apfs.xz          dmg-apfs.apfs as a sealed volume (macOS 11+'s system volume): the
                               sealed flag (0x20) set, its files' extents copied into a
                               file-extent tree (apfs_fext_tree_oid) in a free block, and taken
                               out of the fs-tree, as a sealed volume keeps them

Each holds the files of the volume it came from, with the same bytes: with 7-Zip installed (it
reads both layouts), the script checks that it extracts the same files from each pair. They're
xz-compressed for the repository; BeeZip reads them through the codec. Deterministic: a rerun
writes the same bytes.

    python -I tests/fixtures/make-apple-variants.py [folder to also write them to]
"""
import hashlib, lzma, os, shutil, struct, subprocess, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(here, 'thirdparty', '7zip')
out = os.path.join(here, 'thirdparty', 'apple')
os.makedirs(out, exist_ok=True)


# ---- HFS+ ------------------------------------------------------------------------------------

def be16(b, at): return struct.unpack_from('>H', b, at)[0]
def be32(b, at): return struct.unpack_from('>I', b, at)[0]


def hfs_catalog_overflow(d):
    d = bytearray(d)
    vh = 1024
    bs = be32(d, vh + 0x28)
    total = be32(d, vh + 0x2C)
    fork = lambda off: (vh + off, be32(d, vh + off + 12),
                        [struct.unpack_from('>II', d, vh + off + 16 + 8 * i) for i in range(8)])
    _, _, alloc_ext = fork(0x70)
    _, _, ext_ext = fork(0xC0)
    cat_at, cat_blocks, cat_ext = fork(0x110)
    assert alloc_ext[0][1] >= 1 and ext_ext[1][1] == 0 and cat_ext[1][1] == 0
    bitmap_at = alloc_ext[0][0] * bs
    used = lambda n: d[bitmap_at + n // 8] & (0x80 >> (n % 8))

    def mark(n, on):
        if on:
            d[bitmap_at + n // 8] |= 0x80 >> (n % 8)
        else:
            d[bitmap_at + n // 8] &= ~(0x80 >> (n % 8)) & 0xFF

    # Each catalog block to a free block of its own, every other free one, past the catalog.
    start, count = cat_ext[0]
    free = [n for n in range(start + count, total - 2) if not used(n)][::2]
    assert len(free) >= count, (len(free), count)
    new = free[:count]
    for i, n in enumerate(new):
        d[n * bs:(n + 1) * bs] = d[(start + i) * bs:(start + i + 1) * bs]
        mark(n, True)
    for i in range(count):
        mark(start + i, False)
        d[(start + i) * bs:(start + i + 1) * bs] = bytes(bs)
    extents = [(n, 1) for n in new]

    # The first eight in the volume header (and its copy at the volume's end).
    for at in (vh, total * bs - 1024):
        for i in range(8):
            struct.pack_into('>II', d, at + 0x110 + 16 + 8 * i, *extents[i])

    # The rest in the extents-overflow file's first leaf: records of eight, keyed by the
    # catalog's CNID (4), the data fork (0) and the fork block they start at.
    ext_at = ext_ext[0][0] * bs
    hdr = ext_at + 14
    node_size = be16(d, hdr + 18)
    assert be32(d, hdr + 2) == 0, 'the extents-overflow file is empty'
    recs = []
    for first in range(8, count, 8):
        group = extents[first:first + 8] + [(0, 0)] * (8 - len(extents[first:first + 8]))
        key = struct.pack('>HBBII', 10, 0, 0, 4, first)
        recs.append(key + b''.join(struct.pack('>II', *e) for e in group))
    leaf = bytearray(node_size)
    struct.pack_into('>IIbBHH', leaf, 0, 0, 0, -1, 1, len(recs), 0)
    at = 14
    offsets = []
    for r in recs:
        offsets.append(at)
        leaf[at:at + len(r)] = r
        at += len(r)
    offsets.append(at)
    for i, o in enumerate(offsets):
        struct.pack_into('>H', leaf, node_size - 2 * (i + 1), o)
    d[ext_at + node_size:ext_at + 2 * node_size] = leaf
    # The header record: depth 1, root and only leaf node 1, its records; node 1 in the map.
    struct.pack_into('>HIIII', d, hdr, 1, 1, len(recs), 1, 1)
    free_nodes = be32(d, hdr + 26)
    struct.pack_into('>I', d, hdr + 26, free_nodes - 1)
    map_rec = ext_at + be16(d, ext_at + node_size - 6)
    d[map_rec] |= 0x40
    return bytes(d)


# ---- APFS ------------------------------------------------------------------------------------

def le16(b, at): return struct.unpack_from('<H', b, at)[0]
def le32(b, at): return struct.unpack_from('<I', b, at)[0]
def le64(b, at): return struct.unpack_from('<Q', b, at)[0]


def fletcher64(block):
    s1 = s2 = 0
    for (w,) in struct.iter_unpack('<I', block[8:]):
        s1 = (s1 + w) % 0xFFFFFFFF
        s2 = (s2 + s1) % 0xFFFFFFFF
    c1 = 0xFFFFFFFF - ((s1 + s2) % 0xFFFFFFFF)
    c2 = 0xFFFFFFFF - ((s1 + c1) % 0xFFFFFFFF)
    return struct.pack('<II', c1, c2)


class Apfs:
    def __init__(self, d):
        self.d = bytearray(d)
        self.bs = le32(self.d, 36)
        nx = self.block(0)
        assert nx[32:36] == b'NXSB'
        # The newest container superblock in the checkpoint area.
        base, count = le64(nx, 112), le32(nx, 104) & 0x7FFFFFFF
        best = nx
        for i in range(count):
            b = self.block(base + i)
            if b[32:36] == b'NXSB' and le64(b, 16) > le64(best, 16):
                best = b
        self.nx = best
        self.xid = le64(best, 16)

    def block(self, n):
        return self.d[n * self.bs:(n + 1) * self.bs]

    def put(self, n, b):
        b = bytearray(b)
        b[:8] = fletcher64(b)
        self.d[n * self.bs:(n + 1) * self.bs] = b

    def node(self, b):
        """A B-tree node's entries: (key bytes, value bytes, value's offset in the block)."""
        flags, level, nkeys = le16(b, 32), le16(b, 34), le32(b, 36)
        toff, tlen = le16(b, 40), le16(b, 42)
        keys = 56 + toff + tlen
        vals = self.bs - (40 if flags & 1 else 0)
        fixed = flags & 4
        out = []
        for i in range(nkeys):
            t = 56 + toff + i * (4 if fixed else 8)
            if fixed:
                ko, vo = le16(b, t), le16(b, t + 2)
                kl, vl = 16, (8 if level else 16)
            else:
                ko, kl, vo, vl = le16(b, t), le16(b, t + 2), le16(b, t + 4), le16(b, t + 6)
            out.append((bytes(b[keys + ko:keys + ko + kl]), bytes(b[vals - vo:vals - vo + vl]),
                        vals - vo))
        return level, out

    def omap_lookup(self, omap_oid, oid):
        root = self.block(le64(self.block(omap_oid), 48))
        level, entries = self.node(root)
        while True:
            best = None
            for k, v, _ in entries:
                ko, kx = le64(k, 0), le64(k, 8)
                if (ko, kx) <= (oid, self.xid):
                    best = (ko, v)
            if level == 0:
                assert best and best[0] == oid, hex(oid)
                return le64(best[1], 8)
            level, entries = self.node(self.block(le64(best[1], 0)))

    def fs_leaves(self, vomap, oid):
        """Every fs-tree leaf block, with its paddr, under virtual node `oid`."""
        p = self.omap_lookup(vomap, oid)
        level, entries = self.node(self.block(p))
        if level == 0:
            yield p
            return
        for _, v, _ in entries:
            yield from self.fs_leaves(vomap, le64(v, 0))


def rebuild_leaf(a, b, entries):
    """Leaf node `b` holding only `entries` (key, value): its table, keys from the front of
    the key area and values from the back of the value area, packed, with no free lists."""
    b = bytearray(b)
    flags, toff, tlen = le16(b, 32), le16(b, 40), le16(b, 42)
    root = flags & 1
    assert le16(b, 34) == 0 and not flags & 4 and len(entries) * 8 <= tlen
    keys = 56 + toff + tlen
    vals = a.bs - (40 if root else 0)
    b[56:vals] = bytes(vals - 56)
    struct.pack_into('<I', b, 36, len(entries))
    struct.pack_into('<HH', b, 40, toff, tlen)
    ko = vo = 0
    for i, (k, v) in enumerate(entries):
        vo += len(v)
        struct.pack_into('<HHHH', b, 56 + toff + i * 8, ko, len(k), vo, len(v))
        b[keys + ko:keys + ko + len(k)] = k
        b[vals - vo:vals - vo + len(v)] = v
        ko += len(k)
    struct.pack_into('<HH', b, 44, ko, (vals - vo) - (keys + ko))
    struct.pack_into('<HHHH', b, 48, 0xFFFF, 0, 0xFFFF, 0)
    if root:
        struct.pack_into('<Q', b, a.bs - 16, len(entries))  # btree_info's key count
    return b


def apfs_sealed(d):
    a = Apfs(d)
    bs = a.bs
    apsb_p = a.omap_lookup(le64(a.nx, 160), le64(a.nx, 184))
    apsb = a.block(apsb_p)
    assert apsb[32:36] == b'APSB'
    vomap, root_oid = le64(apsb, 128), le64(apsb, 136)
    # Every file extent record, taken out of the fs-tree's leaves: a sealed volume keeps them
    # only in its file-extent tree.
    extents = []
    for p in sorted(set(a.fs_leaves(vomap, root_oid))):
        b = a.block(p)
        _, entries = a.node(b)
        keep = []
        for k, v, _ in entries:
            if le64(k, 0) >> 60 == 8:  # APFS_TYPE_FILE_EXTENT
                extents.append(((le64(k, 0) & ((1 << 60) - 1), le64(k, 8)), le64(v, 0), le64(v, 8)))
            else:
                keep.append((k, v))
        if len(keep) < len(entries):
            a.put(p, rebuild_leaf(a, b, keep))
    extents.sort()
    assert extents and len(extents) * 20 + 56 + 40 < bs, len(extents)
    # A free block for the file-extent tree: the container's last, if it's all zeros.
    count = le64(a.nx, 40)
    fext_p = count - 1
    assert a.block(fext_p) == bytes(bs)
    n = len(extents)
    node = bytearray(bs)
    struct.pack_into('<QQII', node, 8, fext_p, a.xid, 0x40000002, 0x1F)  # BTREE, FEXT_TREE
    struct.pack_into('<HHI', node, 32, 1 | 2 | 4, 0, n)  # root, leaf, fixed sizes
    struct.pack_into('<HH', node, 40, 0, n * 4)  # table of contents
    keys = 56 + n * 4
    vals = bs - 40
    for i, ((pid, la), lf, phys) in enumerate(extents):
        struct.pack_into('<HH', node, 56 + i * 4, i * 16, (i + 1) * 16)
        struct.pack_into('<QQ', node, keys + i * 16, pid, la)
        struct.pack_into('<QQ', node, vals - (i + 1) * 16, lf, phys)
    free_off = n * 16
    struct.pack_into('<HH', node, 44, free_off, vals - n * 16 - (keys + free_off))
    struct.pack_into('<HHHH', node, 48, 0xFFFF, 0, 0xFFFF, 0)
    # btree_info: physical, fixed 16-byte keys and values.
    struct.pack_into('<IIIIIIQQ', node, vals, 0x10, bs, 16, 16, 16, 16, n, 1)  # BTREE_PHYSICAL
    a.put(fext_p, node)
    # The volume: sealed, with its file-extent tree.
    apsb = bytearray(apsb)
    struct.pack_into('<Q', apsb, 56, le64(apsb, 56) | 0x20)
    struct.pack_into('<QI', apsb, 1032, fext_p, 0x40000002)
    a.put(apsb_p, apsb)
    return bytes(a.d)


# ---- Out, and against 7-Zip ------------------------------------------------------------------

def seven_zip():
    for p in (os.environ.get('SEVENZIP'), shutil.which('7z'), shutil.which('7zz'),
              r'C:\Program Files\7-Zip\7z.exe'):
        if p and os.path.isfile(p):
            return p
    return None


def tree(seven, path):
    with tempfile.TemporaryDirectory() as t:
        subprocess.run([seven, 'x', '-y', '-bso0', '-bsp0', '-bse0', '-o' + t, path], check=False)
        files = {}
        for dp, _, names in os.walk(t):
            for n in names:
                p = os.path.join(dp, n)
                rel = os.path.relpath(p, t).replace(os.sep, '/')
                files[rel] = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        return files


made = [
    ('dmg-hfs.hfs', 'hfs-catalog-overflow.hfs', hfs_catalog_overflow),
    ('dmg-apfs.apfs', 'apfs-sealed.apfs', apfs_sealed),
]
seven = seven_zip()
# With a folder named, the volumes are also written there as they are, to look at.
keep = sys.argv[1] if len(sys.argv) > 1 else None
for base, name, craft in made:
    data = craft(open(os.path.join(src, base), 'rb').read())
    if keep:
        open(os.path.join(keep, name), 'wb').write(data)
    with lzma.open(os.path.join(out, name + '.xz'), 'wb', preset=9 | lzma.PRESET_EXTREME) as f:
        f.write(data)
    if seven:
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, name)
            open(p, 'wb').write(data)
            want, got = tree(seven, os.path.join(src, base)), tree(seven, p)
        assert got == want, (name, sorted(set(got.items()) ^ set(want.items()))[:10])
        print(f'{name}: {len(got)} files, as 7-Zip extracts them from {base}')
    print(name + '.xz', os.path.getsize(os.path.join(out, name + '.xz')), 'bytes')
