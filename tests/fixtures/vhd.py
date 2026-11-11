"""Helpers for tests/fixtures/make-vhd.ps1 (docs/M8.md §9): raw disks and the bytes Hyper-V's
cmdlets can't write without mounting a disk (admin), written from Microsoft's VHD Image Format
Specification and MS-VHDX.

  python -I tests/fixtures/vhd.py <command> <args...>

- raws SRC WORK          the raw disks under WORK/raw (from the committed images in SRC), and a
                         fixed VHD of each (raw + footer) for Convert-VHD to start from
- fill VHDX RAW          writes RAW into a VHDX's blocks: a fixed one's in place, a dynamic one's
                         nonzero blocks appended as fully present
- diff CHILD BASE MOD    fills an empty differencing child (New-VHD -Differencing) with the sectors
                         where MOD differs from BASE: even blocks fully present, odd ones partially,
                         their other sectors 0xEE so that a reader ignoring the bitmap reads
                         garbage; VHD children alike with VHD's bitmaps
- log SRC DIRTY NOSEQ EXPECT   a copy of the VHDX SRC whose log has two entries to replay (DIRTY),
                         the disk it reads after replay (EXPECT), and DIRTY with both entries
                         damaged and cut after its log (NOSEQ)
- paths FILE PREFIX      replaces the absolute paths a child records of its parent (VHD: W2ku and
                         the Parent Unicode Name; VHDX: absolute_win32_path and volume_path) by
                         PREFIX\\<the path below the work folder>, so that the fixtures name no
                         folder of this machine and are found by their relative paths
- malicious DIR          small crafted VHDs: a parent loop, a self-loop, a UNC parent
- expect FILE RAW        prints the SHA-256 of RAW as FILE's virtual disk reads it (RAW padded with
                         zeros to the disk's size), checking RAW fits
- unfix VHD RAW          the disk of a fixed VHD (Convert-VHD's flattening) as a raw file
"""
import hashlib
import os
import random
import shutil
import struct
import sys
import uuid

MiB = 1 << 20
KiB = 1 << 10

BAT_GUID = uuid.UUID('2DC27766-F623-4200-9D64-115E9BFD4A08').bytes_le
META_GUID = uuid.UUID('8B7CA206-4790-4B9A-B8FE-575F050F886E').bytes_le
FILE_PARAMS = uuid.UUID('CAA16737-FA36-4D43-B3B6-33F0AA44E76B').bytes_le
DISK_SIZE = uuid.UUID('2FA54224-CD1B-4876-B211-5DBED83BF4B8').bytes_le
LOGICAL = uuid.UUID('8141BF1D-A96F-4709-BA47-F233A8FAAB5F').bytes_le
PARENT_LOCATOR = uuid.UUID('A8D35F2D-B30B-454D-ABF7-D3D84834AB0C').bytes_le
LOCATOR_VHDX = uuid.UUID('B04AEFB7-D19E-4A81-B789-25B8E9445913').bytes_le


# ---- CRC-32C, VHDX's checksum ----

def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_T = _crc_table()


def crc32c(b):
    c = 0xFFFFFFFF
    for x in b:
        c = (c >> 8) ^ _T[(c ^ x) & 0xFF]
    return c ^ 0xFFFFFFFF


def checksum_at(buf, at=4):
    buf[at:at + 4] = b'\0\0\0\0'
    struct.pack_into('<I', buf, at, crc32c(bytes(buf)))


# ---- VHD ----

def vhd_checksum(b, at):
    return ~sum(x for i, x in enumerate(b) if not at <= i < at + 4) & 0xFFFFFFFF


def chs(size):
    """The disk geometry, by the VHD specification's appendix."""
    ts = min(size // 512, 65535 * 16 * 255)
    if ts >= 65535 * 16 * 63:
        spt, heads = 255, 16
        cth = ts // spt
    else:
        spt = 17
        cth = ts // spt
        heads = max((cth + 1023) // 1024, 4)
        if cth >= heads * 1024 or heads > 16:
            spt, heads = 31, 16
            cth = ts // spt
        if cth >= heads * 1024:
            spt, heads = 63, 16
            cth = ts // spt
    return (cth // heads) << 16 | heads << 8 | spt


def vhd_footer(size, kind, data_offset, uid):
    f = bytearray(512)
    f[0:8] = b'conectix'
    struct.pack_into('>IIQI', f, 8, 2, 0x00010000, data_offset, 0)
    f[28:32] = b'bzfx'
    struct.pack_into('>I', f, 32, 0x00010000)
    f[36:40] = b'Wi2k'
    struct.pack_into('>QQII', f, 40, size, size, chs(size), kind)
    f[68:84] = uid
    struct.pack_into('>I', f, 64, vhd_checksum(f, 64))
    return bytes(f)


class Vhd:
    """A dynamic or differencing VHD's footer, header and block table."""

    def __init__(self, path):
        self.path = path
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            f.seek(size - 512)
            self.footer = bytearray(f.read(512))
            assert self.footer[:8] == b'conectix'
            self.kind = struct.unpack_from('>I', self.footer, 60)[0]
            self.size = struct.unpack_from('>Q', self.footer, 48)[0]
            if self.kind == 2:
                return
            self.dyn_off = struct.unpack_from('>Q', self.footer, 16)[0]
            f.seek(self.dyn_off)
            self.dyn = bytearray(f.read(1024))
            assert self.dyn[:8] == b'cxsparse'
            self.table = struct.unpack_from('>Q', self.dyn, 16)[0]
            self.entries, self.block = struct.unpack_from('>II', self.dyn, 28)
            f.seek(self.table)
            self.bat = list(struct.unpack('>%dI' % self.entries, f.read(4 * self.entries)))


# ---- VHDX ----

class Vhdx:
    """A VHDX's current header, regions, metadata items and block table (its log must be
    empty)."""

    def __init__(self, path, active=False):
        self.path = path
        with open(path, 'rb') as f:
            data = f.read(4 * MiB)
        heads = []
        for off in (64 * KiB, 128 * KiB):
            h = data[off:off + 4096]
            if h[:4] == b'head':
                heads.append((struct.unpack_from('<Q', h, 8)[0], off, h))
        self.seq, self.header_off, self.header = max(heads)
        assert active or self.header[48:64] == b'\0' * 16, 'the log is active'
        rt = data[192 * KiB:256 * KiB]
        assert rt[:4] == b'regi'
        for i in range(struct.unpack_from('<I', rt, 8)[0]):
            e = rt[16 + 32 * i:48 + 32 * i]
            off, length = struct.unpack_from('<QI', e, 16)
            if e[:16] == BAT_GUID:
                self.bat_off, self.bat_len = off, length
            elif e[:16] == META_GUID:
                self.meta_off = off
        with open(path, 'rb') as f:
            f.seek(self.meta_off)
            meta = f.read(MiB)
        assert meta[:8] == b'metadata'
        self.items = {}
        for i in range(struct.unpack_from('<H', meta, 10)[0]):
            e = meta[32 + 32 * i:64 + 32 * i]
            off, length = struct.unpack_from('<II', e, 16)
            self.items[e[:16]] = (self.meta_off + off, meta[off:off + length])
        self.block, self.flags = struct.unpack_from('<II', self.items[FILE_PARAMS][1], 0)
        self.size = struct.unpack_from('<Q', self.items[DISK_SIZE][1], 0)[0]
        self.sector = struct.unpack_from('<I', self.items[LOGICAL][1], 0)[0]
        self.chunk = (1 << 23) * self.sector // self.block
        self.blocks = -(-self.size // self.block)
        with open(path, 'rb') as f:
            f.seek(self.bat_off)
            raw = f.read(self.bat_len)
        self.bat = list(struct.unpack_from('<%dQ' % (self.bat_len // 8), raw))

    def payload_index(self, i):
        return i + i // self.chunk

    def bitmap_index(self, c):
        return c * (self.chunk + 1) + self.chunk


def read_at(path, off, n):
    with open(path, 'rb') as f:
        f.seek(off)
        b = f.read(n)
    return b + b'\0' * (n - len(b))


# ---- raws ----

def seeded(seed, n):
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(n))


def put(data, at, b):
    data[at:at + len(b)] = b


def mbr_4k(ext2, fat12):
    """A disk of 4 KiB sectors, its MBR's addresses in them: ext2 at sector 16, FAT12 at 96."""
    disk = bytearray(160 * 4096)
    struct.pack_into('<I', disk, 440, 0x4B345A42)  # disk signature
    for i, (kind, lba, img) in enumerate(((0x83, 16, ext2), (0x01, 96, fat12))):
        assert len(img) == 64 * 4096
        struct.pack_into('<B3sB3sII', disk, 446 + 16 * i, 0, b'\xfe\xff\xff', kind,
                         b'\xfe\xff\xff', lba, len(img) // 4096)
        put(disk, lba * 4096, img)
    disk[510:512] = b'\x55\xaa'
    return disk


def raws(src, work):
    out = os.path.join(work, 'raw')
    os.makedirs(out, exist_ok=True)
    img = lambda n: bytearray(open(os.path.join(src, n), 'rb').read())

    fat = img('mbr-fat.img')
    # An odd number of sectors (6145). The VHD's has a marker in the last, so that the last
    # block, which the disk only partly fills, is in the file; the VHDX's gets it through
    # dirty.vhdx's log.
    oddx = fat + bytearray(3 * MiB + 512 - len(fat))
    odd = bytearray(oddx)
    put(odd, len(odd) - 512, b'BeeZip: the last sector of an odd-sized disk'.ljust(512, b'.'))

    # gpt > fat + ext4, and two disks made from it, for a chain of three VHDs (blocks of 512 KiB:
    # block 0 holds both file systems' random.bin, block 1 is free space past ext4's data).
    fe = img('gpt-fat-ext4.img')
    fe1 = bytearray(fe)
    put(fe1, 119 * 512, seeded(1, 8 * 512))       # the FAT's random.bin
    put(fe1, 700 * 512, seeded(2, 8 * 512))       # ext4's random.bin
    put(fe1, 1100 * 512, seeded(3, 4 * 512))      # ext4's free space, in block 1
    put(fe1, 1200 * 512, seeded(4, 512))
    fe2 = bytearray(fe1)
    put(fe2, 200 * 512, seeded(5, 4 * 512))       # the FAT's random.bin again
    put(fe2, 1150 * 512, seeded(6, 2 * 512))      # block 1, beside fe1's sectors
    put(fe2, 1101 * 512, seeded(7, 512))          # one of fe1's sectors, changed again

    # A disk made from the VHDX's odd-sized one, for a child (blocks of 1 MiB: the FAT's
    # random.bin in block 0, sectors past the partition in block 1).
    oddx1 = bytearray(oddx)
    put(oddx1, 119 * 512, seeded(8, 8 * 512))     # the FAT's random.bin
    put(oddx1, 2500 * 512, seeded(9, 4 * 512))    # past the partition, in block 1
    put(oddx1, 3000 * 512, seeded(10, 512))

    disk4k = mbr_4k(img('ext2.img'), img('fat12.img'))

    for name, data in (('fat', fat), ('odd', odd), ('odd-x', oddx), ('odd-x-1', oddx1),
                       ('fe', fe), ('fe-1', fe1), ('fe-2', fe2), ('4k', disk4k)):
        open(os.path.join(out, name + '.img'), 'wb').write(data)
        uid = uuid.UUID(int=random.Random(name).getrandbits(128)).bytes
        footer = vhd_footer(len(data), 2, 0xFFFFFFFFFFFFFFFF, uid)
        open(os.path.join(out, name + '-src.vhd'), 'wb').write(bytes(data) + footer)
        print(f'raw {name}: {len(data)} bytes')


# ---- fill ----

def fill(path, raw):
    v = Vhdx(path)
    data = open(raw, 'rb').read()
    assert len(data) <= v.size
    end = -(-os.path.getsize(path) // MiB) * MiB
    with open(path, 'r+b') as f:
        for i in range(v.blocks):
            chunk = data[i * v.block:(i + 1) * v.block]
            e = v.bat[v.payload_index(i)]
            if e & 7 == 6:
                f.seek((e >> 20) * MiB)
                f.write(chunk)
            elif chunk.strip(b'\0'):
                f.seek(end)
                f.write(chunk.ljust(v.block, b'\0'))
                v.bat[v.payload_index(i)] = 6 | ((end // MiB) << 20)
                end += v.block
        f.seek(v.bat_off)
        f.write(struct.pack('<%dQ' % len(v.bat), *v.bat))
    print(f'filled {path} from {raw} ({v.blocks} blocks of {v.block}, {v.sector}-byte sectors)')


# ---- diff ----

def diff_vhdx(path, base, mod):
    v = Vhdx(path)
    assert v.flags & 2, 'not a differencing VHDX'
    end = -(-os.path.getsize(path) // MiB) * MiB
    writes, bitmaps = [], {}
    full = partial = 0
    for i in range(v.blocks):
        start = i * v.block
        n = min(v.block, v.size - start)
        a, b = read_at(base, start, n), read_at(mod, start, n)
        if a == b:
            continue
        s = v.sector
        differ = [j for j in range(n // s) if a[j * s:(j + 1) * s] != b[j * s:(j + 1) * s]]
        if i % 2 == 0 or len(differ) == n // s:
            data, state = b + b'\0' * (v.block - n), 6
            full += 1
        else:
            buf = bytearray(b'\xee' * v.block)
            c = i // v.chunk
            if c not in bitmaps:
                bitmaps[c] = (end, bytearray(MiB))
                end += MiB
            bm = bitmaps[c][1]
            first = (i % v.chunk) * (v.block // s)
            for j in differ:
                buf[j * s:(j + 1) * s] = b[j * s:(j + 1) * s]
                bit = first + j
                bm[bit // 8] |= 1 << (bit % 8)
            data, state = bytes(buf), 7
            partial += 1
        writes.append((end, data))
        v.bat[v.payload_index(i)] = state | ((end // MiB) << 20)
        end += v.block
    for c, (off, bm) in bitmaps.items():
        writes.append((off, bytes(bm)))
        v.bat[v.bitmap_index(c)] = 6 | ((off // MiB) << 20)
    with open(path, 'r+b') as f:
        for off, data in writes:
            f.seek(off)
            f.write(data)
        f.seek(v.bat_off)
        f.write(struct.pack('<%dQ' % len(v.bat), *v.bat))
        f.truncate(end)
    print(f'{path}: {full} fully and {partial} partially present blocks from {mod}')


def diff_vhd(path, base, mod):
    v = Vhd(path)
    assert v.kind == 4, 'not a differencing VHD'
    spb = v.block // 512
    bm_len = -(-(spb // 8) // 512) * 512
    end = os.path.getsize(path) - 512
    writes = []
    full = partial = 0
    for i in range(-(-v.size // v.block)):
        start = i * v.block
        n = min(v.block, v.size - start)
        a, b = read_at(base, start, n), read_at(mod, start, n)
        if a == b:
            continue
        assert v.bat[i] == 0xFFFFFFFF
        differ = [j for j in range(n // 512) if a[j * 512:(j + 1) * 512] != b[j * 512:(j + 1) * 512]]
        bm = bytearray(bm_len)
        if i % 2 == 0 or len(differ) == n // 512:
            buf = bytearray(b + b'\0' * (v.block - n))
            for j in range(spb):
                bm[j // 8] |= 0x80 >> (j % 8)
            full += 1
        else:
            buf = bytearray(b'\xee' * v.block)
            for j in differ:
                buf[j * 512:(j + 1) * 512] = b[j * 512:(j + 1) * 512]
                bm[j // 8] |= 0x80 >> (j % 8)
            partial += 1
        writes.append((end, bytes(bm) + bytes(buf)))
        v.bat[i] = end // 512
        end += bm_len + v.block
    with open(path, 'r+b') as f:
        for off, data in writes:
            f.seek(off)
            f.write(data)
        f.seek(v.table)
        f.write(struct.pack('>%dI' % v.entries, *v.bat))
        f.seek(end)
        f.write(v.footer)
        f.truncate(end + 512)
    print(f'{path}: {full} fully and {partial} partially present blocks from {mod}')


def diff(path, base, mod):
    with open(path, 'rb') as f:
        sig = f.read(8)
    (diff_vhdx if sig == b'vhdxfile' else diff_vhd)(path, base, mod)


# ---- log ----

def log_entry(seq, tail, guid, descs, flushed, last):
    """An entry of descriptors ('data', file offset, 4 KiB page) or ('zero', offset, length)."""
    count = len(descs)
    assert count <= 126
    head = bytearray(4096)
    datas = []
    for i, d in enumerate(descs):
        at = 64 + 32 * i
        if d[0] == 'zero':
            struct.pack_into('<4sIQQQ', head, at, b'zero', 0, d[2], d[1], seq)
        else:
            page = d[2]
            struct.pack_into('<4s4s8sQQ', head, at, b'desc', page[4092:4096], page[:8], d[1], seq)
            s = bytearray(4096)
            struct.pack_into('<4sI', s, 0, b'data', seq >> 32)
            s[8:4092] = page[8:4092]
            struct.pack_into('<I', s, 4092, seq & 0xFFFFFFFF)
            datas.append(bytes(s))
    length = 4096 * (1 + len(datas))
    struct.pack_into('<4sIIIQII16sQQ', head, 0, b'loge', 0, length, tail, seq, count, 0, guid,
                     flushed, last)
    e = bytearray(bytes(head) + b''.join(datas))
    checksum_at(e)
    return bytes(e)


def craft_log(src, base, dirty, noseq, expect_path):
    """As a power failure leaves a file after its log was flushed and before the metadata reached
    its place: two new blocks' payload written at the file's end, and the block table page that
    points at them only in the log, in a sequence of two entries (the second rewrites the first's
    page with the second block added, and zeroes 4 KiB of unused metadata space that holds
    garbage), placed after the stale entries Hyper-V left. `base` is the raw disk `src` holds."""
    v = Vhdx(src)
    data = bytearray(open(src, 'rb').read())
    hdrs = []
    for off in (64 * KiB, 128 * KiB):
        h = data[off:off + 4096]
        hdrs.append((struct.unpack_from('<Q', h, 8)[0], off))
    cur_seq, cur_off = max(hdrs)
    other_off = [o for s, o in hdrs if o != cur_off][0]
    log_len, log_off = struct.unpack_from('<IQ', data, cur_off + 68)
    absent = [b for b in range(v.blocks) if v.bat[v.payload_index(b)] & 7 != 6]
    # The first block not in the file, and the last, which the disk only partly fills.
    b1, b2 = absent[0], absent[-1]
    end = len(data)
    assert end % MiB == 0
    new = {}
    payload = {}
    for b in (b1, b2):
        payload[b] = b''.join(f'BeeZip: block {b}, page {k}, through the log'.encode()
                              .ljust(4096, b'.') for k in range(v.block // 4096))
        new[b] = end
        data += payload[b]
        end += v.block
    bat = bytearray(data[v.bat_off:v.bat_off + v.bat_len])

    def set_entry(b):
        struct.pack_into('<Q', bat, 8 * v.payload_index(b), 6 | ((new[b] // MiB) << 20))

    def page_of(b):
        at = (8 * v.payload_index(b)) // 4096 * 4096
        return at, bytes(bat[at:at + 4096])

    set_entry(b1)
    p1 = page_of(b1)
    set_entry(b2)
    p2 = page_of(b2)
    assert p1[0] == p2[0], 'both entries on one table page'
    zero_at = v.meta_off + MiB - 4096
    data[zero_at:zero_at + 4096] = b'\x5a' * 4096
    guid = uuid.UUID('11112222-3333-4444-5555-666677778888').bytes_le
    seq = 0x1234_5678_0000_0010
    flushed = last = len(data)
    start = 49 * 4096
    a = log_entry(seq, start, guid, [('data', v.bat_off + p1[0], p1[1])], flushed, last)
    second_at = (start + len(a)) % log_len
    b = log_entry(seq + 1, start, guid,
                  [('data', v.bat_off + p2[0], p2[1]), ('zero', zero_at, 4096)], flushed, last)
    for at, e in ((start, a), (second_at, b)):
        for k in range(0, len(e), 4096):
            o = log_off + (at + k) % log_len
            data[o:o + 4096] = e[k:k + 4096]
    h = bytearray(data[cur_off:cur_off + 4096])
    struct.pack_into('<Q', h, 8, cur_seq + 1)
    h[16:32] = uuid.UUID('99990000-0000-0000-0000-000000000001').bytes_le
    h[48:64] = guid
    checksum_at(h)
    data[other_off:other_off + 4096] = h
    open(dirty, 'wb').write(data)
    print(f'{dirty}: blocks {b1} and {b2} at {new[b1]} and {new[b2]} only in its log, entries '
          f'at {start} and {second_at} of its {log_len}-byte log')
    # Both entries damaged: no valid sequence. Nothing past the log is read before that's found.
    for at in (start, second_at):
        data[log_off + at + 100] ^= 0xFF
    open(noseq, 'wb').write(data[:log_off + log_len])
    print(f'{noseq}: both entries damaged, cut after the log')
    # The disk after replay: the source's, with the two blocks.
    disk = bytearray(open(base, 'rb').read())
    disk += bytes(v.size - len(disk))
    for blk in (b1, b2):
        n = min(v.block, v.size - blk * v.block)
        disk[blk * v.block:blk * v.block + n] = payload[blk][:n]
    open(expect_path, 'wb').write(disk)


# ---- paths ----

def neutral(path, prefix, work):
    rel = os.path.relpath(path, work)
    return prefix + '\\' + rel.replace('/', '\\')


def utf16le_path(p):
    return p.encode('utf-16-le')


def paths(path, prefix, work):
    with open(path, 'rb') as f:
        sig = f.read(8)
    if sig == b'vhdxfile':
        paths_vhdx(path, prefix, work)
    else:
        paths_vhd(path, prefix, work)


def paths_vhd(path, prefix, work):
    v = Vhd(path)
    assert v.kind == 4
    dyn = v.dyn
    name = dyn[64:576].decode('utf-16-be').split('\0')[0]
    new_name = neutral(name, prefix, work)
    enc = new_name.encode('utf-16-be')
    assert len(enc) <= 512
    dyn[64:576] = enc.ljust(512, b'\0')
    writes = []
    for i in range(8):
        at = 576 + 24 * i
        code, _, length, _, off = struct.unpack_from('>4sIIIQ', dyn, at)
        if code != b'W2ku':
            continue
        old = read_at(path, off, length).decode('utf-16-le')
        val = utf16le_path(neutral(old, prefix, work))
        assert len(val) <= length, 'the new path is longer than the old'
        struct.pack_into('>I', dyn, at + 8, len(val))
        writes.append((off, val.ljust(length, b'\0')))
    struct.pack_into('>I', dyn, 36, 0)
    struct.pack_into('>I', dyn, 36, vhd_checksum(dyn, 36))
    with open(path, 'r+b') as f:
        f.seek(v.dyn_off)
        f.write(dyn)
        for off, val in writes:
            f.seek(off)
            f.write(val)
    print(f'{path}: parent recorded as {new_name}')


def read_locator(item):
    kv = {}
    for i in range(struct.unpack_from('<H', item, 18)[0]):
        ko, vo, kl, vl = struct.unpack_from('<IIHH', item, 20 + 12 * i)
        kv[item[ko:ko + kl].decode('utf-16-le')] = item[vo:vo + vl].decode('utf-16-le')
    return kv


def locator_bytes(kv, n):
    out = bytearray(n)
    out[:16] = LOCATOR_VHDX
    struct.pack_into('<HH', out, 16, 0, len(kv))
    pos = 20 + 12 * len(kv)
    for i, (k, v) in enumerate(kv.items()):
        kb, vb = k.encode('utf-16-le'), v.encode('utf-16-le')
        struct.pack_into('<IIHH', out, 20 + 12 * i, pos, pos + len(kb), len(kb), len(vb))
        out[pos:pos + len(kb)] = kb
        out[pos + len(kb):pos + len(kb) + len(vb)] = vb
        pos += len(kb) + len(vb)
    assert pos <= n, f'the locator needs {pos} bytes, more than its {n}'
    return bytes(out)


def paths_vhdx(path, prefix, work):
    v = Vhdx(path)
    at, item = v.items[PARENT_LOCATOR]
    kv = read_locator(item)
    if 'absolute_win32_path' in kv:
        kv['absolute_win32_path'] = neutral(kv['absolute_win32_path'], prefix, work)
    if 'volume_path' in kv:
        tail = os.path.relpath(kv['volume_path'].split('}', 1)[1].lstrip('\\'),
                               os.path.splitdrive(work)[1].lstrip('\\'))
        kv['volume_path'] = ('\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\BeeZip\\'
                             + tail.replace('/', '\\'))
    with open(path, 'r+b') as f:
        f.seek(at)
        f.write(locator_bytes(kv, len(item)))
    print(f'{path}: parent recorded as {kv}')


# ---- malicious ----

def crafted_vhd(size, block, uid, parent=None):
    """A dynamic VHD of no blocks, or a differencing one whose parent is `parent`: (unique id,
    W2ru, W2ku, Parent Unicode Name)."""
    blocks = -(-size // block)
    table = 512 + 1024
    bat_len = -(-blocks * 4 // 512) * 512
    loc_at = table + bat_len
    dyn = bytearray(1024)
    dyn[:8] = b'cxsparse'
    struct.pack_into('>QQIII', dyn, 8, 0xFFFFFFFFFFFFFFFF, table, 0x00010000, blocks, block)
    locs = b''
    if parent:
        pid, w2ru, w2ku, name = parent
        dyn[40:56] = pid
        dyn[64:576] = name.encode('utf-16-be')[:512].ljust(512, b'\0')
        at = loc_at
        for i, (code, val) in enumerate(((b'W2ru', w2ru), (b'W2ku', w2ku))):
            raw = val.encode('utf-16-le')
            space = -(-len(raw) // 512) * 512
            struct.pack_into('>4sIIIQ', dyn, 576 + 24 * i, code, space, len(raw), 0, at)
            locs += raw.ljust(space, b'\0')
            at += space
    struct.pack_into('>I', dyn, 36, vhd_checksum(dyn, 36))
    kind = 4 if parent else 3
    footer = vhd_footer(size, kind, 512, uid)
    bat = b'\xff' * (blocks * 4)
    return footer + bytes(dyn) + bat.ljust(bat_len, b'\0') + locs + footer


def malicious(out):
    os.makedirs(out, exist_ok=True)
    ids = {n: uuid.UUID(int=random.Random('malicious-' + n).getrandbits(128)).bytes
           for n in ('a', 'b', 'self', 'unc', 'unc-parent')}
    size, block = 3 * MiB, 2 * MiB
    for me, other in (('a', 'b'), ('b', 'a')):
        name = f'vhd-loop-{other}.vhd'
        open(os.path.join(out, f'vhd-loop-{me}.vhd'), 'wb').write(crafted_vhd(
            size, block, ids[me], (ids[other], '.\\' + name, 'C:\\BeeZip\\' + name, name)))
    open(os.path.join(out, 'vhd-self-loop.vhd'), 'wb').write(crafted_vhd(
        size, block, ids['self'],
        (ids['self'], '.\\vhd-self-loop.vhd', 'C:\\BeeZip\\vhd-self-loop.vhd', 'vhd-self-loop.vhd')))
    unc = '\\\\beezip.invalid\\share\\parent.vhd'
    open(os.path.join(out, 'vhd-unc-parent.vhd'), 'wb').write(crafted_vhd(
        size, block, ids['unc'], (ids['unc-parent'], unc, unc, unc)))
    print('made', sorted(n for n in os.listdir(out) if n.startswith('vhd-')))


# ---- expect, unfix ----

def disk_size(path):
    with open(path, 'rb') as f:
        sig = f.read(8)
    return Vhdx(path, active=True).size if sig == b'vhdxfile' else Vhd(path).size


def expect(path, raw):
    size = disk_size(path)
    data = open(raw, 'rb').read()
    assert len(data) <= size, f'{raw} is larger than {path}'
    print(hashlib.sha256(data + bytes(size - len(data))).hexdigest())


def unfix(path, raw):
    with open(path, 'rb') as f:
        sig = f.read(8)
    if sig == b'vhdxfile':
        v = Vhdx(path)
        assert v.flags & 1, 'not a fixed VHDX'
        out = bytearray()
        for i in range(v.blocks):
            e = v.bat[v.payload_index(i)]
            assert e & 7 == 6
            out += read_at(path, (e >> 20) * MiB, v.block)
        open(raw, 'wb').write(out[:v.size])
        return
    data = open(path, 'rb').read()
    assert data[-512:][:8] == b'conectix'
    size = struct.unpack_from('>Q', data, len(data) - 512 + 48)[0]
    open(raw, 'wb').write(data[:size])


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    {
        'raws': raws, 'fill': fill, 'diff': diff, 'log': craft_log, 'paths': paths,
        'malicious': malicious, 'expect': expect, 'unfix': unfix,
    }[cmd](*args)


main()
