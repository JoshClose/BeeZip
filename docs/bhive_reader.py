#!/usr/bin/env python3
"""A reader for .bhive archives, written from docs/bhive.md alone.

It shares no code with BeeZip and uses only Python's standard library (3.14 or later, for
Zstandard). BeeZip's tests run it against BeeZip's own archives: if the two agree, the
specification is enough to read the format.

    python bhive_reader.py list    ARCHIVE [--recover]
    python bhive_reader.py test    ARCHIVE [--recover]
    python bhive_reader.py extract ARCHIVE DIRECTORY [--recover]

`list` prints one entry a line: kind, size, modification time and creation time (seconds and
nanoseconds since 1970, or `-`), Unix mode and DOS attributes (octal and hex, or `-`), path, and
a link's target, separated by tabs. It is slow, on purpose simple, and checks everything §9 of
the specification asks a reader to check.
"""

import lzma
import os
import struct
import sys
from compression import zstd

MAGIC = b"\x89BHIVE\r\n"
MAX_CELL = 256 << 20
MASK = (1 << 64) - 1


class Bad(Exception):
    """The file breaks the specification."""


# XXH3-64, seed 0, the default secret (xxHash's doc/xxhash_spec.md).

SECRET = bytes.fromhex(
    "b8fe6c3923a44bbe7c01812cf721ad1cded46de9839097db7240a4a4b7b3671f"
    "cb79e64eccc0e578825ad07dccff7221b8084674f743248ee03590e6813a264c"
    "3c2852bb91c300cb88d0658b1b532ea371644897a20df94e3819ef46a9deacd8"
    "a8fa763fe39c343ff9dcbbc7c70b4f1d8a51e04bcdb45931c89f7ec9d9787364"
    "eac5ac8334d3ebc3c581a0fffa1363eb170ddd51b7f0da49d316552629d4689e"
    "2b16be587d47a1fc8ff8b8d17ad031ce45cb3a8f95160428afd7fbcabb4b407e"
)
P32_1, P32_2, P32_3 = 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D
P64_1, P64_2, P64_3 = 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9
P64_4, P64_5 = 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5
PMX1, PMX2 = 0x165667919E3779F9, 0x9FB21C651E98DF25


def _u32(b, at):
    return struct.unpack_from("<I", b, at)[0]


def _u64(b, at):
    return struct.unpack_from("<Q", b, at)[0]


def _fold(a, b):
    p = a * b
    return (p & MASK) ^ (p >> 64)


def _avalanche(h):
    h ^= h >> 37
    h = (h * PMX1) & MASK
    return h ^ (h >> 32)


def _mix16(data, at, secret_at):
    lo = _u64(data, at) ^ _u64(SECRET, secret_at)
    hi = _u64(data, at + 8) ^ _u64(SECRET, secret_at + 8)
    return _fold(lo, hi)


def _stripe(acc, data, at, secret_at):
    values = struct.unpack_from("<8Q", data, at)
    keys = struct.unpack_from("<8Q", SECRET, secret_at)
    for i in range(8):
        key = values[i] ^ keys[i]
        acc[i ^ 1] = (acc[i ^ 1] + values[i]) & MASK
        acc[i] = (acc[i] + (key & 0xFFFFFFFF) * (key >> 32)) & MASK


def xxh3_64(data):
    n = len(data)
    if n == 0:
        h = _u64(SECRET, 56) ^ _u64(SECRET, 64)
        h ^= h >> 33
        h = (h * P64_2) & MASK
        h ^= h >> 29
        h = (h * P64_3) & MASK
        return h ^ (h >> 32)
    if n <= 3:
        combined = (data[0] << 16) | (data[n >> 1] << 24) | data[n - 1] | (n << 8)
        h = combined ^ (_u32(SECRET, 0) ^ _u32(SECRET, 4))
        h ^= h >> 33
        h = (h * P64_2) & MASK
        h ^= h >> 29
        h = (h * P64_3) & MASK
        return h ^ (h >> 32)
    if n <= 8:
        flip = _u64(SECRET, 8) ^ _u64(SECRET, 16)
        h = (_u32(data, n - 4) + (_u32(data, 0) << 32)) ^ flip
        h ^= (((h << 49) | (h >> 15)) & MASK) ^ (((h << 24) | (h >> 40)) & MASK)
        h = (h * PMX2) & MASK
        h ^= (h >> 35) + n
        h = (h * PMX2) & MASK
        return h ^ (h >> 28)
    if n <= 16:
        lo = _u64(data, 0) ^ (_u64(SECRET, 24) ^ _u64(SECRET, 32))
        hi = _u64(data, n - 8) ^ (_u64(SECRET, 40) ^ _u64(SECRET, 48))
        swapped = int.from_bytes(lo.to_bytes(8, "little"), "big")
        return _avalanche((n + swapped + hi + _fold(lo, hi)) & MASK)
    if n <= 128:
        acc = (n * P64_1) & MASK
        if n > 32:
            if n > 64:
                if n > 96:
                    acc += _mix16(data, 48, 96) + _mix16(data, n - 64, 112)
                acc += _mix16(data, 32, 64) + _mix16(data, n - 48, 80)
            acc += _mix16(data, 16, 32) + _mix16(data, n - 32, 48)
        acc += _mix16(data, 0, 0) + _mix16(data, n - 16, 16)
        return _avalanche(acc & MASK)
    if n <= 240:
        acc = (n * P64_1) & MASK
        for i in range(8):
            acc += _mix16(data, 16 * i, 16 * i)
        acc = _avalanche(acc & MASK)
        for i in range(8, n // 16):
            acc += _mix16(data, 16 * i, 16 * (i - 8) + 3)
        acc += _mix16(data, n - 16, 119)
        return _avalanche(acc & MASK)
    acc = [P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1]
    blocks = (n - 1) // 1024
    for block in range(blocks):
        for s in range(16):
            _stripe(acc, data, block * 1024 + s * 64, s * 8)
        keys = struct.unpack_from("<8Q", SECRET, 128)
        for i in range(8):
            a = acc[i]
            acc[i] = (((a ^ (a >> 47)) ^ keys[i]) * P32_1) & MASK
    for s in range(((n - 1) - 1024 * blocks) // 64):
        _stripe(acc, data, blocks * 1024 + s * 64, s * 8)
    _stripe(acc, data, n - 64, 121)
    h = (n * P64_1) & MASK
    for i in range(4):
        h += _fold(acc[2 * i] ^ _u64(SECRET, 11 + 16 * i), acc[2 * i + 1] ^ _u64(SECRET, 19 + 16 * i))
    return _avalanche(h & MASK)


# The format.


class Bytes:
    """A cursor over bytes that never runs past their end."""

    def __init__(self, data):
        self.data, self.pos = data, 0

    def left(self):
        return len(self.data) - self.pos

    def take(self, n):
        if n > self.left():
            raise Bad("the data ends in the middle of a field")
        self.pos += n
        return self.data[self.pos - n : self.pos]

    def uvarint(self):
        value = 0
        for i in range(10):
            b = self.take(1)[0]
            if i == 9 and b > 1:
                break
            value |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                return value
        raise Bad("a number of more than 64 bits")

    def svarint(self):
        u = self.uvarint()
        return (u >> 1) ^ -(u & 1)

    def block(self):
        return self.take(self.uvarint())

    def stamp(self):
        seconds, nanos = self.svarint(), self.uvarint()
        if nanos >= 1_000_000_000:
            raise Bad("a time with a second's worth of nanoseconds or more")
        return seconds, nanos

    def u32(self, what):
        value = self.uvarint()
        if value >= 1 << 32:
            raise Bad(f"{what} of more than 32 bits")
        return value


def unzstd(stored, raw_len, what):
    d = zstd.ZstdDecompressor()
    try:
        raw = d.decompress(stored)
    except zstd.ZstdError as e:
        raise Bad(f"{what} doesn't decode ({e})") from None
    if not d.eof or d.unused_data or len(raw) != raw_len:
        raise Bad(f"{what} isn't one Zstandard frame of its raw length")
    return raw


class Cell:
    def __init__(self, offset, stored, raw, coder, param, checksum):
        self.offset, self.stored, self.raw = offset, stored, raw
        self.coder, self.param, self.checksum = coder, param, checksum
        if raw > MAX_CELL:
            raise Bad("a cell over 256 MiB")
        ok = {
            0: param == 0 and stored == raw,
            1: param == 0 and stored < raw,
            2: param <= 32 and stored < raw,
        }.get(coder)
        if ok is None:
            raise Bad(f"a cell with coder {coder}")
        if not ok:
            raise Bad("a cell whose lengths or parameter break its coder's rules")

    def decode(self, f, number):
        f.seek(self.offset)
        stored = f.read(self.stored)
        what = f"cell {number}"
        if len(stored) != self.stored:
            raise Bad(f"{what} runs past the end of the file")
        if self.coder == 0:
            raw = stored
        elif self.coder == 1:
            raw = unzstd(stored, self.raw, what)
        else:
            size = (2 | (self.param & 1)) << (self.param // 2 + 11)
            d = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": size}]
            )
            try:
                raw = d.decompress(stored)
            except lzma.LZMAError as e:
                raise Bad(f"{what} doesn't decode ({e})") from None
            if not d.eof or d.unused_data or len(raw) != self.raw:
                raise Bad(f"{what} isn't one LZMA2 stream of its raw length")
        if xxh3_64(raw) != self.checksum:
            raise Bad(f"{what} fails its checksum")
        return raw


class Entry:
    KINDS = {0: "file", 1: "folder", 2: "link"}

    def __init__(self, b, cells):
        flags = b.take(1)[0]
        if flags & 0xC0 or flags & 3 == 3:
            raise Bad("an entry with flags or a kind version 1 doesn't have")
        self.kind = self.KINDS[flags & 3]
        self.path = b.block().decode("utf-8", "replace")
        self.modified = b.stamp() if flags & 4 else None
        self.created = b.stamp() if flags & 8 else None
        self.mode = b.u32("a Unix mode") if flags & 16 else None
        self.attributes = b.u32("DOS attributes") if flags & 32 else None
        self.extents, self.size, self.target = [], 0, None
        if self.kind == "file":
            count = b.uvarint()
            if count > b.left() // 3:
                raise Bad("a file with more extents than there are bytes for")
            for _ in range(count):
                cell, offset, length = b.uvarint(), b.uvarint(), b.uvarint()
                if cell >= len(cells):
                    raise Bad(f"an extent in cell {cell}, which isn't there")
                if length == 0 or offset + length > cells[cell].raw:
                    raise Bad("an extent of no bytes, or past the end of its cell")
                self.extents.append((cell, offset, length))
                self.size += length
            if self.size >= 1 << 64:
                raise Bad("a file of 2^64 bytes or more")
        elif self.kind == "link":
            self.target = b.block().decode("utf-8", "replace")


class Archive:
    def __init__(self, path, recover=False):
        self.f = open(path, "rb")
        self.len = os.fstat(self.f.fileno()).st_size
        header = self.f.read(16)
        if len(header) < 16 or header[:8] != MAGIC:
            raise Bad("not a .bhive file")
        version, _, features = struct.unpack_from("<HHI", header, 8)
        if version != 1 or features:
            raise Bad(f"version {version} with features {features:#x}: not for this reader")
        self.incomplete = None
        try:
            self.read_index()
        except Bad as e:
            if not recover:
                raise
            self.incomplete = str(e)
            self.recover()
        self.cache = (None, None)

    def at(self, offset, n):
        self.f.seek(offset)
        data = self.f.read(n)
        if len(data) != n:
            raise Bad("the file ends too soon")
        return data

    def read_index(self):
        if self.len < 64:
            raise Bad("the file is too short to hold an index")
        footer = self.at(self.len - 16, 16)
        if footer[8:] != MAGIC:
            raise Bad("the file doesn't end with a footer")
        offset = _u64(footer, 0)
        if offset < 16 or offset > self.len - 48:
            raise Bad("the footer points outside the file")
        head = self.at(offset, 32)
        coder, stored, raw_len, checksum = self.index_head(head)
        if offset + 32 + stored + 16 != self.len:
            raise Bad("the index and the footer don't end the file")
        raw = self.at(offset + 32, stored)
        if coder:
            raw = unzstd(raw, raw_len, "the index")
        if xxh3_64(raw) != checksum:
            raise Bad("the index fails its checksum")

        b = Bytes(raw)
        count = b.uvarint()
        if count > b.left() // 26:
            raise Bad("a cell table larger than the index")
        self.cells, end = [], 16
        for n in range(count):
            row = b.take(26)
            cell = Cell(*struct.unpack("<QIIBBQ", row))
            if cell.offset < end + 48 or cell.offset + cell.stored > offset:
                raise Bad(f"cell {n} overlaps what is around it")
            end = cell.offset + cell.stored
            self.cells.append(cell)
        count = b.uvarint()
        if count > b.left() // 2:
            raise Bad("more entries than the index has bytes for")
        self.entries = [Entry(b, self.cells) for _ in range(count)]
        self.level = None
        while b.left():
            ident, body = b.uvarint(), b.block()
            if ident == 1 and len(body) == 1:
                self.level = body[0]

    @staticmethod
    def index_head(head):
        if head[:4] != b"BHIX" or head[4] > 1:
            raise Bad("not an index block, or one with an unknown coder")
        stored, raw_len, checksum = struct.unpack_from("<QQQ", head, 8)
        if not head[4] and stored != raw_len:
            raise Bad("a stored index with two lengths")
        return head[4], stored, raw_len, checksum

    def recover(self):
        """What the records before the cells still list (§8)."""
        self.cells, self.entries, self.level = [], [], None
        pos = 16
        while pos + 4 <= self.len:
            tag = self.at(pos, 4)
            try:
                if tag == b"BHIX" and pos + 48 <= self.len:
                    end = pos + 48 + self.index_head(self.at(pos, 32))[1]
                    if end > self.len:
                        break
                    pos = end
                    continue
                if tag != b"BHCL" or pos + 48 > self.len:
                    break
                head = self.at(pos, 48)
                number, raw, stored, coder, param, jcoder, _, items, jraw, jstored, checksum, check = (
                    struct.unpack_from("<IIIBBBBIIIQQ", head, 4)
                )
                if number != len(self.cells) or jcoder > 1 or (not jcoder and jraw != jstored):
                    break
                cell = Cell(pos + 48 + jstored, stored, raw, coder, param, checksum)
                if cell.offset + stored > self.len:
                    break
                journal = self.at(pos + 48, jstored)
                if xxh3_64(head[:40] + journal) != check:
                    break
                if jcoder:
                    journal = unzstd(journal, jraw, "a journal")
                b = Bytes(journal)
                cells = self.cells + [cell]
                entries = [Entry(b, cells) for _ in range(items)]
                if b.left():
                    break
            except Bad:
                break
            self.cells, pos = cells, cell.offset + stored
            self.entries += entries

    def cell(self, n):
        if self.cache[0] != n:
            self.cache = (n, self.cells[n].decode(self.f, n))
        return self.cache[1]

    def read(self, entry):
        """The file's bytes, piece by piece."""
        for cell, offset, length in entry.extents:
            yield self.cell(cell)[offset : offset + length]


def safe(path):
    """The path's components, or None for one this reader won't write."""
    parts = path.split("/")
    for part in parts:
        if part in ("", ".", "..") or any(c in part for c in '\\:\0'):
            return None
    return parts


def stamp(t):
    return "-" if t is None else f"{t[0]}.{t[1]:09d}"


def set_time(target, modified):
    """Gives a file its time, if this system can hold it (Windows holds none before 1601)."""
    if modified:
        ns = modified[0] * 1_000_000_000 + modified[1]
        try:
            os.utime(target, ns=(ns, ns))
        except (OSError, OverflowError):
            pass


def main(argv):
    recover = "--recover" in argv
    argv = [a for a in argv if a != "--recover"]
    if len(argv) < 3 or argv[1] not in ("list", "test", "extract"):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        archive = Archive(argv[2], recover)
    except Bad as e:
        print(f"bhive_reader: {e}", file=sys.stderr)
        return 1
    if archive.incomplete:
        print(f"bhive_reader: the archive is incomplete ({archive.incomplete})", file=sys.stderr)
    failed = 0

    if argv[1] == "list":
        out = open(sys.stdout.fileno(), "w", encoding="utf-8", newline="\n", closefd=False)
        for e in archive.entries:
            mode = "-" if e.mode is None else f"{e.mode:o}"
            attributes = "-" if e.attributes is None else f"{e.attributes:x}"
            fields = [e.kind, str(e.size), stamp(e.modified), stamp(e.created), mode, attributes, e.path]
            if e.target is not None:
                fields.append(e.target)
            out.write("\t".join(fields) + "\n")
        out.flush()
    elif argv[1] == "test":
        for n in range(len(archive.cells)):
            try:
                archive.cell(n)
            except Bad as e:
                print(f"bhive_reader: {e}", file=sys.stderr)
                failed += 1
    else:
        if len(argv) < 4:
            print(__doc__, file=sys.stderr)
            return 2
        root, folders = argv[3], []
        os.makedirs(root, exist_ok=True)
        for e in archive.entries:
            parts = safe(e.path)
            if parts is None:
                print(f"bhive_reader: skipped an unsafe path: {e.path!r}", file=sys.stderr)
                continue
            target = os.path.join(root, *parts)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if e.kind == "folder":
                os.makedirs(target, exist_ok=True)
                folders.append((target, e))
                continue
            if e.kind == "link":
                # Only a link that stays beside or below itself.
                if safe(e.target) is None:
                    print(f"bhive_reader: skipped a link: {e.path!r}", file=sys.stderr)
                    continue
                os.symlink(e.target, target)
                continue
            try:
                with open(target, "wb") as out:
                    for piece in archive.read(e):
                        out.write(piece)
            except Bad as bad:
                print(f"bhive_reader: {e.path}: {bad}", file=sys.stderr)
                os.remove(target)
                failed += 1
                continue
            set_time(target, e.modified)
        for target, e in reversed(folders):
            set_time(target, e.modified)
    return 1 if failed or archive.incomplete else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
