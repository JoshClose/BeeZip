//! The bytes of a `.bhive` file, as docs/bhive.md lays them out: the header and footer, the
//! record before each cell, the index block, and the items of journals and of the index. Nothing
//! here reads a file or decodes a cell; the index parser is a fuzz target of its own.

use std::time::{SystemTime, UNIX_EPOCH};

use xxhash_rust::xxh3::{Xxh3Default, xxh3_64};

use crate::{Error, Result};

/// `\x89BHIVE\r\n`: the high bit and the line ending expose a transfer that mangled the file.
pub const MAGIC: [u8; 8] = [0x89, b'B', b'H', b'I', b'V', b'E', b'\r', b'\n'];
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const FOOTER_LEN: usize = 16;
pub const RECORD_LEN: usize = 48;
pub const INDEX_HEAD_LEN: usize = 32;
pub const CELL_TAG: [u8; 4] = *b"BHCL";
pub const INDEX_TAG: [u8; 4] = *b"BHIX";
/// The most raw bytes a cell holds in version 1.
pub const MAX_CELL: u32 = 256 << 20;
/// A cell's row in the index's table.
pub const ROW_LEN: usize = 26;
/// The index section that holds the level the writer was asked for.
pub const SECTION_LEVEL: u64 = 1;
/// Index sections of M14 (docs/bhive.md §6): the cells' SHA-256 (§13.2), the signatures
/// (§13.3), and an encrypted archive's slot descriptions (§12.9). Even ids are covered by
/// signatures, odd ones aren't.
pub const SECTION_DIGESTS: u64 = 2;
pub const SECTION_SIGNATURES: u64 = 3;
pub const SECTION_SLOTS: u64 = 5;
/// Header feature bit 0: the archive is encrypted (docs/bhive.md §12).
pub const FEATURE_ENCRYPTED: u32 = 1;
/// An encrypted archive's blocks (docs/bhive.md §12.3, §12.6, §12.7).
pub const KEY_TAG: [u8; 4] = *b"BHKY";
pub const SEALED_CELL_TAG: [u8; 4] = *b"BHCE";
pub const SEALED_INDEX_TAG: [u8; 4] = *b"BHIE";
/// A key block's fields before its slots: tag, suite, counts, archive id, key id.
pub const KEY_BLOCK_HEAD_LEN: usize = 60;
/// A sealed cell block's head: tag, two lengths, the record's nonce.
pub const SEALED_CELL_HEAD_LEN: usize = 24;
pub const SEALED_INDEX_HEAD_LEN: usize = 48;
/// A cell's row in an encrypted archive's table: the row, then the cell's id.
pub const SEALED_ROW_LEN: usize = ROW_LEN + 32;
/// The least an encrypted archive puts between two cells' data: a block head and the
/// smallest sealed record (an id, a record head, no journal, a tag).
pub const SEALED_GAP: u64 = (SEALED_CELL_HEAD_LEN + 32 + RECORD_LEN + 16) as u64;
/// The largest LZMA2 dictionary parameter: 256 MiB.
pub const MAX_LZMA2_PARAM: u8 = 32;

/// The checksum of everything in the format: XXH3-64, seed 0.
pub fn checksum(data: &[u8]) -> u64 {
    xxh3_64(data)
}

/// Whether a checksum is the one stored. Under a fuzzer it always is: a fuzzer can't make a
/// checksum fit, and what lies behind one (the index, a journal, a cell's decoder) is what it
/// is there to reach. Every other check still runs.
pub(super) fn sums(computed: u64, stored: u64) -> bool {
    cfg!(fuzzing) || computed == stored
}

pub(super) fn bad(what: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("bhive: {what}"))
}

/// How a cell's bytes are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coder {
    Stored,
    Zstd,
    Lzma2,
}

impl Coder {
    pub const fn id(self) -> u8 {
        match self {
            Self::Stored => 0,
            Self::Zstd => 1,
            Self::Lzma2 => 2,
        }
    }

    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::Stored),
            1 => Ok(Self::Zstd),
            2 => Ok(Self::Lzma2),
            n => Err(bad(format!(
                "a cell uses coder {n}, which version 1 doesn't have"
            ))),
        }
    }

    /// The name `archive.info` and listings show.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stored => "Store",
            Self::Zstd => "Zstd",
            Self::Lzma2 => "LZMA2",
        }
    }
}

/// The dictionary size an LZMA2 parameter stands for, as `.xz` encodes it.
pub const fn lzma2_dict(param: u8) -> u32 {
    (2 | (param as u32 & 1)) << (param / 2 + 11)
}

/// The smallest parameter whose dictionary holds `dict` bytes.
pub fn lzma2_param(dict: u32) -> u8 {
    (0..=MAX_LZMA2_PARAM)
        .find(|&p| lzma2_dict(p) >= dict)
        .unwrap_or(MAX_LZMA2_PARAM)
}

/// A cell, as the index's table and its own record describe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    /// Where its data starts in the file.
    pub offset: u64,
    pub stored: u32,
    pub raw: u32,
    pub coder: Coder,
    pub param: u8,
    /// Of its raw bytes.
    pub checksum: u64,
}

impl Cell {
    /// The rules of docs/bhive.md §4 that a cell's own numbers must keep.
    pub fn check(&self) -> Result<()> {
        if self.raw > MAX_CELL {
            return Err(bad(format!(
                "a cell of {} bytes, over version 1's 256 MiB",
                self.raw
            )));
        }
        let ok = match self.coder {
            Coder::Stored => self.param == 0 && self.stored == self.raw,
            Coder::Zstd => self.param == 0 && self.stored < self.raw,
            Coder::Lzma2 => self.param <= MAX_LZMA2_PARAM && self.stored < self.raw,
        };
        if ok {
            Ok(())
        } else {
            Err(bad(format!(
                "a {} cell of {} bytes stored as {} with parameter {}",
                self.coder.name(),
                self.raw,
                self.stored,
                self.param
            )))
        }
    }

    /// What decoding it allocates: its raw bytes, and LZMA2's dictionary.
    pub fn memory(&self) -> u64 {
        let dict = match self.coder {
            Coder::Lzma2 => u64::from(lzma2_dict(self.param)),
            _ => 0,
        };
        u64::from(self.raw) + dict
    }

    pub fn end(&self) -> u64 {
        self.offset + u64::from(self.stored)
    }
}

/// A run of a file's bytes in one cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub cell: u32,
    pub offset: u32,
    pub len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Folder,
    Link,
}

const HAS_MODIFIED: u8 = 1 << 2;
const HAS_CREATED: u8 = 1 << 3;
const HAS_MODE: u8 = 1 << 4;
const HAS_ATTRS: u8 = 1 << 5;
const RESERVED_FLAGS: u8 = 0b1100_0000;

/// Seconds and nanoseconds since 1970-01-01T00:00:00Z.
pub type Stamp = (i64, u32);

/// A time as an item stores it. Times before 1970 have negative seconds and nanoseconds that
/// still count forward.
pub fn stamp(t: SystemTime) -> Stamp {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (
            i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            d.subsec_nanos(),
        ),
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            match d.subsec_nanos() {
                0 => (-secs, 0),
                n => (-secs - 1, 1_000_000_000 - n),
            }
        }
    }
}

/// An item to write: an entry's description and, for a file, its extents.
#[derive(Debug, Clone, Copy)]
pub struct ItemRef<'a> {
    pub kind: Kind,
    pub path: &'a [u8],
    pub modified: Option<Stamp>,
    pub created: Option<Stamp>,
    pub mode: Option<u32>,
    pub attrs: Option<u32>,
    pub extents: &'a [Extent],
    pub target: &'a [u8],
}

pub fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v & 0x7F) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn put_svarint(out: &mut Vec<u8>, n: i64) {
    put_uvarint(out, ((n << 1) ^ (n >> 63)) as u64);
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_uvarint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_stamp(out: &mut Vec<u8>, (secs, nanos): Stamp) {
    put_svarint(out, secs);
    put_uvarint(out, u64::from(nanos));
}

/// Appends `item` to `out` (docs/bhive.md §7).
pub fn put_item(out: &mut Vec<u8>, item: &ItemRef<'_>) {
    let mut flags = match item.kind {
        Kind::File => 0,
        Kind::Folder => 1,
        Kind::Link => 2,
    };
    for (has, bit) in [
        (item.modified.is_some(), HAS_MODIFIED),
        (item.created.is_some(), HAS_CREATED),
        (item.mode.is_some(), HAS_MODE),
        (item.attrs.is_some(), HAS_ATTRS),
    ] {
        if has {
            flags |= bit;
        }
    }
    out.push(flags);
    put_bytes(out, item.path);
    if let Some(t) = item.modified {
        put_stamp(out, t);
    }
    if let Some(t) = item.created {
        put_stamp(out, t);
    }
    if let Some(m) = item.mode {
        put_uvarint(out, u64::from(m));
    }
    if let Some(a) = item.attrs {
        put_uvarint(out, u64::from(a));
    }
    match item.kind {
        Kind::File => {
            put_uvarint(out, item.extents.len() as u64);
            for e in item.extents {
                put_uvarint(out, u64::from(e.cell));
                put_uvarint(out, u64::from(e.offset));
                put_uvarint(out, u64::from(e.len));
            }
        }
        Kind::Folder => {}
        Kind::Link => put_bytes(out, item.target),
    }
}

/// A reader over bytes that fails, as `Corrupt`, instead of running past their end.
pub struct Bytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bytes<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn left(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.left() {
            return Err(bad("the data ends in the middle of a field"));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32_at(self.take(4)?, 0))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64_at(self.take(8)?, 0))
    }

    pub fn uvarint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            if i == 9 && b > 1 {
                break;
            }
            v |= u64::from(b & 0x7F) << (7 * i);
            if b & 0x80 == 0 {
                // The shortest form only (docs/bhive.md §2): a last byte of 0 after others
                // is a longer form of the same number.
                if i > 0 && b == 0 {
                    return Err(bad("a number not in its shortest form"));
                }
                return Ok(v);
            }
        }
        Err(bad("a number of more than 64 bits"))
    }

    pub fn svarint(&mut self) -> Result<i64> {
        let u = self.uvarint()?;
        Ok((u >> 1) as i64 ^ -((u & 1) as i64))
    }

    /// A `uvarint` length and that many bytes.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.uvarint()?;
        let n = usize::try_from(n).map_err(|_| bad("a length too large"))?;
        self.take(n)
    }

    fn stamp(&mut self) -> Result<Stamp> {
        let secs = self.svarint()?;
        let nanos = self.uvarint()?;
        match u32::try_from(nanos) {
            Ok(n) if n < 1_000_000_000 => Ok((secs, n)),
            _ => Err(bad("a time with a second's worth of nanoseconds or more")),
        }
    }

    fn u32_varint(&mut self, what: &str) -> Result<u32> {
        u32::try_from(self.uvarint()?).map_err(|_| bad(format!("{what} of more than 32 bits")))
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// An entry as an item describes it; a file's extents are `extents[first..first + count]` of
/// its [`Items`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub kind: Kind,
    pub path: Vec<u8>,
    pub modified: Option<Stamp>,
    pub created: Option<Stamp>,
    pub mode: Option<u32>,
    pub attrs: Option<u32>,
    pub first: usize,
    pub count: usize,
    /// The sum of its extents' lengths.
    pub size: u64,
    pub target: Vec<u8>,
}

/// Parsed items, their extents in one list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Items {
    pub items: Vec<Item>,
    pub extents: Vec<Extent>,
}

impl Items {
    pub fn extents_of(&self, item: &Item) -> &[Extent] {
        &self.extents[item.first..item.first + item.count]
    }
}

/// Reads one item from `b` into `out`. Its extents must lie in `cells`: for a journal, the
/// cells up to the record's own.
pub fn item(b: &mut Bytes<'_>, cells: &[Cell], out: &mut Items) -> Result<()> {
    let flags = b.u8()?;
    if flags & RESERVED_FLAGS != 0 {
        return Err(bad("an entry with flags version 1 doesn't have"));
    }
    let kind = match flags & 3 {
        0 => Kind::File,
        1 => Kind::Folder,
        2 => Kind::Link,
        _ => return Err(bad("an entry of a kind version 1 doesn't have")),
    };
    let path = b.bytes()?.to_vec();
    let modified = (flags & HAS_MODIFIED != 0).then(|| b.stamp()).transpose()?;
    let created = (flags & HAS_CREATED != 0).then(|| b.stamp()).transpose()?;
    let mode = (flags & HAS_MODE != 0)
        .then(|| b.u32_varint("a Unix mode"))
        .transpose()?;
    let attrs = (flags & HAS_ATTRS != 0)
        .then(|| b.u32_varint("DOS attributes"))
        .transpose()?;
    let first = out.extents.len();
    let mut size = 0u64;
    let mut target = Vec::new();
    match kind {
        Kind::File => {
            let count = b.uvarint()?;
            // Each extent is at least three bytes.
            if count > (b.left() / 3) as u64 {
                return Err(bad("a file with more extents than the index has bytes for"));
            }
            for _ in 0..count {
                let cell = b.uvarint()?;
                let offset = b.uvarint()?;
                let len = b.uvarint()?;
                let Some(c) = usize::try_from(cell).ok().and_then(|c| cells.get(c)) else {
                    return Err(bad(format!("an extent in cell {cell}, which isn't there")));
                };
                if len == 0
                    || offset
                        .checked_add(len)
                        .is_none_or(|end| end > u64::from(c.raw))
                {
                    return Err(bad(format!(
                        "an extent of {len} bytes at {offset} of cell {cell}, which holds {}",
                        c.raw
                    )));
                }
                size = size
                    .checked_add(len)
                    .ok_or_else(|| bad("a file of 2^64 bytes or more"))?;
                // All three fit: the cell is in a table of u32 rows, and the rest in its raw length.
                out.extents.push(Extent {
                    cell: cell as u32,
                    offset: offset as u32,
                    len: len as u32,
                });
            }
        }
        Kind::Folder => {}
        Kind::Link => target = b.bytes()?.to_vec(),
    }
    out.items.push(Item {
        kind,
        path,
        modified,
        created,
        mode,
        attrs,
        first,
        count: out.extents.len() - first,
        size,
        target,
    });
    Ok(())
}

/// The file's first 16 bytes.
pub fn header() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    h[8..10].copy_from_slice(&VERSION.to_le_bytes());
    h
}

/// Checks a header: the magic, then a version and features this reader knows. Returns the
/// features: [`FEATURE_ENCRYPTED`], or none.
pub fn check_header(h: &[u8]) -> Result<u32> {
    if h.len() < HEADER_LEN || h[..8] != MAGIC {
        return Err(bad("the file doesn't start with a .bhive header"));
    }
    let version = u16::from_le_bytes([h[8], h[9]]);
    if version != VERSION {
        return Err(Error::unsupported_format(format!(
            "bhive: the archive is version {version} of the format; this BeeZip reads version {VERSION}"
        )));
    }
    let features = u32_at(h, 12);
    if features & !FEATURE_ENCRYPTED != 0 {
        return Err(Error::unsupported_format(format!(
            "bhive: the archive was made by a newer program: it uses features this BeeZip \
             doesn't have (flags {features:#x})"
        )));
    }
    Ok(features)
}

/// An encrypted archive's header: feature bit 0.
pub fn header_encrypted() -> [u8; HEADER_LEN] {
    let mut h = header();
    h[12..16].copy_from_slice(&FEATURE_ENCRYPTED.to_le_bytes());
    h
}

/// The file's last 16 bytes.
pub fn footer(index_offset: u64) -> [u8; FOOTER_LEN] {
    let mut f = [0u8; FOOTER_LEN];
    f[..8].copy_from_slice(&index_offset.to_le_bytes());
    f[8..].copy_from_slice(&MAGIC);
    f
}

/// The index block's offset, from a footer.
pub fn parse_footer(f: &[u8]) -> Option<u64> {
    (f.len() == FOOTER_LEN && f[8..] == MAGIC).then(|| u64_at(f, 0))
}

/// The head of a cell block (docs/bhive.md §4.1), without its record checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub number: u32,
    pub raw: u32,
    pub stored: u32,
    pub coder: Coder,
    pub param: u8,
    /// The journal is one zstd frame; otherwise it's stored.
    pub journal_zstd: bool,
    pub journal_items: u32,
    pub journal_raw: u32,
    pub journal_stored: u32,
    pub checksum: u64,
}

impl Record {
    /// The 48 bytes, with the record checksum over them and `journal` as it is stored.
    pub fn encode(&self, journal: &[u8]) -> [u8; RECORD_LEN] {
        let mut h = [0u8; RECORD_LEN];
        h[..4].copy_from_slice(&CELL_TAG);
        h[4..8].copy_from_slice(&self.number.to_le_bytes());
        h[8..12].copy_from_slice(&self.raw.to_le_bytes());
        h[12..16].copy_from_slice(&self.stored.to_le_bytes());
        h[16] = self.coder.id();
        h[17] = self.param;
        h[18] = u8::from(self.journal_zstd);
        h[20..24].copy_from_slice(&self.journal_items.to_le_bytes());
        h[24..28].copy_from_slice(&self.journal_raw.to_le_bytes());
        h[28..32].copy_from_slice(&self.journal_stored.to_le_bytes());
        h[32..40].copy_from_slice(&self.checksum.to_le_bytes());
        let sum = record_checksum(&h, journal);
        h[40..].copy_from_slice(&sum.to_le_bytes());
        h
    }

    /// A record head and the record checksum it claims. The tag must already be right.
    pub fn parse(h: &[u8; RECORD_LEN]) -> Result<(Self, u64)> {
        let journal_zstd = match h[18] {
            0 => false,
            1 => true,
            n => return Err(bad(format!("a journal with coder {n}"))),
        };
        let r = Self {
            number: u32_at(h, 4),
            raw: u32_at(h, 8),
            stored: u32_at(h, 12),
            coder: Coder::from_id(h[16])?,
            param: h[17],
            journal_zstd,
            journal_items: u32_at(h, 20),
            journal_raw: u32_at(h, 24),
            journal_stored: u32_at(h, 28),
            checksum: u64_at(h, 32),
        };
        if !journal_zstd && r.journal_raw != r.journal_stored {
            return Err(bad("a stored journal with two lengths"));
        }
        Ok((r, u64_at(h, 40)))
    }

    /// The cell this record precedes, its data at `offset`.
    pub fn cell(&self, offset: u64) -> Cell {
        Cell {
            offset,
            stored: self.stored,
            raw: self.raw,
            coder: self.coder,
            param: self.param,
            checksum: self.checksum,
        }
    }
}

/// The record checksum: of the head's first 40 bytes, then the journal as stored.
pub fn record_checksum(head: &[u8; RECORD_LEN], journal: &[u8]) -> u64 {
    let mut x = Xxh3Default::new();
    x.update(&head[..40]);
    x.update(journal);
    x.digest()
}

/// The head of the index block (docs/bhive.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexHead {
    /// The index is one zstd frame; otherwise it's stored.
    pub zstd: bool,
    pub stored: u64,
    pub raw: u64,
    pub checksum: u64,
}

impl IndexHead {
    pub fn encode(&self) -> [u8; INDEX_HEAD_LEN] {
        let mut h = [0u8; INDEX_HEAD_LEN];
        h[..4].copy_from_slice(&INDEX_TAG);
        h[4] = u8::from(self.zstd);
        h[8..16].copy_from_slice(&self.stored.to_le_bytes());
        h[16..24].copy_from_slice(&self.raw.to_le_bytes());
        h[24..].copy_from_slice(&self.checksum.to_le_bytes());
        h
    }

    pub fn parse(h: &[u8]) -> Result<Self> {
        if h.len() < INDEX_HEAD_LEN || h[..4] != INDEX_TAG {
            return Err(bad("the footer doesn't point at an index"));
        }
        let zstd = match h[4] {
            0 => false,
            1 => true,
            n => return Err(bad(format!("an index with coder {n}"))),
        };
        let head = Self {
            zstd,
            stored: u64_at(h, 8),
            raw: u64_at(h, 16),
            checksum: u64_at(h, 24),
        };
        if !zstd && head.stored != head.raw {
            return Err(bad("a stored index with two lengths"));
        }
        Ok(head)
    }
}

/// The index's raw bytes (docs/bhive.md §6): the cell table, `entries` items already encoded in
/// `items`, and the level as a section.
pub fn encode_index(cells: &[Cell], entries: u64, items: &[u8], level: Option<u8>) -> Vec<u8> {
    let level = level.map(|l| [l]);
    let sections: Vec<(u64, &[u8])> = level.iter().map(|l| (SECTION_LEVEL, &l[..])).collect();
    encode_index_with(cells, None, entries, items, &sections)
}

/// [`encode_index`] with an encrypted archive's cell ids after each row (docs/bhive.md §12.7)
/// and any sections, as given: a writer gives them in increasing order of id (§6).
pub fn encode_index_with(
    cells: &[Cell],
    ids: Option<&[[u8; 32]]>,
    entries: u64,
    items: &[u8],
    sections: &[(u64, &[u8])],
) -> Vec<u8> {
    debug_assert!(ids.is_none_or(|ids| ids.len() == cells.len()));
    let row = if ids.is_some() {
        SEALED_ROW_LEN
    } else {
        ROW_LEN
    };
    let extra: usize = sections.iter().map(|(_, b)| b.len() + 20).sum();
    let mut out = Vec::with_capacity(cells.len() * row + items.len() + 12 + extra);
    put_uvarint(&mut out, cells.len() as u64);
    for (n, c) in cells.iter().enumerate() {
        out.extend_from_slice(&c.offset.to_le_bytes());
        out.extend_from_slice(&c.stored.to_le_bytes());
        out.extend_from_slice(&c.raw.to_le_bytes());
        out.push(c.coder.id());
        out.push(c.param);
        out.extend_from_slice(&c.checksum.to_le_bytes());
        if let Some(ids) = ids {
            out.extend_from_slice(&ids[n]);
        }
    }
    put_uvarint(&mut out, entries);
    out.extend_from_slice(items);
    for (id, body) in sections {
        put_uvarint(&mut out, *id);
        put_uvarint(&mut out, body.len() as u64);
        out.extend_from_slice(body);
    }
    out
}

/// A parsed index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    pub cells: Vec<Cell>,
    pub items: Items,
    /// The level the writer was asked for, when it said.
    pub level: Option<u8>,
    /// An encrypted archive's cell ids, one per cell; empty otherwise.
    pub ids: Vec<[u8; 32]>,
    /// The entry count, and where the entries' bytes are in the raw index: what the manifest
    /// covers (docs/bhive.md §13.1).
    pub entry_count: u64,
    pub entry_bytes: std::ops::Range<usize>,
    /// Every section after the entries, in order, the level's included.
    pub sections: Vec<Section>,
}

/// An index section (docs/bhive.md §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub id: u64,
    pub body: Vec<u8>,
}

impl Index {
    /// The body of section `id`, if the index has it.
    pub fn section(&self, id: u64) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.body.as_slice())
    }
}

/// How the cell table is laid out: version 1's, or an encrypted archive's (docs/bhive.md §12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableForm {
    /// Rows carry a cell id, and sealed cells need [`SEALED_GAP`] before them.
    pub sealed: bool,
    /// Where the first cell's block may start: after the header, or the key block.
    pub start: u64,
}

impl TableForm {
    pub const PLAIN: Self = Self {
        sealed: false,
        start: HEADER_LEN as u64,
    };
}

/// Parses an index's raw bytes and checks everything docs/bhive.md §9 asks of it. Cells must
/// lie between the header and `index_offset`, where the index block starts. More than
/// `max_entries` entries is `LimitExceeded`.
pub fn parse_index(raw: &[u8], index_offset: u64, max_entries: Option<u64>) -> Result<Index> {
    parse_index_with(raw, index_offset, max_entries, TableForm::PLAIN)
}

/// [`parse_index`] for a table of either form. A sealed cell's length in the file is its
/// stored length and a tag per segment (docs/bhive.md §12.8).
pub fn parse_index_with(
    raw: &[u8],
    index_offset: u64,
    max_entries: Option<u64>,
    form: TableForm,
) -> Result<Index> {
    let (row_len, gap) = if form.sealed {
        (SEALED_ROW_LEN, SEALED_GAP)
    } else {
        (ROW_LEN, RECORD_LEN as u64)
    };
    let mut b = Bytes::new(raw);
    let count = b.uvarint()?;
    if count > (b.left() / row_len) as u64 {
        return Err(bad(format!(
            "a table of {count} cells in an index of {} bytes",
            raw.len()
        )));
    }
    let mut cells = Vec::with_capacity(count as usize);
    let mut ids = Vec::new();
    let mut prev_end = form.start;
    for n in 0..count {
        let row = b.take(row_len)?;
        let cell = Cell {
            offset: u64_at(row, 0),
            stored: u32_at(row, 8),
            raw: u32_at(row, 12),
            coder: Coder::from_id(row[16])?,
            param: row[17],
            checksum: u64_at(row, 18),
        };
        cell.check()?;
        let len = if form.sealed {
            sealed_len(u64::from(cell.stored))
        } else {
            u64::from(cell.stored)
        };
        // A record head lies between a cell and whatever is before it.
        let fits = prev_end
            .checked_add(gap)
            .is_some_and(|min| cell.offset >= min)
            && cell
                .offset
                .checked_add(len)
                .is_some_and(|end| end <= index_offset);
        if !fits {
            return Err(bad(format!(
                "cell {n} at {} overlaps what is around it",
                cell.offset
            )));
        }
        prev_end = cell.offset + len;
        if form.sealed {
            let mut id = [0; 32];
            id.copy_from_slice(&row[ROW_LEN..]);
            ids.push(id);
        }
        cells.push(cell);
    }

    let entries = b.uvarint()?;
    // An item is at least two bytes: its flags and an empty path's length.
    if entries > (b.left() / 2) as u64 {
        return Err(bad(format!(
            "{entries} entries in an index of {} bytes",
            raw.len()
        )));
    }
    if let Some(max) = max_entries
        && entries > max
    {
        return Err(Error::limit(format!(
            "the archive has more than {max} entries (limit `max_entries`)"
        )));
    }
    let mut items = Items::default();
    // Not `entries`: an item in memory is many times its bytes in the index.
    items.items.reserve((entries as usize).min(1 << 16));
    let entries_start = b.pos;
    for _ in 0..entries {
        item(&mut b, &cells, &mut items)?;
    }
    let entry_bytes = entries_start..b.pos;

    let mut level = None;
    let mut sections = Vec::new();
    while b.left() > 0 {
        let id = b.uvarint()?;
        let body = b.bytes()?;
        // Strictly increasing, each id once (docs/bhive.md §6).
        if sections.last().is_some_and(|s: &Section| s.id >= id) {
            return Err(bad(format!("index section {id} is out of order")));
        }
        if id == SECTION_LEVEL && body.len() == 1 {
            level = Some(body[0]);
        }
        sections.push(Section {
            id,
            body: body.to_vec(),
        });
    }
    Ok(Index {
        cells,
        items,
        level,
        ids,
        entry_count: entries,
        entry_bytes,
        sections,
    })
}

/// A sealed cell's or index's length in the file: its plaintext and a tag for each 1 MiB
/// segment, one segment at least (docs/bhive.md §12.8).
pub const fn sealed_len(plain: u64) -> u64 {
    let segments = if plain == 0 {
        1
    } else {
        plain.div_ceil(1 << 20)
    };
    plain + 16 * segments
}

/// Parses a journal's raw bytes: `count` items, with extents in `cells` only (the cells up to
/// the record's own), and nothing after them.
pub fn parse_journal(raw: &[u8], count: u32, cells: &[Cell], out: &mut Items) -> Result<()> {
    let mut b = Bytes::new(raw);
    if u64::from(count) > (b.left() / 2) as u64 {
        return Err(bad("a journal with more items than it has bytes for"));
    }
    for _ in 0..count {
        item(&mut b, cells, out)?;
    }
    if b.left() > 0 {
        return Err(bad("a journal with bytes after its items"));
    }
    Ok(())
}
