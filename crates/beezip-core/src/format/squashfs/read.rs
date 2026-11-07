//! Reading squashfs 4.0 (docs/M5.md §5.10), BeeZip's own reader.
//!
//! - **The layout:** a 96-byte superblock, the compressor's options, the files' data blocks and
//!   the fragment blocks (several files' tails packed into one block), then the tables: inodes,
//!   directories, fragments, the NFS export table, ids and xattrs. Tables are sequences of
//!   metadata blocks, each 8 KiB once decoded, with a 2-byte header whose top bit says it's
//!   stored uncompressed; an inode or a directory is found by the offset of its block from the
//!   table's start and its offset in the decoded block.
//! - **Bounds:** nothing past the superblock's `bytes_used` is read, and it must fit in the file.
//!   The inode and directory tables are walked once when the image opens, recording where each
//!   block starts (4 bytes per block); everything else is read on demand. A data block decodes to
//!   at most the block size and a metadata block to 8 KiB. A file's block list is checked against
//!   what the inode table can hold before anything is read for it, and is read from the table a
//!   block at a time, so a crafted block count can't make the reader allocate. Folders already
//!   listed are skipped (a crafted image can make a cycle), and nesting is bounded.
//! - **Caches:** the last 64 decoded metadata blocks and the last 4 fragment blocks.
//! - **Entries:** a folder before its contents, names in directory order. Files that share an
//!   inode are hard links: the first is the `File`, the rest `Hardlink`s to it. Devices, FIFOs
//!   and sockets are `Other`. Names and link targets are bytes, read through the source's
//!   `NameDecoding` (docs/M5.md §6). Xattrs are ignored.
//! - **Data:** blocks of the block size (a size of 0 is a hole: a block of zeros), the last one
//!   short or the file's tail in a fragment. Every block must decode to exactly its share of the
//!   file, so a file reads its size or fails with `Corrupt`.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
};

use super::{
    MAGIC, MAGIC_BE,
    codec::{Compressor, Decoder},
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    format::{
        ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
    },
    io::{Counter, copy, read_error},
    names::{NameDecoding, SystemPage},
    safefs::Partial,
    source::Source,
    time::from_unix,
};

const SUPERBLOCK_LEN: usize = 96;
/// A metadata block's decoded size (all but a table's last are this long).
const META: usize = 8192;
/// A metadata block's header: stored uncompressed.
const META_UNCOMPRESSED: u16 = 0x8000;
/// A data block's size word: stored uncompressed.
const BLOCK_UNCOMPRESSED: u32 = 1 << 24;
/// A file inode's fragment index when its tail isn't in a fragment.
const NO_FRAGMENT: u32 = 0xFFFF_FFFF;
/// Fragment table entries per metadata block (16 bytes each).
const FRAGMENTS_PER_BLOCK: u64 = (META / 16) as u64;
/// A table pointer that isn't set.
const NOT_SET: u64 = u64::MAX;
/// `flags`: the compressor's options follow the superblock.
const FLAG_COMPRESSOR_OPTIONS: u16 = 0x0400;
/// Names are at most 256 bytes; symlink targets far less than this in practice (Linux: 4 095).
const MAX_NAME: usize = 256;
const MAX_TARGET: u32 = 65_535;
/// A directory header covers at most 256 entries.
const MAX_DIR_RUN: u32 = 256;
/// Folders nested deeper than this are `Corrupt`: no real tree is, and paths would be absurd.
const MAX_DEPTH: usize = 1024;
const META_CACHE: usize = 64;
const FRAGMENT_CACHE: usize = 4;

const S_IFSOCK: u32 = 0o140_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFREG: u32 = 0o100_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("squashfs: {message}"))
}

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// The superblock's fields BeeZip uses.
#[derive(Debug, Clone, Copy)]
struct Superblock {
    block_size: u32,
    frag_count: u32,
    compressor: Compressor,
    flags: u16,
    root_inode: u64,
    bytes_used: u64,
    id_table: u64,
    xattr_table: u64,
    inode_table: u64,
    dir_table: u64,
    frag_table: u64,
    export_table: u64,
}

impl Superblock {
    fn parse(b: &[u8], file_len: u64) -> Result<Self> {
        if b.len() < SUPERBLOCK_LEN {
            return Err(bad("the file is too short to be an image"));
        }
        if b.starts_with(MAGIC_BE) {
            return Err(Error::unsupported_format(
                "big-endian squashfs images aren't supported",
            ));
        }
        if !b.starts_with(MAGIC) {
            return Err(Error::unsupported_format("not a squashfs image"));
        }
        let (major, minor) = (le16(b, 28), le16(b, 30));
        if (major, minor) != (4, 0) {
            return Err(Error::unsupported_format(format!(
                "squashfs {major}.{minor} images aren't supported; BeeZip reads squashfs 4.0"
            )));
        }
        let id = le16(b, 20);
        let compressor = Compressor::from_id(id).ok_or_else(|| {
            Error::unsupported_format(format!("squashfs: unknown compressor {id}"))
        })?;
        let sb = Self {
            block_size: le32(b, 12),
            frag_count: le32(b, 16),
            compressor,
            flags: le16(b, 24),
            root_inode: le64(b, 32),
            bytes_used: le64(b, 40),
            id_table: le64(b, 48),
            xattr_table: le64(b, 56),
            inode_table: le64(b, 64),
            dir_table: le64(b, 72),
            frag_table: le64(b, 80),
            export_table: le64(b, 88),
        };
        let bs = sb.block_size;
        if !bs.is_power_of_two()
            || !(4096..=1 << 20).contains(&bs)
            || u32::from(le16(b, 22)) != bs.trailing_zeros()
        {
            return Err(bad(format!("a block size of {bs} bytes isn't valid")));
        }
        if sb.bytes_used > file_len {
            return Err(bad(format!(
                "the image is cut short: it holds {} bytes, and the file has {file_len}",
                sb.bytes_used
            )));
        }
        if sb.inode_table < SUPERBLOCK_LEN as u64
            || sb.inode_table >= sb.dir_table
            || sb.dir_table > sb.bytes_used
        {
            return Err(bad(
                "the inode and directory tables aren't where they can be",
            ));
        }
        Ok(sb)
    }
}

/// The image: reads at offsets, never past `len`, counting what it reads.
struct Image {
    file: BufReader<Box<dyn ReadSeek>>,
    /// Where `file` is, when known.
    pos: Option<u64>,
    len: u64,
    counter: Counter,
}

impl Image {
    fn read_at(&mut self, at: u64, buf: &mut [u8], what: &str) -> Result<()> {
        let end = at
            .checked_add(buf.len() as u64)
            .filter(|&e| e <= self.len)
            .ok_or_else(|| bad(format!("{what} is past the end of the image")))?;
        if self.pos != Some(at) {
            let rel = self
                .pos
                .and_then(|p| i64::try_from(at).ok().zip(i64::try_from(p).ok()))
                .map(|(a, p)| a - p);
            self.pos = None;
            match rel {
                Some(d) => self.file.seek_relative(d),
                None => self.file.seek(SeekFrom::Start(at)).map(|_| ()),
            }
            .map_err(|e| Error::io("seeking in the image", &e))?;
        }
        self.pos = None;
        self.file.read_exact(buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                bad(format!("the image ends inside {what}"))
            } else {
                read_error(&e)
            }
        })?;
        self.pos = Some(end);
        self.counter.add(buf.len() as u64);
        Ok(())
    }

    fn u16_at(&mut self, at: u64, what: &str) -> Result<u16> {
        let mut b = [0u8; 2];
        self.read_at(at, &mut b, what)?;
        Ok(u16::from_le_bytes(b))
    }

    fn u64_at(&mut self, at: u64, what: &str) -> Result<u64> {
        let mut b = [0u8; 8];
        self.read_at(at, &mut b, what)?;
        Ok(u64::from_le_bytes(b))
    }
}

/// A table of metadata blocks: where each starts, relative to the table, so a position in the
/// table's decoded bytes maps to a block (position / 8 KiB) and an offset in it.
#[derive(Debug, Default)]
struct Table {
    start: u64,
    blocks: Vec<u32>,
}

impl Table {
    /// Walks the block headers from `start` up to `end`. It stops at a header that isn't a
    /// block's or a block that runs past `end`: what's after it can't be reached.
    fn walk(img: &mut Image, start: u64, end: u64, what: &str) -> Result<Self> {
        let mut blocks = Vec::new();
        let mut at = start;
        while at + 2 < end {
            let Ok(rel) = u32::try_from(at - start) else {
                break;
            };
            let header = img.u16_at(at, what)?;
            let stored = u64::from(header & !META_UNCOMPRESSED);
            if stored == 0 || stored > META as u64 || at + 2 + stored > end {
                break;
            }
            blocks.push(rel);
            at += 2 + stored;
        }
        Ok(Self { start, blocks })
    }

    /// The most decoded bytes the table can hold.
    fn bound(&self) -> u64 {
        self.blocks.len() as u64 * META as u64
    }

    /// The position of a reference: a block's offset from the table's start, and an offset in
    /// it.
    fn position(&self, block: u64, offset: u64, what: &str) -> Result<u64> {
        let index = u32::try_from(block)
            .ok()
            .and_then(|b| self.blocks.binary_search(&b).ok())
            .filter(|_| offset < META as u64)
            .ok_or_else(|| bad(format!("{what} points outside its table")))?;
        Ok(index as u64 * META as u64 + offset)
    }
}

/// A small cache, by key, that replaces its least recently used slot.
struct Lru<V> {
    slots: Vec<Slot<V>>,
    cap: usize,
    clock: u64,
}

struct Slot<V> {
    key: Option<u64>,
    used: u64,
    value: V,
}

impl<V: Default> Lru<V> {
    fn new(cap: usize) -> Self {
        Self {
            slots: Vec::with_capacity(cap),
            cap,
            clock: 0,
        }
    }

    fn find(&mut self, key: u64) -> Option<usize> {
        let i = self.slots.iter().position(|s| s.key == Some(key))?;
        self.clock += 1;
        self.slots[i].used = self.clock;
        Some(i)
    }

    /// A slot to fill for `key`, emptied: a new one, or the least recently used. Its key is
    /// set by [`Lru::fill`], once its value is good.
    fn victim(&mut self) -> usize {
        if self.slots.len() < self.cap {
            self.slots.push(Slot {
                key: None,
                used: 0,
                value: V::default(),
            });
            return self.slots.len() - 1;
        }
        let i = self
            .slots
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.used)
            .map_or(0, |(i, _)| i);
        self.slots[i].key = None;
        i
    }

    fn fill(&mut self, i: usize, key: u64) {
        self.clock += 1;
        self.slots[i].key = Some(key);
        self.slots[i].used = self.clock;
    }
}

/// The parts of an image every read needs: the file, the decoder, the tables and the caches.
struct Inner {
    img: Image,
    sb: Superblock,
    decoder: Decoder,
    inodes: Table,
    dirs: Table,
    /// Decoded metadata blocks, by where they are in the image.
    meta: Lru<Vec<u8>>,
    /// Decoded fragment blocks, by fragment index.
    frags: Lru<Vec<u8>>,
    /// A block's stored bytes, and a decoded block lent to the file being read.
    packed: Vec<u8>,
    spare: Vec<u8>,
}

/// What a file's data is made of.
#[derive(Debug, Clone, Copy)]
struct FileInfo {
    blocks_start: u64,
    size: u64,
    /// The block list's position in the inode table, and its length.
    list: u64,
    blocks: u64,
    /// The fragment holding the tail, and where in it the tail starts.
    fragment: Option<(u32, u32)>,
}

#[derive(Debug)]
enum InodeKind {
    Dir {
        at: u64,
        len: u64,
    },
    File(FileInfo),
    Symlink(Vec<u8>),
    /// A device, FIFO or socket, with its file type bits.
    Other(u32),
}

#[derive(Debug)]
struct Inode {
    kind: InodeKind,
    mode: u16,
    mtime: u32,
}

struct DirEntry {
    name: Vec<u8>,
    inode: u64,
}

impl Inner {
    /// The decoded metadata block at `at` in the image.
    fn meta_block(&mut self, at: u64) -> Result<&[u8]> {
        let i = match self.meta.find(at) {
            Some(i) => i,
            None => {
                let i = self.meta.victim();
                let mut out = std::mem::take(&mut self.meta.slots[i].value);
                let decoded = self.decode_meta(at, &mut out);
                self.meta.slots[i].value = out;
                decoded?;
                self.meta.fill(i, at);
                i
            }
        };
        Ok(&self.meta.slots[i].value)
    }

    fn decode_meta(&mut self, at: u64, out: &mut Vec<u8>) -> Result<()> {
        let header = self.img.u16_at(at, "a metadata block")?;
        let stored = usize::from(header & !META_UNCOMPRESSED);
        if stored == 0 || stored > META {
            return Err(bad(format!("a metadata block of {stored} bytes")));
        }
        let mut packed = std::mem::take(&mut self.packed);
        packed.resize(stored, 0);
        let read = self.img.read_at(at + 2, &mut packed, "a metadata block");
        let decoded = read.and_then(|()| {
            if header & META_UNCOMPRESSED != 0 {
                out.clear();
                out.extend_from_slice(&packed);
                Ok(())
            } else {
                self.decoder.decode(&packed, out, META)
            }
        });
        self.packed = packed;
        decoded
    }

    /// `out.len()` bytes of `table`'s decoded bytes from `pos`, across blocks.
    fn read_table(&mut self, which: Which, mut pos: u64, out: &mut [u8]) -> Result<()> {
        let mut done = 0;
        while done < out.len() {
            let table = match which {
                Which::Inodes => &self.inodes,
                Which::Dirs => &self.dirs,
            };
            let index = usize::try_from(pos / META as u64).unwrap_or(usize::MAX);
            let Some(&rel) = table.blocks.get(index) else {
                return Err(bad(format!("{} runs past its table", which.what())));
            };
            let at = table.start + u64::from(rel);
            let offset = (pos % META as u64) as usize;
            let block = self.meta_block(at)?;
            let avail = block.get(offset..).unwrap_or_default();
            if avail.is_empty() {
                return Err(bad(format!("{} runs past its table", which.what())));
            }
            let n = avail.len().min(out.len() - done);
            out[done..done + n].copy_from_slice(&avail[..n]);
            done += n;
            pos += n as u64;
        }
        Ok(())
    }

    fn inode(&mut self, pos: u64) -> Result<Inode> {
        let mut h = [0u8; 16];
        self.read_table(Which::Inodes, pos, &mut h)?;
        let kind = le16(&h, 0);
        let mode = le16(&h, 2);
        let mtime = le32(&h, 8);
        let body = pos + 16;
        let kind = match kind {
            // Basic and extended directories.
            1 | 8 => {
                let mut b = [0u8; 24];
                let n = if kind == 1 { 16 } else { 24 };
                self.read_table(Which::Inodes, body, &mut b[..n])?;
                let (block, size, offset) = if kind == 1 {
                    (le32(&b, 0), u32::from(le16(&b, 8)), le16(&b, 10))
                } else {
                    (le32(&b, 8), le32(&b, 4), le16(&b, 18))
                };
                // The size counts the `.` and `..` that aren't stored.
                let len = u64::from(size)
                    .checked_sub(3)
                    .ok_or_else(|| bad("a folder's size is too small"))?;
                let at = if len == 0 {
                    0
                } else {
                    self.dirs
                        .position(u64::from(block), u64::from(offset), "a folder")?
                };
                if at + len > self.dirs.bound() {
                    return Err(bad("a folder's listing runs past the directory table"));
                }
                InodeKind::Dir { at, len }
            }
            // Basic and extended files.
            2 | 9 => {
                let mut b = [0u8; 40];
                let n = if kind == 2 { 16 } else { 40 };
                self.read_table(Which::Inodes, body, &mut b[..n])?;
                let (blocks_start, fragment, offset, size) = if kind == 2 {
                    (
                        u64::from(le32(&b, 0)),
                        le32(&b, 4),
                        le32(&b, 8),
                        u64::from(le32(&b, 12)),
                    )
                } else {
                    (le64(&b, 0), le32(&b, 28), le32(&b, 32), le64(&b, 8))
                };
                InodeKind::File(self.file_info(
                    blocks_start,
                    size,
                    fragment,
                    offset,
                    body + n as u64,
                )?)
            }
            // Basic and extended symlinks.
            3 | 10 => {
                let mut b = [0u8; 8];
                self.read_table(Which::Inodes, body, &mut b)?;
                let len = le32(&b, 4);
                if len > MAX_TARGET || body + 8 + u64::from(len) > self.inodes.bound() {
                    return Err(bad(format!("a symbolic link's target of {len} bytes")));
                }
                let mut target = vec![0u8; len as usize];
                self.read_table(Which::Inodes, body + 8, &mut target)?;
                InodeKind::Symlink(target)
            }
            4 | 11 => InodeKind::Other(S_IFBLK),
            5 | 12 => InodeKind::Other(S_IFCHR),
            6 | 13 => InodeKind::Other(S_IFIFO),
            7 | 14 => InodeKind::Other(S_IFSOCK),
            other => return Err(bad(format!("an inode of unknown type {other}"))),
        };
        Ok(Inode { kind, mode, mtime })
    }

    /// A file's layout, checked: its block list must fit in the inode table and its tail in its
    /// fragment, before anything is read for it.
    fn file_info(
        &self,
        blocks_start: u64,
        size: u64,
        fragment: u32,
        offset: u32,
        list: u64,
    ) -> Result<FileInfo> {
        let bs = u64::from(self.sb.block_size);
        let fragment = (fragment != NO_FRAGMENT).then_some((fragment, offset));
        let blocks = if fragment.is_some() {
            size / bs
        } else {
            size.div_ceil(bs)
        };
        let room = self.inodes.bound().saturating_sub(list) / 4;
        if blocks > room {
            return Err(bad(format!(
                "a file of {size} bytes needs a list of {blocks} blocks, more than the inode \
                 table can hold"
            )));
        }
        if blocks_start > self.sb.bytes_used {
            return Err(bad("a file's data starts past the end of the image"));
        }
        if let Some((index, offset)) = fragment {
            let tail = size - blocks * bs;
            if index >= self.sb.frag_count || u64::from(offset) + tail > bs {
                return Err(bad("a file's tail is outside its fragment"));
            }
        }
        Ok(FileInfo {
            blocks_start,
            size,
            list,
            blocks,
            fragment,
        })
    }

    /// The entries of the folder listing at `at`, `len` bytes long.
    fn listing(&mut self, at: u64, len: u64) -> Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        let mut pos = at;
        let end = at + len;
        while pos < end {
            if end - pos < 12 {
                return Err(bad("a folder's listing ends inside a header"));
            }
            let mut h = [0u8; 12];
            self.read_table(Which::Dirs, pos, &mut h)?;
            pos += 12;
            let count = le32(&h, 0);
            let start = u64::from(le32(&h, 4));
            if count >= MAX_DIR_RUN {
                return Err(bad(format!(
                    "a folder header of {} entries",
                    u64::from(count) + 1
                )));
            }
            for _ in 0..=count {
                if end - pos < 8 {
                    return Err(bad("a folder's listing ends inside an entry"));
                }
                let mut e = [0u8; 8];
                self.read_table(Which::Dirs, pos, &mut e)?;
                let offset = u64::from(le16(&e, 0));
                let name_len = usize::from(le16(&e, 6)) + 1;
                pos += 8;
                if name_len > MAX_NAME || end - pos < name_len as u64 {
                    return Err(bad("a name in a folder's listing is too long"));
                }
                let mut name = vec![0u8; name_len];
                self.read_table(Which::Dirs, pos, &mut name)?;
                pos += name_len as u64;
                let inode = self.inodes.position(start, offset, "a folder entry")?;
                out.push(DirEntry { name, inode });
            }
        }
        Ok(out)
    }

    /// The decoded fragment block `index`, from the cache when it's there.
    fn fragment_block(&mut self, index: u32) -> Result<&[u8]> {
        let i = match self.frags.find(u64::from(index)) {
            Some(i) => i,
            None => {
                let (start, word) = self.fragment_entry(index)?;
                let i = self.frags.victim();
                let mut out = std::mem::take(&mut self.frags.slots[i].value);
                let decoded = self.decode_block(start, word, self.sb.block_size as usize, &mut out);
                self.frags.slots[i].value = out;
                decoded?;
                self.frags.fill(i, u64::from(index));
                i
            }
        };
        Ok(&self.frags.slots[i].value)
    }

    /// The fragment table's entry `index`: where its block is and its size word.
    fn fragment_entry(&mut self, index: u32) -> Result<(u64, u32)> {
        if index >= self.sb.frag_count {
            return Err(bad("a file's fragment isn't in the fragment table"));
        }
        let i = u64::from(index);
        let at = self.sb.frag_table + (i / FRAGMENTS_PER_BLOCK) * 8;
        let block = self.img.u64_at(at, "the fragment table")?;
        if block >= self.sb.bytes_used {
            return Err(bad("the fragment table points past the end of the image"));
        }
        let off = ((i % FRAGMENTS_PER_BLOCK) * 16) as usize;
        let meta = self.meta_block(block)?;
        let e = meta
            .get(off..off + 16)
            .ok_or_else(|| bad("the fragment table is short"))?;
        Ok((le64(e, 0), le32(e, 8)))
    }

    /// A data or fragment block, stored at `at` with size word `word`, decoded into `out`: at
    /// most `max` bytes. A size of 0 is a hole, which the caller fills.
    fn decode_block(&mut self, at: u64, word: u32, max: usize, out: &mut Vec<u8>) -> Result<u64> {
        let stored = u64::from(word & !BLOCK_UNCOMPRESSED);
        if stored > u64::from(self.sb.block_size) {
            return Err(bad(format!(
                "a block of {stored} bytes is larger than the block size"
            )));
        }
        out.clear();
        if stored == 0 {
            return Ok(0);
        }
        let mut packed = std::mem::take(&mut self.packed);
        packed.resize(stored as usize, 0);
        let read = self.img.read_at(at, &mut packed, "a data block");
        let decoded = read.and_then(|()| {
            if word & BLOCK_UNCOMPRESSED != 0 {
                if packed.len() > max {
                    return Err(bad("a block holds more than its file"));
                }
                out.extend_from_slice(&packed);
                Ok(())
            } else {
                self.decoder.decode(&packed, out, max)
            }
        });
        self.packed = packed;
        decoded.map(|()| stored)
    }

    /// The end of the directory table: the start of whatever follows it. mksquashfs and backhand
    /// write the fragment, export, id and xattr tables after it, each a run of metadata blocks
    /// then their index, so the first block any index points at, or the first index, ends it.
    fn dir_table_end(&mut self) -> Result<u64> {
        let sb = self.sb;
        let mut ends = vec![sb.bytes_used];
        let first = |img: &mut Image, table: u64, ends: &mut Vec<u64>| {
            if table < sb.bytes_used {
                ends.push(table);
                if let Ok(p) = img.u64_at(table, "a table's index") {
                    ends.push(p);
                }
            }
        };
        if sb.frag_count > 0 {
            first(&mut self.img, sb.frag_table, &mut ends);
        } else if sb.frag_table < sb.bytes_used {
            ends.push(sb.frag_table);
        }
        if sb.export_table != NOT_SET {
            first(&mut self.img, sb.export_table, &mut ends);
        }
        first(&mut self.img, sb.id_table, &mut ends);
        // The xattr table's index starts with where its key-value blocks start.
        first(&mut self.img, sb.xattr_table, &mut ends);
        Ok(ends
            .into_iter()
            .filter(|&e| e > sb.dir_table && e <= sb.bytes_used)
            .min()
            .unwrap_or(sb.bytes_used))
    }
}

#[derive(Debug, Clone, Copy)]
enum Which {
    Inodes,
    Dirs,
}

impl Which {
    fn what(self) -> &'static str {
        match self {
            Self::Inodes => "an inode",
            Self::Dirs => "a folder's listing",
        }
    }
}

/// An entry's data.
#[derive(Debug, Clone, Copy)]
enum Data {
    None,
    File(FileInfo),
    /// A hard link: the data of the file with this entry id.
    Link(usize),
}

pub struct SquashfsReader {
    source: Source,
    inner: Inner,
    entries: Vec<Entry>,
    data: Vec<Data>,
    /// Keeps an image spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl SquashfsReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (file, spool): (Box<dyn ReadSeek>, _) = if source.codecs.is_empty() {
            (Box::new(source.input()?), None)
        } else {
            // Blocks are read by offset: spool the decoded stream, under the usual limits.
            let mut tmp = Partial::create_temp("beezip-spool.squashfs")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            let file = File::open(tmp.path())
                .map_err(|e| Error::io(format!("opening {}", tmp.path().display()), &e))?;
            (Box::new(file), Some(tmp))
        };
        let mut file = BufReader::with_capacity(64 * 1024, file);
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| Error::io("reading the image", &e))?;
        source.counter.set(0);
        let mut img = Image {
            file,
            pos: None,
            len: file_len,
            counter: source.counter.clone(),
        };
        let mut head = vec![0u8; SUPERBLOCK_LEN.min(usize::try_from(file_len).unwrap_or(0))];
        img.read_at(0, &mut head, "the superblock")?;
        let sb = Superblock::parse(&head, file_len)?;
        img.len = sb.bytes_used;
        let decoder = Decoder::new(sb.compressor, &source.limits)?;
        let mut inner = Inner {
            img,
            sb,
            decoder,
            inodes: Table::default(),
            dirs: Table::default(),
            meta: Lru::new(META_CACHE),
            frags: Lru::new(FRAGMENT_CACHE),
            packed: Vec::new(),
            spare: Vec::new(),
        };
        if sb.flags & FLAG_COMPRESSOR_OPTIONS != 0 {
            check_options(&mut inner)?;
        }
        inner.inodes = Table::walk(
            &mut inner.img,
            sb.inode_table,
            sb.dir_table,
            "the inode table",
        )?;
        let end = inner.dir_table_end()?;
        inner.dirs = Table::walk(&mut inner.img, sb.dir_table, end, "the directory table")?;
        cx.check()?;
        let (entries, data) = list(&mut inner, &source, cx)?;
        Ok(Self {
            source,
            inner,
            entries,
            data,
            _spool: spool,
        })
    }

    fn pass_meter(&self) -> Meter {
        self.source.counter.set(0);
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.inner.sb.bytes_used));
        meter.entries_total = Some(self.entries.len() as u64);
        meter
    }

    /// The data of entry `id`: a file's, or its target's for a hard link.
    fn file_of(&self, id: usize) -> Option<FileInfo> {
        match self.data.get(id)? {
            Data::File(f) => Some(*f),
            Data::Link(to) => match self.data.get(*to)? {
                Data::File(f) => Some(*f),
                _ => None,
            },
            Data::None => None,
        }
    }
}

/// The compressor's options: read to check they're there and that lz4's are the legacy
/// format the kernel and mksquashfs write; the others don't change how blocks decode.
fn check_options(inner: &mut Inner) -> Result<()> {
    let at = SUPERBLOCK_LEN as u64;
    let opts = inner.meta_block(at)?.to_vec();
    if opts.len() > 64 {
        return Err(bad("the compressor's options are too long"));
    }
    if at + 2 > inner.sb.inode_table {
        return Err(bad("the compressor's options overlap the inode table"));
    }
    if inner.decoder.compressor() == Compressor::Lz4 && le32(&opts, 0) != 1 {
        return Err(Error::unsupported_format(format!(
            "squashfs: lz4 format {} isn't supported",
            le32(&opts, 0)
        )));
    }
    Ok(())
}

/// A folder being listed: its entries not yet listed, in reverse, and its path.
struct Frame {
    rest: Vec<DirEntry>,
    path: String,
    raw: Vec<u8>,
}

/// Every entry, a folder before its contents.
fn list(inner: &mut Inner, source: &Source, cx: &mut dyn Ctx) -> Result<(Vec<Entry>, Vec<Data>)> {
    let names: NameDecoding = source.names;
    let method = Some(inner.sb.compressor.name());
    let sb = inner.sb;
    let root = inner
        .inodes
        .position(sb.root_inode >> 16, sb.root_inode & 0xFFFF, "the root")?;
    let InodeKind::Dir { at, len } = inner.inode(root)?.kind else {
        return Err(bad("the root isn't a folder"));
    };
    let mut seen_dirs: HashSet<u64> = HashSet::from([root]);
    let mut files: HashMap<u64, usize> = HashMap::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut data: Vec<Data> = Vec::new();
    let mut read = 0u64;
    let mut rest = inner.listing(at, len)?;
    read += rest.len() as u64;
    source.limits.check_entries(read)?;
    rest.reverse();
    let mut stack = vec![Frame {
        rest,
        path: String::new(),
        raw: Vec::new(),
    }];
    while let Some(frame) = stack.last_mut() {
        let Some(de) = frame.rest.pop() else {
            stack.pop();
            continue;
        };
        let name = names.decode(&de.name, false, SystemPage::Ansi);
        let (path, raw) = if frame.path.is_empty() {
            (name, de.name.clone())
        } else {
            let mut raw = frame.raw.clone();
            raw.push(b'/');
            raw.extend_from_slice(&de.name);
            (format!("{}/{name}", frame.path), raw)
        };
        let depth = stack.len();
        let inode = inner.inode(de.inode)?;
        let perms = u32::from(inode.mode) & 0o7777;
        let id = entries.len();
        let mut entry = Entry::new(id, path, EntryKind::File);
        entry.raw_path = raw;
        entry.modified = from_unix(i64::from(inode.mtime), 0);
        let mut item = Data::None;
        match inode.kind {
            InodeKind::Dir { at, len } => {
                if !seen_dirs.insert(de.inode) {
                    cx.warn(format!(
                        "skipped `{}`: a folder already listed (the image links folders in a \
                         loop)",
                        entry.path
                    ));
                    continue;
                }
                if depth >= MAX_DEPTH {
                    return Err(bad(format!(
                        "folders are nested more than {MAX_DEPTH} deep"
                    )));
                }
                cx.check()?;
                entry.kind = EntryKind::Dir;
                entry.unix_mode = Some(S_IFDIR | perms);
                let mut rest = inner.listing(at, len)?;
                read += rest.len() as u64;
                source.limits.check_entries(read)?;
                rest.reverse();
                stack.push(Frame {
                    rest,
                    path: entry.path.clone(),
                    raw: entry.raw_path.clone(),
                });
            }
            InodeKind::File(f) => {
                entry.size = Some(f.size);
                entry.method = method;
                entry.unix_mode = Some(S_IFREG | perms);
                match files.get(&de.inode) {
                    Some(&first) => {
                        entry.kind = EntryKind::Hardlink {
                            target: entries[first].path.clone(),
                        };
                        item = Data::Link(first);
                    }
                    None => {
                        files.insert(de.inode, id);
                        item = Data::File(f);
                    }
                }
            }
            InodeKind::Symlink(target) => {
                entry.kind = EntryKind::Symlink {
                    target: names.decode(&target, false, SystemPage::Ansi),
                };
                entry.unix_mode = Some(S_IFLNK | perms);
            }
            InodeKind::Other(kind) => {
                entry.kind = EntryKind::Other;
                entry.unix_mode = Some(kind | perms);
            }
        }
        entries.push(entry);
        data.push(item);
    }
    Ok((entries, data))
}

impl ArchiveReader for SquashfsReader {
    fn format(&self) -> FormatId {
        FormatId::Squashfs
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Squashfs,
            codecs: self.source.codecs.clone(),
            methods: vec![self.inner.sb.compressor.name()],
            comment: None,
            encryption: Encryption::None,
            solid: false,
            sfx: false,
            volumes: 1,
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut meter = self.pass_meter();
        let mut done = 0u64;
        for (id, entry) in self.entries.iter().enumerate() {
            if !sel.matches(entry) {
                continue;
            }
            cx.check()?;
            meter.entries_done = done;
            meter.current = Some(entry.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            match (&entry.kind, self.data.get(id)) {
                (EntryKind::File, Some(Data::File(f))) => {
                    let mut data = self.source.guard(FileData::new(&mut self.inner, *f));
                    sink.entry(entry, &mut data, &mut mcx)?;
                }
                _ => sink.entry(entry, &mut io::empty(), &mut mcx)?,
            }
            done += 1;
        }
        meter.entries_done = done;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        if id >= self.entries.len() {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        }
        let Some(f) = self.file_of(id) else {
            return Ok(Box::new(io::empty()));
        };
        self.source.counter.set(0);
        Ok(Box::new(
            self.source.guard(FileData::new(&mut self.inner, f)),
        ))
    }
}

/// One file's bytes: its blocks in turn, then its tail from its fragment. Exactly its size, or
/// an error.
struct FileData<'a> {
    inner: &'a mut Inner,
    f: FileInfo,
    /// The next block, and where its stored bytes are.
    next: u64,
    at: u64,
    tail_done: bool,
    buf: Vec<u8>,
    pos: usize,
    left: u64,
    /// The first error, given back from then on.
    failed: Option<Error>,
}

impl<'a> FileData<'a> {
    fn new(inner: &'a mut Inner, f: FileInfo) -> Self {
        let mut buf = std::mem::take(&mut inner.spare);
        buf.clear();
        Self {
            inner,
            f,
            next: 0,
            at: f.blocks_start,
            tail_done: false,
            buf,
            pos: 0,
            left: f.size,
            failed: None,
        }
    }

    /// The next block, or the tail, into `buf`.
    fn fill(&mut self) -> Result<()> {
        let bs = u64::from(self.inner.sb.block_size);
        self.pos = 0;
        if self.next < self.f.blocks {
            let i = self.next;
            let want = if i + 1 < self.f.blocks || self.f.fragment.is_some() {
                bs
            } else {
                self.f.size - i * bs
            };
            let mut word = [0u8; 4];
            self.inner
                .read_table(Which::Inodes, self.f.list + i * 4, &mut word)?;
            let word = u32::from_le_bytes(word);
            let stored = self
                .inner
                .decode_block(self.at, word, want as usize, &mut self.buf)?;
            if stored == 0 {
                self.buf.resize(want as usize, 0);
            }
            if self.buf.len() as u64 != want {
                return Err(bad(format!(
                    "a block decodes to {} bytes; it should hold {want}",
                    self.buf.len()
                )));
            }
            self.at += stored;
            self.next += 1;
            return Ok(());
        }
        let tail = self.f.size - self.f.blocks * bs;
        match self.f.fragment {
            Some((index, offset)) if !self.tail_done && tail > 0 => {
                self.tail_done = true;
                let block = self.inner.fragment_block(index)?;
                let offset = offset as usize;
                let part = block
                    .get(offset..offset + tail as usize)
                    .ok_or_else(|| bad("a file's tail is past the end of its fragment"))?;
                self.buf.clear();
                self.buf.extend_from_slice(part);
                Ok(())
            }
            _ => Err(bad("a file's data ends before its size")),
        }
    }
}

impl Read for FileData<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.failed {
            return Err(e.clone().into_io());
        }
        if out.is_empty() || self.left == 0 {
            return Ok(0);
        }
        if self.pos >= self.buf.len()
            && let Err(e) = self.fill()
        {
            self.failed = Some(e.clone());
            return Err(e.into_io());
        }
        let avail = &self.buf[self.pos..];
        let n = avail
            .len()
            .min(out.len())
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        out[..n].copy_from_slice(&avail[..n]);
        self.pos += n;
        self.left -= n as u64;
        Ok(n)
    }
}

impl Drop for FileData<'_> {
    fn drop(&mut self) {
        self.inner.spare = std::mem::take(&mut self.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superblock() -> Vec<u8> {
        let mut b = vec![0u8; SUPERBLOCK_LEN];
        b[..4].copy_from_slice(MAGIC);
        b[12..16].copy_from_slice(&131_072u32.to_le_bytes());
        b[20..22].copy_from_slice(&1u16.to_le_bytes());
        b[22..24].copy_from_slice(&17u16.to_le_bytes());
        b[28..30].copy_from_slice(&4u16.to_le_bytes());
        b[40..48].copy_from_slice(&200u64.to_le_bytes());
        b[64..72].copy_from_slice(&96u64.to_le_bytes());
        b[72..80].copy_from_slice(&150u64.to_le_bytes());
        b
    }

    #[test]
    fn superblocks_are_checked() {
        Superblock::parse(&superblock(), 200).unwrap();
        let kind = |b: &[u8], len| Superblock::parse(b, len).unwrap_err().kind;

        let mut be = superblock();
        be[..4].copy_from_slice(MAGIC_BE);
        assert_eq!(kind(&be, 200), ErrorKind::UnsupportedFormat);
        let mut v3 = superblock();
        v3[28] = 3;
        let err = Superblock::parse(&v3, 200).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedFormat);
        assert!(err.message.contains("3.0"), "{err}");
        let mut comp = superblock();
        comp[20] = 9;
        assert_eq!(kind(&comp, 200), ErrorKind::UnsupportedFormat);

        // Cut short, a bad block size, tables out of order.
        assert_eq!(kind(&superblock(), 199), ErrorKind::Corrupt);
        let mut bs = superblock();
        bs[22] = 16;
        assert_eq!(kind(&bs, 200), ErrorKind::Corrupt);
        let mut order = superblock();
        order[72..80].copy_from_slice(&90u64.to_le_bytes());
        assert_eq!(kind(&order, 200), ErrorKind::Corrupt);
    }

    #[test]
    fn the_cache_replaces_its_oldest() {
        let mut lru: Lru<Vec<u8>> = Lru::new(2);
        for key in [1, 2] {
            let i = lru.victim();
            lru.fill(i, key);
        }
        assert!(lru.find(1).is_some());
        let i = lru.victim();
        lru.fill(i, 3);
        assert!(lru.find(2).is_none());
        assert!(lru.find(1).is_some() && lru.find(3).is_some());
    }

    #[test]
    fn table_positions_must_be_blocks() {
        let t = Table {
            start: 1000,
            blocks: vec![0, 300, 650],
        };
        assert_eq!(t.position(300, 5, "x").unwrap(), 8192 + 5);
        assert!(t.position(301, 0, "x").is_err());
        assert!(t.position(0, 8192, "x").is_err());
        assert_eq!(t.bound(), 3 * 8192);
    }
}
