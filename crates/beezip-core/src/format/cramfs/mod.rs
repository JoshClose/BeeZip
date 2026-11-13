//! CramFS, Linux's compressed ROM file system, read by BeeZip's own code (docs/M10.md).
//!
//! - **The superblock** (§3.1) is at 0, or at 512 after a boot block, in either byte order: the
//!   magic's order is every field's. Flags above bit 15 are ignored with a warning, as 7-Zip
//!   ignores them; others Linux doesn't know are `UnsupportedOperation`.
//! - **7-Zip's own variant** (docs/M11.md §6.1), which no other tool is known to write: a
//!   version 2 image with any of flag bits 12–15 set takes bits 11–13 as a block size of 4 KiB
//!   shifted by them, and bits 14–15 as the method: zlib (0 or 1) or LZMA (2), each block then
//!   five bytes of properties, its size and a raw stream. Bit 11 is Linux's extended-pointer
//!   flag only when bits 12–15 are clear.
//! - **Inodes** are 12 bytes; a folder is one run of its children's inodes, each followed by its
//!   name, NUL-padded to 4 bytes. Files and links are a table of block pointers, then zlib
//!   blocks, one per block of output; a block of no bytes is a hole. Linux 4.15's extended
//!   pointers mark a block stored, or point at its start (direct).
//! - **The block size** isn't stored: it's the page size of the machine the image is for. The
//!   first files of more than one block settle it, 4 to 64 KiB, by where their first block
//!   starts and what it decodes to; with none, 4 KiB.
//! - **The listing** is 7-Zip's: each folder's children, then each child folder's, in the
//!   image's order. Devices, FIFOs and sockets are `Other`. No times: CramFS stores none.
//! - **Damage is `Corrupt`** (§5.2): an image cut after its folders lists whole, and each file
//!   fails only when its own blocks are gone. `test` checks a version 2 image's CRC.
//!
//! Nothing here may panic, whatever the bytes.

#[doc(hidden)]
pub mod write;

use std::{
    borrow::Cow,
    collections::HashSet,
    io::{self, Read, Seek, SeekFrom},
};

use flate2::{Decompress, FlushDecompress, Status};

use super::{
    ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result, TestReport, TestSink,
    backend::{External, ExternalInfo, LevelProperty},
    io::{CountingReader, copy},
    names::SystemPage,
    safefs::Partial,
    source::{Input, Source},
};

const MAGIC: u32 = 0x28CD_3D45;
const SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
/// The boot block some images start with.
const PAD: u64 = 512;
/// The superblock with the root's inode.
const SUPER_LEN: u64 = 76;

const FLAG_V2: u32 = 1;
const FLAG_SORTED: u32 = 2;
const FLAG_HOLES: u32 = 0x100;
const FLAG_WRONG_SIGNATURE: u32 = 0x200;
const FLAG_SHIFTED_ROOT: u32 = 0x400;
const FLAG_EXT_PTRS: u32 = 0x800;
/// Linux's `CRAMFS_SUPPORTED_FLAGS`.
const KNOWN: u32 = 0xFF | FLAG_HOLES | FLAG_WRONG_SIGNATURE | FLAG_SHIFTED_ROOT | FLAG_EXT_PTRS;

/// 7-Zip's variant of a version 2 image: bits 11–13 a block size of 4 KiB shifted by them, bits
/// 14–15 a method (0 and 1 zlib, 2 LZMA, 3 none). Any of bits 12–15 set marks it.
fn sevenzip_variant(flags: u32) -> Option<(u32, u32)> {
    (flags & FLAG_V2 != 0 && flags & 0xF000 != 0)
        .then(|| (4096 << ((flags >> 11) & 7), (flags >> 14) & 3))
}

const BLK_UNCOMPRESSED: u32 = 1 << 31;
const BLK_DIRECT: u32 = 1 << 30;

const S_IFMT: u16 = 0o170_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;
const S_IFLNK: u16 = 0o120_000;

/// 7-Zip's limit on nested folders.
const MAX_DEPTH: usize = 256;
/// The block sizes the layout may show, smallest first.
const BLOCK_SIZES: [u32; 5] = [4096, 8192, 16384, 32768, 65536];
/// How many files the block size is read from.
const SIZE_VOTERS: usize = 16;
/// The longest link target read; Linux's is a page.
const MAX_TARGET: u64 = 64 * 1024;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("cramfs: {message}"))
}

/// Up to `len` bytes at `at`: fewer where the image ends first.
fn read_at(input: &mut (impl Read + Seek), at: u64, len: u64) -> Result<Vec<u8>> {
    input
        .seek(SeekFrom::Start(at))
        .map_err(|e| Error::io("seeking in the image", &e))?;
    let mut out = Vec::new();
    input
        .take(len)
        .read_to_end(&mut out)
        .map_err(|e| Error::io("reading the image", &e))?;
    Ok(out)
}

/// The superblock's fields.
#[derive(Debug, Clone)]
struct Super {
    /// Where it is: 0, or 512.
    base: u64,
    be: bool,
    /// The image's end, as stated (from the file's start, the boot block included).
    size: u32,
    flags: u32,
    crc: u32,
    edition: u32,
    files: u32,
    name: Vec<u8>,
    /// Flags above bit 15, which are ignored.
    ignored: u32,
}

impl Super {
    fn u32(&self, d: &[u8], at: usize) -> Option<u32> {
        let b: [u8; 4] = d.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if self.be {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    fn u16(&self, d: &[u8]) -> Option<u16> {
        let b: [u8; 2] = d.get(..2)?.try_into().ok()?;
        Some(if self.be {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }

    /// The inode at `at` in `d`.
    fn inode(&self, d: &[u8], at: usize) -> Option<Inode> {
        let a = self.u32(d, at)?;
        let b = self.u32(d, at + 4)?;
        let c = self.u32(d, at + 8)?;
        Some(if self.be {
            Inode {
                mode: (a >> 16) as u16,
                size: b >> 8,
                namelen: ((c >> 26) * 4) as usize,
                offset: u64::from(c & 0x03FF_FFFF) * 4,
            }
        } else {
            Inode {
                mode: a as u16,
                size: b & 0xFF_FFFF,
                namelen: ((c & 0x3F) * 4) as usize,
                offset: u64::from(c >> 6) * 4,
            }
        })
    }
}

/// The superblock, at 0 or 512.
fn superblock(input: &mut (impl Read + Seek)) -> Result<(Super, Inode)> {
    let head = read_at(input, 0, PAD + SUPER_LEN)?;
    for base in [0, PAD] {
        let b = base as usize;
        let be = match head.get(b..b + 4) {
            Some([0x45, 0x3D, 0xCD, 0x28]) => false,
            Some([0x28, 0xCD, 0x3D, 0x45]) => true,
            _ => continue,
        };
        if head.get(b + 16..b + 32) != Some(&SIGNATURE[..]) {
            continue;
        }
        let s = head
            .get(b..b + SUPER_LEN as usize)
            .ok_or_else(|| bad("the superblock is cut short"))?;
        let mut sb = Super {
            base,
            be,
            size: 0,
            flags: 0,
            crc: 0,
            edition: 0,
            files: 0,
            name: s[48..64].iter().copied().take_while(|&c| c != 0).collect(),
            ignored: 0,
        };
        let short = || bad("the superblock is cut short");
        sb.size = sb.u32(s, 4).ok_or_else(short)?;
        sb.flags = sb.u32(s, 8).ok_or_else(short)?;
        sb.crc = sb.u32(s, 32).ok_or_else(short)?;
        sb.edition = sb.u32(s, 36).ok_or_else(short)?;
        sb.files = sb.u32(s, 44).ok_or_else(short)?;
        let known = if sevenzip_variant(sb.flags).is_some() {
            KNOWN & !FLAG_EXT_PTRS | 0xF800
        } else {
            KNOWN
        };
        let unknown = sb.flags & !known;
        if unknown & 0xFFFF != 0 {
            return Err(Error::unsupported(format!(
                "cramfs: its superblock sets flags Linux doesn't know ({:#x})",
                unknown & 0xFFFF
            )));
        }
        sb.ignored = unknown;
        let root = sb.inode(s, 64).ok_or_else(short)?;
        if root.mode & S_IFMT != S_IFDIR {
            return Err(bad("the root isn't a folder"));
        }
        return Ok((sb, root));
    }
    Err(bad("there's no CramFS superblock"))
}

/// An inode, without its owner (an `Entry` has none).
#[derive(Debug, Clone, Copy)]
struct Inode {
    mode: u16,
    size: u32,
    namelen: usize,
    offset: u64,
}

/// A node as the folders list it.
#[derive(Debug, Clone)]
struct Node {
    path: Vec<u8>,
    inode: Inode,
}

/// Every node, 7-Zip's order: each folder's children, then each child folder's.
fn walk(
    input: &mut (impl Read + Seek),
    len: u64,
    sb: &Super,
    root: Inode,
    source: &Source,
    cx: &mut dyn Ctx,
) -> Result<Vec<Node>> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    // Folders still to list: (the node's index, or None for the root; its depth), reversed.
    let mut stack: Vec<(Option<usize>, usize)> = vec![(None, 0)];
    while let Some((dir, depth)) = stack.pop() {
        let (inode, path) = match dir {
            None => (root, Vec::new()),
            Some(k) => (nodes[k].inode, nodes[k].path.clone()),
        };
        if inode.offset == 0 && inode.size == 0 {
            continue;
        }
        if !seen.insert(inode.offset) {
            cx.warn(format!(
                "skipped what's in `{}`: a folder already listed (the image links folders in a \
                 loop)",
                String::from_utf8_lossy(&path)
            ));
            continue;
        }
        if depth > MAX_DEPTH {
            return Err(bad(format!(
                "folders are nested more than {MAX_DEPTH} deep"
            )));
        }
        cx.check()?;
        let start = inode.offset;
        let end = start + u64::from(inode.size);
        if start < sb.base + SUPER_LEN {
            return Err(bad(format!(
                "a folder's entries at {start} overlap the superblock"
            )));
        }
        if end > len {
            return Err(bad(format!(
                "the image is cut short: a folder's entries at {start}..{end} aren't in it"
            )));
        }
        let run = read_at(input, start, end - start)?;
        let mut p = 0usize;
        let mut subdirs = Vec::new();
        while p < run.len() {
            let at = start + p as u64;
            let n = sb
                .inode(&run, p)
                .ok_or_else(|| bad(format!("the inode at {at} runs past its folder's end")))?;
            if n.namelen == 0 {
                // mkfs.cramfs writes a name of 253 to 255 bytes so (docs/UPSTREAM.md).
                return Err(bad(format!("the entry at {at} has a name of no length")));
            }
            let name = run
                .get(p + 12..p + 12 + n.namelen)
                .ok_or_else(|| bad(format!("the name at {} isn't in its folder", at + 12)))?;
            let name: Vec<u8> = name.iter().copied().take_while(|&c| c != 0).collect();
            if name.is_empty() {
                return Err(bad(format!("the name at {} is empty", at + 12)));
            }
            let mut full = path.clone();
            if !full.is_empty() {
                full.push(b'/');
            }
            full.extend_from_slice(&name);
            if n.mode & S_IFMT == S_IFDIR {
                subdirs.push((nodes.len(), depth + 1));
            }
            nodes.push(Node {
                path: full,
                inode: n,
            });
            source.limits.check_entries(nodes.len() as u64)?;
            p += 12 + n.namelen;
        }
        stack.extend(subdirs.into_iter().rev().map(|(k, d)| (Some(k), d)));
    }
    Ok(nodes)
}

/// The open image, and what reading it needs.
struct Inner {
    input: CountingReader<Input>,
    len: u64,
    sb: Super,
    blk: u32,
    zlib: Decompress,
    packed: Vec<u8>,
    /// 7-Zip's LZMA variant.
    lzma: bool,
}

impl Inner {
    fn ext(&self) -> bool {
        self.sb.flags & FLAG_EXT_PTRS != 0 && sevenzip_variant(self.sb.flags).is_none()
    }

    /// An LZMA block of 7-Zip's variant: 5 bytes of properties, the size it decodes to (4 bytes,
    /// little-endian), then the stream, which must end exactly there. The dictionary is held to
    /// the block: a window past it is never used, so no more is allocated.
    fn unlzma(packed: &[u8], out: &mut Vec<u8>, want: usize) -> std::result::Result<(), String> {
        let (props, rest) = packed
            .split_at_checked(5)
            .ok_or("it's shorter than its header")?;
        let (size, data) = rest
            .split_at_checked(4)
            .ok_or("it's shorter than its header")?;
        let size = u32::from_le_bytes(size.try_into().unwrap_or_default()) as usize;
        if size != want {
            return Err(format!("it says {size} bytes, for {want}"));
        }
        let dict = u32::from_le_bytes(props[1..5].try_into().unwrap_or_default())
            .min(u32::try_from(want.max(4096)).unwrap_or(u32::MAX));
        let mut src = data;
        let mut r =
            lzma_rust2::LzmaReader::new_with_props(&mut src, want as u64, props[0], dict, None)
                .map_err(|e| format!("it's damaged ({e})"))?;
        out.clear();
        out.resize(want, 0);
        r.read_exact(out)
            .map_err(|e| format!("it's damaged ({e})"))?;
        let mut more = [0u8; 1];
        if !matches!(r.read(&mut more), Ok(0)) {
            return Err("it decodes to more than its size".into());
        }
        drop(r);
        if !src.is_empty() {
            return Err(format!("{} bytes are left after its stream", src.len()));
        }
        Ok(())
    }

    /// Decodes zlib block `packed` into `out`: exactly `want` bytes, or why not.
    fn inflate(
        zlib: &mut Decompress,
        packed: &[u8],
        out: &mut Vec<u8>,
        want: usize,
    ) -> std::result::Result<(), String> {
        zlib.reset(true);
        out.clear();
        out.resize(want + 1, 0);
        let status = zlib
            .decompress(packed, out, FlushDecompress::Finish)
            .map_err(|e| format!("it's damaged ({e})"))?;
        let n = usize::try_from(zlib.total_out()).unwrap_or(usize::MAX);
        if n > want {
            return Err(format!("it decodes to more than its {want} bytes"));
        }
        if status != Status::StreamEnd {
            return Err("its zlib stream ends early".to_owned());
        }
        if n != want {
            return Err(format!("it decodes to {n} bytes, not {want}"));
        }
        out.truncate(n);
        Ok(())
    }

    /// Whether `blk` lays out a file of more than one block of it: its first block starts
    /// right after its pointers and decodes to a whole block (or is a hole).
    fn lays_out(&mut self, i: &Inode, blk: u32, out: &mut Vec<u8>) -> bool {
        let count = u64::from(i.size.div_ceil(blk));
        let first = i.offset + 4 * count;
        let Ok(p) = read_at(&mut self.input, i.offset, 4) else {
            return false;
        };
        let Some(end) = self.sb.u32(&p, 0).map(u64::from) else {
            return false;
        };
        if end == first {
            return true;
        }
        if end < first || end - first > 2 * u64::from(blk) {
            return false;
        }
        let Ok(packed) = read_at(&mut self.input, first, end - first) else {
            return false;
        };
        Self::inflate(&mut self.zlib, &packed, out, blk as usize).is_ok()
    }

    /// The block size, from the first files of more than 4 KiB (docs/M10.md §3.1): the size
    /// most of them lay out as.
    fn block_size(&mut self, nodes: &[Node]) -> u32 {
        if self.ext() {
            return 4096;
        }
        let mut votes = [0usize; BLOCK_SIZES.len()];
        let mut out = Vec::new();
        let files = nodes
            .iter()
            .filter(|n| {
                n.inode.mode & S_IFMT == S_IFREG && n.inode.size > 4096 && n.inode.offset > 0
            })
            .take(SIZE_VOTERS);
        for n in files {
            if let Some(k) = BLOCK_SIZES
                .iter()
                .position(|&b| n.inode.size > b && self.lays_out(&n.inode, b, &mut out))
            {
                votes[k] += 1;
            }
        }
        let best = (0..votes.len())
            .max_by_key(|&k| (votes[k], std::cmp::Reverse(k)))
            .filter(|&k| votes[k] > 0)
            .unwrap_or(0);
        BLOCK_SIZES[best]
    }
}

/// One file's or link's bytes, block by block: exactly its size, or an error.
struct FileData<'a> {
    inner: &'a mut Inner,
    inode: Inode,
    /// Its block pointers, read at the first read.
    table: Option<Vec<u32>>,
    next: usize,
    /// Where the next block starts, when it isn't direct.
    at: u64,
    buf: Vec<u8>,
    pos: usize,
    failed: Option<Error>,
}

impl<'a> FileData<'a> {
    fn new(inner: &'a mut Inner, inode: Inode) -> Self {
        Self {
            inner,
            inode,
            table: None,
            next: 0,
            at: 0,
            buf: Vec::new(),
            pos: 0,
            failed: None,
        }
    }

    fn count(&self) -> usize {
        self.inode.size.div_ceil(self.inner.blk) as usize
    }

    fn table(&mut self) -> Result<()> {
        if self.table.is_some() {
            return Ok(());
        }
        if self.inode.offset == 0 {
            return Err(bad(format!(
                "a file of {} bytes has no blocks",
                self.inode.size
            )));
        }
        let count = self.count();
        let want = 4 * count as u64;
        let d = read_at(&mut self.inner.input, self.inode.offset, want)?;
        if (d.len() as u64) < want {
            return Err(bad(
                "the image is cut short: a file's block pointers aren't in it",
            ));
        }
        let sb = &self.inner.sb;
        let t = (0..count).filter_map(|k| sb.u32(&d, 4 * k)).collect();
        self.table = Some(t);
        self.at = self.inode.offset + want;
        Ok(())
    }

    /// The next block into `buf`.
    fn block(&mut self) -> Result<()> {
        self.table()?;
        let k = self.next;
        let blk = self.inner.blk as usize;
        let want = blk.min(self.inode.size as usize - k * blk);
        let raw = self
            .table
            .as_ref()
            .and_then(|t| t.get(k).copied())
            .ok_or_else(|| bad("a file's block pointers are cut short"))?;
        let ext = self.inner.ext();
        let flags = if ext {
            raw & (BLK_UNCOMPRESSED | BLK_DIRECT)
        } else {
            0
        };
        let ptr = u64::from(raw & !flags);
        let stored = flags & BLK_UNCOMPRESSED != 0;
        let (start, len) = if flags & BLK_DIRECT != 0 {
            let start = ptr << 2;
            if stored {
                self.at = start + want as u64;
                (start, want as u64)
            } else {
                let l = read_at(&mut self.inner.input, start, 2)?;
                let n =
                    self.inner.sb.u16(&l).ok_or_else(|| {
                        bad(format!("the image is cut short in block {k} of a file"))
                    })?;
                self.at = start + 2 + u64::from(n);
                (start + 2, u64::from(n))
            }
        } else {
            let start = self.at;
            if ptr < start {
                return Err(bad(format!("block {k} of a file ends before it starts")));
            }
            self.at = ptr;
            (start, ptr - start)
        };
        self.next += 1;
        self.pos = 0;
        if len == 0 {
            // A hole.
            self.buf.clear();
            self.buf.resize(want, 0);
            return Ok(());
        }
        if len > 2 * blk as u64 || (stored && len != want as u64) {
            return Err(bad(format!(
                "block {k} of a file is {len} bytes, for {want} bytes of output"
            )));
        }
        if start.saturating_add(len) > self.inner.len {
            return Err(bad(format!(
                "the image is cut short: block {k} of a file isn't in it"
            )));
        }
        if stored {
            self.buf = read_at(&mut self.inner.input, start, len)?;
            return Ok(());
        }
        let mut packed = std::mem::take(&mut self.inner.packed);
        packed.clear();
        let got = (|| {
            self.inner
                .input
                .seek(SeekFrom::Start(start))
                .map_err(|e| Error::io("seeking in the image", &e))?;
            (&mut self.inner.input)
                .take(len)
                .read_to_end(&mut packed)
                .map_err(|e| Error::io("reading the image", &e))?;
            if self.inner.lzma {
                Inner::unlzma(&packed, &mut self.buf, want)
            } else {
                Inner::inflate(&mut self.inner.zlib, &packed, &mut self.buf, want)
            }
            .map_err(|e| bad(format!("block {k} of a file: {e}")))
        })();
        self.inner.packed = packed;
        got
    }
}

impl Read for FileData<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.failed {
            return Err(e.clone().into_io());
        }
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.buf.len() {
            if self.next >= self.count() {
                return Ok(0);
            }
            if let Err(e) = self.block() {
                self.failed = Some(e.clone());
                return Err(e.into_io());
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// An entry's data.
#[derive(Debug, Clone, Copy)]
enum Data {
    None,
    /// A file's blocks (a link whose target couldn't be read is listed as a file of them).
    Blocks(Inode),
}

fn kib(n: u32) -> String {
    format!("{} KiB", n / 1024)
}

pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(CramfsReader::open(source, cx)?))
}

pub struct CramfsReader {
    source: Source,
    inner: Inner,
    entries: Vec<Entry>,
    data: Vec<Data>,
    properties: Vec<LevelProperty>,
    /// Keeps an image spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl CramfsReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (input, spool) = if source.codecs.is_empty() {
            (source.input()?, None)
        } else {
            // Blocks are read at offsets: spool the decoded stream.
            let mut tmp = Partial::create_temp("beezip-spool.cramfs")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            (Input::file(tmp.reopen()?)?, Some(tmp))
        };
        let len = input.len();
        let mut input = CountingReader::new(input, source.counter.clone());
        let (sb, root) = superblock(&mut input)?;
        if sb.ignored != 0 {
            cx.warn(format!(
                "{}: its superblock sets flags BeeZip doesn't know ({:#x}); they're ignored",
                source.file_name(),
                sb.ignored
            ));
        }
        let nodes = walk(&mut input, len, &sb, root, &source, cx)?;
        let mut inner = Inner {
            input,
            len,
            sb,
            blk: 4096,
            zlib: Decompress::new(true),
            packed: Vec::new(),
            lzma: false,
        };
        match sevenzip_variant(inner.sb.flags) {
            Some((blk, method)) => {
                if method == 3 {
                    return Err(Error::unsupported(
                        "cramfs: its superblock says compression method 3, which isn't defined",
                    ));
                }
                inner.blk = blk;
                inner.lzma = method == 2;
            }
            None => inner.blk = inner.block_size(&nodes),
        }
        let method_name = if inner.lzma { "LZMA" } else { "zlib" };

        let names = source.names;
        let mut entries = Vec::with_capacity(nodes.len());
        let mut data = Vec::with_capacity(nodes.len());
        for n in &nodes {
            let i = n.inode;
            let mut e = Entry::new(
                entries.len(),
                names.decode(&n.path, false, SystemPage::Ansi),
                EntryKind::Other,
            );
            e.raw_path.clone_from(&n.path);
            e.unix_mode = Some(u32::from(i.mode));
            let mut item = Data::None;
            match i.mode & S_IFMT {
                S_IFDIR => e.kind = EntryKind::Dir,
                S_IFREG => {
                    e.kind = EntryKind::File;
                    e.size = Some(u64::from(i.size));
                    if i.size > 0 {
                        e.method = Some(Cow::Borrowed(method_name));
                        item = Data::Blocks(i);
                    }
                }
                S_IFLNK => match link_target(&mut inner, i) {
                    Ok(t) => {
                        e.kind = EntryKind::Symlink {
                            target: names.decode(&t, false, SystemPage::Ansi),
                        };
                    }
                    // A link whose target can't be read: a file of its blocks, which fails as
                    // it's read.
                    Err(_) => {
                        e.kind = EntryKind::File;
                        e.size = Some(u64::from(i.size));
                        item = Data::Blocks(i);
                    }
                },
                _ => {}
            }
            entries.push(e);
            data.push(item);
        }

        let sb = &inner.sb;
        let mut properties = Vec::new();
        let mut prop = |name: &str, value: String| {
            properties.push(LevelProperty {
                level: "cramfs".to_owned(),
                name: name.to_owned(),
                value,
            });
        };
        if !sb.name.is_empty() {
            prop("Name", String::from_utf8_lossy(&sb.name).into_owned());
        }
        if sb.flags & FLAG_V2 != 0 {
            prop("Edition", sb.edition.to_string());
        }
        prop(
            "Byte order",
            if sb.be { "big-endian" } else { "little-endian" }.to_owned(),
        );
        prop("Block size", kib(inner.blk));
        let set: Vec<&str> = [
            (FLAG_SORTED, "sorted folders"),
            (FLAG_HOLES, "holes"),
            (FLAG_EXT_PTRS, "extended block pointers"),
            (FLAG_SHIFTED_ROOT, "shifted root"),
        ]
        .into_iter()
        .filter(|(f, _)| sb.flags & f != 0)
        .map(|(_, n)| n)
        .collect();
        if !set.is_empty() {
            prop("Flags", set.join(", "));
        }
        if sb.base > 0 {
            prop("Boot block", format!("{} bytes", sb.base));
        }
        prop(
            "Checksum",
            if sb.flags & FLAG_V2 != 0 {
                "CRC-32 of the image"
            } else {
                "none (version 1)"
            }
            .to_owned(),
        );
        if sb.flags & FLAG_V2 != 0 {
            prop("Files", sb.files.to_string());
        }
        Ok(Self {
            source,
            inner,
            entries,
            data,
            properties,
            _spool: spool,
        })
    }

    /// Whether the image's CRC matches, when it has one; `Corrupt` when it doesn't or can't be
    /// read whole.
    fn check_crc(&mut self, cx: &mut dyn Ctx) -> Result<bool> {
        let sb = self.inner.sb.clone();
        if sb.flags & FLAG_V2 == 0 {
            return Ok(false);
        }
        let end = u64::from(sb.size);
        if end < sb.base + SUPER_LEN {
            return Err(bad(format!("the superblock says the image is {end} bytes")));
        }
        if end > self.inner.len {
            return Err(bad(format!(
                "the image is cut short: {} of its {end} bytes",
                self.inner.len
            )));
        }
        let input = &mut self.inner.input;
        input
            .seek(SeekFrom::Start(sb.base))
            .map_err(|e| Error::io("seeking in the image", &e))?;
        let mut h = crc32fast::Hasher::new();
        let mut left = end - sb.base;
        let mut buf = vec![0u8; 256 * 1024];
        let mut first = true;
        while left > 0 {
            cx.check()?;
            let n = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            input
                .read_exact(&mut buf[..n])
                .map_err(|e| Error::io("reading the image", &e))?;
            if first {
                // The CRC field counts as zeros.
                buf[32..36].fill(0);
                first = false;
            }
            h.update(&buf[..n]);
            left -= n as u64;
        }
        if h.finalize() != sb.crc {
            return Err(bad("the image's CRC doesn't match: it's damaged"));
        }
        Ok(true)
    }
}

/// A link's target: its data, which holds no NULs.
fn link_target(inner: &mut Inner, i: Inode) -> Result<Vec<u8>> {
    if u64::from(i.size) > MAX_TARGET {
        return Err(bad(format!("a link's target of {} bytes", i.size)));
    }
    let mut t = Vec::new();
    FileData::new(inner, i)
        .read_to_end(&mut t)
        .map_err(|e| crate::io::read_error(&e))?;
    Ok(t)
}

impl ArchiveReader for CramfsReader {
    fn format(&self) -> FormatId {
        FormatId::External(External::Cramfs)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let methods = if self.data.iter().any(|d| matches!(d, Data::Blocks(_))) {
            vec![Cow::Borrowed(if self.inner.lzma { "LZMA" } else { "zlib" })]
        } else {
            Vec::new()
        };
        Ok(ArchiveInfo {
            format: FormatId::External(External::Cramfs),
            codecs: self.source.codecs.clone(),
            methods,
            comment: None,
            encryption: Encryption::None,
            solid: false,
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: Some(ExternalInfo {
                levels: vec!["cramfs".to_owned()],
                properties: self.properties.clone(),
                notes: Vec::new(),
            }),
        })
    }

    /// Folders and links first, in listing order, then the files in data order.
    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut selected: Vec<usize> = (0..self.entries.len())
            .filter(|&id| sel.matches(&self.entries[id]))
            .collect();
        selected.sort_by_key(|&id| match self.data[id] {
            Data::Blocks(i) => i.offset,
            Data::None => 0,
        });
        // Many small files: written on other threads while the blocks decode.
        if let Some(fs) = sink.as_fs_sink() {
            fs.write_behind(self.source.threads);
        }
        self.source.counter.set(0);
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.inner.len));
        meter.entries_total = Some(selected.len() as u64);
        for (done, &id) in selected.iter().enumerate() {
            cx.check()?;
            meter.entries_done = done as u64;
            meter.current = Some(self.entries[id].path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            let entry = self.entries[id].clone();
            let mut data = self.source.guard(match self.data[id] {
                Data::Blocks(i) => {
                    Box::new(FileData::new(&mut self.inner, i)) as Box<dyn Read + '_>
                }
                Data::None => Box::new(io::empty()),
            });
            sink.entry(&entry, &mut data, &mut mcx)?;
        }
        meter.entries_done = selected.len() as u64;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        if id >= self.entries.len() {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        }
        self.source.counter.set(0);
        let data: Box<dyn Read + '_> = match self.data[id] {
            Data::Blocks(i) => Box::new(FileData::new(&mut self.inner, i)),
            Data::None => Box::new(io::empty()),
        };
        Ok(Box::new(self.source.guard(data)))
    }

    /// The image's CRC, then every file decoded (docs/M10.md §4.4).
    fn test(&mut self, cx: &mut dyn Ctx) -> Option<Result<TestReport>> {
        let mut sink = TestSink::default();
        let crc = match self.check_crc(cx) {
            Ok(checked) => checked,
            Err(e) if e.kind == ErrorKind::Corrupt => {
                sink.report.record("", &e);
                true
            }
            Err(e) => return Some(Err(e)),
        };
        let done = match self.extract(&Selection::all(), &mut sink, cx) {
            Ok(()) => Ok(()),
            Err(e) if e.kind == ErrorKind::Corrupt => {
                sink.report.record("", &e);
                Ok(())
            }
            Err(e) => Err(e),
        };
        Some(done.map(|()| {
            let mut report = sink.report;
            if !crc {
                report.note = Some(
                    "This CramFS image is version 1, which stores no checksum, so the test \
                     shows that BeeZip can read every file, not that their contents are intact."
                        .to_owned(),
                );
            }
            report
        }))
    }
}

#[cfg(test)]
mod tests;
