//! The container (docs/M8.md §5.1): the header, the lookup table, the XML's image names, the
//! resources and their chunk tables, solid resources, split sets and the integrity table.
//!
//! Where the layout comes from: Microsoft's "Windows Imaging File Format (WIM)" (2007) for the
//! header, resource headers, the lookup table, chunk tables, the integrity table and split sets.
//! What it doesn't say (solid resources, their header and chunk table, how a blob finds its
//! solid resource, the LZMS header flag) was read from sample files made by wimlib-imagex, DISM
//! and 7-Zip and checked by SHA-1, never from any implementation's code (the M8 spike,
//! `target/m8-spikes/wim/REPORT.md`).
//!
//! Nothing here trusts a size or an offset before checking it against the file: every resource
//! lies inside its part, chunk tables are read a window at a time (one can be a quarter of the
//! file), and what's held in memory whole (the lookup table, the XML, an image's metadata) is
//! capped.

use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use sha1::{Digest, Sha1};

use crate::{Error, ErrorKind, Result, source::Input};

pub type Hash = [u8; 20];
pub const ZERO: Hash = [0; 20];

pub const HEADER_LEN: usize = 208;
pub const MAGIC: &[u8; 8] = b"MSWIM\0\0\0";
/// wimlib's pipable WIMs: a layout of its own, which 7-Zip doesn't read either.
pub const PIPABLE: &[u8; 8] = b"WLPWM\0\0\0";

/// WIMGAPI's and wimlib's WIMs.
pub const VERSION_WIM: u32 = 0x0001_0D00;
/// Solid ESDs (wimlib writes it for its LZMS WIMs too).
pub const VERSION_ESD: u32 = 0x0000_0E00;

const HDR_COMPRESSION: u32 = 0x2;
pub const HDR_RP_FIX: u32 = 0x80;
const HDR_XPRESS: u32 = 0x2_0000;
const HDR_LZX: u32 = 0x4_0000;
/// Not in Microsoft's paper: set on ESDs and LZMS WIMs.
const HDR_LZMS: u32 = 0x8_0000;
/// "XPRESS 2" in later WIMGAPI headers: no writer is known, and wimlib and 7-Zip read it as
/// XPRESS (docs/M11.md §6.1).
const HDR_XPRESS2: u32 = 0x20_0000;
/// The compression flags' byte: one method's bit, or none.
const HDR_METHODS: u32 = 0x00FF_0000;

const RES_FREE: u8 = 0x1;
pub const RES_METADATA: u8 = 0x2;
const RES_COMPRESSED: u8 = 0x4;
// 0x8, a resource spanning the parts of a split set, is ignored, as wimlib and 7-Zip ignore it.
/// Not in Microsoft's paper: a solid resource, or a blob inside one.
const RES_SOLID: u8 = 0x10;
/// A solid resource's lookup entry gives this as its original size; its real one is in the
/// resource's own header.
const SOLID_MARK: u64 = 0x1_0000_0000;

/// A lookup table entry's bytes.
const LOOKUP_ENTRY: usize = 50;
/// A solid resource's header: its size, chunk size and method.
const SOLID_HEADER: u64 = 16;

/// The largest chunk decoded: LZMS's own limit, 1 GiB (DISM's and wimlib's solid chunks are
/// 64 MiB, and wimlib writes up to 1 GiB on request); `decoder_memory` bounds what's in flight.
/// Larger ones that really hold more are `UnsupportedOperation`.
pub const MAX_CHUNK: u64 = 1 << 30;
/// The largest LZX chunk: the decoder's window of 2²¹ bytes.
const MAX_LZX_CHUNK: u64 = 2 << 20;
/// The lookup table, held whole.
pub const MAX_LOOKUP: u64 = 256 << 20;
/// The XML, held whole; past it, it's skipped with a warning.
pub const MAX_XML: u64 = 16 << 20;
/// The integrity table, held whole.
const MAX_INTEGRITY: u64 = 256 << 20;
/// An uncompressed resource is read in pieces of this.
const RAW_PIECE: u64 = 1 << 20;
/// Chunk table entries read at a time.
const TABLE_WINDOW: u64 = 16_384;
/// Files looked at for a split set's part that isn't where its name says.
const MAX_SCAN: usize = 10_000;
/// A split set's parts looked for by name (`name2.swm`…); past them, only by GUID.
const MAX_BY_NAME: u16 = 256;

pub fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("wim: {message}"))
}

pub fn unsupported(message: impl std::fmt::Display) -> Error {
    Error::unsupported(format!("wim: {message}"))
}

pub fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

pub fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

pub fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

pub fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_err(e: &io::Error) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        bad("the file ends early")
    } else {
        crate::io::read_error(e)
    }
}

/// How a resource's chunks are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    None,
    Xpress,
    Lzx,
    Lzms,
}

impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "Store",
            Self::Xpress => "XPRESS",
            Self::Lzx => "LZX",
            Self::Lzms => "LZMS",
        }
    }
}

/// A resource header: where it is, and how large it is stored and decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Res {
    pub size: u64,
    pub flags: u8,
    pub offset: u64,
    pub original: u64,
}

impl Res {
    fn read(b: &[u8], at: usize) -> Self {
        let sf = le64(b, at);
        Self {
            size: sf & ((1 << 56) - 1),
            flags: (sf >> 56) as u8,
            offset: le64(b, at + 8),
            original: le64(b, at + 16),
        }
    }

    fn compressed(&self) -> bool {
        self.flags & RES_COMPRESSED != 0
    }
}

/// The 208-byte header.
#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub flags: u32,
    pub chunk_size: u32,
    pub guid: [u8; 16],
    pub part: u16,
    pub parts: u16,
    pub images: u32,
    pub lookup: Res,
    pub xml: Res,
    pub boot_index: u32,
    pub integrity: Res,
}

impl Header {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN {
            return Err(bad("the file is shorter than a WIM header"));
        }
        if b.starts_with(PIPABLE) {
            return Err(unsupported(
                "it's a pipable WIM, wimlib's own layout, which BeeZip doesn't read",
            ));
        }
        if !b.starts_with(MAGIC) {
            return Err(bad("it doesn't start as a WIM does"));
        }
        if le32(b, 8) != HEADER_LEN as u32 {
            return Err(bad(format!("a header of {} bytes", le32(b, 8))));
        }
        let h = Self {
            version: le32(b, 12),
            flags: le32(b, 16),
            chunk_size: le32(b, 20),
            guid: b[24..40].try_into().unwrap_or_default(),
            part: le16(b, 40),
            parts: le16(b, 42),
            images: le32(b, 44),
            lookup: Res::read(b, 48),
            xml: Res::read(b, 72),
            boot_index: le32(b, 120),
            integrity: Res::read(b, 124),
        };
        // 1.13 from WIMGAPI, DISM and wimlib; 0.14 for ESDs. No older sample was found.
        if h.version != VERSION_WIM && h.version != VERSION_ESD {
            return Err(unsupported(format!(
                "WIM version {}.{}, which BeeZip doesn't read",
                h.version >> 16,
                (h.version >> 8) & 0xFF
            )));
        }
        if h.part == 0 || h.part > h.parts {
            return Err(bad(format!("it says it's part {} of {}", h.part, h.parts)));
        }
        Ok(h)
    }

    /// The method its chunked resources use.
    pub fn method(&self) -> Result<Method> {
        if self.flags & HDR_COMPRESSION == 0 {
            return Ok(Method::None);
        }
        match self.flags & HDR_METHODS {
            HDR_XPRESS | HDR_XPRESS2 => Ok(Method::Xpress),
            HDR_LZX => Ok(Method::Lzx),
            HDR_LZMS => Ok(Method::Lzms),
            0 => Err(bad("it's compressed, and says with nothing")),
            f => Err(unsupported(format!("compression flags {f:#x}"))),
        }
    }

    /// `1.13`, `0.14`.
    pub fn version_name(&self) -> String {
        format!("{}.{}", self.version >> 16, (self.version >> 8) & 0xFF)
    }
}

/// Positional reads, from any thread.
pub trait ReadAt: Send + Sync {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()>;
}

/// A file read at offsets, by several threads at once.
pub struct FileAt(pub File);

impl ReadAt for FileAt {
    #[cfg(windows)]
    fn read_at(&self, mut off: u64, mut buf: &mut [u8]) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            let n = self.0.seek_read(buf, off)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            off += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    }

    #[cfg(unix)]
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(&self.0, buf, off)
    }
}

/// An input read one thread at a time: a numbered volume set, or a file seen from an offset.
pub struct Locked(pub Mutex<Input>);

impl ReadAt for Locked {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut input = self
            .0
            .lock()
            .map_err(|_| io::Error::other("a reader thread failed"))?;
        input.seek(SeekFrom::Start(off))?;
        input.read_exact(buf)
    }
}

/// One file of a split set, or the whole WIM.
pub struct Part {
    pub input: Arc<dyn ReadAt>,
    pub header: Header,
    pub len: u64,
    pub path: Option<PathBuf>,
}

/// A solid resource: a header (its size, chunk size and method), its chunks' sizes, the chunks.
#[derive(Debug, Clone)]
pub struct Solid {
    pub part: usize,
    pub res: Res,
    /// Its data's size, decoded.
    pub size: u64,
    pub chunk: u64,
    pub method: Method,
    /// Where its data starts among all the solid resources', laid end to end in table order.
    pub base: u64,
}

impl Solid {
    pub fn chunks(&self) -> u64 {
        self.size.div_ceil(self.chunk)
    }

    /// Where its chunks start in its part.
    fn data(&self) -> u64 {
        self.res.offset + SOLID_HEADER + 4 * self.chunks()
    }

    fn data_len(&self) -> u64 {
        self.res.size - SOLID_HEADER - 4 * self.chunks()
    }
}

/// Where a blob is.
#[derive(Debug, Clone, Copy)]
pub enum Loc {
    /// A resource of its own, chunked when compressed.
    Res { part: usize, res: Res },
    /// `size` bytes at `offset` in the solid resources' data, laid end to end in table order.
    Solid { offset: u64, size: u64 },
}

/// A blob of the lookup table: a file's stream, or a reparse point's data.
#[derive(Debug, Clone, Copy)]
pub struct Blob {
    pub loc: Loc,
    pub size: u64,
}

/// An image: its metadata resource, in the lookup table's order.
#[derive(Debug, Clone)]
pub struct ImageRef {
    /// From 1.
    pub index: usize,
    pub part: usize,
    pub meta: Res,
    pub hash: Hash,
    pub name: Option<String>,
}

/// One chunk to read and decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub part: usize,
    pub offset: u64,
    pub packed: u64,
    pub size: u64,
    pub method: Method,
    /// The resource's chunk size: LZX's window.
    pub chunk: u64,
}

/// The WIM, or a split set's parts, opened.
pub struct Container {
    /// By part number, from 1; `None` where a part isn't there.
    pub parts: Vec<Option<Part>>,
    /// Part 1's.
    pub header: Header,
    pub method: Method,
    /// The chunk size of the chunked resources.
    pub chunk: u64,
    pub blobs: HashMap<Hash, Blob>,
    pub solids: Vec<Solid>,
    pub images: Vec<ImageRef>,
    /// What opening found to warn about.
    pub warnings: Vec<String>,
}

/// The paths of the other parts of a split set: `name.swm`, `name2.swm`, `name3.swm`…
fn part_path(first: &Path, k: u16) -> PathBuf {
    let stem = first
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = first
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    if k == 1 {
        first.to_path_buf()
    } else {
        first.with_file_name(format!("{stem}{k}{ext}"))
    }
}

/// Part 1's path for part `part`, `name2.swm` → `name.swm`.
fn first_part(path: &Path, part: u16) -> PathBuf {
    if part == 1 {
        return path.to_path_buf();
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = stem.strip_suffix(&part.to_string()).unwrap_or(&stem);
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    path.with_file_name(format!("{base}{ext}"))
}

pub fn header_of(input: &dyn ReadAt) -> Result<Header> {
    let mut h = [0u8; HEADER_LEN];
    input.read_at(0, &mut h).map_err(|e| read_err(&e))?;
    Header::parse(&h)
}

/// A part of a split set, if `path` is it: the same set (GUID and count), part `k`.
fn open_part(path: &Path, want: &Header, k: u16) -> Option<Part> {
    let f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let input: Arc<dyn ReadAt> = Arc::new(FileAt(f));
    let header = header_of(&*input).ok()?;
    (header.guid == want.guid && header.parts == want.parts && header.part == k).then(|| Part {
        input,
        header,
        len,
        path: Some(path.to_path_buf()),
    })
}

impl Container {
    /// Opens the WIM `first` holds (a whole WIM, or any part of a split set at `path`), and with
    /// a split set, finds its other parts beside it: by their names (`name2.swm`), else by
    /// their header's GUID among the files of the same extension there.
    pub fn open(first: Part, cx_warn: &mut dyn FnMut(String)) -> Result<Self> {
        let given = first.header.part;
        let parts_n = first.header.parts;
        let mut parts: Vec<Option<Part>> = (0..parts_n).map(|_| None).collect();
        let want = first.header.clone();
        let path = first.path.clone();
        parts[usize::from(given) - 1] = Some(first);
        if parts_n > 1 {
            let Some(path) = path else {
                return Err(unsupported(
                    "a part of a split set read through a codec or a volume set",
                ));
            };
            let base = first_part(&path, given);
            let mut missing = Vec::new();
            // By name, as far as names are tried; past that, by GUID only.
            for k in (1..=parts_n).filter(|&k| k != given) {
                match (k <= MAX_BY_NAME)
                    .then(|| open_part(&part_path(&base, k), &want, k))
                    .flatten()
                {
                    Some(p) => parts[usize::from(k) - 1] = Some(p),
                    None => missing.push(k),
                }
            }
            if !missing.is_empty() {
                scan_for_parts(&path, &want, &mut parts, &mut missing);
            }
            if parts[0].is_none() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "wim: this is part {given} of a split set of {parts_n}, and its first \
                         part, {}, isn't beside it",
                        base.display()
                    ),
                ));
            }
            match missing[..] {
                [] => {}
                [k] => cx_warn(format!(
                    "part {k} of the split set, {}, isn't beside it; the files in it can't be \
                     read",
                    part_path(&base, k).display()
                )),
                [k, ..] => cx_warn(format!(
                    "{} of the split set's {parts_n} parts aren't beside it, from part {k} ({}); \
                     the files in them can't be read",
                    missing.len(),
                    part_path(&base, k).display()
                )),
            }
        }
        let header = parts[0]
            .as_ref()
            .map(|p| p.header.clone())
            .ok_or_else(|| bad("no first part"))?;
        let method = header.method()?;
        let chunk = match (method, header.chunk_size) {
            (Method::None, _) => 0,
            (_, 0) => 32_768,
            (_, c) if !c.is_power_of_two() || c < 4096 => {
                return Err(bad(format!("a chunk size of {c}")));
            }
            (_, c) => u64::from(c),
        };
        if method == Method::Lzx && chunk > MAX_LZX_CHUNK {
            return Err(unsupported(format!(
                "LZX in chunks of {chunk} bytes (BeeZip reads up to 2 MiB)"
            )));
        }
        let mut c = Self {
            parts,
            header,
            method,
            chunk,
            blobs: HashMap::new(),
            solids: Vec::new(),
            images: Vec::new(),
            warnings: Vec::new(),
        };
        for p in 0..c.parts.len() {
            if c.parts[p].is_some() {
                c.load_lookup(p)?;
            }
        }
        // Laid end to end, in table order.
        let mut base = 0u64;
        for s in &mut c.solids {
            s.base = base;
            base = base
                .checked_add(s.size)
                .ok_or_else(|| bad("solid resources of more than 2⁶⁴ bytes"))?;
        }
        if c.images.len() != c.header.images as usize {
            c.warnings.push(format!(
                "the header says {} images, and the lookup table has {}",
                c.header.images,
                c.images.len()
            ));
        }
        Ok(c)
    }

    pub fn part(&self, p: usize) -> Result<&Part> {
        match self.parts.get(p) {
            Some(Some(part)) => Ok(part),
            _ => Err(Error::new(
                ErrorKind::NotFound,
                format!("wim: part {} of the split set isn't there", p + 1),
            )),
        }
    }

    pub fn read_at(&self, part: usize, off: u64, buf: &mut [u8]) -> Result<()> {
        self.part(part)?
            .input
            .read_at(off, buf)
            .map_err(|e| read_err(&e))
    }

    /// Checks a resource lies inside its part.
    fn check_res(&self, part: usize, r: &Res, what: &str) -> Result<()> {
        let len = self.part(part)?.len;
        if r.offset.checked_add(r.size).is_none_or(|end| end > len) {
            return Err(bad(format!(
                "{what} at {} of {} bytes runs past the end of the file ({len} bytes)",
                r.offset, r.size
            )));
        }
        Ok(())
    }

    /// Reads part `p`'s lookup table into the blobs; part 1's metadata entries are the images.
    fn load_lookup(&mut self, p: usize) -> Result<()> {
        let lk = self.part(p)?.header.lookup;
        if lk.size == 0 {
            return Ok(());
        }
        // Stored, as WIMGAPI, DISM and wimlib write it (Microsoft's ESDs too); a compressed one,
        // which 7-Zip reads, decodes within MAX_LOOKUP (docs/M11.md §6.1).
        let table = self.read_res(p, &lk, MAX_LOOKUP, "the lookup table")?;
        if table.len() % LOOKUP_ENTRY != 0 {
            self.warnings.push(format!(
                "the lookup table's {} bytes aren't whole entries",
                table.len()
            ));
        }
        for e in table.as_chunks::<LOOKUP_ENTRY>().0 {
            let r = Res::read(e, 0);
            let hash: Hash = e[30..50].try_into().unwrap_or(ZERO);
            if r.flags & RES_FREE != 0 {
                continue;
            }
            if r.flags & RES_SOLID != 0 && r.original == SOLID_MARK {
                self.add_solid(p, r)?;
                continue;
            }
            if r.flags & RES_METADATA != 0 {
                if p == 0 && r.flags & RES_SOLID == 0 {
                    let index = self.images.len() + 1;
                    self.images.push(ImageRef {
                        index,
                        part: p,
                        meta: r,
                        hash,
                        name: None,
                    });
                }
                continue;
            }
            if hash == ZERO {
                continue;
            }
            let blob = if r.flags & RES_SOLID != 0 {
                Blob {
                    loc: Loc::Solid {
                        offset: r.offset,
                        size: r.size,
                    },
                    size: r.size,
                }
            } else {
                Blob {
                    loc: Loc::Res { part: p, res: r },
                    size: r.original,
                }
            };
            self.blobs.entry(hash).or_insert(blob);
        }
        Ok(())
    }

    /// A solid resource's header, checked.
    fn add_solid(&mut self, p: usize, r: Res) -> Result<()> {
        self.check_res(p, &r, "a solid resource")?;
        if r.size < SOLID_HEADER {
            return Err(bad("a solid resource too short for its header"));
        }
        let mut sh = [0u8; SOLID_HEADER as usize];
        self.read_at(p, r.offset, &mut sh)?;
        let size = le64(&sh, 0);
        let chunk = u64::from(le32(&sh, 8));
        let method = match le32(&sh, 12) {
            0 => Method::None,
            1 => Method::Xpress,
            2 => Method::Lzx,
            3 => Method::Lzms,
            m => {
                return Err(unsupported(format!(
                    "a solid resource of method {m}, which BeeZip doesn't know"
                )));
            }
        };
        if !chunk.is_power_of_two() || chunk < 4096 {
            return Err(bad(format!("a solid resource's chunk size of {chunk}")));
        }
        if chunk > MAX_CHUNK && size > MAX_CHUNK {
            return Err(unsupported(format!(
                "solid chunks of {chunk} bytes (WIM allows up to 1 GiB)"
            )));
        }
        if method == Method::Lzx && chunk > MAX_LZX_CHUNK {
            return Err(unsupported(format!(
                "LZX in solid chunks of {chunk} bytes (BeeZip reads up to 2 MiB)"
            )));
        }
        let n = size.div_ceil(chunk);
        if n.checked_mul(4)
            .and_then(|t| t.checked_add(SOLID_HEADER))
            .is_none_or(|t| t > r.size)
        {
            return Err(bad(format!(
                "a solid resource of {size} bytes in {n} chunks whose table doesn't fit in its {} \
                 bytes",
                r.size
            )));
        }
        // Every chunk takes at least a byte.
        if r.size - SOLID_HEADER - 4 * n < n {
            return Err(bad(format!(
                "a solid resource of {n} chunks in {} bytes",
                r.size
            )));
        }
        self.solids.push(Solid {
            part: p,
            res: r,
            size,
            chunk,
            method,
            base: 0,
        });
        Ok(())
    }

    /// Whether anything is compressed with LZMS.
    pub fn uses_lzms(&self) -> bool {
        self.method == Method::Lzms || self.solids.iter().any(|s| s.method == Method::Lzms)
    }

    /// The methods used, chunked resources' first.
    pub fn methods(&self) -> Vec<Method> {
        let mut out = Vec::new();
        let any_chunked = self.images.iter().any(|i| i.meta.compressed())
            || self
                .blobs
                .values()
                .any(|b| matches!(b.loc, Loc::Res { res, .. } if res.compressed()));
        if self.method != Method::None && any_chunked {
            out.push(self.method);
        }
        for s in &self.solids {
            if !out.contains(&s.method) {
                out.push(s.method);
            }
        }
        if out.is_empty() {
            out.push(Method::None);
        }
        out
    }

    /// The solid resource holding `offset`.
    pub fn solid_at(&self, offset: u64) -> Option<usize> {
        let i = self.solids.partition_point(|s| s.base <= offset);
        let s = i.checked_sub(1)?;
        (offset < self.solids[s].base + self.solids[s].size).then_some(s)
    }

    /// The bytes a blob takes in the file: its resource's, or its share of its solid resource's.
    pub fn packed(&self, blob: &Blob) -> u64 {
        match blob.loc {
            Loc::Res { res, .. } => res.size,
            Loc::Solid { offset, size } => self.solid_at(offset).map_or(0, |s| {
                let sol = &self.solids[s];
                let share = (u128::from(size) * u128::from(sol.res.size))
                    .div_ceil(u128::from(sol.size.max(1)));
                u64::try_from(share).unwrap_or(u64::MAX)
            }),
        }
    }

    pub fn method_of(&self, blob: &Blob) -> Method {
        match blob.loc {
            Loc::Res { res, .. } if res.compressed() => self.method,
            Loc::Res { .. } => Method::None,
            Loc::Solid { offset, .. } => self
                .solid_at(offset)
                .map_or(Method::None, |s| self.solids[s].method),
        }
    }

    /// A chunked (or stored) resource's chunks, in order.
    pub fn chunks(&self, part: usize, r: &Res) -> Result<ChunkIter> {
        // The spanned flag is ignored, as wimlib and 7-Zip ignore it: a resource that really ran
        // past its part's end fails `check_res`.
        self.check_res(part, r, "a resource")?;
        let mut it = ChunkIter {
            part,
            table: r.offset,
            width: 4,
            data: r.offset,
            data_len: r.size,
            original: r.original,
            chunk: self.chunk,
            method: self.method,
            n: 0,
            next: 0,
            window: Vec::new(),
            window_first: 0,
            raw: false,
        };
        if !r.compressed() || self.method == Method::None {
            if r.compressed() {
                return Err(bad("a compressed resource in a WIM without compression"));
            }
            if r.size != r.original {
                return Err(bad(format!(
                    "a stored resource of {} bytes that claims {}",
                    r.size, r.original
                )));
            }
            it.raw = true;
            it.n = r.original.div_ceil(RAW_PIECE);
            return Ok(it);
        }
        if self.chunk > MAX_CHUNK && r.original > MAX_CHUNK {
            return Err(unsupported(format!(
                "chunks of {} bytes (WIM allows up to 1 GiB)",
                self.chunk
            )));
        }
        it.n = r.original.div_ceil(self.chunk);
        it.width = if r.original > u64::from(u32::MAX) {
            8
        } else {
            4
        };
        let table = it.n.saturating_sub(1).checked_mul(it.width);
        // Every chunk takes at least a byte.
        let Some(table) = table.filter(|&t| t.checked_add(it.n).is_some_and(|x| x <= r.size))
        else {
            return Err(bad(format!(
                "a resource of {} bytes in {} chunks whose table doesn't fit in it",
                r.size, it.n
            )));
        };
        it.data = r.offset + table;
        it.data_len = r.size - table;
        Ok(it)
    }

    /// A whole resource (the lookup table, the XML) into memory, at most `max` bytes, one chunk
    /// at a time on this thread.
    pub fn read_res(&self, part: usize, r: &Res, max: u64, what: &str) -> Result<Vec<u8>> {
        if r.original > max {
            return Err(Error::limit(format!(
                "wim: {what} is {} bytes, more than BeeZip reads ({max})",
                r.original
            )));
        }
        let mut dec = super::pipe::Decoders::default();
        // Grown as it decodes: the claimed size is held to the limit, not trusted.
        let mut out = Vec::with_capacity(usize::try_from(r.original.min(1 << 20)).unwrap_or(0));
        let mut chunks = self.chunks(part, r)?;
        while let Some(job) = chunks.next(self) {
            out.extend_from_slice(&dec.decode(self, &job?)?);
        }
        if out.len() as u64 != r.original {
            return Err(bad(format!(
                "{what} decoded to {} bytes, not {}",
                out.len(),
                r.original
            )));
        }
        Ok(out)
    }

    /// The images' names from the XML, which is read and then dropped; an encrypted ESD is
    /// refused. A damaged or too large XML is a warning.
    pub fn read_xml(&mut self) -> Result<()> {
        let xml = self.header.xml;
        if xml.size == 0 {
            return Ok(());
        }
        if xml.original > MAX_XML || xml.compressed() {
            self.warnings.push(format!(
                "the XML is {} bytes{}, which BeeZip doesn't read; the images' names aren't \
                 shown",
                xml.original,
                if xml.compressed() { ", compressed" } else { "" }
            ));
            return Ok(());
        }
        let bytes = match self.read_res(0, &xml, MAX_XML, "the XML") {
            Ok(b) => b,
            Err(e) if e.kind == ErrorKind::Corrupt => {
                self.warnings.push(format!(
                    "the XML can't be read ({}); the images' names aren't shown",
                    e.message.trim_start_matches("wim: ")
                ));
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let s = super::super::reparse::utf16(&bytes);
        let s = s.strip_prefix('\u{FEFF}').unwrap_or(&s);
        // No sample was found; Windows Update's encrypted ESDs are said to carry these.
        if s.contains("<ESD>") && s.contains("<KEY>") {
            return Err(unsupported(
                "it's an encrypted ESD, which BeeZip doesn't read",
            ));
        }
        for img in &mut self.images {
            img.name = xml_image_name(s, img.index);
        }
        Ok(())
    }

    /// Checks each part's integrity table, if it has one: the SHA-1 of every 10 MiB (or as the
    /// table says) from the header's end to the lookup table's end. What's wrong, if anything.
    pub fn check_integrity(&self, threads: usize, cx: &mut dyn crate::Ctx) -> Result<Vec<Error>> {
        let mut found = Vec::new();
        for (p, part) in self.parts.iter().enumerate() {
            let Some(part) = part else { continue };
            let it = part.header.integrity;
            if it.size == 0 {
                continue;
            }
            match self.integrity_table(p, part, &it) {
                Ok((chunk, end, hashes)) => {
                    found.extend(self.check_chunks(p, chunk, end, &hashes, threads, cx)?);
                }
                Err(e) if e.kind == ErrorKind::Corrupt => found.push(e),
                Err(e) => return Err(e),
            }
        }
        Ok(found)
    }

    /// A part's integrity table: its chunk size, the end of what it covers, its hashes.
    fn integrity_table(&self, p: usize, part: &Part, it: &Res) -> Result<(u64, u64, Vec<Hash>)> {
        if it.compressed() || it.size != it.original {
            return Err(bad("a compressed integrity table"));
        }
        let t = self.read_res(p, it, MAX_INTEGRITY, "the integrity table")?;
        let (size, n, chunk) = (
            u64::from(le32(&t, 0)),
            u64::from(le32(&t, 4)),
            u64::from(le32(&t, 8)),
        );
        let lk = part.header.lookup;
        let end = lk.offset.saturating_add(lk.size);
        let covered = end.saturating_sub(HEADER_LEN as u64);
        if size != t.len() as u64
            || 12 + 20 * n != size
            || chunk == 0
            || covered.div_ceil(chunk) != n
            || end > part.len
        {
            return Err(bad(format!(
                "part {}'s integrity table doesn't describe the file",
                p + 1
            )));
        }
        let hashes = t[12..].as_chunks::<20>().0.to_vec();
        Ok((chunk, end, hashes))
    }

    fn check_chunks(
        &self,
        p: usize,
        chunk: u64,
        end: u64,
        hashes: &[Hash],
        threads: usize,
        cx: &mut dyn crate::Ctx,
    ) -> Result<Vec<Error>> {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let failed: Mutex<Vec<(usize, Error)>> = Mutex::new(Vec::new());
        let stop = std::sync::atomic::AtomicBool::new(false);
        let one = |i: usize| -> Result<()> {
            let at = HEADER_LEN as u64 + i as u64 * chunk;
            let len = chunk.min(end - at);
            let mut buf = vec![0u8; usize::try_from(len).unwrap_or(0)];
            self.read_at(p, at, &mut buf)?;
            if Sha1::digest(&buf).as_slice() != hashes[i] {
                return Err(bad(format!(
                    "part {}'s bytes {at} to {} don't match the integrity table",
                    p + 1,
                    at + len
                )));
            }
            Ok(())
        };
        let work = || {
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= hashes.len() {
                    return;
                }
                if let Err(e) = one(i)
                    && let Ok(mut f) = failed.lock()
                {
                    f.push((i, e));
                }
            }
        };
        std::thread::scope(|s| {
            for _ in 1..threads.clamp(1, 64).min(hashes.len()) {
                s.spawn(work);
            }
            // This thread checks too, and for cancellation between chunks.
            loop {
                if cx.check().is_err() {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= hashes.len() {
                    break;
                }
                if let Err(e) = one(i)
                    && let Ok(mut f) = failed.lock()
                {
                    f.push((i, e));
                }
            }
        });
        cx.check()?;
        let mut failed = failed.into_inner().unwrap_or_default();
        failed.sort_by_key(|(i, _)| *i);
        let mut out = Vec::new();
        for (_, e) in failed {
            // A part that can't be read stops the test; a mismatch is reported.
            if e.kind != ErrorKind::Corrupt {
                return Err(e);
            }
            out.push(e);
        }
        Ok(out)
    }
}

/// The other parts, where they aren't where their names say: files of the same extension beside
/// `path` whose header names this set and a part still missing.
fn scan_for_parts(path: &Path, want: &Header, parts: &mut [Option<Part>], missing: &mut Vec<u16>) {
    let dir = path.parent().unwrap_or(Path::new("."));
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let ext = path.extension().map(|e| e.to_ascii_lowercase());
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for e in read.flatten().take(MAX_SCAN) {
        if missing.is_empty() {
            break;
        }
        let p = e.path();
        if p.extension().map(|e| e.to_ascii_lowercase()) != ext || !p.is_file() {
            continue;
        }
        let Some(header) = File::open(&p).ok().and_then(|f| header_of(&FileAt(f)).ok()) else {
            continue;
        };
        let k = header.part;
        if header.guid == want.guid
            && header.parts == want.parts
            && missing.contains(&k)
            && let Some(part) = open_part(&p, want, k)
        {
            parts[usize::from(k) - 1] = Some(part);
            missing.retain(|&m| m != k);
        }
    }
}

/// `<IMAGE INDEX="n">…<NAME>x</NAME>`: the image's own name, not a deeper element's.
fn xml_image_name(xml: &str, index: usize) -> Option<String> {
    let tag = format!("<IMAGE INDEX=\"{index}\">");
    let at = xml.find(&tag)? + tag.len();
    let end = xml[at..].find("</IMAGE>").map_or(xml.len(), |e| at + e);
    let body = &xml[at..end];
    let s = body.find("<NAME>")? + "<NAME>".len();
    let e = body[s..].find("</NAME>")? + s;
    let name = unescape(&body[s..e]);
    (!name.is_empty()).then_some(name)
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// A chunked resource's chunks, read from its chunk table a window at a time.
pub struct ChunkIter {
    part: usize,
    /// Where the chunk table starts, its entries' width, and where the chunks start.
    table: u64,
    width: u64,
    data: u64,
    data_len: u64,
    original: u64,
    chunk: u64,
    method: Method,
    n: u64,
    next: u64,
    /// Chunk offsets read, from entry `window_first`.
    window: Vec<u64>,
    window_first: u64,
    /// An uncompressed resource, read in pieces.
    raw: bool,
}

impl ChunkIter {
    /// Chunk `i`'s offset among the chunks.
    fn offset_of(&mut self, c: &Container, i: u64) -> Result<u64> {
        if i == 0 {
            return Ok(0);
        }
        if i >= self.n {
            return Ok(self.data_len);
        }
        let k = i - 1;
        if k < self.window_first || k >= self.window_first + self.window.len() as u64 {
            let count = TABLE_WINDOW.min(self.n - 1 - k);
            let mut buf = vec![0u8; usize::try_from(count * self.width).unwrap_or(0)];
            c.read_at(self.part, self.table + k * self.width, &mut buf)?;
            self.window = buf
                .chunks_exact(self.width as usize)
                .map(|e| {
                    if self.width == 4 {
                        u64::from(le32(e, 0))
                    } else {
                        le64(e, 0)
                    }
                })
                .collect();
            self.window_first = k;
        }
        Ok(self.window[(k - self.window_first) as usize])
    }

    /// The next chunk; after an error, none.
    pub fn next(&mut self, c: &Container) -> Option<Result<Chunk>> {
        if self.next >= self.n {
            return None;
        }
        let i = self.next;
        self.next += 1;
        if self.raw {
            let at = i * RAW_PIECE;
            let len = RAW_PIECE.min(self.original - at);
            return Some(Ok(Chunk {
                part: self.part,
                offset: self.data + at,
                packed: len,
                size: len,
                method: Method::None,
                chunk: RAW_PIECE,
            }));
        }
        let r = (|| {
            let a = self.offset_of(c, i)?;
            let b = self.offset_of(c, i + 1)?;
            let size = self.chunk.min(self.original - i * self.chunk);
            if b <= a || b > self.data_len {
                return Err(bad(format!(
                    "chunk {i} of a resource lies at {a}..{b} of its {} bytes",
                    self.data_len
                )));
            }
            let packed = b - a;
            if packed > size {
                return Err(bad(format!(
                    "chunk {i} of a resource is {packed} bytes packed, for {size}"
                )));
            }
            Ok(Chunk {
                part: self.part,
                offset: self.data + a,
                packed,
                size,
                method: self.method,
                chunk: self.chunk,
            })
        })();
        if r.is_err() {
            self.next = self.n;
        }
        Some(r)
    }

    /// The largest chunk it decodes.
    pub fn max_chunk(&self) -> u64 {
        if self.raw {
            RAW_PIECE.min(self.original)
        } else {
            self.chunk.min(self.original)
        }
    }
}

/// Where a solid resource's chunks are: their sizes summed from its table, read a window at a
/// time, as far as asked. The runs of one resource are asked for in order, so the table is read
/// once.
pub struct SolidCursor {
    s: usize,
    /// The next chunk whose size isn't summed yet, and where it starts among the chunks.
    next: u64,
    at: u64,
    window: Vec<u32>,
    window_first: u64,
    /// The first chunk that can't be found, and why.
    failed: Option<(u64, Error)>,
}

impl SolidCursor {
    pub fn new(s: usize) -> Self {
        Self {
            s,
            next: 0,
            at: 0,
            window: Vec::new(),
            window_first: 0,
            failed: None,
        }
    }

    fn size_of(&mut self, c: &Container, sol: &Solid, i: u64) -> Result<u64> {
        if i < self.window_first || i >= self.window_first + self.window.len() as u64 {
            let count = TABLE_WINDOW.min(sol.chunks() - i);
            let mut buf = vec![0u8; usize::try_from(count * 4).unwrap_or(0)];
            c.read_at(sol.part, sol.res.offset + SOLID_HEADER + i * 4, &mut buf)?;
            self.window = buf
                .as_chunks::<4>()
                .0
                .iter()
                .map(|e| u32::from_le_bytes(*e))
                .collect();
            self.window_first = i;
        }
        Ok(u64::from(self.window[(i - self.window_first) as usize]))
    }

    /// Chunk `i` of the resource.
    pub fn chunk(&mut self, c: &Container, i: u64) -> Result<Chunk> {
        let sol = c
            .solids
            .get(self.s)
            .ok_or_else(|| bad("a solid resource that isn't there"))?
            .clone();
        if let Some((f, e)) = &self.failed
            && i >= *f
        {
            return Err(e.clone());
        }
        if i < self.next {
            // Asked out of order: from the start again.
            self.next = 0;
            self.at = 0;
        }
        while self.next <= i {
            let k = self.next;
            let r = (|| {
                let packed = self.size_of(c, &sol, k)?;
                let size = sol.chunk.min(sol.size - k * sol.chunk);
                if packed == 0 || packed > size || self.at + packed > sol.data_len() {
                    return Err(bad(format!(
                        "chunk {k} of a solid resource is {packed} bytes packed, for {size}, at \
                         {} of its {} bytes",
                        self.at,
                        sol.data_len()
                    )));
                }
                Ok(Chunk {
                    part: sol.part,
                    offset: sol.data() + self.at,
                    packed,
                    size,
                    method: sol.method,
                    chunk: sol.chunk,
                })
            })();
            match r {
                Ok(ch) => {
                    self.at += ch.packed;
                    self.next += 1;
                    if k == i {
                        return Ok(ch);
                    }
                }
                Err(e) => {
                    self.failed = Some((k, e.clone()));
                    return Err(e);
                }
            }
        }
        Err(bad("a solid chunk that isn't there"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_set_names() {
        let p = Path::new("dir/install.swm");
        assert_eq!(part_path(p, 1), Path::new("dir/install.swm"));
        assert_eq!(part_path(p, 3), Path::new("dir/install3.swm"));
        assert_eq!(
            first_part(Path::new("dir/install12.swm"), 12),
            Path::new("dir/install.swm")
        );
        assert_eq!(
            first_part(Path::new("dir/a2b.swm"), 2),
            Path::new("dir/a2b.swm")
        );
    }

    #[test]
    fn image_names_from_the_xml() {
        let xml = "<WIM><IMAGE INDEX=\"1\"><WINDOWS><NAME>no</NAME></WINDOWS></IMAGE>\
                   <IMAGE INDEX=\"2\"><NAME>Windows &amp; more</NAME></IMAGE></WIM>";
        // Image 1's NAME is deeper than its own: still found, as the spike did.
        assert_eq!(xml_image_name(xml, 1).as_deref(), Some("no"));
        assert_eq!(xml_image_name(xml, 2).as_deref(), Some("Windows & more"));
        assert_eq!(xml_image_name(xml, 3), None);
    }

    #[test]
    fn headers_are_checked() {
        let mut h = vec![0u8; HEADER_LEN];
        h[..8].copy_from_slice(MAGIC);
        h[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        h[12..16].copy_from_slice(&VERSION_WIM.to_le_bytes());
        h[40..42].copy_from_slice(&1u16.to_le_bytes());
        h[42..44].copy_from_slice(&1u16.to_le_bytes());
        assert!(Header::parse(&h).is_ok());
        let kind = |h: &[u8]| Header::parse(h).unwrap_err().kind;
        let mut v = h.clone();
        v[12..16].copy_from_slice(&0x0001_0900u32.to_le_bytes());
        assert_eq!(kind(&v), ErrorKind::UnsupportedOperation);
        let mut p = h.clone();
        p[..8].copy_from_slice(PIPABLE);
        assert_eq!(kind(&p), ErrorKind::UnsupportedOperation);
        let mut z = h.clone();
        z[40..42].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(kind(&z), ErrorKind::Corrupt);
        assert_eq!(kind(&h[..100]), ErrorKind::Corrupt);
        let mut m = h.clone();
        m[16..20].copy_from_slice(&(HDR_COMPRESSION | 0x10_0000).to_le_bytes());
        assert_eq!(
            Header::parse(&m).unwrap().method().unwrap_err().kind,
            ErrorKind::UnsupportedOperation
        );
        m[16..20].copy_from_slice(&(HDR_COMPRESSION | HDR_LZMS).to_le_bytes());
        assert_eq!(Header::parse(&m).unwrap().method().unwrap(), Method::Lzms);
    }
}
