//! UDIF, the container inside Apple disk images (docs/M5.md §5.11): BeeZip's own reader and
//! writer. The volume inside is format/dmg.rs's.
//!
//! - **The layout:** the data fork (the disk's sectors in chunks, each compressed on its own),
//!   then an XML property list, then the 512-byte big-endian `koly` trailer that locates both.
//!   The plist's `resource-fork` → `blkx` array has an entry per partition: its name and a base64
//!   `mish` block, a 204-byte header and then 40-byte records of chunks (type, first sector,
//!   sector count, compressed offset and length).
//! - **Reading:** every offset, length and count is checked against the file before it's used:
//!   the plist may be at most [`MAX_PLIST`], a chunk may decode to at most [`MAX_CHUNK`] and be
//!   stored in little more than that, and chunks may not overlap. The plist is read by a small
//!   scanner of the subset Apple writes, with bounded depth and size.
//! - **The disk** is a `Read + Seek` over the sectors of every partition, laid out where their
//!   `mish` blocks put them. A read binary-searches the chunk that holds its position and decodes
//!   it, keeping the last 16 decoded chunks: one cached chunk made a bzip2 image take 6.7 s to
//!   read and four took 0.54 s (docs/M5.md §16). Every chunk must decode to exactly its sectors,
//!   except a raw chunk at the end of a partition, which may be stored short.
//! - **Chunks:** zlib (flate2), bzip2, LZFSE (lzfse_rust), LZMA (an xz stream, lzma-rust2, under
//!   the job's decoder memory), ADC (here), raw, and zero-fill. Other types fail when read.
//! - **Writing:** UDZO with one partition, the whole volume, in 1 MiB zlib chunks (raw where
//!   zlib doesn't make a chunk smaller), with the partition's and the data fork's CRC32s and the
//!   master checksum over the partitions' checksums, as hdiutil and 7-Zip check them.

use std::io::{self, Read, Seek, SeekFrom, Write};

use flate2::{Compression, write::ZlibEncoder};

use crate::{
    Ctx, Error, Progress, Result,
    io::{read_error, write_error},
    limits::Limits,
};

/// The disk's sector size: every sector number in UDIF counts these.
pub const SECTOR: u64 = 512;
/// The trailer's size, which is also the size of the partition table's sectors.
pub const KOLY_LEN: usize = 512;
/// The largest property list read. A 64 MiB plist describes over a terabyte in 1 MiB chunks.
pub const MAX_PLIST: u64 = 64 << 20;
/// The most one chunk may decode to. hdiutil writes 1 MiB; some older tools wrote less.
pub const MAX_CHUNK: u64 = 16 << 20;
/// The chunk size BeeZip writes.
pub const WRITE_CHUNK: u64 = 1 << 20;

const MISH_HEADER: usize = 204;
const MISH_RUN: usize = 40;
/// Decoded chunks the disk keeps, and the most bytes they may hold together.
const CACHE_CHUNKS: usize = 16;
const CACHE_BYTES: usize = 64 << 20;
/// The plist scanner's bounds: Apple's plists are four levels deep and hold a few dozen values.
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 100_000;

/// Chunk types.
pub const ZERO: u32 = 0x0000_0000;
pub const RAW: u32 = 0x0000_0001;
pub const IGNORE: u32 = 0x0000_0002;
pub const ADC: u32 = 0x8000_0004;
pub const ZLIB: u32 = 0x8000_0005;
pub const BZIP2: u32 = 0x8000_0006;
pub const LZFSE: u32 = 0x8000_0007;
pub const LZMA: u32 = 0x8000_0008;
pub const COMMENT: u32 = 0x7FFF_FFFE;
pub const END: u32 = 0xFFFF_FFFF;

/// `UDIFChecksum.type` for CRC32.
const CRC32: u32 = 2;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("dmg: {message}"))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_be_bytes)
}

fn be64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_be_bytes)
}

fn eof_or(e: &io::Error, what: &str) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        bad(format!("the image ends inside {what}"))
    } else {
        read_error(e)
    }
}

/// A `UDIFChecksum` (type, size in bits, 128 bytes of data): the CRC32 when it is one.
fn crc_at(b: &[u8], at: usize) -> Option<u32> {
    (be32(b, at) == CRC32 && be32(b, at + 4) == 32).then(|| be32(b, at + 8))
}

/// The name of a chunk type's codec, as `ArchiveInfo::methods` lists it.
pub fn method_name(kind: u32) -> Option<&'static str> {
    Some(match kind {
        RAW => "raw",
        ADC => "ADC",
        ZLIB => "zlib",
        BZIP2 => "bzip2",
        LZFSE => "LZFSE",
        LZMA => "LZMA",
        _ => return None,
    })
}

/// The `koly` trailer: where the data fork and the plist are, and the checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Koly {
    pub data_offset: u64,
    pub data_len: u64,
    pub xml_offset: u64,
    pub xml_len: u64,
    pub sectors: u64,
    pub data_crc: Option<u32>,
    pub master_crc: Option<u32>,
}

impl Koly {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != KOLY_LEN || !b.starts_with(b"koly") {
            return Err(bad("there is no `koly` trailer"));
        }
        let (version, size) = (be32(b, 4), be32(b, 8));
        if version != 4 || size != 512 {
            return Err(Error::unsupported_format(format!(
                "UDIF version {version} with a {size}-byte trailer isn't supported"
            )));
        }
        Ok(Self {
            data_offset: be64(b, 24),
            data_len: be64(b, 32),
            xml_offset: be64(b, 216),
            xml_len: be64(b, 224),
            sectors: be64(b, 492),
            data_crc: crc_at(b, 80),
            master_crc: crc_at(b, 352),
        })
    }

    /// The trailer of a one-segment, flattened image whose data fork starts the file.
    fn write(&self, segment_id: [u8; 16]) -> [u8; KOLY_LEN] {
        let mut k = [0u8; KOLY_LEN];
        let mut put32 = |at: usize, v: u32| k[at..at + 4].copy_from_slice(&v.to_be_bytes());
        put32(4, 4); // version
        put32(8, 512); // header size
        put32(12, 1); // flags: flattened
        put32(56, 1); // segment number
        put32(60, 1); // segment count
        put32(80, CRC32);
        put32(84, 32);
        put32(88, self.data_crc.unwrap_or(0));
        put32(352, CRC32);
        put32(356, 32);
        put32(360, self.master_crc.unwrap_or(0));
        put32(488, 1); // image variant: a device image
        k[..4].copy_from_slice(b"koly");
        k[24..32].copy_from_slice(&self.data_offset.to_be_bytes());
        k[32..40].copy_from_slice(&self.data_len.to_be_bytes());
        k[64..80].copy_from_slice(&segment_id);
        k[216..224].copy_from_slice(&self.xml_offset.to_be_bytes());
        k[224..232].copy_from_slice(&self.xml_len.to_be_bytes());
        k[492..500].copy_from_slice(&self.sectors.to_be_bytes());
        k
    }
}

/// One `blkx` entry: a partition and its chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// As hdiutil names them: `disk image (Apple_HFS : 4)`, `Protective Master Boot Record (MBR
    /// : 0)`.
    pub name: String,
    /// Where the partition starts on the disk, in sectors.
    pub first_sector: u64,
    pub sectors: u64,
    /// The CRC32 of its decoded sectors, when that's the checksum it has.
    pub crc: Option<u32>,
    pub runs: Vec<Run>,
}

impl Partition {
    pub fn bytes(&self) -> u64 {
        self.sectors * SECTOR
    }
}

/// One chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub kind: u32,
    /// The first sector, from the start of the disk.
    pub sector: u64,
    pub sectors: u64,
    /// Where its bytes are in the file.
    pub offset: u64,
    pub len: u64,
    /// The partition's last chunk, which may be stored short when it's raw.
    pub tail: bool,
}

impl Run {
    fn start(&self) -> u64 {
        self.sector * SECTOR
    }

    fn end(&self) -> u64 {
        (self.sector + self.sectors) * SECTOR
    }

    fn is_zero(&self) -> bool {
        matches!(self.kind, ZERO | IGNORE)
    }
}

/// The most a chunk of `decoded` bytes may be stored in: raw, bzip2 and ADC can grow a little
/// on incompressible data, and the rest less.
fn max_packed(decoded: u64) -> u64 {
    decoded + decoded / 8 + 4096
}

/// A `mish` block, checked against a file of `file_len` bytes whose data fork starts at
/// `data_base`.
fn parse_mish(name: String, data: &[u8], file_len: u64, data_base: u64) -> Result<Partition> {
    if data.len() < MISH_HEADER || !data.starts_with(b"mish") {
        return Err(bad(format!("partition `{name}` has no chunk table")));
    }
    if be32(data, 4) != 1 {
        return Err(bad(format!(
            "partition `{name}` has a chunk table of version {}",
            be32(data, 4)
        )));
    }
    let first_sector = be64(data, 8);
    let sectors = be64(data, 16);
    let base = be64(data, 24);
    if first_sector
        .checked_add(sectors)
        .is_none_or(|end| end > u64::MAX / SECTOR)
    {
        return Err(bad(format!("partition `{name}` claims {sectors} sectors")));
    }
    let count = be32(data, 200) as usize;
    let need = count
        .checked_mul(MISH_RUN)
        .and_then(|n| n.checked_add(MISH_HEADER));
    if need.is_none_or(|n| n > data.len()) {
        return Err(bad(format!(
            "partition `{name}` claims {count} chunks in {} bytes",
            data.len()
        )));
    }
    let mut runs = Vec::with_capacity(count);
    for r in data[MISH_HEADER..]
        .as_chunks::<MISH_RUN>()
        .0
        .iter()
        .take(count)
    {
        let kind = be32(r, 0);
        let (sector, n, off, len) = (be64(r, 8), be64(r, 16), be64(r, 24), be64(r, 32));
        if matches!(kind, COMMENT | END) || n == 0 {
            continue;
        }
        if sector.checked_add(n).is_none_or(|end| end > sectors) {
            return Err(bad(format!(
                "partition `{name}` has a chunk past its end ({n} sectors at {sector} of \
                 {sectors})"
            )));
        }
        let mut run = Run {
            kind,
            sector: first_sector + sector,
            sectors: n,
            offset: 0,
            len: 0,
            tail: false,
        };
        if !run.is_zero() {
            let decoded = n * SECTOR;
            if decoded > MAX_CHUNK {
                return Err(bad(format!(
                    "partition `{name}` has a chunk of {decoded} bytes (at most {MAX_CHUNK} are \
                     read)"
                )));
            }
            if len > max_packed(decoded) {
                return Err(bad(format!(
                    "partition `{name}` has a chunk of {decoded} bytes stored in {len}"
                )));
            }
            let at = data_base.checked_add(base).and_then(|b| b.checked_add(off));
            if at
                .and_then(|a| a.checked_add(len))
                .is_none_or(|end| end > file_len)
            {
                return Err(bad(format!(
                    "partition `{name}` has a chunk past the end of the file"
                )));
            }
            run.offset = at.unwrap_or(0);
            run.len = len;
        }
        runs.push(run);
    }
    if let Some(last) = runs
        .iter_mut()
        .filter(|r| !r.is_zero())
        .max_by_key(|r| r.sector)
    {
        last.tail = true;
    }
    Ok(Partition {
        name,
        first_sector,
        sectors,
        crc: crc_at(data, 64),
        runs,
    })
}

/// A UDIF image's trailer and partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub koly: Koly,
    pub partitions: Vec<Partition>,
}

impl Image {
    /// The codecs its chunks use, in the order first seen.
    pub fn methods(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for r in self.partitions.iter().flat_map(|p| &p.runs) {
            if let Some(m) = method_name(r.kind)
                && !out.contains(&m)
            {
                out.push(m);
            }
        }
        out
    }

    /// The disk's size: up to the end of its last partition.
    pub fn disk_size(&self) -> u64 {
        self.partitions
            .iter()
            .map(|p| p.first_sector + p.sectors)
            .max()
            .unwrap_or(0)
            * SECTOR
    }
}

/// Reads the trailer and the partition tables of the image `r`, which is `len` bytes long.
pub fn read_image<R: Read + Seek + ?Sized>(r: &mut R, len: u64) -> Result<Image> {
    if len < KOLY_LEN as u64 {
        return Err(bad("the file is too short for a disk image"));
    }
    let mut trailer = [0u8; KOLY_LEN];
    r.seek(SeekFrom::Start(len - KOLY_LEN as u64))
        .map_err(|e| read_error(&e))?;
    r.read_exact(&mut trailer)
        .map_err(|e| eof_or(&e, "its trailer"))?;
    let koly = Koly::parse(&trailer)?;
    if koly.xml_len == 0 {
        return Err(Error::unsupported_format(
            "a disk image without a property list (an old resource-fork image) isn't supported",
        ));
    }
    if koly.xml_len > MAX_PLIST {
        return Err(bad(format!(
            "the property list is {} bytes (at most {MAX_PLIST} are read)",
            koly.xml_len
        )));
    }
    if koly
        .xml_offset
        .checked_add(koly.xml_len)
        .is_none_or(|end| end > len)
    {
        return Err(bad("the property list is past the end of the file"));
    }
    if koly.data_offset > len {
        return Err(bad("the data fork is past the end of the file"));
    }
    let mut xml = vec![0u8; koly.xml_len as usize];
    r.seek(SeekFrom::Start(koly.xml_offset))
        .map_err(|e| read_error(&e))?;
    r.read_exact(&mut xml)
        .map_err(|e| eof_or(&e, "its property list"))?;
    let entries = plist::blkx(&xml)?;
    if entries.is_empty() {
        return Err(bad("the image has no partitions"));
    }
    let partitions = entries
        .into_iter()
        .map(|(name, data)| parse_mish(name, &data, len, koly.data_offset))
        .collect::<Result<Vec<_>>>()?;
    Ok(Image { koly, partitions })
}

/// The disk inside an image: every partition's sectors where their tables put them, read
/// through a cache of decoded chunks. A window limits it to one partition, for a filesystem
/// that should see only its own.
pub struct Disk<R> {
    src: R,
    runs: Vec<Run>,
    size: u64,
    base: u64,
    len: u64,
    pos: u64,
    /// Most recently used last.
    cache: Vec<(usize, Vec<u8>)>,
    cached: usize,
    mem_kib: u32,
    decodes: u64,
}

impl<R: Read + Seek> Disk<R> {
    /// `src` is the image. Chunks of different partitions that claim the same sectors are
    /// `Corrupt`.
    pub fn new(src: R, image: &Image, limits: &Limits) -> Result<Self> {
        let mut runs: Vec<Run> = image
            .partitions
            .iter()
            .flat_map(|p| p.runs.iter().copied())
            .collect();
        runs.sort_by_key(|r| r.sector);
        if runs
            .windows(2)
            .any(|w| w[0].sector + w[0].sectors > w[1].sector)
        {
            return Err(bad("two chunks hold the same sectors"));
        }
        let size = image.disk_size();
        Ok(Self {
            src,
            runs,
            size,
            base: 0,
            len: size,
            pos: 0,
            cache: Vec::new(),
            cached: 0,
            mem_kib: limits.decoder_memory_kib(),
            decodes: 0,
        })
    }

    /// The whole disk's size.
    pub fn disk_size(&self) -> u64 {
        self.size
    }

    /// Limits reads to `len` bytes from `base`, and seeks to the window's start.
    pub fn set_window(&mut self, base: u64, len: u64) -> Result<()> {
        if base.checked_add(len).is_none_or(|end| end > self.size) {
            return Err(bad(format!(
                "a partition of {len} bytes at {base} is past the end of a {}-byte disk",
                self.size
            )));
        }
        self.base = base;
        self.len = len;
        self.pos = 0;
        Ok(())
    }

    /// The window's size: what reads see as the end.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many chunks have been decoded so far.
    pub fn decodes(&self) -> u64 {
        self.decodes
    }

    /// Run `i`'s decoded bytes, from the cache or decoded now.
    fn chunk(&mut self, i: usize) -> Result<&[u8]> {
        if let Some(at) = self.cache.iter().position(|(j, _)| *j == i) {
            let hit = self.cache.remove(at);
            self.cache.push(hit);
        } else {
            let run = self.runs[i];
            let mut packed = vec![0u8; run.len as usize];
            self.src
                .seek(SeekFrom::Start(run.offset))
                .map_err(|e| read_error(&e))?;
            self.src
                .read_exact(&mut packed)
                .map_err(|e| eof_or(&e, "a chunk"))?;
            let data = decode_chunk(
                run.kind,
                &packed,
                (run.sectors * SECTOR) as usize,
                run.tail,
                self.mem_kib,
            )?;
            self.decodes += 1;
            self.cached += data.len();
            self.cache.push((i, data));
            while self.cache.len() > CACHE_CHUNKS
                || (self.cached > CACHE_BYTES && self.cache.len() > 1)
            {
                let (_, old) = self.cache.remove(0);
                self.cached -= old.len();
            }
        }
        Ok(self.cache.last().map_or(&[][..], |(_, d)| d.as_slice()))
    }
}

impl<R: Read + Seek> Read for Disk<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.len {
            return Ok(0);
        }
        let at = self.base + self.pos;
        let want = buf
            .len()
            .min(usize::try_from(self.len - self.pos).unwrap_or(usize::MAX));
        let next = self.runs.partition_point(|r| r.start() <= at);
        let n = match next.checked_sub(1).map(|i| (i, self.runs[i])) {
            Some((i, run)) if at < run.end() => {
                let off = (at - run.start()) as usize;
                let n = want.min((run.end() - at) as usize);
                if run.is_zero() {
                    buf[..n].fill(0);
                } else {
                    let data = self.chunk(i).map_err(Error::into_io)?;
                    let src = data
                        .get(off..off + n)
                        .ok_or_else(|| bad("a chunk is shorter than its sectors").into_io())?;
                    buf[..n].copy_from_slice(src);
                }
                n
            }
            // Sectors no chunk covers read as zeros.
            _ => {
                let end = self.runs.get(next).map_or(u64::MAX, Run::start);
                let n = want.min(usize::try_from(end - at).unwrap_or(usize::MAX));
                buf[..n].fill(0);
                n
            }
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R> Seek for Disk<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
        };
        self.pos = to.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a seek before the start of the disk",
            )
        })?;
        Ok(self.pos)
    }
}

/// A `Write` that holds at most `max` bytes, for decoders that push their output.
struct Bounded<'a> {
    out: &'a mut Vec<u8>,
    max: usize,
}

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.out.len() + buf.len() > self.max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "it decodes to more than its sectors",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decodes one chunk of type `kind` to exactly `want` bytes. A raw chunk at the end of its
/// partition (`tail`) may be stored short; the rest of it is zeros.
pub fn decode_chunk(
    kind: u32,
    packed: &[u8],
    want: usize,
    tail: bool,
    mem_kib: u32,
) -> Result<Vec<u8>> {
    let what = method_name(kind).unwrap_or("unknown");
    let limit = want as u64 + 1;
    let mut out = Vec::with_capacity(want);
    let decoded: io::Result<()> = match kind {
        RAW => {
            if packed.len() > want || (packed.len() < want && !tail) {
                return Err(bad(format!(
                    "a raw chunk of {want} bytes is stored in {}",
                    packed.len()
                )));
            }
            out.extend_from_slice(packed);
            out.resize(want, 0);
            return Ok(out);
        }
        ZLIB => flate2::read::ZlibDecoder::new(packed)
            .take(limit)
            .read_to_end(&mut out)
            .map(drop),
        BZIP2 => bzip2::read::BzDecoder::new(packed)
            .take(limit)
            .read_to_end(&mut out)
            .map(drop),
        LZFSE => {
            let mut sink = Bounded {
                out: &mut out,
                max: want,
            };
            lzfse_rust::LzfseRingDecoder::default()
                .decode(&mut &packed[..], &mut sink)
                .map(drop)
                .map_err(io::Error::other)
        }
        LZMA if packed.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]) => {
            lzma_rust2::XzReader::new_mem_limit(packed, false, mem_kib)
                .take(limit)
                .read_to_end(&mut out)
                .map(drop)
        }
        LZMA => lzma_rust2::LzmaReader::new_mem_limit(packed, mem_kib, None)
            .and_then(|r| r.take(limit).read_to_end(&mut out))
            .map(drop),
        ADC => {
            out = adc_decode(packed, want)?;
            Ok(())
        }
        other => {
            return Err(Error::unsupported(format!(
                "dmg: chunks of type {other:#010x} aren't supported"
            )));
        }
    };
    decoded.map_err(|e| bad(format!("a {what} chunk is damaged: {e}")))?;
    if out.len() != want {
        return Err(bad(format!(
            "a {what} chunk decodes to {} bytes instead of {want}",
            out.len()
        )));
    }
    Ok(out)
}

/// ADC (Apple Data Compression), the byte-oriented LZ77 of UDCO images. A byte with the top bit
/// set starts a literal of 1–128 bytes; one with `01` on top a match of 4–67 bytes at a 16-bit
/// distance; the rest a match of 3–18 bytes at a 10-bit distance. Distances count from 1.
pub fn adc_decode(src: &[u8], max: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(max);
    let mut i = 0;
    while let Some(&op) = src.get(i) {
        if op & 0x80 != 0 {
            let n = usize::from(op & 0x7F) + 1;
            let lit = src
                .get(i + 1..i + 1 + n)
                .ok_or_else(|| bad("an ADC chunk ends inside a literal"))?;
            if out.len() + n > max {
                return Err(bad("an ADC chunk decodes to more than its sectors"));
            }
            out.extend_from_slice(lit);
            i += 1 + n;
            continue;
        }
        let (n, dist, step) = if op & 0x40 != 0 {
            let (Some(&hi), Some(&lo)) = (src.get(i + 1), src.get(i + 2)) else {
                return Err(bad("an ADC chunk ends inside a match"));
            };
            let dist = (usize::from(hi) << 8 | usize::from(lo)) + 1;
            (usize::from(op & 0x3F) + 4, dist, 3)
        } else {
            let Some(&lo) = src.get(i + 1) else {
                return Err(bad("an ADC chunk ends inside a match"));
            };
            let dist = (usize::from(op & 0x03) << 8 | usize::from(lo)) + 1;
            (usize::from((op & 0x3F) >> 2) + 3, dist, 2)
        };
        if dist > out.len() {
            return Err(bad("an ADC match reaches before the start of its chunk"));
        }
        if out.len() + n > max {
            return Err(bad("an ADC chunk decodes to more than its sectors"));
        }
        let from = out.len() - dist;
        for k in 0..n {
            let b = out[from + k];
            out.push(b);
        }
        i += step;
    }
    Ok(out)
}

/// What hdiutil calls the one partition of an image without a partition map, whose
/// filesystem's type is `hint` (`Apple_HFS`).
pub fn whole_disk_name(hint: &str) -> String {
    format!("whole disk ({hint} : 0)")
}

/// Writes the `size` bytes of `volume` (a multiple of 512) to `out` as a UDZO image with one
/// partition named `name`, reporting progress and checking for cancellation between chunks.
/// Returns the image's size.
pub fn write_udzo(
    volume: &mut dyn Read,
    size: u64,
    name: &str,
    out: &mut dyn Write,
    cx: &mut dyn Ctx,
) -> Result<u64> {
    if !size.is_multiple_of(SECTOR) {
        return Err(Error::invalid_args(format!(
            "a disk image's volume must be whole sectors, not {size} bytes"
        )));
    }
    let sectors = size / SECTOR;
    let mut raw = vec![0u8; WRITE_CHUNK as usize];
    let mut packed: Vec<u8> = Vec::new();
    let mut runs: Vec<Run> = Vec::new();
    let mut data_crc = crc32fast::Hasher::new();
    let mut part_crc = crc32fast::Hasher::new();
    let mut offset = 0u64;
    let mut done = 0u64;
    while done < size {
        cx.check()?;
        cx.progress(&Progress {
            bytes_done: done,
            bytes_total: Some(size),
            ..Progress::default()
        });
        let n = (size - done).min(WRITE_CHUNK) as usize;
        volume
            .read_exact(&mut raw[..n])
            .map_err(|e| read_error(&e))?;
        let chunk = &raw[..n];
        part_crc.update(chunk);
        packed.clear();
        let mut z = ZlibEncoder::new(std::mem::take(&mut packed), Compression::default());
        z.write_all(chunk).map_err(|e| write_error(&e))?;
        packed = z.finish().map_err(|e| write_error(&e))?;
        let (kind, bytes) = if packed.len() < n {
            (ZLIB, packed.as_slice())
        } else {
            (RAW, chunk)
        };
        out.write_all(bytes).map_err(|e| write_error(&e))?;
        data_crc.update(bytes);
        runs.push(Run {
            kind,
            sector: done / SECTOR,
            sectors: n as u64 / SECTOR,
            offset,
            len: bytes.len() as u64,
            tail: false,
        });
        offset += bytes.len() as u64;
        done += n as u64;
    }
    let part_crc = part_crc.finalize();
    let data_crc = data_crc.finalize();
    // The master checksum is the CRC32 of the partitions' checksums, as stored.
    let master_crc = crc32fast::hash(&part_crc.to_be_bytes());

    let mish = mish(sectors, part_crc, &runs, offset);
    let xml = plist::write_blkx(name, &mish);
    out.write_all(&xml).map_err(|e| write_error(&e))?;
    let koly = Koly {
        data_offset: 0,
        data_len: offset,
        xml_offset: offset,
        xml_len: xml.len() as u64,
        sectors,
        data_crc: Some(data_crc),
        master_crc: Some(master_crc),
    };
    // A UUID made from the content, so the same volume gives the same image.
    let mut id = [0u8; 16];
    for (i, part) in id.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let mut h = crc32fast::Hasher::new_with_initial(i as u32);
        h.update(&data_crc.to_be_bytes());
        h.update(&part_crc.to_be_bytes());
        h.update(&size.to_be_bytes());
        h.update(name.as_bytes());
        part.copy_from_slice(&h.finalize().to_be_bytes());
    }
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    out.write_all(&koly.write(id))
        .map_err(|e| write_error(&e))?;
    cx.progress(&Progress {
        bytes_done: size,
        bytes_total: Some(size),
        ..Progress::default()
    });
    Ok(offset + xml.len() as u64 + KOLY_LEN as u64)
}

/// A `mish` block for one partition of `sectors` sectors starting the disk, ending with the
/// terminator hdiutil writes.
fn mish(sectors: u64, crc: u32, runs: &[Run], end: u64) -> Vec<u8> {
    let mut m = vec![0u8; MISH_HEADER];
    m[..4].copy_from_slice(b"mish");
    m[4..8].copy_from_slice(&1u32.to_be_bytes());
    m[16..24].copy_from_slice(&sectors.to_be_bytes());
    // Buffers needed: the sectors of the largest chunk, and 8 more, as hdiutil counts them.
    let buffers = (WRITE_CHUNK / SECTOR + 8) as u32;
    m[32..36].copy_from_slice(&buffers.to_be_bytes());
    // The block descriptor of a partition that is the whole device.
    m[36..40].copy_from_slice(&0xFFFF_FFFEu32.to_be_bytes());
    m[64..68].copy_from_slice(&CRC32.to_be_bytes());
    m[68..72].copy_from_slice(&32u32.to_be_bytes());
    m[72..76].copy_from_slice(&crc.to_be_bytes());
    let count = runs.len() as u32 + 1;
    m[200..204].copy_from_slice(&count.to_be_bytes());
    let mut put = |kind: u32, sector: u64, n: u64, off: u64, len: u64| {
        m.extend_from_slice(&kind.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        m.extend_from_slice(&sector.to_be_bytes());
        m.extend_from_slice(&n.to_be_bytes());
        m.extend_from_slice(&off.to_be_bytes());
        m.extend_from_slice(&len.to_be_bytes());
    };
    for r in runs {
        put(r.kind, r.sector, r.sectors, r.offset, r.len);
    }
    put(END, sectors, 0, end, 0);
    m
}

/// The property list: a small scanner of the subset Apple writes, and the writer of BeeZip's.
mod plist {
    use super::{MAX_DEPTH, MAX_NODES, bad};
    use crate::Result;

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Value {
        Dict(Vec<(String, Value)>),
        Array(Vec<Value>),
        String(String),
        Data(Vec<u8>),
        /// Integers, dates, booleans: never needed here.
        Other,
    }

    impl Value {
        fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
    }

    struct Tag<'a> {
        name: &'a [u8],
        close: bool,
        empty: bool,
    }

    struct Scanner<'a> {
        s: &'a [u8],
        at: usize,
        nodes: usize,
    }

    impl<'a> Scanner<'a> {
        fn rest(&self) -> &'a [u8] {
            self.s.get(self.at..).unwrap_or_default()
        }

        /// Whitespace, the XML declaration, the DOCTYPE and comments.
        fn skip_misc(&mut self) -> Result<()> {
            loop {
                while self.rest().first().is_some_and(u8::is_ascii_whitespace) {
                    self.at += 1;
                }
                let r = self.rest();
                let end: &[u8] = if r.starts_with(b"<?") {
                    b"?>"
                } else if r.starts_with(b"<!--") {
                    b"-->"
                } else if r.starts_with(b"<!") {
                    b">"
                } else {
                    return Ok(());
                };
                let close = memchr::memmem::find(r, end)
                    .ok_or_else(|| bad("the property list ends inside a declaration"))?;
                self.at += close + end.len();
            }
        }

        fn tag(&mut self) -> Result<Tag<'a>> {
            let r = self.rest();
            if r.first() != Some(&b'<') {
                return Err(bad("the property list has text where a value should be"));
            }
            let mut i = 1;
            let close = r.get(1) == Some(&b'/');
            if close {
                i += 1;
            }
            let start = i;
            while r
                .get(i)
                .is_some_and(|c| !c.is_ascii_whitespace() && *c != b'>' && *c != b'/')
            {
                i += 1;
            }
            let name = &r[start..i];
            let mut quote = None;
            loop {
                match (r.get(i), quote) {
                    (None, _) => return Err(bad("the property list ends inside a tag")),
                    (Some(&c), Some(q)) if c == q => quote = None,
                    (Some(_), Some(_)) => {}
                    (Some(&c), None) if c == b'"' || c == b'\'' => quote = Some(c),
                    (Some(b'>'), None) => break,
                    (Some(_), None) => {}
                }
                i += 1;
            }
            let empty = r.get(i - 1) == Some(&b'/');
            self.at += i + 1;
            Ok(Tag { name, close, empty })
        }

        fn text(&mut self) -> &'a [u8] {
            let r = self.rest();
            let n = memchr::memchr(b'<', r).unwrap_or(r.len());
            self.at += n;
            &r[..n]
        }

        fn close(&mut self, name: &[u8]) -> Result<()> {
            let t = self.tag()?;
            if !t.close || t.name != name {
                return Err(bad(format!(
                    "the property list has `{}` where `</{}>` should be",
                    String::from_utf8_lossy(t.name),
                    String::from_utf8_lossy(name)
                )));
            }
            Ok(())
        }

        fn value(&mut self, depth: usize) -> Result<Value> {
            if depth > MAX_DEPTH {
                return Err(bad("the property list is nested too deeply"));
            }
            self.nodes += 1;
            if self.nodes > MAX_NODES {
                return Err(bad("the property list has too many values"));
            }
            self.skip_misc()?;
            let t = self.tag()?;
            if t.close {
                return Err(bad("the property list closes a value it didn't open"));
            }
            match t.name {
                b"dict" => {
                    let mut items = Vec::new();
                    if t.empty {
                        return Ok(Value::Dict(items));
                    }
                    loop {
                        self.skip_misc()?;
                        if self.rest().starts_with(b"</") {
                            self.close(b"dict")?;
                            return Ok(Value::Dict(items));
                        }
                        let k = self.tag()?;
                        if k.close || k.name != b"key" {
                            return Err(bad("the property list has a dict entry without a key"));
                        }
                        let key = if k.empty {
                            String::new()
                        } else {
                            let key = unescape(self.text());
                            self.close(b"key")?;
                            key
                        };
                        let v = self.value(depth + 1)?;
                        items.push((key, v));
                    }
                }
                b"array" => {
                    let mut items = Vec::new();
                    if t.empty {
                        return Ok(Value::Array(items));
                    }
                    loop {
                        self.skip_misc()?;
                        if self.rest().starts_with(b"</") {
                            self.close(b"array")?;
                            return Ok(Value::Array(items));
                        }
                        items.push(self.value(depth + 1)?);
                    }
                }
                b"key" => Err(bad("the property list has a key outside a dict")),
                name => {
                    if t.empty {
                        return Ok(match name {
                            b"string" => Value::String(String::new()),
                            b"data" => Value::Data(Vec::new()),
                            _ => Value::Other,
                        });
                    }
                    let text = self.text();
                    self.close(name)?;
                    Ok(match name {
                        b"string" => Value::String(unescape(text)),
                        b"data" => Value::Data(base64_decode(text)?),
                        _ => Value::Other,
                    })
                }
            }
        }
    }

    /// `<plist>` and the value inside it.
    pub(super) fn parse(xml: &[u8]) -> Result<Value> {
        let mut s = Scanner {
            s: xml,
            at: 0,
            nodes: 0,
        };
        s.skip_misc()?;
        let t = s.tag()?;
        if t.close || t.empty || t.name != b"plist" {
            return Err(bad("the property list doesn't start with <plist>"));
        }
        let v = s.value(0)?;
        s.skip_misc()?;
        s.close(b"plist")?;
        Ok(v)
    }

    /// Each `resource-fork` → `blkx` entry's name and data, in order. A partition without a
    /// name is named by its `CFName`, or not at all.
    pub(super) fn blkx(xml: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        let root = parse(xml)?;
        let Some(Value::Array(items)) = root.get("resource-fork").and_then(|r| r.get("blkx"))
        else {
            return Err(bad("the property list has no partitions (`blkx`)"));
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let name = match (item.get("Name"), item.get("CFName")) {
                (Some(Value::String(n)), _) | (_, Some(Value::String(n))) => n.clone(),
                _ => String::new(),
            };
            let Some(Value::Data(data)) = item.get("Data") else {
                return Err(bad(format!("partition `{name}` has no chunk table")));
            };
            out.push((name, data.clone()));
        }
        Ok(out)
    }

    fn unescape(text: &[u8]) -> String {
        let s = String::from_utf8_lossy(text);
        if !s.contains('&') {
            return s.into_owned();
        }
        let mut out = String::with_capacity(s.len());
        let mut rest = &*s;
        while let Some(at) = rest.find('&') {
            out.push_str(&rest[..at]);
            rest = &rest[at..];
            let Some(semi) = rest.find(';').filter(|&i| i <= 10) else {
                out.push('&');
                rest = &rest[1..];
                continue;
            };
            let entity = &rest[1..semi];
            let c = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .map(|h| u32::from_str_radix(h, 16))
                    .or_else(|| entity.strip_prefix('#').map(str::parse::<u32>))
                    .and_then(|n| n.ok())
                    .and_then(char::from_u32),
            };
            match c {
                Some(c) => {
                    out.push(c);
                    rest = &rest[semi + 1..];
                }
                None => {
                    out.push('&');
                    rest = &rest[1..];
                }
            }
        }
        out.push_str(rest);
        out
    }

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Base64, ignoring whitespace; padding is optional.
    fn base64_decode(text: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(text.len() / 4 * 3);
        let (mut acc, mut bits) = (0u32, 0u32);
        for &c in text {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                c if c.is_ascii_whitespace() => continue,
                _ => return Err(bad("the property list has data that isn't base64")),
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Ok(out)
    }

    fn base64_encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for c in data.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// The plist of an image with one partition, laid out as hdiutil lays it out.
    pub(super) fn write_blkx(name: &str, mish: &[u8]) -> Vec<u8> {
        let name = escape(name);
        let mut s = String::from(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "\t<key>resource-fork</key>\n",
            "\t<dict>\n",
            "\t\t<key>blkx</key>\n",
            "\t\t<array>\n",
            "\t\t\t<dict>\n",
            "\t\t\t\t<key>Attributes</key>\n",
            "\t\t\t\t<string>0x0050</string>\n",
            "\t\t\t\t<key>CFName</key>\n",
        ));
        s.push_str(&format!("\t\t\t\t<string>{name}</string>\n"));
        s.push_str("\t\t\t\t<key>Data</key>\n\t\t\t\t<data>\n");
        let b64 = base64_encode(mish);
        for line in b64.as_bytes().chunks(52) {
            s.push_str("\t\t\t\t");
            s.push_str(&String::from_utf8_lossy(line));
            s.push('\n');
        }
        s.push_str("\t\t\t\t</data>\n");
        s.push_str("\t\t\t\t<key>ID</key>\n\t\t\t\t<string>-1</string>\n");
        s.push_str(&format!(
            "\t\t\t\t<key>Name</key>\n\t\t\t\t<string>{name}</string>\n"
        ));
        s.push_str("\t\t\t</dict>\n\t\t</array>\n\t</dict>\n</dict>\n</plist>\n");
        s.into_bytes()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn base64_round_trips() {
            for n in 0..20 {
                let data: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
                let enc = base64_encode(&data);
                assert_eq!(base64_decode(enc.as_bytes()).unwrap(), data);
                let wrapped: String = enc.chars().flat_map(|c| [c, '\n']).collect();
                assert_eq!(base64_decode(wrapped.as_bytes()).unwrap(), data);
            }
            assert_eq!(base64_decode(b"aGk=").unwrap(), b"hi");
            assert!(base64_decode(b"a*b").is_err());
        }

        #[test]
        fn scanner_reads_apples_subset() {
            let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- a comment -->
<dict>
	<key>resource-fork</key>
	<dict>
		<key>blkx</key>
		<array>
			<dict>
				<key>Attributes</key><string>0x0050</string>
				<key>CFName</key><string>Driver &amp; Map (DDM : 0)</string>
				<key>Data</key>
				<data>
				aGk=
				</data>
				<key>ID</key><string>-1</string>
				<key>Name</key><string>Driver &amp; Map &#40;DDM : 0&#x29;</string>
			</dict>
			<dict>
				<key>CFName</key><string>no name</string>
				<key>Data</key><data/>
				<key>Count</key><integer>4</integer>
				<key>Flag</key><true/>
			</dict>
		</array>
		<key>plst</key>
		<array><dict><key>Data</key><data>AAAA</data></dict></array>
	</dict>
</dict>
</plist>
"#;
            let entries = blkx(xml).unwrap();
            assert_eq!(
                entries,
                [
                    ("Driver & Map (DDM : 0)".to_owned(), b"hi".to_vec()),
                    ("no name".to_owned(), Vec::new()),
                ]
            );
        }

        #[test]
        fn scanner_refuses_what_it_cant_read() {
            let wrap = |inner: &str| format!("<plist version=\"1.0\">{inner}</plist>");
            for bad_xml in [
                "".to_owned(),
                "<dict></dict>".to_owned(),
                wrap("<dict><key>a</key>"),
                wrap("<dict><string>a</string></dict>"),
                wrap("<key>a</key>"),
                wrap("<array><string>a</array>"),
                wrap("<dict><key>resource-fork</key><dict><key>blkx</key><string/></dict></dict>"),
                wrap(&"<array>".repeat(40)),
                wrap(
                    "<dict><key>resource-fork</key><dict><key>blkx</key><array><dict><key>Name</key><string>x</string></dict></array></dict></dict>",
                ),
            ] {
                assert!(blkx(bad_xml.as_bytes()).is_err(), "{bad_xml}");
            }
            let many = wrap(&format!(
                "<array>{}</array>",
                "<true/>".repeat(MAX_NODES + 1)
            ));
            let err = parse(many.as_bytes()).unwrap_err();
            assert!(err.message.contains("too many"), "{err}");
        }

        #[test]
        fn written_plists_read_back() {
            let xml = write_blkx("whole disk (Apple_HFS : 0)", b"mish and more bytes");
            assert_eq!(
                blkx(&xml).unwrap(),
                [(
                    "whole disk (Apple_HFS : 0)".to_owned(),
                    b"mish and more bytes".to_vec()
                )]
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::SimpleCtx;

    fn image_of(volume: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_udzo(
            &mut &volume[..],
            volume.len() as u64,
            &whole_disk_name("Apple_HFS"),
            &mut out,
            &mut SimpleCtx::new(),
        )
        .unwrap();
        out
    }

    fn volume(len: usize) -> Vec<u8> {
        // Compressible text, then noise, then zeros.
        let mut v = Vec::with_capacity(len);
        let mut x = 0x2545_F491u32;
        while v.len() < len {
            let i = v.len();
            v.push(if i < len / 3 {
                b"BeeZip disk image "[i % 18]
            } else if i < 2 * len / 3 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            } else {
                0
            });
        }
        v
    }

    fn read_all(image: &[u8]) -> (Image, Vec<u8>) {
        let mut c = Cursor::new(image);
        let img = read_image(&mut c, image.len() as u64).unwrap();
        let mut disk = Disk::new(c, &img, &Limits::default()).unwrap();
        let mut out = Vec::new();
        disk.read_to_end(&mut out).unwrap();
        (img, out)
    }

    #[test]
    fn udzo_round_trips() {
        let vol = volume(6 * WRITE_CHUNK as usize + 4096);
        let image = image_of(&vol);
        let (img, out) = read_all(&image);
        assert_eq!(out, vol);
        assert_eq!(img.partitions.len(), 1);
        let p = &img.partitions[0];
        assert_eq!(p.name, "whole disk (Apple_HFS : 0)");
        assert_eq!(p.bytes(), vol.len() as u64);
        assert_eq!(p.crc, Some(crc32fast::hash(&vol)));
        assert_eq!(img.koly.sectors, vol.len() as u64 / SECTOR);
        assert_eq!(
            img.koly.data_crc,
            Some(crc32fast::hash(&image[..img.koly.data_len as usize]))
        );
        assert_eq!(
            img.koly.master_crc,
            Some(crc32fast::hash(&p.crc.unwrap().to_be_bytes()))
        );
        // The noise didn't compress, so it's stored raw.
        assert_eq!(img.methods(), ["zlib", "raw"]);
        // The same volume gives the same image.
        assert_eq!(image_of(&vol), image);
    }

    #[test]
    fn a_volume_must_be_whole_sectors() {
        let mut out = Vec::new();
        let err = write_udzo(
            &mut &[0u8; 700][..],
            700,
            "x",
            &mut out,
            &mut SimpleCtx::new(),
        )
        .unwrap_err();
        assert_eq!(err.kind, crate::ErrorKind::InvalidArgs);
    }

    #[test]
    fn koly_round_trips() {
        let k = Koly {
            data_offset: 0,
            data_len: 1234,
            xml_offset: 1234,
            xml_len: 99,
            sectors: 2048,
            data_crc: Some(7),
            master_crc: Some(9),
        };
        let b = k.write([1; 16]);
        assert_eq!(Koly::parse(&b).unwrap(), k);
        let mut v5 = b;
        v5[4..8].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            Koly::parse(&v5).unwrap_err().kind,
            crate::ErrorKind::UnsupportedFormat
        );
        assert!(Koly::parse(&b[..511]).is_err());
    }

    /// A `mish` block of the given runs (kind, sector, count, offset, len).
    fn mish_of(sectors: u64, runs: &[(u32, u64, u64, u64, u64)]) -> Vec<u8> {
        let r: Vec<Run> = runs
            .iter()
            .map(|&(kind, sector, n, offset, len)| Run {
                kind,
                sector,
                sectors: n,
                offset,
                len,
                tail: false,
            })
            .collect();
        mish(sectors, 0, &r, 0)
    }

    #[test]
    fn chunk_tables_are_checked() {
        let p = |m: &[u8]| parse_mish("p".into(), m, 10_000, 0);
        // Fine: two chunks and the terminator.
        let ok = p(&mish_of(8, &[(ZLIB, 0, 4, 0, 100), (ZERO, 4, 4, 0, 0)])).unwrap();
        assert_eq!(ok.runs.len(), 2);
        assert!(ok.runs[0].tail);
        // A count past the block.
        let mut m = mish_of(8, &[(ZLIB, 0, 4, 0, 100)]);
        m[200..204].copy_from_slice(&1000u32.to_be_bytes());
        assert!(p(&m).unwrap_err().message.contains("1000 chunks"));
        // A chunk past the partition's end, past the file's, or too big.
        assert!(p(&mish_of(8, &[(ZLIB, 6, 4, 0, 100)])).is_err());
        assert!(p(&mish_of(8, &[(ZLIB, 0, 4, 9_990, 100)])).is_err());
        assert!(p(&mish_of(8, &[(ZLIB, 0, 4, u64::MAX, 2)])).is_err());
        let huge = MAX_CHUNK / SECTOR + 1;
        assert!(p(&mish_of(huge, &[(ZLIB, 0, huge, 0, 100)])).is_err());
        assert!(p(&mish_of(8, &[(ZLIB, 0, 1, 0, 9_000)])).is_err());
        // Zero-fill may be as large as the partition.
        let big = u64::MAX / SECTOR / 2;
        assert!(p(&mish_of(big, &[(ZERO, 0, big, 0, 0)])).is_ok());
        // A partition past what sectors can address.
        assert!(p(&mish_of(u64::MAX, &[])).is_err());
        assert!(p(b"mish").is_err());
        assert!(p(&[0u8; 204]).is_err());
    }

    #[test]
    fn overlapping_chunks_are_corrupt() {
        let image = Image {
            koly: Koly::parse(
                &Koly {
                    data_offset: 0,
                    data_len: 0,
                    xml_offset: 0,
                    xml_len: 1,
                    sectors: 8,
                    data_crc: None,
                    master_crc: None,
                }
                .write([0; 16]),
            )
            .unwrap(),
            partitions: vec![Partition {
                name: "p".into(),
                first_sector: 0,
                sectors: 8,
                crc: None,
                runs: vec![
                    Run {
                        kind: ZERO,
                        sector: 0,
                        sectors: 4,
                        offset: 0,
                        len: 0,
                        tail: false,
                    },
                    Run {
                        kind: ZERO,
                        sector: 3,
                        sectors: 4,
                        offset: 0,
                        len: 0,
                        tail: false,
                    },
                ],
            }],
        };
        assert!(Disk::new(Cursor::new(Vec::new()), &image, &Limits::default()).is_err());
    }

    #[test]
    fn every_codec_decodes() {
        let data = volume(64 * 1024);
        let want = data.len();
        let zlib = {
            let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
            z.write_all(&data).unwrap();
            z.finish().unwrap()
        };
        let bz = {
            let mut z = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            z.write_all(&data).unwrap();
            z.finish().unwrap()
        };
        let mut lzfse = Vec::new();
        lzfse_rust::encode_bytes(&data, &mut lzfse).unwrap();
        let xz = {
            let mut w =
                lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::default()).unwrap();
            w.write_all(&data).unwrap();
            w.finish().unwrap()
        };
        let lzma = {
            let mut w = lzma_rust2::LzmaWriter::new_use_header(
                Vec::new(),
                &lzma_rust2::LzmaOptions::default(),
                Some(want as u64),
            )
            .unwrap();
            w.write_all(&data).unwrap();
            w.finish().unwrap()
        };
        let mem = Limits::default().decoder_memory_kib();
        for (kind, packed) in [
            (ZLIB, &zlib),
            (BZIP2, &bz),
            (LZFSE, &lzfse),
            (LZMA, &xz),
            (LZMA, &lzma),
        ] {
            assert_eq!(
                decode_chunk(kind, packed, want, false, mem).unwrap(),
                data,
                "{kind:#x}"
            );
            // Too few sectors for what it holds, or too many.
            assert!(
                decode_chunk(kind, packed, want - 512, false, mem).is_err(),
                "{kind:#x}"
            );
            assert!(
                decode_chunk(kind, packed, want + 512, false, mem).is_err(),
                "{kind:#x}"
            );
            // Damaged.
            let cut = &packed[..packed.len() / 2];
            assert!(
                decode_chunk(kind, cut, want, false, mem).is_err(),
                "{kind:#x}"
            );
        }
        assert_eq!(decode_chunk(RAW, &data, want, false, mem).unwrap(), data);
        assert!(decode_chunk(RAW, &data[..100], want, false, mem).is_err());
        let short = decode_chunk(RAW, &data[..100], 512, true, mem).unwrap();
        assert_eq!(&short[..100], &data[..100]);
        assert!(short[100..].iter().all(|&b| b == 0));
        assert_eq!(
            decode_chunk(0x8000_00FF, b"", 512, false, mem)
                .unwrap_err()
                .kind,
            crate::ErrorKind::UnsupportedOperation
        );
    }

    #[test]
    fn adc_vectors() {
        // A literal, then a 2-byte match (3 bytes, distance 3), then a 3-byte one (10 bytes,
        // distance 1).
        let src = [0x82, b'a', b'b', b'c', 0x00, 0x02, 0x46, 0x00, 0x00];
        assert_eq!(adc_decode(&src, 100).unwrap(), b"abcabccccccccccc");
        // The longest of each: a 128-byte literal, an 18-byte match at distance 1024, a 67-byte
        // match at distance 65 536.
        let mut src = vec![0xFF];
        let lit: Vec<u8> = (0..128u8).collect();
        src.extend_from_slice(&lit);
        let mut want = lit.clone();
        src.extend_from_slice(&[0x80 | 127]);
        let lit2: Vec<u8> = (0..128u8).map(|b| b ^ 0x55).collect();
        src.extend_from_slice(&lit2);
        want.extend_from_slice(&lit2);
        // 256 bytes so far; distance 200: (200 - 1) = 199 → high bits 0, low 199.
        src.extend_from_slice(&[0x0F << 2, 199]);
        let from = want.len() - 200;
        for k in 0..18 {
            want.push(want[from + k]);
        }
        src.extend_from_slice(&[0x40 | 0x3F, 0x00, 0xFF]);
        let from = want.len() - 256;
        for k in 0..67 {
            want.push(want[from + k]);
        }
        assert_eq!(adc_decode(&src, 1000).unwrap(), want);
        // Reaching before the start, running out, decoding too much.
        assert!(adc_decode(&[0x00, 0x00], 10).is_err());
        assert!(adc_decode(&[0x82, b'a'], 10).is_err());
        assert!(adc_decode(&[0x80, b'a', 0x40], 10).is_err());
        assert!(adc_decode(&[0x80, b'a', 0x46, 0, 0], 5).is_err());
    }

    #[test]
    fn the_disk_keeps_sixteen_chunks() {
        let vol = volume(20 * WRITE_CHUNK as usize);
        let image = image_of(&vol);
        let mut c = Cursor::new(&image[..]);
        let img = read_image(&mut c, image.len() as u64).unwrap();
        let mut disk = Disk::new(c, &img, &Limits::default()).unwrap();
        let mut buf = [0u8; 16];
        // Touch chunks 0..16, then again: no more decodes.
        for round in 0..2 {
            for i in 0..16u64 {
                disk.seek(SeekFrom::Start(i * WRITE_CHUNK + 100)).unwrap();
                disk.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, &vol[(i * WRITE_CHUNK + 100) as usize..][..16]);
            }
            assert_eq!(disk.decodes(), 16, "round {round}");
        }
        // A 17th pushes out the least recently used (chunk 0).
        disk.seek(SeekFrom::Start(16 * WRITE_CHUNK)).unwrap();
        disk.read_exact(&mut buf).unwrap();
        disk.seek(SeekFrom::Start(WRITE_CHUNK)).unwrap();
        disk.read_exact(&mut buf).unwrap();
        assert_eq!(disk.decodes(), 17);
        disk.seek(SeekFrom::Start(0)).unwrap();
        disk.read_exact(&mut buf).unwrap();
        assert_eq!(disk.decodes(), 18);
        // A read across two chunks.
        let mut two = vec![0u8; 64];
        disk.seek(SeekFrom::Start(3 * WRITE_CHUNK - 32)).unwrap();
        disk.read_exact(&mut two).unwrap();
        assert_eq!(two, &vol[(3 * WRITE_CHUNK - 32) as usize..][..64]);
    }

    #[test]
    fn windows_and_gaps() {
        // Two partitions with a gap between them, as a partition map lays them out.
        let a = volume(4096);
        let b = vec![7u8; 2048];
        let mut file = Vec::new();
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&a).unwrap();
        let za = z.finish().unwrap();
        file.extend_from_slice(&za);
        file.extend_from_slice(&b);
        // The second partition starts at sector 16.
        let mut second = mish_of(4, &[(RAW, 0, 4, za.len() as u64, 2048)]);
        second[8..16].copy_from_slice(&16u64.to_be_bytes());
        let image = Image {
            koly: Koly::parse(
                &Koly {
                    data_offset: 0,
                    data_len: file.len() as u64,
                    xml_offset: 0,
                    xml_len: 1,
                    sectors: 20,
                    data_crc: None,
                    master_crc: None,
                }
                .write([0; 16]),
            )
            .unwrap(),
            partitions: vec![
                parse_mish(
                    "a".into(),
                    &mish_of(8, &[(ZLIB, 0, 8, 0, za.len() as u64)]),
                    file.len() as u64,
                    0,
                )
                .unwrap(),
                parse_mish("b".into(), &second, file.len() as u64, 0).unwrap(),
            ],
        };
        let mut disk = Disk::new(Cursor::new(file), &image, &Limits::default()).unwrap();
        assert_eq!(disk.disk_size(), 20 * SECTOR);
        let mut all = Vec::new();
        disk.read_to_end(&mut all).unwrap();
        assert_eq!(&all[..4096], &a[..]);
        assert!(all[4096..8192].iter().all(|&x| x == 0));
        assert_eq!(&all[8192..], &b[..]);
        disk.set_window(16 * SECTOR, 4 * SECTOR).unwrap();
        let mut part = Vec::new();
        disk.read_to_end(&mut part).unwrap();
        assert_eq!(part, b);
        assert!(disk.set_window(16 * SECTOR, 5 * SECTOR).is_err());
    }

    #[test]
    fn damaged_images_are_corrupt() {
        let vol = volume(64 * 1024);
        let image = image_of(&vol);
        let len = image.len() as u64;
        let read = |b: &[u8]| read_image(&mut Cursor::new(b), b.len() as u64);
        assert!(read(&image[..100]).is_err());
        // The plist past the end, or claiming too much.
        let mut b = image.clone();
        let k = b.len() - 512;
        b[k + 224..k + 232].copy_from_slice(&(len * 2).to_be_bytes());
        assert!(read(&b).is_err());
        b[k + 224..k + 232].copy_from_slice(&(MAX_PLIST + 1).to_be_bytes());
        assert!(read(&b).unwrap_err().message.contains("property list"));
        // No plist at all.
        b[k + 224..k + 232].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            read(&b).unwrap_err().kind,
            crate::ErrorKind::UnsupportedFormat
        );
        // A damaged chunk is found when it's read.
        let mut b = image.clone();
        b[10] ^= 0xFF;
        b[11] ^= 0xFF;
        let mut c = Cursor::new(&b[..]);
        let img = read_image(&mut c, len).unwrap();
        let mut disk = Disk::new(c, &img, &Limits::default()).unwrap();
        let err = disk.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(Error::from(err).kind, crate::ErrorKind::Corrupt);
    }
}
