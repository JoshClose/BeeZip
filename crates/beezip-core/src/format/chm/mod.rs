//! CHM, Microsoft's compiled HTML Help, read by BeeZip's own code (docs/M9.md).
//!
//! - **The container** (§3.1): an ITSF header, then an ITSP directory of chunks. Every chunk is
//!   read and every listing (PMGL) chunk taken, whatever the header says the first one is:
//!   chmcmd 3.2.2 names chunk 1 when chunk 0 is a listing chunk too. An entry is an ENCINT name
//!   length, the UTF-8 name, and ENCINTs for its section, offset and length.
//! - **Section 0** is stored bytes at the content offset. **Section 1** is one LZX stream, read
//!   by `format/lzx.rs` as a cabinet folder's is, and described by three section-0 streams: its
//!   window and reset interval (`ControlData`), the first byte of every 32 KiB frame
//!   (`ResetTable`), and the stream itself (`Content`). Each frame decodes from its own slice,
//!   with a reset at every reset interval; every frame decodes whole, the last too, and the
//!   output is cut to the stated length (§3.3).
//! - **The listing** is 7-Zip's (§4.1): folders first, then files in data order (section 0's,
//!   then section 1's, by offset), without their leading `/`, and without the `::DataSpace`
//!   streams. Extraction follows that order, so section 1 decodes once, forwards.
//! - **Section 1 is read as 7-Zip reads it** (docs/M11.md §6.1): under whatever name
//!   `::DataSpace/NameList` gives it (`MSCompressed`), as LZX whatever `Transform/List` says
//!   (the control data's `LZXC` decides), and with `LZXC` and reset table version 3 read as
//!   version 2. A file in a third section, which nothing is known to write, fails alone.
//! - **Damage is `Corrupt`** (§5.2): a file cut after its directory still lists whole, and each
//!   file fails only when its own data is gone. Another ITSF version, control data that isn't
//!   `LZXC`, or a reset table of another layout is `UnsupportedOperation` (§5.3).
//!
//! Nothing here may panic, whatever the bytes.

#[doc(hidden)]
pub mod write;

use std::{
    borrow::Cow,
    io::{self, Read, Seek, SeekFrom},
};

use super::{
    ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
    lzx::{self, Lzx},
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result, TestReport, TestSink,
    backend::{External, ExternalInfo, LevelProperty},
    io::{CountingReader, copy},
    safefs::Partial,
    source::{Input, Source},
};

/// One frame of section 1's output: LZX's frame, and the reset table's block.
const FRAME: u64 = lzx::FRAME as u64;
/// The most of a frame's slice that's read. No frame's bits take more (a 32 KiB uncompressed
/// block, or 16-bit literal codes with their trees); what a damaged table claims beyond it is
/// never read.
const MAX_SLICE: u64 = 3 * FRAME;
/// Directory chunks are 4 or 8 KiB. A chunk over this is damage, not something to allocate.
const MAX_CHUNK: u64 = 1 << 20;
/// `#SYSTEM` is a few KiB; only this much is read for Info.
const MAX_SYSTEM: u64 = 1 << 20;

const NAMELIST: &[u8] = b"::DataSpace/NameList";
/// Section 1's name when `NameList` gives none.
const COMPRESSED: &str = "MSCompressed";
/// Section 1's streams, under `::DataSpace/Storage/<its name>/`.
const CONTROL: &str = "ControlData";
const CONTENT: &str = "Content";
const RESET_TABLE: &str =
    "Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";

/// Section `name`'s stream `stream`, as the directory names it.
fn storage(name: &str, stream: &str) -> Vec<u8> {
    format!("::DataSpace/Storage/{name}/{stream}").into_bytes()
}

const NO_CHECKSUMS: &str = "A CHM help file stores no checksums of its files' data, so the test \
shows that BeeZip can read every file, not that their contents are intact.";

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("chm: {message}"))
}

fn le16(d: &[u8], at: usize) -> Option<u16> {
    let b = d.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn le32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

fn le64(d: &[u8], at: usize) -> Option<u64> {
    let b = d.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(b.try_into().ok()?))
}

/// UTF-16LE text, an odd last byte left out.
fn utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// CHM's ENCINT: big-endian groups of 7 bits, the top bit set on all but the last. At most nine
/// bytes (63 bits).
fn encint(d: &[u8], p: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for _ in 0..9 {
        let c = *d.get(*p)?;
        *p += 1;
        v = (v << 7) | u64::from(c & 0x7f);
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Up to `len` bytes at `at`: fewer where the file ends first.
fn read_at(input: &mut (impl Read + Seek), at: u64, len: u64) -> Result<Vec<u8>> {
    input
        .seek(SeekFrom::Start(at))
        .map_err(|e| Error::io("seeking in the help file", &e))?;
    let mut out = Vec::new();
    input
        .take(len)
        .read_to_end(&mut out)
        .map_err(|e| Error::io("reading the help file", &e))?;
    Ok(out)
}

/// An entry as the directory stores it.
#[derive(Debug, Clone)]
struct Raw {
    name: Vec<u8>,
    section: u64,
    offset: u64,
    length: u64,
}

#[derive(Debug, Clone, Copy)]
struct Header {
    lang: u32,
    dir_off: u64,
    dir_len: u64,
    content_off: u64,
}

fn header(input: &mut (impl Read + Seek), len: u64) -> Result<Header> {
    let h = read_at(input, 0, 0x60.min(len))?;
    if h.len() < 0x58 {
        return Err(bad("the header is cut short"));
    }
    if &h[..4] != b"ITSF" {
        return Err(bad("there's no ITSF header"));
    }
    let short = || bad("the header is cut short");
    let version = le32(&h, 4).ok_or_else(short)?;
    if !(2..=3).contains(&version) {
        return Err(Error::unsupported(format!(
            "its ITSF header is version {version}"
        )));
    }
    let hlen = le32(&h, 8).ok_or_else(short)?;
    let dir_off = le64(&h, 0x48).ok_or_else(short)?;
    let dir_len = le64(&h, 0x50).ok_or_else(short)?;
    // Version 3 says where section 0 starts; version 2's follows the directory.
    let content_off = if version == 3 && hlen >= 0x60 {
        le64(&h, 0x58).ok_or_else(short)?
    } else {
        dir_off
            .checked_add(dir_len)
            .ok_or_else(|| bad("the directory's place overflows"))?
    };
    Ok(Header {
        lang: le32(&h, 0x14).ok_or_else(short)?,
        dir_off,
        dir_len,
        content_off,
    })
}

/// Every entry of every listing chunk, in chunk order.
fn directory(
    input: &mut (impl Read + Seek),
    len: u64,
    h: &Header,
    max_entries: u64,
) -> Result<Vec<Raw>> {
    let end = h
        .dir_off
        .checked_add(h.dir_len)
        .filter(|&e| e <= len)
        .ok_or_else(|| bad("the directory is cut short"))?;
    let itsp = read_at(input, h.dir_off, 0x54.min(h.dir_len))?;
    if itsp.len() < 0x30 || &itsp[..4] != b"ITSP" {
        return Err(bad("the directory has no ITSP header"));
    }
    let short = || bad("the directory's header is cut short");
    let hlen = u64::from(le32(&itsp, 8).ok_or_else(short)?);
    let cs = u64::from(le32(&itsp, 0x10).ok_or_else(short)?);
    let chunks = u64::from(le32(&itsp, 0x2c).ok_or_else(short)?);
    if !(0x20..=MAX_CHUNK).contains(&cs) {
        return Err(bad(format!("a directory chunk of {cs} bytes")));
    }
    let first = h.dir_off.saturating_add(hlen);
    if chunks
        .checked_mul(cs)
        .and_then(|b| b.checked_add(first))
        .is_none_or(|e| e > end)
    {
        return Err(bad(format!(
            "the directory's {chunks} chunks of {cs} bytes run past it"
        )));
    }
    let mut out = Vec::new();
    let mut chunk = vec![0u8; cs as usize];
    input
        .seek(SeekFrom::Start(first))
        .map_err(|e| Error::io("seeking in the help file", &e))?;
    for i in 0..chunks {
        input
            .read_exact(&mut chunk)
            .map_err(|e| Error::io("reading the help file's directory", &e))?;
        // Index (PMGI) chunks aren't needed for a whole listing.
        if &chunk[..4] != b"PMGL" {
            continue;
        }
        let free = le32(&chunk, 4).unwrap_or(u32::MAX) as usize;
        let used = chunk
            .len()
            .checked_sub(free)
            .filter(|&u| u >= 0x14)
            .ok_or_else(|| bad(format!("directory chunk {i} has {free} bytes free")))?;
        let c = &chunk[..used];
        let mut p = 0x14;
        while p < used {
            let at = p;
            let cut = || bad(format!("directory chunk {i}'s entry at {at} is cut short"));
            let n = encint(c, &mut p).ok_or_else(cut)?;
            let name = usize::try_from(n)
                .ok()
                .and_then(|n| c.get(p..p.checked_add(n)?))
                .ok_or_else(cut)?
                .to_vec();
            p += name.len();
            let section = encint(c, &mut p).ok_or_else(cut)?;
            let offset = encint(c, &mut p).ok_or_else(cut)?;
            let length = encint(c, &mut p).ok_or_else(cut)?;
            out.push(Raw {
                name,
                section,
                offset,
                length,
            });
            if out.len() as u64 > max_entries {
                return Err(Error::limit(format!(
                    "chm: the help file has more than {max_entries} entries (limit `max_entries`)"
                )));
            }
        }
    }
    Ok(out)
}

/// Section 1: an LZX stream in 32 KiB frames (docs/M9.md §3.2).
#[derive(Debug, Clone)]
struct Sec1 {
    window_bits: u32,
    reset_interval: u64,
    frames_per_reset: u64,
    /// Its decoded length.
    len: u64,
    /// Where `Content` starts in the file.
    content_at: u64,
    /// Each frame's first byte in `Content`, then the compressed length.
    starts: Vec<u64>,
}

impl Sec1 {
    /// Frame `f`'s bytes in `Content`.
    fn slice(&self, f: u64) -> Option<(u64, u64)> {
        let i = usize::try_from(f).ok()?;
        Some((*self.starts.get(i)?, *self.starts.get(i.checked_add(1)?)?))
    }
}

/// The open file, and what reading it needs.
struct Inner {
    input: CountingReader<Input>,
    len: u64,
    content_off: u64,
    /// Where each entry's data is, by id (`None` for folders).
    items: Vec<Option<Raw>>,
    /// Section 1, or why its files can't be read.
    sec1: std::result::Result<Sec1, Error>,
    frames: Option<Frames>,
}

impl Inner {
    /// A section-0 stream's bytes, by name, when it's whole.
    fn stream(&mut self, raws: &[Raw], name: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(r) = raws.iter().find(|r| r.name == name) else {
            return Ok(None);
        };
        if r.section != 0 {
            return Err(bad(format!(
                "{} isn't in section 0",
                String::from_utf8_lossy(name)
            )));
        }
        let at = self
            .content_off
            .checked_add(r.offset)
            .ok_or_else(|| bad("an entry's offset overflows"))?;
        let d = read_at(&mut self.input, at, r.length)?;
        if (d.len() as u64) < r.length {
            return Err(bad(format!(
                "the file is cut short: {} isn't in it",
                String::from_utf8_lossy(name)
            )));
        }
        Ok(Some(d))
    }

    /// Entry `id`'s data.
    fn data(&mut self, id: usize) -> Result<Box<dyn Read + Send + '_>> {
        let Some(item) = self.items.get(id).cloned().flatten() else {
            return Ok(Box::new(io::empty()));
        };
        match item.section {
            0 => {
                let at = self
                    .content_off
                    .checked_add(item.offset)
                    .ok_or_else(|| bad("an entry's offset overflows"))?;
                Ok(Box::new(Stored {
                    input: &mut self.input,
                    at,
                    left: item.length,
                }))
            }
            1 => {
                let s = self.sec1.as_ref().map_err(Clone::clone)?;
                let end = item
                    .offset
                    .checked_add(item.length)
                    .filter(|&e| e <= s.len)
                    .ok_or_else(|| {
                        bad(format!(
                            "a file runs past section 1's end ({} bytes)",
                            s.len
                        ))
                    })?;
                if self.frames.is_none() {
                    self.frames = Some(Frames::new(s.window_bits)?);
                }
                let frames = self
                    .frames
                    .as_mut()
                    .ok_or_else(|| bad("section 1's decoder is missing"))?;
                Ok(Box::new(Compressed {
                    frames,
                    sec1: s,
                    input: &mut self.input,
                    len: self.len,
                    pos: item.offset,
                    end,
                }))
            }
            n => Err(bad(format!(
                "a file in section {n}; BeeZip reads sections 0 and 1"
            ))),
        }
    }
}

/// A section-0 file: stored bytes, failing where the file is cut short.
struct Stored<'a> {
    input: &'a mut CountingReader<Input>,
    at: u64,
    left: u64,
}

impl Read for Stored<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        self.input.seek(SeekFrom::Start(self.at))?;
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.input.read(&mut buf[..want])?;
        if n == 0 {
            return Err(bad("the file is cut short").into_io());
        }
        self.at += n as u64;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Section 1's decoder, and the frame it decoded last.
struct Frames {
    lzx: Lzx,
    /// The frame `out` holds.
    cur: Option<u64>,
    out: Vec<u8>,
    packed: Vec<u8>,
    /// The first frame that failed, and why: the frames after it in its reset interval can't be
    /// decoded either.
    failed: Option<(u64, Error)>,
}

impl Frames {
    fn new(window_bits: u32) -> Result<Self> {
        Ok(Self {
            lzx: Lzx::new(window_bits).map_err(bad)?,
            cur: None,
            out: Vec::with_capacity(lzx::FRAME),
            packed: Vec::new(),
            failed: None,
        })
    }

    /// Frame `f`, decoded: from the frame after the current one when it's in the same reset
    /// interval, else from the interval's first.
    fn frame(
        &mut self,
        s: &Sec1,
        input: &mut CountingReader<Input>,
        len: u64,
        f: u64,
    ) -> Result<&[u8]> {
        if self.cur == Some(f) {
            return Ok(&self.out);
        }
        let interval = f / s.frames_per_reset;
        if let Some((k, e)) = &self.failed
            && *k / s.frames_per_reset == interval
            && f >= *k
        {
            return Err(e.clone());
        }
        let mut g = match self.cur {
            Some(c) if c < f && c / s.frames_per_reset == interval => c + 1,
            _ => interval * s.frames_per_reset,
        };
        while g <= f {
            if g % s.frames_per_reset == 0 {
                self.lzx.reset();
            }
            self.cur = None;
            if let Err(e) = self.decode(s, input, len, g) {
                self.failed = Some((g, e.clone()));
                return Err(e);
            }
            self.cur = Some(g);
            g += 1;
        }
        Ok(&self.out)
    }

    fn decode(
        &mut self,
        s: &Sec1,
        input: &mut CountingReader<Input>,
        len: u64,
        g: u64,
    ) -> Result<()> {
        let (a, b) = s
            .slice(g)
            .ok_or_else(|| bad(format!("section 1's frame {g} isn't in the reset table")))?;
        let at = s.content_at.saturating_add(a);
        if at >= len {
            return Err(bad(format!(
                "the file is cut short: section 1's frame {g} isn't in it"
            )));
        }
        let want = (b - a).min(MAX_SLICE);
        let cut = at.saturating_add(want) > len;
        input
            .seek(SeekFrom::Start(at))
            .map_err(|e| Error::io("seeking in the help file", &e))?;
        self.packed.clear();
        (&mut *input)
            .take(want)
            .read_to_end(&mut self.packed)
            .map_err(|e| Error::io("reading the help file", &e))?;
        self.out.clear();
        self.lzx
            .decode_frame(&self.packed, lzx::FRAME, &mut self.out)
            .map_err(|e| {
                if cut {
                    bad(format!("the file is cut short in section 1's frame {g}"))
                } else {
                    bad(format!("section 1's frame {g} is damaged: {e}"))
                }
            })
    }
}

/// A section-1 file, decoded frame by frame.
struct Compressed<'a> {
    frames: &'a mut Frames,
    sec1: &'a Sec1,
    input: &'a mut CountingReader<Input>,
    len: u64,
    pos: u64,
    end: u64,
}

impl Read for Compressed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.end || buf.is_empty() {
            return Ok(0);
        }
        let frame = self
            .frames
            .frame(self.sec1, self.input, self.len, self.pos / FRAME)
            .map_err(Error::into_io)?;
        let off = (self.pos % FRAME) as usize;
        let n = buf
            .len()
            .min(frame.len().saturating_sub(off))
            .min(usize::try_from(self.end - self.pos).unwrap_or(usize::MAX));
        if n == 0 {
            return Err(bad("section 1 decodes short").into_io());
        }
        buf[..n].copy_from_slice(&frame[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

/// An entry whose data can't be read: the error, on every read.
struct Failing(Error);

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self.0.clone().into_io())
    }
}

/// Section 1's description, from the streams of the storage named `name`. `UnsupportedOperation`
/// is a layout nothing reads; other errors are damage, which fails section 1's files when
/// they're read. `Transform/List` isn't read: 7-Zip never reads it either, and `LZXC` decides.
fn sec1(inner: &mut Inner, raws: &[Raw], name: &str) -> Result<Sec1> {
    let cd = inner
        .stream(raws, &storage(name, CONTROL))?
        .ok_or_else(|| bad("there's no LZX control data"))?;
    if cd.len() < 0x18 {
        return Err(bad("the LZX control data is cut short"));
    }
    if &cd[4..8] != b"LZXC" {
        return Err(Error::unsupported(format!(
            "its compressed section isn't LZX (`{}`)",
            String::from_utf8_lossy(&cd[4..8])
        )));
    }
    let short = || bad("the LZX control data is cut short");
    // Version 1 counts bytes, 2 frames; 3, which no writer is known for, is read as 2.
    let unit = match le32(&cd, 8).ok_or_else(short)? {
        1 => 1,
        2 | 3 => FRAME,
        v => {
            return Err(Error::unsupported(format!(
                "its LZX control data is version {v}"
            )));
        }
    };
    let reset_interval = u64::from(le32(&cd, 12).ok_or_else(short)?) * unit;
    let window = u64::from(le32(&cd, 16).ok_or_else(short)?) * unit;
    let window_bits = match window {
        0x8000 => 15,
        0x1_0000 => 16,
        0x2_0000 => 17,
        0x4_0000 => 18,
        0x8_0000 => 19,
        0x10_0000 => 20,
        0x20_0000 => 21,
        w => return Err(bad(format!("an LZX window of {w} bytes"))),
    };
    if reset_interval == 0 || !reset_interval.is_multiple_of(FRAME) {
        return Err(bad(format!("a reset interval of {reset_interval} bytes")));
    }
    let rt = inner
        .stream(raws, &storage(name, RESET_TABLE))?
        .ok_or_else(|| bad("there's no reset table"))?;
    let short = || bad("the reset table is cut short");
    if rt.len() < 0x28 {
        return Err(short());
    }
    let version = le32(&rt, 0).ok_or_else(short)?;
    let count = u64::from(le32(&rt, 4).ok_or_else(short)?);
    let entry_size = le32(&rt, 8).ok_or_else(short)?;
    let table = le32(&rt, 12).ok_or_else(short)? as usize;
    let len = le64(&rt, 16).ok_or_else(short)?;
    let packed = le64(&rt, 24).ok_or_else(short)?;
    let block = le64(&rt, 32).ok_or_else(short)?;
    // Version 3, which no writer is known for, is read as 2.
    if !(2..=3).contains(&version) || entry_size != 8 || block != FRAME {
        return Err(Error::unsupported(format!(
            "its reset table is version {version}, with {entry_size}-byte entries for blocks of \
             {block} bytes"
        )));
    }
    let frames = len.div_ceil(FRAME);
    if count < frames {
        return Err(bad(format!(
            "the reset table has {count} entries for {frames} frames"
        )));
    }
    // Each frame's entry must be in the table, so their number is bounded by the file's size.
    let mut starts = Vec::new();
    let mut last = 0;
    for k in 0..frames {
        let at = usize::try_from(k)
            .ok()
            .and_then(|k| k.checked_mul(8)?.checked_add(table))
            .ok_or_else(short)?;
        let start = le64(&rt, at).ok_or_else(short)?;
        if start < last || start > packed {
            return Err(bad(format!(
                "the reset table's entry for frame {k} is out of place"
            )));
        }
        starts.push(start);
        last = start;
    }
    starts.push(packed);
    let content_name = storage(name, CONTENT);
    let content = raws
        .iter()
        .find(|r| r.name == content_name && r.section == 0)
        .ok_or_else(|| bad("there's no compressed content"))?;
    if packed > content.length {
        return Err(bad(format!(
            "the compressed stream's {packed} bytes are more than its {} in the file",
            content.length
        )));
    }
    Ok(Sec1 {
        window_bits,
        reset_interval,
        frames_per_reset: reset_interval / FRAME,
        len,
        content_at: inner
            .content_off
            .checked_add(content.offset)
            .ok_or_else(|| bad("an entry's offset overflows"))?,
        starts,
    })
}

/// Section 1's name, from `::DataSpace/NameList` when it holds one: any name reads, as 7-Zip
/// reads it, from the storage of that name. `MSCompressed` when the list is missing or damaged.
fn section_name(inner: &mut Inner, raws: &[Raw]) -> String {
    let Ok(Some(nl)) = inner.stream(raws, NAMELIST) else {
        return COMPRESSED.to_owned();
    };
    let count = le16(&nl, 2).unwrap_or(0);
    let mut p = 4usize;
    for i in 0..count.min(2) {
        let Some(n) = le16(&nl, p) else { break };
        let Some(b) = nl.get(p + 2..p + 2 + 2 * usize::from(n)) else {
            break;
        };
        let name = utf16le(b);
        let name = name.trim_end_matches('\0');
        // A name that would leave the storage folder isn't one.
        if i == 1 && !name.is_empty() && !name.contains(['/', '\\']) {
            return name.to_owned();
        }
        p += 2 + 2 * usize::from(n) + 2;
    }
    COMPRESSED.to_owned()
}

/// What `#SYSTEM` says, for Info: its title, default topic, compiler and language.
fn system(d: &[u8]) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let mut p = 4usize;
    while let (Some(code), Some(n)) = (le16(d, p), le16(d, p + 2)) {
        let Some(v) = d.get(p + 4..p + 4 + usize::from(n)) else {
            break;
        };
        let text = || {
            std::str::from_utf8(v)
                .ok()
                .map(|s| s.trim_end_matches('\0').trim().to_owned())
                .filter(|s| !s.is_empty())
        };
        match code {
            2 => out.extend(text().map(|t| ("Default topic", t))),
            3 => out.extend(text().map(|t| ("Title", t))),
            4 => out.extend(le32(v, 0).map(|l| ("Language", format!("0x{l:04X}")))),
            9 => out.extend(text().map(|t| ("Compiler", t))),
            _ => {}
        }
        p += 4 + usize::from(n);
    }
    out
}

fn kib(n: u64) -> String {
    format!("{} KiB", n / 1024)
}

pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(ChmReader::open(source, cx)?))
}

pub struct ChmReader {
    source: Source,
    inner: Inner,
    entries: Vec<Entry>,
    methods: Vec<Cow<'static, str>>,
    properties: Vec<LevelProperty>,
    /// Keeps a help file spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl ChmReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (input, spool) = if source.codecs.is_empty() {
            (source.input()?, None)
        } else {
            // The help file is read at offsets: spool the decoded stream.
            let mut tmp = Partial::create_temp("beezip-spool.chm")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            (Input::file(tmp.reopen()?)?, Some(tmp))
        };
        let len = input.len();
        let mut input = CountingReader::new(input, source.counter.clone());
        let h = header(&mut input, len)?;
        let max_entries = source.limits.max_entries.unwrap_or(u64::MAX);
        let raws = directory(&mut input, len, &h, max_entries)?;
        let mut inner = Inner {
            input,
            len,
            content_off: h.content_off,
            items: Vec::new(),
            sec1: Err(bad("there's no compressed section")),
            frames: None,
        };
        let compressed = section_name(&mut inner, &raws);

        // Folders first, then files in data order, as 7-Zip lists them (§4.1).
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for (k, r) in raws.iter().enumerate() {
            if r.name.starts_with(b"::") {
                continue;
            }
            let name = r.name.strip_prefix(b"/").unwrap_or(&r.name);
            match name.strip_suffix(b"/") {
                // The root.
                Some(b"") => {}
                _ if name.is_empty() => {}
                Some(dir) => dirs.push(dir),
                None => files.push((r.section, r.offset, k, name)),
            }
        }
        files.sort_by_key(|&(section, offset, k, _)| (section, offset, k));
        if files.iter().any(|f| f.0 == 1) {
            match sec1(&mut inner, &raws, &compressed) {
                Ok(s) => inner.sec1 = Ok(s),
                Err(e) if e.kind == ErrorKind::UnsupportedOperation => return Err(e),
                Err(e) => inner.sec1 = Err(e),
            }
        }
        let lzx: Cow<'static, str> = match &inner.sec1 {
            Ok(s) => Cow::Owned(format!("LZX:{}", s.window_bits)),
            Err(_) => Cow::Borrowed("LZX"),
        };
        let mut entries = Vec::with_capacity(dirs.len() + files.len());
        let mut methods: Vec<Cow<'static, str>> = Vec::new();
        for &dir in &dirs {
            let mut e = Entry::new(
                entries.len(),
                String::from_utf8_lossy(dir).into_owned(),
                EntryKind::Dir,
            );
            e.raw_path = dir.to_vec();
            entries.push(e);
            inner.items.push(None);
        }
        for &(section, _, k, name) in &files {
            let r = &raws[k];
            let mut e = Entry::new(
                entries.len(),
                String::from_utf8_lossy(name).into_owned(),
                EntryKind::File,
            );
            e.raw_path = name.to_vec();
            e.size = Some(r.length);
            e.method = match section {
                0 => Some(Cow::Borrowed("Copy")),
                1 => Some(lzx.clone()),
                _ => None,
            };
            if let Some(m) = &e.method
                && !methods.contains(m)
            {
                methods.push(m.clone());
            }
            entries.push(e);
            inner.items.push(Some(r.clone()));
        }

        let mut properties = Vec::new();
        let mut prop = |name: &str, value: String| {
            properties.push(LevelProperty {
                level: "chm".to_owned(),
                name: name.to_owned(),
                value,
            });
        };
        let system_id = entries
            .iter()
            .position(|e| e.path == "#SYSTEM" && e.kind == EntryKind::File);
        let mut said = system_id
            .and_then(|id| {
                let mut d = Vec::new();
                inner
                    .data(id)
                    .ok()?
                    .take(MAX_SYSTEM)
                    .read_to_end(&mut d)
                    .ok()?;
                Some(system(&d))
            })
            .unwrap_or_default();
        if !said.iter().any(|(n, _)| *n == "Language") && h.lang != 0 {
            said.push(("Language", format!("0x{:04X}", h.lang)));
        }
        for name in ["Title", "Default topic", "Language", "Compiler"] {
            if let Some((_, v)) = said.iter().find(|(n, _)| *n == name) {
                prop(name, v.clone());
            }
        }
        if let Ok(s) = &inner.sec1 {
            prop("LZX window", kib(1 << s.window_bits));
            prop("Reset interval", kib(s.reset_interval));
        }
        Ok(Self {
            source,
            inner,
            entries,
            methods,
            properties,
            _spool: spool,
        })
    }
}

impl ArchiveReader for ChmReader {
    fn format(&self) -> FormatId {
        FormatId::External(External::Chm)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::External(External::Chm),
            codecs: self.source.codecs.clone(),
            methods: self.methods.clone(),
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
                levels: vec!["chm".to_owned()],
                properties: self.properties.clone(),
                notes: Vec::new(),
            }),
        })
    }

    /// In listing order, which is data order: section 1 decodes once, forwards, skipping the
    /// reset intervals no selected file is in.
    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let selected: Vec<usize> = (0..self.entries.len())
            .filter(|&id| sel.matches(&self.entries[id]))
            .collect();
        // Many small files: written on other threads while section 1 decodes.
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
            let data = match self.inner.data(id) {
                Ok(d) => d,
                Err(e) => Box::new(Failing(e)),
            };
            let mut data = self.source.guard(data);
            sink.entry(&self.entries[id], &mut data, &mut mcx)?;
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
        let data = self.inner.data(id)?;
        Ok(Box::new(self.source.guard(data)))
    }

    /// Every file read in one pass; a CHM has no checksums to check (docs/M9.md §4.4).
    fn test(&mut self, cx: &mut dyn Ctx) -> Option<Result<TestReport>> {
        let mut sink = TestSink::default();
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
            report.note = Some(NO_CHECKSUMS.to_owned());
            report
        }))
    }
}

#[cfg(test)]
mod tests;
