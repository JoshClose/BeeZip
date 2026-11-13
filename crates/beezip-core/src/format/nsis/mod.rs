//! NSIS installers, read by BeeZip's own code (docs/M10.md).
//!
//! - **The first header** (§3.2) is at a 512-byte boundary of the file, at the executable's
//!   overlay: flags, `EF BE AD DE`, `NullsoftInst`, the header's length and the length of
//!   everything after the first header, CRC included. The method isn't stored; it's read from
//!   the data as 7-Zip reads it: LZMA's properties (with or without the x86 filter's byte),
//!   NSIS's bzip2 block mark, or else deflate.
//! - **Solid installers** are one stream: the header's length and the header, then each file as
//!   its length and bytes. **Non-solid ones** have the header first, then a record per file,
//!   compressed or stored. Identical files are stored once.
//! - **The listing** is 7-Zip's (`header.rs`), with the uninstaller always listed: it's the
//!   installer's stub, its icon patched, then the uninstaller's data, as `WriteUninstaller`
//!   writes it.
//! - **Sizes are exact** (§4.1): a solid stream is decoded once as the installer opens, to read
//!   each file's length; a non-solid installer's compressed records are decoded then too.
//! - **Deflate** comes in NSIS 2's form too, whose stored blocks have no NLEN (`inflate.rs`):
//!   zlib's form is read first, and NSIS 2's where that fails or (for a record) doesn't end at
//!   the record's end. **bzip2** is NSIS's own (`bzip2.rs`).
//! - **Damage is `Corrupt`** (§5.2): a file cut after its header lists whole, and each file fails
//!   only when its own data is gone. `test` checks the installer's CRC.
//!
//! Nothing here may panic, whatever the bytes.

mod bzip2;
mod header;
mod inflate;
#[doc(hidden)]
pub mod write;

use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Seek, SeekFrom},
    rc::Rc,
};

use header::{Item, ItemKind, Parsed};

use super::{
    ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Limits, Meter, MeteredCtx, Result, TestReport, TestSink,
    backend::{External, ExternalInfo, LevelProperty},
    io::{Counter, CountingReader, copy},
    limits::{Budget, Guarded, RatioGuard},
    names::SystemPage,
    safefs::Partial,
    source::{Input, Source},
    time::from_ntfs,
};

const SIGNATURE: &[u8; 16] = b"\xEF\xBE\xAD\xDENullsoftInst";
const FIRST_LEN: u64 = 28;
/// First-header flags: an uninstaller, silent, no CRC, CRC even so.
const FH_UNINSTALL: u32 = 1;
const FH_NO_CRC: u32 = 4;
const FH_FORCE_CRC: u32 = 8;
/// The largest header read; real ones are under 1 MB.
const MAX_HEADER: u32 = 64 << 20;
/// The most of the file searched for a first header when none was found by detection.
const MAX_SEARCH: u64 = 256 << 20;
/// An uninstaller's icon patch, and the stub it patches, held in memory.
const MAX_PATCH: u64 = 16 << 20;
const MAX_STUB: u64 = 64 << 20;
/// A record several selected files share is held in memory up to this size.
const MAX_SHARED: u64 = 64 << 20;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("nsis: {message}"))
}

fn le32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// A stored header, whose records say their own method.
    Copy,
    Deflate,
    Bzip2,
    Lzma {
        filter: bool,
    },
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::Copy => "Copy",
            Self::Deflate => "Deflate",
            Self::Bzip2 => "BZip2",
            Self::Lzma { .. } => "LZMA",
        }
    }
}

/// LZMA's properties as NSIS writes them: `lc=3 lp=0 pb=2`, a dictionary of at most 2 GiB.
fn is_lzma(p: &[u8]) -> bool {
    p.len() >= 7 && p[0] == 0x5D && p[1] == 0 && p[2] == 0 && p[5] == 0 && p[6] & 0x80 == 0
}

/// The method of a stream that starts with `p`.
fn sniff(p: &[u8]) -> Method {
    if is_lzma(p) {
        Method::Lzma { filter: false }
    } else if p.len() > 1 && p[0] <= 1 && is_lzma(&p[1..]) {
        Method::Lzma { filter: true }
    } else if p.len() > 1 && p[0] == 0x31 && p[1] < 14 {
        Method::Bzip2
    } else {
        Method::Deflate
    }
}

/// An io error as a BeeZip error: the decoders' own are `Corrupt` already; lzma-rust2's are
/// made so.
fn decode_error(e: &io::Error, what: &str) -> Error {
    let err = crate::io::read_error(e);
    if err.kind == ErrorKind::Io {
        bad(format!("{what} is damaged or cut short ({e})"))
    } else {
        err
    }
}

/// Reads with lzma-rust2's errors made `Corrupt`.
struct Lzma<R>(R);

impl<R: Read> Read for Lzma<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .read(buf)
            .map_err(|e| decode_error(&e, "an LZMA stream").into_io())
    }
}

/// A decoder of `method` over `src`, which starts at the stream's first byte.
fn decoder<'a>(
    method: Method,
    nsis2: bool,
    mut src: Box<dyn Read + 'a>,
    limits: &Limits,
) -> Result<Box<dyn Read + 'a>> {
    Ok(match method {
        Method::Copy => src,
        Method::Deflate => Box::new(inflate::Inflate::new(src, nsis2)),
        Method::Bzip2 => Box::new(bzip2::Bzip2::new(src)),
        Method::Lzma { filter } => {
            let mut head = [0u8; 6];
            let n = if filter { 6 } else { 5 };
            src.read_exact(&mut head[..n])
                .map_err(|_| bad("an LZMA stream is cut short in its properties"))?;
            let (bcj, props) = if filter {
                match head[0] {
                    0 => (false, &head[1..6]),
                    1 => (true, &head[1..6]),
                    f => {
                        return Err(Error::unsupported(format!(
                            "its LZMA stream has the filter byte {f}"
                        )));
                    }
                }
            } else {
                (false, &head[..5])
            };
            let dict = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
            if u64::from(dict) > limits.decoder_memory {
                return Err(Error::limit(format!(
                    "nsis: an LZMA dictionary of {dict} bytes (limit `decoder_memory`)"
                )));
            }
            let mut r = lzma_rust2::LzmaReader::new_with_props(src, u64::MAX, props[0], dict, None)
                .map_err(|e| bad(format!("an LZMA stream's properties are damaged ({e})")))?;
            // What decoded before a cut comes first; the error after.
            r.set_defer_errors(true);
            if bcj {
                Box::new(Lzma(lzma_rust2::filter::bcj::BcjReader::new_x86(r, 0)))
            } else {
                Box::new(Lzma(r))
            }
        }
    })
}

/// Bytes `at..end` of the file, read in order. `strict`: the file ending first is an error
/// (a stored record), not the end (a stream, whose decoder says it's cut short).
struct Section<I> {
    input: I,
    at: u64,
    end: u64,
    strict: bool,
    sought: bool,
}

impl<I: Read + Seek> Section<I> {
    fn new(input: I, at: u64, end: u64, strict: bool) -> Self {
        Self {
            input,
            at,
            end,
            strict,
            sought: false,
        }
    }
}

impl<I: Read + Seek> Read for Section<I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.at >= self.end || buf.is_empty() {
            return Ok(0);
        }
        if !self.sought {
            self.input.seek(SeekFrom::Start(self.at))?;
            self.sought = true;
        }
        let want = buf
            .len()
            .min(usize::try_from(self.end - self.at).unwrap_or(usize::MAX));
        let n = self.input.read(&mut buf[..want])?;
        if n == 0 && self.strict {
            return Err(bad("the installer is cut short").into_io());
        }
        self.at += n as u64;
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

/// Up to `len` bytes of `r`, or the error that stopped them.
fn read_n(r: &mut dyn Read, len: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.take(len).read_to_end(&mut out)?;
    Ok(out)
}

/// The first header.
#[derive(Debug, Clone, Copy)]
struct First {
    /// Where it is in the file: the stub's length.
    at: u64,
    flags: u32,
    header_size: u32,
    /// Everything after the first header, the CRC included.
    arc_size: u32,
}

impl First {
    fn crc(&self) -> bool {
        self.flags & FH_NO_CRC == 0 || self.flags & FH_FORCE_CRC != 0
    }

    /// Where the data ends: the CRC's place, or the end.
    fn end(&self) -> u64 {
        self.at + u64::from(self.arc_size) - if self.crc() { 4 } else { 0 }
    }
}

/// The first header at `at`, if one is there.
fn first_at(input: &mut (impl Read + Seek), at: u64) -> Result<Option<First>> {
    input
        .seek(SeekFrom::Start(at))
        .map_err(|e| Error::io("seeking in the installer", &e))?;
    let mut h = Vec::new();
    input
        .take(FIRST_LEN)
        .read_to_end(&mut h)
        .map_err(|e| Error::io("reading the installer", &e))?;
    if h.len() < FIRST_LEN as usize || h[4..20] != SIGNATURE[..] {
        return Ok(None);
    }
    let flags = le32(&h, 0).unwrap_or(0);
    if flags & !0xF != 0 {
        return Err(Error::unsupported(format!(
            "its first header has flags NSIS doesn't write ({flags:#x})"
        )));
    }
    Ok(Some(First {
        at,
        flags,
        header_size: le32(&h, 20).unwrap_or(0),
        arc_size: le32(&h, 24).unwrap_or(0),
    }))
}

/// The first header, at `hint` (where detection found it) or at the first 512-byte boundary
/// that holds one.
fn find_first(input: &mut CountingReader<Input>, len: u64, hint: u64) -> Result<First> {
    if hint > 0
        && let Some(f) = first_at(input, hint)?
    {
        return Ok(f);
    }
    input
        .seek(SeekFrom::Start(0))
        .map_err(|e| Error::io("seeking in the installer", &e))?;
    let mut buf = vec![0u8; 1 << 20];
    let mut base = 0u64;
    while base < len.min(MAX_SEARCH) {
        let n =
            read_n(input, buf.len() as u64).map_err(|e| Error::io("reading the installer", &e))?;
        buf[..n.len()].copy_from_slice(&n);
        for at in (0..n.len()).step_by(512) {
            if n.get(at + 4..at + 20) == Some(&SIGNATURE[..]) {
                return first_at(input, base + at as u64)?
                    .ok_or_else(|| bad("the first header is cut short"));
            }
        }
        if n.len() < buf.len() {
            break;
        }
        base += n.len() as u64;
    }
    Err(bad("there's no NSIS first header"))
}

/// How the data is laid out.
#[derive(Debug, Clone, Copy)]
struct Layout {
    first: First,
    /// The stream's method (solid), or the header record's (non-solid; `Copy` when stored).
    method: Method,
    solid: bool,
    /// LZMA's dictionary.
    dict: Option<u32>,
    /// Non-solid: where the records start in the file.
    data_at: u64,
    /// Solid deflate: NSIS 2's stored blocks.
    nsis2: bool,
    /// Where the data ends: the CRC's place, or the file's end if it's cut short.
    end: u64,
}

/// What a solid stream's scan found: each record's length by position, or why it's unknown.
type Lengths = BTreeMap<u32, std::result::Result<u32, Error>>;

/// The solid stream after the header, decoded in order, its position counted. It reads the
/// file through a handle of its own.
struct Solid {
    dec: Box<dyn Read>,
    /// Bytes from the records' start.
    at: u64,
    failed: Option<Error>,
}

/// The solid stream, shared by the readers of the files in it.
type Shared = Rc<RefCell<Solid>>;

/// A read from the shared solid stream.
struct Via(Shared);

impl Read for Via {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(buf)
    }
}

impl Solid {
    /// The stream from its start, through `ratio` when given (scans at open), with the header
    /// read: its bytes, `header_size` of them.
    fn open(
        input: CountingReader<Input>,
        l: &Layout,
        nsis2: bool,
        limits: &Limits,
        ratio: Option<&Counter>,
    ) -> Result<(Self, Vec<u8>)> {
        let src = Section::new(input, l.first.at + FIRST_LEN, l.end, false);
        let mut dec = decoder(l.method, nsis2, Box::new(src), limits)?;
        if let Some(c) = ratio {
            dec = Box::new(Guarded::new(
                dec,
                RatioGuard::new(c, limits),
                Budget::default(),
            ));
        }
        let mut s = Self {
            dec,
            at: 0,
            failed: None,
        };
        let mut len = [0u8; 4];
        s.dec
            .read_exact(&mut len)
            .map_err(|e| decode_error(&e, "the header"))?;
        if u32::from_le_bytes(len) != l.first.header_size {
            return Err(bad(
                "the solid stream doesn't start with the header the first header describes",
            ));
        }
        let h = read_n(&mut s.dec, u64::from(l.first.header_size))
            .map_err(|e| decode_error(&e, "the header"))?;
        if h.len() as u64 != u64::from(l.first.header_size) {
            return Err(bad("the header is cut short"));
        }
        Ok((s, h))
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e.clone());
        e
    }

    /// On to `pos`, which must not be behind.
    fn skip_to(&mut self, pos: u32) -> Result<()> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let pos = u64::from(pos);
        if pos < self.at {
            return Err(bad(format!(
                "a file's data at {pos} is inside the one before it"
            )));
        }
        let want = pos - self.at;
        let n = io::copy(&mut (&mut self.dec).take(want), &mut io::sink())
            .map_err(|e| decode_error(&e, "the solid stream"));
        match n {
            Ok(n) => {
                self.at += n;
                if n < want {
                    return Err(self.fail(bad(format!(
                        "the solid stream ends before a file's data at {pos}"
                    ))));
                }
                Ok(())
            }
            Err(e) => Err(self.fail(e)),
        }
    }

    /// A record's length at the current position.
    fn length(&mut self) -> Result<u32> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let mut b = [0u8; 4];
        if let Err(e) = self.dec.read_exact(&mut b) {
            let e = if e.kind() == io::ErrorKind::UnexpectedEof {
                bad("the solid stream ends before a file's data")
            } else {
                decode_error(&e, "the solid stream")
            };
            return Err(self.fail(e));
        }
        self.at += 4;
        Ok(u32::from_le_bytes(b))
    }
}

impl Read for Solid {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.failed {
            return Err(e.clone().into_io());
        }
        match self.dec.read(buf) {
            Ok(n) => {
                self.at += n as u64;
                Ok(n)
            }
            Err(e) => {
                let e = decode_error(&e, "the solid stream");
                self.failed = Some(e.clone());
                Err(e.into_io())
            }
        }
    }
}

/// A record's data in the stream: exactly `len` bytes, or an error.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(bad("a file's data is cut short").into_io());
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Each needed record's length, in one pass over the solid stream.
fn scan_solid(solid: &mut Solid, items: &[Item]) -> Lengths {
    let mut need: BTreeSet<u32> = items
        .iter()
        .filter(|i| i.kind != ItemKind::Empty)
        .map(|i| i.pos)
        .collect();
    let uninstallers: BTreeSet<u32> = items
        .iter()
        .filter(|i| i.kind == ItemKind::Uninstaller { patch: true })
        .map(|i| i.pos)
        .collect();
    let mut out = Lengths::new();
    while let Some(pos) = need.pop_first() {
        let got = solid.skip_to(pos).and_then(|()| solid.length());
        if let Ok(len) = got
            && uninstallers.contains(&pos)
            && let Some(next) = pos.checked_add(4).and_then(|p| p.checked_add(len))
        {
            need.insert(next);
        }
        out.insert(pos, got);
    }
    out
}

/// What the scan at open learnt of a non-solid record.
#[derive(Debug, Clone)]
struct Record {
    /// Its bytes in the file.
    packed: u32,
    compressed: bool,
    method: Method,
    /// Deflate in NSIS 2's form.
    nsis2: bool,
    /// Its decoded length.
    size: u64,
}

/// The open installer, and what reading it needs.
struct Inner {
    /// The file from its start, to open again for a solid stream's own handle.
    whole: Source,
    /// Keeps an installer spooled out of a codec alive, and opens it again.
    spool: Option<Partial>,
    input: CountingReader<Input>,
    counter: Counter,
    len: u64,
    layout: Layout,
    limits: Limits,
    /// Solid: each record's length by position.
    lengths: Lengths,
    /// Non-solid: each record by position, or why it can't be read.
    records: BTreeMap<u32, std::result::Result<Record, Error>>,
}

impl Inner {
    /// Another handle on the file, for a solid stream.
    fn fresh(&self) -> Result<CountingReader<Input>> {
        let input = match &self.spool {
            Some(p) => Input::file(p.reopen()?)?,
            None => self.whole.input()?,
        };
        Ok(CountingReader::new(input, self.counter.clone()))
    }

    /// The solid stream from its start, the header read past.
    fn solid(&self) -> Result<Shared> {
        let (s, _) = Solid::open(
            self.fresh()?,
            &self.layout,
            self.layout.nsis2,
            &self.limits,
            None,
        )?;
        Ok(Rc::new(RefCell::new(s)))
    }

    /// A non-solid record at `pos`: its first word, then what it holds.
    fn record_head(&mut self, pos: u32) -> Result<(u32, bool, Vec<u8>)> {
        let at = self.layout.data_at + u64::from(pos);
        let head = {
            let mut s = Section::new(&mut self.input, at, self.layout.end, true);
            read_n(&mut s, 4 + 8).map_err(|e| crate::io::read_error(&e))?
        };
        let word = le32(&head, 0).ok_or_else(|| {
            bad(format!(
                "the installer is cut short: a file's data at {pos} isn't in it"
            ))
        })?;
        let packed = word & 0x7FFF_FFFF;
        if at + 4 + u64::from(packed) > self.layout.end {
            return Err(bad(format!(
                "a file's data at {pos} runs past the installer's end"
            )));
        }
        Ok((packed, word & 0x8000_0000 != 0, head[4..].to_vec()))
    }

    /// A non-solid record's decoder over its bytes, in the form given.
    fn record_reader(&mut self, pos: u32, r: &Record) -> Result<Box<dyn Read + '_>> {
        let at = self.layout.data_at + u64::from(pos) + 4;
        let end = at + u64::from(r.packed);
        let limits = self.limits.clone();
        let src = Section::new(&mut self.input, at, end, !r.compressed);
        if !r.compressed {
            return Ok(Box::new(src));
        }
        decoder(r.method, r.nsis2, Box::new(src), &limits)
    }

    /// Decodes a compressed record whole, counting it, in the form asked: its length, if it
    /// ends at the record's end.
    fn measure(&mut self, pos: u32, packed: u32, method: Method, nsis2: bool) -> Result<u64> {
        let at = self.layout.data_at + u64::from(pos) + 4;
        let end = at + u64::from(packed);
        let limits = self.limits.clone();
        let counter = self.counter.clone();
        let src = Section::new(&mut self.input, at, end, false);
        let mut sink = io::sink();
        let ratio = RatioGuard::new(&counter, &limits);
        match method {
            Method::Deflate => {
                let mut d = inflate::Inflate::new(src, nsis2);
                let n = io::copy(
                    &mut Guarded::new(&mut d, ratio, Budget::default()),
                    &mut sink,
                )
                .map_err(|e| crate::io::read_error(&e))?;
                if !d.done() || d.consumed() != u64::from(packed) {
                    return Err(bad(format!(
                        "a file's deflate stream at {pos} doesn't end at its record's end"
                    )));
                }
                Ok(n)
            }
            Method::Bzip2 => {
                let mut d = bzip2::Bzip2::new(src);
                let n = io::copy(
                    &mut Guarded::new(&mut d, ratio, Budget::default()),
                    &mut sink,
                )
                .map_err(|e| crate::io::read_error(&e))?;
                if !d.done() {
                    return Err(bad(format!("a file's bzip2 stream at {pos} has no end")));
                }
                Ok(n)
            }
            Method::Lzma { .. } | Method::Copy => {
                let d = decoder(method, nsis2, Box::new(src), &limits)?;
                io::copy(&mut Guarded::new(d, ratio, Budget::default()), &mut sink)
                    .map_err(|e| crate::io::read_error(&e))
            }
        }
    }

    /// A non-solid record, scanned: its length, method and form.
    fn scan_record(&mut self, pos: u32) -> Result<Record> {
        let (packed, compressed, head) = self.record_head(pos)?;
        if !compressed {
            return Ok(Record {
                packed,
                compressed,
                method: Method::Copy,
                nsis2: false,
                size: u64::from(packed),
            });
        }
        let method = match self.layout.method {
            Method::Copy => sniff(&head),
            m => m,
        };
        let size = match self.measure(pos, packed, method, false) {
            Ok(n) => (n, false),
            Err(e) if method == Method::Deflate && e.kind == ErrorKind::Corrupt => {
                // NSIS 2's form, which must end at the record's end too.
                (
                    self.measure(pos, packed, method, true).map_err(|_| e)?,
                    true,
                )
            }
            Err(e) => return Err(e),
        };
        Ok(Record {
            packed,
            compressed,
            method,
            nsis2: size.1,
            size: size.0,
        })
    }

    /// Every needed record of a non-solid installer.
    fn scan_records(&mut self, items: &[Item], cx: &mut dyn Ctx) -> Result<()> {
        let mut need: BTreeSet<u32> = items
            .iter()
            .filter(|i| i.kind != ItemKind::Empty)
            .map(|i| i.pos)
            .collect();
        let uninstallers: BTreeSet<u32> = items
            .iter()
            .filter(|i| i.kind == ItemKind::Uninstaller { patch: true })
            .map(|i| i.pos)
            .collect();
        while let Some(pos) = need.pop_first() {
            cx.check()?;
            let got = self.scan_record(pos);
            match &got {
                Err(e) if e.kind == ErrorKind::LimitExceeded => return Err(e.clone()),
                Err(e) if e.kind == ErrorKind::UnsupportedOperation => return Err(e.clone()),
                Ok(r) if uninstallers.contains(&pos) => {
                    if let Some(next) = pos.checked_add(4).and_then(|p| p.checked_add(r.packed)) {
                        need.insert(next);
                    }
                }
                _ => {}
            }
            self.records.insert(pos, got);
        }
        Ok(())
    }

    /// A non-solid record as the scan found it.
    fn record(&self, pos: u32) -> Result<Record> {
        self.records
            .get(&pos)
            .cloned()
            .unwrap_or_else(|| Err(bad(format!("no file's data at {pos}"))))
    }

    /// The length of the record at `pos`, and where the next one is.
    fn record_len(&self, pos: u32) -> Result<(u64, u32)> {
        if self.layout.solid {
            let len = self
                .lengths
                .get(&pos)
                .cloned()
                .unwrap_or_else(|| Err(bad(format!("no file's data at {pos}"))))?;
            let next = pos
                .checked_add(4)
                .and_then(|p| p.checked_add(len))
                .ok_or_else(|| bad("a file's data runs past 4 GiB"))?;
            Ok((u64::from(len), next))
        } else {
            let r = self
                .records
                .get(&pos)
                .cloned()
                .unwrap_or_else(|| Err(bad(format!("no file's data at {pos}"))))?;
            let next = pos
                .checked_add(4)
                .and_then(|p| p.checked_add(r.packed))
                .ok_or_else(|| bad("a file's data runs past 4 GiB"))?;
            Ok((r.size, next))
        }
    }

    /// An item's size: its record's, or the stub's and the uninstaller's.
    fn size(&self, it: &Item) -> Option<u64> {
        match it.kind {
            ItemKind::Empty => Some(0),
            ItemKind::File => self.record_len(it.pos).ok().map(|r| r.0),
            ItemKind::Uninstaller { patch } => {
                let data = if patch {
                    self.record_len(it.pos).ok()?.1
                } else {
                    it.pos
                };
                Some(self.layout.first.at + self.record_len(data).ok()?.0)
            }
        }
    }

    /// The stub, read whole for an uninstaller.
    fn stub(&mut self) -> Result<Vec<u8>> {
        let len = self.layout.first.at;
        if len > MAX_STUB {
            return Err(bad(format!(
                "the installer's stub of {len} bytes is too large to rebuild its uninstaller"
            )));
        }
        let mut s = Section::new(&mut self.input, 0, len, true);
        read_n(&mut s, len).map_err(|e| crate::io::read_error(&e))
    }

    /// The installer's CRC, when it has one: `Ok(false)` without.
    fn check_crc(&mut self, cx: &mut dyn Ctx) -> Result<bool> {
        let f = self.layout.first;
        if !f.crc() {
            return Ok(false);
        }
        let end = f.end();
        if end + 4 > self.len {
            return Err(bad(format!(
                "the installer is cut short: {} of its {} bytes",
                self.len,
                end + 4
            )));
        }
        // NSIS's loader leaves out the first 512 bytes, which hold the first header only in a
        // bare installer.
        let start = if f.at == 0 { 0 } else { 512.min(end) };
        let mut h = crc32fast::Hasher::new();
        let mut s = Section::new(&mut self.input, start, end + 4, true);
        let mut buf = vec![0u8; 256 * 1024];
        let mut left = end - start;
        while left > 0 {
            cx.check()?;
            let n = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            s.read_exact(&mut buf[..n])
                .map_err(|e| crate::io::read_error(&e))?;
            h.update(&buf[..n]);
            left -= n as u64;
        }
        let mut stored = [0u8; 4];
        s.read_exact(&mut stored)
            .map_err(|e| crate::io::read_error(&e))?;
        if h.finalize() != u32::from_le_bytes(stored) {
            return Err(bad("the installer's CRC doesn't match: it's damaged"));
        }
        Ok(true)
    }
}

/// Patches the stub as `WriteUninstaller` does: records of a length, an offset and bytes, up to
/// a length of 0.
fn patch(stub: &mut [u8], patches: &[u8]) -> Result<()> {
    let mut p = patches;
    while p.len() >= 4 {
        let len = le32(p, 0).unwrap_or(0) as usize;
        if len == 0 {
            break;
        }
        let off = le32(p, 4).ok_or_else(|| bad("an uninstaller's patch is cut short"))? as usize;
        let bytes = p
            .get(8..8usize.saturating_add(len))
            .ok_or_else(|| bad("an uninstaller's patch is cut short"))?;
        stub.get_mut(off..off.saturating_add(len))
            .ok_or_else(|| bad("an uninstaller's patch is outside the stub"))?
            .copy_from_slice(bytes);
        p = &p[8 + len..];
    }
    Ok(())
}

/// The first header's layout: the method from the bytes after it, and solid or not.
fn layout(
    input: &mut CountingReader<Input>,
    len: u64,
    first: First,
    limits: &Limits,
) -> Result<Layout> {
    if first.header_size > MAX_HEADER {
        return Err(bad(format!(
            "a header of {} bytes (at most {MAX_HEADER} are read)",
            first.header_size
        )));
    }
    if u64::from(first.arc_size) < FIRST_LEN + 4 {
        return Err(bad(format!(
            "the first header says the data is {} bytes",
            first.arc_size
        )));
    }
    let end = first.end().min(len);
    let body = {
        let mut s = Section::new(input, first.at + FIRST_LEN, end, false);
        read_n(&mut s, 16).map_err(|e| Error::io("reading the installer", &e))?
    };
    if body.len() < 12 {
        return Err(bad("the installer is cut short after its first header"));
    }
    let word = le32(&body, 0).unwrap_or(0);
    let (method, solid) = if word == first.header_size {
        (Method::Copy, false)
    } else if word & 0x8000_0000 != 0 && sniff(&body[4..]) != Method::Deflate {
        (sniff(&body[4..]), false)
    } else if sniff(&body) != Method::Deflate {
        (sniff(&body), true)
    } else if body[3] == 0x80 {
        // A compressed header record of under 16 MiB: deflate, non-solid.
        (Method::Deflate, false)
    } else {
        (Method::Deflate, true)
    };
    let dict = match method {
        Method::Lzma { filter } => {
            let p = if solid { &body[..] } else { &body[4..] };
            le32(p, 1 + usize::from(filter))
        }
        _ => None,
    };
    if let Some(d) = dict
        && u64::from(d) > limits.decoder_memory
    {
        return Err(Error::limit(format!(
            "nsis: an LZMA dictionary of {d} bytes (limit `decoder_memory`)"
        )));
    }
    let data_at = if solid {
        0
    } else {
        first.at + FIRST_LEN + 4 + u64::from(word & 0x7FFF_FFFF)
    };
    Ok(Layout {
        first,
        method,
        solid,
        dict,
        data_at,
        nsis2: false,
        end,
    })
}

/// A non-solid installer's header.
fn header_record(inner: &mut Inner) -> Result<Vec<u8>> {
    let l = inner.layout;
    let at = l.first.at + FIRST_LEN;
    let word = {
        let mut s = Section::new(&mut inner.input, at, l.end, true);
        let mut b = [0u8; 4];
        s.read_exact(&mut b)
            .map_err(|e| crate::io::read_error(&e))?;
        u32::from_le_bytes(b)
    };
    let packed = word & 0x7FFF_FFFF;
    let start = at + 4;
    let stop = start + u64::from(packed);
    if stop > l.end {
        return Err(bad("the installer is cut short in its header"));
    }
    let want = u64::from(l.first.header_size);
    let read = |inner: &mut Inner, nsis2: bool| -> Result<Vec<u8>> {
        let limits = inner.limits.clone();
        let src = Section::new(&mut inner.input, start, stop, word & 0x8000_0000 == 0);
        let method = if word & 0x8000_0000 == 0 {
            Method::Copy
        } else {
            l.method
        };
        let mut d = decoder(method, nsis2, Box::new(src), &limits)?;
        let h = read_n(&mut d, want).map_err(|e| decode_error(&e, "the header"))?;
        if h.len() as u64 != want {
            return Err(bad("the header is cut short"));
        }
        Ok(h)
    };
    match read(inner, false) {
        Err(e) if l.method == Method::Deflate && e.kind == ErrorKind::Corrupt => {
            read(inner, true).map_err(|_| e)
        }
        other => other,
    }
}

pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(NsisReader::open(source, cx)?))
}

pub struct NsisReader {
    source: Source,
    inner: Inner,
    parsed: Parsed,
    entries: Vec<Entry>,
    methods: Vec<Cow<'static, str>>,
    properties: Vec<LevelProperty>,
}

impl NsisReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        // The whole file: the stub before the first header is the uninstaller's, and the CRC
        // starts in it.
        let mut whole = source.clone();
        whole.offset = 0;
        let (input, spool) = if source.codecs.is_empty() {
            (whole.input()?, None)
        } else {
            let mut tmp = Partial::create_temp("beezip-spool.exe")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            (Input::file(tmp.reopen()?)?, Some(tmp))
        };
        let len = input.len();
        let mut input = CountingReader::new(input, source.counter.clone());
        let first = find_first(&mut input, len, source.offset)?;
        let limits = source.limits.clone();
        let mut layout = layout(&mut input, len, first, &limits)?;
        let mut inner = Inner {
            whole,
            spool,
            input,
            counter: source.counter.clone(),
            len,
            layout,
            limits: limits.clone(),
            lengths: Lengths::new(),
            records: BTreeMap::new(),
        };
        let max_entries = limits.max_entries.unwrap_or(u64::MAX);

        let parsed = if layout.solid {
            // zlib's deflate first; NSIS 2's where that fails, whichever reads further.
            let scan = |inner: &mut Inner, nsis2: bool| -> Result<(Parsed, Lengths)> {
                let counter = inner.counter.clone();
                let (mut s, h) =
                    Solid::open(inner.fresh()?, &layout, nsis2, &limits, Some(&counter))?;
                let parsed = header::parse(&h, max_entries)?;
                let lengths = scan_solid(&mut s, &parsed.items);
                if let Some(e) = s.failed.take()
                    && e.kind == ErrorKind::LimitExceeded
                {
                    return Err(e);
                }
                Ok((parsed, lengths))
            };
            let known = |l: &Lengths| l.values().filter(|v| v.is_ok()).count();
            let mut got = scan(&mut inner, false);
            if layout.method == Method::Deflate {
                let failed = match &got {
                    Err(e) => e.kind == ErrorKind::Corrupt,
                    Ok((_, l)) => l.values().any(Result::is_err),
                };
                if failed && let Ok(other) = scan(&mut inner, true) {
                    let better = match &got {
                        Err(_) => true,
                        Ok((_, l)) => known(&other.1) > known(l),
                    };
                    if better {
                        got = Ok(other);
                        layout.nsis2 = true;
                        inner.layout.nsis2 = true;
                    }
                }
            }
            let (parsed, lengths) = got?;
            inner.lengths = lengths;
            parsed
        } else {
            let h = header_record(&mut inner)?;
            let parsed = header::parse(&h, max_entries)?;
            inner.scan_records(&parsed.items, cx)?;
            parsed
        };

        // The entries.
        let names = source.names;
        let unicode = parsed.strings.unicode();
        let mut entries = Vec::with_capacity(parsed.items.len());
        let mut methods: Vec<Cow<'static, str>> = Vec::new();
        let stream_method: Cow<'static, str> = match (layout.method, layout.dict) {
            (Method::Lzma { .. }, Some(d)) if d.is_power_of_two() => {
                Cow::Owned(format!("LZMA:{}", d.trailing_zeros()))
            }
            (m, _) => Cow::Borrowed(m.name()),
        };
        for it in &parsed.items {
            let mut name = if unicode {
                String::from_utf8_lossy(&it.name).into_owned()
            } else {
                names.decode(&it.name, false, SystemPage::Ansi)
            };
            let mut raw = it.name.clone();
            if let ItemKind::Uninstaller { patch: true } = it.kind
                && layout.first.at == 0
            {
                // No stub to rebuild it with: the uninstaller's data only, as 7-Zip names it.
                name.push_str(".nsis");
                raw.extend_from_slice(b".nsis");
            }
            let mut e = Entry::new(entries.len(), name, EntryKind::File);
            e.raw_path = raw;
            e.size = inner.size(it);
            e.modified = it.mtime.and_then(from_ntfs);
            e.dos_attrs = it.attrib;
            e.method = match it.kind {
                ItemKind::Empty => None,
                _ if layout.solid => Some(stream_method.clone()),
                _ => match inner.records.get(&it.pos) {
                    Some(Ok(r)) if !r.compressed => Some(Cow::Borrowed("Copy")),
                    Some(Ok(r)) => Some(Cow::Borrowed(r.method.name())),
                    _ => None,
                },
            };
            if !layout.solid
                && it.kind == ItemKind::File
                && let Some(Ok(r)) = inner.records.get(&it.pos)
            {
                e.packed_size = Some(u64::from(r.packed));
            }
            if let Some(m) = &e.method
                && !methods.contains(m)
            {
                methods.push(m.clone());
            }
            entries.push(e);
        }

        let mut properties = Vec::new();
        let mut prop = |name: &str, value: String| {
            properties.push(LevelProperty {
                level: "nsis".to_owned(),
                name: name.to_owned(),
                value,
            });
        };
        prop("Version", parsed.strings.describe().to_owned());
        prop(
            "Kind",
            if layout.first.flags & FH_UNINSTALL != 0 {
                "uninstaller"
            } else {
                "installer"
            }
            .to_owned(),
        );
        let method = match (layout.method, layout.dict) {
            (Method::Lzma { filter }, d) => {
                let mut m = "LZMA".to_owned();
                if let Some(d) = d {
                    m.push_str(&format!(", {} dictionary", size_name(u64::from(d))));
                }
                if filter {
                    m.push_str(", x86 filter");
                }
                m
            }
            (Method::Copy, _) => "a stored header, each file's own".to_owned(),
            (Method::Deflate, _) if layout.nsis2 => "Deflate (NSIS 2's)".to_owned(),
            (m, _) => m.name().to_owned(),
        };
        prop("Method", method);
        if parsed.is64 {
            prop("Target", "64-bit".to_owned());
        }
        prop("Header", size_name(u64::from(layout.first.header_size)));
        prop("Instructions", parsed.instructions.to_string());
        prop("Stub", format!("{} bytes", layout.first.at));
        prop(
            "Checksum",
            if layout.first.crc() {
                "CRC-32 of the installer"
            } else {
                "none"
            }
            .to_owned(),
        );
        Ok(Self {
            source,
            inner,
            parsed,
            entries,
            methods,
            properties,
        })
    }

    /// A reader of an item's data: from `solid`, the shared stream, in a solid installer.
    fn data<'a>(
        inner: &'a mut Inner,
        it: &Item,
        solid: Option<&Shared>,
    ) -> Result<Box<dyn Read + 'a>> {
        match it.kind {
            ItemKind::Empty => Ok(Box::new(io::empty())),
            ItemKind::File => match solid {
                Some(s) => {
                    let len = {
                        let mut s = s.borrow_mut();
                        s.skip_to(it.pos)?;
                        s.length()?
                    };
                    Ok(Box::new(Exact {
                        inner: Via(s.clone()),
                        left: u64::from(len),
                    }))
                }
                None => {
                    let r = inner.record(it.pos)?;
                    let size = r.size;
                    let d = inner.record_reader(it.pos, &r)?;
                    Ok(Box::new(Exact {
                        inner: d,
                        left: size,
                    }))
                }
            },
            ItemKind::Uninstaller { patch: has_patch } => {
                let mut stub = inner.stub()?;
                let data_pos = if has_patch {
                    let (len, next) = inner.record_len(it.pos)?;
                    if len > MAX_PATCH {
                        return Err(bad(format!("an uninstaller's patch of {len} bytes")));
                    }
                    let patches = match solid {
                        Some(s) => {
                            let mut s = s.borrow_mut();
                            s.skip_to(it.pos)?;
                            s.length()?;
                            read_n(&mut *s, len).map_err(|e| crate::io::read_error(&e))?
                        }
                        None => {
                            let r = inner.record(it.pos)?;
                            let mut d = inner.record_reader(it.pos, &r)?;
                            read_n(&mut d, len).map_err(|e| crate::io::read_error(&e))?
                        }
                    };
                    if patches.len() as u64 != len {
                        return Err(bad("an uninstaller's patch is cut short"));
                    }
                    // A bare installer has no stub to patch: the uninstaller's data alone.
                    if !stub.is_empty() {
                        patch(&mut stub, &patches)?;
                    }
                    next
                } else {
                    it.pos
                };
                let (len, _) = inner.record_len(data_pos)?;
                let data: Box<dyn Read + 'a> = match solid {
                    Some(s) => {
                        {
                            let mut s = s.borrow_mut();
                            s.skip_to(data_pos)?;
                            s.length()?;
                        }
                        Box::new(Via(s.clone()))
                    }
                    None => {
                        let r = inner.record(data_pos)?;
                        inner.record_reader(data_pos, &r)?
                    }
                };
                Ok(Box::new(io::Cursor::new(stub).chain(Exact {
                    inner: data,
                    left: len,
                })))
            }
        }
    }
}

fn size_name(n: u64) -> String {
    if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
        format!("{} MiB", n >> 20)
    } else if n >= 1024 {
        format!("{} KiB", n.div_ceil(1024))
    } else {
        format!("{n} bytes")
    }
}

impl ArchiveReader for NsisReader {
    fn format(&self) -> FormatId {
        FormatId::External(External::Nsis)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::External(External::Nsis),
            codecs: self.source.codecs.clone(),
            methods: self.methods.clone(),
            comment: None,
            encryption: Encryption::None,
            solid: self.inner.layout.solid,
            sfx: self.inner.layout.first.at > 0,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: Some(ExternalInfo {
                backend: None,
                levels: vec!["nsis".to_owned()],
                properties: self.properties.clone(),
                notes: Vec::new(),
            }),
        })
    }

    /// In listing order, which is data order: a solid stream decodes once, forwards, and a
    /// record that several selected files name is decoded once for them all.
    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let selected: Vec<usize> = (0..self.entries.len())
            .filter(|&id| sel.matches(&self.entries[id]))
            .collect();
        if let Some(fs) = sink.as_fs_sink() {
            fs.write_behind(self.source.threads);
        }
        self.source.counter.set(0);
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.inner.len));
        meter.entries_total = Some(selected.len() as u64);
        let mut shared: BTreeMap<u32, usize> = BTreeMap::new();
        for &id in &selected {
            let it = &self.parsed.items[id];
            if it.kind == ItemKind::File {
                *shared.entry(it.pos).or_default() += 1;
            }
        }
        let mut held: Option<(u32, Vec<u8>)> = None;
        let mut solid: Option<Shared> = None;
        for (done, &id) in selected.iter().enumerate() {
            cx.check()?;
            meter.entries_done = done as u64;
            meter.current = Some(self.entries[id].path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            let it = self.parsed.items[id].clone();
            let entry = &self.entries[id];
            if let Some((pos, data)) = &held
                && it.kind == ItemKind::File
                && *pos == it.pos
            {
                let mut data = self.source.guard(data.as_slice());
                sink.entry(entry, &mut data, &mut mcx)?;
                continue;
            }
            held = None;
            if self.inner.layout.solid && it.kind != ItemKind::Empty {
                // A record behind the stream's position (a large one shared): from the start.
                if solid
                    .as_ref()
                    .is_some_and(|s| s.borrow().at > u64::from(it.pos))
                {
                    solid = None;
                }
                if solid.is_none() {
                    match self.inner.solid() {
                        Ok(s) => solid = Some(s),
                        Err(e) => {
                            sink.entry(entry, &mut Failing(e), &mut mcx)?;
                            continue;
                        }
                    }
                }
            }
            let data = match Self::data(&mut self.inner, &it, solid.as_ref()) {
                Ok(d) => d,
                Err(e) => Box::new(Failing(e)),
            };
            let share = shared.get(&it.pos).copied().unwrap_or(0) > 1
                && it.kind == ItemKind::File
                && entry.size.is_some_and(|n| n <= MAX_SHARED);
            if share {
                let mut data = data;
                let mut buf = Vec::new();
                let got = data.read_to_end(&mut buf);
                drop(data);
                match got {
                    Ok(_) => {
                        let mut r = self.source.guard(buf.as_slice());
                        sink.entry(entry, &mut r, &mut mcx)?;
                        held = Some((it.pos, buf));
                    }
                    Err(e) => {
                        sink.entry(entry, &mut Failing(crate::io::read_error(&e)), &mut mcx)?;
                    }
                }
                continue;
            }
            let mut data = self.source.guard(data);
            sink.entry(entry, &mut data, &mut mcx)?;
        }
        meter.entries_done = selected.len() as u64;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    /// One file: in a solid installer, decoded from the stream's start up to it.
    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let it = self
            .parsed
            .items
            .get(id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        self.source.counter.set(0);
        let solid = if self.inner.layout.solid && it.kind != ItemKind::Empty {
            Some(self.inner.solid()?)
        } else {
            None
        };
        let data = Self::data(&mut self.inner, &it, solid.as_ref())?;
        Ok(Box::new(self.source.guard(data)))
    }

    /// The installer's CRC, then every file decoded (docs/M10.md §4.4).
    fn test(&mut self, cx: &mut dyn Ctx) -> Option<Result<TestReport>> {
        let mut sink = TestSink::default();
        let crc = match self.inner.check_crc(cx) {
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
                    "This installer was built without its CRC (`CRCCheck off`), so the test \
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
