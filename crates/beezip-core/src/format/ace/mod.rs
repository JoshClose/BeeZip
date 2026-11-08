//! ACE 1.0 and 2.0 (docs/M6.md §4), read only. BeeZip's own reader, taken in from unarc-rs
//! 0.8.1's `ace` module (Copyright (c) Mike Krüger, MIT), itself a port of acefile (Copyright
//! (c) 2017-2026, Daniel Roethlisberger and contributors, BSD-2-Clause: its full notice is in
//! `LICENSE-acefile` beside this file). Checked against acefile 0.6.14 and unace 2.5, run in
//! Docker as oracles only.
//!
//! - **The layout:** a main header (`**ACE**` at byte 7), then a header per file followed by its
//!   data, and maybe a recovery record. Every header carries a CRC-16, checked before any field
//!   is read, and every field is bounded by the header's size. A file cut short is listed as far
//!   as it goes; the entry it cuts fails when read.
//! - **Methods:** stored, ACE 1.0's LZ77, and ACE 2.0's LZ77 with modes. ACE 2.0's EXE, DELTA,
//!   SOUND and PIC modes are refused (`UnsupportedOperation`) when an entry reaches one, not
//!   decoded (docs/M6.md §14); listing doesn't need them. Entries are decoded into the sink as
//!   they're read, through a dictionary of at most 4 MiB, and each one's CRC-32 is checked at its
//!   end. A solid archive's entries share the dictionary, so reaching one decodes those before;
//!   in any other archive each entry starts with an empty one, as in unace.
//! - **Names** are bytes in the OEM code page, read through the source's `NameDecoding`, then
//!   `\` becomes `/`; a NUL ends a name, as in acefile. Times are DOS local times.
//! - **Volumes** (`x.ace`, `x.c00`, `x.c01`…): the reader opens the set's later parts itself,
//!   and an entry split between parts decodes across them. An entry that goes on in a part
//!   that isn't there is listed, and fails when read.
//! - **Passwords:** ACE's own Blowfish ([`blowfish`], [`crypt`]). ACE can't tell a wrong
//!   password from damaged data, so either is "wrong password or damaged data"
//!   (`WrongPassword`), and the entry is tried again with the next password the context gives,
//!   up to `MAX_PASSWORD_TRIES`. The one that worked is tried first on the next entry.
//!
//! How it differs from unarc-rs: entries stream instead of being decoded into a `Vec` each;
//! names keep their OEM bytes; the dictionary size is `1 << (bits + 10)`, as in acefile; file
//! headers of type 3 are 64-bit files, not recovery records; the password flag is bit 14; the
//! key is ACE's, not plain SHA-1's, the S-boxes ACE's and the blocks little-endian; ACE 2.0's
//! other modes are refused rather than skipped; headers are bounds-checked.

mod bits;
mod blowfish;
mod crypt;
mod header;
mod huffman;
mod lz77;

use std::{
    borrow::Cow,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
};

use crypt::Decrypt;
#[doc(hidden)]
pub use crypt::encrypt;
use header::{
    ATTR_DIRECTORY, COMP_BLOCKED, COMP_LZ77, COMP_STORED, FLAG_CONTNEXT, FLAG_CONTPREV,
    FLAG_LOCKED, FLAG_MULTIVOLUME, FLAG_PASSWORD, FLAG_RECOVERY, FLAG_SOLID, FileHeader, Header,
    MainHeader, bad,
};
use lz77::{Dictionary, Lz77, Stop};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    ctx::MAX_PASSWORD_TRIES,
    detect::{Confidence, Probe},
    io::{drain, read_error},
    limits::{Budget, Guarded, RatioGuard},
    names::{NameDecoding, SystemPage},
    source::Source,
    time::{DosClock, DosTime},
};

pub struct Ace;

impl ArchiveFormat for Ace {
    fn id(&self) -> FormatId {
        FormatId::Ace
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".ace", ".cba"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        header_at(probe.head)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            volumes: true,
            ..FormatCaps::default()
        }
    }
}

/// An ACE main header at the start of `head`: certain when its CRC-16 holds, likely on
/// `**ACE**` alone.
pub fn header_at(head: &[u8]) -> Option<Confidence> {
    header::main_header_at(head).map(|ok| {
        if ok {
            Confidence::Certain
        } else {
            Confidence::Likely
        }
    })
}

fn method_name(method: u8) -> &'static str {
    match method {
        COMP_STORED => "Store",
        COMP_LZ77 => "ACE 1.0",
        COMP_BLOCKED => "ACE 2.0",
        _ => "Unknown",
    }
}

fn wrong_password(path: &str) -> Error {
    Error::new(
        ErrorKind::WrongPassword,
        format!("ace: `{path}`: wrong password or damaged data"),
    )
}

/// Errors that end a pass, not just the entry they happen in.
fn fatal(e: &Error) -> bool {
    !matches!(
        e.kind,
        ErrorKind::Corrupt | ErrorKind::UnsupportedOperation | ErrorKind::UnsupportedFormat
    )
}

/// A stretch of an entry's packed data: in which part of the set, where, how long.
#[derive(Debug, Clone, Copy)]
struct Segment {
    part: usize,
    offset: u64,
    len: u64,
}

/// What reading an entry takes, besides its [`Entry`].
#[derive(Debug, Clone)]
struct EntryAt {
    segments: Vec<Segment>,
    method: u8,
    dict_size: usize,
    size: u64,
    /// ACE's CRC-32, from the entry's last header.
    crc: u32,
    encrypted: bool,
    /// Why the entry can't be read: a part of the set it needs isn't there, or the file is cut
    /// short.
    unreadable: Option<Error>,
}

/// What comes next in a part.
enum Next {
    Header(Vec<u8>),
    End,
    /// The file ends inside a header.
    Cut,
}

trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

enum PartReader {
    Seek(BufReader<Box<dyn ReadSeek>>),
    /// The archive inside a codec, read forward only.
    Stream(Box<dyn Read + Send>),
}

/// The archive's bytes, one part of the set at a time. Reads are counted in the source's
/// counter as the parts' places in the whole set, for progress and the ratio limit.
struct Parts {
    source: Source,
    /// Each part's size; unknown in a decoded stream.
    lens: Vec<Option<u64>>,
    starts: Vec<u64>,
    cur: Option<(usize, PartReader)>,
    /// The position in the current part.
    pos: u64,
}

impl Parts {
    fn new(source: &Source, lens: &[Option<u64>]) -> Self {
        let mut starts = Vec::with_capacity(lens.len());
        let mut at = 0u64;
        for len in lens {
            starts.push(at);
            at = at.saturating_add(len.unwrap_or(0));
        }
        Self {
            source: source.clone(),
            lens: lens.to_vec(),
            starts,
            cur: None,
            pos: 0,
        }
    }

    /// The sizes of the first `parts` parts of `source`: the input's own size for the first
    /// (the whole joined set for a numbered split), each file's for the rest.
    fn sizes(source: &Source, parts: usize) -> Result<Vec<Option<u64>>> {
        if !source.codecs.is_empty() {
            return Ok(vec![None]);
        }
        let mut lens = vec![Some(source.input()?.len())];
        for p in source.volumes.iter().take(parts).skip(1) {
            let meta = std::fs::metadata(p)
                .map_err(|e| Error::io(format!("opening {}", p.display()), &e))?;
            lens.push(Some(meta.len()));
        }
        Ok(lens)
    }

    fn name(&self, part: usize) -> String {
        self.source
            .volumes
            .get(part)
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.source.file_name())
    }

    fn open(&self, part: usize) -> Result<PartReader> {
        if !self.source.codecs.is_empty() {
            return Ok(PartReader::Stream(self.source.open_stream()?));
        }
        let r: Box<dyn ReadSeek> = if part == 0 {
            Box::new(self.source.input()?)
        } else {
            let p = self
                .source
                .volumes
                .get(part)
                .ok_or_else(|| bad("a part past the end of the set"))?;
            Box::new(File::open(p).map_err(|e| Error::io(format!("opening {}", p.display()), &e))?)
        };
        Ok(PartReader::Seek(BufReader::with_capacity(64 * 1024, r)))
    }

    /// Goes to `offset` in `part`. A stream is read forward to it, or opened again to go back.
    fn seek(&mut self, part: usize, offset: u64) -> Result<()> {
        let reopen = match &self.cur {
            Some((p, PartReader::Stream(_))) => *p != part || offset < self.pos,
            Some((p, PartReader::Seek(_))) => *p != part,
            None => true,
        };
        if reopen {
            self.cur = Some((part, self.open(part)?));
            self.pos = 0;
        }
        let Some((_, r)) = &mut self.cur else {
            return Err(bad("no part open"));
        };
        match r {
            PartReader::Seek(f) => {
                if offset != self.pos {
                    let moved = match i64::try_from(i128::from(offset) - i128::from(self.pos)) {
                        Ok(d) => f.seek_relative(d),
                        Err(_) => f.seek(SeekFrom::Start(offset)).map(drop),
                    };
                    moved.map_err(|e| Error::io("seeking in the archive", &e))?;
                }
                let start = self.starts.get(part).copied().unwrap_or(0);
                self.source.counter.set(start.saturating_add(offset));
            }
            PartReader::Stream(s) => {
                let skip = offset - self.pos;
                let n = io::copy(&mut s.take(skip), &mut io::sink()).map_err(|e| read_error(&e))?;
                if n != skip {
                    return Err(bad("the archive is cut short"));
                }
            }
        }
        self.pos = offset;
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = match &mut self.cur {
            Some((_, PartReader::Seek(f))) => {
                let n = f.read(buf)?;
                self.source.counter.add(n as u64);
                n
            }
            Some((_, PartReader::Stream(s))) => s.read(buf)?,
            None => 0,
        };
        self.pos += n as u64;
        Ok(n)
    }

    /// Fills `buf` as far as the part goes; returns how much it got.
    fn read_full(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut got = 0;
        while got < buf.len() {
            match self.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(read_error(&e)),
            }
        }
        Ok(got)
    }

    /// The next header's bytes, its CRC-16 checked.
    fn header(&mut self, part: usize) -> Result<Next> {
        let at = self.pos;
        if self
            .lens
            .get(part)
            .copied()
            .flatten()
            .is_some_and(|len| at >= len)
        {
            return Ok(Next::End);
        }
        let mut head = [0u8; 4];
        match self.read_full(&mut head)? {
            0 if self.lens.get(part).copied().flatten().is_none() => return Ok(Next::End),
            4 => {}
            _ => return Ok(Next::Cut),
        }
        let crc = u16::from_le_bytes([head[0], head[1]]);
        let mut body = vec![0u8; usize::from(u16::from_le_bytes([head[2], head[3]]))];
        if self.read_full(&mut body)? < body.len() {
            return Ok(Next::Cut);
        }
        if header::crc16(&body) != crc {
            return Err(self.at(part, at, "the header fails its CRC-16"));
        }
        Ok(Next::Header(body))
    }

    fn at(&self, part: usize, at: u64, what: &str) -> Error {
        bad(format!("{}, byte {at}: {what}", self.name(part)))
    }

    /// Where `n` bytes of data from here end, which must be within the part (header at `start`).
    fn data_end(&self, part: usize, start: u64, n: u64) -> Result<u64> {
        let len = self.lens.get(part).copied().flatten();
        match (self.pos.checked_add(n), len) {
            (Some(end), Some(len)) if end <= len => Ok(end),
            (Some(end), None) => Ok(end),
            _ => Err(self.at(part, start, "its data runs past the end of the file")),
        }
    }
}

/// An entry's packed bytes, across the parts they're in.
struct Packed<'a> {
    parts: &'a mut Parts,
    segments: &'a [Segment],
    next: usize,
    left: u64,
}

impl Read for Packed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.left == 0 {
            let Some(s) = self.segments.get(self.next) else {
                return Ok(0);
            };
            self.parts.seek(s.part, s.offset).map_err(Error::into_io)?;
            self.left = s.len;
            self.next += 1;
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.parts.read(&mut buf[..want])?;
        if n == 0 && want > 0 {
            return Err(bad("the archive is cut short").into_io());
        }
        self.left -= n as u64;
        Ok(n)
    }
}

enum Body<'a> {
    Stored {
        src: Box<dyn Read + 'a>,
        /// A solid archive's dictionary, which stored entries feed too.
        dict: Option<&'a mut Dictionary>,
    },
    Lz77 {
        lz: Box<Lz77<Box<dyn Read + 'a>>>,
        dict: &'a mut Dictionary,
    },
    /// Nothing to read: the entry fails with the error already set.
    None,
}

/// An entry's data, decoded, its CRC-32 checked at the end. An error is given again on every
/// read after it.
struct EntryData<'a> {
    path: &'a str,
    encrypted: bool,
    expect: u32,
    crc: crc32fast::Hasher,
    left: u64,
    checked: bool,
    body: Body<'a>,
    failed: Option<Error>,
}

impl<'a> EntryData<'a> {
    /// Goes to the entry's data and sets up its decoding, with `password` if it's encrypted.
    /// Outside a solid archive the dictionary starts empty.
    fn open(
        parts: &'a mut Parts,
        dict: &'a mut Dictionary,
        at: &'a EntryAt,
        path: &'a str,
        solid: bool,
        password: Option<&str>,
    ) -> Result<Self> {
        let mut data = Self {
            path,
            encrypted: at.encrypted,
            expect: at.crc,
            crc: crc32fast::Hasher::new(),
            left: at.size,
            checked: false,
            body: Body::None,
            failed: None,
        };
        if let Some(why) = &at.unreadable {
            data.failed = Some(why.clone());
            return Ok(data);
        }
        if !matches!(at.method, COMP_STORED | COMP_LZ77 | COMP_BLOCKED) {
            data.failed = Some(Error::unsupported(format!(
                "ace: `{path}` is compressed with method {}, which ACE 2.0 doesn't have",
                at.method
            )));
            return Ok(data);
        }
        let Some(first) = at.segments.first() else {
            return Err(bad(format!("`{path}` has no data")));
        };
        parts.seek(first.part, first.offset)?;
        let packed = Packed {
            parts,
            segments: &at.segments,
            next: 1,
            left: first.len,
        };
        let src: Box<dyn Read + 'a> = match password {
            Some(pw) => Box::new(Decrypt::new(packed, pw)),
            None => Box::new(packed),
        };
        if !solid {
            dict.clear();
        }
        data.body = match at.method {
            COMP_STORED if solid => {
                dict.reserve(at.dict_size);
                Body::Stored {
                    src,
                    dict: Some(dict),
                }
            }
            COMP_STORED => Body::Stored { src, dict: None },
            _ => {
                dict.reserve(at.dict_size);
                Body::Lz77 {
                    lz: Box::new(Lz77::new(src, at.size)),
                    dict,
                }
            }
        };
        Ok(data)
    }

    /// A damaged entry's error. An encrypted one may only have the wrong password.
    fn damaged(&self, e: Error) -> Error {
        match e.kind {
            ErrorKind::Corrupt if self.encrypted => wrong_password(self.path),
            ErrorKind::Corrupt => Error::corrupt(format!(
                "ace: `{}`: {}",
                self.path,
                e.message.trim_start_matches("ace: ")
            )),
            _ => e,
        }
    }

    fn step(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.left == 0 {
            if !self.checked {
                self.checked = true;
                if !self.crc.clone().finalize() != self.expect {
                    return Err(if self.encrypted {
                        wrong_password(self.path)
                    } else {
                        Error::corrupt(format!("ace: `{}` doesn't match its CRC-32", self.path))
                    });
                }
            }
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let path = self.path;
        let got = match &mut self.body {
            Body::Stored { src, dict } => match src.read(&mut buf[..want]) {
                Ok(0) => Err(bad("the data is cut short")),
                Ok(n) => {
                    if let Some(d) = dict {
                        d.extend(&buf[..n]);
                    }
                    Ok(n)
                }
                Err(e) => Err(read_error(&e)),
            },
            Body::Lz77 { lz, dict } => match lz.read(dict, &mut buf[..want]) {
                Ok(0) => Err(bad("the data is cut short")),
                Ok(n) => Ok(n),
                Err(Stop::Error(e)) => Err(e),
                Err(Stop::Mode(mode)) => {
                    return Err(Error::unsupported(format!(
                        "ace: `{path}` uses ACE 2.0's {mode} mode, which BeeZip doesn't decode"
                    )));
                }
            },
            Body::None => Err(bad("no data")),
        };
        let n = got.map_err(|e| self.damaged(e))?;
        self.crc.update(&buf[..n]);
        self.left -= n as u64;
        Ok(n)
    }
}

impl Read for EntryData<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.failed {
            return Err(e.clone().into_io());
        }
        self.step(buf).map_err(|e| {
            self.failed = Some(e.clone());
            e.into_io()
        })
    }
}

/// Asks for entry `path`'s password after `failed` wrong ones.
fn ask(cx: &mut dyn Ctx, path: &str, failed: u32) -> Result<String> {
    cx.password(Some(path), failed).map_err(|e| match e.kind {
        ErrorKind::WrongPassword if failed > 0 => wrong_password(path),
        _ => e,
    })
}

/// What a pass over the archive keeps between entries.
struct Pass<'s> {
    source: &'s Source,
    solid: bool,
    /// The last password that worked.
    password: &'s mut Option<String>,
    parts: Parts,
    dict: Dictionary,
}

impl Pass<'_> {
    /// Decodes entry `e` into `sink`, or only through the dictionary without one (a solid
    /// archive's entries before a wanted one), trying passwords until one works. Returns the
    /// password it read the entry with. A sink may skip an entry; in a solid archive the rest is
    /// decoded anyway, for the dictionary. Damage in what no sink reads ends only that entry: in
    /// a solid archive, the entries that needed it then fail their own checks.
    fn entry(
        &mut self,
        e: &Entry,
        at: &EntryAt,
        mut sink: Option<&mut dyn EntrySink>,
        cx: &mut dyn Ctx,
    ) -> Result<Option<String>> {
        // An entry that can't be read needs no password to fail.
        let encrypted = at.encrypted && at.unreadable.is_none();
        // A solid archive's dictionary as it was, to try the next password from.
        let before = (self.solid && encrypted).then(|| self.dict.clone());
        let mut failed = 0u32;
        let mut candidate = self.password.clone();
        loop {
            let pw = match (encrypted, candidate.take()) {
                (false, _) => None,
                (true, Some(pw)) => Some(pw),
                (true, None) => Some(ask(cx, &e.path, failed)?),
            };
            let mut data = EntryData::open(
                &mut self.parts,
                &mut self.dict,
                at,
                &e.path,
                self.solid,
                pw.as_deref(),
            )?;
            // What went wrong, and whether the sink said so.
            let (result, from_sink) = match sink.as_deref_mut() {
                Some(s) => {
                    let mut guarded = self.source.guard(&mut data);
                    match s.entry(e, &mut guarded, cx) {
                        Err(err) => (Err(err), true),
                        Ok(()) if self.solid => {
                            let (read, ratio) = guarded.into_parts();
                            if read.failed.is_some() {
                                // The sink saw the error and dealt with it.
                                (Ok(()), false)
                            } else {
                                let budget = self.source.budget.clone();
                                let mut rest = Guarded::new(read, ratio, budget);
                                (drain(&mut rest, cx).map(drop), false)
                            }
                        }
                        Ok(()) => (Ok(()), false),
                    }
                }
                None => {
                    let ratio = RatioGuard::new(&self.source.counter, &self.source.limits);
                    let mut guarded = Guarded::new(&mut data, ratio, Budget::default());
                    (drain(&mut guarded, cx).map(drop), false)
                }
            };
            drop(data);
            let err = match result {
                Ok(()) => {
                    if pw.is_some() {
                        *self.password = pw.clone();
                    }
                    return Ok(pw);
                }
                Err(err) => err,
            };
            if err.kind == ErrorKind::WrongPassword && encrypted {
                failed += 1;
                if failed >= MAX_PASSWORD_TRIES {
                    return Err(wrong_password(&e.path));
                }
                if let Some(d) = &before {
                    self.dict.clone_from(d);
                }
                // A sink that skipped the entry needn't see it again.
                if !from_sink {
                    sink = None;
                }
                continue;
            }
            if from_sink || fatal(&err) {
                return Err(err);
            }
            return Ok(pw);
        }
    }
}

pub struct AceReader {
    source: Source,
    main: MainHeader,
    comment: Option<String>,
    entries: Vec<Entry>,
    at: Vec<EntryAt>,
    /// The sizes of the parts read: the set's when the archive says it's one.
    lens: Vec<Option<u64>>,
    /// The last password that worked.
    password: Option<String>,
    /// What `open_entry`'s reader reads from.
    parts: Option<Parts>,
    dict: Dictionary,
}

/// An entry being listed: its first header, and where its data is so far.
struct Listing {
    name: Vec<u8>,
    entry: Entry,
    at: EntryAt,
}

fn entry_for(id: usize, h: &FileHeader, names: &NameDecoding, clock: &mut DosClock) -> Entry {
    // A NUL ends the name, as it does for acefile and the Windows API.
    let raw = h
        .name
        .split(|&b| b == 0)
        .next()
        .unwrap_or_default()
        .to_vec();
    let mut path = names
        .decode(&raw, false, SystemPage::Oem)
        .replace('\\', "/");
    let dir = h.attribs & ATTR_DIRECTORY != 0;
    if dir && !path.ends_with('/') {
        path.push('/');
    }
    let file = !dir;
    Entry {
        id,
        path,
        raw_path: raw,
        kind: if dir { EntryKind::Dir } else { EntryKind::File },
        size: file.then_some(h.size),
        packed_size: file.then_some(h.packed),
        modified: clock.read(DosTime {
            date: (h.datetime >> 16) as u16,
            time: h.datetime as u16,
        }),
        // ACE keeps CRC-32 without its final inversion.
        crc32: file.then_some(!h.crc),
        method: file.then(|| Cow::Borrowed(method_name(h.method))),
        encrypted: file && h.flag(FLAG_PASSWORD),
        unix_mode: None,
        // DOS archivers leave the high half undefined.
        dos_attrs: Some(h.attribs & 0xFFFF),
    }
}

impl AceReader {
    /// Reads every header of every part, skipping the data. An archive cut short is listed as
    /// far as it goes, the entry it cuts failing when read, with a warning.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let set = if source.codecs.is_empty() && !source.joined {
            source.volumes.len().max(1)
        } else {
            1
        };
        let mut lens = Parts::sizes(&source, set)?;
        let mut parts = Parts::new(&source, &lens);
        let names = source.names;
        let mut clock = DosClock::default();
        let mut main: Option<MainHeader> = None;
        let mut list = List::default();
        let mut used = 0;

        for part in 0..set {
            parts.seek(part, 0)?;
            let name = parts.name(part);
            let first = match parts.header(part)? {
                Next::Header(body) => header::parse(&body)?,
                Next::End | Next::Cut => return Err(bad(format!("{name} has no main header"))),
            };
            let Header::Main(m) = first else {
                return Err(bad(format!("{name} doesn't start with ACE's main header")));
            };
            let set_member = m.flags & FLAG_MULTIVOLUME != 0;
            match &main {
                None => main = Some(m),
                Some(first) => {
                    if !set_member || m.volume != first.volume.wrapping_add(part as u8) {
                        return Err(bad(format!("{name} isn't the next part of the set")));
                    }
                }
            }
            used = part + 1;
            let whole = list.part(&mut parts, part, &source, &names, &mut clock, cx)?;
            // Not a set: other files of that name aren't its parts.
            if !set_member || !whole {
                break;
            }
        }
        let Some(main) = main else {
            return Err(bad("the archive has no main header"));
        };
        if let Some(l) = list.open.take() {
            let why = format!(
                "ace: `{}` goes on in the part of the set after {}, which isn't there",
                l.entry.path,
                parts.name(used - 1)
            );
            cx.warn(why.clone());
            list.close(l, Error::new(ErrorKind::NotFound, why));
        }
        let solid = main.flags & FLAG_SOLID != 0;
        if solid && main.volume > 0 {
            // A solid archive is decoded from its start, which is in a part that isn't here.
            let why = Error::new(
                ErrorKind::NotFound,
                format!(
                    "ace: {} is part {} of a solid set; its first part is needed to read it",
                    parts.name(0),
                    u32::from(main.volume) + 1
                ),
            );
            for a in &mut list.at {
                a.unreadable.get_or_insert_with(|| why.clone());
            }
        }
        lens.truncate(used);
        let comment = main
            .comment
            .as_deref()
            .and_then(|c| lz77::comment(c).ok())
            .map(|c| names.decode(&c, false, SystemPage::Oem))
            .filter(|c| !c.is_empty());
        Ok(Self {
            source,
            main,
            comment,
            entries: list.entries,
            at: list.at,
            lens,
            password: None,
            parts: None,
            dict: Dictionary::default(),
        })
    }
}

/// The listing so far.
#[derive(Default)]
struct List {
    entries: Vec<Entry>,
    at: Vec<EntryAt>,
    /// An entry that goes on in the next part.
    open: Option<Listing>,
}

impl List {
    fn push(&mut self, l: Listing) {
        self.entries.push(l.entry);
        self.at.push(l.at);
    }

    /// Lists `l`, which can't be read.
    fn close(&mut self, mut l: Listing, why: Error) {
        l.at.unreadable = Some(why);
        self.push(l);
    }

    /// Lists one part's file headers, after its main header; false when the part is cut short,
    /// which ends the listing.
    fn part(
        &mut self,
        parts: &mut Parts,
        part: usize,
        source: &Source,
        names: &NameDecoding,
        clock: &mut DosClock,
        cx: &mut dyn Ctx,
    ) -> Result<bool> {
        loop {
            cx.check()?;
            let start = parts.pos;
            let body = match parts.header(part)? {
                Next::Header(body) => body,
                Next::End => return Ok(true),
                Next::Cut => {
                    let why = parts.at(part, start, "the file ends inside a header");
                    cx.warn(why.message.clone());
                    if let Some(l) = self.open.take() {
                        self.close(l, why);
                    }
                    return Ok(false);
                }
            };
            let h = match header::parse(&body)
                .map_err(|e| parts.at(part, start, e.message.trim_start_matches("ace: ")))?
            {
                Header::Main(_) => return Err(parts.at(part, start, "a second main header")),
                Header::Other { addsize } => {
                    let skipped = parts
                        .data_end(part, start, addsize)
                        .and_then(|to| parts.seek(part, to));
                    match skipped {
                        Ok(()) => continue,
                        Err(e) if e.kind == ErrorKind::Corrupt => {
                            cx.warn(e.message);
                            return Ok(false);
                        }
                        Err(e) => return Err(e),
                    }
                }
                Header::File(h) => h,
            };
            let data = parts.pos;
            let end = parts.data_end(part, start, h.packed);
            let len = match &end {
                Ok(_) => h.packed,
                Err(_) => parts.lens[part].unwrap_or(data).saturating_sub(data),
            };
            let segment = Segment {
                part,
                offset: data,
                len,
            };
            match self.open.take() {
                Some(mut l) => {
                    if !h.flag(FLAG_CONTPREV) || h.name != l.name {
                        return Err(parts.at(
                            part,
                            start,
                            &format!("`{}` doesn't go on here", l.entry.path),
                        ));
                    }
                    l.at.segments.push(segment);
                    l.at.crc = h.crc;
                    if let Some(p) = &mut l.entry.packed_size {
                        *p = p.saturating_add(len);
                    }
                    l.entry.crc32 = l.entry.crc32.map(|_| !h.crc);
                    self.open = Some(l);
                }
                None if h.flag(FLAG_CONTPREV) => {
                    if !self.entries.is_empty() || part > 0 {
                        return Err(parts.at(part, start, "an entry goes on from nowhere"));
                    }
                    // The set was opened without its first part.
                    let shown = names.decode(&h.name, false, SystemPage::Oem);
                    cx.warn(format!(
                        "ace: `{shown}` starts in a part before {}, which isn't there; it's \
                         left out",
                        parts.name(part)
                    ));
                }
                None => {
                    let id = self.entries.len();
                    source.limits.check_entries(id as u64 + 1)?;
                    self.open = Some(Listing {
                        name: h.name.clone(),
                        entry: entry_for(id, &h, names, clock),
                        at: EntryAt {
                            segments: vec![segment],
                            method: h.method,
                            dict_size: h.dict_size(),
                            size: h.size,
                            crc: h.crc,
                            encrypted: h.flag(FLAG_PASSWORD),
                            unreadable: None,
                        },
                    });
                }
            }
            // Past the data; a stream finds out only now that it ends inside it.
            let skipped = end.and_then(|to| parts.seek(part, to));
            if let Err(e) = skipped {
                if e.kind != ErrorKind::Corrupt {
                    return Err(e);
                }
                let what = match &self.open {
                    Some(l) => format!("`{}` is cut short", l.entry.path),
                    None => "the archive is cut short".to_owned(),
                };
                let why = parts.at(part, start, &what);
                cx.warn(why.message.clone());
                if let Some(l) = self.open.take() {
                    self.close(l, why);
                }
                return Ok(false);
            }
            if !h.flag(FLAG_CONTNEXT)
                && let Some(l) = self.open.take()
            {
                self.push(l);
            }
        }
    }
}

impl AceReader {
    fn solid(&self) -> bool {
        self.main.flags & FLAG_SOLID != 0
    }

    fn total(&self) -> u64 {
        match self.lens.iter().copied().sum::<Option<u64>>() {
            Some(n) => n,
            None => self.source.size,
        }
    }

    fn has_data(&self, id: usize) -> bool {
        self.entries[id].kind == EntryKind::File && self.at[id].size > 0
    }
}

impl ArchiveReader for AceReader {
    fn format(&self) -> FormatId {
        FormatId::Ace
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods: Vec<Cow<'static, str>> = Vec::new();
        let files: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .collect();
        for m in files.iter().filter_map(|e| e.method.as_ref()) {
            if !methods.contains(m) {
                methods.push(m.clone());
            }
        }
        let encrypted = files.iter().filter(|e| e.encrypted).count();
        Ok(ArchiveInfo {
            format: FormatId::Ace,
            codecs: self.source.codecs.clone(),
            methods,
            comment: self.comment.clone(),
            encryption: match encrypted {
                0 => Encryption::None,
                n if n == files.len() => Encryption::All,
                _ => Encryption::Some,
            },
            solid: self.solid(),
            sfx: false,
            volumes: self.lens.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: self.main.flags & FLAG_LOCKED != 0,
            recovery_record: self.main.flags & FLAG_RECOVERY != 0,
            external: None,
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        self.source.counter.set(0);
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.total()));
        meter.entries_total = Some(self.entries.len() as u64);
        let wanted: Vec<bool> = self.entries.iter().map(|e| sel.matches(e)).collect();
        let solid = self.solid();
        let Some(last) = wanted.iter().rposition(|&w| w) else {
            MeteredCtx::new(cx, &meter).report();
            return Ok(());
        };
        let has_data: Vec<bool> = (0..self.entries.len()).map(|i| self.has_data(i)).collect();
        let mut pass = Pass {
            source: &self.source,
            solid,
            password: &mut self.password,
            parts: Parts::new(&self.source, &self.lens),
            dict: Dictionary::default(),
        };
        for (id, e) in self.entries.iter().enumerate().take(last + 1) {
            cx.check()?;
            let at = &self.at[id];
            // A solid archive decodes the entries before a wanted one; one whose part is
            // unreadable can't be, and nothing after it needs it.
            let through = solid && has_data[id] && at.unreadable.is_none();
            if !wanted[id] && !through {
                continue;
            }
            meter.entries_done = id as u64;
            meter.current = Some(e.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            if !has_data[id] {
                sink.entry(e, &mut io::empty(), &mut mcx)?;
                continue;
            }
            if wanted[id] {
                pass.entry(e, at, Some(&mut *sink), &mut mcx)?;
            } else {
                pass.entry(e, at, None, &mut mcx)?;
            }
        }
        meter.entries_done = self.entries.len() as u64;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        if id >= self.entries.len() {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        }
        if !self.has_data(id) {
            return Ok(Box::new(io::empty()));
        }
        self.source.counter.set(0);
        let solid = self.solid();
        let has_data: Vec<bool> = (0..id).map(|i| self.has_data(i)).collect();
        let mut pass = Pass {
            source: &self.source,
            solid,
            password: &mut self.password,
            parts: Parts::new(&self.source, &self.lens),
            dict: Dictionary::default(),
        };
        if solid {
            for (k, e) in self.entries[..id].iter().enumerate() {
                if has_data[k] && self.at[k].unreadable.is_none() {
                    cx.check()?;
                    pass.entry(e, &self.at[k], None, cx)?;
                }
            }
        }
        let (e, at) = (&self.entries[id], &self.at[id]);
        // The reader handed out can't ask again, so an encrypted entry's password is found by
        // decoding it once first.
        let password = if at.encrypted && at.unreadable.is_none() {
            let before = pass.dict.clone();
            let pw = pass.entry(e, at, None, cx)?;
            pass.dict = before;
            pw
        } else {
            None
        };
        let Pass { parts, dict, .. } = pass;
        self.dict = dict;
        let parts = self.parts.insert(parts);
        let data = EntryData::open(
            parts,
            &mut self.dict,
            at,
            &e.path,
            solid,
            password.as_deref(),
        )?;
        Ok(Box::new(self.source.guard(data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_by_the_main_header() {
        let mut body = vec![header::TYPE_MAIN, 0, 0];
        body.extend_from_slice(header::MAGIC);
        body.extend_from_slice(&[10, 20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut file = header::crc16(&body).to_le_bytes().to_vec();
        file.extend_from_slice(&(body.len() as u16).to_le_bytes());
        file.extend_from_slice(&body);
        assert_eq!(header_at(&file), Some(Confidence::Certain));
        file[4] = header::TYPE_FILE32;
        assert_eq!(header_at(&file), Some(Confidence::Likely), "magic alone");
        assert_eq!(header_at(b"PK\x03\x04"), None);
    }
}
