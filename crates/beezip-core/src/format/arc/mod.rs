//! ARC (docs/M6.md §4), read only, BeeZip's own, written from public descriptions of the
//! format: SEA's ARC, PKWARE's PKARC/PKPAK and NoGate's PAK, which share it.
//!
//! - **Headers:** `1A`, the method, a 13-byte name (NUL-terminated), the packed size, the DOS
//!   date and time, the CRC-16 and the original size; method 1's older header has no original
//!   size. `1A 00` ends the archive. Names are bytes, decoded as OEM; `\` reads as `/`.
//! - **Methods:** 1 and 2 stored; 3 packed (RLE90); 4 squeezed (Huffman, then RLE90); 5–7 the
//!   first crunched (12-bit LZW into a hashed table, with RLE90 in 6 and 7, a faster hash in
//!   7); 8 crunched (compress's LZW, 9–12 bits, then RLE90); 9 squashed (compress's LZW, 9–13
//!   bits). PAK's 10 (crushed) and 11 (distilled) are listed but refused, as is any other
//!   method (docs/M6.md §14): their only decoders are reverse-engineered from PAK.EXE.
//! - **The CRC-16** of each entry is checked, with its size, when its data has been read.
//! - **Passwords:** ARC has no flag for them. A password XORs every entry's packed bytes, the
//!   plain ones included, so one shows only as data that fails its check. When an entry fails
//!   without one, BeeZip asks for a password and decodes it again; the one that works is kept
//!   for the rest, and an entry that then fails is tried without it too (an archive can mix
//!   both). ARC 5.21 upper-cases passwords, so each answer is tried as typed and upper-cased,
//!   as one attempt. `Entry::encrypted` is set on the entries a password was needed for, once
//!   read.
//! - **Sniffing** is structural, since the magic is one byte: a whole plausible first header,
//!   and the next header or the end marker after its data where the head holds it.

mod unpack;

use std::{
    borrow::Cow,
    io::{self, BufReader, Read, Seek, SeekFrom},
};

use unpack::{Crunch12, Rle90, Unsqueeze, Xor};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    codec::compress::{Check16, Decoder as Lzw12, Lzw},
    ctx::MAX_PASSWORD_TRIES,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, CountingReader},
    names::SystemPage,
    source::{self, Source},
    time::{DosClock, DosTime},
};

pub struct Arc;

const MARK: u8 = 0x1A;
/// The name field: 12 characters and a NUL.
const NAME_LEN: usize = 13;
/// Method 1's header, without the original size.
const OLD_HEADER: usize = 25;
const HEADER: usize = 29;
/// The highest method of SEA's ARC and PAK.
const LAST_METHOD: u8 = 11;

impl ArchiveFormat for Arc {
    fn id(&self) -> FormatId {
        FormatId::Arc
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".arc"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        first_header(probe.head, probe.len)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}

/// A whole plausible first header: a method ARC or PAK writes, a NUL-terminated name of
/// printable bytes, a plausible date, sizes within the file, and after the data (where `head`
/// holds it) another header or the end marker.
fn first_header(head: &[u8], len: Option<u64>) -> Option<Confidence> {
    let h = Header::parse(head).ok()??;
    if !(1..=LAST_METHOD).contains(&h.method) {
        return None;
    }
    let name = cstr(&head[2..2 + NAME_LEN]);
    let printable = |b: u8| b == b' ' || b.is_ascii_graphic() || b >= 0x80;
    if name.len() == NAME_LEN || name.is_empty() || name[0] == b' ' {
        return None;
    }
    if !name.iter().all(|&b| printable(b)) {
        return None;
    }
    let month = (h.date >> 5) & 0x0F;
    let day = h.date & 0x1F;
    if month > 12 || day > 31 || h.time >> 11 > 23 || (h.time >> 5) & 0x3F > 59 {
        return None;
    }
    if h.method <= 2 && h.size != h.packed {
        return None;
    }
    let next = (h.len as u64).checked_add(h.packed)?;
    if len.is_some_and(|l| next.saturating_add(2) > l) {
        return None;
    }
    if let Some(after) = usize::try_from(next)
        .ok()
        .and_then(|n| head.get(n..n.checked_add(2)?))
        && (after[0] != MARK || after[1] > LAST_METHOD)
    {
        return None;
    }
    Some(Confidence::Certain)
}

fn arc_error(msg: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("arc: {msg}"))
}

fn cstr(b: &[u8]) -> &[u8] {
    b.split(|&c| c == 0).next().unwrap_or_default()
}

/// One header.
#[derive(Debug, Clone)]
struct Header {
    method: u8,
    name: Vec<u8>,
    packed: u64,
    date: u16,
    time: u16,
    crc: u16,
    size: u64,
    /// The header's own length.
    len: usize,
}

impl Header {
    /// The header at the start of `b`: `None` at the end marker, an error if `b` doesn't start
    /// with one or is too short.
    fn parse(b: &[u8]) -> Result<Option<Self>> {
        let short = || arc_error("a header is cut short");
        let (&mark, rest) = b.split_first().ok_or_else(short)?;
        if mark != MARK {
            return Err(arc_error("no ARC header where one should be"));
        }
        let method = *rest.first().ok_or_else(short)?;
        if method == 0 {
            return Ok(None);
        }
        let len = if method == 1 { OLD_HEADER } else { HEADER };
        let b = b.get(..len).ok_or_else(short)?;
        let u16_at = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let packed = u64::from(u32_at(15));
        Ok(Some(Self {
            method,
            name: cstr(&b[2..2 + NAME_LEN]).to_vec(),
            packed,
            date: u16_at(19),
            time: u16_at(21),
            crc: u16_at(23),
            size: if method == 1 {
                packed
            } else {
                u64::from(u32_at(25))
            },
            len,
        }))
    }
}

fn method_name(m: u8) -> Cow<'static, str> {
    match m {
        1 | 2 => "Store".into(),
        3 => "Packed".into(),
        4 => "Squeezed".into(),
        5..=7 => "Crunched (old)".into(),
        8 => "Crunched".into(),
        9 => "Squashed".into(),
        10 => "Crushed".into(),
        11 => "Distilled".into(),
        m => format!("method {m}").into(),
    }
}

/// Where an entry's data is.
#[derive(Debug, Clone, Copy)]
struct Item {
    offset: u64,
    packed: u64,
    size: u64,
    crc: u16,
    method: u8,
}

/// A password's bytes; `None` is no password.
type Key = Option<Vec<u8>>;

/// The input, counted, read forward from a position: the file, or the decoded stream of a
/// compressed one (`.arc.gz`), which can only skip.
struct Input {
    inner: Inner,
    at: u64,
}

enum Inner {
    File(BufReader<CountingReader<source::Input>>),
    Stream(Box<dyn Read + Send>),
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = match &mut self.inner {
            Inner::File(f) => f.read(buf)?,
            Inner::Stream(s) => s.read(buf)?,
        };
        self.at += n as u64;
        Ok(n)
    }
}

impl Input {
    /// Moves forward to `to`.
    fn skip_to(&mut self, to: u64) -> Result<()> {
        if to < self.at {
            return Err(arc_error("an entry before the one read last"));
        }
        match &mut self.inner {
            // Relative, so the buffer survives a skip over a small entry.
            Inner::File(f) => {
                let seek = match i64::try_from(to - self.at) {
                    Ok(d) => f.seek_relative(d),
                    Err(_) => f.seek(SeekFrom::Start(to)).map(drop),
                };
                seek.map_err(|e| Error::io("seeking in the archive", &e))?;
                self.at = to;
            }
            Inner::Stream(_) => {
                let want = to - self.at;
                let n = io::copy(&mut self.take(want), &mut io::sink())
                    .map_err(|e| crate::io::read_error(&e).context("arc"))?;
                if n != want {
                    return Err(arc_error("the archive is cut short"));
                }
            }
        }
        Ok(())
    }
}

/// An entry's data, decoded with `key`, its size and CRC-16 checked at the end. With `ask`, any
/// sign the data is wrong (a decoder's error, the size, the CRC) fails as `WrongPassword`, which
/// every sink hands back, so the reader can ask for a password and try again.
struct Attempt<'a> {
    inner: Check16<Box<dyn Read + 'a>>,
    ask: bool,
}

impl Read for Attempt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Err(e) if self.inner.failed && self.ask => {
                Err(Error::new(ErrorKind::WrongPassword, e.to_string()).into_io())
            }
            Err(e) if self.inner.failed => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{e} (or it needs a password: ARC can't tell)"),
            )),
            other => other,
        }
    }
}

/// The refusal for an entry whose method BeeZip doesn't decode.
fn refusal(e: &Entry, method: u8) -> Error {
    let what = match method {
        10 => "PAK's crushed method (10)".to_owned(),
        11 => "PAK's distilled method (11)".to_owned(),
        m => format!("method {m}"),
    };
    Error::unsupported(format!(
        "`{}` is compressed with {what}, which BeeZip can't decode",
        e.path
    ))
}

/// Entry `e`'s data from `r`, which is at its start.
fn attempt<'a>(
    r: impl Read + 'a,
    item: Item,
    e: &Entry,
    key: &Key,
    ask: bool,
) -> Result<Attempt<'a>> {
    let packed = r.take(item.packed);
    let packed: Box<dyn Read + 'a> = match key {
        Some(k) if !k.is_empty() => Box::new(Xor::new(packed, k)),
        _ => Box::new(packed),
    };
    let decoded: Box<dyn Read + 'a> = match item.method {
        1 | 2 => packed,
        3 => Box::new(Rle90::new(packed)),
        4 => Box::new(Rle90::new(Unsqueeze::new(packed))),
        5 => Box::new(Crunch12::new(packed, false)),
        6 => Box::new(Rle90::new(Crunch12::new(packed, false))),
        7 => Box::new(Rle90::new(Crunch12::new(packed, true))),
        8 => Box::new(Rle90::new(Crunched::new(packed))),
        9 => Box::new(Lzw12::raw(packed, Lzw::SQUASH).map_err(|err| Error::from_io(&err))?),
        m => return Err(refusal(e, m)),
    };
    Ok(Attempt {
        inner: Check16::new(decoded, item.size, item.crc, format!("arc: `{}`", e.path)),
        ask,
    })
}

/// Method 8: a byte giving the widest code (12), then compress's LZW.
struct Crunched<R: Read> {
    inner: Option<R>,
    lzw: Option<Lzw12<R>>,
}

impl<R: Read> Crunched<R> {
    fn new(inner: R) -> Self {
        Self {
            inner: Some(inner),
            lzw: None,
        }
    }
}

impl<R: Read> Read for Crunched<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(mut r) = self.inner.take() {
            let mut bits = [0u8];
            if r.read(&mut bits)? == 0 {
                // An empty entry.
                return Ok(0);
            }
            if !(9..=12).contains(&bits[0]) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("crunched with {}-bit codes (12 at most)", bits[0]),
                ));
            }
            self.lzw = Some(Lzw12::raw(r, Lzw::crunch(u32::from(bits[0])))?);
        }
        match &mut self.lzw {
            Some(l) => l.read(buf),
            None => Ok(0),
        }
    }
}

/// A reader that fails at once with a refusal, handed to the sink so a test records it.
struct Refused(Option<Error>);

impl Read for Refused {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self
            .0
            .take()
            .unwrap_or_else(|| Error::unsupported("refused"))
            .into_io())
    }
}

fn wrong_password() -> Error {
    Error::new(ErrorKind::WrongPassword, "wrong password or damaged data")
}

/// The keys tried for one entry so far, and those still to try before asking again.
#[derive(Default)]
struct Tries {
    plain_tried: bool,
    /// Passwords that failed, each in both its forms.
    failed: u32,
    /// The upper-cased form of the last answer.
    upper: Option<Key>,
}

/// What to do after an entry's data failed with `tried`: the next key, or `None` when nobody
/// can be asked (`PasswordRequired`), so the entry fails as damaged. An answer is tried as
/// typed, then upper-cased, as one attempt: ARC 5.21 upper-cases the passwords it's given.
fn next_key(path: &str, tried: &Key, t: &mut Tries, cx: &mut dyn Ctx) -> Result<Option<Key>> {
    if let Some(k) = t.upper.take() {
        return Ok(Some(k));
    }
    let (plain_tried, failed) = (&mut t.plain_tried, &mut t.failed);
    // A password that worked for the entries before: this one may be plain.
    if tried.is_some() && !*plain_tried {
        *plain_tried = true;
        return Ok(Some(None));
    }
    if tried.is_some() {
        *failed += 1;
    }
    if *failed > MAX_PASSWORD_TRIES {
        return Err(wrong_password());
    }
    match cx.password(Some(path), *failed) {
        Ok(pw) => {
            let upper = pw.to_ascii_uppercase();
            if upper != pw {
                t.upper = Some(Some(upper.into_bytes()));
            }
            Ok(Some(Some(pw.into_bytes())))
        }
        Err(e) if e.kind == ErrorKind::PasswordRequired && *failed == 0 => Ok(None),
        Err(e)
            if matches!(
                e.kind,
                ErrorKind::WrongPassword | ErrorKind::PasswordRequired
            ) =>
        {
            Err(wrong_password())
        }
        Err(e) => Err(e),
    }
}

pub struct ArcReader {
    source: Source,
    entries: Vec<Entry>,
    items: Vec<Item>,
    /// The password that worked last.
    password: Key,
    /// Per entry, the key its data was found to decode with.
    known: Vec<Option<Key>>,
}

impl ArcReader {
    /// Reads every header, skipping the data.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let mut r = Self {
            source,
            entries: Vec::new(),
            items: Vec::new(),
            password: None,
            known: Vec::new(),
        };
        r.list(cx)?;
        r.known = vec![None; r.entries.len()];
        Ok(r)
    }

    /// The archive from its start, counted, and its length if known.
    fn input(&self) -> Result<(Input, Option<u64>)> {
        if self.source.codecs.is_empty() {
            let file = self.source.open_file()?;
            let len = self.source.size.saturating_sub(self.source.offset);
            let inner = Inner::File(BufReader::with_capacity(BUF_SIZE, file));
            Ok((Input { inner, at: 0 }, Some(len)))
        } else {
            let inner = Inner::Stream(self.source.open_stream()?);
            Ok((Input { inner, at: 0 }, None))
        }
    }

    fn list(&mut self, cx: &mut dyn Ctx) -> Result<()> {
        let (mut r, len) = self.input()?;
        let mut clock = DosClock::default();
        let names = self.source.names;
        let mut buf = [0u8; HEADER];
        loop {
            cx.check()?;
            let at = r.at;
            let n = read_up_to(&mut r, &mut buf[..2])?;
            if n == 0 && !self.entries.is_empty() {
                // No end marker: the archive ends with its last entry.
                break;
            }
            let more = match buf.get(..2) {
                Some([MARK, m]) if n == 2 && *m != 0 => {
                    let want = if *m == 1 { OLD_HEADER } else { HEADER };
                    read_up_to(&mut r, &mut buf[2..want])?
                }
                _ => 0,
            };
            let h =
                Header::parse(&buf[..n + more]).map_err(|e| e.context(format!("at byte {at}")))?;
            let Some(h) = h else {
                break;
            };
            let id = self.entries.len();
            self.source.limits.check_entries(id as u64 + 1)?;
            let offset = r.at;
            if let Some(len) = len
                && offset.saturating_add(h.packed) > len
            {
                return Err(arc_error(format!(
                    "an entry of {} bytes at byte {offset} runs past the end of the file",
                    h.packed
                )));
            }
            let path = names
                .decode(&h.name, false, SystemPage::Oem)
                .replace('\\', "/");
            self.entries.push(Entry {
                id,
                path,
                raw_path: h.name.clone(),
                kind: EntryKind::File,
                size: Some(h.size),
                packed_size: Some(h.packed),
                modified: clock.read(DosTime {
                    date: h.date,
                    time: h.time,
                }),
                crc32: None,
                method: Some(method_name(h.method)),
                encrypted: false,
                unix_mode: None,
                dos_attrs: None,
            });
            self.items.push(Item {
                offset,
                packed: h.packed,
                size: h.size,
                crc: h.crc,
                method: h.method,
            });
            r.skip_to(offset + h.packed)?;
        }
        Ok(())
    }

    /// Decodes entry `id` from `r` (at its data) with `key` into nothing: whether it matches.
    fn verify(&self, r: impl Read, id: usize, key: &Key, cx: &mut dyn Ctx) -> Result<bool> {
        let mut a = attempt(r, self.items[id], &self.entries[id], key, true)?;
        let drained = crate::io::drain(&mut self.source.guard(&mut a), cx);
        match drained {
            Ok(_) => Ok(true),
            Err(_) if a.inner.failed => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The key entry `id` decodes with: tried, asked for, or `None` inside when nobody can be
    /// asked. Each try decodes the entry once.
    fn find_key(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Option<Key>> {
        if let Some(k) = &self.known[id] {
            return Ok(Some(k.clone()));
        }
        let path = self.entries[id].path.clone();
        let mut key = self.password.clone();
        let mut tries = Tries {
            plain_tried: key.is_none(),
            ..Tries::default()
        };
        loop {
            cx.check()?;
            let (mut r, _) = self.input()?;
            r.skip_to(self.items[id].offset)?;
            if self.verify(r, id, &key, cx)? {
                self.found(id, &key);
                return Ok(Some(key));
            }
            match next_key(&path, &key, &mut tries, cx)? {
                Some(k) => key = k,
                None => return Ok(None),
            }
        }
    }

    /// Entry `id` decoded with `key`: keeps it for the rest, and marks the entry.
    fn found(&mut self, id: usize, key: &Key) {
        self.known[id] = Some(key.clone());
        if key.as_ref().is_some_and(|k| !k.is_empty()) {
            self.password.clone_from(key);
            self.entries[id].encrypted = true;
        }
    }
}

/// Reads until `buf` is full or the input ends: how much it read.
fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(crate::io::read_error(&e).context("arc")),
        }
    }
    Ok(n)
}

impl ArchiveReader for ArcReader {
    fn format(&self) -> FormatId {
        FormatId::Arc
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods: Vec<Cow<'static, str>> = Vec::new();
        for m in self.entries.iter().filter_map(|e| e.method.as_ref()) {
            if !methods.contains(m) {
                methods.push(m.clone());
            }
        }
        let encrypted = self.entries.iter().filter(|e| e.encrypted).count();
        Ok(ArchiveInfo {
            format: FormatId::Arc,
            codecs: self.source.codecs.clone(),
            methods,
            comment: None,
            encryption: match encrypted {
                0 => Encryption::None,
                n if n == self.entries.len() => Encryption::All,
                _ => Encryption::Some,
            },
            solid: false,
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: None,
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let (mut r, len) = self.input()?;
        let mut meter = Meter::new(self.source.counter.clone(), len);
        meter.entries_total = Some(self.entries.len() as u64);
        for id in 0..self.entries.len() {
            cx.check()?;
            if !sel.matches(&self.entries[id]) {
                continue;
            }
            meter.entries_done = id as u64;
            meter.current = Some(self.entries[id].path.clone());
            let item = self.items[id];
            if !matches!(item.method, 1..=9) {
                let err = refusal(&self.entries[id], item.method);
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.report();
                sink.entry(&self.entries[id], &mut Refused(Some(err)), &mut mcx)?;
                continue;
            }
            r.skip_to(item.offset)?;
            let path = self.entries[id].path.clone();
            let mut key = self.known[id]
                .clone()
                .unwrap_or_else(|| self.password.clone());
            let mut tries = Tries {
                plain_tried: key.is_none(),
                ..Tries::default()
            };
            let mut ask = true;
            let mut first = true;
            loop {
                // The first try reads the pass's input; another one reads the entry again.
                let mut again;
                let from: &mut dyn Read = if first {
                    &mut r
                } else {
                    // Opening resets the pass's byte count; progress goes on from where it was.
                    let done = self.source.counter.get();
                    again = self.input()?.0;
                    self.source.counter.set(done);
                    again.skip_to(item.offset)?;
                    &mut again
                };
                first = false;
                let mut e = self.entries[id].clone();
                e.encrypted = key.as_ref().is_some_and(|k| !k.is_empty());
                let mut a = attempt(from, item, &e, &key, ask)?;
                let sent = {
                    let mut mcx = MeteredCtx::new(cx, &meter);
                    mcx.report();
                    sink.entry(&e, &mut self.source.guard(&mut a), &mut mcx)
                };
                let (failed_data, verified) = (a.inner.failed, a.inner.verified);
                drop(a);
                match sent {
                    Ok(()) => {
                        // Only data read to its end says which key works: a sink may skip an
                        // entry, or keep going past a failure (the last try's).
                        if verified {
                            self.found(id, &key);
                        }
                        break;
                    }
                    Err(err) if failed_data && ask && err.kind == ErrorKind::WrongPassword => {
                        match next_key(&path, &key, &mut tries, cx)? {
                            Some(k) => key = k,
                            None => {
                                // Nobody to ask: the entry is damaged, as far as anyone knows.
                                key = None;
                                ask = false;
                            }
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let e = self
            .entries
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?
            .clone();
        let item = self.items[id];
        if !matches!(item.method, 1..=9) {
            return Err(refusal(&e, item.method));
        }
        // ARC's password shows only at the data's end: the entry is decoded once to find its
        // key before data is handed out. Nobody to ask: it's read as it is, and fails as
        // damaged at its end.
        let key = self.find_key(id, cx)?.unwrap_or(None);
        let (mut r, _) = self.input()?;
        r.skip_to(item.offset)?;
        let a = attempt(r, item, &self.entries[id], &key, false)?;
        Ok(Box::new(self.source.guard(a)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        unpack::tests::{crunch12, rle90, sample, squeeze},
        *,
    };
    use crate::{
        SimpleCtx, TestSink,
        codec::compress::{crc16, encode_raw},
    };

    const DATE: u16 = 0x50CF;
    const TIME: u16 = 0x45AF;

    /// `data` packed as `method` does it.
    fn pack(method: u8, data: &[u8]) -> Vec<u8> {
        match method {
            3 => rle90(data),
            4 => squeeze(&rle90(data)),
            5 => crunch12(data, false),
            6 => crunch12(&rle90(data), false),
            7 => crunch12(&rle90(data), true),
            8 => {
                let mut v = vec![12];
                v.extend(encode_raw(&rle90(data), Lzw::crunch(12)));
                v
            }
            9 => encode_raw(data, Lzw::SQUASH),
            _ => data.to_vec(),
        }
    }

    /// One entry: its header, then `data` packed with `method` and XORed with `key`.
    fn entry(method: u8, name: &[u8], data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut packed = pack(method, data);
        if !key.is_empty() {
            for (i, b) in packed.iter_mut().enumerate() {
                *b ^= key[i % key.len()];
            }
        }
        let mut h = vec![MARK, method];
        let mut n = [0u8; NAME_LEN];
        n[..name.len()].copy_from_slice(name);
        h.extend(n);
        h.extend((packed.len() as u32).to_le_bytes());
        h.extend(DATE.to_le_bytes());
        h.extend(TIME.to_le_bytes());
        h.extend(crc16(0, data).to_le_bytes());
        if method != 1 {
            h.extend((data.len() as u32).to_le_bytes());
        }
        h.extend(packed);
        h
    }

    fn arc(entries: &[(u8, &[u8], &[u8])], key: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = entries
            .iter()
            .flat_map(|(m, name, data)| entry(*m, name, data, key))
            .collect();
        out.extend([MARK, 0]);
        out
    }

    struct Opened {
        _dir: tempfile::TempDir,
        reader: ArcReader,
    }

    fn open(bytes: &[u8]) -> Result<Opened> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.arc");
        std::fs::write(&path, bytes).unwrap();
        let source = Source::new(&path, Vec::new(), &crate::OpenOptions::default())?;
        let reader = ArcReader::open(source, &mut SimpleCtx::new())?;
        Ok(Opened { _dir: dir, reader })
    }

    fn read(o: &mut Opened, id: usize, cx: &mut SimpleCtx) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        o.reader
            .open_entry(id, cx)?
            .read_to_end(&mut out)
            .map_err(|e| Error::from_io(&e))?;
        Ok(out)
    }

    fn test(o: &mut Opened, cx: &mut SimpleCtx) -> Result<crate::TestReport> {
        let mut sink = TestSink::default();
        o.reader.extract(&Selection::all(), &mut sink, cx)?;
        Ok(sink.report)
    }

    fn probe(head: &[u8]) -> Option<Confidence> {
        Arc.sniff(&Probe {
            head,
            len: Some(head.len() as u64),
            ..Probe::default()
        })
    }

    #[test]
    fn every_method_reads() {
        let data = sample();
        let methods: Vec<u8> = (1..=9).collect();
        let names: Vec<Vec<u8>> = methods
            .iter()
            .map(|m| format!("M{m}.BIN").into_bytes())
            .collect();
        let list: Vec<(u8, &[u8], &[u8])> = methods
            .iter()
            .zip(&names)
            .map(|(&m, n)| (m, n.as_slice(), data.as_slice()))
            .collect();
        let a = arc(&list, b"");
        assert_eq!(probe(&a), Some(Confidence::Certain));
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new();
        let entries = o.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 9);
        for (id, e) in entries.iter().enumerate() {
            assert_eq!(e.size, Some(data.len() as u64));
            assert_eq!(read(&mut o, id, &mut cx).unwrap(), data, "{}", e.path);
        }
        let report = test(&mut o, &mut cx).unwrap();
        assert!(report.ok(), "{report:?}");
        let info = o.reader.info(&mut cx).unwrap();
        assert_eq!(
            info.methods,
            [
                "Store",
                "Packed",
                "Squeezed",
                "Crunched (old)",
                "Crunched",
                "Squashed"
            ]
        );
        assert_eq!(info.encryption, Encryption::None);
        // Empty entries in every method.
        let list: Vec<(u8, &[u8], &[u8])> = methods
            .iter()
            .zip(&names)
            .map(|(&m, n)| (m, n.as_slice(), &b""[..]))
            .collect();
        let mut o = open(&arc(&list, b"")).unwrap();
        assert!(test(&mut o, &mut cx).unwrap().ok());
    }

    #[test]
    fn pak_methods_and_unknown_ones_are_listed_but_refused() {
        let a = arc(
            &[
                (10, b"CRUSH.TXT", b"x"),
                (11, b"DISTIL.TXT", b"y"),
                (2, b"PLAIN.TXT", b"plain"),
                (30, b"SUBDIR", b"z"),
            ],
            b"",
        );
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new();
        let methods: Vec<String> = o
            .reader
            .entries(&mut cx)
            .unwrap()
            .iter()
            .map(|e| e.method.clone().unwrap().into_owned())
            .collect();
        assert_eq!(methods, ["Crushed", "Distilled", "Store", "method 30"]);
        for (id, what) in [(0, "crushed"), (1, "distilled"), (3, "method 30")] {
            let err = read(&mut o, id, &mut cx).err().unwrap();
            assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
            assert!(err.message.contains(what), "{err}");
        }
        assert_eq!(read(&mut o, 2, &mut cx).unwrap(), b"plain");
        let report = test(&mut o, &mut cx).unwrap();
        assert_eq!(report.entries, 4);
        assert_eq!(report.errors_total, 3);
        assert!(
            report
                .errors
                .iter()
                .all(|e| e.kind == ErrorKind::UnsupportedOperation)
        );
    }

    #[test]
    fn sniffing_wants_a_whole_header() {
        let a = arc(&[(2, b"A.TXT", b"hello"), (2, b"B.TXT", b"x")], b"");
        assert_eq!(probe(&a), Some(Confidence::Certain));
        assert_eq!(probe(&a[..29]), None, "no room for what follows");
        let mut v = a.clone();
        v[1] = 0x45;
        assert_eq!(probe(&v), None, "method");
        let mut v = a.clone();
        v[2..15].fill(b'A');
        assert_eq!(probe(&v), None, "no NUL");
        let mut v = a.clone();
        v[3] = 0x07;
        assert_eq!(probe(&v), None, "unprintable");
        let mut v = a.clone();
        v[15] = 200;
        assert_eq!(probe(&v), None, "past the end");
        let mut v = a.clone();
        v[34] = b'?';
        assert_eq!(probe(&v), None, "no header after the data");
        let mut v = a.clone();
        v[25] = 9;
        assert_eq!(probe(&v), None, "stored, with two sizes");
        assert_eq!(
            probe(&[MARK, 0]),
            None,
            "an empty archive has nothing to go on"
        );
        assert_eq!(probe(b"\x1aE\xdf\xa3 Matroska"), None);
    }

    #[test]
    fn headers_are_checked() {
        let a = arc(&[(2, b"A.TXT", b"hello"), (1, b"OLD.TXT", b"old")], b"");
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new();
        assert_eq!(read(&mut o, 1, &mut cx).unwrap(), b"old");
        // No end marker.
        let mut o = open(&a[..a.len() - 2]).unwrap();
        assert_eq!(o.reader.entries(&mut cx).unwrap().len(), 2);
        // Nothing but the end marker.
        let mut o = open(&[MARK, 0]).unwrap();
        assert!(o.reader.entries(&mut cx).unwrap().is_empty());
        let corrupt = |bytes: &[u8]| {
            let err = open(bytes).err().expect("must fail");
            assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
        };
        corrupt(&a[..10]);
        corrupt(&a[..a.len() - 5]);
        corrupt(b"");
        corrupt(b"PK\x03\x04");
        let mut junk = a.clone();
        junk[34] = b'?';
        corrupt(&junk);
        let mut far = a;
        far[15..19].copy_from_slice(&u32::MAX.to_le_bytes());
        corrupt(&far);
    }

    #[test]
    fn names_are_oem_bytes() {
        let a = arc(&[(2, b"DIR\\A.TXT", b"a"), (2, b"\x81BER.TXT", b"b")], b"");
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new();
        let e = o.reader.entries(&mut cx).unwrap();
        assert_eq!(e[0].path, "DIR/A.TXT");
        assert_eq!(e[1].path, "üBER.TXT");
        assert_eq!(e[1].raw_path, b"\x81BER.TXT");
    }

    #[test]
    fn a_bad_crc_is_damage_when_nobody_can_be_asked() {
        let mut a = arc(&[(2, b"A.TXT", b"hello"), (3, b"B.TXT", b"bbbbbb")], b"");
        let at = a.windows(5).position(|w| w == b"hello").unwrap();
        a[at] ^= 1;
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new();
        let report = test(&mut o, &mut cx).unwrap();
        assert_eq!(report.errors_total, 1, "{report:?}");
        assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
        assert!(report.errors[0].message.contains("CRC-16"));
        let err = read(&mut o, 0, &mut cx).err().unwrap();
        assert_eq!(err.kind, ErrorKind::Corrupt);
        assert_eq!(read(&mut o, 1, &mut cx).unwrap(), b"bbbbbb");
    }

    #[test]
    fn a_password_is_asked_for_when_the_data_fails() {
        let text = b"some text that compresses, some text that compresses".repeat(20);
        let list: [(u8, &[u8], &[u8]); 3] = [
            (2, b"A.TXT", b"hello"),
            (8, b"B.TXT", &text),
            (4, b"C.TXT", &text),
        ];
        let a = arc(&list, b"SECRET");
        // The right one, after a wrong one.
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new().with_passwords(&["nope", "SECRET"]);
        let report = test(&mut o, &mut cx).unwrap();
        assert!(report.ok(), "{report:?}");
        assert!(
            o.reader
                .entries(&mut cx)
                .unwrap()
                .iter()
                .all(|e| e.encrypted)
        );
        assert_eq!(o.reader.info(&mut cx).unwrap().encryption, Encryption::All);
        // Entries read on their own.
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new().with_password("SECRET");
        assert_eq!(read(&mut o, 1, &mut cx).unwrap(), text);
        assert_eq!(read(&mut o, 0, &mut cx).unwrap(), b"hello");
        // No password: damage. A wrong one: a wrong password.
        let mut o = open(&a).unwrap();
        let report = test(&mut o, &mut SimpleCtx::new()).unwrap();
        assert_eq!(report.errors_total, 3);
        assert!(report.errors.iter().all(|e| e.kind == ErrorKind::Corrupt));
        let mut o = open(&a).unwrap();
        let err = test(&mut o, &mut SimpleCtx::new().with_password("nope")).unwrap_err();
        assert_eq!(err.kind, ErrorKind::WrongPassword);
        let mut o = open(&a).unwrap();
        let err = read(&mut o, 1, &mut SimpleCtx::new().with_password("nope")).unwrap_err();
        assert_eq!(err.kind, ErrorKind::WrongPassword);
    }

    /// ARC 5.21 upper-cases the password it's given: `beezip` opens what `-gbeezip` made, as
    /// one attempt.
    #[test]
    fn a_password_is_tried_upper_cased_too() {
        let text = b"garbled, garbled, garbled".repeat(20);
        let a = arc(&[(8, b"A.TXT", &text), (2, b"B.TXT", b"plain")], b"BEEZIP");
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new().with_password("beezip");
        let report = test(&mut o, &mut cx).unwrap();
        assert!(report.ok(), "{report:?}");
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new().with_password("beezip");
        assert_eq!(read(&mut o, 0, &mut cx).unwrap(), text);
        // A password ARC wrote as typed, lower case and all, still works as typed.
        let a = arc(&[(2, b"C.TXT", b"lower")], b"lower");
        let mut o = open(&a).unwrap();
        assert!(
            test(&mut o, &mut SimpleCtx::new().with_password("lower"))
                .unwrap()
                .ok()
        );
    }

    /// Entries added with and without `-g`: the password is kept, and a plain entry after it
    /// is tried without it.
    #[test]
    fn plain_and_encrypted_entries_mix() {
        let text = b"text text text text".repeat(40);
        let mut a = entry(2, b"A.TXT", b"plain", b"");
        a.extend(entry(8, b"B.TXT", &text, b"SECRET"));
        a.extend(entry(3, b"C.TXT", b"cccccccc plain", b""));
        a.extend(entry(2, b"D.TXT", b"secret again", b"SECRET"));
        a.extend([MARK, 0]);
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new().with_password("SECRET");
        let report = test(&mut o, &mut cx).unwrap();
        assert!(report.ok(), "{report:?}");
        let flags: Vec<bool> = o
            .reader
            .entries(&mut cx)
            .unwrap()
            .iter()
            .map(|e| e.encrypted)
            .collect();
        assert_eq!(flags, [false, true, false, true]);
        assert_eq!(o.reader.info(&mut cx).unwrap().encryption, Encryption::Some);
    }
}
