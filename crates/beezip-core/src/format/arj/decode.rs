//! An entry's data: each piece's packed bytes read from its part, ungarbled, decoded and
//! checked against the piece's CRC-32, all as the sink reads, in fixed memory.
//!
//! - **Methods 1–3** are LZH with ARJ's 26 KiB window, which delharc's `-lh6-`/`-lh7-` decoder
//!   reads (its window is larger, and its tables the same: 510 commands, 17 offsets).
//! - **Method 4** is ARJ's own (`decode_f`): a literal or a match, each length and distance a
//!   unary prefix and a few bits, no Huffman codes. Its reach is under 16 KiB.
//! - **Garble** XORs every packed byte with the password's next byte plus the header's modifier,
//!   the password starting over with each piece.

use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    sync::Arc,
};

use delharc::decode::{Decoder, Lh7Decoder};

use crate::{
    Error, ErrorKind, Result,
    io::BUF_SIZE,
    source::{Input, Source},
};

/// The set's parts, as listed when the archive opened.
pub struct Set {
    pub source: Source,
    /// Each part's size; `None` for one read through codecs.
    pub lens: Vec<Option<u64>>,
    /// Where each part starts in the progress count.
    starts: Vec<u64>,
    /// The progress total: every part's size, or the compressed file's.
    pub total: u64,
}

impl Set {
    pub fn new(source: Source) -> Result<Self> {
        let mut lens = Vec::with_capacity(source.volumes.len());
        for (k, path) in source.volumes.iter().enumerate() {
            lens.push(if k == 0 {
                source.codecs.is_empty().then_some(source.size)
            } else {
                let meta = std::fs::metadata(path)
                    .map_err(|e| Error::io(format!("opening {}", path.display()), &e))?;
                Some(meta.len())
            });
        }
        let mut starts = Vec::with_capacity(lens.len());
        let mut total = 0u64;
        for len in &lens {
            starts.push(total);
            total = total.saturating_add(len.unwrap_or(source.size));
        }
        Ok(Self {
            source,
            lens,
            starts,
            total,
        })
    }

    /// The part's file name, for messages.
    pub fn part_name(&self, k: usize) -> String {
        self.source
            .volumes
            .get(k)
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

enum Body {
    /// A plain part, buffered. What's read from it, or skipped, is counted here.
    File(BufReader<Input>),
    /// The first part through the source's codecs, which count the compressed bytes.
    Stream(Box<dyn Read + Send>),
}

struct Open {
    part: usize,
    body: Body,
    pos: u64,
}

/// Reads the parts forward, one open at a time. A plain part seeks; the stream through codecs
/// skips by reading, and starts over to go back.
pub struct Parts {
    set: Arc<Set>,
    open: Option<Open>,
}

impl Parts {
    /// A new pass over the set: the progress count starts at zero.
    pub fn new(set: &Arc<Set>) -> Self {
        set.source.counter.set(0);
        Self {
            set: set.clone(),
            open: None,
        }
    }

    /// The position in the open part.
    pub fn pos(&self) -> u64 {
        self.open.as_ref().map_or(0, |o| o.pos)
    }

    fn open_part(&mut self, k: usize) -> Result<()> {
        self.open = None;
        let src = &self.set.source;
        let body = if k == 0 && !src.codecs.is_empty() {
            Body::Stream(src.open_stream()?)
        } else {
            let input = if k == 0 {
                src.input()?
            } else {
                let path = src
                    .volumes
                    .get(k)
                    .ok_or_else(|| Error::corrupt("arj: a part past the set's end"))?;
                let file = File::open(path)
                    .map_err(|e| Error::io(format!("opening {}", path.display()), &e))?;
                Input::file(file)?
            };
            let start = self.set.starts.get(k).copied().unwrap_or(0);
            if start > src.counter.get() {
                src.counter.set(start);
            }
            Body::File(BufReader::with_capacity(BUF_SIZE, input))
        };
        self.open = Some(Open {
            part: k,
            body,
            pos: 0,
        });
        Ok(())
    }

    /// Moves to byte `at` of part `k`.
    pub fn goto(&mut self, k: usize, at: u64) -> Result<()> {
        let reopen = match &self.open {
            Some(o) => o.part != k || (o.pos > at && matches!(o.body, Body::Stream(_))),
            None => true,
        };
        if reopen {
            self.open_part(k)?;
        }
        let counter = self.set.source.counter.clone();
        let Some(o) = self.open.as_mut() else {
            return Ok(());
        };
        if at == o.pos {
            return Ok(());
        }
        let seek = |e: io::Error| Error::io("seeking in the archive", &e);
        match &mut o.body {
            Body::File(f) if at > o.pos => {
                let by = at - o.pos;
                f.seek_relative(i64::try_from(by).unwrap_or(i64::MAX))
                    .map_err(seek)?;
                counter.add(by);
            }
            Body::File(f) => {
                f.seek(SeekFrom::Start(at)).map_err(seek)?;
            }
            Body::Stream(s) => {
                let by = at - o.pos;
                let n = io::copy(&mut s.by_ref().take(by), &mut io::sink())
                    .map_err(|e| crate::io::read_error(&e).context("arj"))?;
                if n != by {
                    return Err(Error::corrupt("arj: the archive is cut short"));
                }
            }
        }
        o.pos = at;
        Ok(())
    }
}

impl Read for Parts {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(o) = self.open.as_mut() else {
            return Ok(0);
        };
        let n = match &mut o.body {
            Body::File(f) => {
                let n = f.read(buf)?;
                self.set.source.counter.add(n as u64);
                n
            }
            Body::Stream(s) => s.read(buf)?,
        };
        o.pos += n as u64;
        Ok(n)
    }
}

/// One piece of an entry: a file is one, unless it's split between parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    pub part: usize,
    /// Where its packed bytes start in the part.
    pub data: u64,
    pub packed: u64,
    pub size: u64,
    pub crc: u32,
    pub method: u8,
    pub garbled: bool,
    pub modifier: u8,
}

/// Garble: XOR with the password's next byte plus the modifier.
struct Garble {
    key: Vec<u8>,
    modifier: u8,
    at: usize,
}

impl Garble {
    fn new(password: &[u8], modifier: u8) -> Self {
        // An empty password is ARJ's string with only its NUL.
        let key = if password.is_empty() {
            vec![0]
        } else {
            password.to_vec()
        };
        Self {
            key,
            modifier,
            at: 0,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            *b ^= self.modifier.wrapping_add(self.key[self.at]);
            self.at += 1;
            if self.at == self.key.len() {
                self.at = 0;
            }
        }
    }
}

fn cut_short() -> io::Error {
    Error::corrupt("arj: the archive is cut short").into_io()
}

/// A piece's packed bytes: at most `left` more, ungarbled.
struct Packed {
    parts: Parts,
    left: u64,
    garble: Option<Garble>,
}

impl Read for Packed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.parts.read(&mut buf[..want])?;
        if n == 0 {
            return Err(cut_short());
        }
        self.left -= n as u64;
        if let Some(g) = &mut self.garble {
            g.apply(&mut buf[..n]);
        }
        Ok(n)
    }
}

/// Bits, most significant first, as ARJ's `getbits` reads them.
struct Bits<R> {
    inner: R,
    buf: Box<[u8; 4096]>,
    at: usize,
    end: usize,
    acc: u32,
    count: u32,
}

impl<R: Read> Bits<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Box::new([0; 4096]),
            at: 0,
            end: 0,
            acc: 0,
            count: 0,
        }
    }

    fn byte(&mut self) -> io::Result<u32> {
        if self.at == self.end {
            let n = loop {
                match self.inner.read(&mut self.buf[..]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    r => break r?,
                }
            };
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the packed data ends early",
                ));
            }
            (self.at, self.end) = (0, n);
        }
        let b = self.buf[self.at];
        self.at += 1;
        Ok(u32::from(b))
    }

    /// The next `n` bits, `n` at most 16.
    fn get(&mut self, n: u32) -> io::Result<u32> {
        while self.count < n {
            self.acc = (self.acc << 8) | self.byte()?;
            self.count += 8;
        }
        self.count -= n;
        Ok((self.acc >> self.count) & ((1 << n) - 1))
    }
}

/// Method 4's window: its farthest match reaches 15 872 bytes back.
const FAST_WINDOW: usize = 1 << 14;

/// ARJ's method 4.
struct Fastest<R> {
    bits: Bits<R>,
    window: Box<[u8; FAST_WINDOW]>,
    produced: u64,
    /// A match's distance and the bytes of it still to copy.
    copy: (usize, usize),
}

impl<R: Read> Fastest<R> {
    fn new(inner: R) -> Self {
        Self {
            bits: Bits::new(inner),
            window: Box::new([0; FAST_WINDOW]),
            produced: 0,
            copy: (0, 0),
        }
    }

    /// A unary prefix of up to `to - from` ones choosing the width, then that many bits, as
    /// ARJ's `decode_len` (0, 7) and `decode_ptr` (9, 13).
    fn value(&mut self, from: u32, to: u32) -> io::Result<u32> {
        let mut add = 0;
        let mut width = from;
        while width < to {
            if self.bits.get(1)? == 0 {
                break;
            }
            add += 1 << width;
            width += 1;
        }
        Ok(self.bits.get(width)? + add)
    }

    fn push(&mut self, b: u8) {
        // The position in the window wraps with the count.
        self.window[(self.produced as usize) & (FAST_WINDOW - 1)] = b;
        self.produced += 1;
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            if self.copy.1 > 0 {
                let from = (self.produced as usize).wrapping_sub(self.copy.0) & (FAST_WINDOW - 1);
                let b = self.window[from];
                self.push(b);
                buf[n] = b;
                n += 1;
                self.copy.1 -= 1;
                continue;
            }
            let len = self.value(0, 7)?;
            if len == 0 {
                let b = self.bits.get(8)? as u8;
                self.push(b);
                buf[n] = b;
                n += 1;
            } else {
                let back = self.value(9, 13)?;
                if u64::from(back) >= self.produced {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a match reaches back before the start",
                    ));
                }
                self.copy = (back as usize + 1, len as usize + 2);
            }
        }
        Ok(n)
    }

    fn into_inner(self) -> R {
        self.bits.inner
    }
}

/// A piece's decoder.
enum Method {
    Store(Box<Packed>),
    Lzh(Box<Lh7Decoder<Packed>>),
    Fastest(Box<Fastest<Packed>>),
}

impl Method {
    /// Reads at most `buf.len()`, which the caller keeps within the piece's size.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Store(p) => p.read(buf),
            Self::Lzh(d) => {
                d.fill_buffer(buf).map_err(io::Error::from)?;
                Ok(buf.len())
            }
            Self::Fastest(d) => d.read(buf),
        }
    }

    fn into_parts(self) -> Parts {
        match self {
            Self::Store(p) => p.parts,
            Self::Lzh(d) => d.into_inner().parts,
            Self::Fastest(d) => d.into_inner().parts,
        }
    }
}

/// The methods BeeZip decodes.
pub fn decodes(method: u8) -> bool {
    method <= 4
}

struct Decoding {
    method: Method,
    left: u64,
    crc: crc32fast::Hasher,
    expect: u32,
}

/// An entry's data, piece after piece. It owns the parts while reading, and hands them back.
pub struct EntryData<'a> {
    set: Arc<Set>,
    pieces: &'a [Piece],
    path: &'a str,
    /// The garble password, for garbled pieces.
    key: Option<Vec<u8>>,
    next: usize,
    idle: Option<Parts>,
    decoding: Option<Decoding>,
    /// Why the entry can't be read, given on the first read.
    fail: Option<Error>,
    /// Every piece was read and matched its CRC.
    pub verified: bool,
}

impl<'a> EntryData<'a> {
    pub fn new(
        parts: Parts,
        pieces: &'a [Piece],
        path: &'a str,
        key: Option<Vec<u8>>,
        fail: Option<Error>,
    ) -> Self {
        Self {
            set: parts.set.clone(),
            pieces,
            path,
            key,
            next: 0,
            idle: Some(parts),
            decoding: None,
            fail,
            verified: false,
        }
    }

    pub fn into_parts(self) -> Parts {
        match (self.decoding, self.idle) {
            (Some(d), _) => d.method.into_parts(),
            (None, Some(p)) => p,
            // Only after a panic part-way through a piece: nothing is open.
            (None, None) => Parts {
                set: self.set,
                open: None,
            },
        }
    }

    fn garbled(&self) -> bool {
        self.pieces.iter().any(|p| p.garbled)
    }

    /// A read error with the entry named. On a garbled entry, data that doesn't decode is as
    /// likely a wrong password as damage: garble has no password check.
    fn hint(&self, e: io::Error) -> io::Error {
        if e.get_ref().is_some_and(|x| x.is::<Error>()) || e.raw_os_error().is_some() {
            return e;
        }
        if self.garbled() {
            return wrong_password().into_io();
        }
        let what = if e.kind() == io::ErrorKind::UnexpectedEof {
            "the packed data ends early".to_owned()
        } else {
            e.to_string()
        };
        Error::corrupt(format!("arj: `{}`: {what}", self.path)).into_io()
    }

    fn mismatch(&self) -> io::Error {
        if self.garbled() {
            wrong_password().into_io()
        } else {
            Error::corrupt(format!("arj: `{}` doesn't match its CRC-32", self.path)).into_io()
        }
    }

    /// Starts piece `self.next`, or reports the entry's end.
    fn start(&mut self) -> io::Result<bool> {
        let Some(piece) = self.pieces.get(self.next) else {
            self.verified = true;
            return Ok(false);
        };
        self.next += 1;
        let Some(mut parts) = self.idle.take() else {
            return Err(Error::corrupt("arj: the entry's reader was lost").into_io());
        };
        if piece.size == 0 {
            self.idle = Some(parts);
            return if piece.crc == 0 {
                Ok(true)
            } else {
                Err(self.mismatch())
            };
        }
        if let Err(e) = parts.goto(piece.part, piece.data) {
            self.idle = Some(parts);
            return Err(e.into_io());
        }
        let garble = piece
            .garbled
            .then(|| Garble::new(self.key.as_deref().unwrap_or_default(), piece.modifier));
        let packed = Packed {
            parts,
            left: piece.packed,
            garble,
        };
        let method = match piece.method {
            0 => Method::Store(Box::new(packed)),
            4 => Method::Fastest(Box::new(Fastest::new(packed))),
            _ => Method::Lzh(Box::new(Lh7Decoder::new(packed))),
        };
        self.decoding = Some(Decoding {
            method,
            left: piece.size,
            crc: crc32fast::Hasher::new(),
            expect: piece.crc,
        });
        Ok(true)
    }
}

/// What a garbled entry that fails reads as (as zip's ZipCrypto does).
pub fn wrong_password() -> Error {
    Error::new(ErrorKind::WrongPassword, "wrong password or damaged data")
}

impl Read for EntryData<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.fail {
            return Err(e.clone().into_io());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(d) = self.decoding.as_mut() {
                if d.left > 0 {
                    let want = buf.len().min(usize::try_from(d.left).unwrap_or(usize::MAX));
                    let n = match d.method.read(&mut buf[..want]) {
                        Ok(0) => Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the packed data ends early",
                        )),
                        r => r,
                    };
                    let n = n.map_err(|e| self.hint(e))?;
                    let Some(d) = self.decoding.as_mut() else {
                        return Ok(0);
                    };
                    d.crc.update(&buf[..n]);
                    d.left -= n as u64;
                    return Ok(n);
                }
                if let Some(d) = self.decoding.take() {
                    let ok = d.crc.finalize() == d.expect;
                    self.idle = Some(d.method.into_parts());
                    if !ok {
                        return Err(self.mismatch());
                    }
                }
                continue;
            }
            if !self.start()? {
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fastest(data: &[u8], size: usize) -> io::Result<Vec<u8>> {
        let mut d = Fastest::new(data);
        let mut out = vec![0u8; size];
        let mut n = 0;
        while n < size {
            let k = d.read(&mut out[n..])?;
            n += k;
        }
        Ok(out)
    }

    #[test]
    fn method_4_literals_and_matches() {
        // A literal `A` (a 0, then eight bits), a match of three (`10` picks one more bit, `0`:
        // length 1, plus 2) one byte back (a 0, then nine zero bits): unarc-rs's case.
        assert_eq!(fastest(&[0x20, 0xc0, 0], 4).unwrap(), b"AAAA");
        // A match before any byte.
        assert!(fastest(&[0x80, 0], 1).is_err());
        for data in [&[][..], &[0][..], &[0x80][..]] {
            assert!(fastest(data, 1).is_err());
        }
    }

    #[test]
    fn garble_is_its_own_inverse_and_restarts_the_password() {
        let mut g = Garble::new(b"secret", 0x42);
        let mut data = *b"Hello, World! This is a test.";
        g.apply(&mut data);
        assert_ne!(&data, b"Hello, World! This is a test.");
        let mut g = Garble::new(b"secret", 0x42);
        g.apply(&mut data);
        assert_eq!(&data, b"Hello, World! This is a test.");
        let mut g = Garble::new(b"", 0x10);
        let mut one = [0x10u8];
        g.apply(&mut one);
        assert_eq!(one, [0]);
    }

    #[test]
    fn bits_come_most_significant_first() {
        let mut b = Bits::new(&[0b1010_0000u8, 0xFF][..]);
        assert_eq!(b.get(1).unwrap(), 1);
        assert_eq!(b.get(3).unwrap(), 0b010);
        assert_eq!(b.get(0).unwrap(), 0);
        assert_eq!(b.get(12).unwrap(), 0x0FF);
        assert!(b.get(1).is_err());
    }
}
