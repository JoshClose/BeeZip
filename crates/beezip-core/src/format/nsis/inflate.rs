//! Raw deflate (RFC 1951) of BeeZip's own, for NSIS installers (docs/M10.md §3.2). NSIS up to
//! 2.51 decoded deflate with its own copy of zlib's inflater, which reads a stored block's
//! length and not its complement, and makensis 2 wrote stored blocks that way; NSIS 3 reads
//! and writes zlib's form. zlib-rs refuses NSIS 2's, so this reads either, as asked.
//!
//! It streams: the input is pulled as needed, and the output comes out through [`Read`] with
//! 32 KiB of history kept for back-references. Errors are `Corrupt`.

use std::io::{self, Read};

use crate::Error;

const WINDOW: usize = 32 * 1024;
/// How much is decoded ahead of what's been read.
const CHUNK: usize = 64 * 1024;
const INPUT: usize = 64 * 1024;

fn bad(message: &str) -> io::Error {
    Error::corrupt(format!("nsis: deflate: {message}")).into_io()
}

/// Bits of the fast table's index.
const FAST: u32 = 10;

/// A canonical Huffman code: a table for codes of up to [`FAST`] bits, and the counts and
/// symbols for the rest.
struct Huff {
    /// `(length << 12) | symbol`, 0 where the code is longer than `FAST`.
    fast: Vec<u16>,
    count: [u16; 16],
    sym: Vec<u16>,
}

impl Huff {
    fn new(lens: &[u8]) -> io::Result<Self> {
        let mut count = [0u16; 16];
        for &l in lens {
            count[usize::from(l)] += 1;
        }
        count[0] = 0;
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - i32::from(c);
            if left < 0 {
                return Err(bad("a Huffman code is over-subscribed"));
            }
        }
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut sym = vec![0u16; lens.len()];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                let o = &mut offs[usize::from(l)];
                sym[usize::from(*o)] = s as u16;
                *o += 1;
            }
        }
        let mut fast = vec![0u16; 1 << FAST];
        let mut code: u32 = 0;
        let mut idx = 0usize;
        for len in 1..=15u32 {
            for _ in 0..count[len as usize] {
                if len <= FAST {
                    // Deflate's codes are read from the low bit up.
                    let rev = (code.reverse_bits() >> (32 - len)) as usize;
                    let mut i = rev;
                    while i < (1 << FAST) {
                        fast[i] = ((len as u16) << 12) | sym[idx];
                        i += 1 << len;
                    }
                }
                idx += 1;
                code += 1;
            }
            code <<= 1;
        }
        Ok(Self { fast, count, sym })
    }

    fn fixed() -> io::Result<(Self, Self)> {
        let mut l = [0u8; 288];
        for (i, v) in l.iter_mut().enumerate() {
            *v = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        Ok((Self::new(&l)?, Self::new(&[5u8; 30])?))
    }
}

const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The order code length codes come in.
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

enum State {
    /// At a block's header.
    Header,
    /// In a stored block, with this many bytes left.
    Stored(usize),
    /// In a block of codes.
    Codes(Box<(Huff, Huff)>),
    Done,
}

pub(super) struct Inflate<R> {
    input: R,
    buf: Box<[u8]>,
    at: usize,
    end: usize,
    /// Bytes moved from `buf` into `bits`.
    taken: u64,
    bits: u64,
    nbits: u32,
    nsis2: bool,
    /// History, then output not yet read from `pos` on.
    out: Vec<u8>,
    pos: usize,
    state: State,
    last: bool,
}

impl<R: Read> Inflate<R> {
    /// `nsis2`: stored blocks have no NLEN.
    pub(super) fn new(input: R, nsis2: bool) -> Self {
        Self {
            input,
            buf: vec![0; INPUT].into_boxed_slice(),
            at: 0,
            end: 0,
            taken: 0,
            bits: 0,
            nbits: 0,
            nsis2,
            out: Vec::with_capacity(WINDOW + 2 * CHUNK),
            pos: 0,
            state: State::Header,
            last: false,
        }
    }

    /// The input bytes the stream took, up to its last block's end.
    pub(super) fn consumed(&self) -> u64 {
        self.taken - u64::from(self.nbits / 8)
    }

    /// Whether the last block has ended.
    pub(super) fn done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// The next input byte; `None` at the input's end.
    fn byte(&mut self) -> io::Result<Option<u8>> {
        if self.at == self.end {
            self.at = 0;
            self.end = loop {
                match self.input.read(&mut self.buf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            };
            if self.end == 0 {
                return Ok(None);
            }
        }
        let b = self.buf[self.at];
        self.at += 1;
        self.taken += 1;
        Ok(Some(b))
    }

    /// As many bits as fit, without failing at the input's end.
    fn refill(&mut self) -> io::Result<()> {
        while self.nbits <= 56 {
            match self.byte()? {
                Some(b) => {
                    self.bits |= u64::from(b) << self.nbits;
                    self.nbits += 8;
                }
                None => break,
            }
        }
        Ok(())
    }

    fn take(&mut self, n: u32) -> io::Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        if self.nbits < n {
            self.refill()?;
            if self.nbits < n {
                return Err(bad("the stream ends inside a block"));
            }
        }
        let v = (self.bits & ((1u64 << n) - 1)) as u32;
        self.bits >>= n;
        self.nbits -= n;
        Ok(v)
    }

    fn symbol(&mut self, h: &Huff) -> io::Result<u16> {
        if self.nbits < 15 {
            self.refill()?;
        }
        let e = h.fast[(self.bits & ((1 << FAST) - 1)) as usize];
        if e != 0 {
            let len = u32::from(e >> 12);
            if len > self.nbits {
                return Err(bad("the stream ends inside a code"));
            }
            self.bits >>= len;
            self.nbits -= len;
            return Ok(e & 0xFFF);
        }
        // Longer than the table: bit by bit, canonically.
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= self.take(1)? as i32;
            let count = i32::from(h.count[len]);
            if code - count < first {
                return h
                    .sym
                    .get(usize::try_from(index + (code - first)).unwrap_or(usize::MAX))
                    .copied()
                    .ok_or_else(|| bad("a code is out of range"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(bad("a code isn't in its table"))
    }

    /// A dynamic block's two codes.
    fn dynamic(&mut self) -> io::Result<(Huff, Huff)> {
        let hlit = self.take(5)? as usize + 257;
        let hdist = self.take(5)? as usize + 1;
        let hclen = self.take(4)? as usize + 4;
        if hlit > 286 || hdist > 30 {
            return Err(bad("a block has too many codes"));
        }
        let mut cl = [0u8; 19];
        for &o in &CL_ORDER[..hclen] {
            cl[o] = self.take(3)? as u8;
        }
        let clh = Huff::new(&cl)?;
        let mut lens = [0u8; 286 + 30];
        let n = hlit + hdist;
        let mut i = 0;
        while i < n {
            let s = self.symbol(&clh)?;
            let (value, times) = match s {
                0..=15 => (s as u8, 1),
                16 => {
                    let prev = *i
                        .checked_sub(1)
                        .and_then(|p| lens.get(p))
                        .ok_or_else(|| bad("a repeat has no length before it"))?;
                    (prev, 3 + self.take(2)? as usize)
                }
                17 => (0, 3 + self.take(3)? as usize),
                18 => (0, 11 + self.take(7)? as usize),
                _ => return Err(bad("a code length symbol is out of range")),
            };
            if i + times > n {
                return Err(bad("a block has too many code lengths"));
            }
            lens[i..i + times].fill(value);
            i += times;
        }
        if lens[256] == 0 {
            return Err(bad("a block has no end-of-block code"));
        }
        Ok((Huff::new(&lens[..hlit])?, Huff::new(&lens[hlit..n])?))
    }

    /// Decodes until `CHUNK` bytes are ahead of what's been read, or the stream ends.
    fn step(&mut self) -> io::Result<()> {
        // Keep 32 KiB of history; drop what's before it.
        if self.pos > WINDOW + CHUNK {
            let drop = self.pos - WINDOW;
            self.out.drain(..drop);
            self.pos -= drop;
        }
        while self.out.len() - self.pos < CHUNK {
            match std::mem::replace(&mut self.state, State::Header) {
                State::Done => {
                    self.state = State::Done;
                    return Ok(());
                }
                State::Header => {
                    if self.last {
                        self.state = State::Done;
                        return Ok(());
                    }
                    self.last = self.take(1)? == 1;
                    self.state = match self.take(2)? {
                        0 => {
                            // To a byte boundary, then LEN (and NLEN but in NSIS 2's form).
                            let r = self.nbits % 8;
                            self.bits >>= r;
                            self.nbits -= r;
                            let len = self.take(16)? as usize;
                            if !self.nsis2 && self.take(16)? as usize != !len & 0xFFFF {
                                return Err(bad(
                                    "a stored block's NLEN isn't its LEN's complement",
                                ));
                            }
                            State::Stored(len)
                        }
                        1 => State::Codes(Box::new(Huff::fixed()?)),
                        2 => State::Codes(Box::new(self.dynamic()?)),
                        _ => return Err(bad("a block is of type 3")),
                    };
                }
                State::Stored(mut left) => {
                    // Whole bytes still in the bit buffer, then the input.
                    while left > 0 && self.nbits >= 8 {
                        self.out.push(self.bits as u8);
                        self.bits >>= 8;
                        self.nbits -= 8;
                        left -= 1;
                    }
                    while left > 0 && self.out.len() - self.pos < CHUNK {
                        if self.at == self.end {
                            // The input buffer refilled, its first byte taken.
                            let b = self
                                .byte()?
                                .ok_or_else(|| bad("the stream ends inside a stored block"))?;
                            self.out.push(b);
                            left -= 1;
                            continue;
                        }
                        let n = left.min(self.end - self.at);
                        self.out.extend_from_slice(&self.buf[self.at..self.at + n]);
                        self.at += n;
                        self.taken += n as u64;
                        left -= n;
                    }
                    self.state = if left > 0 {
                        State::Stored(left)
                    } else {
                        State::Header
                    };
                }
                State::Codes(t) => {
                    let (lit, dist) = &*t;
                    let mut ended = false;
                    while self.out.len() - self.pos < CHUNK {
                        let s = usize::from(self.symbol(lit)?);
                        if s < 256 {
                            self.out.push(s as u8);
                            continue;
                        }
                        if s == 256 {
                            ended = true;
                            break;
                        }
                        let s = s - 257;
                        if s >= 29 {
                            return Err(bad("a length symbol is out of range"));
                        }
                        let len = usize::from(LBASE[s]) + self.take(u32::from(LEXT[s]))? as usize;
                        let ds = usize::from(self.symbol(dist)?);
                        if ds >= 30 {
                            return Err(bad("a distance symbol is out of range"));
                        }
                        let d = usize::from(DBASE[ds]) + self.take(u32::from(DEXT[ds]))? as usize;
                        if d > self.out.len() {
                            return Err(bad("a distance reaches before the stream's start"));
                        }
                        let start = self.out.len() - d;
                        if d >= len {
                            self.out.extend_from_within(start..start + len);
                        } else {
                            for k in 0..len {
                                let c = self.out[start + k];
                                self.out.push(c);
                            }
                        }
                    }
                    self.state = if ended {
                        State::Header
                    } else {
                        State::Codes(t)
                    };
                }
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for Inflate<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos == self.out.len() {
            self.step()?;
        }
        let n = buf.len().min(self.out.len() - self.pos);
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::DeflateEncoder};

    use super::*;

    fn noise(len: usize) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }

    fn deflate(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn inflate(packed: &[u8], nsis2: bool) -> io::Result<(Vec<u8>, u64)> {
        let mut r = Inflate::new(packed, nsis2);
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok((out, r.consumed()))
    }

    /// Stored blocks as NSIS 2 wrote them: LEN without NLEN.
    fn nsis2_stored(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let blocks: Vec<&[u8]> = data.chunks(30_000).collect();
        for (i, b) in blocks.iter().enumerate() {
            out.push(u8::from(i + 1 == blocks.len()));
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(b);
        }
        out
    }

    #[test]
    fn reads_what_zlib_writes() {
        let mut data = noise(300_000);
        data.extend(b"abcabcabc".repeat(50_000));
        for level in [0, 1, 6, 9] {
            let packed = deflate(&data, level);
            let (out, used) = inflate(&packed, false).unwrap();
            assert!(out == data, "level {level}");
            assert_eq!(used, packed.len() as u64, "level {level}");
        }
    }

    #[test]
    fn reads_nsis_2s_stored_blocks_only_when_asked() {
        let data = noise(100_000);
        let packed = nsis2_stored(&data);
        let (out, used) = inflate(&packed, true).unwrap();
        assert!(out == data);
        assert_eq!(used, packed.len() as u64);
        let e = inflate(&packed, false).unwrap_err();
        assert!(e.to_string().contains("NLEN"), "{e}");
        // And zlib's stored blocks aren't NSIS 2's.
        assert!(inflate(&deflate(&data, 0), true).map_or(true, |(o, _)| o != data));
    }

    #[test]
    fn says_where_the_stream_ends() {
        let data = noise(5000);
        let mut packed = deflate(&data, 6);
        let len = packed.len() as u64;
        packed.extend_from_slice(b"the next record");
        let (out, used) = inflate(&packed, false).unwrap();
        assert!(out == data);
        assert_eq!(used, len);
    }

    #[test]
    fn damage_is_corrupt() {
        let data = b"hello hello hello hello".repeat(1000);
        let packed = deflate(&data, 9);
        for cut in [1, packed.len() / 2, packed.len() - 1] {
            let e = inflate(&packed[..cut], false).unwrap_err();
            assert_eq!(
                crate::io::read_error(&e).kind,
                crate::ErrorKind::Corrupt,
                "{cut}"
            );
        }
        assert!(inflate(&[0x07], false).is_err(), "block type 3");
    }
}
