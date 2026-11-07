//! Unix `compress` (`.Z`, docs/M5.md §5.7): LZW with LSB-first codes of 9 up to `max_bits` (at
//! most 16) bits. In-house, written from the format as libarchive (BSD-2) and public
//! descriptions give it.
//!
//! - **The header** is `1F 9D` and a flags byte: bits 0–4 are `max_bits`, 0x80 is block mode
//!   (code 256 is CLEAR, the first free code 257), 0x60 is reserved.
//! - **Groups:** compress writes codes in groups of eight, so one group is `n_bits` bytes. When
//!   the code width grows, and after a CLEAR, it pads the group to its full length, so the
//!   decoder skips to the next group boundary, counted from the last width change.
//! - There is no end code, length or checksum: the stream ends with its input.
//! - BeeZip writes 16-bit block mode, as `compress` does by default, with compress's rule for
//!   when to clear the table. There are no levels.

use std::io::{self, Read, Write};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
};

pub struct Compress;

const MAGIC: [u8; 2] = [0x1F, 0x9D];
const BLOCK_MODE: u8 = 0x80;
const RESERVED: u8 = 0x60;
const CLEAR: u32 = 256;
const INIT_BITS: u32 = 9;
const MAX_BITS: u32 = 16;
/// How often, in input bytes, a full table's ratio is checked.
const CHECK_GAP: u64 = 10_000;
const IN_BUF: usize = 64 * 1024;

impl Codec for Compress {
    fn id(&self) -> CodecId {
        CodecId::Compress
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".z", ".taz"]
    }

    /// `1F 9D`, a flags byte giving 9–16 bits with the reserved bits clear, and a first code
    /// that is a literal (or CLEAR in block mode): about 2⁻²¹ false positives on random data
    /// (docs/M5.md §16).
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let head = probe.head;
        if head.len() < 3 || head[..2] != MAGIC {
            return None;
        }
        let flags = head[2];
        if !(9..=16).contains(&(flags & 0x1F)) || flags & RESERVED != 0 {
            return None;
        }
        let first_ok = match head.get(3..5) {
            Some(&[a, b]) => {
                let code = u32::from(a) | (u32::from(b) & 1) << 8;
                code < 256 || (code == CLEAR && flags & BLOCK_MODE != 0)
            }
            // The empty stream is the header alone; one byte more can't hold a code.
            _ => head.len() == 3,
        };
        first_ok.then_some(Confidence::Certain)
    }

    fn levels(&self) -> Option<Levels> {
        None
    }

    fn decoder<'a>(
        &self,
        r: Box<dyn Read + Send + 'a>,
        _: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        Ok(Box::new(Decoder::new(r)))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        opts.resolve_level(self.id(), self.levels())?;
        Ok(finisher(Encoder::new(w), |e| e.finish()))
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!(".Z: {msg}"))
}

/// The largest code before the width grows; at `max_bits`, the table's end. As in compress, the
/// first section is 9 bits even when `max_bits` is 9.
fn section_end(n_bits: u32, max_bits: u32) -> u32 {
    if n_bits == max_bits {
        1 << max_bits
    } else {
        (1 << n_bits) - 1
    }
}

/// A streaming decoder in fixed memory: 64 KiB of input, 192 KiB of tables and at most 64 KiB
/// of one string's output.
pub struct Decoder<R> {
    inner: R,
    inbuf: Box<[u8]>,
    in_pos: usize,
    in_len: usize,
    bitbuf: u32,
    bitcnt: u32,
    /// Bits read since the last group boundary.
    group_bits: u64,
    started: bool,
    done: bool,
    block: bool,
    max_bits: u32,
    n_bits: u32,
    maxcode: u32,
    free_ent: u32,
    oldcode: Option<u32>,
    finchar: u8,
    prefix: Box<[u16]>,
    suffix: Box<[u8]>,
    /// The current string, last byte first.
    stack: Vec<u8>,
}

impl<R: Read> Decoder<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            inbuf: vec![0; IN_BUF].into_boxed_slice(),
            in_pos: 0,
            in_len: 0,
            bitbuf: 0,
            bitcnt: 0,
            group_bits: 0,
            started: false,
            done: false,
            block: false,
            max_bits: MAX_BITS,
            n_bits: INIT_BITS,
            maxcode: 0,
            free_ent: 0,
            oldcode: None,
            finchar: 0,
            prefix: vec![0; 1 << MAX_BITS].into_boxed_slice(),
            suffix: (0..1u32 << MAX_BITS).map(|i| i as u8).collect(),
            stack: Vec::with_capacity(1 << MAX_BITS),
        }
    }

    fn byte(&mut self) -> io::Result<Option<u8>> {
        if self.in_pos == self.in_len {
            self.in_len = loop {
                match self.inner.read(&mut self.inbuf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            };
            self.in_pos = 0;
            if self.in_len == 0 {
                return Ok(None);
            }
        }
        self.in_pos += 1;
        Ok(Some(self.inbuf[self.in_pos - 1]))
    }

    fn header(&mut self) -> io::Result<()> {
        let mut h = [0u8; 3];
        for b in &mut h {
            *b = self.byte()?.ok_or_else(|| bad("the header is cut short"))?;
        }
        if h[..2] != MAGIC {
            return Err(bad("not a compress stream"));
        }
        self.max_bits = u32::from(h[2] & 0x1F);
        if !(9..=MAX_BITS).contains(&self.max_bits) {
            return Err(bad(&format!(
                "a code width of {} bits (9 to 16 are possible)",
                self.max_bits
            )));
        }
        // The reserved bits are ignored, as gzip ignores them.
        self.block = h[2] & BLOCK_MODE != 0;
        self.reset();
        Ok(())
    }

    fn reset(&mut self) {
        self.n_bits = INIT_BITS;
        self.maxcode = (1 << INIT_BITS) - 1;
        self.free_ent = if self.block { CLEAR + 1 } else { 256 };
        self.oldcode = None;
        self.group_bits = 0;
    }

    /// The next code, or `None` when fewer than `n_bits` bits are left.
    fn code(&mut self) -> io::Result<Option<u32>> {
        while self.bitcnt < self.n_bits {
            match self.byte()? {
                Some(b) => {
                    self.bitbuf |= u32::from(b) << self.bitcnt;
                    self.bitcnt += 8;
                }
                None => return Ok(None),
            }
        }
        let code = self.bitbuf & ((1 << self.n_bits) - 1);
        self.bitbuf >>= self.n_bits;
        self.bitcnt -= self.n_bits;
        self.group_bits += u64::from(self.n_bits);
        Ok(Some(code))
    }

    /// Skips the rest of the current group of eight codes: `false` if the input ends first.
    fn align(&mut self) -> io::Result<bool> {
        let group = u64::from(self.n_bits) * 8;
        let rem = self.group_bits % group;
        self.group_bits = 0;
        if rem == 0 {
            return Ok(true);
        }
        // Fewer than 8 bits are buffered after a code, and the skip ends on a byte boundary.
        let skip = (group - rem).saturating_sub(u64::from(self.bitcnt));
        self.bitbuf = 0;
        self.bitcnt = 0;
        for _ in 0..skip / 8 {
            if self.byte()?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Decodes one code into `stack`, or sets `done` at the end of the input.
    fn step(&mut self) -> io::Result<()> {
        loop {
            if self.free_ent > self.maxcode {
                if !self.align()? {
                    self.done = true;
                    return Ok(());
                }
                // A max_bits of 9 grows to 10 bits, as compress does.
                self.n_bits += 1;
                if self.n_bits > MAX_BITS {
                    return Err(bad("the code width grows past 16 bits"));
                }
                self.maxcode = section_end(self.n_bits, self.max_bits);
            }
            let Some(code) = self.code()? else {
                self.done = true;
                return Ok(());
            };
            if self.block && code == CLEAR {
                if !self.align()? {
                    self.done = true;
                    return Ok(());
                }
                self.reset();
                continue;
            }
            let mut c = code;
            if c >= self.free_ent {
                // Only the code about to be defined can be used before it is (KwKwK).
                let Some(old) = self.oldcode.filter(|_| c == self.free_ent) else {
                    return Err(bad("a code that isn't defined yet"));
                };
                self.stack.push(self.finchar);
                c = old;
            }
            while c >= 256 {
                self.stack.push(self.suffix[c as usize]);
                // A prefix is always smaller than its code, so this ends.
                c = u32::from(self.prefix[c as usize]);
            }
            self.finchar = c as u8;
            self.stack.push(self.finchar);
            if let Some(old) = self.oldcode
                && self.free_ent < 1 << self.max_bits
            {
                self.prefix[self.free_ent as usize] = old as u16;
                self.suffix[self.free_ent as usize] = self.finchar;
                self.free_ent += 1;
            }
            self.oldcode = Some(code);
            return Ok(());
        }
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.started {
            self.started = true;
            self.header()?;
        }
        let mut n = 0;
        while n < buf.len() {
            if !self.stack.is_empty() {
                let k = self.stack.len().min(buf.len() - n);
                let from = self.stack.len() - k;
                for (o, s) in buf[n..n + k]
                    .iter_mut()
                    .zip(self.stack[from..].iter().rev())
                {
                    *o = *s;
                }
                self.stack.truncate(from);
                n += k;
            } else if self.done {
                break;
            } else {
                self.step()?;
            }
        }
        Ok(n)
    }
}

const HASH_BITS: u32 = 17;
const EMPTY: u32 = u32::MAX;

/// A streaming encoder compatible with compress(1): 16-bit block mode, with its rules for
/// growing the width and clearing the table. Memory: a 768 KiB hash table.
pub struct Encoder<W: Write> {
    out: W,
    buf: Vec<u8>,
    bitbuf: u64,
    bitcnt: u32,
    /// Codes written in the current group of eight.
    in_group: u32,
    max_bits: u32,
    n_bits: u32,
    maxcode: u32,
    free_ent: u32,
    ent: Option<u32>,
    keys: Box<[u32]>,
    codes: Box<[u16]>,
    in_count: u64,
    out_count: u64,
    checkpoint: u64,
    ratio: u64,
}

impl<W: Write> Encoder<W> {
    pub fn new(out: W) -> Self {
        Self::with_bits(out, MAX_BITS)
    }

    /// A narrower table, for tests of the decoder at every width.
    pub fn with_bits(out: W, max_bits: u32) -> Self {
        let max_bits = max_bits.clamp(INIT_BITS, MAX_BITS);
        Self {
            out,
            buf: vec![MAGIC[0], MAGIC[1], max_bits as u8 | BLOCK_MODE],
            bitbuf: 0,
            bitcnt: 0,
            in_group: 0,
            max_bits,
            n_bits: INIT_BITS,
            maxcode: (1 << INIT_BITS) - 1,
            free_ent: CLEAR + 1,
            ent: None,
            keys: vec![EMPTY; 1 << HASH_BITS].into_boxed_slice(),
            codes: vec![0; 1 << HASH_BITS].into_boxed_slice(),
            in_count: 0,
            out_count: 3,
            checkpoint: CHECK_GAP,
            ratio: 0,
        }
    }

    fn output(&mut self, code: u32, clear: bool) -> io::Result<()> {
        self.bitbuf |= u64::from(code) << self.bitcnt;
        self.bitcnt += self.n_bits;
        self.in_group = (self.in_group + 1) % 8;
        if clear || self.free_ent > self.maxcode {
            if self.in_group != 0 {
                // Pad the group with zeros.
                self.bitcnt += (8 - self.in_group) * self.n_bits;
                self.in_group = 0;
            }
            if clear {
                self.n_bits = INIT_BITS;
                self.maxcode = (1 << INIT_BITS) - 1;
            } else {
                self.n_bits += 1;
                self.maxcode = section_end(self.n_bits, self.max_bits);
            }
        }
        while self.bitcnt >= 8 {
            self.buf.push(self.bitbuf as u8);
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
            self.out_count += 1;
        }
        if self.buf.len() >= IN_BUF {
            self.out.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }

    fn slot(&self, key: u32) -> usize {
        let mut i = (key.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize;
        while self.keys[i] != EMPTY && self.keys[i] != key {
            i = (i + 1) & ((1 << HASH_BITS) - 1);
        }
        i
    }

    /// compress's rule: once the table is full, check the ratio every 10 000 input bytes and
    /// start over when it stops improving.
    fn check_ratio(&mut self) -> io::Result<()> {
        self.checkpoint = self.in_count + CHECK_GAP;
        let ratio = (self.in_count << 8) / self.out_count.max(1);
        if ratio > self.ratio {
            self.ratio = ratio;
            return Ok(());
        }
        self.ratio = 0;
        self.keys.fill(EMPTY);
        self.free_ent = CLEAR + 1;
        self.output(CLEAR, true)
    }

    pub fn finish(mut self) -> io::Result<()> {
        if let Some(ent) = self.ent.take() {
            self.output(ent, false)?;
        }
        if self.bitcnt > 0 {
            self.buf.push(self.bitbuf as u8);
        }
        self.out.write_all(&self.buf)?;
        self.out.flush()
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        for &c in data {
            self.in_count += 1;
            let Some(ent) = self.ent else {
                self.ent = Some(u32::from(c));
                continue;
            };
            let key = u32::from(c) << 16 | ent;
            let i = self.slot(key);
            if self.keys[i] == key {
                self.ent = Some(u32::from(self.codes[i]));
                continue;
            }
            self.output(ent, false)?;
            self.ent = Some(u32::from(c));
            if self.free_ent < 1 << self.max_bits {
                self.keys[i] = key;
                self.codes[i] = self.free_ent as u16;
                self.free_ent += 1;
            } else if self.in_count >= self.checkpoint {
                self.check_ratio()?;
            }
        }
        Ok(data.len())
    }

    /// Codes can't be flushed in the middle of a group without changing the stream.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(data: &[u8], bits: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = Encoder::with_bits(&mut out, bits);
        e.write_all(data).unwrap();
        e.finish().unwrap();
        out
    }

    fn decode(data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Decoder::new(data).read_to_end(&mut out)?;
        Ok(out)
    }

    /// Text with long runs, then noise: the table fills and clears.
    fn sample(n: usize) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                if (i / 50_000) % 2 == 0 {
                    b"the quick brown fox "[i % 20]
                } else {
                    x as u8
                }
            })
            .collect()
    }

    #[test]
    fn round_trips_at_every_width() {
        let data = sample(300_000);
        for bits in 9..=16 {
            assert_eq!(decode(&encode(&data, bits)).unwrap(), data, "{bits} bits");
        }
        assert_eq!(decode(&encode(b"", 16)).unwrap(), b"");
        assert_eq!(encode(b"", 16), [0x1F, 0x9D, 0x90]);
        assert_eq!(decode(&encode(b"a", 16)).unwrap(), b"a");
    }

    /// Reads of one byte at a time see the same stream: the padding after a CLEAR may be split
    /// across reads (compcol 0.7.8's bug, docs/M5.md §16).
    #[test]
    fn decodes_through_one_byte_reads() {
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let Some((&b, rest)) = self.0.split_first() else {
                    return Ok(0);
                };
                if buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = b;
                self.0 = rest;
                Ok(1)
            }
        }
        let data = sample(200_000);
        let z = encode(&data, 12);
        let mut out = Vec::new();
        Decoder::new(Trickle(&z)).read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn rejects_bad_streams() {
        assert!(decode(b"\x1f\x9d").is_err());
        assert!(decode(b"\x1f\x9d\x91abc").is_err(), "17 bits");
        assert!(decode(b"\x1f\x8bxxx").is_err());
        // A first code past the table.
        assert!(decode(&[0x1F, 0x9D, 0x90, 0xFF, 0x01]).is_err());
    }

    #[test]
    fn sniffs_the_header() {
        let probe = |head: &[u8]| {
            Compress.sniff(&Probe {
                head,
                len: Some(head.len() as u64),
                ..Probe::default()
            })
        };
        assert_eq!(probe(&encode(b"hello", 16)), Some(Confidence::Certain));
        assert_eq!(probe(&[0x1F, 0x9D, 0x90]), Some(Confidence::Certain));
        assert_eq!(probe(&[0x1F, 0x9D, 0xF0, b'a', 0]), None, "reserved bits");
        assert_eq!(probe(&[0x1F, 0x9D, 0x88, b'a', 0]), None, "8 bits");
        assert_eq!(
            probe(&[0x1F, 0x9D, 0x90, 0x02, 0x01]),
            None,
            "first code 258"
        );
    }
}
