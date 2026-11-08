//! ACE's bit stream: 32-bit little-endian words, read from the most significant bit down.

use std::io::{self, Read};

use super::header::bad;
use crate::{Result, io::read_error};

const BUF: usize = 16 * 1024;

pub struct BitReader<R> {
    inner: R,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    eof: bool,
    /// The next bits, from the top down.
    acc: u64,
    /// Bits held in `acc`, `pad` of them zeros past the end of the data.
    held: u32,
    pad: u32,
}

impl<R: Read> BitReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0u8; BUF].into_boxed_slice(),
            start: 0,
            end: 0,
            eof: false,
            acc: 0,
            held: 0,
            pad: 0,
        }
    }

    /// The next word. A last word of fewer than four bytes is filled out with zeros.
    fn word(&mut self) -> io::Result<Option<u32>> {
        while self.end - self.start < 4 && !self.eof {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
            match self.inner.read(&mut self.buf[self.end..]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let n = (self.end - self.start).min(4);
        if n == 0 {
            return Ok(None);
        }
        let mut w = [0u8; 4];
        w[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        Ok(Some(u32::from_le_bytes(w)))
    }

    /// Fills `acc` to more than 32 bits, with zeros past the end of the data.
    fn refill(&mut self) -> Result<()> {
        while self.held <= 32 {
            let w = if self.pad > 0 {
                None
            } else {
                self.word().map_err(|e| read_error(&e))?
            };
            match w {
                Some(w) => self.acc |= u64::from(w) << (32 - self.held),
                None => self.pad += 32,
            }
            self.held += 32;
        }
        Ok(())
    }

    /// The next `n` bits (at most 32) without taking them. Past the end of the data they're
    /// zeros.
    pub fn peek(&mut self, n: u32) -> Result<u32> {
        debug_assert!(n <= 32);
        if n == 0 {
            return Ok(0);
        }
        if self.held < n {
            self.refill()?;
        }
        Ok((self.acc >> (64 - n)) as u32)
    }

    /// Takes `n` bits (at most 32); taking bits past the end of the data fails.
    pub fn skip(&mut self, n: u32) -> Result<()> {
        if self.held < n {
            self.refill()?;
        }
        if n > self.held - self.pad {
            return Err(bad("the compressed data ends early"));
        }
        self.acc = if n >= 64 { 0 } else { self.acc << n };
        self.held -= n;
        Ok(())
    }

    pub fn read(&mut self, n: u32) -> Result<u32> {
        let v = self.peek(n)?;
        self.skip(n)?;
        Ok(v)
    }

    /// An unsigned number of `bits` bits whose top bit, always set, isn't stored.
    pub fn read_known_width(&mut self, bits: u32) -> Result<u32> {
        if bits < 2 {
            return Ok(bits);
        }
        Ok(self.read(bits - 1)? + (1 << (bits - 1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_acefile() {
        // acefile's BitStream doctest.
        let mut bs = BitReader::new(&b"01234567"[..]);
        assert_eq!(bs.peek(31).unwrap(), 429_463_704);
        assert_eq!(bs.read(31).unwrap(), 429_463_704);
        bs.skip(3).unwrap();
        assert_eq!(bs.read(5).unwrap(), 27);
        // acefile reads two Golomb-Rice codes here, nine bits in all.
        bs.skip(9).unwrap();
        assert_eq!(bs.read_known_width(10).unwrap(), 618);
        assert_eq!(bs.read(7).unwrap(), 52);
        assert_eq!(bs.peek(31).unwrap(), 0, "zeros past the end");
        assert!(bs.read(1).is_err());
    }

    #[test]
    fn known_width_numbers_keep_their_top_bit() {
        let mut bs = BitReader::new(&[0, 0, 0, 0b1010_0000][..]);
        assert_eq!(bs.read_known_width(0).unwrap(), 0);
        assert_eq!(bs.read_known_width(1).unwrap(), 1);
        assert_eq!(bs.read_known_width(4).unwrap(), 0b1101);
    }

    #[test]
    fn words_cross_buffer_refills() {
        let data: Vec<u8> = (0..BUF as u32 + 9).map(|i| (i * 7) as u8).collect();
        let mut bs = BitReader::new(&data[..]);
        let mut words = Vec::new();
        for _ in 0..(BUF / 4) + 2 {
            words.push(bs.read(32).unwrap());
        }
        let expect: Vec<u32> = data
            .chunks(4)
            .take(words.len())
            .map(|c| {
                let mut w = [0u8; 4];
                w[..c.len()].copy_from_slice(c);
                u32::from_le_bytes(w)
            })
            .collect();
        assert_eq!(words, expect);
        assert!(bs.read(32).is_ok(), "the short last word, zero-filled");
        assert!(bs.read(1).is_err());
    }
}
