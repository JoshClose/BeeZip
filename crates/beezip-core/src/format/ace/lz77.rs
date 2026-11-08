//! ACE's LZ77: literals and copies coded with two Huffman trees, in blocks that each bring their
//! own trees. ACE 2.0 adds a type code that switches modes; unace reads one in ACE 1.0 data
//! too. Mode 0 is LZ77 itself; EXE, DELTA, SOUND and PIC are refused (docs/M6.md §14). Archive and file
//! comments are coded the same way, more simply ([`comment`]).

use std::io::Read;

use super::{
    bits::BitReader,
    header::bad,
    huffman::{Tree, read_tree},
};
use crate::{Error, Result};

const MAX_CODE_WIDTH: u8 = 11;
const MAX_DIC_BITS: u32 = 22;
pub const MIN_DIC_SIZE: usize = 1 << 10;
pub const MAX_DIC_SIZE: usize = 1 << MAX_DIC_BITS;
/// 0–255 literals, 256–259 copies at a recent distance, 260–282 copies whose distance has 0–22
/// bits, 283 the type code.
const TYPE_CODE: u16 = 260 + MAX_DIC_BITS as u16 + 1;
const NUM_MAIN_CODES: usize = 260 + MAX_DIC_BITS as usize + 2;
const NUM_LEN_CODES: usize = 255;
const MAX_DIST_AT_LEN2: u32 = 255;
const MAX_DIST_AT_LEN3: u32 = 8191;

/// ACE 2.0's modes, by number.
const MODES: [&str; 8] = [
    "LZ77",
    "DELTA",
    "EXE",
    "SOUND_8",
    "SOUND_16",
    "SOUND_32A",
    "SOUND_32B",
    "PIC",
];
const MODE_LZ77: u32 = 0;
const MODE_DELTA: u32 = 1;
const MODE_EXE: u32 = 2;

/// The last bytes decoded, for copies to read: a ring of a power of two, at most the
/// dictionary size the entries ask for (1 KiB to 4 MiB). It grows with the output, so a small
/// input never takes the whole size. A solid archive's entries share it.
#[derive(Clone, Default)]
pub struct Dictionary {
    buf: Vec<u8>,
    /// Where the next byte goes.
    pos: usize,
    /// How many of `buf`'s bytes have been written.
    filled: usize,
    /// The most `buf` may grow to.
    limit: usize,
}

impl Dictionary {
    /// Lets the history grow to `size` bytes; it never shrinks.
    pub fn reserve(&mut self, size: usize) {
        let want = size.clamp(MIN_DIC_SIZE, MAX_DIC_SIZE).next_power_of_two();
        self.limit = self.limit.max(want);
    }

    /// Forgets the history, keeping the room.
    pub fn clear(&mut self) {
        self.pos = 0;
        self.filled = 0;
    }

    /// Moves the history into a ring of `cap` bytes, oldest first.
    fn grow(&mut self, cap: usize) {
        let old = self.buf.len();
        let mut grown = vec![0u8; cap];
        for (i, b) in grown[..self.filled].iter_mut().enumerate() {
            *b = self.buf[(self.pos + old - self.filled + i) % old];
        }
        self.buf = grown;
        self.pos = self.filled;
    }

    /// Makes room for one more byte: a full ring below its limit doubles.
    fn room(&mut self) {
        let cap = self.buf.len();
        if self.filled == cap && cap < self.limit.max(MIN_DIC_SIZE) {
            self.grow((cap * 2).clamp(MIN_DIC_SIZE, self.limit.max(MIN_DIC_SIZE)));
        }
    }

    pub fn extend(&mut self, data: &[u8]) {
        for &b in data {
            self.push(b);
        }
    }

    fn push(&mut self, b: u8) {
        self.room();
        let cap = self.buf.len();
        self.buf[self.pos] = b;
        self.pos = (self.pos + 1) & (cap - 1);
        if self.filled < cap {
            self.filled += 1;
        }
    }

    /// Copies `out.len()` bytes from `dist` back, into the history and `out`. The caller has
    /// checked that `dist` is within what the history holds.
    fn copy(&mut self, dist: usize, out: &mut [u8]) {
        for o in out.iter_mut() {
            self.room();
            let cap = self.buf.len();
            let b = self.buf[(self.pos + cap - dist) & (cap - 1)];
            *o = b;
            self.buf[self.pos] = b;
            self.pos = (self.pos + 1) & (cap - 1);
            if self.filled < cap {
                self.filled += 1;
            }
        }
    }
}

/// Why decoding stopped.
pub enum Stop {
    Error(Error),
    /// An ACE 2.0 mode BeeZip doesn't decode, by name.
    Mode(&'static str),
}

impl From<Error> for Stop {
    fn from(e: Error) -> Self {
        Self::Error(e)
    }
}

/// One entry's LZ77 stream, decoded into a [`Dictionary`] it shares with a solid archive's other
/// entries.
pub struct Lz77<R> {
    bits: BitReader<R>,
    /// The block's main and length trees, and the symbols left in it.
    trees: Option<(Tree, Tree)>,
    block_left: u32,
    /// A block whose count was 0 never ends: acefile's counter goes below zero and stays there.
    endless: bool,
    /// The last four distances, oldest first.
    recent: [u32; 4],
    /// A copy that didn't fit the caller's buffer: its distance and what is left of it.
    copy: Option<(usize, usize)>,
    /// Bytes still to be produced, copies counted when they start.
    left: u64,
}

impl<R: Read> Lz77<R> {
    pub fn new(inner: R, size: u64) -> Self {
        Self {
            bits: BitReader::new(inner),
            trees: None,
            block_left: 0,
            endless: false,
            recent: [0; 4],
            copy: None,
            left: size,
        }
    }

    fn main_symbol(&mut self) -> Result<u16> {
        if self.block_left == 0 && !self.endless {
            let main = read_tree(&mut self.bits, MAX_CODE_WIDTH, NUM_MAIN_CODES)?;
            let len = read_tree(&mut self.bits, MAX_CODE_WIDTH, NUM_LEN_CODES)?;
            self.trees = Some((main, len));
            self.block_left = self.bits.read(15)?;
            self.endless = self.block_left == 0;
        }
        if !self.endless {
            self.block_left -= 1;
        }
        match &self.trees {
            Some((main, _)) => main.read_symbol(&mut self.bits),
            None => Err(bad("a block without trees")),
        }
    }

    fn len_symbol(&mut self) -> Result<u32> {
        match &self.trees {
            Some((_, len)) => Ok(u32::from(len.read_symbol(&mut self.bits)?)),
            None => Err(bad("a block without trees")),
        }
    }

    /// The distance `offset` back in the recent ones (0 the latest), moved to the end.
    fn reuse(&mut self, offset: usize) -> u32 {
        let at = 3 - offset;
        let d = self.recent[at];
        self.recent.copy_within(at + 1.., at);
        self.recent[3] = d;
        d
    }

    /// Decodes up to `out.len()` bytes into `out` and `dict`. Returns how many; 0 only when the
    /// entry is complete or `out` is empty.
    pub fn read(&mut self, dict: &mut Dictionary, out: &mut [u8]) -> Result<usize, Stop> {
        let mut n = 0;
        while n < out.len() {
            if let Some((dist, left)) = self.copy {
                let k = left.min(out.len() - n);
                dict.copy(dist, &mut out[n..n + k]);
                n += k;
                self.copy = (left > k).then_some((dist, left - k));
                continue;
            }
            if self.left == 0 {
                break;
            }
            let sym = self.main_symbol()?;
            if sym <= 255 {
                out[n] = sym as u8;
                dict.push(sym as u8);
                n += 1;
                self.left -= 1;
            } else if sym < TYPE_CODE {
                let (dist, len) = if sym <= 259 {
                    let len = self.len_symbol()?;
                    let offset = usize::from(sym & 0x03);
                    let dist = self.reuse(offset);
                    (dist, len + if offset > 1 { 3 } else { 2 })
                } else {
                    let dist = self.bits.read_known_width(u32::from(sym - 260))?;
                    let len = self.len_symbol()?;
                    self.recent.copy_within(1.., 0);
                    self.recent[3] = dist;
                    let extra = if dist <= MAX_DIST_AT_LEN2 {
                        2
                    } else if dist <= MAX_DIST_AT_LEN3 {
                        3
                    } else {
                        4
                    };
                    (dist, len + extra)
                };
                let dist = dist as usize + 1;
                if u64::from(len) > self.left {
                    return Err(bad("a copy runs past the end of its entry").into());
                }
                if dist > dict.filled {
                    return Err(bad("a copy reaches back before the data").into());
                }
                self.left -= u64::from(len);
                self.copy = Some((dist, len as usize));
            } else if sym == TYPE_CODE {
                // unace 2.5 takes a type code in ACE 1.0 data as well (acefile doesn't).

                let mode = self.bits.read(8)?;
                match mode {
                    MODE_LZ77 => {}
                    MODE_DELTA => {
                        self.bits.read(8)?;
                        self.bits.read(17)?;
                        return Err(Stop::Mode(MODES[1]));
                    }
                    MODE_EXE => {
                        self.bits.read(8)?;
                        return Err(Stop::Mode(MODES[2]));
                    }
                    m if (m as usize) < MODES.len() => return Err(Stop::Mode(MODES[m as usize])),
                    m => return Err(bad(format!("an unknown ACE 2.0 mode, {m}")).into()),
                }
            } else {
                return Err(bad(format!("an LZ77 symbol past the type code, {sym}")).into());
            }
        }
        Ok(n)
    }
}

/// The most a comment holds: its size is stored in 15 bits.
const MAX_COMMENT: usize = (1 << 15) - 1;

/// Decodes an archive or file comment: its size, a tree, then literals and copies from where the
/// last two bytes' sum was seen before.
pub fn comment(packed: &[u8]) -> Result<Vec<u8>> {
    let mut bs = BitReader::new(packed);
    let want = bs.read(15)? as usize;
    let tree = read_tree(&mut bs, MAX_CODE_WIDTH, NUM_MAIN_CODES)?;
    let mut out: Vec<u8> = Vec::with_capacity(want.min(MAX_COMMENT));
    let mut seen = [0usize; 511];
    while out.len() < want {
        let from = match out.len() {
            0 | 1 => 0,
            n => {
                let h = usize::from(out[n - 1]) + usize::from(out[n - 2]);
                std::mem::replace(&mut seen[h], n)
            }
        };
        let code = tree.read_symbol(&mut bs)?;
        if code < 256 {
            out.push(code as u8);
        } else {
            for i in 0..usize::from(code - 256 + 2) {
                let b = *out
                    .get(from + i)
                    .ok_or_else(|| bad("a comment copies from past its end"))?;
                out.push(b);
            }
        }
    }
    out.truncate(want);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_distances_match_acefile() {
        // acefile's DistHist doctest: append 1–5, retrieve(2), (0), (1), (1).
        let mut lz = Lz77::new(&[][..], 0);
        for d in 1..=5 {
            lz.recent.copy_within(1.., 0);
            lz.recent[3] = d;
        }
        assert_eq!(lz.reuse(2), 3);
        assert_eq!(lz.reuse(0), 3);
        assert_eq!(lz.reuse(1), 5);
        assert_eq!(lz.reuse(1), 3);
    }
    #[test]
    fn the_dictionary_grows_with_the_output() {
        let mut d = Dictionary::default();
        d.reserve(10);
        assert!(d.buf.is_empty(), "nothing taken before the output");
        let data: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();
        d.extend(&data);
        // Held to its 1 KiB limit, the ring has wrapped.
        assert_eq!((d.buf.len(), d.filled), (MIN_DIC_SIZE, MIN_DIC_SIZE));
        // A later entry asks for more: the wrapped history moves into a bigger ring in order.
        d.reserve(3000);
        let mut out = [0u8; 4];
        d.copy(MIN_DIC_SIZE, &mut out);
        assert_eq!(d.buf.len(), 2048);
        // 1500 - 1024 = 476, 220 as a byte.
        assert_eq!(out, [220, 221, 222, 223]);
        d.reserve(64 << 20);
        d.extend(&vec![7; 5 << 20]);
        assert_eq!(d.buf.len(), MAX_DIC_SIZE, "capped at 4 MiB");
        d.copy(1, &mut out);
        assert_eq!(out, [7; 4], "an overlapping copy repeats");
    }
}
