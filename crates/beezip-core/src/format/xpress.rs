//! XPRESS Huffman decoding (MS-XCA §2.1-2.2, "LZ77+Huffman"), BeeZip's own, written from the
//! specification (docs/M8.md §4.2): what WOF's XPRESS4K/8K/16K chunks and WIM's XPRESS
//! resources hold. It decodes byte for byte every stream Windows' Compression API, ntdll and
//! WOF wrote in the M8 spike, at 77–90 % of Windows' own speed; 28.5 million fuzzed inputs
//! checked against `RtlDecompressBufferEx` found no difference but the two below.
//!
//! Where it differs from Windows, only on damaged data (docs/M8.md decision 7): an over-full
//! table, which Windows sometimes accepts and decodes non-canonically, is refused as the
//! specification says; input left after the output is full is ignored, where Windows refuses
//! about 258 bytes or more. And where MS-XCA's decoder pseudocode falls short, it follows
//! Windows: the 32-bit match lengths Windows' compressor writes (and the encoder pseudocode
//! describes) are read.
//!
//! - **Blocks:** each block is a 256-byte table of 512 four-bit code lengths, then a bitstream
//!   of 16-bit little-endian words read from their top bit, through a 32-bit register that
//!   always holds at least the next 16 bits (the spec's `NextBits`/`ExtraBitCount`). A block
//!   gives 65,536 bytes of output, counted from where it starts (a match may run past its end;
//!   the next block then starts where the match ended, as the spec's `BlockEnd` is set). The next
//!   block's table starts at the byte the register has read up to.
//! - **Codes** are canonical, up to 15 bits, and must be complete: an over-full or incomplete
//!   table is an error, as the spec's table construction says, except a single symbol of 1 bit,
//!   which Windows accepts too. A table of [`TABLE_BITS`] decodes short codes in one lookup;
//!   longer ones are decoded from the code counts.
//! - **Matches:** symbol − 256 gives the length (low 4 bits, + 3) and the offset's bit count
//!   (high 4 bits). Length 15 reads a byte from the byte stream; 255 there reads a 16-bit length
//!   (and 0 there a 32-bit one, as the spec's encoder writes for 65,536 and more). Offsets
//!   reaching before the output's start, and lengths running past its end, are errors.
//! - **The end:** decoding stops when the output is full; an end-of-stream symbol (256) after it
//!   is never read, and bytes after it are ignored. A stream shorter than the words the register
//!   reads is an error, as in Windows, even when their bits aren't used.
//!
//! Nothing here may panic, whatever the bytes.

pub type Error = &'static str;

const SYMBOLS: usize = 512;
/// What `decode` gives for a pattern no symbol has.
const INVALID: usize = SYMBOLS;
const MAX_CODE: usize = 15;
/// The bits the fast table decodes at once.
pub const TABLE_BITS: u32 = 11;
/// The output a block's table covers.
pub const BLOCK: usize = 65_536;

/// A block's canonical code.
pub struct Code {
    /// `symbol << 4 | length` for codes up to [`TABLE_BITS`]; 0 where a longer code starts.
    table: [u16; 1 << TABLE_BITS],
    count: [u16; MAX_CODE + 1],
    /// Symbols in code order: by length, then by symbol.
    sorted: [u16; SYMBOLS],
}

impl Default for Code {
    fn default() -> Self {
        Self {
            table: [0; 1 << TABLE_BITS],
            count: [0; MAX_CODE + 1],
            sorted: [0; SYMBOLS],
        }
    }
}

impl Code {
    /// Builds the code from a block's 256-byte table.
    pub fn build(&mut self, packed: &[u8]) -> Result<(), Error> {
        let mut lens = [0u8; SYMBOLS];
        for (i, &b) in packed.iter().take(SYMBOLS / 2).enumerate() {
            lens[2 * i] = b & 0x0F;
            lens[2 * i + 1] = b >> 4;
        }
        self.count = [0; MAX_CODE + 1];
        for &l in &lens {
            self.count[usize::from(l)] += 1;
        }
        self.count[0] = 0;
        let mut left: i32 = 1;
        for l in 1..=MAX_CODE {
            left = (left << 1) - i32::from(self.count[l]);
            if left < 0 {
                return Err("an over-full XPRESS Huffman table");
            }
        }
        // Windows accepts one incomplete code: a single symbol of 1 bit (code 0; a 1 bit is
        // then an error).
        if left != 0 && !(self.count[1] == 1 && self.count[2..].iter().all(|&c| c == 0)) {
            return Err("an incomplete XPRESS Huffman table");
        }
        let mut offs = [0usize; MAX_CODE + 2];
        for l in 1..=MAX_CODE {
            offs[l + 1] = offs[l] + usize::from(self.count[l]);
        }
        for (sym, &l) in lens.iter().enumerate() {
            if l != 0 {
                let at = &mut offs[usize::from(l)];
                self.sorted[*at] = sym as u16;
                *at += 1;
            }
        }
        self.table.fill(0);
        let mut code: u32 = 0;
        let mut i = 0usize;
        for l in 1..=MAX_CODE as u32 {
            for _ in 0..self.count[l as usize] {
                if l <= TABLE_BITS {
                    let shift = TABLE_BITS - l;
                    let start = (code << shift) as usize;
                    let entry = (self.sorted[i] << 4) | l as u16;
                    self.table[start..start + (1 << shift)].fill(entry);
                }
                code += 1;
                i += 1;
            }
            code <<= 1;
        }
        Ok(())
    }

    /// The symbol at the top of `bits` (which holds at least 15 valid bits) and its length.
    #[inline(always)]
    fn decode(&self, bits: u32) -> (usize, u32) {
        let e = self.table[(bits >> (32 - TABLE_BITS)) as usize];
        if e != 0 {
            return (usize::from(e >> 4), u32::from(e & 0xF));
        }
        self.decode_long(bits)
    }

    #[cold]
    fn decode_long(&self, bits: u32) -> (usize, u32) {
        let code15 = bits >> (32 - MAX_CODE as u32);
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        for l in 1..=MAX_CODE as u32 {
            let code = code15 >> (MAX_CODE as u32 - l);
            let count = u32::from(self.count[l as usize]);
            if code >= first && code - first < count {
                return (usize::from(self.sorted[(index + code - first) as usize]), l);
            }
            index += count;
            first = (first + count) << 1;
        }
        // Only the one-symbol code leaves patterns without a symbol.
        (INVALID, 1)
    }
}

/// The input as the spec reads it: 16-bit words into the register, bytes for long lengths.
struct Input<'a> {
    data: &'a [u8],
    /// The spec's `CurrentPosition`; may pass the end, where words read as zeros.
    pos: usize,
    over: bool,
}

impl Input<'_> {
    /// The next word; past the end, zero, and `over` is set (an error once decoding ends, as
    /// Windows refuses such a stream even when the bits aren't used).
    #[inline(always)]
    fn word(&mut self) -> u32 {
        let w = match self.data.get(self.pos..self.pos + 2) {
            Some(w) => u32::from(u16::from_le_bytes([w[0], w[1]])),
            None => {
                self.over = true;
                0
            }
        };
        self.pos += 2;
        w
    }

    fn byte(&mut self) -> Result<usize, Error> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or("XPRESS data that ends early")?;
        self.pos += 1;
        Ok(usize::from(b))
    }

    fn u16(&mut self) -> Result<usize, Error> {
        let w = self
            .data
            .get(self.pos..self.pos + 2)
            .ok_or("XPRESS data that ends early")?;
        self.pos += 2;
        Ok(usize::from(u16::from_le_bytes([w[0], w[1]])))
    }

    fn u32(&mut self) -> Result<usize, Error> {
        let w = self
            .data
            .get(self.pos..self.pos + 4)
            .ok_or("XPRESS data that ends early")?;
        self.pos += 4;
        Ok(u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as usize)
    }
}

/// A decoder, keeping its table between calls.
#[derive(Default)]
pub struct Decoder {
    code: Box<Code>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes `input` into all of `out`.
    pub fn decode(&mut self, input: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let code = &mut *self.code;
        let mut inp = Input {
            data: input,
            pos: 0,
            over: false,
        };
        let mut o = 0usize;
        // The register and how far it runs ahead of the bits used.
        let mut next: u32 = 0;
        let mut extra: i32 = 16;
        while o < out.len() {
            let table = input
                .get(inp.pos..inp.pos + SYMBOLS / 2)
                .ok_or("XPRESS data that ends before a block's table")?;
            code.build(table)?;
            inp.pos += SYMBOLS / 2;
            next = (inp.word() << 16) | inp.word();
            extra = 16;
            let block_end = o.saturating_add(BLOCK).min(out.len());
            while o < block_end {
                let (sym, len) = code.decode(next);
                next <<= len;
                extra -= len as i32;
                if extra < 0 {
                    next |= inp.word() << (-extra) as u32;
                    extra += 16;
                }
                if sym < 256 {
                    out[o] = sym as u8;
                    o += 1;
                    continue;
                }
                if sym == INVALID {
                    return Err("an XPRESS code its table doesn't have");
                }
                let s = sym - 256;
                let mut length = s & 0xF;
                let obits = (s >> 4) as u32;
                if length == 15 {
                    length = inp.byte()?;
                    if length == 255 {
                        length = inp.u16()?;
                        if length == 0 {
                            length = inp.u32()?;
                        }
                        length = length
                            .checked_sub(15)
                            .ok_or("an XPRESS match length below its range")?;
                    }
                    length += 15;
                }
                length += 3;
                let offset = ((u64::from(next) << obits) >> 32) as usize + (1usize << obits);
                next = ((u64::from(next) << obits) & 0xFFFF_FFFF) as u32;
                extra -= obits as i32;
                if extra < 0 {
                    next |= inp.word() << (-extra) as u32;
                    extra += 16;
                }
                if offset > o {
                    return Err("an XPRESS match that reaches before the data");
                }
                if length > out.len() - o {
                    return Err("an XPRESS match that runs past the data's end");
                }
                copy_match(out, o, offset, length);
                o += length;
            }
            // The next block's table starts where the register has read to.
        }
        // As Windows, a stream must hold every word the register has read, used or not.
        if inp.over {
            return Err("XPRESS data that ends early");
        }
        let _ = (next, extra);
        Ok(())
    }
}

/// Copies `len` bytes from `offset` back to `dst`; they may overlap.
#[inline(always)]
fn copy_match(out: &mut [u8], dst: usize, offset: usize, len: usize) {
    let src = dst - offset;
    if offset >= len {
        out.copy_within(src..src + len, dst);
    } else if offset >= 8 {
        let mut i = 0;
        while i + 8 <= len {
            out.copy_within(src + i..src + i + 8, dst + i);
            i += 8;
        }
        while i < len {
            out[dst + i] = out[src + i];
            i += 1;
        }
    } else if offset == 1 {
        let b = out[src];
        out[dst..dst + len].fill(b);
    } else {
        for i in 0..len {
            out[dst + i] = out[src + i];
        }
    }
}

/// Decodes `input` into a new buffer of `size` bytes.
pub fn decompress(input: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; size];
    Decoder::new().decode(input, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect()
    }

    /// MS-XCA §3.2's first example: the alphabet as literals, then EOF.
    #[test]
    fn spec_example_literals() {
        let mut v = vec![0u8; 48];
        v.extend(hex("50 55 55 55 55 55 55 55 55 55 55 45 44 04"));
        v.resize(128, 0);
        v.push(0x04);
        v.resize(256, 0);
        v.extend(hex(
            "d8 52 3e d7 94 11 5b e9 19 5f f9 d6 7c df 8d 04 00 00 00 00",
        ));
        assert_eq!(decompress(&v, 26).unwrap(), b"abcdefghijklmnopqrstuvwxyz");
    }

    /// MS-XCA §3.2's second example: "abc" × 100, a match of 297.
    #[test]
    fn spec_example_long_match() {
        let mut v = vec![0u8; 48];
        v.extend(hex("30 23"));
        v.resize(128, 0);
        v.push(0x02);
        v.resize(143, 0);
        v.push(0x20);
        v.resize(256, 0);
        v.extend(hex("a8 dc 00 00 ff 26 01"));
        let want: Vec<u8> = b"abc".iter().copied().cycle().take(300).collect();
        assert_eq!(decompress(&v, 300).unwrap(), want);
    }
}
