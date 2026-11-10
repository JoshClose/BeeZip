//! LZX decoding as cabinets use it (MS-CAB's LZX, the LZXD of MS-PATCH without reference data),
//! BeeZip's own (docs/M7.md §8.4). It replaced lzxd 0.2.7, which decoded at about a quarter of
//! 7-Zip's speed and needed three workarounds (`docs/UPSTREAM.md`).
//!
//! - **One frame per call:** each cabinet data block is a frame of 32 KiB of output (the last
//!   may be shorter), whose bitstream starts afresh at the block's first byte. Blocks of LZX
//!   (verbatim, aligned and uncompressed) run across frames, with their trees.
//! - **The bitstream** is 16-bit little-endian words, read from their top bit, kept in a 64-bit
//!   buffer refilled a word at a time. Past the data it reads zeros; a frame that used them is
//!   `Corrupt`.
//! - **Huffman codes** are canonical, up to 16 bits: a table of [`TABLE_BITS`] decodes the short
//!   ones in one lookup, and the rest are decoded from the code counts. A tree must be complete,
//!   or empty where LZX allows it (the length tree, when no match is longer than 8).
//! - **Matches** may run past a frame's end into the next one, as Microsoft's compressor makes
//!   them, but not past their LZX block's end, nor reach before the stream's start or further
//!   back than the window.
//! - **E8 translation** (x86 call addresses) is undone on each frame's output after it's copied
//!   out of the window, as the spec, libmspack and 7-Zip do.
//!
//! Nothing here may panic, whatever the bytes: every index is bounded.

/// The bits the fast table decodes at once.
const TABLE_BITS: u32 = 12;
const MAX_CODE: usize = 16;
const NUM_CHARS: usize = 256;
const PRETREE: usize = 20;
const ALIGNED: usize = 8;
const LENGTHS: usize = 249;
const MIN_MATCH: usize = 2;
/// A frame's output: one cabinet data block's.
pub const FRAME: usize = 32 * 1024;

/// What went wrong, for `cab.rs` to word as a damaged block.
pub type Error = &'static str;

/// The extra bits of each position slot: 0 for the first four, then 1, 1, 2, 2… up to 17.
const fn extra_bits(slot: usize) -> u32 {
    if slot < 4 {
        0
    } else {
        let e = (slot - 2) / 2;
        if e > 17 { 17 } else { e as u32 }
    }
}

/// The most position slots: those of a 2 MiB window, cabinets' largest.
const MAX_SLOTS: usize = 50;

const fn bases() -> [u32; MAX_SLOTS + 1] {
    let mut b = [0u32; MAX_SLOTS + 1];
    let mut i = 1;
    while i <= MAX_SLOTS {
        b[i] = b[i - 1] + (1 << extra_bits(i - 1));
        i += 1;
    }
    b
}

/// Where each position slot's offsets start (before the 2 LZX subtracts).
const POSITION_BASE: [u32; MAX_SLOTS + 1] = bases();

/// The bitstream of one frame. It's `Copy` so the hot loop can keep it in registers.
#[derive(Clone, Copy)]
struct Bits<'a> {
    data: &'a [u8],
    /// The next byte to load into `buf`.
    pos: usize,
    /// Zero words loaded past the data's end.
    over: usize,
    /// Bits not yet read, from the top.
    buf: u64,
    n: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            over: 0,
            buf: 0,
            n: 0,
        }
    }

    /// Fills the buffer to more than 48 bits. Away from the data's end it loads the next four
    /// words at once and counts the whole ones that fit; the bits of the next word that spill
    /// below them are its own, so ORing that word in again later changes nothing.
    #[inline]
    fn refill(&mut self) {
        if self.n > 48 {
            return;
        }
        if let Some(w) = self.data.get(self.pos..self.pos + 8) {
            let v = u64::from_be_bytes([w[1], w[0], w[3], w[2], w[5], w[4], w[7], w[6]]);
            let words = (64 - self.n) / 16;
            self.buf |= v >> self.n;
            self.n += words * 16;
            self.pos += words as usize * 2;
            return;
        }
        while self.n <= 48 {
            let w = match self.data.get(self.pos..self.pos + 2) {
                Some(w) => {
                    self.pos += 2;
                    u16::from_le_bytes([w[0], w[1]])
                }
                None => {
                    self.over += 1;
                    0
                }
            };
            self.buf |= u64::from(w) << (48 - self.n);
            self.n += 16;
        }
    }

    /// The next `k` bits (1 to 32), which must be in the buffer.
    #[inline]
    fn peek(&self, k: u32) -> u32 {
        (self.buf >> (64 - k)) as u32
    }

    #[inline]
    fn skip(&mut self, k: u32) {
        self.buf <<= k;
        self.n -= k;
    }

    /// The next `k` bits, up to 32.
    #[inline]
    fn read(&mut self, k: u32) -> u32 {
        if k == 0 {
            return 0;
        }
        if self.n < k {
            self.refill();
        }
        let v = self.peek(k);
        self.skip(k);
        v
    }

    /// Skips to the next word, or past a whole word when already at one: what LZX does before an
    /// uncompressed block's bytes.
    fn align(&mut self) {
        self.refill();
        let rem = self.n % 16;
        self.skip(if rem == 0 { 16 } else { rem });
    }

    /// The byte the reader has reached, at a word boundary (after [`Bits::align`]).
    fn byte_pos(&self) -> usize {
        (self.pos + 2 * self.over).saturating_sub((self.n / 8) as usize)
    }

    /// Reads on from byte `at`.
    fn reset_at(&mut self, at: usize) {
        self.pos = at;
        self.over = 0;
        self.buf = 0;
        self.n = 0;
    }

    /// Whether more was read than the data holds.
    fn overrun(&self) -> bool {
        self.byte_pos() > self.data.len()
    }
}

/// A canonical Huffman code, decoded through a table of [`TABLE_BITS`] and its code counts.
struct Huff {
    /// `symbol << 5 | length` for codes up to [`TABLE_BITS`]; 0 where a longer code starts.
    table: Box<[u16; 1 << TABLE_BITS]>,
    count: [u16; MAX_CODE + 1],
    /// The symbols in code order: by length, then by symbol.
    sorted: Vec<u16>,
    empty: bool,
}

impl Huff {
    fn new() -> Self {
        Self {
            table: Box::new([0; 1 << TABLE_BITS]),
            count: [0; MAX_CODE + 1],
            sorted: Vec::new(),
            empty: true,
        }
    }

    /// Builds the code from `lens`. An incomplete or over-full code is an error, unless every
    /// length is 0 and `may_be_empty`.
    fn build(&mut self, lens: &[u8], may_be_empty: bool) -> Result<(), Error> {
        self.count = [0; MAX_CODE + 1];
        for &l in lens {
            let l = usize::from(l);
            if l > MAX_CODE {
                return Err("an LZX code longer than 16 bits");
            }
            self.count[l] += 1;
        }
        self.count[0] = 0;
        let used: u32 = self.count.iter().map(|&c| u32::from(c)).sum();
        if used == 0 {
            self.empty = true;
            return if may_be_empty {
                Ok(())
            } else {
                Err("an empty LZX tree")
            };
        }
        let mut left: i64 = 1;
        for l in 1..=MAX_CODE {
            left = (left << 1) - i64::from(self.count[l]);
            if left < 0 {
                return Err("an over-full LZX tree");
            }
        }
        if left != 0 {
            return Err("an incomplete LZX tree");
        }
        self.empty = false;
        // The symbols by length, then by symbol.
        let mut offs = [0usize; MAX_CODE + 2];
        for l in 1..=MAX_CODE {
            offs[l + 1] = offs[l] + usize::from(self.count[l]);
        }
        self.sorted.clear();
        self.sorted.resize(used as usize, 0);
        for (sym, &l) in lens.iter().enumerate() {
            if l != 0 {
                let at = &mut offs[usize::from(l)];
                self.sorted[*at] = sym as u16;
                *at += 1;
            }
        }
        // The table: each short code's entries, codes assigned in order.
        self.table.fill(0);
        let mut code: u32 = 0;
        let mut i = 0usize;
        for l in 1..=MAX_CODE as u32 {
            for _ in 0..self.count[l as usize] {
                if l <= TABLE_BITS {
                    let sym = self.sorted[i];
                    let shift = TABLE_BITS - l;
                    let start = (code << shift) as usize;
                    let entry = (sym << 5) | l as u16;
                    self.table[start..start + (1 << shift)].fill(entry);
                }
                code += 1;
                i += 1;
            }
            code <<= 1;
        }
        Ok(())
    }

    /// The next symbol. The buffer must hold 16 bits.
    #[inline]
    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, Error> {
        if self.empty {
            return Err("a symbol from an empty LZX tree");
        }
        let e = self.table[bits.peek(TABLE_BITS) as usize];
        let l = u32::from(e & 0x1F);
        if l != 0 {
            bits.skip(l);
            return Ok(e >> 5);
        }
        let code16 = bits.peek(16);
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        for l in 1..=MAX_CODE as u32 {
            let code = code16 >> (16 - l);
            let count = u32::from(self.count[l as usize]);
            if code >= first && code - first < count {
                bits.skip(l);
                return Ok(self.sorted[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
        }
        Err("a bad LZX code")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Before the first block, and between blocks.
    None,
    Verbatim,
    Aligned,
    Uncompressed,
}

/// One folder's LZX stream.
pub struct Lzx {
    window: Vec<u8>,
    mask: usize,
    slots: usize,
    /// Bytes decoded so far, from the stream's start.
    total: u64,
    /// Where the next frame's output starts.
    frame_start: u64,
    r: [u32; 3],
    kind: Kind,
    /// What's left of the current block.
    remaining: u32,
    /// An odd-sized uncompressed block's padding byte is still to skip.
    pad: bool,
    main_lens: Vec<u8>,
    length_lens: [u8; LENGTHS],
    main: Huff,
    length: Huff,
    aligned: Huff,
    pretree: Huff,
    /// Whether the E8 header has been read, and the translation size it gave.
    started: bool,
    e8: Option<i32>,
    /// Blocks read, for the benchmark.
    blocks: u64,
}

impl Lzx {
    /// A stream with a window of 2^`bits` bytes: 15 to 21 in cabinets.
    pub fn new(bits: u32) -> Result<Self, Error> {
        let slots = match bits {
            15 => 30,
            16 => 32,
            17 => 34,
            18 => 36,
            19 => 38,
            20 => 42,
            21 => 50,
            _ => return Err("an LZX window of other than 15 to 21 bits"),
        };
        let size = 1usize << bits;
        Ok(Self {
            window: vec![0; size],
            mask: size - 1,
            slots,
            total: 0,
            frame_start: 0,
            r: [1, 1, 1],
            kind: Kind::None,
            remaining: 0,
            pad: false,
            main_lens: vec![0; NUM_CHARS + 8 * slots],
            length_lens: [0; LENGTHS],
            main: Huff::new(),
            length: Huff::new(),
            aligned: Huff::new(),
            pretree: Huff::new(),
            started: false,
            e8: None,
            blocks: 0,
        })
    }

    /// Decodes one frame from `input` (one data block's bytes) into `out`, which gets `out_len`
    /// bytes (at most [`FRAME`]).
    pub fn decode_frame(
        &mut self,
        input: &[u8],
        out_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if out_len > FRAME {
            return Err("an LZX frame of more than 32 KiB");
        }
        let mut bits = Bits::new(input);
        if !self.started {
            self.started = true;
            if bits.read(1) == 1 {
                let hi = bits.read(16);
                let lo = bits.read(16);
                self.e8 = Some(((hi << 16) | lo) as i32);
            }
        }
        let end = self.frame_start + out_len as u64;
        while self.total < end {
            if self.remaining == 0 {
                self.next_block(&mut bits)?;
            }
            match self.kind {
                Kind::Uncompressed => self.copy_raw(&mut bits, end)?,
                _ => self.decode_symbols(&mut bits, end)?,
            }
            if bits.overrun() {
                return Err("LZX data that ends early");
            }
        }
        let from = out.len();
        self.output(out_len, out);
        if let Some(size) = self.e8
            && let Some(frame) = out.get_mut(from..)
        {
            e8_translate(frame, self.frame_start, size);
        }
        self.frame_start = end;
        Ok(())
    }

    /// Reads the next block's header and trees.
    fn next_block(&mut self, bits: &mut Bits<'_>) -> Result<(), Error> {
        if self.kind == Kind::Uncompressed {
            // Back to bits after the bytes, past an odd block's padding.
            let mut at = bits.byte_pos();
            if self.pad {
                self.pad = false;
                if at < bits.data.len() {
                    at += 1;
                }
            }
            bits.reset_at(at);
        }
        self.blocks += 1;
        let kind = bits.read(3);
        let hi = bits.read(16);
        let lo = bits.read(8);
        let size = (hi << 8) | lo;
        if size == 0 {
            return Err("an empty LZX block");
        }
        match kind {
            1 | 2 => {
                if kind == 2 {
                    let mut lens = [0u8; ALIGNED];
                    for l in &mut lens {
                        *l = bits.read(3) as u8;
                    }
                    self.aligned.build(&lens, false)?;
                }
                let main_len = self.main_lens.len();
                self.read_lengths(bits, Which::Main, 0, NUM_CHARS)?;
                self.read_lengths(bits, Which::Main, NUM_CHARS, main_len)?;
                self.read_lengths(bits, Which::Length, 0, LENGTHS)?;
                self.main.build(&self.main_lens, false)?;
                self.length.build(&self.length_lens, true)?;
                self.kind = if kind == 2 {
                    Kind::Aligned
                } else {
                    Kind::Verbatim
                };
            }
            3 => {
                bits.align();
                let at = bits.byte_pos();
                let r = bits
                    .data
                    .get(at..at + 12)
                    .ok_or("an uncompressed LZX block cut short")?;
                for (i, w) in r.as_chunks::<4>().0.iter().enumerate() {
                    self.r[i] = u32::from_le_bytes(*w);
                }
                bits.reset_at(at + 12);
                self.kind = Kind::Uncompressed;
                self.pad = size % 2 == 1;
            }
            _ => return Err("an LZX block of an unknown type"),
        }
        self.remaining = size;
        Ok(())
    }

    /// The path lengths `first..last` of the main or length tree, as differences from the last
    /// block's, through a pretree.
    fn read_lengths(
        &mut self,
        bits: &mut Bits<'_>,
        which: Which,
        first: usize,
        last: usize,
    ) -> Result<(), Error> {
        let mut pre = [0u8; PRETREE];
        for l in &mut pre {
            *l = bits.read(4) as u8;
        }
        self.pretree.build(&pre, false)?;
        let lens: &mut [u8] = match which {
            Which::Main => &mut self.main_lens,
            Which::Length => &mut self.length_lens,
        };
        let lens = lens.get_mut(..last).ok_or("LZX lengths past the tree")?;
        let mut i = first;
        while i < last {
            bits.refill();
            let z = self.pretree.decode(bits)?;
            let (run, value) = match z {
                17 => (bits.read(4) as usize + 4, 0),
                18 => (bits.read(5) as usize + 20, 0),
                19 => {
                    let run = bits.read(1) as usize + 4;
                    bits.refill();
                    let z = self.pretree.decode(bits)?;
                    if z > 16 {
                        return Err("a bad LZX length");
                    }
                    (run, (lens[i] + 17 - z as u8) % 17)
                }
                0..=16 => (1, (lens[i] + 17 - z as u8) % 17),
                _ => return Err("a bad LZX length"),
            };
            let to = (i + run).min(last);
            lens[i..to].fill(value);
            i = to;
        }
        Ok(())
    }

    /// Copies an uncompressed block's bytes, up to the frame's end.
    fn copy_raw(&mut self, bits: &mut Bits<'_>, end: u64) -> Result<(), Error> {
        let at = bits.byte_pos();
        let want = u64::from(self.remaining).min(end - self.total) as usize;
        let src = bits
            .data
            .get(at..)
            .map(|d| &d[..want.min(d.len())])
            .unwrap_or_default();
        if src.is_empty() {
            return Err("an uncompressed LZX block cut short");
        }
        let n = src.len();
        let mut done = 0;
        while done < n {
            let pos = (self.total as usize + done) & self.mask;
            let room = (self.window.len() - pos).min(n - done);
            self.window[pos..pos + room].copy_from_slice(&src[done..done + room]);
            done += room;
        }
        self.total += n as u64;
        self.remaining -= n as u32;
        bits.reset_at(at + n);
        Ok(())
    }

    /// Decodes a verbatim or aligned block's symbols, up to the frame's end; the last match may
    /// run past it. The state it changes is kept in locals while it runs.
    fn decode_symbols(&mut self, bits: &mut Bits<'_>, end: u64) -> Result<(), Error> {
        let aligned = self.kind == Kind::Aligned;
        let slots = self.slots;
        let mask = self.mask;
        let mut b = *bits;
        let mut total = self.total;
        let mut remaining = self.remaining;
        let mut r = self.r;
        let window = &mut self.window[..];
        let (main, length, aligned_tree) = (&self.main, &self.length, &self.aligned);
        let wsize = window.len();
        macro_rules! tri {
            ($e:expr) => {
                match $e {
                    Ok(v) => v,
                    Err(e) => break Err(e),
                }
            };
        }
        let result = loop {
            if remaining == 0 || total >= end {
                break Ok(());
            }
            // Enough for a main and a length symbol.
            if b.n < 32 {
                b.refill();
            }
            let sym = usize::from(tri!(main.decode(&mut b)));
            if sym < NUM_CHARS {
                window[total as usize & mask] = sym as u8;
                total += 1;
                remaining -= 1;
                // A second literal without refilling, while 16 bits are left.
                if remaining != 0 && total < end && b.n >= 16 {
                    let e = main.table[b.peek(TABLE_BITS) as usize];
                    let l = u32::from(e & 0x1F);
                    let s2 = usize::from(e >> 5);
                    if l != 0 && s2 < NUM_CHARS {
                        b.skip(l);
                        window[total as usize & mask] = s2 as u8;
                        total += 1;
                        remaining -= 1;
                    }
                }
                continue;
            }
            let m = sym - NUM_CHARS;
            let slot = m >> 3;
            let mut len = m & 7;
            if len == 7 {
                len += usize::from(tri!(length.decode(&mut b)));
            }
            len += MIN_MATCH;
            let offset = match slot {
                0 => r[0],
                1 => {
                    r.swap(0, 1);
                    r[0]
                }
                2 => {
                    r.swap(0, 2);
                    r[0]
                }
                _ => {
                    if slot >= slots {
                        break Err("an LZX position slot past the window");
                    }
                    b.refill();
                    let extra = extra_bits(slot);
                    let base = POSITION_BASE[slot] - 2;
                    let off = if aligned && extra >= 3 {
                        let verbatim = b.read(extra - 3) << 3;
                        b.refill();
                        base + verbatim + u32::from(tri!(aligned_tree.decode(&mut b)))
                    } else {
                        base + b.read(extra)
                    };
                    r = [off, r[0], r[1]];
                    off
                }
            } as usize;
            if offset == 0 || offset as u64 > total || offset > wsize {
                break Err("an LZX match that reaches before the data");
            }
            if len > remaining as usize {
                break Err("an LZX match that runs past its block");
            }
            copy_match(window, mask, total as usize & mask, offset, len);
            total += len as u64;
            remaining -= len as u32;
        };
        *bits = b;
        self.total = total;
        self.remaining = remaining;
        self.r = r;
        result
    }

    /// The frame's output, out of the window.
    fn output(&self, len: usize, out: &mut Vec<u8>) {
        let start = self.frame_start as usize & self.mask;
        let first = len.min(self.window.len() - start);
        out.extend_from_slice(&self.window[start..start + first]);
        out.extend_from_slice(&self.window[..len - first]);
    }
}

/// Copies `len` bytes from `offset` back to `dst`, in the window.
#[inline]
fn copy_match(window: &mut [u8], mask: usize, dst: usize, offset: usize, len: usize) {
    let src = dst.wrapping_sub(offset) & mask;
    let w = window.len();
    if dst + len <= w && src + len <= w {
        // Eight bytes at a time when the source is at least that far back, which a copy of a
        // fixed size compiles to a load and a store for; then byte by byte.
        let mut i = 0;
        if offset >= 8 {
            while i + 8 <= len {
                let chunk: [u8; 8] = window[src + i..src + i + 8].try_into().unwrap_or_default();
                window[dst + i..dst + i + 8].copy_from_slice(&chunk);
                i += 8;
            }
        }
        while i < len {
            window[dst + i] = window[src + i];
            i += 1;
        }
    } else {
        for i in 0..len {
            window[(dst + i) & mask] = window[(src + i) & mask];
        }
    }
}

#[derive(Clone, Copy)]
enum Which {
    Main,
    Length,
}

/// LZX's E8 translation of one decoded frame that starts `offset` bytes into its folder, as
/// the spec (and libmspack, and 7-Zip) do it: an `E8` byte's 32-bit operand `abs`, when
/// `-pos <= abs < size`, becomes `abs - pos` if `abs >= 0`, else `abs + size`. Not done in the
/// last 10 bytes of a frame, in frames of 10 bytes or less, or after the first GiB.
pub fn e8_translate(data: &mut [u8], offset: u64, size: i32) {
    if offset >= 0x4000_0000 || data.len() <= 10 {
        return;
    }
    let end = data.len() - 10;
    let mut i = 0;
    while i < end {
        let Some(at) = memchr::memchr(0xE8, &data[i..end]) else {
            return;
        };
        i += at;
        // Below 1 GiB, so it fits.
        let pos = (offset + i as u64) as i32;
        let abs = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
        if abs >= -pos && abs < size {
            let rel = if abs >= 0 {
                abs.wrapping_sub(pos)
            } else {
                abs.wrapping_add(size)
            };
            data[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
        }
        i += 5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_slots_add_up() {
        assert_eq!(&POSITION_BASE[..10], &[0, 1, 2, 3, 4, 6, 8, 12, 16, 24]);
        assert_eq!(extra_bits(36), 17);
        assert_eq!(extra_bits(49), 17);
        // A 2 MiB window's last slot reaches its end.
        assert_eq!(POSITION_BASE[50], 2 * 1024 * 1024);
    }

    #[test]
    fn huffman_codes_are_canonical() {
        let mut h = Huff::new();
        // a: 1 bit (0), b: 2 bits (10), c and d: 3 bits (110, 111).
        h.build(&[1, 2, 3, 3], false).unwrap();
        let mut w = Writer::new();
        w.put(0b0, 1);
        w.put(0b111, 3);
        w.put(0b110, 3);
        w.put(0b10, 2);
        let data = w.finish();
        let mut bits = Bits::new(&data);
        bits.refill();
        let got: Vec<u16> = (0..4).map(|_| h.decode(&mut bits).unwrap()).collect();
        assert_eq!(got, [0, 3, 2, 1]);
        assert!(h.build(&[1, 1, 1], false).is_err(), "over-full");
        assert!(h.build(&[1, 2], false).is_err(), "incomplete");
        assert!(h.build(&[0, 0], true).is_ok());
        assert!(h.build(&[0, 0], false).is_err());
    }

    #[test]
    fn long_codes_decode_past_the_table() {
        // Lengths 1, 2, …, 15, 16, 16: complete, with codes longer than the table.
        let mut lens: Vec<u8> = (1..=16).collect();
        lens.push(16);
        let mut h = Huff::new();
        h.build(&lens, false).unwrap();
        // The last symbol's code is sixteen 1s.
        let data = [0xFF, 0xFF, 0x00, 0x00];
        let mut bits = Bits::new(&data);
        bits.refill();
        assert_eq!(h.decode(&mut bits).unwrap(), 16);
        // Fifteen 1s then a 0: the second-to-last.
        let data = [0xFE, 0xFF, 0x00, 0x00];
        let mut bits = Bits::new(&data);
        bits.refill();
        assert_eq!(h.decode(&mut bits).unwrap(), 15);
    }

    /// Bits written as LZX reads them: into 16-bit words from the top, little-endian.
    struct Writer {
        out: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl Writer {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                acc: 0,
                n: 0,
            }
        }

        fn put(&mut self, v: u32, k: u32) {
            for i in (0..k).rev() {
                self.acc = (self.acc << 1) | ((v >> i) & 1);
                self.n += 1;
                if self.n == 16 {
                    self.out.extend_from_slice(&(self.acc as u16).to_le_bytes());
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                let pad = 16 - self.n;
                self.put(0, pad);
            }
            self.out
        }
    }

    #[test]
    fn an_uncompressed_block_and_its_padding() {
        // No E8; an uncompressed block of 3 bytes ("abc"), padded, then another of 2.
        let mut w = Writer::new();
        w.put(0, 1);
        w.put(3, 3);
        w.put(0, 16);
        w.put(3, 8);
        // 28 bits: the rest of the second word is skipped to align.
        let mut data = w.finish();
        data.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
        data.extend_from_slice(b"abc");
        data.push(0); // padding
        let mut w = Writer::new();
        w.put(3, 3);
        w.put(0, 16);
        w.put(2, 8);
        data.extend_from_slice(&w.finish());
        data.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
        data.extend_from_slice(b"de");
        let mut lzx = Lzx::new(15).unwrap();
        let mut out = Vec::new();
        lzx.decode_frame(&data, 5, &mut out).unwrap();
        assert_eq!(out, b"abcde");
    }

    #[test]
    fn crafted_streams_fail_without_panicking() {
        let mut out = Vec::new();
        for seed in 0..2000u32 {
            let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
            let data: Vec<u8> = (0..300)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let mut lzx = Lzx::new(15 + seed % 7).unwrap();
            out.clear();
            for _ in 0..3 {
                if lzx.decode_frame(&data, FRAME, &mut out).is_err() {
                    break;
                }
            }
        }
    }
    /// Decodes every LZX folder of the cabinet `BEEZIP_LZX_BENCH` names, alone: how fast the
    /// decoder is, without the reader around it. `cargo test --release -- --ignored bench`.
    #[test]
    #[ignore = "a benchmark, given BEEZIP_LZX_BENCH"]
    fn bench_lzx() {
        let Ok(path) = std::env::var("BEEZIP_LZX_BENCH") else {
            return;
        };
        let cab = std::fs::read(path).unwrap();
        let le16 = |at: usize| usize::from(u16::from_le_bytes([cab[at], cab[at + 1]]));
        let le32 = |at: usize| u32::from_le_bytes(cab[at..at + 4].try_into().unwrap()) as usize;
        let folders = le16(26);
        let flags = le16(30);
        let (mut at, folder_res, data_res) = if flags & 4 != 0 {
            (
                36 + 4 + le16(36),
                usize::from(cab[38]),
                usize::from(cab[39]),
            )
        } else {
            (36, 0, 0)
        };
        assert_eq!(flags & 3, 0, "a cabinet of a set");
        let started = std::time::Instant::now();
        let mut total = 0usize;
        let mut lzx_blocks = 0u64;
        let mut out = Vec::with_capacity(FRAME);
        for _ in 0..folders {
            let (start, blocks, kind) = (le32(at), le16(at + 4), le16(at + 6));
            at += 8 + folder_res;
            assert_eq!(kind & 0xF, 3, "an LZX folder");
            let mut lzx = Lzx::new(((kind >> 8) & 0x1F) as u32).unwrap();
            let mut b = start;
            for _ in 0..blocks {
                let (packed, unpacked) = (le16(b + 4), le16(b + 6));
                let data = &cab[b + 8 + data_res..b + 8 + data_res + packed];
                out.clear();
                lzx.decode_frame(data, unpacked, &mut out).unwrap();
                total += out.len();
                b += 8 + data_res + packed;
            }
            lzx_blocks += lzx.blocks;
        }
        let secs = started.elapsed().as_secs_f64();
        eprintln!(
            "{total} bytes in {secs:.2} s: {:.0} MB/s, {lzx_blocks} LZX blocks",
            total as f64 / secs / 1e6
        );
    }
}
