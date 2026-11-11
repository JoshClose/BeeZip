//! LZX decoding as cabinets, WIM images and WOF files use it (MS-CAB's LZX, the LZXD of MS-PATCH
//! without reference data), BeeZip's own (docs/M7.md §8.4, docs/M8.md §4.3). It replaced lzxd 0.2.7, which decoded at about a quarter of
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
//! - **Matches** may not run past their frame's end (MS-PATCH §2.1.5: no match spans a 32 KiB
//!   boundary; 7-Zip calls one a data error), nor past their LZX block's end, nor reach before the
//!   stream's start or further back than the window. BeeZip 0.2.0 let one run on into the next
//!   frame, which in a 32 KiB window overwrote the frame's own first bytes: wrong data, no error
//!   (docs/M8.md §6.1).
//! - **E8 translation** (x86 call addresses) is undone on each frame's output after it's copied
//!   out of the window, as the spec, libmspack and 7-Zip do.
//! - **WIM and WOF** ([`Lzx::new_wim`]) compress each chunk on its own, as one frame as long as
//!   the chunk (32 KiB in WOF, up to 2 MiB in a WIM), each with a fresh state: no E8 header
//!   (translation is always on, with a size of 12,000,000), and a block's size is one bit for
//!   32,768, else 16 bits, or 24 past a 32 KiB window. A match may not run past the chunk's end.
//!   Found by trying the variants on Microsoft's boot.wim, DISM's and wimlib's WIMs and
//!   Windows-written WOF files (docs/M8.md §4.3).
//!
//! - **The window is a ring of twice the window's size plus [`SLACK`] bytes** (docs/M8.md §6.1),
//!   so a match is copied 16 and then 8 bytes at a time and may run over into bytes no match can
//!   reach yet, and the hot loop checks one bound: the nearest of the block's end, the frame's
//!   end and the ring's end. A two-literal table (`pairs`) decodes two short literal codes in one
//!   lookup. About 1.45 times as fast as BeeZip 0.2.0's decoder, for 2 MiB more memory with a
//!   21-bit window.
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
    #[inline(always)]
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
        self.refill_end();
    }

    /// [`Bits::refill`] within eight bytes of the data's end: a word at a time, zeros past it.
    #[cold]
    #[inline(never)]
    fn refill_end(&mut self) {
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

    /// The next `k` bits, 0 to 32, which must be in the buffer.
    #[inline(always)]
    fn take(&mut self, k: u32) -> u32 {
        let v = ((self.buf >> (63 - k)) >> 1) as u32;
        self.skip(k);
        v
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
            // No code reads as a short one: decode() finds it empty off its fast path.
            self.table.fill(0);
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
        let e = self.table[bits.peek(TABLE_BITS) as usize];
        let l = u32::from(e & 0x1F);
        if l != 0 {
            bits.skip(l);
            return Ok(e >> 5);
        }
        if self.empty {
            return Err("a symbol from an empty LZX tree");
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

/// A pair-table entry's kind: none (a code longer than the table: decode it alone), one literal,
/// two literals, or a match's main symbol.
const PAIR_KIND: u32 = 0x60;
const PAIR_ONE: u32 = 0x20;
const PAIR_TWO: u32 = 0x40;
const PAIR_MATCH: u32 = 0x60;

/// The main tree's table as up to two symbols a lookup: bits 0-4 the bits all of them take, 5-6
/// the kind, 8-15 and 16-23 two literals (or 8-19 a match's symbol), 24-28 the first literal's
/// bits alone.
fn pair_table(main: &Huff, pairs: &mut [u32; 1 << TABLE_BITS]) {
    let mask = (1usize << TABLE_BITS) - 1;
    for (i, p) in pairs.iter_mut().enumerate() {
        let e1 = main.table[i];
        let l1 = u32::from(e1 & 0x1F);
        let s1 = u32::from(e1 >> 5);
        *p = if l1 == 0 {
            0
        } else if s1 as usize >= NUM_CHARS {
            PAIR_MATCH | (s1 << 8) | l1
        } else {
            let e2 = main.table[(i << l1) & mask];
            let l2 = u32::from(e2 & 0x1F);
            let s2 = u32::from(e2 >> 5);
            if l2 != 0 && l1 + l2 <= TABLE_BITS && (s2 as usize) < NUM_CHARS {
                PAIR_TWO | (l1 << 24) | (s2 << 16) | (s1 << 8) | (l1 + l2)
            } else {
                PAIR_ONE | (l1 << 24) | (s1 << 8) | l1
            }
        };
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

/// Bytes past the ring's end: a match that runs over it (at most 257 bytes) and a wide copy's
/// overrun land there before they're moved to the ring's start.
const SLACK: usize = 512;

/// One folder's LZX stream.
pub struct Lzx {
    /// A ring of twice the window, and [`SLACK`]: a wide copy's overrun (up to 15 bytes past a
    /// match) then only touches bytes further back than any offset reaches.
    window: Vec<u8>,
    /// The ring's size, less one.
    mask: usize,
    /// The window's size: the furthest a match may reach.
    wsize: usize,
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
    /// The main tree's table read for up to two symbols at once ([`pair_table`]).
    pairs: Box<[u32; 1 << TABLE_BITS]>,
    length: Huff,
    aligned: Huff,
    pretree: Huff,
    /// Whether the E8 header has been read, and the translation size it gave.
    started: bool,
    e8: Option<i32>,
    /// Blocks read, for the benchmark.
    blocks: u64,
    /// A WIM or WOF chunk ([`Lzx::new_wim`]).
    wim: bool,
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
            window: vec![0; 2 * size + SLACK],
            mask: 2 * size - 1,
            wsize: size,
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
            pairs: Box::new([0; 1 << TABLE_BITS]),
            length: Huff::new(),
            aligned: Huff::new(),
            pretree: Huff::new(),
            started: false,
            e8: None,
            blocks: 0,
            wim: false,
        })
    }

    /// One WIM or WOF chunk's stream, with a window of 2^`bits` bytes (15 for WOF's 32 KiB
    /// chunks), decoded as one frame of up to the window's size.
    pub fn new_wim(bits: u32) -> Result<Self, Error> {
        Ok(Self {
            wim: true,
            ..Self::new(bits)?
        })
    }

    /// A fresh stream again, as [`Lzx::new`] made it, keeping its buffers: the next of a WIM's
    /// chunks, each of which starts afresh. What the window held can't be reached, since no match
    /// may reach before the stream's start.
    pub fn reset(&mut self) {
        self.total = 0;
        self.frame_start = 0;
        self.r = [1, 1, 1];
        self.kind = Kind::None;
        self.remaining = 0;
        self.pad = false;
        self.main_lens.fill(0);
        self.length_lens = [0; LENGTHS];
        self.started = false;
        self.e8 = None;
    }

    /// Decodes one frame from `input` (one data block's bytes, or a WIM chunk's) into `out`, which
    /// gets `out_len` bytes (at most [`FRAME`], or the window for a WIM chunk).
    pub fn decode_frame(
        &mut self,
        input: &[u8],
        out_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if out_len > if self.wim { self.wsize } else { FRAME } {
            return Err("an LZX frame longer than its window");
        }
        let mut bits = Bits::new(input);
        if !self.started {
            self.started = true;
            if self.wim {
                self.e8 = Some(12_000_000);
            } else if bits.read(1) == 1 {
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
        let size = if !self.wim {
            let hi = bits.read(16);
            (hi << 8) | bits.read(8)
        } else if bits.read(1) == 1 {
            32_768
        } else if self.wsize > FRAME {
            let hi = bits.read(8);
            (hi << 16) | bits.read(16)
        } else {
            bits.read(16)
        };
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
                pair_table(&self.main, &mut self.pairs);
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
            let room = (self.mask + 1 - pos).min(n - done);
            self.window[pos..pos + room].copy_from_slice(&src[done..done + room]);
            done += room;
        }
        self.total += n as u64;
        self.remaining -= n as u32;
        bits.reset_at(at + n);
        Ok(())
    }

    /// Decodes a verbatim or aligned block's symbols, up to the frame's end. The state it
    /// changes is kept in locals while it runs. The hot loop works in
    /// ring positions with one bound, the nearest of the block's end, the frame's end and the
    /// ring's end; a match that runs past the ring's end is moved to its start afterwards.
    #[inline(never)]
    fn decode_symbols(&mut self, bits: &mut Bits<'_>, end: u64) -> Result<(), Error> {
        let aligned = self.kind == Kind::Aligned;
        let slots = self.slots;
        let ring = self.mask + 1;
        let wsize = self.wsize;
        let mut b = *bits;
        let mut r = self.r;
        let (main, length, aligned_tree) = (&self.main, &self.length, &self.aligned);
        let pairs = &*self.pairs;
        let window = &mut self.window[..];
        macro_rules! tri {
            ($e:expr) => {
                match $e {
                    Ok(v) => v,
                    Err(e) => break Err(e),
                }
            };
        }
        let result = loop {
            if self.remaining == 0 || self.total >= end {
                break Ok(());
            }
            let start = self.total as usize & self.mask;
            let room = u64::from(self.remaining)
                .min(end - self.total)
                .min((ring - start) as u64) as usize;
            let stop = start + room;
            let block_end = start + self.remaining as usize;
            let frame_end = start + (end - self.total) as usize;
            // Where a match must end: its block's end, and its frame's.
            let limit = block_end.min(frame_end);
            // The furthest back a match may reach, at `pos`: `pos + before`, at most the window.
            let before = (self.total - start as u64).min(wsize as u64) as usize;
            let mut pos = start;
            let inner = loop {
                if pos >= stop {
                    break Ok(());
                }
                // Enough for a main and a length symbol.
                if b.n < 32 {
                    b.refill();
                }
                let e = pairs[b.peek(TABLE_BITS) as usize];
                let kind = e & PAIR_KIND;
                if kind == PAIR_TWO && pos + 1 < stop {
                    b.skip(e & 0x1F);
                    window[pos] = (e >> 8) as u8;
                    window[pos + 1] = (e >> 16) as u8;
                    pos += 2;
                    continue;
                }
                if kind != PAIR_MATCH && kind != 0 {
                    b.skip((e >> 24) & 0x1F);
                    window[pos] = (e >> 8) as u8;
                    pos += 1;
                    continue;
                }
                let sym = if kind == PAIR_MATCH {
                    b.skip(e & 0x1F);
                    ((e >> 8) & 0xFFF) as usize
                } else {
                    usize::from(tri!(main.decode(&mut b)))
                };
                if sym < NUM_CHARS {
                    window[pos] = sym as u8;
                    pos += 1;
                    continue;
                }
                let m = sym - NUM_CHARS;
                let slot = m >> 3;
                let mut len = m & 7;
                if len == 7 {
                    len += usize::from(tri!(length.decode(&mut b)));
                }
                len += MIN_MATCH;
                let offset = if slot < 3 {
                    // A repeated offset, swapped to the front.
                    r.swap(slot, 0);
                    r[0]
                } else {
                    if slot >= slots {
                        break Err("an LZX position slot past the window");
                    }
                    // More than 48 bits: at most 17 extra bits, or 14 and an aligned symbol of
                    // at most 7.
                    b.refill();
                    let extra = extra_bits(slot);
                    let base = POSITION_BASE[slot] - 2;
                    let off = if aligned && extra >= 3 {
                        let verbatim = b.take(extra - 3) << 3;
                        base + verbatim + u32::from(tri!(aligned_tree.decode(&mut b)))
                    } else {
                        base + b.take(extra)
                    };
                    r = [off, r[0], r[1]];
                    off
                } as usize;
                if offset == 0 || offset > (pos + before).min(wsize) {
                    break Err("an LZX match that reaches before the data");
                }
                if pos + len > limit {
                    break Err(if pos + len > block_end {
                        "an LZX match that runs past its block"
                    } else {
                        "an LZX match that runs past its frame"
                    });
                }
                copy_match(window, ring, pos, offset, len);
                pos += len;
            };
            let done = pos - start;
            self.total += done as u64;
            self.remaining -= done as u32;
            if let Err(e) = inner {
                break Err(e);
            }
            // Past the ring's end: those bytes belong at its start.
            if pos > ring {
                window.copy_within(ring..pos, 0);
            }
        };
        *bits = b;
        self.r = r;
        result
    }

    /// The frame's output, out of the window.
    fn output(&self, len: usize, out: &mut Vec<u8>) {
        let start = self.frame_start as usize & self.mask;
        let first = len.min(self.mask + 1 - start);
        out.extend_from_slice(&self.window[start..start + first]);
        out.extend_from_slice(&self.window[..len - first]);
    }
}

/// Copies `len` bytes from `offset` back to `dst` in the ring of `ring` bytes, the slack past
/// it taking what runs over its end. `dst < ring`, `offset` at most half the ring, and `len` at
/// most 257, so `dst + len` is within the slack.
#[inline(always)]
fn copy_match(window: &mut [u8], ring: usize, dst: usize, offset: usize, len: usize) {
    if offset > dst {
        // From before the ring's start: byte by byte, wrapping. `dst` is then within the first
        // half of the ring, so the match doesn't reach the slack.
        let mut s = dst + ring - offset;
        for i in 0..len {
            if s >= ring {
                s -= ring;
            }
            let v = window.get(s).copied().unwrap_or_default();
            if let Some(d) = window.get_mut(dst + i) {
                *d = v;
            }
            s += 1;
        }
        return;
    }
    let src = dst - offset;
    if dst + len + 16 > window.len() {
        // Not reached: the slack holds a whole match and an overrun.
        for i in 0..len {
            let v = window.get(src + i).copied().unwrap_or_default();
            if let Some(d) = window.get_mut(dst + i) {
                *d = v;
            }
        }
        return;
    }
    // Sixteen bytes at a time when the source is at least that far back, then eight; each copy
    // may write up to 15 bytes past the match, into bytes not yet decoded or further back than
    // the window.
    let mut i = 0;
    if offset >= 16 {
        loop {
            let chunk: [u8; 16] = window[src + i..src + i + 16].try_into().unwrap_or_default();
            window[dst + i..dst + i + 16].copy_from_slice(&chunk);
            i += 16;
            if i >= len {
                return;
            }
        }
    }
    if offset >= 8 {
        loop {
            let chunk: [u8; 8] = window[src + i..src + i + 8].try_into().unwrap_or_default();
            window[dst + i..dst + i + 8].copy_from_slice(&chunk);
            i += 8;
            if i >= len {
                return;
            }
        }
    }
    while i < len {
        window[dst + i] = window[src + i];
        i += 1;
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

    /// A verbatim block of `b`, then `literals - 1` of `a`, then a match of 8 bytes at offset 1,
    /// in a 32 KiB window. Main tree: `a` 0, `b` 10, the match (slot 0, length 8) 11.
    fn ending_in_a_match(literals: usize) -> Vec<u8> {
        let block = literals as u32 + 8;
        let mut w = Writer::new();
        w.put(0, 1);
        w.put(1, 3);
        w.put(block >> 8, 16);
        w.put(block & 0xFF, 8);
        // A pretree of 0 (no change: `0`), 15 (2 more: `10`) and 16 (1 more: `11`).
        let lengths = |w: &mut Writer, lens: &mut dyn Iterator<Item = u8>| {
            for z in 0..PRETREE {
                w.put(
                    match z {
                        0 => 1,
                        15 | 16 => 2,
                        _ => 0,
                    },
                    4,
                );
            }
            for l in lens {
                match l {
                    0 => w.put(0, 1),
                    1 => w.put(0b11, 2),
                    _ => w.put(0b10, 2),
                }
            }
        };
        lengths(
            &mut w,
            &mut (0..NUM_CHARS).map(|i| match i {
                0x61 => 1,
                0x62 => 2,
                _ => 0,
            }),
        );
        lengths(
            &mut w,
            &mut (NUM_CHARS..NUM_CHARS + 8 * 30).map(|i| u8::from(i == NUM_CHARS + 6) * 2),
        );
        lengths(&mut w, &mut std::iter::repeat_n(0, LENGTHS));
        w.put(0b10, 2);
        for _ in 1..literals {
            w.put(0, 1);
        }
        w.put(0b11, 2);
        w.finish()
    }

    /// No match may run past its frame's end (MS-PATCH §2.1.5). BeeZip 0.2.0 decoded one, and in
    /// a 32 KiB window its overflow landed on the frame's first bytes: this frame came out
    /// starting `a`, not `b`, with no error (docs/M8.md §6.1).
    #[test]
    fn a_match_past_its_frame_is_corrupt() {
        let mut out = Vec::new();
        let err = Lzx::new(15)
            .unwrap()
            .decode_frame(&ending_in_a_match(FRAME - 3), FRAME, &mut out)
            .unwrap_err();
        assert_eq!(err, "an LZX match that runs past its frame");

        // Ending at the frame's end is fine.
        out.clear();
        Lzx::new(15)
            .unwrap()
            .decode_frame(&ending_in_a_match(FRAME - 8), FRAME, &mut out)
            .unwrap();
        assert_eq!(out.len(), FRAME);
        assert_eq!(out[0], b'b');
        assert!(out[1..].iter().all(|&b| b == b'a'));
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
