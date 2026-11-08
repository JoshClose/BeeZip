//! ARC's own methods, as streaming readers: the password's XOR, RLE90 ("packing"), squeezing
//! (Huffman, as in Richard Greenlaw's public-domain SQ/USQ) and the 12-bit LZW of the first
//! crunched methods (5–7). The newer crunched and squashed methods are compress's LZW, in
//! `codec::compress`. Written from public descriptions of the formats.

use std::io::{self, Read};

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

/// Bytes from a reader one at a time, through a small buffer.
struct Bytes<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
}

impl<R: Read> Bytes<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0; 4096].into_boxed_slice(),
            pos: 0,
            len: 0,
        }
    }

    fn next(&mut self) -> io::Result<Option<u8>> {
        if self.pos == self.len {
            self.len = loop {
                match self.inner.read(&mut self.buf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            };
            self.pos = 0;
            if self.len == 0 {
                return Ok(None);
            }
        }
        self.pos += 1;
        Ok(Some(self.buf[self.pos - 1]))
    }
}

/// ARC's "encryption": every byte of an entry's packed data XORed with the password, repeated.
pub struct Xor<R> {
    inner: R,
    key: Vec<u8>,
    at: usize,
}

impl<R: Read> Xor<R> {
    pub fn new(inner: R, key: &[u8]) -> Self {
        Self {
            inner,
            key: key.to_vec(),
            at: 0,
        }
    }
}

impl<R: Read> Read for Xor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if !self.key.is_empty() {
            for b in &mut buf[..n] {
                *b ^= self.key[self.at];
                self.at = (self.at + 1) % self.key.len();
            }
        }
        Ok(n)
    }
}

/// The repeat marker: `c 90 n` is `c` `n` times in all, and `90 00` is a 0x90 byte.
const DLE: u8 = 0x90;

/// RLE90 ("packing"), ARC's methods 3, 4, 6, 7 and 8 after their other step.
pub struct Rle90<R> {
    inner: Bytes<R>,
    last: Option<u8>,
    repeat: u8,
}

impl<R: Read> Rle90<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner: Bytes::new(inner),
            last: None,
            repeat: 0,
        }
    }
}

impl<R: Read> Read for Rle90<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            if self.repeat > 0 {
                let (Some(c), k) = (self.last, usize::from(self.repeat).min(buf.len() - n)) else {
                    return Err(bad("RLE90: a repeat before any byte"));
                };
                buf[n..n + k].fill(c);
                n += k;
                self.repeat -= k as u8;
                continue;
            }
            let Some(b) = self.inner.next()? else {
                break;
            };
            if b != DLE {
                self.last = Some(b);
                buf[n] = b;
                n += 1;
                continue;
            }
            match self.inner.next()? {
                None => return Err(bad("RLE90: the data ends inside a repeat")),
                // A 0x90 byte, which doesn't become the byte to repeat (as ARC reads it).
                Some(0) => {
                    buf[n] = DLE;
                    n += 1;
                }
                Some(count) => {
                    if self.last.is_none() {
                        return Err(bad("RLE90: a repeat before any byte"));
                    }
                    self.repeat = count - 1;
                }
            }
        }
        Ok(n)
    }
}

/// Squeezing's end of data, the 257th value.
const SPEOF: u16 = 256;
/// The most nodes a tree of 257 values has.
const MAX_NODES: usize = 256;

/// Squeezed data (method 4, before RLE90): a node count, that many pairs of children (a
/// non-negative child is a node, a negative one `-(v + 1)` the value `v`), then the bits of the
/// codes, low bit first, walking from node 0. A child past the table, or a value past
/// [`SPEOF`], is refused when the table is read (unarc-rs 0.8.1's decoder indexes past it).
pub struct Unsqueeze<R> {
    inner: Bytes<R>,
    nodes: Vec<[i16; 2]>,
    started: bool,
    done: bool,
    bits: u8,
    left: u8,
}

impl<R: Read> Unsqueeze<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner: Bytes::new(inner),
            nodes: Vec::new(),
            started: false,
            done: false,
            bits: 0,
            left: 0,
        }
    }

    fn word(&mut self) -> io::Result<u16> {
        let short = || bad("squeezed: the decoding tree is cut short");
        let lo = self.inner.next()?.ok_or_else(short)?;
        let hi = self.inner.next()?.ok_or_else(short)?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    fn tree(&mut self) -> io::Result<()> {
        let count = usize::from(self.word()?);
        if count > MAX_NODES {
            return Err(bad(&format!("squeezed: a decoding tree of {count} nodes")));
        }
        self.nodes.reserve_exact(count);
        for _ in 0..count {
            let pair = [self.word()? as i16, self.word()? as i16];
            for c in pair {
                let ok = if c >= 0 {
                    (c as usize) < count
                } else {
                    -(i32::from(c) + 1) <= i32::from(SPEOF)
                };
                if !ok {
                    return Err(bad("squeezed: the decoding tree points outside itself"));
                }
            }
            self.nodes.push(pair);
        }
        // No nodes: the empty file.
        self.done = count == 0;
        Ok(())
    }

    /// The next value, or `None` at its end (or the input's).
    fn value(&mut self) -> io::Result<Option<u8>> {
        let mut node = 0usize;
        loop {
            if self.left == 0 {
                match self.inner.next()? {
                    Some(b) => (self.bits, self.left) = (b, 8),
                    None => return Ok(None),
                }
            }
            let bit = usize::from(self.bits & 1);
            self.bits >>= 1;
            self.left -= 1;
            let child = self.nodes[node][bit];
            if child >= 0 {
                node = child as usize;
                continue;
            }
            let v = (-(i32::from(child) + 1)) as u16;
            if v == SPEOF {
                return Ok(None);
            }
            return Ok(Some(v as u8));
        }
    }
}

impl<R: Read> Read for Unsqueeze<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.started {
            self.started = true;
            self.tree()?;
        }
        let mut n = 0;
        while n < buf.len() && !self.done {
            match self.value()? {
                Some(b) => {
                    buf[n] = b;
                    n += 1;
                }
                None => self.done = true,
            }
        }
        Ok(n)
    }
}

/// The table of the first crunched methods: 4096 strings, each a code and a byte after it,
/// placed by hashing the pair.
const TABSIZE: usize = 4096;
/// The code before a single byte.
const NO_PRED: u16 = 0xFFFF;
/// Where a placed string's chain continues after a collision; 0 ends it.
const PROBE: usize = 101;

#[derive(Debug, Clone, Copy)]
struct Slot {
    used: bool,
    next: u16,
    pred: u16,
    foll: u8,
}

/// The hashed string table of ARC's methods 5–7 (from Kent Williams' public-domain LZWCOM):
/// the code of a string is where `(pred, foll)` landed. Methods 5 and 6 hash with the middle 12
/// bits of a square, method 7 with a multiplication. A collision follows the slot's chain to
/// its end, then looks for a free slot from 101 further on.
pub struct Table {
    slots: Vec<Slot>,
    fast: bool,
    /// Strings that may still be added.
    room: usize,
}

impl Table {
    pub fn new(fast: bool) -> Self {
        let mut t = Self {
            slots: vec![
                Slot {
                    used: false,
                    next: 0,
                    pred: NO_PRED,
                    foll: 0,
                };
                TABSIZE
            ],
            fast,
            room: TABSIZE,
        };
        for c in 0..=255u8 {
            t.add(NO_PRED, c);
        }
        t
    }

    fn hash(&self, pred: u16, foll: u8) -> usize {
        let key = u32::from(pred.wrapping_add(u16::from(foll)));
        if self.fast {
            (key.wrapping_mul(15073) & 0xFFF) as usize
        } else {
            let k = key | 0x800;
            ((k * k) >> 6) as usize & 0xFFF
        }
    }

    /// Places `(pred, foll)`, while there's room. Returns its slot.
    pub fn add(&mut self, pred: u16, foll: u8) -> Option<usize> {
        if self.room == 0 {
            return None;
        }
        let mut at = self.hash(pred, foll);
        if self.slots[at].used {
            // The end of this slot's chain: links only go to slots taken after it, so it ends.
            let mut end = at;
            let mut steps = 0;
            while self.slots[end].next != 0 && steps < TABSIZE {
                end = usize::from(self.slots[end].next);
                steps += 1;
            }
            // `room` says a slot is free.
            at = (end + PROBE) & 0xFFF;
            while self.slots[at].used {
                at = (at + 1) % TABSIZE;
            }
            self.slots[end].next = at as u16;
        }
        self.slots[at] = Slot {
            used: true,
            next: 0,
            pred,
            foll,
        };
        self.room -= 1;
        Some(at)
    }

    /// The slot holding `(pred, foll)`, for the test encoder.
    #[cfg(test)]
    pub fn find(&self, pred: u16, foll: u8) -> Option<usize> {
        let mut at = self.hash(pred, foll);
        for _ in 0..TABSIZE {
            let s = self.slots[at];
            if !s.used {
                return None;
            }
            if s.pred == pred && s.foll == foll {
                return Some(at);
            }
            if s.next == 0 {
                return None;
            }
            at = usize::from(s.next);
        }
        None
    }
}

/// The first crunched methods' LZW (5–7, before RLE90 in 6 and 7): fixed 12-bit codes, two to
/// three bytes, high bits first, into a [`Table`] that stops growing when full.
pub struct Crunch12<R> {
    inner: Bytes<R>,
    table: Table,
    /// The low half of the middle byte, when a second code is due.
    half: Option<u8>,
    old: Option<u16>,
    finchar: u8,
    /// The current string, last byte first.
    stack: Vec<u8>,
    done: bool,
}

impl<R: Read> Crunch12<R> {
    pub fn new(inner: R, fast: bool) -> Self {
        Self {
            inner: Bytes::new(inner),
            table: Table::new(fast),
            half: None,
            old: None,
            finchar: 0,
            stack: Vec::with_capacity(TABSIZE),
            done: false,
        }
    }

    fn code(&mut self) -> io::Result<Option<u16>> {
        let Some(a) = self.inner.next()? else {
            return Ok(None);
        };
        if let Some(h) = self.half.take() {
            return Ok(Some(u16::from(h) << 8 | u16::from(a)));
        }
        let Some(b) = self.inner.next()? else {
            return Ok(None);
        };
        self.half = Some(b & 0x0F);
        Ok(Some(u16::from(a) << 4 | u16::from(b >> 4)))
    }

    /// Decodes one code into `stack`.
    fn step(&mut self) -> io::Result<()> {
        let Some(code) = self.code()? else {
            self.done = true;
            return Ok(());
        };
        let mut c = usize::from(code);
        if !self.table.slots[c].used {
            // A string not in the table yet: the last one and its own first byte.
            let Some(old) = self.old else {
                return Err(bad("crunched: the first code isn't a byte"));
            };
            self.stack.push(self.finchar);
            c = usize::from(old);
        }
        // A crafted table can loop: no string is longer than the table.
        while self.table.slots[c].pred != NO_PRED {
            if self.stack.len() > TABSIZE {
                return Err(bad("crunched: a string longer than the table"));
            }
            self.stack.push(self.table.slots[c].foll);
            c = usize::from(self.table.slots[c].pred) & 0xFFF;
        }
        self.finchar = self.table.slots[c].foll;
        self.stack.push(self.finchar);
        if let Some(old) = self.old {
            self.table.add(old, self.finchar);
        }
        self.old = Some(code);
        Ok(())
    }
}

impl<R: Read> Read for Crunch12<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            if let Some(b) = self.stack.pop() {
                buf[n] = b;
                n += 1;
            } else if self.done {
                break;
            } else {
                self.step()?;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::{BinaryHeap, HashMap};

    use super::*;

    /// RLE90 as ARC writes it: runs of 3 to 255, a 0x90 as `90 00`, and never a run of 0x90s.
    pub fn rle90(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let c = data[i];
            if c == DLE {
                out.extend([DLE, 0]);
                i += 1;
                continue;
            }
            let mut run = 1;
            while i + run < data.len() && data[i + run] == c && run < 255 {
                run += 1;
            }
            if run >= 3 {
                out.extend([c, DLE, run as u8]);
            } else {
                out.extend(std::iter::repeat_n(c, run));
            }
            i += run;
        }
        out
    }

    /// Squeezes `data` (after RLE90): a Huffman tree over the bytes and the end value.
    pub fn squeeze(data: &[u8]) -> Vec<u8> {
        let mut freq: HashMap<u16, u64> = HashMap::new();
        for &b in data {
            *freq.entry(u16::from(b)).or_default() += 1;
        }
        freq.insert(SPEOF, 1);
        // Trees as nested children: a leaf is `-(v + 1)`, a node its index once placed.
        enum T {
            Leaf(u16),
            Node(Box<T>, Box<T>),
        }
        let mut heap: BinaryHeap<std::cmp::Reverse<(u64, usize)>> = BinaryHeap::new();
        let mut trees: Vec<Option<T>> = Vec::new();
        let mut syms: Vec<_> = freq.into_iter().collect();
        syms.sort_unstable();
        for (v, f) in syms {
            heap.push(std::cmp::Reverse((f, trees.len())));
            trees.push(Some(T::Leaf(v)));
        }
        while heap.len() > 1 {
            let std::cmp::Reverse((fa, a)) = heap.pop().unwrap();
            let std::cmp::Reverse((fb, b)) = heap.pop().unwrap();
            let t = T::Node(
                Box::new(trees[a].take().unwrap()),
                Box::new(trees[b].take().unwrap()),
            );
            heap.push(std::cmp::Reverse((fa + fb, trees.len())));
            trees.push(Some(t));
        }
        let root = trees.into_iter().flatten().next().unwrap();
        // Node 0 is the root; codes as bit lists.
        let mut nodes: Vec<[i16; 2]> = Vec::new();
        let mut codes: HashMap<u16, Vec<u8>> = HashMap::new();
        fn place(
            t: &T,
            nodes: &mut Vec<[i16; 2]>,
            codes: &mut HashMap<u16, Vec<u8>>,
            path: Vec<u8>,
        ) -> i16 {
            match t {
                T::Leaf(v) => {
                    codes.insert(*v, path);
                    -(*v as i16) - 1
                }
                T::Node(l, r) => {
                    let at = nodes.len();
                    nodes.push([0, 0]);
                    let mut lp = path.clone();
                    lp.push(0);
                    let mut rp = path;
                    rp.push(1);
                    nodes[at][0] = place(l, nodes, codes, lp);
                    nodes[at][1] = place(r, nodes, codes, rp);
                    at as i16
                }
            }
        }
        place(&root, &mut nodes, &mut codes, Vec::new());
        let mut out = (nodes.len() as u16).to_le_bytes().to_vec();
        for n in &nodes {
            out.extend(n[0].to_le_bytes());
            out.extend(n[1].to_le_bytes());
        }
        let (mut byte, mut k) = (0u8, 0);
        for v in data.iter().map(|&b| u16::from(b)).chain([SPEOF]) {
            for &bit in &codes[&v] {
                byte |= bit << k;
                k += 1;
                if k == 8 {
                    out.push(byte);
                    (byte, k) = (0, 0);
                }
            }
        }
        if k > 0 {
            out.push(byte);
        }
        out
    }

    /// The first crunched methods' LZW, as ARC 4 wrote it: greedy, into the hashed table.
    pub fn crunch12(data: &[u8], fast: bool) -> Vec<u8> {
        let mut t = Table::new(fast);
        let mut codes = Vec::new();
        let mut w: Option<u16> = None;
        for &c in data {
            let Some(pred) = w else {
                w = Some(t.find(NO_PRED, c).unwrap() as u16);
                continue;
            };
            if let Some(at) = t.find(pred, c) {
                w = Some(at as u16);
                continue;
            }
            codes.push(pred);
            t.add(pred, c);
            w = Some(t.find(NO_PRED, c).unwrap() as u16);
        }
        codes.extend(w);
        let mut out = Vec::new();
        for pair in codes.chunks(2) {
            out.push((pair[0] >> 4) as u8);
            match pair.get(1) {
                Some(&b) => {
                    out.push(((pair[0] & 0xF) << 4 | b >> 8) as u8);
                    out.push(b as u8);
                }
                None => out.push(((pair[0] & 0xF) << 4) as u8),
            }
        }
        out
    }

    fn all(r: impl Read) -> io::Result<Vec<u8>> {
        let mut r = r;
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Text, runs (of 0x90 too) and noise.
    pub fn sample() -> Vec<u8> {
        let mut v = b"the quick brown fox ".repeat(300);
        v.extend([0x90; 300]);
        v.extend([b'A'; 600]);
        v.extend([0x90, 0, 0x90, b'x', b'x', b'x', b'x']);
        let mut x = 7u32;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            v.push((x % 23) as u8 + b'a');
        }
        v
    }

    #[test]
    fn rle90_round_trips() {
        let data = sample();
        assert_eq!(all(Rle90::new(&rle90(&data)[..])).unwrap(), data);
        assert_eq!(all(Rle90::new(&b"ab\x90\x04c"[..])).unwrap(), b"abbbbc");
        assert_eq!(all(Rle90::new(&b"\x90\x00"[..])).unwrap(), b"\x90");
        assert!(
            all(Rle90::new(&b"\x90\x05"[..])).is_err(),
            "nothing to repeat"
        );
        assert!(all(Rle90::new(&b"a\x90"[..])).is_err(), "cut short");
        // One byte at a time, across reads.
        let packed = rle90(&data);
        let mut r = Rle90::new(&packed[..]);
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        while r.read(&mut b).unwrap() == 1 {
            out.push(b[0]);
        }
        assert_eq!(out, data);
    }

    #[test]
    fn unsqueeze_round_trips_and_checks_its_tree() {
        let data = rle90(&sample());
        assert_eq!(all(Unsqueeze::new(&squeeze(&data)[..])).unwrap(), data);
        assert_eq!(all(Unsqueeze::new(&squeeze(b"")[..])).unwrap(), b"");
        assert_eq!(all(Unsqueeze::new(&squeeze(b"aaaa")[..])).unwrap(), b"aaaa");
        assert_eq!(all(Unsqueeze::new(&[0u8, 0][..])).unwrap(), b"", "no nodes");
        // A child past the table, a value past the end value, too many nodes, a cut tree.
        for bad in [
            &[1u8, 0, 1, 0, 0xFF, 0xFF][..],
            &[1, 0, 0xFE, 0xFE, 0xFF, 0xFF],
            &[0x01, 0x01],
            &[2, 0, 1, 0],
        ] {
            assert!(all(Unsqueeze::new(bad)).is_err(), "{bad:?}");
        }
        // A tree that loops on itself only reads its input.
        let looped = [1u8, 0, 0, 0, 0, 0, 0xAA, 0x55];
        assert_eq!(all(Unsqueeze::new(&looped[..])).unwrap(), b"");
    }

    #[test]
    fn crunch12_round_trips_both_hashes() {
        let data = sample();
        for fast in [false, true] {
            let packed = crunch12(&data, fast);
            assert!(packed.len() < data.len());
            assert_eq!(all(Crunch12::new(&packed[..], fast)).unwrap(), data);
            assert_eq!(
                all(Crunch12::new(&crunch12(b"a", fast)[..], fast)).unwrap(),
                b"a"
            );
            assert_eq!(
                all(Crunch12::new(&crunch12(b"", fast)[..], fast)).unwrap(),
                b""
            );
        }
        // The table fills: more strings than 4096.
        let mut x = 1u32;
        let noise: Vec<u8> = (0..60_000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect();
        assert_eq!(
            all(Crunch12::new(&crunch12(&noise, true)[..], true)).unwrap(),
            noise
        );
    }

    #[test]
    fn crunch12_survives_any_input() {
        let mut x = 99u32;
        for _ in 0..200 {
            let junk: Vec<u8> = (0..3000)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            for fast in [false, true] {
                let _ = all(Crunch12::new(&junk[..], fast));
            }
        }
    }

    #[test]
    fn xor_repeats_the_key() {
        let data = b"hello, world";
        let once = all(Xor::new(&data[..], b"key")).unwrap();
        assert_ne!(&once[..], data);
        assert_eq!(all(Xor::new(&once[..], b"key")).unwrap(), data);
        assert_eq!(all(Xor::new(&data[..], b"")).unwrap(), data);
    }
}
