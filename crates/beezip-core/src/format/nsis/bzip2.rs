//! NSIS's bzip2, decoded by BeeZip's own code (docs/M10.md §3.2). NSIS ships its own copy of
//! bzip2 with the parts an installer doesn't need taken out: there's no stream header, a block
//! starts with the byte `0x31` and the stream ends with `0x17` (each in the bit stream, where
//! bzip2 has 48-bit marks), and there are no CRCs and no randomised bit. The rest of a block is
//! bzip2's: the 24-bit origin pointer, the symbol map, the Huffman tables and selectors, then
//! the MTF and run-length coded block of up to 900 kB.
//!
//! It streams a block at a time: a block's symbols and links (3.6 MB at most) are the memory it
//! takes. Errors are `Corrupt`.

use std::io::{self, Read};

use crate::Error;

const MAX_BLOCK: usize = 900_000;
const INPUT: usize = 64 * 1024;
/// bzip2's limit on selectors.
const MAX_SELECTORS: usize = 18_002;

fn bad(message: &str) -> io::Error {
    Error::corrupt(format!("nsis: bzip2: {message}")).into_io()
}

/// One group's Huffman code, as bzip2 decodes it: by length, from the shortest.
struct Table {
    limit: [i32; 22],
    base: [i32; 22],
    perm: Vec<u16>,
    min: u32,
}

impl Table {
    fn new(lens: &[u8]) -> Self {
        let min = u32::from(lens.iter().copied().min().unwrap_or(1));
        let max = u32::from(lens.iter().copied().max().unwrap_or(1));
        let mut perm = Vec::with_capacity(lens.len());
        for l in min..=max {
            for (s, &x) in lens.iter().enumerate() {
                if u32::from(x) == l {
                    perm.push(s as u16);
                }
            }
        }
        let mut count = [0i32; 22];
        for &l in lens {
            count[usize::from(l)] += 1;
        }
        let mut limit = [i32::MAX; 22];
        let mut base = [0i32; 22];
        let (mut code, mut idx) = (0i32, 0i32);
        for l in min..=max {
            let l = l as usize;
            base[l] = idx - code;
            code += count[l];
            idx += count[l];
            limit[l] = code - 1;
            code <<= 1;
        }
        Self {
            limit,
            base,
            perm,
            min,
        }
    }
}

pub(super) struct Bzip2<R> {
    input: R,
    buf: Box<[u8]>,
    at: usize,
    end: usize,
    taken: u64,
    /// Bits, the next one highest.
    bits: u64,
    nbits: u32,
    /// The block: each entry's low 8 bits are its byte, the rest the next entry.
    tt: Vec<u32>,
    /// The next entry, and how many are left.
    next: usize,
    left: usize,
    /// The run-length state: the last byte, how many times running, and repeats still to give.
    last: Option<u8>,
    same: u32,
    repeat: (u8, u32),
    done: bool,
}

impl<R: Read> Bzip2<R> {
    pub(super) fn new(input: R) -> Self {
        Self {
            input,
            buf: vec![0; INPUT].into_boxed_slice(),
            at: 0,
            end: 0,
            taken: 0,
            bits: 0,
            nbits: 0,
            tt: Vec::new(),
            next: 0,
            left: 0,
            last: None,
            same: 0,
            repeat: (0, 0),
            done: false,
        }
    }

    /// The input bytes the stream took, up to its end mark.
    #[cfg(test)]
    pub(super) fn consumed(&self) -> u64 {
        self.taken - u64::from(self.nbits / 8)
    }

    pub(super) fn done(&self) -> bool {
        self.done && self.left == 0 && self.repeat.1 == 0
    }

    fn take(&mut self, n: u32) -> io::Result<u32> {
        while self.nbits < n {
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
                    return Err(bad("the stream ends inside a block"));
                }
            }
            self.bits = (self.bits << 8) | u64::from(self.buf[self.at]);
            self.at += 1;
            self.taken += 1;
            self.nbits += 8;
        }
        self.nbits -= n;
        Ok(((self.bits >> self.nbits) & ((1u64 << n) - 1)) as u32)
    }

    fn symbol(&mut self, t: &Table) -> io::Result<usize> {
        let mut len = t.min;
        let mut code = self.take(len)? as i32;
        loop {
            if len > 20 {
                return Err(bad("a code isn't in its table"));
            }
            if code <= t.limit[len as usize] {
                let i = code + t.base[len as usize];
                return usize::try_from(i)
                    .ok()
                    .and_then(|i| t.perm.get(i))
                    .map(|&s| usize::from(s))
                    .ok_or_else(|| bad("a code isn't in its table"));
            }
            code = (code << 1) | self.take(1)? as i32;
            len += 1;
        }
    }

    /// The next block into `tt`, or the end mark.
    fn block(&mut self) -> io::Result<()> {
        match self.take(8)? {
            0x17 => {
                self.done = true;
                return Ok(());
            }
            0x31 => {}
            _ => return Err(bad("a block doesn't start with its mark")),
        }
        let orig = self.take(24)? as usize;
        let used16 = self.take(16)?;
        let mut seq = Vec::with_capacity(256);
        for i in 0..16u32 {
            if used16 & (0x8000 >> i) != 0 {
                let m = self.take(16)?;
                for j in 0..16u32 {
                    if m & (0x8000 >> j) != 0 {
                        seq.push((i * 16 + j) as u8);
                    }
                }
            }
        }
        if seq.is_empty() {
            return Err(bad("a block uses no bytes"));
        }
        let alpha = seq.len() + 2;
        let groups = self.take(3)? as usize;
        if !(2..=6).contains(&groups) {
            return Err(bad("a block has a group count out of range"));
        }
        let nsel = self.take(15)? as usize;
        if nsel == 0 {
            return Err(bad("a block has no selectors"));
        }
        let mut mtf: Vec<u8> = (0..groups as u8).collect();
        let mut sels = Vec::with_capacity(nsel.min(MAX_SELECTORS));
        for _ in 0..nsel {
            let mut j = 0;
            while self.take(1)? == 1 {
                j += 1;
                if j >= groups {
                    return Err(bad("a selector is out of range"));
                }
            }
            let v = mtf.remove(j);
            mtf.insert(0, v);
            // bzip2 reads but ignores selectors past its limit.
            if sels.len() < MAX_SELECTORS {
                sels.push(v);
            }
        }
        let mut tables = Vec::with_capacity(groups);
        for _ in 0..groups {
            let mut len = self.take(5)? as i32;
            let mut lens = vec![0u8; alpha];
            for l in &mut lens {
                loop {
                    if !(1..=20).contains(&len) {
                        return Err(bad("a code length is out of range"));
                    }
                    if self.take(1)? == 0 {
                        break;
                    }
                    len += if self.take(1)? == 0 { 1 } else { -1 };
                }
                *l = len as u8;
            }
            tables.push(Table::new(&lens));
        }

        // The MTF and run-length coded symbols.
        let eob = alpha - 1;
        let mut order = seq;
        let mut counts = [0u32; 256];
        self.tt.clear();
        let (mut run, mut run_bit) = (0usize, 1usize);
        let (mut group, mut left) = (0usize, 0u32);
        let mut t = 0usize;
        loop {
            if left == 0 {
                t = usize::from(
                    *sels
                        .get(group)
                        .ok_or_else(|| bad("a block runs out of selectors"))?,
                );
                group += 1;
                left = 50;
            }
            left -= 1;
            let s = self.symbol(&tables[t])?;
            if s <= 1 {
                // RUNA and RUNB.
                run += run_bit << s;
                run_bit <<= 1;
                if run > MAX_BLOCK {
                    return Err(bad("a run is longer than a block"));
                }
                continue;
            }
            if run > 0 {
                let c = order[0];
                if self.tt.len() + run > MAX_BLOCK {
                    return Err(bad("a block is longer than 900 kB"));
                }
                counts[usize::from(c)] += run as u32;
                self.tt.extend(std::iter::repeat_n(u32::from(c), run));
                run = 0;
                run_bit = 1;
            }
            if s == eob {
                break;
            }
            let k = s - 1;
            if k >= order.len() {
                return Err(bad("an MTF index is out of range"));
            }
            let c = order.remove(k);
            order.insert(0, c);
            if self.tt.len() >= MAX_BLOCK {
                return Err(bad("a block is longer than 900 kB"));
            }
            counts[usize::from(c)] += 1;
            self.tt.push(u32::from(c));
        }
        let n = self.tt.len();
        if orig >= n {
            return Err(bad("a block's origin pointer is past its end"));
        }
        // The inverse BWT: each entry links to the next.
        let mut cum = [0u32; 256];
        let mut sum = 0;
        for (c, &k) in cum.iter_mut().zip(&counts) {
            *c = sum;
            sum += k;
        }
        for i in 0..n {
            let c = (self.tt[i] & 0xFF) as usize;
            let at = cum[c] as usize;
            self.tt[at] |= (i as u32) << 8;
            cum[c] += 1;
        }
        self.next = (self.tt[orig] >> 8) as usize;
        self.left = n;
        self.last = None;
        self.same = 0;
        Ok(())
    }
}

impl<R: Read> Read for Bzip2<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            if self.repeat.1 > 0 {
                let k = (buf.len() - n).min(self.repeat.1 as usize);
                buf[n..n + k].fill(self.repeat.0);
                n += k;
                self.repeat.1 -= k as u32;
                continue;
            }
            if self.left == 0 {
                if n > 0 || self.done {
                    break;
                }
                self.block()?;
                continue;
            }
            let e = self.tt[self.next];
            let c = e as u8;
            self.next = (e >> 8) as usize;
            self.left -= 1;
            if self.same == 4 {
                // A count of repeats after four equal bytes.
                self.repeat = (self.last.unwrap_or(0), u32::from(c));
                self.same = 0;
                self.last = None;
                continue;
            }
            if Some(c) == self.last {
                self.same += 1;
            } else {
                self.same = 1;
                self.last = Some(c);
            }
            buf[n] = c;
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream with one block holding `data` (no runs of four equal bytes, which bzip2 would
    /// code first), coded as simply as bzip2 allows: two tables of 9-bit codes.
    pub(crate) fn encode(data: &[u8]) -> Vec<u8> {
        struct W {
            out: Vec<u8>,
            acc: u64,
            n: u32,
        }
        impl W {
            fn put(&mut self, v: u32, bits: u32) {
                self.acc = (self.acc << bits) | u64::from(v);
                self.n += bits;
                while self.n >= 8 {
                    self.n -= 8;
                    self.out.push((self.acc >> self.n) as u8);
                }
            }
        }
        // The BWT, naively.
        let n = data.len();
        let mut rot: Vec<usize> = (0..n).collect();
        rot.sort_by(|&a, &b| {
            (0..n)
                .map(|k| data[(a + k) % n])
                .cmp((0..n).map(|k| data[(b + k) % n]))
        });
        let last: Vec<u8> = rot.iter().map(|&r| data[(r + n - 1) % n]).collect();
        let orig = rot.iter().position(|&r| r == 0).unwrap();
        let mut w = W {
            out: Vec::new(),
            acc: 0,
            n: 0,
        };
        w.put(0x31, 8);
        w.put(orig as u32, 24);
        // Every byte value used, so the MTF order is 0..=255.
        w.put(0xFFFF, 16);
        for _ in 0..16 {
            w.put(0xFFFF, 16);
        }
        let alpha = 256 + 2;
        // MTF symbols: index + 1, and runs of index 0 as RUNA (0) and RUNB (1) digits.
        let mut order: Vec<u8> = (0..=255).collect();
        let mut syms = Vec::new();
        let mut zeros = 0usize;
        let flush = |zeros: &mut usize, syms: &mut Vec<usize>| {
            let mut r = *zeros;
            while r > 0 {
                if r % 2 == 1 {
                    syms.push(0);
                    r = (r - 1) / 2;
                } else {
                    syms.push(1);
                    r = (r - 2) / 2;
                }
            }
            *zeros = 0;
        };
        for &c in &last {
            let k = order.iter().position(|&o| o == c).unwrap();
            order.remove(k);
            order.insert(0, c);
            if k == 0 {
                zeros += 1;
            } else {
                flush(&mut zeros, &mut syms);
                syms.push(k + 1);
            }
        }
        flush(&mut zeros, &mut syms);
        syms.push(alpha - 1);
        let groups = 2;
        let nsel = syms.len().div_ceil(50);
        w.put(groups, 3);
        w.put(nsel as u32, 15);
        for _ in 0..nsel {
            w.put(0, 1);
        }
        // Equal lengths: 9 bits for 258 symbols.
        for _ in 0..groups {
            w.put(9, 5);
            for _ in 0..alpha {
                w.put(0, 1);
            }
        }
        for &s in &syms {
            w.put(s as u32, 9);
        }
        w.put(0x17, 8);
        if w.n > 0 {
            let pad = 8 - w.n;
            w.put(0, pad);
        }
        w.out
    }

    fn decode(packed: &[u8]) -> io::Result<(Vec<u8>, u64)> {
        let mut r = Bzip2::new(packed);
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok((out, r.consumed()))
    }

    #[test]
    fn reads_a_block_without_runs() {
        let data = b"the bee comb holds the honey, and the bee holds the comb".to_vec();
        let packed = encode(&data);
        let (out, used) = decode(&packed).unwrap();
        assert_eq!(out, data);
        assert_eq!(used, packed.len() as u64);
    }

    #[test]
    fn damage_is_corrupt() {
        let packed = encode(b"some bytes to code, some bytes to code");
        for cut in [0, 1, 5, packed.len() / 2, packed.len() - 1] {
            let e = decode(&packed[..cut]).unwrap_err();
            assert_eq!(
                crate::io::read_error(&e).kind,
                crate::ErrorKind::Corrupt,
                "{cut}"
            );
        }
        let mut bad_mark = packed.clone();
        bad_mark[0] = 0x32;
        assert!(decode(&bad_mark).is_err());
        // A standard bzip2 stream isn't NSIS's.
        assert!(decode(b"BZh91AY&SY").is_err());
    }
}
