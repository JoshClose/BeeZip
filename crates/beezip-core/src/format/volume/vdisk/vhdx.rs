//! VHDX, from MS-VHDX (docs/M8.md §3.2), read only: the file is never written.
//!
//! - **Headers:** of the two 4 KiB headers whose signature and CRC-32C are right, the one with the
//!   larger sequence number is current; equal numbers are `Corrupt`. Version 1 only.
//! - **The log:** a current header whose LogGuid isn't zero has writes still to apply. The active
//!   sequence is found as MS-VHDX §2.3.3 says, wrapping round the log's end, and replayed into an
//!   overlay in memory ([`Overlay`]) that every later read of the file goes through. A log with no
//!   valid sequence, or a file shorter than its FlushedFileOffset, is `Corrupt`. Every file
//!   Hyper-V writes keeps stale entries in its log with LogGuid zero: those are never replayed.
//! - **Regions and metadata:** an unknown region or metadata item marked required is
//!   `UnsupportedOperation`, as MS-VHDX says to refuse it (7-Zip and Hyper-V refuse too); unknown
//!   optional ones are passed over.
//! - **Blocks** by their state in the block table: not present (zeros, or the parent's in a
//!   differencing disk), undefined, zero and unmapped (zeros, never the stale offset they may
//!   hold), fully present, and partially present (the sector bitmap, bit 0 of byte 0 first, marks
//!   the sectors this file holds; the parent has the rest). States 4 and 5, and a block in the
//!   header area, are `Corrupt`.
//! - **The parent** is looked for by its locator's `relative_path`, then `absolute_win32_path`, by
//!   [`Files`]' rules. It must be a VHDX whose DataWriteGuid is the child's `parent_linkage` (or
//!   `parent_linkage2`) and whose logical sectors are the child's size.
//! - **Refused** (`UnsupportedOperation`, so 7-Zip may try): a version other than 1, a log of a
//!   version other than 0 to replay, a log over 64 MiB, a block table over 2^23 entries, a parent
//!   locator of another type.
//! - **Blocks past the file's end** read as zeros, counted in Info, as M7 reads a truncated
//!   image.

use std::{cell::RefCell, collections::BTreeMap};

use super::{Files, Got, Handle, Layer, Origin, guid, le16, le32, le64, vhd::run_at};
use crate::{Error, Result};

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
/// The largest log replayed.
const MAX_LOG: u64 = 64 * MIB;
/// The most block table entries read: 64 MiB of table, 8 TiB of 1 MiB blocks.
const MAX_BAT: u64 = 1 << 23;
/// MS-VHDX's largest disk.
const MAX_SIZE: u64 = 64 << 40;
/// The largest metadata item read: MS-VHDX's limit.
const MAX_ITEM: u64 = MIB;
/// How many times its own length the log's entries may be checksummed while looking for the
/// active sequence: a valid log's entries don't overlap, so this is only reached by entries
/// crafted to overlap.
const CRC_PASSES: u64 = 4;

const fn g(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let (a, b, c) = (d1.to_le_bytes(), d2.to_le_bytes(), d3.to_le_bytes());
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

const BAT_REGION: [u8; 16] = g(
    0x2DC2_7766,
    0xF623,
    0x4200,
    [0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08],
);
const META_REGION: [u8; 16] = g(
    0x8B7C_A206,
    0x4790,
    0x4B9A,
    [0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E],
);
const FILE_PARAMS: [u8; 16] = g(
    0xCAA1_6737,
    0xFA36,
    0x4D43,
    [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B],
);
const DISK_SIZE: [u8; 16] = g(
    0x2FA5_4224,
    0xCD1B,
    0x4876,
    [0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8],
);
const DISK_ID: [u8; 16] = g(
    0xBECA_12AB,
    0xB2E6,
    0x4523,
    [0x93, 0xEF, 0xC3, 0x09, 0xE0, 0x00, 0xC7, 0x46],
);
const LOGICAL: [u8; 16] = g(
    0x8141_BF1D,
    0xA96F,
    0x4709,
    [0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F],
);
const PHYSICAL: [u8; 16] = g(
    0xCDA3_48C7,
    0x445D,
    0x4471,
    [0x9C, 0xC9, 0xE9, 0x88, 0x52, 0x51, 0xC5, 0x56],
);
const PARENT_LOCATOR: [u8; 16] = g(
    0xA8D3_5F2D,
    0xB30B,
    0x454D,
    [0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C],
);
const LOCATOR_VHDX: [u8; 16] = g(
    0xB04A_EFB7,
    0xD19E,
    0x4A81,
    [0xB7, 0x89, 0x25, 0xB8, 0xE9, 0x44, 0x59, 0x13],
);

/// Block table states.
const NOT_PRESENT: u64 = 0;
const FULLY_PRESENT: u64 = 6;
const PARTIALLY_PRESENT: u64 = 7;

fn array<const N: usize>(b: &[u8]) -> [u8; N] {
    b.try_into().unwrap_or([0; N])
}

/// The CRC-32C of `b` with its 4-byte checksum at `at` taken as zero, as VHDX checksums its
/// headers, region tables and log entries.
fn crc_with_hole(b: &[u8], at: usize) -> u32 {
    let c = fstool::crc::crc32c_append(0, &b[..at]);
    let c = fstool::crc::crc32c_append(c, &[0; 4]);
    fstool::crc::crc32c_append(c, &b[at + 4..])
}

/// An extent the log wrote: its length, and its bytes (`None`: zeros).
type Extent = (u64, Option<Box<[u8]>>);

/// The log's writes, by file offset: extents that don't overlap, of zeros or of bytes.
#[derive(Default)]
pub struct Overlay {
    map: BTreeMap<u64, Extent>,
}

impl Overlay {
    /// `len` bytes at `start` become `data` (zeros when `None`, else `len` bytes), over whatever
    /// the log wrote there before.
    fn put(&mut self, start: u64, len: u64, data: Option<Box<[u8]>>) {
        let end = start.saturating_add(len);
        if start >= end {
            return;
        }
        // The extents that overlap `start..end`: the one before `start`, and those inside.
        let hit: Vec<u64> = self
            .map
            .range(..end)
            .rev()
            .take_while(|(s, (l, _))| s.saturating_add(*l) > start)
            .map(|(s, _)| *s)
            .collect();
        for s in hit {
            let Some((l, d)) = self.map.remove(&s) else {
                continue;
            };
            let e = s.saturating_add(l);
            let part = |from: u64, to: u64| -> Option<Box<[u8]>> {
                let (a, b) = (
                    usize::try_from(from - s).ok()?,
                    usize::try_from(to - s).ok()?,
                );
                d.as_ref().and_then(|d| d.get(a..b)).map(Box::from)
            };
            if s < start {
                let keep = part(s, start);
                self.map
                    .insert(s, (start - s, if d.is_some() { keep } else { None }));
            }
            if e > end {
                let keep = part(end, e);
                self.map
                    .insert(end, (e - end, if d.is_some() { keep } else { None }));
            }
        }
        self.map.insert(start, (end - start, data));
    }

    /// Patches `buf`, the file's bytes at `off`, with what the log wrote there.
    fn apply(&self, off: u64, buf: &mut [u8]) {
        if self.map.is_empty() || buf.is_empty() {
            return;
        }
        let end = off.saturating_add(buf.len() as u64);
        let first = self.map.range(..=off).next_back().map_or(off, |(s, _)| *s);
        for (&s, (l, d)) in self.map.range(first..end) {
            let (a, b) = (s.max(off), s.saturating_add(*l).min(end));
            if a >= b {
                continue;
            }
            let (Ok(da), Ok(db)) = (usize::try_from(a - off), usize::try_from(b - off)) else {
                continue;
            };
            let dst = &mut buf[da..db];
            match d {
                None => dst.fill(0),
                Some(d) => {
                    let (Ok(sa), Ok(sb)) = (usize::try_from(a - s), usize::try_from(b - s)) else {
                        continue;
                    };
                    match d.get(sa..sb) {
                        Some(src) => dst.copy_from_slice(src),
                        None => dst.fill(0),
                    }
                }
            }
        }
    }

    /// Bytes of `start..end` the log wrote data (not zeros) to.
    fn data_in(&self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        let first = self
            .map
            .range(..=start)
            .next_back()
            .map_or(start, |(s, _)| *s);
        self.map
            .range(first..end)
            .filter(|(_, (_, d))| d.is_some())
            .map(|(&s, (l, _))| s.saturating_add(*l).min(end).saturating_sub(s.max(start)))
            .sum()
    }
}

/// The file as its log leaves it: the replayed writes over its bytes, and zeros past its end.
struct Image {
    src: Handle,
    overlay: Overlay,
    /// Where the log says the file ends, at least its length.
    end: u64,
}

impl Image {
    /// `buf.len()` bytes at `at`; past the file's end (a file cut short), zeros.
    fn read_at(&mut self, at: u64, buf: &mut [u8], what: &str) -> Result<()> {
        if at.checked_add(buf.len() as u64).is_none() {
            return Err(Error::corrupt(format!(
                "{what}: {} bytes at {at} overflow",
                buf.len()
            )));
        }
        let real = usize::try_from(self.src.len.saturating_sub(at))
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if real > 0 {
            self.src.read_exact_at(at, &mut buf[..real], what)?;
        }
        buf[real..].fill(0);
        self.overlay.apply(at, buf);
        Ok(())
    }

    /// `n` bytes at `at`, which the file must hold, in a new buffer of at most `cap` bytes.
    fn read_vec(&mut self, at: u64, n: u64, cap: u64, what: &str) -> Result<Vec<u8>> {
        if at.checked_add(n).is_none_or(|e| e > self.src.len) {
            return Err(Error::corrupt(format!(
                "{what}: {n} bytes at {at} reach past the file's end ({} bytes)",
                self.src.len
            )));
        }
        let mut v = super::alloc(n, cap, what)?;
        self.read_at(at, &mut v, what)?;
        Ok(v)
    }

    /// Bytes of `n` at `at` the file holds: before its end, or written by the log.
    fn holds(&self, at: u64, n: u64) -> u64 {
        let end = at.saturating_add(n);
        let before = end.min(self.src.len).saturating_sub(at);
        before + self.overlay.data_in(at.max(self.src.len), end)
    }
}

/// A header whose signature and checksum are right.
struct Header {
    seq: u64,
    data_write: [u8; 16],
    log_guid: [u8; 16],
    log_version: u16,
    version: u16,
    log_len: u32,
    log_off: u64,
}

fn header(b: &[u8]) -> Option<Header> {
    if b.len() < 4096 || &b[..4] != b"head" || crc_with_hole(&b[..4096], 4) != le32(b, 4) {
        return None;
    }
    Some(Header {
        seq: le64(b, 8),
        data_write: array(&b[32..48]),
        log_guid: array(&b[48..64]),
        log_version: le16(b, 64),
        version: le16(b, 66),
        log_len: le32(b, 68),
        log_off: le64(b, 72),
    })
}

/// The current header (see the module's notes).
fn current_header(file: &mut Handle) -> Result<Header> {
    let mut b = vec![0u8; 4096];
    file.read_exact_at(64 * KIB, &mut b, "vhdx: the first header")?;
    let h1 = header(&b);
    file.read_exact_at(128 * KIB, &mut b, "vhdx: the second header")?;
    let h2 = header(&b);
    match (h1, h2) {
        (Some(a), Some(b)) if a.seq == b.seq => Err(Error::corrupt(
            "vhdx: both headers have the same sequence number",
        )),
        (Some(a), Some(b)) => Ok(if a.seq > b.seq { a } else { b }),
        (Some(a), None) | (None, Some(a)) => Ok(a),
        (None, None) => Err(Error::corrupt("vhdx: neither header is valid")),
    }
}

/// What the sequence search needs of a valid log entry.
#[derive(Clone, Copy)]
struct Summary {
    len: u64,
    tail: u64,
    seq: u64,
    flushed: u64,
    last: u64,
    count: u64,
}

/// The log, read whole, with what's been learned of each 4 KiB sector of it as an entry's start.
struct Log {
    buf: Vec<u8>,
    guid: [u8; 16],
    entries: Vec<Option<Option<Summary>>>,
    /// Bytes still to checksum (see [`CRC_PASSES`]).
    budget: u64,
}

impl Log {
    fn len(&self) -> u64 {
        self.buf.len() as u64
    }

    /// The 4 KiB sector `k` sectors after offset `at`, wrapping round the log's end.
    fn sector(&self, at: u64, k: u64) -> &[u8] {
        let o = usize::try_from((at + k * 4096) % self.len()).unwrap_or(0);
        self.buf.get(o..o + 4096).unwrap_or(&[0; 4096])
    }

    /// Descriptor `i` of the entry at `at`: 32 bytes, from 64 bytes into it.
    fn descriptor(&self, at: u64, i: u64) -> &[u8] {
        let pos = 64 + 32 * i;
        let off = usize::try_from(pos % 4096).unwrap_or(0);
        &self.sector(at, pos / 4096)[off..off + 32]
    }

    /// The entry at `at`, if it's valid (MS-VHDX §2.3.1), learned once.
    fn entry(&mut self, at: u64) -> Result<Option<Summary>> {
        let k = usize::try_from(at / 4096).unwrap_or(usize::MAX);
        if let Some(Some(known)) = self.entries.get(k) {
            return Ok(*known);
        }
        let e = self.check(at)?;
        if let Some(slot) = self.entries.get_mut(k) {
            *slot = Some(e);
        }
        Ok(e)
    }

    fn check(&mut self, at: u64) -> Result<Option<Summary>> {
        let n = self.len();
        let first: [u8; 64] = array(&self.sector(at, 0)[..64]);
        if &first[..4] != b"loge" {
            return Ok(None);
        }
        let s = Summary {
            len: u64::from(le32(&first, 8)),
            tail: u64::from(le32(&first, 12)),
            seq: le64(&first, 16),
            count: u64::from(le32(&first, 24)),
            flushed: le64(&first, 48),
            last: le64(&first, 56),
        };
        if s.len == 0
            || !s.len.is_multiple_of(4096)
            || s.len > n
            || !s.tail.is_multiple_of(4096)
            || s.tail >= n
            || s.seq == 0
            || first[32..48] != self.guid
            || !s.flushed.is_multiple_of(MIB)
            || !s.last.is_multiple_of(MIB)
        {
            return Ok(None);
        }
        let desc_sectors = (64 + 32 * s.count).div_ceil(4096);
        if desc_sectors * 4096 > s.len {
            return Ok(None);
        }
        // Each descriptor and data sector, before the checksum over the whole entry.
        let mut data = 0u64;
        for i in 0..s.count {
            let d = self.descriptor(at, i);
            if le64(d, 24) != s.seq {
                return Ok(None);
            }
            match &d[..4] {
                b"zero" => {
                    if !le64(d, 8).is_multiple_of(4096) || !le64(d, 16).is_multiple_of(4096) {
                        return Ok(None);
                    }
                }
                b"desc" => {
                    let k = desc_sectors + data;
                    if !le64(d, 16).is_multiple_of(4096) || (k + 1) * 4096 > s.len {
                        return Ok(None);
                    }
                    let sec = self.sector(at, k);
                    if &sec[..4] != b"data"
                        || u64::from(le32(sec, 4)) != s.seq >> 32
                        || u64::from(le32(sec, 4092)) != s.seq & 0xFFFF_FFFF
                    {
                        return Ok(None);
                    }
                    data += 1;
                }
                _ => return Ok(None),
            }
        }
        if self.budget < s.len {
            return Err(Error::corrupt(
                "vhdx: the log's entries overlap more than any log is written",
            ));
        }
        self.budget -= s.len;
        let mut c = crc_with_hole(self.sector(at, 0), 4);
        for k in 1..s.len / 4096 {
            c = fstool::crc::crc32c_append(c, self.sector(at, k));
        }
        Ok((c == le32(&first, 4)).then_some(s))
    }

    /// The offsets of the active sequence's entries, oldest first (MS-VHDX §2.3.3), and its
    /// newest entry.
    fn active(&mut self) -> Result<Option<(Vec<u64>, Summary)>> {
        let n = self.len();
        let sectors = n / 4096;
        let mut best: Option<(Vec<u64>, Summary)> = None;
        let (mut tail, mut old_tail) = (0u64, 0u64);
        for _ in 0..=sectors {
            // The sequence of entries from `tail`, each numbered one more than the last.
            let mut offs: Vec<u64> = Vec::new();
            let mut head: Option<Summary> = None;
            let mut at = tail;
            while (offs.len() as u64) < sectors {
                let Some(e) = self.entry(at)? else {
                    break;
                };
                if head.is_some_and(|h| e.seq != h.seq.wrapping_add(1)) {
                    break;
                }
                offs.push(at);
                head = Some(e);
                at = (at + e.len) % n;
            }
            // Valid when the newest entry's tail is in it.
            let start = head.and_then(|h| offs.iter().position(|&o| o == h.tail));
            match (head, start) {
                (Some(h), Some(i)) => {
                    if best.as_ref().is_none_or(|(_, b)| h.seq > b.seq) {
                        best = Some((offs[i..].to_vec(), h));
                    }
                    tail = at;
                }
                _ => tail = (tail + 4096) % n,
            }
            // Past the log's end, or back where it began (a sequence round the whole log): every
            // place has been tried.
            if tail <= old_tail {
                break;
            }
            old_tail = tail;
        }
        Ok(best)
    }

    /// Replays the entries at `offs`, checked by [`Log::check`], into `ov`, in order.
    fn replay(&self, offs: &[u64], ov: &mut Overlay) {
        for &at in offs {
            let count = u64::from(le32(self.sector(at, 0), 24));
            let desc_sectors = (64 + 32 * count).div_ceil(4096);
            let mut data = 0u64;
            for i in 0..count {
                let d = self.descriptor(at, i);
                if &d[..4] == b"zero" {
                    ov.put(le64(d, 16), le64(d, 8), None);
                    continue;
                }
                let sec = self.sector(at, desc_sectors + data);
                let mut page = vec![0u8; 4096];
                page[..8].copy_from_slice(&d[8..16]);
                page[8..4092].copy_from_slice(&sec[8..4092]);
                page[4092..].copy_from_slice(&d[4..8]);
                ov.put(le64(d, 16), 4096, Some(page.into_boxed_slice()));
                data += 1;
            }
        }
    }
}

/// The log of `h` replayed into an overlay (see the module's notes): the overlay, where the file
/// then ends, and how many entries were replayed.
fn replay(src: &mut Handle, h: &Header) -> Result<(Overlay, u64, usize)> {
    let (len, off) = (u64::from(h.log_len), h.log_off);
    if len == 0 || !len.is_multiple_of(MIB) || !off.is_multiple_of(MIB) || off < MIB {
        return Err(Error::corrupt(format!(
            "vhdx: the log is misplaced ({len} bytes at {off})"
        )));
    }
    if len > MAX_LOG {
        return Err(Error::unsupported(format!(
            "vhdx: a log of {len} bytes to replay; BeeZip replays them up to {MAX_LOG}"
        )));
    }
    let buf = src.read_vec(off, len, MAX_LOG, "vhdx: the log")?;
    let mut log = Log {
        entries: vec![None; usize::try_from(len / 4096).unwrap_or(0)],
        buf,
        guid: h.log_guid,
        budget: len.saturating_mul(CRC_PASSES),
    };
    let Some((offs, head)) = log.active()? else {
        return Err(Error::corrupt(
            "vhdx: the log has no valid sequence to replay",
        ));
    };
    if src.len < head.flushed {
        return Err(Error::corrupt(format!(
            "vhdx: the file is cut short: {} bytes, where its log says it has at least {}",
            src.len, head.flushed
        )));
    }
    let mut ov = Overlay::default();
    log.replay(&offs, &mut ov);
    Ok((ov, src.len.max(head.last), offs.len()))
}

/// A differencing disk's parent locator: the names its parent is recorded by, and its identity.
#[derive(Clone)]
struct Locator {
    linkage: String,
    linkage2: Option<String>,
    relative: Option<String>,
    absolute: Option<String>,
}

/// A GUID as written in a locator, or by [`guid`], without braces, in lowercase.
fn plain(g: &str) -> String {
    g.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_lowercase()
}

fn locator(item: &[u8]) -> Result<Locator> {
    if item.len() < 20 {
        return Err(Error::corrupt("vhdx: the parent locator is cut short"));
    }
    if item[..16] != LOCATOR_VHDX {
        return Err(Error::unsupported(format!(
            "vhdx: a parent locator of type {}; BeeZip follows a VHDX's",
            guid(&array(&item[..16]))
        )));
    }
    let count = usize::from(le16(item, 18));
    if 20 + 12 * count > item.len() {
        return Err(Error::corrupt(
            "vhdx: the parent locator's entries run past it",
        ));
    }
    let mut entries: Vec<(String, String)> = Vec::new();
    for i in 0..count {
        let e = &item[20 + 12 * i..32 + 12 * i];
        let (ko, vo) = (le32(e, 0) as usize, le32(e, 4) as usize);
        let (kl, vl) = (usize::from(le16(e, 8)), usize::from(le16(e, 10)));
        let text = |o: usize, l: usize| -> Result<String> {
            let units: Vec<u16> = o
                .checked_add(l)
                .filter(|_| l.is_multiple_of(2))
                .and_then(|end| item.get(o..end))
                .ok_or_else(|| Error::corrupt("vhdx: a parent locator entry is malformed"))?
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16(&units)
                .map_err(|_| Error::corrupt("vhdx: a parent locator entry isn't UTF-16"))
        };
        let (k, v) = (text(ko, kl)?, text(vo, vl)?);
        if entries.iter().any(|(key, _)| *key == k) {
            return Err(Error::corrupt(format!(
                "vhdx: the parent locator names `{k}` twice"
            )));
        }
        entries.push((k, v));
    }
    let get = |k: &str| {
        entries
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.trim().is_empty())
    };
    let linkage = get("parent_linkage")
        .ok_or_else(|| Error::corrupt("vhdx: the parent locator has no parent_linkage"))?;
    Ok(Locator {
        linkage,
        linkage2: get("parent_linkage2"),
        relative: get("relative_path"),
        absolute: get("absolute_win32_path"),
    })
}

/// One VHDX file.
pub struct Vhdx {
    /// The file through its log, in a cell so that [`Layer::held_in`] can read sector bitmaps.
    file: RefCell<Image>,
    name: String,
    creator: String,
    size: u64,
    sector: u32,
    physical: u32,
    block: u64,
    /// Data blocks per sector bitmap block.
    chunk: u64,
    disk_id: [u8; 16],
    fixed: bool,
    parent: Option<Locator>,
    bat: Vec<u64>,
    past_end: u64,
    /// How many log entries were replayed, if any.
    replayed: Option<usize>,
    /// The last block's sector bitmap read.
    bitmap: Option<(u64, Vec<u8>)>,
}

impl Vhdx {
    /// Opens the VHDX `file` is (named `name`), its log replayed in memory.
    fn open(mut src: Handle, name: &str) -> Result<Self> {
        if src.len < 320 * KIB {
            return Err(Error::corrupt(
                "vhdx: the file is too short for its headers",
            ));
        }
        let mut ident = [0u8; 520];
        src.read_exact_at(0, &mut ident, "vhdx: the file identifier")?;
        if &ident[..8] != b"vhdxfile" {
            return Err(Error::corrupt("vhdx: no file identifier"));
        }
        let units: Vec<u16> = ident[8..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect();
        let creator = String::from_utf16_lossy(&units);
        let header = current_header(&mut src)?;
        if header.version != 1 {
            return Err(Error::unsupported(format!(
                "vhdx: version {}; BeeZip reads version 1",
                header.version
            )));
        }
        let (overlay, end, replayed) = if header.log_guid == [0; 16] {
            (Overlay::default(), src.len, None)
        } else {
            if header.log_version != 0 {
                return Err(Error::unsupported(format!(
                    "vhdx: a log of version {} to replay; BeeZip replays version 0",
                    header.log_version
                )));
            }
            let (ov, end, n) = replay(&mut src, &header)?;
            (ov, end, Some(n))
        };
        let mut file = Image { src, overlay, end };

        // The region table: the first copy that checks out.
        let mut table = None;
        for at in [192 * KIB, 256 * KIB] {
            let t = file.read_vec(at, 64 * KIB, 64 * KIB, "vhdx: a region table")?;
            if &t[..4] == b"regi" && crc_with_hole(&t, 4) == le32(&t, 4) && le32(&t, 8) <= 2047 {
                table = Some(t);
                break;
            }
        }
        let rt = table.ok_or_else(|| Error::corrupt("vhdx: neither region table is valid"))?;
        let (mut bat_r, mut meta_r) = (None, None);
        for i in 0..le32(&rt, 8) as usize {
            let e = &rt[16 + 32 * i..48 + 32 * i];
            let (off, len, required) = (le64(e, 16), u64::from(le32(e, 24)), le32(e, 28) & 1 == 1);
            let slot = if e[..16] == BAT_REGION {
                &mut bat_r
            } else if e[..16] == META_REGION {
                &mut meta_r
            } else if required {
                return Err(Error::unsupported(format!(
                    "vhdx: a region BeeZip doesn't know, marked required ({})",
                    guid(&array(&e[..16]))
                )));
            } else {
                continue;
            };
            if !off.is_multiple_of(MIB)
                || off < MIB
                || !len.is_multiple_of(MIB)
                || len == 0
                || slot.is_some()
            {
                return Err(Error::corrupt("vhdx: a malformed region table entry"));
            }
            *slot = Some((off, len));
        }
        let ((bat_off, bat_len), (meta_off, meta_len)) = bat_r.zip(meta_r).ok_or_else(|| {
            Error::corrupt("vhdx: the region table lacks the block table or the metadata")
        })?;

        // The metadata.
        let mt = file.read_vec(meta_off, 64 * KIB, 64 * KIB, "vhdx: the metadata table")?;
        if &mt[..8] != b"metadata" || le16(&mt, 10) > 2047 {
            return Err(Error::corrupt("vhdx: the metadata table is malformed"));
        }
        let mut items: Vec<([u8; 16], Vec<u8>)> = Vec::new();
        for i in 0..usize::from(le16(&mt, 10)) {
            let e = &mt[32 + 32 * i..64 + 32 * i];
            let id: [u8; 16] = array(&e[..16]);
            let (off, len, flags) = (u64::from(le32(e, 16)), u64::from(le32(e, 20)), le32(e, 24));
            let (user, required) = (flags & 1 == 1, flags & 4 == 4);
            let known = !user
                && [
                    FILE_PARAMS,
                    DISK_SIZE,
                    DISK_ID,
                    LOGICAL,
                    PHYSICAL,
                    PARENT_LOCATOR,
                ]
                .contains(&id);
            if !known {
                if required {
                    return Err(Error::unsupported(format!(
                        "vhdx: a metadata item BeeZip doesn't know, marked required ({})",
                        guid(&id)
                    )));
                }
                continue;
            }
            if len > MAX_ITEM || (len > 0 && (off < 64 * KIB || off + len > meta_len)) {
                return Err(Error::corrupt(format!(
                    "vhdx: metadata item {} is misplaced",
                    guid(&id)
                )));
            }
            if items.iter().any(|(k, _)| *k == id) {
                return Err(Error::corrupt(format!(
                    "vhdx: metadata item {} is there twice",
                    guid(&id)
                )));
            }
            let v = if len == 0 {
                Vec::new()
            } else {
                file.read_vec(meta_off + off, len, MAX_ITEM, "vhdx: a metadata item")?
            };
            items.push((id, v));
        }
        let item = |id: &[u8; 16], min: usize, what: &str| -> Result<&[u8]> {
            items
                .iter()
                .find(|(k, v)| k == id && v.len() >= min)
                .map(|(_, v)| v.as_slice())
                .ok_or_else(|| Error::corrupt(format!("vhdx: the metadata has no {what}")))
        };
        let fp = item(&FILE_PARAMS, 8, "file parameters")?;
        let (block, fp_flags) = (u64::from(le32(fp, 0)), le32(fp, 4));
        let (fixed, has_parent) = (fp_flags & 1 == 1, fp_flags & 2 == 2);
        let size = le64(item(&DISK_SIZE, 8, "virtual disk size")?, 0);
        let sector = le32(item(&LOGICAL, 4, "logical sector size")?, 0);
        let physical = le32(item(&PHYSICAL, 4, "physical sector size")?, 0);
        let disk_id: [u8; 16] = array(&item(&DISK_ID, 16, "virtual disk id")?[..16]);
        if !block.is_power_of_two() || !(MIB..=256 * MIB).contains(&block) {
            return Err(Error::corrupt(format!("vhdx: blocks of {block} bytes")));
        }
        if sector != 512 && sector != 4096 {
            return Err(Error::corrupt(format!(
                "vhdx: logical sectors of {sector} bytes"
            )));
        }
        if size == 0 || !size.is_multiple_of(u64::from(sector)) || size > MAX_SIZE {
            return Err(Error::corrupt(format!("vhdx: a disk of {size} bytes")));
        }
        let parent = if has_parent {
            Some(locator(item(&PARENT_LOCATOR, 0, "parent locator")?)?)
        } else {
            None
        };

        // The block table.
        let chunk = (1u64 << 23) * u64::from(sector) / block;
        let blocks = size.div_ceil(block);
        let bitmaps = blocks.div_ceil(chunk);
        let needed = if has_parent {
            bitmaps * (chunk + 1)
        } else {
            blocks + (blocks - 1) / chunk
        };
        if needed > MAX_BAT {
            return Err(Error::unsupported(format!(
                "vhdx: a block table of {needed} entries; BeeZip reads up to {MAX_BAT}"
            )));
        }
        if needed * 8 > bat_len {
            return Err(Error::corrupt(
                "vhdx: the block table is too small for the disk",
            ));
        }
        let raw = file.read_vec(bat_off, needed * 8, MAX_BAT * 8, "vhdx: the block table")?;
        let bat: Vec<u64> = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect();
        let at = |i: u64| bat.get(usize::try_from(i).unwrap_or(usize::MAX)).copied();
        let mut past_end = 0u64;
        let beyond = |off: u64, len: u64| off.checked_add(len).is_none_or(|x| x > file.end);
        for b in 0..blocks {
            let e = at(b + b / chunk).unwrap_or(0);
            match e & 7 {
                0..=3 => {}
                s @ (FULLY_PRESENT | PARTIALLY_PRESENT) => {
                    if s == PARTIALLY_PRESENT && !has_parent {
                        return Err(Error::corrupt(format!(
                            "vhdx: block {b} is partially present in a disk with no parent"
                        )));
                    }
                    let off = (e >> 20) * MIB;
                    if off < MIB {
                        return Err(Error::corrupt(format!(
                            "vhdx: block {b} lies in the header area"
                        )));
                    }
                    if beyond(off, block) {
                        past_end += 1;
                    }
                    if s == PARTIALLY_PRESENT {
                        let m = at((b / chunk) * (chunk + 1) + chunk).unwrap_or(0);
                        if m & 7 != FULLY_PRESENT {
                            return Err(Error::corrupt(format!(
                                "vhdx: block {b} is partially present without its sector bitmap"
                            )));
                        }
                    }
                }
                s => {
                    return Err(Error::corrupt(format!(
                        "vhdx: block {b} has the reserved state {s}"
                    )));
                }
            }
        }
        if has_parent {
            for c in 0..bitmaps {
                let e = at(c * (chunk + 1) + chunk).unwrap_or(0);
                match e & 7 {
                    NOT_PRESENT => {}
                    FULLY_PRESENT => {
                        let off = (e >> 20) * MIB;
                        if off < MIB {
                            return Err(Error::corrupt(format!(
                                "vhdx: sector bitmap {c} lies in the header area"
                            )));
                        }
                        if beyond(off, MIB) {
                            past_end += 1;
                        }
                    }
                    s => {
                        return Err(Error::corrupt(format!(
                            "vhdx: sector bitmap {c} has the state {s}"
                        )));
                    }
                }
            }
        }
        Ok(Self {
            file: RefCell::new(file),
            name: name.to_owned(),
            creator,
            size,
            sector,
            physical,
            block,
            chunk,
            disk_id,
            fixed,
            parent,
            bat,
            past_end,
            replayed,
            bitmap: None,
        })
    }

    /// Block `b`'s entry in the block table.
    fn entry(&self, b: u64) -> Result<u64> {
        b.checked_add(b / self.chunk)
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| self.bat.get(i))
            .copied()
            .ok_or_else(|| Error::corrupt("vhdx: a read past the block table"))
    }

    /// Where block `b`'s bits are in its sector bitmap block, and how many bytes they take.
    fn bitmap_at(&self, b: u64) -> (u64, usize) {
        let per = self.block / u64::from(self.sector) / 8;
        let i = (b / self.chunk) * (self.chunk + 1) + self.chunk;
        let e = usize::try_from(i)
            .ok()
            .and_then(|i| self.bat.get(i))
            .copied()
            .unwrap_or(0);
        (
            (e >> 20) * MIB + (b % self.chunk) * per,
            usize::try_from(per).unwrap_or(0),
        )
    }

    /// Loads block `b`'s sector bitmap.
    fn load_bitmap(&mut self, b: u64) -> Result<()> {
        if self.bitmap.as_ref().is_some_and(|(k, _)| *k == b) {
            return Ok(());
        }
        let (at, n) = self.bitmap_at(b);
        let mut v = self.bitmap.take().map(|(_, v)| v).unwrap_or_default();
        v.resize(n, 0);
        self.file
            .get_mut()
            .read_at(at, &mut v, "vhdx: a sector bitmap")?;
        self.bitmap = Some((b, v));
        Ok(())
    }

    /// Bytes of `a..z` (offsets in partially present block `b`, at `base` in the file) its
    /// bitmap marks as this file's and the file holds; on a failed read, every byte the file
    /// holds (high, never low).
    fn present_in(&self, b: u64, base: u64, a: u64, z: u64) -> u64 {
        let Ok(mut file) = self.file.try_borrow_mut() else {
            return z - a;
        };
        let (at, n) = self.bitmap_at(b);
        let mut bits = vec![0u8; n];
        if file
            .read_at(at, &mut bits, "vhdx: a sector bitmap")
            .is_err()
        {
            return file.holds(base.saturating_add(a), z - a);
        }
        let mut held = 0;
        super::vhd::present_runs(&bits, false, u64::from(self.sector), a, z, |s, len| {
            held += file.holds(base.saturating_add(s), len);
        });
        held
    }

    fn method(&self) -> &'static str {
        if self.parent.is_some() {
            "Differencing"
        } else if self.fixed {
            "Fixed"
        } else {
            "Dynamic"
        }
    }
}

/// A GUID without its braces, as Windows shows a disk's.
fn show(id: &[u8; 16]) -> String {
    plain(&guid(id))
}

impl Layer for Vhdx {
    fn len(&self) -> u64 {
        self.size
    }

    fn sector(&self) -> u32 {
        self.sector
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)> {
        let (b, within) = (off / self.block, off % self.block);
        let n = buf
            .len()
            .min(usize::try_from(self.block - within).unwrap_or(usize::MAX));
        let e = self.entry(b)?;
        let base = (e >> 20) * MIB;
        match e & 7 {
            FULLY_PRESENT => {
                self.file.get_mut().read_at(
                    base.saturating_add(within),
                    &mut buf[..n],
                    "vhdx: a block",
                )?;
                Ok((n, Got::Data))
            }
            PARTIALLY_PRESENT => {
                self.load_bitmap(b)?;
                let bits = self.bitmap.as_ref().map_or(&[][..], |(_, v)| v.as_slice());
                let sector = u64::from(self.sector);
                let (marked, stop) = run_at(bits, false, sector, within, within + n as u64);
                let m = usize::try_from(stop - within).unwrap_or(n).clamp(1, n);
                if marked {
                    self.file.get_mut().read_at(
                        base.saturating_add(within),
                        &mut buf[..m],
                        "vhdx: a block",
                    )?;
                    Ok((m, Got::Data))
                } else {
                    Ok((m, Got::Hole))
                }
            }
            NOT_PRESENT if self.parent.is_some() => Ok((n, Got::Hole)),
            // Not present without a parent, undefined, zero, unmapped.
            0..=3 => Ok((n, Got::Zero)),
            s => Err(Error::corrupt(format!(
                "vhdx: block {b} has the reserved state {s}"
            ))),
        }
    }

    fn held_in(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len).min(self.size);
        if start >= end {
            return 0;
        }
        let (first, last) = (start / self.block, (end - 1) / self.block);
        let mut held = 0u64;
        for b in first..=last {
            let Ok(e) = self.entry(b) else {
                break;
            };
            let state = e & 7;
            if state != FULLY_PRESENT && state != PARTIALLY_PRESENT {
                continue;
            }
            let at = b * self.block;
            let (a, z) = (start.max(at) - at, end.min(at + self.block) - at);
            let base = (e >> 20) * MIB;
            held += if state == FULLY_PRESENT {
                self.file
                    .try_borrow()
                    .map_or(z - a, |f| f.holds(base.saturating_add(a), z - a))
            } else {
                self.present_in(b, base, a, z)
            };
        }
        held
    }

    fn file_bytes(&self) -> u64 {
        self.file.try_borrow().map_or(0, |f| f.src.len)
    }

    fn properties(&self, out: &mut Vec<(&'static str, String)>) {
        out.push(("Method", self.method().into()));
        out.push(("Cluster Size", self.block.to_string()));
        out.push(("Sector Size", self.sector.to_string()));
        out.push(("Physical Sector Size", self.physical.to_string()));
        out.push(("Creator Application", self.creator.clone()));
        out.push(("ID", show(&self.disk_id)));
        if let Some(p) = &self.parent {
            out.push(("Parent Linkage", plain(&p.linkage)));
        }
        if let Some(n) = self.replayed {
            out.push(("Log", format!("replayed in memory: {n} entries")));
        }
    }

    fn notes(&self, out: &mut Vec<String>) {
        if let Some(n) = self.replayed {
            out.push(format!(
                "vhdx: {}'s log had {n} entries still to apply: they were replayed in memory, and \
                 the file wasn't changed",
                self.name
            ));
        }
        if self.past_end > 0 {
            out.push(format!(
                "vhdx: {} of {}'s blocks lie past its end and read as zeros",
                self.past_end, self.name
            ));
        }
    }
}

/// A candidate parent's DataWriteGuid, from its headers alone; `Err` why it isn't a VHDX.
fn data_write_guid(file: &mut Handle) -> Result<std::result::Result<[u8; 16], String>> {
    let mut sig = [0u8; 8];
    if file.len < 320 * KIB {
        return Ok(Err("it's too short to be a VHDX".into()));
    }
    file.read_exact_at(0, &mut sig, "the parent disk's signature")?;
    if &sig != b"vhdxfile" {
        return Ok(Err(
            "it isn't a VHDX, and a VHDX's parent must be one".into()
        ));
    }
    match current_header(file) {
        Ok(h) => Ok(Ok(h.data_write)),
        Err(e) => Ok(Err(e.message)),
    }
}

/// The levels of the VHDX `file` is, its parents' below it.
pub fn layers(file: Handle, origin: Origin, files: &mut Files) -> Result<Vec<Box<dyn Layer>>> {
    let v = Vhdx::open(file, &origin.name)?;
    chain(v, origin, files)
}

/// `v`'s level, and its parents' below it.
fn chain(v: Vhdx, origin: Origin, files: &mut Files) -> Result<Vec<Box<dyn Layer>>> {
    let Some(loc) = v.parent.clone() else {
        return Ok(vec![Box::new(v)]);
    };
    let sector = v.sector;
    let mut out: Vec<Box<dyn Layer>> = vec![Box::new(v)];
    let mut recorded: Vec<&str> = [loc.relative.as_deref(), loc.absolute.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    recorded.dedup();
    let (want, want2) = (plain(&loc.linkage), loc.linkage2.as_deref().map(plain));
    let parents = files.find(
        &origin,
        &recorded,
        true,
        true,
        "the parent disk",
        |files, mut h, o| {
            // Its identity first, from its headers alone.
            let dw = match data_write_guid(&mut h)? {
                Ok(g) => plain(&guid(&g)),
                Err(why) => return Ok(Err(why)),
            };
            if dw != want && Some(&dw) != want2.as_ref() {
                return Ok(Err(format!(
                    "its DataWriteGuid is {{{dw}}}, not the child's parent_linkage {{{want}}}: \
                     it changed after this disk was made"
                )));
            }
            let p = Vhdx::open(h, &o.name)?;
            if p.sector != sector {
                return Ok(Err(format!(
                    "its sectors are {} bytes, and the child's {sector}",
                    p.sector
                )));
            }
            chain(p, o, files).map(Ok)
        },
    )?;
    out.extend(parents);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::vhd::tests::{
        check_sums, fixture, levels, mutate, open_path, raw, sha256, sha256_of, sums,
    };
    use super::*;
    use crate::ErrorKind;

    fn le32_at(b: &[u8], at: usize) -> u32 {
        le32(b, at)
    }

    /// The current header's offset in `b`, a VHDX file.
    fn current(b: &[u8]) -> usize {
        let seq = |at: usize| le64(b, at + 8);
        if seq(64 << 10) > seq(128 << 10) {
            64 << 10
        } else {
            128 << 10
        }
    }

    /// Both headers' checksums made right again.
    fn fix_headers(b: &mut [u8]) {
        for at in [64usize << 10, 128 << 10] {
            let c = crc_with_hole(&b[at..at + 4096], 4);
            b[at + 4..at + 8].copy_from_slice(&c.to_le_bytes());
        }
    }

    /// Where the region table says the metadata and the block table are.
    fn regions(b: &[u8]) -> ((usize, usize), (usize, usize)) {
        let rt = &b[192 << 10..256 << 10];
        let (mut bat, mut meta) = ((0, 0), (0, 0));
        for i in 0..le32_at(rt, 8) as usize {
            let e = &rt[16 + 32 * i..48 + 32 * i];
            let r = (le64(e, 16) as usize, le32(e, 24) as usize);
            if e[..16] == BAT_REGION {
                bat = r;
            } else if e[..16] == META_REGION {
                meta = r;
            }
        }
        (bat, meta)
    }

    /// The parent locator item's place in `b`.
    fn locator_at(b: &[u8]) -> (usize, usize) {
        let (_, (meta, _)) = regions(b);
        let mt = &b[meta..meta + (64 << 10)];
        for i in 0..usize::from(le16(mt, 10)) {
            let e = &mt[32 + 32 * i..64 + 32 * i];
            if e[..16] == PARENT_LOCATOR {
                return (meta + le32(e, 16) as usize, le32(e, 20) as usize);
            }
        }
        panic!("no parent locator");
    }

    /// The child `b`'s parent locator, its entries replaced by `kv`.
    fn set_locator(b: &mut [u8], kv: &[(&str, &str)]) {
        let (at, n) = locator_at(b);
        let mut out = vec![0u8; n];
        out[..16].copy_from_slice(&LOCATOR_VHDX);
        out[18..20].copy_from_slice(&(kv.len() as u16).to_le_bytes());
        let mut pos = 20 + 12 * kv.len();
        for (i, (k, v)) in kv.iter().enumerate() {
            let kb: Vec<u8> = k.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let vb: Vec<u8> = v.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let e = &mut out[20 + 12 * i..32 + 12 * i];
            e[..4].copy_from_slice(&(pos as u32).to_le_bytes());
            e[4..8].copy_from_slice(&((pos + kb.len()) as u32).to_le_bytes());
            e[8..10].copy_from_slice(&(kb.len() as u16).to_le_bytes());
            e[10..12].copy_from_slice(&(vb.len() as u16).to_le_bytes());
            out[pos..pos + kb.len()].copy_from_slice(&kb);
            out[pos + kb.len()..pos + kb.len() + vb.len()].copy_from_slice(&vb);
            pos += kb.len() + vb.len();
        }
        b[at..at + n].copy_from_slice(&out);
    }

    /// The child `b`'s parent_linkage.
    fn linkage(b: &[u8]) -> String {
        let (at, n) = locator_at(b);
        locator(&b[at..at + n]).unwrap().linkage
    }

    /// `b`'s DataWriteGuid, in both headers, set to the GUID `g` writes.
    fn set_data_write(b: &mut [u8], g: &str) {
        let hex: Vec<u8> = plain(g)
            .split('-')
            .collect::<String>()
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(&[hex[3], hex[2], hex[1], hex[0]]);
        raw[4..6].copy_from_slice(&[hex[5], hex[4]]);
        raw[6..8].copy_from_slice(&[hex[7], hex[6]]);
        raw[8..].copy_from_slice(&hex[8..]);
        assert_eq!(plain(&guid(&raw)), plain(g));
        for at in [64usize << 10, 128 << 10] {
            b[at + 32..at + 48].copy_from_slice(&raw);
        }
        fix_headers(b);
    }

    #[test]
    fn crc32c_is_castagnoli() {
        assert_eq!(fstool::crc::crc32c_append(0, b"123456789"), 0xE306_9283);
    }

    #[test]
    fn fixtures_read_as_their_disks() {
        check_sums(&[".vhdx", ".avhdx"]);
        // qemu-img's, read as the raw image it was made from.
        let mut d = open_path(&fixture("../7zip/gpt-ntfs.vhdx")).unwrap();
        assert_eq!(sha256(&mut d), sha256_of(&raw("gpt-ntfs.img")));
    }

    #[test]
    fn properties() {
        let d = open_path(&fixture("4k-fixed.vhdx")).unwrap();
        assert_eq!(d.sector(), 4096);
        let p = d.properties();
        for want in [
            ("Method", "Fixed"),
            ("Cluster Size", "1048576"),
            ("Sector Size", "4096"),
            ("Physical Sector Size", "4096"),
        ] {
            assert!(p.contains(&(want.0, want.1.to_owned())), "{p:?}");
        }
        assert!(
            p.iter()
                .any(|(k, v)| *k == "Creator Application" && v.contains("Windows"))
        );
        let d = open_path(&fixture("kids/odd-1.avhdx")).unwrap();
        let p = d.properties();
        assert!(p.contains(&("Method", "Differencing".to_owned())), "{p:?}");
        assert!(p.contains(&("Parent", "odd.vhdx".to_owned())), "{p:?}");
        assert!(d.notes().is_empty());
    }

    #[test]
    fn held_in_is_exact() {
        // Block 0 whole, and sectors 2500-2503 and 3000 of block 1.
        let l = levels(&fixture("kids/odd-1.avhdx"));
        assert_eq!(l[0].held_in(0, u64::MAX), MIB + 5 * 512);
        assert_eq!(l[0].held_in(2499 * 512, 2 * 512), 512);
        assert_eq!(l[0].held_in(2504 * 512, 496 * 512), 0);
        assert_eq!(l[0].held_in(MIB - 10, 20), 10);
        assert_eq!(l[1].held_in(0, u64::MAX), MIB);
        assert_eq!(
            levels(&fixture("4k-fixed.vhdx"))[0].held_in(0, u64::MAX),
            3 * MIB
        );
        // Blocks 0 and 1, and the 512 bytes of the disk in block 3, through the log.
        assert_eq!(
            levels(&fixture("dirty.vhdx"))[0].held_in(0, u64::MAX),
            2 * MIB + 512
        );
        let d = open_path(&fixture("kids/odd-1.avhdx")).unwrap();
        assert_eq!(d.held_in(0, d.len()), 2 * MIB + 5 * 512);
    }

    // ---- The log. ----

    /// The disk `dirty.vhdx` was made from, with the blocks its log adds (`blocks`).
    fn dirty_disk(blocks: &[u64]) -> Vec<u8> {
        let mut d = raw("mbr-fat.img");
        d.resize(3 * MIB as usize + 512, 0);
        for &b in blocks {
            let block: Vec<u8> = (0..256)
                .flat_map(|k| {
                    let mut p =
                        format!("BeeZip: block {b}, page {k}, through the log").into_bytes();
                    p.resize(4096, b'.');
                    p
                })
                .collect();
            let at = (b * MIB) as usize;
            let n = (d.len() - at).min(block.len());
            d[at..at + n].copy_from_slice(&block[..n]);
        }
        d
    }

    /// `dirty.vhdx`'s log: where it is, and the offsets in it of its two entries.
    fn dirty_log(b: &[u8]) -> (usize, usize, Vec<usize>) {
        let h = current(b);
        let (len, off) = (le32(b, h + 68) as usize, le64(b, h + 72) as usize);
        let lg = &b[h + 48..h + 64];
        let entries = (0..len / 4096)
            .map(|k| k * 4096)
            .filter(|&at| {
                &b[off + at..off + at + 4] == b"loge" && &b[off + at + 32..off + at + 48] == lg
            })
            .collect();
        (off, len, entries)
    }

    fn try_bytes(name: &str, b: &[u8]) -> Result<super::super::VirtualDisk> {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(name);
        std::fs::write(&p, b).unwrap();
        open_path(&p)
    }

    #[test]
    fn an_active_log_is_replayed_in_memory() {
        let path = fixture("dirty.vhdx");
        let before = std::fs::read(&path).unwrap();
        let want = sums()
            .into_iter()
            .find(|(p, _)| p == "dirty.vhdx")
            .unwrap()
            .1;
        assert_eq!(sha256_of(&dirty_disk(&[1, 3])), want);
        let mut d = open_path(&path).unwrap();
        assert_eq!(sha256(&mut d), want);
        assert!(
            d.properties()
                .contains(&("Log", "replayed in memory: 2 entries".into()))
        );
        assert!(d.notes()[0].contains("the file wasn't changed"));
        drop(d);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    /// The same two entries moved to the log's last sector: the first wraps round its end.
    #[test]
    fn a_log_replays_across_its_end() {
        let mut b = std::fs::read(fixture("dirty.vhdx")).unwrap();
        let (off, len, entries) = dirty_log(&b);
        assert_eq!(entries.len(), 2);
        let mut taken = Vec::new();
        for &at in &entries {
            let n = le32(&b, off + at + 8) as usize;
            taken.push(b[off + at..off + at + n].to_vec());
            b[off + at..off + at + n].fill(0);
        }
        let start = len - 4096;
        let mut at = start;
        for mut e in taken {
            e[12..16].copy_from_slice(&(start as u32).to_le_bytes());
            let c = crc_with_hole(&e, 4);
            e[4..8].copy_from_slice(&c.to_le_bytes());
            for (k, s) in e.chunks(4096).enumerate() {
                let o = off + (at + 4096 * k) % len;
                b[o..o + 4096].copy_from_slice(s);
            }
            at = (at + e.len()) % len;
        }
        let mut d = try_bytes("wrap.vhdx", &b).unwrap();
        assert_eq!(sha256(&mut d), sha256_of(&dirty_disk(&[1, 3])));
    }

    /// The second entry damaged: the first alone is the active sequence.
    #[test]
    fn a_damaged_entry_ends_the_sequence() {
        let mut b = std::fs::read(fixture("dirty.vhdx")).unwrap();
        let (off, _, entries) = dirty_log(&b);
        b[off + entries[1] + 4096 + 100] ^= 0xFF;
        let mut d = try_bytes("badcrc.vhdx", &b).unwrap();
        assert_eq!(sha256(&mut d), sha256_of(&dirty_disk(&[1])));
        assert!(
            d.properties()
                .contains(&("Log", "replayed in memory: 1 entries".into()))
        );
    }

    #[test]
    fn logs_that_cant_be_replayed() {
        let e = open_path(&fixture("dirty-noseq.vhdx")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
        assert!(e.message.contains("no valid sequence"), "{e}");
        let b = std::fs::read(fixture("dirty.vhdx")).unwrap();
        // Shorter than its FlushedFileOffset.
        let e = try_bytes("short.vhdx", &b[..6 << 20]).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
        assert!(e.message.contains("cut short"), "{e}");
        // A log of another version, and one over 64 MiB.
        let h = current(&b);
        let mut v = b.clone();
        v[h + 64..h + 66].copy_from_slice(&1u16.to_le_bytes());
        fix_headers(&mut v);
        let e = try_bytes("v1.vhdx", &v).err().unwrap();
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
        let mut v = b.clone();
        v[h + 68..h + 72].copy_from_slice(&(128u32 << 20).to_le_bytes());
        fix_headers(&mut v);
        let e = try_bytes("big.vhdx", &v).err().unwrap();
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
        // A log of no valid entry is never replayed when the LogGuid is zero: Hyper-V's own
        // files keep stale entries.
        let mut v = b.clone();
        v[h + 48..h + 64].fill(0);
        fix_headers(&mut v);
        let mut d = try_bytes("clean.vhdx", &v).unwrap();
        assert_eq!(sha256(&mut d), sha256_of(&dirty_disk(&[])));
    }

    /// Damage anywhere in the log's entries: replayed, or refused cleanly.
    #[test]
    fn mutated_logs_never_panic() {
        let orig = std::fs::read(fixture("dirty.vhdx")).unwrap();
        let (off, _, entries) = dirty_log(&orig);
        let span = (off + entries[0], off + entries[1] + 3 * 4096);
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("m.vhdx");
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..200 {
            let mut b = orig.clone();
            for _ in 0..1 + seed % 4 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = span.0 + (seed % (span.1 - span.0) as u64) as usize;
                b[at] = (seed >> 32) as u8;
            }
            std::fs::write(&p, &b).unwrap();
            if let Ok(mut d) = open_path(&p) {
                let _ = sha256(&mut d);
            }
        }
    }

    // ---- Damage, and what BeeZip doesn't read. ----

    #[test]
    fn damage_and_variants_refused() {
        let b = std::fs::read(fixture("parents/odd.vhdx")).unwrap();
        let expect = |name: &str, v: &[u8], kind: ErrorKind| {
            let e = try_bytes(name, v).err().unwrap();
            assert_eq!(e.kind, kind, "{name}: {e}");
        };
        // Equal sequence numbers.
        let mut v = b.clone();
        let s = le64(&v, (64 << 10) + 8);
        v[(128 << 10) + 8..(128 << 10) + 16].copy_from_slice(&s.to_le_bytes());
        fix_headers(&mut v);
        expect("seq.vhdx", &v, ErrorKind::Corrupt);
        // Version 2.
        let mut v = b.clone();
        for at in [64usize << 10, 128 << 10] {
            v[at + 66..at + 68].copy_from_slice(&2u16.to_le_bytes());
        }
        fix_headers(&mut v);
        expect("v2.vhdx", &v, ErrorKind::UnsupportedOperation);
        // An unknown region marked required, in both tables.
        let mut v = b.clone();
        for at in [192usize << 10, 256 << 10] {
            let n = le32(&v, at + 8) as usize;
            let e = at + 16 + 32 * n;
            v[e..e + 16].copy_from_slice(&[0x5A; 16]);
            v[e + 16..e + 24].copy_from_slice(&MIB.to_le_bytes());
            v[e + 24..e + 28].copy_from_slice(&(MIB as u32).to_le_bytes());
            v[e + 28..e + 32].copy_from_slice(&1u32.to_le_bytes());
            v[at + 8..at + 12].copy_from_slice(&(n as u32 + 1).to_le_bytes());
            let c = crc_with_hole(&v[at..at + (64 << 10)], 4);
            v[at + 4..at + 8].copy_from_slice(&c.to_le_bytes());
        }
        expect("region.vhdx", &v, ErrorKind::UnsupportedOperation);
        // An unknown metadata item marked required.
        let mut v = b.clone();
        let ((bat, _), (meta, _)) = regions(&v);
        let n = usize::from(le16(&v, meta + 10));
        let e = meta + 32 + 32 * n;
        let first = v[meta + 32..meta + 64].to_vec();
        v[e..e + 32].copy_from_slice(&first);
        v[e..e + 16].copy_from_slice(&[0x5A; 16]);
        v[e + 24..e + 28].copy_from_slice(&4u32.to_le_bytes());
        v[meta + 10..meta + 12].copy_from_slice(&(n as u16 + 1).to_le_bytes());
        expect("meta.vhdx", &v, ErrorKind::UnsupportedOperation);
        // The same, optional: passed over.
        v[e + 24..e + 28].copy_from_slice(&0u32.to_le_bytes());
        assert!(try_bytes("meta-optional.vhdx", &v).is_ok());
        // A block in a reserved state, and one in the header area.
        let mut v = b.clone();
        v[bat] = (v[bat] & !7) | 4;
        expect("state.vhdx", &v, ErrorKind::Corrupt);
        let mut v = b.clone();
        v[bat..bat + 8].copy_from_slice(&6u64.to_le_bytes());
        expect("header.vhdx", &v, ErrorKind::Corrupt);
        // A block past the file's end: zeros, noted.
        let mut v = b.clone();
        v[bat..bat + 8].copy_from_slice(&(6 | (64u64 << 20)).to_le_bytes());
        let mut d = try_bytes("past.vhdx", &v).unwrap();
        assert!(
            d.notes()[0].contains("1 of past.vhdx's blocks lie past its end"),
            "{:?}",
            d.notes()
        );
        assert_eq!(
            sha256(&mut d),
            sha256_of(&vec![0u8; 3 * MIB as usize + 512])
        );
        // One at the top of the offsets a block table entry can hold.
        let mut v = b.clone();
        v[bat..bat + 8].copy_from_slice(&(6 | (u64::MAX >> 20 << 20)).to_le_bytes());
        let mut d = try_bytes("top.vhdx", &v).unwrap();
        assert_eq!(d.held_in(0, MIB), 0);
        let mut buf = vec![1u8; 4096];
        match std::io::Read::read(&mut d, &mut buf) {
            Ok(n) => assert!(buf[..n].iter().all(|&x| x == 0)),
            Err(e) => assert_eq!(Error::from_io(&e).kind, ErrorKind::Corrupt),
        }
        // Neither header valid; the file too short.
        let mut v = b.clone();
        v[64 << 10] = 0;
        v[128 << 10] = 0;
        expect("heads.vhdx", &v, ErrorKind::Corrupt);
        expect("short.vhdx", &b[..300 << 10], ErrorKind::Corrupt);
    }

    #[test]
    fn mutated_fixtures_never_panic() {
        mutate(
            &["parents/odd.vhdx", "kids/odd-1.avhdx", "4k-fixed.vhdx"],
            60,
        );
    }

    // ---- Parents. ----

    /// `kids/odd-1.avhdx` and its parent, copied to `child` and `parent` under `dir`, the child's
    /// locator set to `kv` when given.
    fn place(dir: &Path, child: &str, parent: Option<&str>, kv: Option<&[(&str, &str)]>) {
        let mut c = std::fs::read(fixture("kids/odd-1.avhdx")).unwrap();
        if let Some(kv) = kv {
            set_locator(&mut c, kv);
        }
        for f in [Some(child), parent].into_iter().flatten() {
            std::fs::create_dir_all(dir.join(f).parent().unwrap()).unwrap();
        }
        std::fs::write(dir.join(child), c).unwrap();
        if let Some(p) = parent {
            std::fs::copy(fixture("parents/odd.vhdx"), dir.join(p)).unwrap();
        }
    }

    fn child_sum() -> String {
        sums()
            .into_iter()
            .find(|(p, _)| p == "kids/odd-1.avhdx")
            .unwrap()
            .1
    }

    #[test]
    fn a_parent_is_found_beside_or_absolute() {
        let t = tempfile::tempdir().unwrap();
        let c = std::fs::read(fixture("kids/odd-1.avhdx")).unwrap();
        let link = linkage(&c);
        // Both in one folder: its relative path leads nowhere, its name beside it.
        place(t.path(), "one/odd-1.avhdx", Some("one/odd.vhdx"), None);
        let mut d = open_path(&t.path().join("one/odd-1.avhdx")).unwrap();
        assert_eq!(sha256(&mut d), child_sum());
        // Elsewhere, by its absolute path.
        let other = tempfile::tempdir().unwrap();
        let abs = other.path().join("base.vhdx");
        std::fs::copy(fixture("parents/odd.vhdx"), &abs).unwrap();
        let kv = [
            ("parent_linkage", link.as_str()),
            ("relative_path", r"..\nowhere\base.vhdx"),
            ("absolute_win32_path", abs.to_str().unwrap()),
        ];
        place(t.path(), "abs/odd-1.avhdx", None, Some(&kv));
        let mut d = open_path(&t.path().join("abs/odd-1.avhdx")).unwrap();
        assert_eq!(sha256(&mut d), child_sum());
        // By parent_linkage2: a parent written to since, and recorded so.
        let mut p = std::fs::read(fixture("parents/odd.vhdx")).unwrap();
        let g2 = "{01234567-89ab-cdef-0123-456789abcdef}";
        set_data_write(&mut p, g2);
        let kv = [
            ("parent_linkage", link.as_str()),
            ("parent_linkage2", g2),
            ("relative_path", r".\base.vhdx"),
        ];
        place(t.path(), "two/odd-1.avhdx", None, Some(&kv));
        std::fs::write(t.path().join("two/base.vhdx"), &p).unwrap();
        let mut d = open_path(&t.path().join("two/odd-1.avhdx")).unwrap();
        assert_eq!(sha256(&mut d), child_sum());
    }

    #[test]
    fn a_missing_changed_or_unlike_parent_is_not_found() {
        let t = tempfile::tempdir().unwrap();
        let child = t.path().join("kids/odd-1.avhdx");
        place(t.path(), "kids/odd-1.avhdx", None, None);
        let e = open_path(&child).err().unwrap();
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(e.message.contains("odd-1.avhdx"), "{e}");
        assert!(
            e.message.contains(r"parents\odd.vhdx (its relative path"),
            "{e}"
        );
        assert!(e.message.contains("not there"), "{e}");
        // Written to since: another DataWriteGuid.
        let mut p = std::fs::read(fixture("parents/odd.vhdx")).unwrap();
        set_data_write(&mut p, "{01234567-89ab-cdef-0123-456789abcdef}");
        std::fs::create_dir_all(t.path().join("parents")).unwrap();
        std::fs::write(t.path().join("parents/odd.vhdx"), &p).unwrap();
        let e = open_path(&child).err().unwrap();
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(
            e.message.contains("its DataWriteGuid is {01234567-89ab"),
            "{e}"
        );
        assert!(
            e.message.contains("it changed after this disk was made"),
            "{e}"
        );
        // The right identity, but sectors of 4 KiB.
        let c = std::fs::read(&child).unwrap();
        let mut p = std::fs::read(fixture("4k-fixed.vhdx")).unwrap();
        set_data_write(&mut p, &linkage(&c));
        std::fs::write(t.path().join("parents/odd.vhdx"), &p).unwrap();
        let e = open_path(&child).err().unwrap();
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(e.message.contains("its sectors are 4096 bytes"), "{e}");
        // A VHD of its name.
        std::fs::copy(fixture("fat-dyn.vhd"), t.path().join("parents/odd.vhdx")).unwrap();
        let e = open_path(&child).err().unwrap();
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(e.message.contains("a VHDX's parent must be one"), "{e}");
    }

    #[test]
    fn a_network_parent_is_never_opened() {
        let t = tempfile::tempdir().unwrap();
        let c = std::fs::read(fixture("kids/odd-1.avhdx")).unwrap();
        let link = linkage(&c);
        let kv = [
            ("parent_linkage", link.as_str()),
            ("relative_path", r"\\beezip.invalid\share\odd.vhdx"),
            ("absolute_win32_path", r"\\beezip.invalid\share\odd.vhdx"),
            ("volume_path", r"\\?\UNC\beezip.invalid\share\odd.vhdx"),
        ];
        place(t.path(), "unc.avhdx", None, Some(&kv));
        let e = open_path(&t.path().join("unc.avhdx")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Unsafe, "{e}");
        // A parent locator of another type.
        let mut c = c;
        let (at, _) = locator_at(&c);
        c[at] ^= 1;
        let e = try_bytes("type.avhdx", &c).err().unwrap();
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    }
}
