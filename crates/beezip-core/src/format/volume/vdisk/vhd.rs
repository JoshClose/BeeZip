//! VHD, from Microsoft's Virtual Hard Disk Image Format Specification (docs/M8.md §3.1), read
//! only.
//!
//! - **The footer** is the file's last 512 bytes (511 from Virtual PC before 2004): `conectix`
//!   and the one's-complement checksum. Its version, 1.0 in every VHD known, isn't checked, nor
//!   the dynamic header's, as 7-Zip checks neither (docs/M11.md §6.1). A dynamic or differencing
//!   disk whose last footer is damaged uses its copy at the start, with a note in Info.
//! - **The size** is the footer's current size, as Windows reads it: a disk qemu-img rounded up to
//!   its geometry reads zeros past the raw image, as qemu reads it.
//! - **A fixed disk** is the file's first bytes.
//! - **Dynamic and differencing disks** have a header (`cxsparse`) and a block table; each block
//!   in the file is a sector bitmap (a bit a sector, the most significant first, padded to 512
//!   bytes) and the block. A dynamic disk reads a block whatever its bitmap says (Windows
//!   zero-fills new blocks) and a block not in the file as zeros; a differencing disk reads the
//!   sectors its bitmap marks, and its parent's elsewhere.
//! - **The parent** is looked for by its relative path (`W2ru`), its absolute path (`W2ku`) and
//!   the Parent Unicode Name, in that order, by [`Files`]' rules. It must be a VHD whose unique id
//!   is the child's Parent Unique ID; the parent's time stamp isn't checked (Hyper-V writes 0).
//! - **Blocks** of 512 bytes to 2 GiB, the most the header can say; a block is read from the file
//!   where it is, never held whole. **The block table** is read a page at a time ([`Paged`]),
//!   whatever its size.
//! - **Refused** (`UnsupportedOperation`): a disk type other than fixed, dynamic or
//!   differencing.
//! - **Blocks past the file's end** read as zeros, counted in Info, as M7 reads a truncated
//!   image.

use std::cell::RefCell;

use super::{Files, Got, Handle, Layer, Origin, Paged, Width, be32, be64};
use crate::{Error, Result, backend::External};

/// A block table entry for a block that isn't in the file.
const UNUSED: u32 = 0xFFFF_FFFF;
/// The longest parent locator read.
const MAX_LOCATOR: u64 = 64 << 10;
/// Seconds from 1970 to 2000-01-01, where a VHD's time stamps start.
const EPOCH_2000: i64 = 946_684_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fixed,
    Dynamic,
    Differencing,
}

/// A footer whose cookie and checksum are right.
struct Footer {
    version: u32,
    time: u32,
    app: [u8; 4],
    app_version: u32,
    host: [u8; 4],
    size: u64,
    kind: u32,
    id: [u8; 16],
    data_offset: u64,
    saved: bool,
}

fn array<const N: usize>(b: &[u8]) -> [u8; N] {
    b.try_into().unwrap_or([0; N])
}

/// The one's-complement sum VHD checksums with, of `b` without its checksum at `at`.
fn checksum(b: &[u8], at: usize) -> u32 {
    !b.iter()
        .enumerate()
        .filter(|(i, _)| !(at..at + 4).contains(i))
        .fold(0u32, |s, (_, &x)| s.wrapping_add(u32::from(x)))
}

fn footer(f: &[u8; 512]) -> Option<Footer> {
    if &f[..8] != b"conectix" || be32(f, 64) != checksum(f, 64) {
        return None;
    }
    Some(Footer {
        version: be32(f, 12),
        data_offset: be64(f, 16),
        time: be32(f, 24),
        app: array(&f[28..32]),
        app_version: be32(f, 32),
        host: array(&f[36..40]),
        size: be64(f, 48),
        kind: be32(f, 60),
        id: array(&f[68..84]),
        saved: f[84] != 0,
    })
}

/// The file's footer: at its end (512 or 511 bytes), else, for a dynamic or differencing disk,
/// its copy at the start. With it, where the disk's data ends, and whether the copy was used.
fn find_footer(file: &mut Handle) -> Result<Option<(Footer, u64, bool)>> {
    let len = file.len;
    if len < 511 {
        return Ok(None);
    }
    let n = usize::try_from(len.min(512)).unwrap_or(512);
    let mut tail = [0u8; 512];
    file.read_exact_at(len - n as u64, &mut tail[..n], "vhd: the footer")?;
    if n == 512
        && let Some(f) = footer(&tail)
    {
        return Ok(Some((f, len - 512, false)));
    }
    // Virtual PC before 2004 wrote 511 bytes.
    let mut short = [0u8; 512];
    short[..511].copy_from_slice(&tail[n - 511..n]);
    if let Some(f) = footer(&short) {
        return Ok(Some((f, len - 511, false)));
    }
    if len >= 512 {
        let mut head = [0u8; 512];
        file.read_exact_at(0, &mut head, "vhd: the footer's copy")?;
        if let Some(f) = footer(&head)
            && f.kind != 2
        {
            return Ok(Some((f, len, true)));
        }
    }
    Ok(None)
}

/// UTF-16 text up to its first NUL, little-endian or not; `None` if it isn't UTF-16.
fn utf16(b: &[u8], little: bool) -> Option<String> {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            if little {
                u16::from_le_bytes(*c)
            } else {
                u16::from_be_bytes(*c)
            }
        })
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16(&units).ok()
}

/// Whether the sector holding offset `a` of a block (of sectors of `sector` bytes) is marked in
/// the sector bitmap `bits`, and where the run of sectors marked alike from it ends, at most `z`
/// (above `a`). The most significant bit of byte 0 is the first sector's when `msb` (VHD), else
/// the least (VHDX).
pub(super) fn run_at(bits: &[u8], msb: bool, sector: u64, a: u64, z: u64) -> (bool, u64) {
    let byte = |k: u64| -> u8 {
        usize::try_from(k / 8)
            .ok()
            .and_then(|i| bits.get(i))
            .copied()
            .unwrap_or(0)
    };
    let bit = |k: u64| -> bool {
        let shift = if msb { 7 - k % 8 } else { k % 8 };
        byte(k) >> shift & 1 == 1
    };
    let mut k = a / sector;
    let marked = bit(k);
    let all = if marked { 0xFF } else { 0 };
    k += 1;
    while k.saturating_mul(sector) < z {
        // Eight sectors at a time where their byte is all one way.
        if k.is_multiple_of(8) && byte(k) == all {
            k += 8;
        } else if bit(k) == marked {
            k += 1;
        } else {
            break;
        }
    }
    (marked, k.saturating_mul(sector).min(z))
}

/// Calls `f(start, len)` for each run of the sectors of `a..z` (offsets in a block) marked in the
/// sector bitmap `bits`, clipped to `a..z` (see [`run_at`]).
pub(super) fn present_runs(
    bits: &[u8],
    msb: bool,
    sector: u64,
    a: u64,
    z: u64,
    mut f: impl FnMut(u64, u64),
) {
    let mut at = a;
    while at < z {
        let (marked, stop) = run_at(bits, msb, sector, at, z);
        if marked {
            f(at, stop - at);
        }
        at = stop;
    }
}

/// One VHD file.
pub struct Vhd {
    /// The file, in a cell so that [`Layer::held_in`] can read sector bitmaps.
    file: RefCell<Handle>,
    name: String,
    kind: Kind,
    footer: Footer,
    from_copy: bool,
    size: u64,
    block: u64,
    bitmap_len: u64,
    /// The block table, read a page at a time.
    bat: Paged,
    /// Where the disk's data ends: the footer's start.
    data_end: u64,
    parent_id: [u8; 16],
    past_end: u64,
    /// The last block's sector bitmap read.
    bitmap: Option<(u64, Vec<u8>)>,
}

impl Vhd {
    /// Opens the VHD `file` is (named `name`), with the names its parent is recorded by, in the
    /// order they're tried: `W2ru`, `W2ku`, the Parent Unicode Name.
    fn open(mut file: Handle, name: &str) -> Result<(Self, Vec<String>)> {
        let (footer, data_end, from_copy) = find_footer(&mut file)?.ok_or_else(|| {
            Error::corrupt("vhd: no valid footer at the file's end, nor a copy at its start")
        })?;
        let kind = match footer.kind {
            2 => Kind::Fixed,
            3 => Kind::Dynamic,
            4 => Kind::Differencing,
            k => {
                return Err(Error::unsupported(format!(
                    "vhd: a disk of type {k}; BeeZip reads fixed, dynamic and differencing disks"
                )));
            }
        };
        let size = footer.size;
        let mut v = Self {
            file: RefCell::new(file),
            name: name.to_owned(),
            kind,
            footer,
            from_copy,
            size,
            block: 0,
            bitmap_len: 0,
            bat: Paged::new(0, 0, Width::Be32),
            data_end,
            parent_id: [0; 16],
            past_end: 0,
            bitmap: None,
        };
        if kind == Kind::Fixed {
            if size > data_end {
                return Err(Error::corrupt(format!(
                    "vhd: a fixed disk of {size} bytes in {data_end} bytes of file"
                )));
            }
            return Ok((v, Vec::new()));
        }
        let file = v.file.get_mut();
        let mut h = [0u8; 1024];
        file.read_exact_at(v.footer.data_offset, &mut h, "vhd: the dynamic disk header")?;
        if &h[..8] != b"cxsparse" || be32(&h, 36) != checksum(&h, 36) {
            return Err(Error::corrupt("vhd: the dynamic disk header is damaged"));
        }
        let table = be64(&h, 16);
        let max_entries = u64::from(be32(&h, 28));
        let block = u64::from(be32(&h, 32));
        if block < 512 || !block.is_power_of_two() {
            return Err(Error::corrupt(format!("vhd: blocks of {block} bytes")));
        }
        let blocks = size.div_ceil(block);
        if blocks > max_entries {
            return Err(Error::corrupt(format!(
                "vhd: {max_entries} block table entries for a disk of {blocks} blocks"
            )));
        }
        if table.checked_add(blocks * 4).is_none_or(|e| e > file.len) {
            return Err(Error::corrupt(format!(
                "vhd: the block table: {} bytes at {table} reach past the file's end ({} bytes)",
                blocks * 4,
                file.len
            )));
        }
        let bat = Paged::new(table, blocks, Width::Be32);
        let bitmap_len = (block / 512).div_ceil(8).div_ceil(512) * 512;
        let mut past_end = 0u64;
        bat.scan(
            |at, out| file.read_exact_at(at, out, "vhd: the block table"),
            |_, e| {
                if e != u64::from(UNUSED) && e * 512 + bitmap_len + block > data_end {
                    past_end += 1;
                }
                Ok(())
            },
        )?;
        let mut names = Vec::new();
        if kind == Kind::Differencing {
            let (mut rel, mut abs) = (None, None);
            for i in 0..8 {
                let e = &h[576 + 24 * i..600 + 24 * i];
                let code = &e[..4];
                let (len, off) = (u64::from(be32(e, 8)), be64(e, 16));
                let slot = match code {
                    b"W2ru" => &mut rel,
                    b"W2ku" => &mut abs,
                    // Wi2r and Wi2k (deprecated), Mac and MacX: not followed.
                    _ => continue,
                };
                if slot.is_some() || len == 0 || len > MAX_LOCATOR {
                    continue;
                }
                let Ok(data) = file.read_vec(off, len, MAX_LOCATOR, "vhd: a parent locator") else {
                    continue;
                };
                *slot = utf16(&data, true).filter(|s| !s.is_empty());
            }
            let unicode = utf16(&h[64..576], false).filter(|s| !s.is_empty());
            for n in [rel, abs, unicode].into_iter().flatten() {
                // Hyper-V records the absolute path twice.
                if !names.contains(&n) {
                    names.push(n);
                }
            }
            v.parent_id = array(&h[40..56]);
        }
        v.block = block;
        v.bitmap_len = bitmap_len;
        v.bat = bat;
        v.past_end = past_end;
        Ok((v, names))
    }

    /// The block table entry of block `b`, read through `file`.
    fn entry(&self, file: &mut Handle, b: u64) -> Result<u32> {
        let e = self.bat.get(b, "vhd: the block table", |at, out| {
            file.read_exact_at(at, out, "vhd: the block table")
        })?;
        Ok(u32::try_from(e).unwrap_or(UNUSED))
    }

    /// Bytes of `n` at `at` before the disk's data ends.
    fn in_file(&self, at: u64, n: u64) -> u64 {
        n.min(self.data_end.saturating_sub(at))
    }

    /// Loads block `b`'s sector bitmap, which starts at `start`.
    fn load_bitmap(&mut self, b: u64, start: u64) -> Result<()> {
        if self.bitmap.as_ref().is_some_and(|(k, _)| *k == b) {
            return Ok(());
        }
        let mut v = self.bitmap.take().map(|(_, v)| v).unwrap_or_default();
        v.resize(usize::try_from(self.bitmap_len).unwrap_or(0), 0);
        read_data(self.file.get_mut(), self.data_end, start, &mut v)?;
        self.bitmap = Some((b, v));
        Ok(())
    }

    /// Bytes of `a..z` (offsets in block `b`, whose entry is `e`) its bitmap marks as this file's
    /// and the file holds; on a failed read, every byte the file holds (high, never low).
    fn present_in(&self, e: u32, a: u64, z: u64) -> u64 {
        let start = u64::from(e) * 512;
        let data = start + self.bitmap_len;
        let mut bits = vec![0u8; usize::try_from(self.bitmap_len).unwrap_or(0)];
        let read = match self.file.try_borrow_mut() {
            Ok(mut f) => read_data(&mut f, self.data_end, start, &mut bits).is_ok(),
            Err(_) => false,
        };
        if !read {
            return self.in_file(data + a, z - a);
        }
        let mut held = 0;
        present_runs(&bits, true, 512, a, z, |s, n| {
            held += self.in_file(data + s, n);
        });
        held
    }
}

/// `buf.len()` bytes of the file at `at`, zeros past `end`.
fn read_data(file: &mut Handle, end: u64, at: u64, buf: &mut [u8]) -> Result<()> {
    let real = usize::try_from(end.saturating_sub(at))
        .unwrap_or(usize::MAX)
        .min(buf.len());
    if real > 0 {
        file.read_exact_at(at, &mut buf[..real], "vhd: a block")?;
    }
    buf[real..].fill(0);
    Ok(())
}

/// A VHD time stamp as `YYYY-MM-DD hh:mm:ss`, UTC.
fn time(t: u32) -> String {
    match time::OffsetDateTime::from_unix_timestamp(EPOCH_2000 + i64::from(t)) {
        Ok(d) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            d.year(),
            u8::from(d.month()),
            d.day(),
            d.hour(),
            d.minute(),
            d.second()
        ),
        Err(_) => t.to_string(),
    }
}

/// Four bytes of a footer as text, without trailing spaces or NULs.
fn text4(b: &[u8; 4]) -> String {
    String::from_utf8_lossy(b)
        .trim_end_matches([' ', '\0'])
        .to_owned()
}

/// A VHD's unique id, a UUID stored big-endian as the rest of the format is:
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, its bytes in order.
fn show(id: &[u8; 16]) -> String {
    let hex = |r: std::ops::Range<usize>| -> String {
        id[r].iter().map(|b| format!("{b:02x}")).collect()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    )
}

impl Layer for Vhd {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)> {
        if self.kind == Kind::Fixed {
            self.file
                .get_mut()
                .read_exact_at(off, buf, "vhd: the disk")?;
            return Ok((buf.len(), Got::Data));
        }
        let (b, within) = (off / self.block, off % self.block);
        let n = buf
            .len()
            .min(usize::try_from(self.block - within).unwrap_or(usize::MAX));
        let e = {
            let mut file = self.file.borrow_mut();
            self.entry(&mut file, b)?
        };
        if e == UNUSED {
            let got = match self.kind {
                Kind::Differencing => Got::Hole,
                _ => Got::Zero,
            };
            return Ok((n, got));
        }
        let start = u64::from(e) * 512;
        let data = start + self.bitmap_len;
        if self.kind == Kind::Dynamic {
            read_data(
                self.file.get_mut(),
                self.data_end,
                data + within,
                &mut buf[..n],
            )?;
            return Ok((n, Got::Data));
        }
        // A differencing disk: the run of sectors marked alike from `within`.
        self.load_bitmap(b, start)?;
        let bits = self.bitmap.as_ref().map_or(&[][..], |(_, v)| v.as_slice());
        let (marked, stop) = run_at(bits, true, 512, within, within + n as u64);
        let m = usize::try_from(stop - within).unwrap_or(n).clamp(1, n);
        if marked {
            read_data(
                self.file.get_mut(),
                self.data_end,
                data + within,
                &mut buf[..m],
            )?;
            Ok((m, Got::Data))
        } else {
            Ok((m, Got::Hole))
        }
    }

    fn held_in(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len).min(self.size);
        if start >= end {
            return 0;
        }
        if self.kind == Kind::Fixed {
            return end - start;
        }
        let (first, last) = (start / self.block, (end - 1) / self.block);
        let mut held = 0u64;
        for b in first..=last {
            let e = match self.file.try_borrow_mut() {
                Ok(mut f) => self.entry(&mut f, b),
                Err(_) => break,
            };
            let Ok(e) = e else {
                break;
            };
            if e == UNUSED {
                continue;
            }
            let base = b * self.block;
            let (a, z) = (start.max(base) - base, end.min(base + self.block) - base);
            held += match self.kind {
                Kind::Differencing => self.present_in(e, a, z),
                _ => self.in_file(u64::from(e) * 512 + self.bitmap_len + a, z - a),
            };
        }
        held
    }

    fn file_bytes(&self) -> u64 {
        self.file.try_borrow().map_or(0, |f| f.len)
    }

    fn properties(&self, out: &mut Vec<(&'static str, String)>) {
        let f = &self.footer;
        let method = match self.kind {
            Kind::Fixed => "Fixed",
            Kind::Dynamic => "Dynamic",
            Kind::Differencing => "Differencing",
        };
        out.push(("Method", method.into()));
        if self.kind != Kind::Fixed {
            out.push(("Cluster Size", self.block.to_string()));
        }
        out.push((
            "Creator Application",
            format!(
                "{} {}.{}",
                text4(&f.app),
                f.app_version >> 16,
                f.app_version & 0xFFFF
            ),
        ));
        let host = match &f.host {
            b"Wi2k" => "Windows".to_owned(),
            b"Mac " => "Macintosh".to_owned(),
            other => text4(other),
        };
        out.push(("Host OS", host));
        out.push(("Created", time(f.time)));
        out.push(("ID", show(&f.id)));
        if self.kind == Kind::Differencing {
            out.push(("Parent ID", show(&self.parent_id)));
        }
        if f.saved {
            out.push(("Saved State", "+".into()));
        }
    }

    fn notes(&self, out: &mut Vec<String>) {
        let v = self.footer.version;
        if v != 0x0001_0000 {
            out.push(format!(
                "vhd: {}'s footer says version {}.{}, where every VHD known is 1.0; it was read \
                 as one",
                self.name,
                v >> 16,
                v & 0xFFFF
            ));
        }
        if self.from_copy {
            out.push(format!(
                "vhd: the footer at the end of {} is damaged; its copy at the start was used",
                self.name
            ));
        }
        if self.past_end > 0 {
            out.push(format!(
                "vhd: {} of {}'s blocks lie past its end and read as zeros",
                self.past_end, self.name
            ));
        }
    }
}

/// Whether `file` is a VHDX: what a VHD's parent mustn't be.
fn is_vhdx(file: &mut Handle) -> Result<bool> {
    let mut sig = [0u8; 8];
    Ok(file.len >= 8 && {
        file.read_exact_at(0, &mut sig, "the parent disk's signature")?;
        &sig == b"vhdxfile"
    })
}

/// The levels of the VHD `file` is, its parents' below it.
pub fn layers(file: Handle, origin: Origin, files: &mut Files) -> Result<Vec<Box<dyn Layer>>> {
    let (v, names) = Vhd::open(file, &origin.name)?;
    if v.kind != Kind::Differencing {
        return Ok(vec![Box::new(v)]);
    }
    let want = v.parent_id;
    let mut out: Vec<Box<dyn Layer>> = vec![Box::new(v)];
    let recorded: Vec<&str> = names.iter().map(String::as_str).collect();
    let parents = files.find(
        &origin,
        &recorded,
        true,
        true,
        "the parent disk",
        |files, mut h, o| {
            // Its identity first, from its footer alone.
            if is_vhdx(&mut h)? {
                return Ok(Err("it's a VHDX, and a VHD's parent must be a VHD".into()));
            }
            let Some((f, _, _)) = find_footer(&mut h)? else {
                return Ok(Err("it isn't a VHD: it has no valid footer".into()));
            };
            if f.id != want {
                return Ok(Err(format!(
                    "its unique id is {}, not the child's Parent Unique ID {}: it changed after \
                     this disk was made",
                    show(&f.id),
                    show(&want)
                )));
            }
            super::layers(Some(External::Vhd), h, o, files).map(Ok)
        },
    )?;
    out.extend(parents);
    Ok(out)
}

#[cfg(test)]
pub(super) mod tests {
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use super::super::{Files, Handle, Layer, Origin, VirtualDisk};
    use super::*;
    use crate::{ErrorKind, io::Counter};

    /// A file of `tests/fixtures/thirdparty/vhd` (or of `thirdparty/`, with `../`).
    pub fn fixture(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/thirdparty/vhd")
            .join(rel)
    }

    /// What each fixture's disk reads as, from `SHA256SUMS`.
    pub fn sums() -> Vec<(String, String)> {
        std::fs::read_to_string(fixture("SHA256SUMS"))
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once(" *"))
            .map(|(h, p)| (p.to_owned(), h.to_owned()))
            .collect()
    }

    fn kind(path: &Path) -> External {
        match path.extension().and_then(|e| e.to_str()) {
            Some("vhd") => External::Vhd,
            _ => External::Vhdx,
        }
    }

    /// The disk at `path`, with its parents.
    pub fn open_path(path: &Path) -> Result<VirtualDisk> {
        let origin = Origin::of(path);
        let mut files = Files::new(&origin, Counter::new());
        let f = std::fs::File::open(path).unwrap();
        let len = f.metadata().unwrap().len();
        super::super::open(
            kind(path),
            Handle::new(Box::new(f), len),
            origin,
            &mut files,
        )
    }

    /// The levels of the disk at `path`.
    pub fn levels(path: &Path) -> Vec<Box<dyn Layer>> {
        let origin = Origin::of(path);
        let mut files = Files::new(&origin, Counter::new());
        let f = std::fs::File::open(path).unwrap();
        let len = f.metadata().unwrap().len();
        super::super::layers(
            Some(kind(path)),
            Handle::new(Box::new(f), len),
            origin,
            &mut files,
        )
        .unwrap()
    }

    /// The SHA-256 of the whole disk, read in pieces of an odd size.
    pub fn sha256(d: &mut VirtualDisk) -> String {
        use std::io::Read;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 100_003];
        let mut total = 0u64;
        loop {
            let n = d.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n as u64;
            h.update(&buf[..n]);
        }
        assert_eq!(total, d.len());
        hex(&h.finalize())
    }

    pub fn sha256_of(data: &[u8]) -> String {
        hex(&Sha256::digest(data))
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Every fixture whose name ends in one of `exts` reads as `SHA256SUMS` says.
    pub fn check_sums(exts: &[&str]) {
        let mut checked = 0;
        for (p, want) in &sums() {
            if !exts.iter().any(|e| p.ends_with(e)) {
                continue;
            }
            let mut d = open_path(&fixture(p)).unwrap_or_else(|e| panic!("{p}: {e}"));
            assert_eq!(&sha256(&mut d), want, "{p}");
            checked += 1;
        }
        assert!(checked >= 4, "{checked} fixtures");
    }

    /// The raw image `name` of `thirdparty/7zip`.
    pub fn raw(name: &str) -> Vec<u8> {
        std::fs::read(fixture("../7zip").join(name)).unwrap()
    }

    #[test]
    fn fixtures_read_as_their_disks() {
        check_sums(&[".vhd"]);
        // qemu-img's, read as the raw image they were made from.
        for name in ["mbr-fat.vhd", "mbr-fat-fixed.vhd"] {
            let mut d = open_path(&fixture("../7zip").join(name)).unwrap();
            assert_eq!(sha256(&mut d), sha256_of(&raw("mbr-fat.img")), "{name}");
        }
    }

    #[test]
    fn properties_and_parents() {
        let d = open_path(&fixture("kids/fe-2.vhd")).unwrap();
        assert_eq!(d.depth(), 3);
        let props = d.properties();
        let get = |k: &str| props.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("Method"), Some("Differencing"));
        assert_eq!(get("Cluster Size"), Some("524288"));
        assert_eq!(get("Host OS"), Some("Windows"));
        assert_eq!(get("Parent"), Some("fe-1.vhd > fe.vhd"));
        assert!(get("Parent ID").is_some());
        let d = open_path(&fixture("fat-fixed.vhd")).unwrap();
        let props = d.properties();
        assert!(props.contains(&("Method", "Fixed".to_owned())), "{props:?}");
        assert!(d.notes().is_empty());
    }

    /// `held_in` counts the bytes of present blocks, and of a differencing disk's present
    /// sectors, never holes.
    #[test]
    fn held_in_is_exact() {
        // One 512 KiB block holding all of the 288 KiB disk.
        let l = levels(&fixture("fat-dyn.vhd"));
        assert_eq!(l[0].held_in(0, u64::MAX), 294_912);
        assert_eq!(l[0].held_in(1000, 10), 10);
        // Blocks 0 and 6 (the last, which holds one sector of the disk) of seven.
        let l = levels(&fixture("odd.vhd"));
        assert_eq!(l[0].held_in(0, u64::MAX), 524_288 + 512);
        assert_eq!(l[0].held_in(524_288, 5 * 524_288), 0);
        // fe-1.vhd: block 0 whole, and sectors 1100-1103 and 1200 of block 1.
        let l = levels(&fixture("kids/fe-1.vhd"));
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].held_in(0, u64::MAX), 524_288 + 5 * 512);
        assert_eq!(l[0].held_in(1099 * 512, 2 * 512), 512);
        assert_eq!(l[0].held_in(1104 * 512, 96 * 512), 0);
        assert_eq!(l[0].held_in(1103 * 512 + 100, 300), 300);
        assert_eq!(l[0].held_in(1150 * 512, 100 * 512), 512);
        // Its parent's two blocks hold all the disk.
        assert_eq!(l[1].held_in(0, u64::MAX), 708_608);
        let d = open_path(&fixture("kids/fe-1.vhd")).unwrap();
        assert_eq!(d.held_in(0, 708_608), 708_608);
        assert_eq!(d.file_bytes(), 1_118_208 + 1_052_160);
    }

    // ---- Crafted VHDs, for the parent rules and damage. ----

    /// How a crafted differencing VHD names its parent.
    #[derive(Clone, Copy)]
    pub struct Parent<'a> {
        pub id: [u8; 16],
        pub w2ru: Option<&'a str>,
        pub w2ku: Option<&'a str>,
        pub name: &'a str,
    }

    fn crafted_footer(size: u64, kind: u32, id: [u8; 16]) -> [u8; 512] {
        let mut f = [0u8; 512];
        f[..8].copy_from_slice(b"conectix");
        f[8..12].copy_from_slice(&2u32.to_be_bytes());
        f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        f[16..24].copy_from_slice(&512u64.to_be_bytes());
        f[28..32].copy_from_slice(b"bzt ");
        f[36..40].copy_from_slice(b"Wi2k");
        f[40..48].copy_from_slice(&size.to_be_bytes());
        f[48..56].copy_from_slice(&size.to_be_bytes());
        f[60..64].copy_from_slice(&kind.to_be_bytes());
        f[68..84].copy_from_slice(&id);
        let sum = checksum(&f, 64);
        f[64..68].copy_from_slice(&sum.to_be_bytes());
        f
    }

    /// A dynamic VHD of `size` bytes in blocks of 4 KiB (with `parent`, a differencing one)
    /// holding `blocks`: (index, its bytes, the sectors present).
    pub fn crafted(
        size: u64,
        id: [u8; 16],
        parent: Option<&Parent>,
        blocks: &[(u32, Vec<u8>, Vec<u32>)],
    ) -> Vec<u8> {
        const BLOCK: u64 = 4096;
        let count = size.div_ceil(BLOCK);
        let table = 1536u64;
        let bat_len = (count * 4).div_ceil(512) * 512;
        let mut locs = Vec::new();
        let mut h = [0u8; 1024];
        h[..8].copy_from_slice(b"cxsparse");
        h[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        h[16..24].copy_from_slice(&table.to_be_bytes());
        h[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        h[28..32].copy_from_slice(&(count as u32).to_be_bytes());
        h[32..36].copy_from_slice(&(BLOCK as u32).to_be_bytes());
        if let Some(p) = parent {
            h[40..56].copy_from_slice(&p.id);
            let name: Vec<u8> = p.name.encode_utf16().flat_map(u16::to_be_bytes).collect();
            let n = name.len().min(512);
            h[64..64 + n].copy_from_slice(&name[..n]);
            let mut at = table + bat_len;
            for (i, (code, val)) in [(b"W2ru", p.w2ru), (b"W2ku", p.w2ku)]
                .into_iter()
                .enumerate()
            {
                let Some(val) = val else {
                    continue;
                };
                let raw: Vec<u8> = val.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let space = (raw.len() as u64).div_ceil(512) * 512;
                let e = &mut h[576 + 24 * i..600 + 24 * i];
                e[..4].copy_from_slice(code);
                e[4..8].copy_from_slice(&(space as u32).to_be_bytes());
                e[8..12].copy_from_slice(&(raw.len() as u32).to_be_bytes());
                e[16..24].copy_from_slice(&at.to_be_bytes());
                locs.extend_from_slice(&raw);
                locs.resize((at + space - table - bat_len) as usize, 0);
                at += space;
            }
        }
        let sum = checksum(&h, 36);
        h[36..40].copy_from_slice(&sum.to_be_bytes());
        let mut bat = vec![0xFFu8; (count * 4) as usize];
        bat.resize(bat_len as usize, 0);
        let mut data = Vec::new();
        let mut at = table + bat_len + locs.len() as u64;
        for (i, bytes, present) in blocks {
            let i = *i as usize;
            bat[i * 4..i * 4 + 4].copy_from_slice(&((at / 512) as u32).to_be_bytes());
            let mut bitmap = [0u8; 512];
            for &s in present {
                bitmap[s as usize / 8] |= 0x80 >> (s % 8);
            }
            data.extend_from_slice(&bitmap);
            let mut b = bytes.clone();
            b.resize(BLOCK as usize, 0);
            data.extend_from_slice(&b);
            at += 512 + BLOCK;
        }
        let kind = if parent.is_some() { 4 } else { 3 };
        let f = crafted_footer(size, kind, id);
        let mut out = Vec::new();
        out.extend_from_slice(&f);
        out.extend_from_slice(&h);
        out.extend_from_slice(&bat);
        out.extend_from_slice(&locs);
        out.extend_from_slice(&data);
        out.extend_from_slice(&f);
        out
    }

    pub fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    /// A base disk of 64 KiB whose block 0 is `0x11`s, and a child of it, by `parent`, whose
    /// block 0 has sector 1 of `0x22`s.
    fn pair(dir: &Path, base: &str, child: &str, parent: &Parent) {
        for f in [base, child] {
            std::fs::create_dir_all(dir.join(f).parent().unwrap()).unwrap();
        }
        let b = crafted(65536, id(1), None, &[(0, vec![0x11; 4096], vec![])]);
        std::fs::write(dir.join(base), b).unwrap();
        let mut blk = vec![0xEE; 4096];
        blk[512..1024].fill(0x22);
        let c = crafted(65536, id(2), Some(parent), &[(0, blk, vec![1])]);
        std::fs::write(dir.join(child), c).unwrap();
    }

    /// The child's first 2 KiB read through its chain.
    fn first_sectors(path: &Path) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut d = open_path(path)?;
        let mut b = vec![0u8; 2048];
        d.read_exact(&mut b).unwrap();
        Ok(b)
    }

    /// Sector 1 is the child's, and the rest its parent's.
    fn expect_chain(path: &Path) {
        let b = first_sectors(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(b[..512].iter().all(|&x| x == 0x11));
        assert!(b[512..1024].iter().all(|&x| x == 0x22));
        assert!(b[1024..].iter().all(|&x| x == 0x11));
    }

    #[test]
    fn a_parent_is_found_by_its_relative_path_beside_or_absolute() {
        let t = tempfile::tempdir().unwrap();
        // `..\parents\base.vhd`, which 7-Zip doesn't follow.
        let p = Parent {
            id: id(1),
            w2ru: Some(r"..\parents\base.vhd"),
            w2ku: Some(r"C:\BeeZip\nowhere\base.vhd"),
            name: r"C:\BeeZip\nowhere\base.vhd",
        };
        pair(t.path(), "parents/base.vhd", "kids/child.vhd", &p);
        expect_chain(&t.path().join("kids/child.vhd"));
        // Beside it, the relative path leading nowhere.
        let p = Parent {
            w2ru: Some(r"..\nowhere\base.vhd"),
            ..p
        };
        pair(t.path(), "beside/base.vhd", "beside/child.vhd", &p);
        expect_chain(&t.path().join("beside/child.vhd"));
        // By its absolute path, elsewhere on a local drive.
        let other = tempfile::tempdir().unwrap();
        let abs = other.path().join("base.vhd");
        let p = Parent {
            w2ru: Some(r"..\nowhere\elsewhere.vhd"),
            w2ku: abs.to_str(),
            name: "elsewhere.vhd",
            ..p
        };
        pair(other.path(), "base.vhd", "unused.vhd", &p);
        pair(t.path(), "abs/unused.vhd", "abs/child.vhd", &p);
        std::fs::remove_file(t.path().join("abs/unused.vhd")).unwrap();
        expect_chain(&t.path().join("abs/child.vhd"));
    }

    #[test]
    fn a_missing_or_changed_parent_is_not_found() {
        let t = tempfile::tempdir().unwrap();
        let p = Parent {
            id: id(1),
            w2ru: Some(r"..\parents\base.vhd"),
            w2ku: Some(r"C:\BeeZip\nowhere\base.vhd"),
            name: r"C:\BeeZip\nowhere\base.vhd",
        };
        pair(t.path(), "parents/base.vhd", "kids/child.vhd", &p);
        std::fs::remove_file(t.path().join("parents/base.vhd")).unwrap();
        let e = first_sectors(&t.path().join("kids/child.vhd")).unwrap_err();
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(e.message.contains("child.vhd"), "{e}");
        assert!(e.message.contains("its relative path"), "{e}");
        assert!(e.message.contains("not there"), "{e}");
        // A disk of the parent's name beside it, made after: another unique id.
        let other = crafted(65536, id(9), None, &[]);
        std::fs::write(t.path().join("kids/base.vhd"), other).unwrap();
        let e = first_sectors(&t.path().join("kids/child.vhd")).unwrap_err();
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(
            e.message.contains("it changed after this disk was made"),
            "{e}"
        );
        // A VHDX of the parent's name is passed over too.
        std::fs::copy(fixture("parents/odd.vhdx"), t.path().join("kids/base.vhd")).unwrap();
        let e = first_sectors(&t.path().join("kids/child.vhd")).unwrap_err();
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(e.message.contains("a VHD's parent must be a VHD"), "{e}");
    }

    #[test]
    fn loops_and_network_parents_are_refused() {
        let t = tempfile::tempdir().unwrap();
        let named = |me: u8, other: &str| {
            let name = format!(r".\{other}");
            crafted(
                65536,
                id(me),
                Some(&Parent {
                    id: id(if me == 1 { 2 } else { 1 }),
                    w2ru: Some(&name),
                    w2ku: None,
                    name: other,
                }),
                &[],
            )
        };
        std::fs::write(t.path().join("a.vhd"), named(1, "b.vhd")).unwrap();
        std::fs::write(t.path().join("b.vhd"), named(2, "a.vhd")).unwrap();
        let e = open_path(&t.path().join("a.vhd")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
        assert!(e.message.contains("loops"), "{e}");
        let me = crafted(
            65536,
            id(3),
            Some(&Parent {
                id: id(3),
                w2ru: Some(r".\self.vhd"),
                w2ku: None,
                name: "self.vhd",
            }),
            &[],
        );
        std::fs::write(t.path().join("self.vhd"), me).unwrap();
        let e = open_path(&t.path().join("self.vhd")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
        let unc = r"\\beezip.invalid\share\base.vhd";
        let c = crafted(
            65536,
            id(4),
            Some(&Parent {
                id: id(5),
                w2ru: Some(unc),
                w2ku: Some(unc),
                name: unc,
            }),
            &[],
        );
        std::fs::write(t.path().join("unc.vhd"), c).unwrap();
        let e = open_path(&t.path().join("unc.vhd")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Unsafe, "{e}");
    }

    /// A chain of 64 levels opens and reads through every level; one of 65 is refused.
    #[test]
    fn a_chain_deeper_than_64_is_refused() {
        use std::io::Read;
        let t = tempfile::tempdir().unwrap();
        let name = |i: u8| format!("d{i:02}.vhd");
        std::fs::write(
            t.path().join(name(0)),
            crafted(65536, id(100), None, &[(0, vec![0xAA; 4096], vec![])]),
        )
        .unwrap();
        for i in 1..=64u8 {
            let rel = format!(r".\{}", name(i - 1));
            // Level i holds sector i % 8 of block 0, and block i.
            let c = crafted(
                65536,
                id(100 + i),
                Some(&Parent {
                    id: id(100 + i - 1),
                    w2ru: Some(&rel),
                    w2ku: None,
                    name: &name(i - 1),
                }),
                &[
                    (0, vec![i; 4096], vec![u32::from(i % 8)]),
                    (u32::from(i % 16), vec![i; 4096], (0..8).collect()),
                ],
            );
            std::fs::write(t.path().join(name(i)), c).unwrap();
        }
        let mut d = open_path(&t.path().join(name(63))).unwrap();
        assert_eq!(d.depth(), 64);
        let mut b = vec![0u8; 65536];
        d.read_exact(&mut b).unwrap();
        // Sector k of block 0 is the topmost level i with i % 8 == k (levels 16, 32 and 48
        // hold all of block 0, below those); block b is the topmost with i % 16 == b.
        assert_eq!(b[0], 56);
        assert_eq!(b[512 * 7], 63);
        assert_eq!(b[4096], 49);
        let e = open_path(&t.path().join(name(64))).err().unwrap();
        assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    }

    /// A damaged footer at the end: the copy at the start, with a note. Other damage, and what
    /// BeeZip doesn't read.
    #[test]
    fn damage_and_variants_refused() {
        let base = crafted(65536, id(1), None, &[(0, vec![0x11; 4096], vec![])]);
        let t = tempfile::tempdir().unwrap();
        let try_open = |name: &str, b: &[u8]| {
            let p = t.path().join(name);
            std::fs::write(&p, b).unwrap();
            open_path(&p)
        };
        let mut b = base.clone();
        let n = b.len();
        b[n - 100] ^= 1;
        let d = try_open("copy.vhd", &b).unwrap();
        assert!(d.notes()[0].contains("its copy at the start was used"));
        // A block table entry past the file's end: zeros, noted.
        let mut b = base.clone();
        b[1536..1540].copy_from_slice(&0x0010_0000u32.to_be_bytes());
        let mut d = try_open("past.vhd", &b).unwrap();
        assert!(d.notes()[0].contains("1 of past.vhd's blocks lie past its end"));
        assert_eq!(sha256(&mut d), sha256_of(&[0u8; 65536]));
        // The footer's version, the header's version, its block size.
        let refit = |b: &mut Vec<u8>| {
            for at in [0, b.len() - 512] {
                let mut f: [u8; 512] = b[at..at + 512].try_into().unwrap();
                let s = checksum(&f, 64);
                f[64..68].copy_from_slice(&s.to_be_bytes());
                b[at..at + 512].copy_from_slice(&f);
            }
            let mut h: [u8; 1024] = b[512..1536].try_into().unwrap();
            let s = checksum(&h, 36);
            h[36..40].copy_from_slice(&s.to_be_bytes());
            b[512..1536].copy_from_slice(&h);
        };
        // Read as 7-Zip reads them (docs/M11.md §6.1): versions other than 1.0, the footer's
        // noted; blocks of 512 MiB, whose 128 KiB sector bitmap leaves block 0's data past the
        // file's end, so the disk reads as zeros.
        let want = sha256_of(&[vec![0x11; 4096], vec![0; 61440]].concat());
        let mut b = base.clone();
        let n = b.len();
        b[n - 512 + 12..n - 512 + 16].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        b[12..16].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        refit(&mut b);
        let mut d = try_open("v2.vhd", &b).unwrap();
        assert!(d.notes()[0].contains("says version 2.0"), "{:?}", d.notes());
        assert_eq!(sha256(&mut d), want);
        let mut b = base.clone();
        b[512 + 24..512 + 28].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        refit(&mut b);
        assert_eq!(sha256(&mut try_open("h2.vhd", &b).unwrap()), want);
        let mut b = base.clone();
        b[512 + 32..512 + 36].copy_from_slice(&(512u32 << 20).to_be_bytes());
        refit(&mut b);
        let mut d = try_open("big.vhd", &b).unwrap();
        assert!(d.notes()[0].contains("lie past its end"), "{:?}", d.notes());
        assert_eq!(sha256(&mut d), sha256_of(&[0u8; 65536]));
        let mut b = base.clone();
        b[512 + 32..512 + 36].copy_from_slice(&3000u32.to_be_bytes());
        refit(&mut b);
        let e = try_open("odd.vhd", &b).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
        let mut b = base.clone();
        b[512] = b'x';
        let e = try_open("hdr.vhd", &b).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
        let e = try_open("none.vhd", &[0u8; 600]).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    }

    /// A block table of 2^24 + 1 entries, over the 2^24 BeeZip read whole until M11 (docs/M11.md
    /// §6.1), read a page at a time: its first and last blocks.
    #[test]
    fn a_block_table_over_2_24_entries_is_read_in_pages() {
        use std::io::{Read, Seek, SeekFrom};
        let count = (1u64 << 24) + 1;
        let size = count * 4096;
        let b = crafted(
            size,
            id(9),
            None,
            &[
                (0, vec![0x5A; 4096], vec![]),
                ((count - 1) as u32, vec![0xA5; 4096], vec![]),
            ],
        );
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("wide.vhd");
        std::fs::write(&p, &b).unwrap();
        drop(b);
        let mut d = open_path(&p).unwrap();
        let mut buf = vec![0u8; 4096];
        for (at, byte) in [(0, 0x5A), (size - 4096, 0xA5), (size / 2, 0)] {
            d.seek(SeekFrom::Start(at)).unwrap();
            d.read_exact(&mut buf).unwrap();
            assert!(buf.iter().all(|&x| x == byte), "at {at}");
        }
        assert_eq!(d.held_in(0, size), 8192);
    }

    /// The VHDs `make-vdisk.sh` crafts in `thirdparty/vdisk/` from `fat-dyn.vhd` and
    /// `fat-fixed.vhd`, which 7-Zip reads and BeeZip refused until M11 (docs/M11.md §6.1): a
    /// footer and a dynamic header of version 2.0, a block of 512 MiB. Each reads as their disk.
    #[test]
    fn variants_read_as_their_disks() {
        super::super::testing::check_all(&[".vhd"]);
        // Detected as what they are, as M11's other variants there are (docs/M11.md §6.1).
        let dir = super::super::testing::dir();
        for (f, kind) in [
            ("h-footer-v2.vhd", External::Vhd),
            ("h-dynhdr-v2.vhd", External::Vhd),
            ("h-block512m.vhd", External::Vhd),
            ("q-v1.qcow", External::Qcow2),
            ("q-v1-c.qcow", External::Qcow2),
            ("q-v1-child.qcow", External::Qcow2),
            ("v-grain2m.vmdk", External::Vmdk),
            ("v-vmfsraw.vmdk", External::Vmdk),
            ("d-undo.vdi", External::Vdi),
        ] {
            let det = crate::detect_path(&dir.join(f), &crate::Limits::default()).unwrap();
            assert_eq!(
                det.format(),
                Some(crate::format::FormatId::External(kind)),
                "{f}"
            );
        }
    }

    /// Bytes of the fixtures changed at random: each opens and reads cleanly, or fails cleanly.
    #[test]
    fn mutated_fixtures_never_panic() {
        mutate(&["fat-dyn.vhd", "odd.vhd", "kids/fe-1.vhd"], 150);
    }

    /// Opens `n` mutations (`BEEZIP_VDISK_MUTATIONS` for a longer run) of each of `names`, in a
    /// copy of the fixtures so that a child finds its parents, and reads their disks, at most
    /// 16 MiB of each, then what's inside them.
    pub fn mutate(names: &[&str], n: u32) {
        use std::io::Read;
        let n = std::env::var("BEEZIP_VDISK_MUTATIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(n);
        let t = tempfile::tempdir().unwrap();
        for dir in ["parents", "kids"] {
            std::fs::create_dir_all(t.path().join(dir)).unwrap();
        }
        for e in walk(&fixture("")) {
            let rel = e.strip_prefix(fixture("")).unwrap().to_owned();
            std::fs::copy(&e, t.path().join(&rel)).unwrap();
        }
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for name in names {
            let orig = std::fs::read(fixture(name)).unwrap();
            let path = t.path().join(name);
            for _ in 0..n {
                let mut b = orig.clone();
                // A few bytes in the first 4 MiB (the headers and tables), or anywhere.
                for _ in 0..1 + next() % 8 {
                    let span = if next() % 4 == 0 {
                        b.len()
                    } else {
                        b.len().min(4 << 20)
                    };
                    let at = (next() % span as u64) as usize;
                    b[at] = match next() % 3 {
                        0 => 0xFF,
                        1 => 0,
                        _ => next() as u8,
                    };
                }
                if next() % 16 == 0 {
                    b.truncate((next() % b.len() as u64) as usize);
                }
                std::fs::write(&path, &b).unwrap();
                if let Ok(mut d) = open_path(&path) {
                    let _ = d.properties();
                    let _ = d.held_in(0, u64::MAX);
                    let mut buf = vec![0u8; 65536];
                    let mut left = 16u64 << 20;
                    while left > 0 {
                        match d.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(k) => left = left.saturating_sub(k as u64),
                        }
                    }
                }
                through_disk_reader(&path);
            }
            std::fs::write(&path, &orig).unwrap();
        }
    }

    /// What the fuzz targets do with a disk: `DiskReader` opens it and what's inside, under
    /// their tight limits, and extracts everything into a sink that keeps nothing.
    fn through_disk_reader(path: &Path) {
        use crate::{ArchiveReader, Limits, NullSink, OpenOptions, Selection, SimpleCtx};
        let opts = OpenOptions::new(Limits {
            max_ratio: Some(200),
            ratio_grace: 1 << 20,
            max_total_bytes: Some(32 << 20),
            max_entries: Some(10_000),
            max_layers: 4,
            decoder_memory: 64 << 20,
        });
        let Ok(source) = crate::source::Source::new(path, Vec::new(), &opts) else {
            return;
        };
        let mut cx = SimpleCtx::new();
        if let Ok(mut r) = crate::format::volume::DiskReader::open(source, kind(path), &mut cx) {
            let _ = r.entries(&mut cx);
            let _ = r.info(&mut cx);
            let _ = r.extract(&Selection::all(), &mut NullSink::default(), &mut cx);
        }
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }
}
