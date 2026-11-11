//! Partition tables (docs/M7.md §3): GPT and MBR, BeeZip's own (fstool reads GPT at 512-byte
//! sectors and MBR's primary entries only, and no backup GPT header).
//!
//! - **GPT:** the header is looked for at 512 and at 4096 bytes, since a disk of 4 KiB sectors
//!   has it at 4096. It must say `EFI PART`, revision 1.0, its own sector and a size up to a
//!   sector, with its CRC. The entry array holds at most [`MAX_GPT_ENTRIES`] entries of a power
//!   of two from 128 bytes to a sector, inside the disk and with its CRC. When the primary header
//!   or its array fails, the backup header in the disk's last sector is used instead, with a
//!   warning.
//! - **MBR:** the four primary entries, then the extended partition's chain of EBRs. Each link
//!   must go forward on the disk, as mbrman requires, so a chain can't loop; it stops at
//!   [`MAX_LOGICAL`] logical partitions. The extended partition itself isn't listed. Its sectors
//!   are the device's: 4096 bytes in a virtual disk of 4 KiB sectors, else 512 (docs/M8.md §3.8).
//! - **Names** are as 7-Zip names the partitions, without the extension: the index among those
//!   listed, padded to the widest, then GPT's partition name (`0.data`). Logical partitions follow
//!   the primary ones in that numbering, as 7-Zip numbers them.
//! - A partition that starts past the image's end is left out with a warning; one that ends past
//!   it is read with zeros there, with a warning ([`super::DiskReader`]).

use fstool::block::BlockDevice;

use super::Device;
use crate::{Ctx, Error, Result, backend::External};

/// The most GPT entries read, as fstool bounds them.
pub const MAX_GPT_ENTRIES: u32 = 4096;
/// The most logical partitions an MBR disk's chain of EBRs gives.
pub const MAX_LOGICAL: usize = 256;

/// A disk's partition table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    /// GPT or MBR.
    pub scheme: External,
    /// The sector size the table is in.
    pub sector: u64,
    pub partitions: Vec<Partition>,
}

/// A partition, in bytes from the disk's start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// As 7-Zip names it, without the extension: `0.data`, `1`.
    pub name: String,
    pub start: u64,
    pub len: u64,
}

/// The extension of a partition listed as a file, from the file system found in it: as 7-Zip
/// names them (`0.data.fat`, `1.linux.img`).
pub fn extension(fs: Option<External>) -> &'static str {
    match fs {
        Some(External::Fat) => "fat",
        Some(External::Ntfs) => "ntfs",
        Some(External::Hfs) => "hfs",
        Some(External::Apfs) => "apfs",
        _ => "img",
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or_default())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default())
}

/// The disk's partition table: GPT when a header checks out, otherwise MBR.
pub fn read(dev: &Device, cx: &mut dyn Ctx) -> Result<Table> {
    let mut dev = dev.clone();
    if let Some(t) = gpt(&mut dev, cx)? {
        return Ok(t);
    }
    mbr(&mut dev, cx)
}

/// What one GPT header says, once checked.
struct Header {
    entries_lba: u64,
    count: u32,
    entry_size: u32,
    array_crc: u32,
}

/// The GPT header at sector `lba` for sectors of `sector` bytes, if it checks out.
fn header(dev: &mut Device, sector: u64, lba: u64) -> Option<Header> {
    let at = lba.checked_mul(sector)?;
    let mut h = vec![0u8; usize::try_from(sector).ok()?];
    dev.read_exact_at(at, &mut h).ok()?;
    let size = usize::try_from(le32(&h, 12)).ok()?;
    if !h.starts_with(b"EFI PART")
        || le32(&h, 8) != 0x0001_0000
        || !(92..=h.len()).contains(&size)
        || le64(&h, 24) != lba
    {
        return None;
    }
    let mut crc = crc32fast::Hasher::new();
    crc.update(&h[..16]);
    crc.update(&[0; 4]);
    crc.update(&h[20..size]);
    if crc.finalize() != le32(&h, 16) {
        return None;
    }
    Some(Header {
        entries_lba: le64(&h, 72),
        count: le32(&h, 80),
        entry_size: le32(&h, 84),
        array_crc: le32(&h, 88),
    })
}

/// The entry array `h` points to, if it's bounded, inside the disk and matches its CRC.
fn array(dev: &mut Device, sector: u64, h: &Header) -> Option<Vec<u8>> {
    let size = u64::from(h.entry_size);
    if h.count == 0
        || h.count > MAX_GPT_ENTRIES
        || !size.is_power_of_two()
        || !(128..=sector).contains(&size)
    {
        return None;
    }
    let len = u64::from(h.count) * size;
    let at = h.entries_lba.checked_mul(sector)?;
    if at.checked_add(len)? > dev.real_len() {
        return None;
    }
    let mut a = vec![0u8; usize::try_from(len).ok()?];
    dev.read_exact_at(at, &mut a).ok()?;
    (crc32fast::hash(&a) == h.array_crc).then_some(a)
}

/// A GPT table: the primary header at 512 or 4096 bytes, else a backup.
fn gpt(dev: &mut Device, cx: &mut dyn Ctx) -> Result<Option<Table>> {
    for sector in [512u64, 4096] {
        if let Some(h) = header(dev, sector, 1)
            && let Some(a) = array(dev, sector, &h)
        {
            return gpt_table(dev, sector, &h, &a, cx).map(Some);
        }
    }
    for sector in [512u64, 4096] {
        let last = dev.real_len() / sector;
        if last < 2 {
            continue;
        }
        if let Some(h) = header(dev, sector, last - 1)
            && let Some(a) = array(dev, sector, &h)
        {
            cx.warn(
                "the disk's GPT header is damaged; its backup at the disk's end is read instead"
                    .to_owned(),
            );
            return gpt_table(dev, sector, &h, &a, cx).map(Some);
        }
    }
    Ok(None)
}

/// A GPT partition's name, as stored in UTF-16 up to its first NUL; an unpaired surrogate
/// becomes U+FFFD, and a slash or a control character `_`, so the name stays one folder.
fn gpt_name(b: &[u8]) -> String {
    let units = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&u| u != 0);
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn gpt_table(
    dev: &Device,
    sector: u64,
    h: &Header,
    array: &[u8],
    cx: &mut dyn Ctx,
) -> Result<Table> {
    let size = usize::try_from(h.entry_size).map_err(|_| Error::corrupt("GPT: entry size"))?;
    let mut found = Vec::new();
    for e in array.chunks_exact(size) {
        if e[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let (first, last) = (le64(e, 32), le64(e, 40));
        let name = gpt_name(&e[56..128]);
        let span = last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(sector))
            .zip(first.checked_mul(sector));
        match span {
            Some((len, start)) if start < dev.real_len() => found.push((name, start, len)),
            _ => cx.warn(format!(
                "GPT partition `{name}` (sectors {first} to {last}) isn't on the disk; it's left \
                 out"
            )),
        }
    }
    Ok(Table {
        scheme: External::Gpt,
        sector,
        partitions: named(found),
    })
}

/// The partitions with their names: the index, padded to the widest, and the name if any.
fn named(found: Vec<(String, u64, u64)>) -> Vec<Partition> {
    let width = found.len().saturating_sub(1).to_string().len();
    found
        .into_iter()
        .enumerate()
        .map(|(i, (name, start, len))| Partition {
            name: if name.is_empty() {
                format!("{i:0width$}")
            } else {
                format!("{i:0width$}.{name}")
            },
            start,
            len,
        })
        .collect()
}

/// An MBR partition entry: its type and its sectors, from the sector it's relative to.
fn mbr_entry(e: &[u8]) -> (u8, u64, u64) {
    (e[4], u64::from(le32(e, 8)), u64::from(le32(e, 12)))
}

fn is_extended(t: u8) -> bool {
    matches!(t, 0x05 | 0x0F | 0x85)
}

/// An MBR table: the primary entries, then the extended partition's logical ones.
fn mbr(dev: &mut Device, cx: &mut dyn Ctx) -> Result<Table> {
    let sector = if dev.block_size() == 4096 { 4096 } else { 512 };
    let mut s = [0u8; 512];
    dev.read_exact_at(0, &mut s)?;
    if le16(&s, 510) != 0xAA55 {
        return Err(Error::corrupt("the disk has no partition table"));
    }
    let sectors = dev.real_len() / sector;
    let mut found = Vec::new();
    let mut extended = None;
    let mut protective = false;
    for e in s[446..510].as_chunks::<16>().0 {
        let (t, start, count) = mbr_entry(e);
        if t == 0 || count == 0 {
            continue;
        }
        if t == 0xEE {
            protective = true;
        } else if is_extended(t) {
            if extended.is_none() {
                extended = Some((start, count));
            }
        } else {
            found.push((String::new(), start, count));
        }
    }
    if let Some((ext_start, ext_count)) = extended {
        logical(dev, sector, ext_start, ext_count, &mut found, cx);
    }
    if found.is_empty() && protective {
        return Err(Error::corrupt(
            "the disk's GPT headers and their backup are damaged",
        ));
    }
    let mut kept = Vec::new();
    for (name, start, count) in found {
        if start >= sectors {
            cx.warn(format!(
                "an MBR partition at sector {start} isn't on the disk; it's left out"
            ));
        } else {
            kept.push((name, start * sector, count * sector));
        }
    }
    Ok(Table {
        scheme: External::Mbr,
        sector,
        partitions: named(kept),
    })
}

/// The logical partitions of the extended partition at `ext_start`: a chain of EBRs, each with a
/// partition (relative to the EBR) and a link to the next (relative to the extended partition).
/// Links must go forward and stay inside the extended partition.
fn logical(
    dev: &mut Device,
    sector: u64,
    ext_start: u64,
    ext_count: u64,
    found: &mut Vec<(String, u64, u64)>,
    cx: &mut dyn Ctx,
) {
    let ext_end = ext_start.saturating_add(ext_count);
    let mut ebr = ext_start;
    for _ in 0..MAX_LOGICAL {
        let mut s = [0u8; 512];
        if dev
            .read_exact_at(ebr.saturating_mul(sector), &mut s)
            .is_err()
            || le16(&s, 510) != 0xAA55
        {
            cx.warn(format!(
                "the extended partition's chain ends at sector {ebr}, which isn't an EBR"
            ));
            return;
        }
        let (t, rel, count) = mbr_entry(&s[446..462]);
        if t != 0 && count != 0 && !is_extended(t) {
            found.push((String::new(), ebr + rel, count));
        }
        let (t, next, _) = mbr_entry(&s[462..478]);
        if !is_extended(t) || next == 0 {
            return;
        }
        let next = ext_start.saturating_add(next);
        if next <= ebr || next >= ext_end {
            cx.warn(format!(
                "the extended partition's chain goes back from sector {ebr} to {next}; it ends \
                 there"
            ));
            return;
        }
        ebr = next;
    }
    cx.warn(format!(
        "the extended partition has more than {MAX_LOGICAL} logical partitions; the rest are \
         left out"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimpleCtx;

    fn dev(bytes: Vec<u8>) -> Device {
        let len = bytes.len() as u64;
        Device::new(Box::new(std::io::Cursor::new(bytes)), len)
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// A GPT disk of `sectors` sectors of `sector` bytes, with `parts` (name, first, last), and
    /// its backup header and array at the end.
    fn gpt_disk(sector: usize, sectors: usize, parts: &[(&str, u64, u64)]) -> Vec<u8> {
        let mut d = vec![0u8; sector * sectors];
        d[510] = 0x55;
        d[511] = 0xAA;
        d[446 + 4] = 0xEE;
        put32(&mut d, 446 + 8, 1);
        put32(&mut d, 446 + 12, (sectors - 1) as u32);
        let mut array = vec![0u8; 128 * 128];
        for (i, (name, first, last)) in parts.iter().enumerate() {
            let e = &mut array[i * 128..(i + 1) * 128];
            e[0] = 0xAF; // any type
            e[16] = i as u8 + 1;
            put64(e, 32, *first);
            put64(e, 40, *last);
            for (k, u) in name.encode_utf16().enumerate() {
                e[56 + 2 * k..58 + 2 * k].copy_from_slice(&u.to_le_bytes());
            }
        }
        let array_sectors = array.len().div_ceil(sector);
        let crc = crc32fast::hash(&array);
        let last = (sectors - 1) as u64;
        for (my, entries) in [(1u64, 2u64), (last, last - array_sectors as u64)] {
            let mut h = vec![0u8; 92];
            h[..8].copy_from_slice(b"EFI PART");
            put32(&mut h, 8, 0x0001_0000);
            put32(&mut h, 12, 92);
            put64(&mut h, 24, my);
            put64(&mut h, 72, entries);
            put32(&mut h, 80, 128);
            put32(&mut h, 84, 128);
            put32(&mut h, 88, crc);
            let c = crc32fast::hash(&h);
            put32(&mut h, 16, c);
            let at = my as usize * sector;
            d[at..at + 92].copy_from_slice(&h);
            let at = entries as usize * sector;
            d[at..at + array.len()].copy_from_slice(&array);
        }
        d
    }

    #[test]
    fn gpt_at_512_and_4096() {
        let mut cx = SimpleCtx::default();
        for sector in [512usize, 4096] {
            let disk = gpt_disk(sector, 64, &[("data", 40, 47), ("", 48, 49)]);
            let t = read(&dev(disk), &mut cx).unwrap();
            assert_eq!(t.scheme, External::Gpt);
            assert_eq!(t.sector, sector as u64);
            let s = sector as u64;
            assert_eq!(
                t.partitions,
                [
                    Partition {
                        name: "0.data".into(),
                        start: 40 * s,
                        len: 8 * s
                    },
                    Partition {
                        name: "1".into(),
                        start: 48 * s,
                        len: 2 * s
                    },
                ]
            );
        }
    }

    #[test]
    fn gpt_backup_when_the_primary_is_damaged() {
        let mut disk = gpt_disk(512, 64, &[("a/b", 40, 47)]);
        disk[512 + 16] ^= 1; // the primary header's CRC
        let mut cx = SimpleCtx::default();
        let t = read(&dev(disk), &mut cx).unwrap();
        assert_eq!(t.partitions[0].name, "0.a_b");
    }

    #[test]
    fn gpt_tables_too_large_are_refused() {
        let mut disk = gpt_disk(512, 64, &[("x", 40, 47)]);
        for at in [512usize, 63 * 512] {
            put32(&mut disk, at + 80, u32::MAX);
            disk[at + 16..at + 20].fill(0);
            let c = crc32fast::hash(&disk[at..at + 92]);
            put32(&mut disk, at + 16, c);
        }
        let mut cx = SimpleCtx::default();
        // No GPT: the protective MBR alone is refused.
        assert!(read(&dev(disk), &mut cx).is_err());
    }

    fn mbr_disk() -> Vec<u8> {
        let mut d = vec![0u8; 512 * 400];
        d[510] = 0x55;
        d[511] = 0xAA;
        let entry = |d: &mut [u8], at: usize, t: u8, start: u32, count: u32| {
            d[at + 4] = t;
            put32(d, at + 8, start);
            put32(d, at + 12, count);
        };
        entry(&mut d, 446, 0x0C, 10, 20);
        entry(&mut d, 462, 0x05, 100, 300);
        // EBR 1 at 100: a partition at 100+5, a link to 100+50.
        let e1 = 100 * 512;
        d[e1 + 510] = 0x55;
        d[e1 + 511] = 0xAA;
        entry(&mut d, e1 + 446, 0x83, 5, 10);
        entry(&mut d, e1 + 462, 0x05, 50, 60);
        let e2 = 150 * 512;
        d[e2 + 510] = 0x55;
        d[e2 + 511] = 0xAA;
        entry(&mut d, e2 + 446, 0x07, 2, 30);
        d
    }

    #[test]
    fn mbr_with_logical_partitions() {
        let mut cx = SimpleCtx::default();
        let t = read(&dev(mbr_disk()), &mut cx).unwrap();
        assert_eq!(t.scheme, External::Mbr);
        let spans: Vec<_> = t
            .partitions
            .iter()
            .map(|p| (p.name.as_str(), p.start / 512, p.len / 512))
            .collect();
        assert_eq!(spans, [("0", 10, 20), ("1", 105, 10), ("2", 152, 30)]);
    }

    #[test]
    fn an_ebr_chain_that_goes_back_ends() {
        let mut disk = mbr_disk();
        // EBR 2 links back to EBR 1, and EBR 1 to itself in a second disk.
        let e2 = 150 * 512;
        disk[e2 + 462 + 4] = 0x05;
        put32(&mut disk, e2 + 462 + 8, 1);
        let mut cx = SimpleCtx::default();
        assert_eq!(
            read(&dev(disk.clone()), &mut cx).unwrap().partitions.len(),
            3
        );
        let e1 = 100 * 512;
        put32(&mut disk, e1 + 462 + 8, 0);
        // A link of 0 ends the chain.
        assert_eq!(read(&dev(disk), &mut cx).unwrap().partitions.len(), 2);
    }
}
