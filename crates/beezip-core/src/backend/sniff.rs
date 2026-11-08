//! BeeZip's own sniffers for the formats the 7-Zip backend reads, with 7-Zip's signatures
//! (docs/M6.md §3.2), so `file.detect` names them whether or not 7-Zip is installed.
//!
//! Each checks the structure around its magic. A long magic at a fixed place (WIM's
//! `MSWIM\0\0\0`, QCOW's `QFI\xFB`) is `Certain` with its structure and `Likely` without, so a
//! damaged image still opens, to be refused with a reason. A short or common one (ext's
//! `53 EF`, a boot sector's `55 AA`) claims nothing without its structure.
//!
//! The partitioned disks (GPT, MBR) are never more than `Likely`, so they rank below ISO and the
//! file systems, which can hold a partition table too: an isohybrid ISO is an ISO, and a FAT
//! floppy's boot sector isn't an MBR disk. A GPT disk's protective MBR is GPT's.
//!
//! Nothing here may panic, whatever the bytes: the fuzzers reach it through detection.

use super::External;
use crate::detect::{Confidence, Probe};

/// Whether `probe` holds `kind`, and how sure that is.
pub fn sniff(kind: External, probe: &Probe<'_>) -> Option<Confidence> {
    let h = probe.head;
    match kind {
        External::Wim => wim(h),
        External::Chm => chm(h),
        External::Msi => msi(probe),
        // Found at an executable's overlay, by [`nsis_header`].
        External::Nsis => None,
        External::Vhdx => vhdx(h),
        External::Vhd => vhd(probe),
        External::Vmdk => vmdk(h),
        External::Qcow2 => qcow(h),
        External::Vdi => vdi(h),
        External::Fat => fat(h),
        External::Ntfs => ntfs(h),
        External::Ext => ext(h),
        External::Hfs => hfs(h),
        External::Apfs => apfs(h),
        External::Cramfs => cramfs(h),
        External::Gpt => gpt(h),
        External::Mbr => mbr(probe),
    }
}

/// NSIS's first header at the start of `start`: flags NSIS knows (its `FH_FLAGS_MASK`, 0xF),
/// `EF BE AD DE` and `NullsoftInst`, then the length of the header and of everything after it.
/// NSIS's loader and 7-Zip look for it at 512-byte boundaries of the executable; installers
/// put it at the start of the PE overlay.
pub fn nsis_header(start: &[u8]) -> Option<Confidence> {
    let ok = le32(start, 0)? & !0xF == 0
        && start.get(4..20) == Some(b"\xEF\xBE\xAD\xDENullsoftInst")
        && le32(start, 20)? > 0
        && le32(start, 24)? > 28;
    ok.then_some(Confidence::Certain)
}

/// `Certain` when the structure around a magic checks out, `Likely` on the magic alone.
fn checked(structure: bool) -> Confidence {
    if structure {
        Confidence::Certain
    } else {
        Confidence::Likely
    }
}

/// `MSWIM\0\0\0`, then a 208-byte header of WIM 1.x or a solid ESD (0.14), a chunk size that is
/// 0 or a power of two from 4 KiB, and a part number within the part count (a split `.swm`).
fn wim(h: &[u8]) -> Option<Confidence> {
    if !h.starts_with(b"MSWIM\0\0\0") {
        return None;
    }
    let header = || {
        let version = le32(h, 12)?;
        let chunk = le32(h, 20)?;
        let (part, parts) = (le16(h, 40)?, le16(h, 42)?);
        Some(
            le32(h, 8)? == 208
                && (version == 0x0E00 || version >> 16 == 1)
                && (chunk == 0 || (chunk.is_power_of_two() && chunk >= 4096))
                && (1..=parts).contains(&part),
        )
    };
    Some(checked(header() == Some(true)))
}

/// `ITSF`, version 3 with its 0x60-byte header: what 7-Zip opens.
fn chm(h: &[u8]) -> Option<Confidence> {
    if !h.starts_with(b"ITSF") {
        return None;
    }
    Some(checked(le32(h, 4) == Some(3) && le32(h, 8) == Some(0x60)))
}

/// A Compound File's signature.
const COMPOUND: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
/// The root CLSID of a Windows Installer package, {000C1084-0000-0000-C000-000000000046}, as
/// stored. A merge module has it too: it is made as a package is.
const MSI_PACKAGE: &[u8] = b"\x84\x10\x0C\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46";
/// A patch's, {000C1086-0000-0000-C000-000000000046}.
const MSI_PATCH: &[u8] = b"\x86\x10\x0C\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46";

/// A Compound File (version 3 with 512-byte sectors, or 4 with 4 KiB ones) whose root entry,
/// the first in its first directory sector, is a root storage with an installer's CLSID. An
/// Office document has its own CLSID and isn't claimed. When that sector is in neither the head
/// nor the tail, an installer's extension makes it `Likely`.
fn msi(probe: &Probe<'_>) -> Option<Confidence> {
    let h = probe.head;
    if !h.starts_with(COMPOUND) || le16(h, 0x1C)? != 0xFFFE || le16(h, 0x20)? != 6 {
        return None;
    }
    let shift = match (le16(h, 0x1A)?, le16(h, 0x1E)?) {
        (3, 9) => 9,
        (4, 12) => 12,
        _ => return None,
    };
    // Sectors from 0xFFFFFFFA up are markers, not places.
    let dir = le32(h, 0x30)?;
    if dir >= 0xFFFF_FFFA {
        return None;
    }
    match bytes_at(probe, (u64::from(dir) + 1) << shift, 128) {
        Some(root) => {
            let clsid = root.get(0x50..0x60)?;
            (root.get(0x42) == Some(&5) && (clsid == MSI_PACKAGE || clsid == MSI_PATCH))
                .then_some(Confidence::Certain)
        }
        None => named(probe, External::Msi).then_some(Confidence::Likely),
    }
}

/// `vhdxfile`, then the creator: UTF-16 text, then NULs to its 512 bytes. The headers that
/// would say more start at 64 KiB, just past the head.
fn vhdx(h: &[u8]) -> Option<Confidence> {
    if !h.starts_with(b"vhdxfile") {
        return None;
    }
    Some(checked(h.get(8..520).is_some_and(utf16_text)))
}

/// A VHD footer, in the last 512 bytes (a fixed disk has only that; Virtual PC before 2004 wrote
/// 511) or, copied, at the start (a dynamic or differencing disk). One that checks out is
/// `Certain`; `conectix` at the start alone is `Likely`.
fn vhd(probe: &Probe<'_>) -> Option<Confidence> {
    let t = probe.tail;
    let at_end = [512, 511]
        .into_iter()
        .any(|n| t.len().checked_sub(n).is_some_and(|i| vhd_footer(&t[i..])));
    if at_end || probe.head.get(..512).is_some_and(vhd_footer) {
        return Some(Confidence::Certain);
    }
    probe
        .head
        .starts_with(b"conectix")
        .then_some(Confidence::Likely)
}

/// `conectix`, format version 1.0, a fixed, dynamic or differencing disk, and the checksum: the
/// one's complement of the sum of the footer's other bytes.
fn vhd_footer(f: &[u8]) -> bool {
    if !f.starts_with(b"conectix") || be32(f, 12) != Some(0x0001_0000) {
        return false;
    }
    let sum = f
        .iter()
        .enumerate()
        .filter(|(i, _)| !(64..68).contains(i))
        .fold(0u32, |sum, (_, &b)| sum.wrapping_add(u32::from(b)));
    matches!(be32(f, 60), Some(2..=4)) && be32(f, 64) == Some(!sum)
}

/// A sparse extent's header, `KDMV` with version 1 to 3, a capacity and a power-of-two grain;
/// or a descriptor, the text file that names a disk's extents, which is `Likely`.
fn vmdk(h: &[u8]) -> Option<Confidence> {
    if h.starts_with(b"KDMV") {
        let ok = matches!(le32(h, 4), Some(1..=3))
            && le64(h, 12).is_some_and(|sectors| sectors > 0)
            && le64(h, 20).is_some_and(u64::is_power_of_two);
        return Some(checked(ok));
    }
    let text = h.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(h);
    text.starts_with(b"# Disk DescriptorFile")
        .then_some(Confidence::Likely)
}

/// `QFI\xFB` with version 1 to 3 and a cluster size QEMU accepts: 512 bytes to 64 KiB for
/// version 1, to 2 MiB after.
fn qcow(h: &[u8]) -> Option<Confidence> {
    if !h.starts_with(b"QFI\xFB") {
        return None;
    }
    let ok = match be32(h, 4) {
        Some(1) => h.get(32).is_some_and(|bits| (9..=16).contains(bits)),
        Some(2 | 3) => be32(h, 20).is_some_and(|bits| (9..=21).contains(&bits)),
        _ => false,
    };
    Some(checked(ok))
}

/// VirtualBox's signature at 64, with a version 0.x or 1.x header (1.x with its size: QEMU
/// writes 0x180 bytes, VirtualBox 0x190).
fn vdi(h: &[u8]) -> Option<Confidence> {
    if h.get(64..68) != Some(&[0x7F, 0x10, 0xDA, 0xBE]) {
        return None;
    }
    let ok = match le32(h, 68).map(|v| v >> 16) {
        Some(0) => true,
        Some(1) => le32(h, 72).is_some_and(|size| (0x180..=0x1000).contains(&size)),
        _ => false,
    };
    Some(checked(ok))
}

/// An x86 boot sector: a jump (`EB xx 90` or `E9 xx xx`) and `55 AA` at 510.
fn boot_sector(b: &[u8; 512]) -> bool {
    matches!(b, [0xEB, _, 0x90, ..] | [0xE9, ..]) && b[510..] == [0x55, 0xAA]
}

/// A boot sector whose BIOS parameter block describes a FAT12, FAT16 or FAT32 volume that adds
/// up: a sector size from 512 bytes to 4 KiB and a cluster of a power of two of them, reserved
/// sectors, one or two FATs, a media byte, a root directory of whole sectors (FAT12 and 16),
/// FAT32's zero version and reserved bytes, and FATs big enough for the clusters after them.
/// NTFS's and exFAT's boot sectors zero those fields.
fn fat(h: &[u8]) -> Option<Confidence> {
    let b: &[u8; 512] = h.get(..512)?.try_into().ok()?;
    if !boot_sector(b) {
        return None;
    }
    let bps = u64::from(le16(b, 11)?);
    let spc = u64::from(b[13]);
    let reserved = u64::from(le16(b, 14)?);
    let fats = u64::from(b[16]);
    let root_entries = u64::from(le16(b, 17)?);
    let total16 = le16(b, 19)?;
    let fat16_size = le16(b, 22)?;
    let fat32 = root_entries == 0 && fat16_size == 0;
    let total = match total16 {
        0 => u64::from(le32(b, 32)?),
        n => u64::from(n),
    };
    let fat_size = if fat32 {
        u64::from(le32(b, 36)?)
    } else {
        u64::from(fat16_size)
    };
    // FAT32's 16-bit sector count should be 0, but mkfs.fat fills it in when the count fits,
    // and 7-Zip reads such a volume.
    let layout = if fat32 {
        le16(b, 42)? == 0 && b[52..64].iter().all(|&x| x == 0)
    } else {
        root_entries * 32 % bps.max(1) == 0
    };
    let fields = matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc.is_power_of_two()
        && reserved >= 1
        && matches!(fats, 1 | 2)
        && matches!(b[21], 0xF0 | 0xF8..=0xFF)
        && fat_size > 0
        && layout;
    if !fields {
        return None;
    }
    let data = reserved + fats * fat_size + root_entries * 32 / bps;
    let clusters = total.checked_sub(data)? / spc;
    let bits = match clusters {
        _ if fat32 => 32,
        0..4085 => 12,
        4085..65525 => 16,
        // Too many clusters for a FAT16 layout.
        _ => return None,
    };
    (clusters > 0 && (clusters + 2) * bits <= fat_size * bps * 8).then_some(Confidence::Certain)
}

/// `NTFS    ` at 3, in a boot sector whose parameter block is NTFS's: a sector size from 512
/// bytes to 4 KiB, sectors per cluster a power of two (above 0x80, `2^(256 - n)`: the big
/// clusters of Windows 10), FAT's fields zero, a sector count, and MFT record and index block
/// sizes in a byte each.
fn ntfs(h: &[u8]) -> Option<Confidence> {
    if h.get(3..11) != Some(b"NTFS    ") {
        return None;
    }
    let bpb = |b: &[u8; 512]| {
        let bps = le16(b, 11).unwrap_or(0);
        let cluster_log = match b[13] {
            n @ 0..=0x80 => n.is_power_of_two().then(|| n.trailing_zeros()),
            n => Some(256 - u32::from(n)),
        };
        boot_sector(b)
            && matches!(bps, 512 | 1024 | 2048 | 4096)
            && cluster_log.is_some_and(|log| bps.trailing_zeros() + log <= 31)
            && b[14..21].iter().all(|&x| x == 0)
            && b[22..24] == [0, 0]
            && b[32..36] == [0; 4]
            && le64(b, 0x28).is_some_and(|sectors| sectors > 0)
            && b[0x40] != 0
            && b[0x41..0x44] == [0; 3]
            && b[0x44] != 0
            && b[0x45..0x48] == [0; 3]
    };
    let ok = h
        .get(..512)
        .and_then(|b| <&[u8; 512]>::try_from(b).ok())
        .is_some_and(bpb);
    Some(checked(ok))
}

/// `53 EF` at 1080, in an ext2/3/4 superblock that adds up: a block size from 1 to 64 KiB, the
/// first data block where that size puts it, inodes and blocks, groups no bigger than a bitmap
/// block can map, and for revision 1 a power-of-two inode size and the first inode from 11.
fn ext(h: &[u8]) -> Option<Confidence> {
    let sb = h.get(1024..2048)?;
    if le16(sb, 0x38)? != 0xEF53 {
        return None;
    }
    let log = le32(sb, 0x18)?;
    if log > 6 {
        return None;
    }
    let block = 1024u32 << log;
    let inodes = le32(sb, 0)?;
    let first_data = le32(sb, 0x14)?;
    let blocks_per_group = le32(sb, 0x20)?;
    let inodes_per_group = le32(sb, 0x28)?;
    let revision = le32(sb, 0x4C)?;
    let fields = inodes > 0
        && (le32(sb, 4)? > 0 || le32(sb, 0x150)? > 0)
        && (first_data == 0 || (log == 0 && first_data == 1))
        && blocks_per_group > 0
        && (1..=inodes.min(block * 8)).contains(&inodes_per_group);
    let rev = match revision {
        0 => true,
        1 => {
            let inode_size = u32::from(le16(sb, 0x58)?);
            inode_size.is_power_of_two()
                && (128..=block).contains(&inode_size)
                && le32(sb, 0x54)? >= 11
        }
        _ => false,
    };
    (fields && rev).then_some(Confidence::Certain)
}

/// An HFS+ (`H+`, version 4) or HFSX (`HX`, version 5) volume header at 1024, with a
/// power-of-two block size from 512 bytes, some blocks, and no more of them free.
fn hfs(h: &[u8]) -> Option<Confidence> {
    let v = h.get(1024..1536)?;
    if !matches!(v.get(..4)?, b"H+\0\x04" | b"HX\0\x05") {
        return None;
    }
    let size = be32(v, 0x28)?;
    let total = be32(v, 0x2C)?;
    let free = be32(v, 0x30)?;
    (size.is_power_of_two() && size >= 512 && total > 0 && free <= total)
        .then_some(Confidence::Certain)
}

/// An APFS container superblock: `NXSB` at 32 in an object of type 1, a block size from 4 to
/// 64 KiB and some blocks. `Certain` when its Fletcher-64 checksum matches, `Likely` when not.
fn apfs(h: &[u8]) -> Option<Confidence> {
    if h.get(32..36) != Some(b"NXSB") {
        return None;
    }
    let size = le32(h, 36)?;
    let ok = le32(h, 24)? & 0xFFFF == 1
        && size.is_power_of_two()
        && (4096..=65536).contains(&size)
        && le64(h, 40)? > 0;
    if !ok {
        return None;
    }
    let sum = h
        .get(..usize::try_from(size).ok()?)
        .is_some_and(|block| block.get(8..).map(fletcher64) == le64(block, 0));
    Some(checked(sum))
}

/// APFS's checksum of an object, over everything after the checksum itself.
fn fletcher64(data: &[u8]) -> u64 {
    const M: u64 = 0xFFFF_FFFF;
    let (mut a, mut b) = (0u64, 0u64);
    for &word in data.as_chunks::<4>().0 {
        a = (a + u64::from(u32::from_le_bytes(word))) % M;
        b = (b + a) % M;
    }
    let low = M - (a + b) % M;
    let high = M - (a + low) % M;
    high << 32 | low
}

/// CramFS's magic in either byte order (a big-endian image is a big-endian machine's), with
/// `Compressed ROMFS` after it, at 0 or at 512 (after a boot block).
fn cramfs(h: &[u8]) -> Option<Confidence> {
    [0, 512]
        .into_iter()
        .any(|at| {
            h.get(at..at + 32).is_some_and(|s| {
                matches!(s[..4], [0x45, 0x3D, 0xCD, 0x28] | [0x28, 0xCD, 0x3D, 0x45])
                    && &s[16..] == b"Compressed ROMFS"
            })
        })
        .then_some(Confidence::Certain)
}

/// A GPT header in sector 1: `EFI PART`, revision 1.0, its own sector number and its CRC.
/// `Likely` at most (see the module's notes). 512-byte sectors only: 7-Zip 26.00 reads a disk of
/// 4 KiB sectors as an MBR disk of 512-byte ones and lists garbage, so those aren't claimed.
fn gpt(h: &[u8]) -> Option<Confidence> {
    gpt_header(h, 512).then_some(Confidence::Likely)
}

fn gpt_header(h: &[u8], sector: usize) -> bool {
    let header = || {
        let g = h.get(sector..)?;
        let size = usize::try_from(le32(g, 12)?).ok()?;
        if !g.starts_with(b"EFI PART")
            || le32(g, 8)? != 0x0001_0000
            || !(92..=sector).contains(&size)
            || le64(g, 24)? != 1
        {
            return Some(false);
        }
        let g = g.get(..size)?;
        let mut crc = crc32fast::Hasher::new();
        crc.update(&g[..16]);
        crc.update(&[0; 4]);
        crc.update(&g[20..]);
        Some(le32(g, 16)? == crc.finalize())
    };
    header() == Some(true)
}

/// `55 AA` at 510 and a partition table that holds up: each entry's status 0x00 or 0x80, a used
/// entry other than GPT's 0xEE, each used one starting after sector 0, inside the file when its
/// length is known, and none overlapping. A volume's boot sector (NTFS's, exFAT's) isn't a
/// disk's. `Likely` at most (see the module's notes).
fn mbr(probe: &Probe<'_>) -> Option<Confidence> {
    let b = probe.head.get(..512)?;
    if b.get(510..) != Some(&[0x55, 0xAA]) || matches!(b.get(3..11)?, b"NTFS    " | b"EXFAT   ") {
        return None;
    }
    let sectors = probe.len.map(|len| len / 512);
    let mut used: Vec<(u64, u64)> = Vec::with_capacity(4);
    let (mut gpt_entry, mut others) = (false, false);
    for e in b.get(446..510)?.as_chunks::<16>().0 {
        if !matches!(e[0], 0x00 | 0x80) {
            return None;
        }
        if e[4] == 0 {
            continue;
        }
        let start = u64::from(le32(e, 8)?);
        let end = start + u64::from(le32(e, 12)?);
        let overlaps = used.iter().any(|&(from, to)| start < to && from < end);
        if start == 0 || end == start || overlaps || sectors.is_some_and(|n| end > n) {
            return None;
        }
        used.push((start, end));
        gpt_entry |= e[4] == 0xEE;
        others |= e[4] != 0xEE;
    }
    // A hybrid MBR, GPT's entry beside others, is GPT's when the GPT header checks out.
    (others && !(gpt_entry && gpt(probe.head).is_some())).then_some(Confidence::Likely)
}

/// UTF-16LE text without control characters, up to a NUL, then nothing but NULs.
fn utf16_text(b: &[u8]) -> bool {
    let units = || b.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c));
    let n = units().position(|u| u == 0).unwrap_or(b.len() / 2);
    char::decode_utf16(units().take(n)).all(|c| c.is_ok_and(|c| !c.is_control()))
        && b.get(n * 2..)
            .is_some_and(|rest| rest.iter().all(|&x| x == 0))
}

/// The file's name ends in one of `kind`'s extensions.
fn named(probe: &Probe<'_>, kind: External) -> bool {
    probe
        .name
        .is_some_and(|n| kind.extensions().iter().any(|e| n.ends_with(e)))
}

/// `n` bytes at `at` in the file: from the head, or from the tail when the length is known.
fn bytes_at<'a>(probe: &Probe<'a>, at: u64, n: usize) -> Option<&'a [u8]> {
    let in_head = usize::try_from(at)
        .ok()
        .and_then(|i| probe.head.get(i..i.checked_add(n)?));
    in_head.or_else(|| {
        let tail_start = probe.len?.checked_sub(probe.tail.len() as u64)?;
        let i = usize::try_from(at.checked_sub(tail_start)?).ok()?;
        probe.tail.get(i..i.checked_add(n)?)
    })
}

fn array<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    array(b, at).map(u16::from_le_bytes)
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    array(b, at).map(u32::from_le_bytes)
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    array(b, at).map(u64::from_le_bytes)
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    array(b, at).map(u32::from_be_bytes)
}

/// Small images of each format, for the tests here and detection's.
#[cfg(test)]
pub(crate) mod images {
    pub fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    pub fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    pub fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    pub fn put32be(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }

    /// A 1.44 MB floppy's FAT12 boot sector, as mkfs.fat writes it, in a whole floppy.
    pub fn fat12() -> Vec<u8> {
        let mut b = vec![0u8; 1_474_560];
        b[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[3..11].copy_from_slice(b"mkfs.fat");
        put16(&mut b, 11, 512);
        b[13] = 1;
        put16(&mut b, 14, 1);
        b[16] = 2;
        put16(&mut b, 17, 224);
        put16(&mut b, 19, 2880);
        b[21] = 0xF0;
        put16(&mut b, 22, 9);
        b[38] = 0x29;
        b[54..62].copy_from_slice(b"FAT12   ");
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    /// The boot sector of a 64 MiB FAT32 volume, as mkfs.fat writes it.
    pub fn fat32() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        b[3..11].copy_from_slice(b"mkfs.fat");
        put16(&mut b, 11, 512);
        b[13] = 1;
        put16(&mut b, 14, 32);
        b[16] = 2;
        b[21] = 0xF8;
        put32(&mut b, 32, 131_072);
        put32(&mut b, 36, 1009);
        put32(&mut b, 44, 2);
        put16(&mut b, 48, 1);
        put16(&mut b, 50, 6);
        b[66] = 0x29;
        b[82..90].copy_from_slice(b"FAT32   ");
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    /// The boot sector of a 64 MiB NTFS volume, as mkntfs writes it.
    pub fn ntfs() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        b[3..11].copy_from_slice(b"NTFS    ");
        put16(&mut b, 11, 512);
        b[13] = 8;
        b[21] = 0xF8;
        b[0x24] = 0x80;
        b[0x26] = 0x80;
        put64(&mut b, 0x28, 131_071);
        put64(&mut b, 0x30, 4);
        put64(&mut b, 0x38, 8191);
        b[0x40] = 0xF6;
        b[0x44] = 1;
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    /// A partition table entry: status, type, first sector and count.
    pub type Part = (u8, u8, u32, u32);

    /// A disk of `sectors` 512-byte sectors with an MBR holding `parts`.
    pub fn mbr(sectors: usize, parts: &[Part]) -> Vec<u8> {
        let mut b = vec![0u8; sectors * 512];
        for (i, &(status, kind, start, count)) in parts.iter().enumerate() {
            let e = 446 + 16 * i;
            b[e] = status;
            b[e + 4] = kind;
            put32(&mut b, e + 8, start);
            put32(&mut b, e + 12, count);
        }
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    /// A GPT disk of `sectors` sectors of `size` bytes: a protective MBR and the header in
    /// sector 1.
    pub fn gpt(sectors: u32, size: usize) -> Vec<u8> {
        let mut b = mbr(1, &[(0, 0xEE, 1, sectors - 1)]);
        b.resize(sectors as usize * size, 0);
        let g = &mut b[size..size + 92];
        g[..8].copy_from_slice(b"EFI PART");
        put32(g, 8, 0x0001_0000);
        put32(g, 12, 92);
        put64(g, 24, 1);
        put64(g, 32, u64::from(sectors) - 1);
        put64(g, 40, 34);
        put64(g, 48, u64::from(sectors).saturating_sub(34));
        put64(g, 72, 2);
        put32(g, 80, 128);
        put32(g, 84, 128);
        let crc = crc32fast::hash(g);
        put32(g, 16, crc);
        b
    }

    /// A VHD footer for a disk of `kind` (2 fixed, 3 dynamic).
    pub fn vhd_footer(kind: u32) -> Vec<u8> {
        let mut f = vec![0u8; 512];
        f[..8].copy_from_slice(b"conectix");
        put32be(&mut f, 8, 2);
        put32be(&mut f, 12, 0x0001_0000);
        f[16..24].copy_from_slice(&[0xFF; 8]);
        f[28..32].copy_from_slice(b"qemu");
        put32be(&mut f, 60, kind);
        let sum = f.iter().fold(0u32, |s, &b| s + u32::from(b));
        put32be(&mut f, 64, !sum);
        f
    }

    /// A Compound File of version 3 whose directory starts at sector `dir`, its root entry
    /// carrying `clsid`, `sectors` sectors long.
    pub fn compound(clsid: &[u8], dir: u32, sectors: usize) -> Vec<u8> {
        let mut b = vec![0u8; 512 * (sectors + 1)];
        b[..8].copy_from_slice(super::COMPOUND);
        put16(&mut b, 0x18, 0x3E);
        put16(&mut b, 0x1A, 3);
        put16(&mut b, 0x1C, 0xFFFE);
        put16(&mut b, 0x1E, 9);
        put16(&mut b, 0x20, 6);
        put32(&mut b, 0x30, dir);
        let root = 512 * (dir as usize + 1);
        for (i, c) in "Root Entry".encode_utf16().enumerate() {
            put16(&mut b, root + 2 * i, c);
        }
        put16(&mut b, root + 0x40, 22);
        b[root + 0x42] = 5;
        b[root + 0x50..root + 0x60].copy_from_slice(clsid);
        b
    }

    /// The root CLSID of a Word document, {00020906-0000-0000-C000-000000000046}.
    pub const WORD: &[u8] = b"\x06\x09\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46";

    /// NSIS's first header, with `flags`.
    pub fn nsis(flags: u32) -> Vec<u8> {
        let mut h = vec![0u8; 28];
        put32(&mut h, 0, flags);
        h[4..20].copy_from_slice(b"\xEF\xBE\xAD\xDENullsoftInst");
        put32(&mut h, 20, 0x1000);
        put32(&mut h, 24, 0x2000);
        h
    }
}

#[cfg(test)]
mod tests {
    use super::{
        images::{
            Part, WORD, compound, fat12, fat32, gpt, mbr, nsis, ntfs, put16, put32, put32be, put64,
            vhd_footer,
        },
        *,
    };

    fn probe(head: &[u8]) -> Probe<'_> {
        Probe {
            head,
            tail: &head[head.len().saturating_sub(crate::detect::TAIL_LEN)..],
            len: Some(head.len() as u64),
            name: None,
        }
    }

    fn sniffs(data: &[u8]) -> Vec<(External, Confidence)> {
        External::ALL
            .into_iter()
            .filter_map(|k| sniff(k, &probe(data)).map(|c| (k, c)))
            .collect()
    }

    const CERTAIN: Confidence = Confidence::Certain;
    const LIKELY: Confidence = Confidence::Likely;

    #[test]
    fn wim() {
        let mut h = vec![0u8; 208];
        h[..8].copy_from_slice(b"MSWIM\0\0\0");
        put32(&mut h, 8, 208);
        put32(&mut h, 12, 0x0001_0D00);
        put32(&mut h, 20, 32768);
        put16(&mut h, 40, 1);
        put16(&mut h, 42, 1);
        assert_eq!(sniffs(&h), [(External::Wim, CERTAIN)]);
        // A solid ESD.
        put32(&mut h, 12, 0x0E00);
        put32(&mut h, 20, 0);
        assert_eq!(sniff(External::Wim, &probe(&h)), Some(CERTAIN));
        // Part 2 of 1.
        put16(&mut h, 40, 2);
        assert_eq!(sniff(External::Wim, &probe(&h)), Some(LIKELY));
        assert_eq!(sniff(External::Wim, &probe(b"MSWIM\0\0")), None);
    }

    #[test]
    fn chm() {
        let mut h = b"ITSF\x03\0\0\0\x60\0\0\0\x01\0\0\0".to_vec();
        assert_eq!(sniffs(&h), [(External::Chm, CERTAIN)]);
        h[4] = 2;
        assert_eq!(sniffs(&h), [(External::Chm, LIKELY)]);
    }

    #[test]
    fn msi_is_a_compound_file_with_an_installers_clsid() {
        let msi = compound(MSI_PACKAGE, 1, 2);
        assert_eq!(sniffs(&msi), [(External::Msi, CERTAIN)]);
        let msp = compound(MSI_PATCH, 0, 1);
        assert_eq!(sniffs(&msp), [(External::Msi, CERTAIN)]);
        let doc = compound(WORD, 1, 2);
        assert_eq!(sniffs(&doc), []);
        let named = |data: &[u8], name: &'static str| {
            sniff(
                External::Msi,
                &Probe {
                    name: Some(name),
                    ..probe(data)
                },
            )
        };
        assert_eq!(
            named(&doc, "x.msi"),
            None,
            "the CLSID decides when it's there"
        );

        // The directory far into the file: past the head and before the tail, the name
        // decides; in the tail, the CLSID does.
        let far = compound(MSI_PACKAGE, 200, 201);
        let p = Probe {
            head: &far[..4096],
            tail: &far[far.len() - 1024..],
            len: Some(far.len() as u64),
            name: None,
        };
        assert_eq!(sniff(External::Msi, &p), Some(CERTAIN));
        let p = Probe { tail: &[], ..p };
        assert_eq!(sniff(External::Msi, &p), None);
        assert_eq!(
            sniff(
                External::Msi,
                &Probe {
                    name: Some("x.msm"),
                    ..p
                }
            ),
            Some(LIKELY)
        );
        let doc = compound(WORD, 200, 201);
        let p = Probe {
            head: &doc[..4096],
            tail: &doc[doc.len() - 1024..],
            len: Some(doc.len() as u64),
            name: Some("x.msi"),
        };
        assert_eq!(sniff(External::Msi, &p), None);

        // Version 4, with 4 KiB sectors.
        let mut v4 = vec![0u8; 4096 * 3];
        v4[..512].copy_from_slice(&msi[..512]);
        put16(&mut v4, 0x1A, 4);
        put16(&mut v4, 0x1E, 12);
        v4[8192..8192 + 128].copy_from_slice(&msi[1024..1024 + 128]);
        assert_eq!(sniffs(&v4), [(External::Msi, CERTAIN)]);
        put16(&mut v4, 0x1E, 9);
        assert_eq!(sniffs(&v4), []);
    }

    #[test]
    fn vhdx() {
        let mut h = vec![0u8; 1024];
        h[..8].copy_from_slice(b"vhdxfile");
        for (i, c) in "Microsoft Windows 10.0.26300.0".encode_utf16().enumerate() {
            put16(&mut h, 8 + 2 * i, c);
        }
        assert_eq!(sniffs(&h), [(External::Vhdx, CERTAIN)]);
        h[300] = 1;
        assert_eq!(sniffs(&h), [(External::Vhdx, LIKELY)]);
        assert_eq!(sniffs(b"vhdxfile"), [(External::Vhdx, LIKELY)]);
    }

    #[test]
    fn vhd_footer_at_the_end_or_the_start() {
        // A fixed disk: the data, then the footer.
        let mut fixed = vec![0u8; 4096];
        fixed.extend(vhd_footer(2));
        assert_eq!(sniffs(&fixed), [(External::Vhd, CERTAIN)]);
        // Virtual PC's 511-byte footer.
        let mut short = vec![0u8; 4096];
        let mut footer = vhd_footer(2);
        footer.pop();
        let sum = footer[..64]
            .iter()
            .chain(&footer[68..])
            .fold(0u32, |s, &b| s + u32::from(b));
        put32be(&mut footer, 64, !sum);
        short.extend(footer);
        assert_eq!(sniffs(&short), [(External::Vhd, CERTAIN)]);
        // A dynamic disk: the footer's copy, the dynamic header, the footer.
        let mut dynamic = vhd_footer(3);
        dynamic.extend(vec![0u8; 2048]);
        dynamic.extend(vhd_footer(3));
        assert_eq!(sniffs(&dynamic), [(External::Vhd, CERTAIN)]);
        // A broken checksum: the magic at the start is likely; at the end, nothing.
        let n = dynamic.len();
        dynamic[100] = 1;
        dynamic[n - 100] = 1;
        assert_eq!(sniffs(&dynamic), [(External::Vhd, LIKELY)]);
        let n = fixed.len();
        fixed[n - 100] = 1;
        assert_eq!(sniffs(&fixed), []);
    }

    #[test]
    fn vmdk() {
        let mut h = vec![0u8; 512];
        h[..4].copy_from_slice(b"KDMV");
        put32(&mut h, 4, 1);
        put32(&mut h, 8, 3);
        put64(&mut h, 12, 286_720);
        put64(&mut h, 20, 128);
        assert_eq!(sniffs(&h), [(External::Vmdk, CERTAIN)]);
        put64(&mut h, 20, 100);
        assert_eq!(sniffs(&h), [(External::Vmdk, LIKELY)]);
        let text =
            b"# Disk DescriptorFile\nversion=1\nCID=fffffffe\ncreateType=\"monolithicFlat\"\n";
        assert_eq!(sniffs(text), [(External::Vmdk, LIKELY)]);
    }

    #[test]
    fn qcow() {
        let mut h = vec![0u8; 104];
        h[..4].copy_from_slice(b"QFI\xFB");
        put32be(&mut h, 4, 3);
        put32be(&mut h, 20, 16);
        assert_eq!(sniffs(&h), [(External::Qcow2, CERTAIN)]);
        put32be(&mut h, 20, 30);
        assert_eq!(sniffs(&h), [(External::Qcow2, LIKELY)]);
        // Version 1 keeps its cluster size in a byte at 32.
        put32be(&mut h, 4, 1);
        h[32] = 12;
        assert_eq!(sniffs(&h), [(External::Qcow2, CERTAIN)]);
        put32be(&mut h, 4, 4);
        assert_eq!(sniffs(&h), [(External::Qcow2, LIKELY)]);
    }

    #[test]
    fn vdi() {
        let mut h = vec![0u8; 512];
        h[..40].copy_from_slice(b"<<< Oracle VM VirtualBox Disk Image >>>\n");
        put32(&mut h, 64, 0xBEDA_107F);
        put32(&mut h, 68, 0x0001_0001);
        put32(&mut h, 72, 0x190);
        assert_eq!(sniffs(&h), [(External::Vdi, CERTAIN)]);
        put32(&mut h, 68, 0x0002_0000);
        assert_eq!(sniffs(&h), [(External::Vdi, LIKELY)]);
    }

    #[test]
    fn fat_boot_sectors() {
        assert_eq!(sniffs(&fat12()), [(External::Fat, CERTAIN)]);
        assert_eq!(sniffs(&fat32()), [(External::Fat, CERTAIN)]);
        // A small FAT32 (the 1 MiB fixture): mkfs.fat puts its sector count in the 16-bit field.
        let mut small = fat32();
        put32(&mut small, 32, 0);
        put16(&mut small, 19, 2048);
        put32(&mut small, 36, 16);
        assert_eq!(sniffs(&small), [(External::Fat, CERTAIN)]);
        // FAT16: 32 MiB with 2 KiB clusters.
        let mut fat16 = fat12();
        fat16.truncate(512);
        fat16[13] = 4;
        put16(&mut fat16, 14, 4);
        put16(&mut fat16, 17, 512);
        put16(&mut fat16, 19, 0);
        put32(&mut fat16, 32, 65_536);
        fat16[21] = 0xF8;
        put16(&mut fat16, 22, 64);
        assert_eq!(sniffs(&fat16), [(External::Fat, CERTAIN)]);

        let broken = |f: fn(&mut Vec<u8>)| {
            let mut b = fat12();
            f(&mut b);
            sniff(External::Fat, &probe(&b))
        };
        assert_eq!(broken(|b| b[0] = 0), None, "jump");
        assert_eq!(broken(|b| b[510] = 0), None, "55 AA");
        assert_eq!(broken(|b| put16(b, 11, 500)), None, "sector size");
        assert_eq!(broken(|b| b[13] = 3), None, "cluster size");
        assert_eq!(broken(|b| put16(b, 14, 0)), None, "reserved sectors");
        assert_eq!(broken(|b| b[16] = 0), None, "no FAT");
        assert_eq!(broken(|b| b[21] = 0x12), None, "media byte");
        assert_eq!(
            broken(|b| put16(b, 17, 225)),
            None,
            "root of part of a sector"
        );
        assert_eq!(broken(|b| put16(b, 22, 1)), None, "a FAT too small");
        assert_eq!(broken(|b| put16(b, 19, 20)), None, "no room for data");
        let mut b = fat32();
        b[60] = 1;
        assert_eq!(sniff(External::Fat, &probe(&b)), None, "FAT32's reserved");

        // NTFS's and exFAT's boot sectors aren't FAT.
        assert_eq!(sniff(External::Fat, &probe(&ntfs())), None);
        let mut exfat = vec![0u8; 512];
        exfat[..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        exfat[3..11].copy_from_slice(b"EXFAT   ");
        exfat[510..].copy_from_slice(&[0x55, 0xAA]);
        assert_eq!(sniffs(&exfat), []);
    }

    #[test]
    fn ntfs_boot_sector() {
        assert_eq!(sniffs(&ntfs()), [(External::Ntfs, CERTAIN)]);
        let mut b = ntfs();
        // 2^(256 - 0xF4) = 4096 sectors: 2 MiB clusters.
        b[13] = 0xF4;
        assert_eq!(sniffs(&b), [(External::Ntfs, CERTAIN)]);
        b[16] = 2;
        assert_eq!(sniffs(&b), [(External::Ntfs, LIKELY)], "a FAT count");
        assert_eq!(sniffs(&ntfs()[..100]), [(External::Ntfs, LIKELY)]);
    }

    fn ext_superblock() -> Vec<u8> {
        let mut h = vec![0u8; 2048];
        let sb = &mut h[1024..];
        put32(sb, 0, 16_384);
        put32(sb, 4, 16_384);
        put32(sb, 0x18, 2);
        put32(sb, 0x1C, 2);
        put32(sb, 0x20, 32_768);
        put32(sb, 0x24, 32_768);
        put32(sb, 0x28, 16_384);
        put16(sb, 0x38, 0xEF53);
        put16(sb, 0x3A, 1);
        put32(sb, 0x4C, 1);
        put32(sb, 0x54, 11);
        put16(sb, 0x58, 256);
        h
    }

    #[test]
    fn ext_superblock_adds_up() {
        assert_eq!(sniffs(&ext_superblock()), [(External::Ext, CERTAIN)]);
        let broken = |at: usize, v: u32| {
            let mut h = ext_superblock();
            put32(&mut h, 1024 + at, v);
            sniff(External::Ext, &probe(&h))
        };
        assert_eq!(broken(0x18, 7), None, "block size");
        assert_eq!(broken(0x14, 1), None, "first data block with 4 KiB blocks");
        assert_eq!(broken(0x28, 40_000), None, "inodes per group");
        assert_eq!(broken(0x4C, 2), None, "revision");
        assert_eq!(broken(0x54, 3), None, "first inode");
        assert_eq!(broken(0, 0), None, "no inodes");
        // 1 KiB blocks put the first data block at 1.
        let mut h = ext_superblock();
        put32(&mut h, 1024 + 0x18, 0);
        put32(&mut h, 1024 + 0x14, 1);
        put32(&mut h, 1024 + 0x28, 2048);
        assert_eq!(sniff(External::Ext, &probe(&h)), Some(CERTAIN));
    }

    #[test]
    fn hfs_volume_header() {
        let mut h = vec![0u8; 1536];
        h[1024..1028].copy_from_slice(b"H+\0\x04");
        put32be(&mut h, 1024 + 0x28, 4096);
        put32be(&mut h, 1024 + 0x2C, 567);
        put32be(&mut h, 1024 + 0x30, 100);
        assert_eq!(sniffs(&h), [(External::Hfs, CERTAIN)]);
        h[1024..1028].copy_from_slice(b"HX\0\x05");
        assert_eq!(sniffs(&h), [(External::Hfs, CERTAIN)]);
        h[1027] = 4;
        assert_eq!(sniffs(&h), []);
        h[1027] = 5;
        put32be(&mut h, 1024 + 0x28, 3000);
        assert_eq!(sniffs(&h), []);
    }

    #[test]
    fn apfs_superblock_and_checksum() {
        let mut h = vec![0u8; 4096];
        put32(&mut h, 24, 0x8000_0001);
        h[32..36].copy_from_slice(b"NXSB");
        put32(&mut h, 36, 4096);
        put64(&mut h, 40, 2681);
        let sum = fletcher64(&h[8..]);
        put64(&mut h, 0, sum);
        assert_eq!(sniffs(&h), [(External::Apfs, CERTAIN)]);
        h[100] = 1;
        assert_eq!(sniffs(&h), [(External::Apfs, LIKELY)]);
        put32(&mut h, 36, 1000);
        assert_eq!(sniffs(&h), []);
        // The checksum's definition: an object of zeros.
        assert_eq!(fletcher64(&[0; 8]), 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn cramfs_either_byte_order_at_0_or_512() {
        let mut h = vec![0u8; 1024];
        h[..4].copy_from_slice(&0x28CD_3D45u32.to_le_bytes());
        h[16..32].copy_from_slice(b"Compressed ROMFS");
        assert_eq!(sniffs(&h), [(External::Cramfs, CERTAIN)]);
        h[..4].copy_from_slice(&0x28CD_3D45u32.to_be_bytes());
        assert_eq!(sniffs(&h), [(External::Cramfs, CERTAIN)]);
        let mut padded = vec![0u8; 512];
        padded.extend_from_slice(&h[..512]);
        assert_eq!(sniffs(&padded), [(External::Cramfs, CERTAIN)]);
        h[20] = b'x';
        assert_eq!(sniffs(&h), []);
    }

    #[test]
    fn gpt_header_and_crc() {
        assert_eq!(
            sniffs(&gpt(128, 512)),
            [(External::Gpt, LIKELY)],
            "its protective MBR isn't an MBR disk"
        );
        // 4 KiB sectors: 7-Zip can't read the disk, so it isn't claimed, nor is its protective
        // MBR.
        assert_eq!(sniffs(&gpt(16, 4096)), []);
        let mut bad = gpt(128, 512);
        bad[512 + 40] ^= 1;
        assert_eq!(sniffs(&bad), []);
    }

    #[test]
    fn mbr_partition_table() {
        let disk = mbr(64, &[(0x80, 0x0C, 2, 30), (0, 0x83, 32, 32)]);
        assert_eq!(sniffs(&disk), [(External::Mbr, LIKELY)]);
        let sniff_mbr =
            |sectors, parts: &[Part]| sniff(External::Mbr, &probe(&mbr(sectors, parts)));
        assert_eq!(sniff_mbr(64, &[]), None, "no partition");
        assert_eq!(sniff_mbr(64, &[(0x81, 0x0C, 2, 30)]), None, "status");
        assert_eq!(sniff_mbr(64, &[(0, 0x0C, 0, 30)]), None, "at sector 0");
        assert_eq!(sniff_mbr(64, &[(0, 0x0C, 2, 0)]), None, "empty");
        assert_eq!(sniff_mbr(64, &[(0, 0x0C, 2, 63)]), None, "past the end");
        assert_eq!(
            sniff_mbr(64, &[(0, 0x0C, 2, 30), (0, 0x83, 31, 2)]),
            None,
            "overlapping"
        );
        assert_eq!(sniff_mbr(64, &[(0, 0xEE, 1, 63)]), None, "GPT's");
        assert_eq!(
            sniff_mbr(64, &[(0, 0xEE, 1, 31), (0, 0x0C, 32, 32)]),
            Some(LIKELY),
            "GPT's entry beside others, without a GPT header"
        );
        // With one, a hybrid MBR is GPT's.
        let mut hybrid = gpt(64, 512);
        put32(&mut hybrid, 446 + 12, 31);
        hybrid[462 + 4] = 0x0C;
        put32(&mut hybrid, 462 + 8, 32);
        put32(&mut hybrid, 462 + 12, 32);
        assert_eq!(sniffs(&hybrid), [(External::Gpt, LIKELY)]);
        // Without a length, the extents can't be checked.
        let big = mbr(4, &[(0, 0x0C, 2048, 1 << 20)]);
        let p = Probe {
            len: None,
            ..probe(&big)
        };
        assert_eq!(sniff(External::Mbr, &p), Some(LIKELY));
    }

    #[test]
    fn nsis_first_header() {
        assert_eq!(nsis_header(&nsis(0)), Some(CERTAIN));
        assert_eq!(nsis_header(&nsis(1)), Some(CERTAIN), "an uninstaller");
        assert_eq!(nsis_header(&nsis(0x31)), None, "flags NSIS doesn't know");
        let mut h = nsis(0);
        put32(&mut h, 24, 28);
        assert_eq!(nsis_header(&h), None, "nothing after the header");
        assert_eq!(nsis_header(&nsis(0)[..27]), None);
    }

    /// Every sniffer, on every cut of every image here and on bytes that are all one value.
    #[test]
    fn short_or_odd_input_never_panics() {
        let mut v4 = compound(MSI_PACKAGE, 0, 1);
        put16(&mut v4, 0x1A, 4);
        put16(&mut v4, 0x1E, 12);
        let images = [
            fat12()[..4096].to_vec(),
            fat32(),
            ntfs(),
            ext_superblock(),
            gpt(16, 4096),
            mbr(4, &[(0, 0x0C, 2, 2)]),
            vhd_footer(2),
            compound(MSI_PACKAGE, 3, 4),
            v4,
            nsis(0),
        ];
        for image in &images {
            for cut in 0..=image.len() {
                let head = &image[..cut];
                for k in External::ALL {
                    for p in [
                        probe(head),
                        Probe {
                            head,
                            tail: head,
                            len: Some(u64::MAX),
                            name: Some("x.msi"),
                        },
                    ] {
                        let _ = sniff(k, &p);
                    }
                }
                let _ = nsis_header(head);
            }
        }
        for byte in [0x00, 0x55, 0xAA, 0xFF] {
            let data = vec![byte; 70_000];
            assert_eq!(sniffs(&data), [], "{byte:#x}");
        }
    }
}
