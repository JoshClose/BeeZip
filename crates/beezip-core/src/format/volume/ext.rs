//! ext2/3/4 (docs/M7.md §5): fstool's ext module behind BeeZip's checks, with BeeZip reading
//! what fstool would lose or can't be trusted with.
//!
//! - **Before fstool reads the volume**, BeeZip checks the superblock ([`check_super`]): the block
//!   size (at most 64 KiB), `s_log_groups_per_flex` under 32, `s_blocks_count_hi` (zero without
//!   `64bit`), blocks per group from 256 (or one group) to the bits of a block, and a group count
//!   the image can hold. Without this, fstool's group layout asks for up to 128 GiB
//!   (`layout.rs:683`), shifts past 32 bits (`layout.rs:680`, a panic in a checked build) or indexes
//!   past a bitmap (`synth_block_bitmap`). An incompatible feature BeeZip doesn't read
//!   (compression, `dirdata`, a journal device, an unknown one, or more than 2³² blocks) is
//!   `UnsupportedOperation`, so 7-Zip reads the volume when it's installed (docs/M7.md decision 7).
//!   An image cut short reads zeros past its end, with a warning.
//! - **fstool** reads the superblock (with its checksum) and the group descriptors (`meta_bg`,
//!   `flex_bg`), which say where each group's inodes are, and decodes inodes' first 128 bytes,
//!   folder entries and extent records. The rest is BeeZip's:
//!   - **inodes** are read whole, for their times, `i_blocks`' high half and in-inode attributes;
//!   - **block maps and extent trees** ([`Map`]): fstool's `file_block` wraps a 48-bit block number
//!     into 32 bits and overflows (`mod.rs:5751`) on an extent near the end of the logical range,
//!     and walks the tree again for every block. BeeZip's map gives whole runs, so a file's data
//!     is read an extent at a time, holes and unwritten extents as zeros;
//!   - **folders** ([`Fs::read_dir`]), inline ones too (fstool lists them empty), with names as
//!     bytes through BeeZip's name decoding (fstool makes them lossy). A name holding `/` or NUL is
//!     left out with a warning;
//!   - **symlink targets**, as bytes, at most [`MAX_LINK`] (fstool reads a 64-bit size into
//!     memory, `mod.rs:4961`): from `i_block`, from inline data or from the first blocks;
//!   - **inline data**, from the inode's `system.data` attribute (fstool fails a file whose other
//!     attributes it can't decode).
//! - **The walk** goes from the root, parents before what's in them, at most [`MAX_DEPTH`] folders
//!   deep and never into a folder twice (by inode), checking for cancellation between folders.
//!   The first path of a file's inode is the file; later ones are hard links to it. Folders,
//!   links and special files (devices, FIFOs, sockets: `Other`) are listed too. Times are UTC with
//!   nanoseconds and epoch bits ([`inode_times`]); the mode is `i_mode`. A file's packed size is
//!   what `i_blocks` says is allocated, so a sparse file of 100 GB in a small image is refused
//!   before it's read (`super::check_claim`). Folders may read at most as many blocks as the
//!   image has, in all.
//! - **A journal that needs recovery** (`needs_recovery`) is replayed as the kernel does on
//!   mounting ([`replay`]), into a map of the blocks it replaces, never onto the image (docs/M7.md
//!   decision 4). The device fstool and BeeZip read through ([`Disk`]) takes those blocks from the
//!   journal. fstool's own replay writes to the device and can overflow on a 64-bit tag. A journal
//!   that can't be replayed is warned about, and the volume read as last written.
//! - **fscrypt:** an encrypted folder is listed but not entered, with a warning: its names are
//!   ciphertext. An encrypted file (only reachable through a crafted image or a hard link) is
//!   listed as encrypted and fails `UnsupportedOperation` when read; an encrypted symlink is
//!   `Other`. An encrypted root folder fails the open with `UnsupportedOperation`: there's nothing
//!   to list.

use std::{
    collections::{HashMap, HashSet},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    sync::Arc,
    time::SystemTime,
};

use fstool::{
    block::BlockDevice,
    fs::ext::{
        Ext,
        constants::feature,
        dir, extent,
        group::{BG_BLOCK_UNINIT, GroupDesc},
        inode::{INODE_BASE_SIZE, Inode},
        jbd2, layout,
        superblock::Superblock,
    },
};

use super::{Device, FileSystem, VolumeOptions};
use crate::{
    Ctx, Error, ErrorKind, Result,
    backend::External,
    format::{Entry, EntryKind},
    io::read_error,
    limits::Limits,
    names::{NameDecoding, SystemPage},
    time::from_unix,
};

/// The deepest folder the walk goes into, as for DMGs.
pub const MAX_DEPTH: usize = 256;
/// The longest symlink target read: Linux's `PATH_MAX`.
pub const MAX_LINK: u64 = 4096;
/// The most blocks and revocations a journal replay keeps, a few dozen bytes each.
pub const MAX_REPLAY: usize = 1 << 20;

/// Where the superblock is, in bytes from the volume's start.
const SB_OFFSET: u64 = 1024;
/// The root folder's inode.
const ROOT: u32 = 2;

const S_IFMT: u16 = 0xF000;
const S_IFIFO: u16 = 0x1000;
const S_IFCHR: u16 = 0x2000;
const S_IFDIR: u16 = 0x4000;
const S_IFBLK: u16 = 0x6000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;
const S_IFSOCK: u16 = 0xC000;

/// `i_flags`: fscrypt's encryption.
const ENCRYPT_FL: u32 = 0x800;
/// `i_flags`: `i_blocks` counts file system blocks, not 512-byte sectors (`huge_file`).
const HUGE_FILE_FL: u32 = 0x4_0000;
/// `i_flags`: `i_block` holds an extent tree.
const EXTENTS_FL: u32 = 0x8_0000;
/// `i_flags`: the inode holds an extended attribute's value (`ea_inode`).
const EA_INODE_FL: u32 = 0x20_0000;
/// `i_flags`: the data is in `i_block` and the `system.data` attribute.
const INLINE_DATA_FL: u32 = 0x1000_0000;

/// The incompatible features BeeZip reads.
const READ_INCOMPAT: u32 = feature::INCOMPAT_FILETYPE
    | feature::INCOMPAT_RECOVER
    | feature::INCOMPAT_META_BG
    | feature::INCOMPAT_EXTENTS
    | feature::INCOMPAT_64BIT
    | feature::INCOMPAT_MMP
    | feature::INCOMPAT_FLEX_BG
    | feature::INCOMPAT_EA_INODE
    | feature::INCOMPAT_CSUM_SEED
    | feature::INCOMPAT_LARGEDIR
    | feature::INCOMPAT_INLINE_DATA
    | feature::INCOMPAT_ENCRYPT
    | feature::INCOMPAT_CASEFOLD;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("ext: {message}"))
}

/// An fstool error met while opening the volume. Errors of the image come back as they were.
fn fs_error(e: fstool::Error) -> Error {
    let plain = |m: &str| {
        m.trim_start_matches("ext4: ")
            .trim_start_matches("ext: ")
            .to_owned()
    };
    match e {
        fstool::Error::Io(e) => read_error(&e),
        fstool::Error::Unsupported(m) => Error::unsupported(format!("ext: {}", plain(&m))),
        fstool::Error::InvalidImage(m) | fstool::Error::InvalidArgument(m) => bad(plain(&m)),
        fstool::Error::OutOfBounds { offset, len, size } => bad(format!(
            "a read of {len} bytes at {offset}, past the end of the volume ({size} bytes)"
        )),
        e => bad(e),
    }
}

/// Errors that end the listing rather than leaving out what they happened in.
fn fatal(e: &Error) -> bool {
    !matches!(e.kind, ErrorKind::Corrupt | ErrorKind::UnsupportedOperation)
}

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Where the journal keeps a newer copy of a block of the volume: a byte offset in the image,
/// and whether the copy's first four bytes were escaped (they held the journal's magic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Copy {
    at: u64,
    escaped: bool,
}

/// The device fstool and BeeZip read the volume through (see the module's notes): the image,
/// with each block a replayed journal replaces read from the journal instead. Writes fail.
#[derive(Clone)]
struct Disk {
    dev: Device,
    /// The volume's blocks the journal replaces, by number.
    journal: Arc<HashMap<u64, Copy>>,
    /// The volume's block size.
    bs: u64,
    pos: u64,
}

impl Disk {
    fn new(dev: Device) -> Self {
        Self {
            dev,
            journal: Arc::new(HashMap::new()),
            bs: 1024,
            pos: 0,
        }
    }

    /// Exactly `buf.len()` bytes at `offset`. Past the end is `Corrupt`.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if self.journal.is_empty() {
            return self.dev.read_exact_at(offset, buf);
        }
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.dev.len())
        {
            return Err(bad(format!(
                "a read of {} bytes at {offset}, past the end of the volume ({} bytes)",
                buf.len(),
                self.dev.len()
            )));
        }
        let mut done = 0;
        while done < buf.len() {
            let at = offset + done as u64;
            let (block, within) = (at / self.bs, at % self.bs);
            let n = (buf.len() - done).min(usize::try_from(self.bs - within).unwrap_or(usize::MAX));
            let part = &mut buf[done..done + n];
            match self.journal.get(&block).copied() {
                Some(copy) => {
                    self.dev.read_exact_at(copy.at + within, part)?;
                    if copy.escaped && within < 4 {
                        let magic = jbd2::JBD2_MAGIC.to_be_bytes();
                        let k = (4 - within as usize).min(n);
                        part[..k].copy_from_slice(&magic[within as usize..within as usize + k]);
                    }
                }
                None => self.dev.read_exact_at(at, part)?,
            }
            done += n;
        }
        Ok(())
    }
}

impl Read for Disk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.dev.len().saturating_sub(self.pos);
        let n = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
        if n == 0 {
            return Ok(0);
        }
        self.read_at(self.pos, &mut buf[..n])
            .map_err(Error::into_io)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Disk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.dev.len().checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = to.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a seek before the volume's start",
            )
        })?;
        Ok(self.pos)
    }
}

impl Write for Disk {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a disk image is read only here",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 {
        512
    }

    fn total_size(&self) -> u64 {
        self.dev.len()
    }

    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}

/// What BeeZip takes from the superblock, once [`check_super`] has checked it.
#[derive(Debug, Clone)]
struct Super {
    /// The block size, 1 KiB to 64 KiB.
    bs: u64,
    /// The volume's blocks.
    blocks: u64,
    incompat: u32,
    ro_compat: u32,
    /// The journal's inode, or 0.
    journal: u32,
    /// The bytes of a cluster (a block, without `bigalloc`).
    cluster: u64,
    label: Vec<u8>,
    uuid: [u8; 16],
    free: u64,
}

/// Names for the incompatible features in `bits` BeeZip doesn't read.
fn unread_features(bits: u32) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (feature::INCOMPAT_COMPRESSION, "compression"),
        (feature::INCOMPAT_JOURNAL_DEV, "journal_dev"),
        (feature::INCOMPAT_DIRDATA, "dirdata"),
    ] {
        if bits & bit != 0 {
            names.push(name.to_owned());
        }
    }
    let rest = bits
        & !(feature::INCOMPAT_COMPRESSION
            | feature::INCOMPAT_JOURNAL_DEV
            | feature::INCOMPAT_DIRDATA);
    if rest != 0 {
        names.push(format!("unknown ({rest:#x})"));
    }
    names.join(", ")
}

/// The superblock, read through `disk` and checked before fstool reads it (see the module's
/// notes).
fn check_super(disk: &mut Disk) -> Result<Super> {
    let mut b = [0u8; 1024];
    disk.read_at(SB_OFFSET, &mut b).map_err(|e| match e.kind {
        ErrorKind::Corrupt => bad("the image is too short to hold a superblock"),
        _ => e,
    })?;
    if le16(&b, 0x38) != 0xEF53 {
        return Err(bad("there's no superblock (its magic is wrong)"));
    }
    let log = le32(&b, 0x18);
    if log > 6 {
        return Err(bad(format!(
            "the superblock says blocks are 2^{} bytes; ext's largest is 64 KiB",
            u64::from(log) + 10
        )));
    }
    let bs = 1024u64 << log;
    let incompat = le32(&b, 0x60);
    let ro_compat = le32(&b, 0x64);
    if incompat & feature::INCOMPAT_JOURNAL_DEV != 0 {
        return Err(Error::unsupported(
            "ext: this is an external journal, not a file system",
        ));
    }
    if incompat & !READ_INCOMPAT != 0 {
        return Err(Error::unsupported(format!(
            "ext: the volume uses features BeeZip doesn't read: {}",
            unread_features(incompat & !READ_INCOMPAT)
        )));
    }
    let wide = incompat & feature::INCOMPAT_64BIT != 0;
    let high = u64::from(le32(&b, 0x150));
    if high != 0 && !wide {
        return Err(bad(
            "the superblock's high block count is set without the 64bit feature",
        ));
    }
    let blocks = u64::from(le32(&b, 0x04)) | high << 32;
    let first = u64::from(le32(&b, 0x14));
    if blocks == 0 || first > 1 || first >= blocks {
        return Err(bad(format!(
            "the superblock says the volume has {blocks} blocks from block {first}"
        )));
    }
    let cluster = if ro_compat & feature::RO_COMPAT_BIGALLOC != 0 {
        let log = le32(&b, 0x1C);
        if !(le32(&b, 0x18)..=20).contains(&log) {
            return Err(bad(format!(
                "the superblock says clusters are 2^{} bytes",
                u64::from(log) + 10
            )));
        }
        1024u64 << log
    } else {
        bs
    };
    // A group's bitmap has a bit for each of its clusters (blocks, without bigalloc).
    let per_group = u64::from(le32(&b, 0x20));
    let clusters = if cluster == bs {
        per_group
    } else {
        u64::from(le32(&b, 0x24))
    };
    if per_group == 0 {
        return Err(bad("the superblock says a group has no blocks"));
    }
    let groups = (blocks - first).div_ceil(per_group);
    if clusters > 8 * bs
        || clusters * (cluster / bs) != per_group
        || (per_group < 256 && groups > 1)
    {
        return Err(bad(format!(
            "the superblock says a group has {per_group} blocks of {bs} bytes"
        )));
    }
    // Every group but the last must start in the image: with at least 256 blocks to a group,
    // what fstool keeps for each (two bitmaps) stays within 1/128 of the image.
    let real = disk.dev.real_len() / bs;
    if groups > real / 128 + 1 {
        return Err(bad(format!(
            "the superblock claims {groups} block groups, more than an image of {} bytes holds",
            disk.dev.real_len()
        )));
    }
    if high != 0 {
        return Err(Error::unsupported(
            "ext: the volume has more than 2^32 blocks",
        ));
    }
    if incompat & feature::INCOMPAT_FLEX_BG != 0 && b[0x174] > 31 {
        return Err(bad(format!(
            "the superblock says 2^{} groups share their tables",
            b[0x174]
        )));
    }
    let mut free = u64::from(le32(&b, 0x0C));
    if wide {
        free |= u64::from(le32(&b, 0x158)) << 32;
    }
    let label = &b[0x78..0x88];
    let label = &label[..label.iter().position(|&c| c == 0).unwrap_or(label.len())];
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&b[0x68..0x78]);
    disk.bs = bs;
    let sup = Super {
        bs,
        blocks,
        incompat,
        ro_compat,
        journal: le32(&b, 0xE0),
        cluster,
        label: label.to_vec(),
        uuid,
        free,
    };
    if per_group > 8 * bs
        && ro_compat & (feature::RO_COMPAT_GDT_CSUM | feature::RO_COMPAT_METADATA_CSUM) != 0
    {
        check_unwritten_bitmaps(disk, &b, &sup)?;
    }
    Ok(sup)
}

/// With bigalloc, a group has more blocks than its bitmap has bits (they count clusters). fstool
/// counts blocks: for a group whose bitmap was never written (`BLOCK_UNINIT`), it makes one up
/// with a bit for each of the group's own metadata blocks, and indexes past it when they aren't
/// near the group's start (`synth_block_bitmap`, a panic). Such a group is refused here, from
/// the descriptors fstool would read.
fn check_unwritten_bitmaps(disk: &mut Disk, raw: &[u8; 1024], sup: &Super) -> Result<()> {
    let sb = Superblock::decode(raw).map_err(fs_error)?;
    let layout = layout::from_superblock(&sb).map_err(fs_error)?;
    let (bs, bits) = (sup.bs, 8 * sup.bs);
    let size = layout.desc_size;
    let per_block = usize::try_from(layout.descs_per_block()).unwrap_or(0);
    let mut block = vec![0u8; usize::try_from(bs).unwrap_or(0)];
    for i in 0..layout.gdt_blocks {
        let Some(&at) = layout.gdt_block_locations(i).first() else {
            return Err(bad(format!("group descriptor block {i} is nowhere")));
        };
        disk.read_at(u64::from(at) * bs, &mut block)?;
        for (k, d) in block.chunks_exact(size).enumerate() {
            let g = i as usize * per_block + k;
            let Some(group) = layout.groups.get(g) else {
                break;
            };
            let desc = GroupDesc::decode(d);
            if desc.flags & BG_BLOCK_UNINIT == 0 {
                continue;
            }
            let (start, end) = (u64::from(group.start_block), u64::from(group.end_block));
            let table = u64::from(desc.inode_table);
            let far = |from: u64, to: u64| to > start + bits && from <= end;
            if u64::from(layout.base_meta_blocks(g as u32)) >= bits
                || far(
                    u64::from(desc.block_bitmap),
                    u64::from(desc.block_bitmap) + 1,
                )
                || far(
                    u64::from(desc.inode_bitmap),
                    u64::from(desc.inode_bitmap) + 1,
                )
                || far(table, table + u64::from(layout.inode_table_blocks))
            {
                return Err(bad(format!(
                    "group {g}'s metadata is past what its bitmap covers"
                )));
            }
        }
    }
    Ok(())
}

/// The superblock, checked, with `disk` made as long as the volume says it is: an image cut
/// short reads zeros past its end, with a warning.
fn prepare(disk: &mut Disk, cx: &mut dyn Ctx) -> Result<Super> {
    let sup = check_super(disk)?;
    let want = sup.blocks * sup.bs;
    if want > disk.dev.len() {
        cx.warn(format!(
            "the image is cut short: the ext volume is {want} bytes and the image {}; the rest \
             reads as zeros",
            disk.dev.real_len()
        ));
        disk.dev = disk.dev.clone().padded(want);
    }
    Ok(sup)
}

/// An inode, read whole: fstool's decoding of its first 128 bytes, and the slot it came from.
struct Node {
    ino: u32,
    base: Inode,
    slot: Vec<u8>,
}

/// An inode's times, UTC (`None` when it has no room for one, or it's out of range).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    pub accessed: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub changed: Option<SystemTime>,
    pub created: Option<SystemTime>,
}

/// The times of the inode in `slot` (all of it, `s_inode_size` bytes): 32-bit seconds, signed,
/// and where `i_extra_isize` reaches them, two epoch bits that extend them to 2446 and
/// nanoseconds, as the kernel's `ext4_decode_extra_time` reads them. The creation time is only in
/// the extra fields.
pub fn inode_times(slot: &[u8]) -> Times {
    let extra = if slot.len() > INODE_BASE_SIZE + 2 {
        INODE_BASE_SIZE + usize::from(le16(slot, INODE_BASE_SIZE))
    } else {
        INODE_BASE_SIZE
    };
    let has = |at: usize| at + 4 <= extra && at + 4 <= slot.len();
    let time = |base: usize, ext: usize| {
        let secs = i64::from(le32(slot, base).cast_signed());
        let x = if has(ext) { le32(slot, ext) } else { 0 };
        from_unix(secs + (i64::from(x & 3) << 32), x >> 2)
    };
    Times {
        accessed: time(0x08, 0x8C),
        modified: time(0x10, 0x88),
        changed: time(0x0C, 0x84),
        created: has(0x90).then(|| time(0x90, 0x94)).flatten(),
    }
}

impl Node {
    fn mode(&self) -> u16 {
        self.base.mode
    }

    fn kind(&self) -> u16 {
        self.base.mode & S_IFMT
    }

    fn flags(&self) -> u32 {
        self.base.flags
    }

    /// `i_size` with its high half.
    fn size(&self) -> u64 {
        self.base.file_size()
    }

    fn iblock(&self) -> [u8; 60] {
        extent::iblock_to_bytes(&self.base.block)
    }

    /// 512-byte sectors allocated to the inode (`i_blocks`, with `huge_file`'s high half and
    /// units).
    fn sectors(&self, sup: &Super) -> u64 {
        if sup.ro_compat & feature::RO_COMPAT_HUGE_FILE == 0 {
            return u64::from(self.base.blocks_512);
        }
        let n = u64::from(self.base.blocks_512) | u64::from(le16(&self.slot, 0x74)) << 32;
        if self.flags() & HUGE_FILE_FL != 0 {
            n.saturating_mul(sup.bs / 512)
        } else {
            n
        }
    }

    /// Bytes allocated to the inode: its data, its maps and its attribute block.
    fn allocated(&self, sup: &Super) -> u64 {
        self.sectors(sup).saturating_mul(512)
    }

    /// The value of the `system.data` attribute in the inode itself: inline data past `i_block`.
    fn system_data(&self) -> Option<&[u8]> {
        let s = &self.slot;
        if s.len() <= INODE_BASE_SIZE + 2 {
            return None;
        }
        let area = s.get(INODE_BASE_SIZE + usize::from(le16(s, INODE_BASE_SIZE))..)?;
        if le32(area, 0) != 0xEA02_0000 {
            return None;
        }
        // Entries follow the magic; values are placed from the first entry.
        let entries = &area[4..];
        let mut pos = 0;
        while pos + 16 <= entries.len() && le32(entries, pos) != 0 {
            let name_len = usize::from(entries[pos]);
            let name = entries.get(pos + 16..pos + 16 + name_len)?;
            if entries[pos + 1] == 7 && name == b"data" && le32(entries, pos + 4) == 0 {
                let at = usize::from(le16(entries, pos + 2));
                let len = usize::try_from(le32(entries, pos + 8)).ok()?;
                return entries.get(at..at.checked_add(len)?);
            }
            pos += (16 + name_len).next_multiple_of(4);
        }
        None
    }

    /// The first `size` bytes of an inline-data inode: `i_block`, then `system.data`.
    fn inline(&self, size: u64) -> Result<Vec<u8>> {
        let tail = self.system_data().unwrap_or_default();
        if size > 60 + tail.len() as u64 {
            return Err(bad(format!(
                "inode {} claims {size} bytes of inline data, and holds {}",
                self.ino,
                60 + tail.len()
            )));
        }
        let size = usize::try_from(size).unwrap_or(0);
        let mut out = self.iblock()[..size.min(60)].to_vec();
        out.extend_from_slice(&tail[..size.saturating_sub(60)]);
        Ok(out)
    }

    /// A symlink whose target is in `i_block`, as the kernel's `ext4_inode_is_fast_symlink`
    /// decides.
    fn fast_link(&self, sup: &Super) -> bool {
        if self.flags() & EA_INODE_FL != 0 {
            return self.size() > 0 && self.size() < 60;
        }
        let attr = if self.base.file_acl != 0 || le16(&self.slot, 0x76) != 0 {
            sup.cluster / 512
        } else {
            0
        };
        self.sectors(sup).saturating_sub(attr) == 0
    }
}

/// Inode `ino`, read whole.
fn node(ext: &Ext, disk: &mut Disk, ino: u32) -> Result<Node> {
    let l = &ext.layout;
    if ino == 0 || ino > l.inodes_count {
        return Err(bad(format!(
            "inode {ino} is out of range (there are {})",
            l.inodes_count
        )));
    }
    let (group, idx) = (
        (ino - 1) / l.inodes_per_group,
        (ino - 1) % l.inodes_per_group,
    );
    let table = l
        .groups
        .get(group as usize)
        .ok_or_else(|| bad(format!("inode {ino} is in group {group}, past the last")))?
        .inode_table;
    let size = u64::from(l.inode_size);
    let at = u64::from(table) * u64::from(l.block_size) + u64::from(idx) * size;
    let mut slot = vec![0u8; usize::from(l.inode_size).max(INODE_BASE_SIZE)];
    disk.read_at(at, &mut slot)
        .map_err(|e| bad(format!("inode {ino} can't be read: {}", e.message)))?;
    let mut base = [0u8; INODE_BASE_SIZE];
    base.copy_from_slice(&slot[..INODE_BASE_SIZE]);
    Ok(Node {
        ino,
        base: Inode::decode(&base),
        slot,
    })
}

/// One extent of a leaf: `len` blocks from logical block `logical` at block `phys`, or zeros for
/// an unwritten (preallocated) one.
#[derive(Debug, Clone, Copy)]
struct Run {
    logical: u64,
    len: u64,
    phys: u64,
    unwritten: bool,
}

/// An extent tree's leaf, for logical blocks `lo..hi`.
#[derive(Debug, Clone, Default)]
struct Leaf {
    lo: u64,
    hi: u64,
    runs: Vec<Run>,
}

/// An extent tree's deepest level: ext4's limit.
const MAX_EXTENT_DEPTH: u16 = 5;

enum Tree {
    /// The tree's root (`i_block`), and the leaf last read.
    Extents { root: [u8; 60], leaf: Option<Leaf> },
    /// ext2/3's block map: 12 direct pointers, then single, double and triple indirect blocks;
    /// with the pointer block last read at each level (0 the deepest).
    Blocks {
        ptrs: [u32; 15],
        cache: [Option<(u32, Vec<u32>)>; 3],
    },
}

/// Where an inode's blocks are on the volume (see the module's notes). Every block it gives is
/// inside the volume.
struct Map {
    ino: u32,
    tree: Tree,
    bs: u64,
    blocks: u64,
}

impl Map {
    fn new(node: &Node, sup: &Super) -> Self {
        let tree = if node.flags() & EXTENTS_FL != 0 {
            Tree::Extents {
                root: node.iblock(),
                leaf: None,
            }
        } else {
            Tree::Blocks {
                ptrs: node.base.block,
                cache: [None, None, None],
            }
        };
        Self {
            ino: node.ino,
            tree,
            bs: sup.bs,
            blocks: sup.blocks,
        }
    }

    fn damaged(&self, what: impl std::fmt::Display) -> Error {
        bad(format!("inode {}'s {what}", self.ino))
    }

    /// Logical block `n`: where it is (`None` for a hole or an unwritten extent) and how many
    /// blocks from it on are in the same run, at least 1.
    fn run(&mut self, disk: &mut Disk, n: u64) -> Result<(Option<u64>, u64)> {
        if n >= 1 << 32 {
            return Err(self.damaged("size is past the largest file ext holds"));
        }
        match self.tree {
            Tree::Extents { .. } => self.extent_run(disk, n),
            Tree::Blocks { .. } => self.block_run(disk, n),
        }
    }

    fn extent_run(&mut self, disk: &mut Disk, n: u64) -> Result<(Option<u64>, u64)> {
        let cached = match &self.tree {
            Tree::Extents { leaf: Some(l), .. } => (l.lo..l.hi).contains(&n),
            _ => false,
        };
        if !cached {
            let leaf = self.find_leaf(disk, n)?;
            if let Tree::Extents { leaf: slot, .. } = &mut self.tree {
                *slot = Some(leaf);
            }
        }
        let Tree::Extents {
            leaf: Some(leaf), ..
        } = &self.tree
        else {
            return Err(self.damaged("extent tree is missing"));
        };
        let i = leaf.runs.partition_point(|r| r.logical + r.len <= n);
        Ok(match leaf.runs.get(i) {
            Some(r) if r.logical <= n => {
                let left = (r.logical + r.len - n).min(leaf.hi - n);
                ((!r.unwritten).then_some(r.phys + (n - r.logical)), left)
            }
            Some(r) => (None, r.logical.min(leaf.hi) - n),
            None => (None, leaf.hi - n),
        })
    }

    /// The leaf whose range holds logical block `n`, from the root down.
    fn find_leaf(&self, disk: &mut Disk, n: u64) -> Result<Leaf> {
        let Tree::Extents { root, .. } = &self.tree else {
            return Err(self.damaged("extent tree is missing"));
        };
        let mut node = root.to_vec();
        let top =
            extent::decode_header(&node).map_err(|_| self.damaged("extent tree has no header"))?;
        if top.depth > MAX_EXTENT_DEPTH {
            return Err(self.damaged(format!("extent tree is {} deep", top.depth)));
        }
        let (mut depth, mut lo, mut hi) = (top.depth, 0u64, 1u64 << 32);
        loop {
            let h = extent::decode_header(&node)
                .map_err(|_| self.damaged("extent tree has a node without a header"))?;
            let count = usize::from(h.entries);
            if h.depth != depth || count > (node.len() - 12) / 12 {
                return Err(self.damaged("extent tree is damaged"));
            }
            let records = node[12..12 + count * 12].as_chunks::<12>().0.iter();
            if depth == 0 {
                let mut runs = Vec::with_capacity(count);
                let mut end = 0;
                for r in records.map(|r| extent::decode_leaf(r)) {
                    let (len, unwritten) = match r.len {
                        0 => return Err(self.damaged("extent tree has an empty extent")),
                        n if n > 32768 => (u64::from(n - 32768), true),
                        n => (u64::from(n), false),
                    };
                    let logical = u64::from(r.logical);
                    if logical < end {
                        return Err(self.damaged("extents overlap or are out of order"));
                    }
                    if r.physical == 0 || r.physical.saturating_add(len) > self.blocks {
                        return Err(self.damaged(format!(
                            "extent at block {} is past the volume's end",
                            r.physical
                        )));
                    }
                    end = logical + len;
                    runs.push(Run {
                        logical,
                        len,
                        phys: r.physical,
                        unwritten,
                    });
                }
                return Ok(Leaf { lo, hi, runs });
            }
            let idx: Vec<(u64, u64)> = records
                .map(|r| {
                    let x = extent::decode_idx(r);
                    (u64::from(x.block), x.leaf)
                })
                .collect();
            if idx.windows(2).any(|w| w[1].0 <= w[0].0) {
                return Err(self.damaged("extent index is out of order"));
            }
            let k = idx.partition_point(|&(start, _)| start <= n);
            if k == 0 {
                // Before the first subtree: a hole up to it.
                let next = idx.first().map_or(hi, |f| f.0.min(hi));
                return Ok(Leaf {
                    lo,
                    hi: next,
                    runs: Vec::new(),
                });
            }
            let (start, child) = idx[k - 1];
            lo = lo.max(start);
            hi = idx.get(k).map_or(hi, |x| x.0.min(hi));
            if child == 0 || child >= self.blocks {
                return Err(self.damaged(format!(
                    "extent tree points at block {child}, past the volume's end"
                )));
            }
            node = vec![0u8; usize::try_from(self.bs).unwrap_or(0)];
            disk.read_at(child * self.bs, &mut node)?;
            depth -= 1;
        }
    }

    fn block_run(&mut self, disk: &mut Disk, n: u64) -> Result<(Option<u64>, u64)> {
        let Tree::Blocks { ptrs, .. } = &self.tree else {
            return Err(self.damaged("block map is missing"));
        };
        let ptrs = *ptrs;
        if n < 12 {
            return run_in(&ptrs[..12], n as usize, self.blocks, self.ino);
        }
        let per = self.bs / 4;
        let mut m = n - 12;
        for level in 1..=3u32 {
            let span = per.pow(level);
            if m < span {
                return self.indirect(disk, ptrs[11 + level as usize], level, m);
            }
            m -= span;
        }
        Err(self.damaged("size is past what a block map holds"))
    }

    /// Block `m` of the subtree of `level` levels under the pointer block `top`.
    fn indirect(
        &mut self,
        disk: &mut Disk,
        top: u32,
        level: u32,
        mut m: u64,
    ) -> Result<(Option<u64>, u64)> {
        let (per, blocks, ino) = (self.bs / 4, self.blocks, self.ino);
        let (mut block, mut level) = (top, level);
        loop {
            if block == 0 {
                // The whole rest of this subtree is a hole.
                return Ok((None, per.pow(level) - m));
            }
            let under = per.pow(level - 1);
            let i = usize::try_from(m / under).unwrap_or(usize::MAX);
            let ptrs = self.pointers(disk, level as usize - 1, block)?;
            if level == 1 {
                return run_in(ptrs, i, blocks, ino);
            }
            block = ptrs.get(i).copied().unwrap_or(0);
            m %= under;
            level -= 1;
        }
    }

    /// Pointer block `block` at `level`, from the cache or read.
    fn pointers(&mut self, disk: &mut Disk, level: usize, block: u32) -> Result<&[u32]> {
        if u64::from(block) >= self.blocks {
            return Err(self.damaged(format!(
                "block map points at block {block}, past the volume's end"
            )));
        }
        let bs = self.bs;
        let Tree::Blocks { cache, .. } = &mut self.tree else {
            return Ok(&[]);
        };
        let slot = &mut cache[level.min(2)];
        if slot.as_ref().is_none_or(|(b, _)| *b != block) {
            let mut raw = vec![0u8; usize::try_from(bs).unwrap_or(0)];
            disk.read_at(u64::from(block) * bs, &mut raw)?;
            let ptrs = raw
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&c| u32::from_le_bytes(c))
                .collect();
            *slot = Some((block, ptrs));
        }
        Ok(slot.as_ref().map_or(&[][..], |(_, p)| p.as_slice()))
    }
}

/// The run from pointer `i` of `ptrs`, a block map's: blocks that follow each other, or a hole.
/// They must be among the volume's `blocks`.
fn run_in(ptrs: &[u32], i: usize, blocks: u64, ino: u32) -> Result<(Option<u64>, u64)> {
    let Some(&first) = ptrs.get(i) else {
        return Ok((None, 1));
    };
    let rest = &ptrs[i..];
    if first == 0 {
        let len = rest.iter().take_while(|&&b| b == 0).count();
        return Ok((None, len as u64));
    }
    let first = u64::from(first);
    let len = rest
        .iter()
        .enumerate()
        .take_while(|&(k, &b)| u64::from(b) == first + k as u64)
        .count() as u64;
    if first + len > blocks {
        return Err(bad(format!(
            "inode {ino}'s block map points at block {first}, past the volume's end"
        )));
    }
    Ok((Some(first), len))
}

/// A file's data, a run at a time (see the module's notes).
struct Data {
    disk: Disk,
    map: Map,
    pos: u64,
    size: u64,
}

impl Read for Data {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let bs = self.map.bs;
        let (at, run) = self
            .map
            .run(&mut self.disk, self.pos / bs)
            .map_err(Error::into_io)?;
        let within = self.pos % bs;
        let n = (run * bs - within)
            .min(self.size - self.pos)
            .min(buf.len() as u64) as usize;
        match at {
            None => buf[..n].fill(0),
            Some(block) => self
                .disk
                .read_at(block * bs + within, &mut buf[..n])
                .map_err(Error::into_io)?,
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// An entry whose data can't be read: its error, on the first read.
struct Refused(Option<Error>);

impl Read for Refused {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self
            .0
            .take()
            .unwrap_or_else(|| Error::unsupported("refused"))
            .into_io())
    }
}

/// The entries of one folder's block or inline area: each name, as stored, and its inode.
fn dirents(area: &[u8], filetype: bool, out: &mut Vec<(Vec<u8>, u32)>) {
    let mut off = 0;
    while off < area.len() {
        let Some(e) = dir::decode_entry(&area[off..], filetype) else {
            break;
        };
        // A free slot (inode 0) and metadata_csum's tail are skipped.
        if e.inode != 0 && !e.name.is_empty() {
            out.push((e.name.to_vec(), e.inode));
        }
        off += e.rec_len;
    }
}

/// tid `a` is `b` or later, with 32-bit wrapping (the kernel's `tid_geq`).
fn tid_geq(a: u32, b: u32) -> bool {
    a.wrapping_sub(b).cast_signed() >= 0
}

/// One committed transaction: its id and the blocks it logged, with where each copy is.
type Transaction = (u32, Vec<(u64, Copy)>);

/// The blocks a journal that needs recovery replaces, as the kernel's `jbd2_journal_recover`
/// replays them: committed transactions from `s_start`, in order, each block's newest copy unless
/// a revocation at or after its transaction says otherwise. `None` when there's nothing to
/// replay. Descriptor and commit checksums aren't checked, nor fast commits replayed.
fn replay(
    ext: &Ext,
    sup: &Super,
    disk: &mut Disk,
    cx: &mut dyn Ctx,
) -> Result<Option<HashMap<u64, Copy>>> {
    const JBD2_DESCRIPTOR: u32 = 1;
    const JBD2_COMMIT: u32 = 2;
    const JBD2_REVOKE: u32 = 5;
    const FLAG_ESCAPE: u32 = 1;
    const FLAG_SAME_UUID: u32 = 2;
    const FLAG_LAST_TAG: u32 = 8;
    const KNOWN: u32 = 0x3F;
    const FAST_COMMIT: u32 = 0x20;
    if sup.journal == 0 {
        cx.warn(
            "the volume's journal is on another device, so it can't be replayed; the volume is \
             read as last written"
                .to_owned(),
        );
        return Ok(None);
    }
    let journal = node(ext, disk, sup.journal)?;
    let bs = sup.bs;
    let length = journal.size() / bs;
    let mut map = Map::new(&journal, sup);
    let mut block = vec![0u8; usize::try_from(bs).unwrap_or(0)];
    let Some(at) = map.run(disk, 0)?.0 else {
        return Err(bad("the journal's first block is a hole"));
    };
    disk.read_at(at * bs, &mut block)?;
    let kind = be32(&block, 4);
    if be32(&block, 0) != jbd2::JBD2_MAGIC || !matches!(kind, 3 | 4) {
        return Err(bad("the journal has no superblock"));
    }
    if u64::from(be32(&block, 12)) != bs {
        return Err(bad("the journal's block size isn't the volume's"));
    }
    let (maxlen, first, mut tid, start) = (
        u64::from(be32(&block, 16)),
        u64::from(be32(&block, 20)),
        be32(&block, 24),
        u64::from(be32(&block, 28)),
    );
    if start == 0 {
        return Ok(None);
    }
    let features = if kind == 4 { be32(&block, 0x28) } else { 0 };
    if features & !KNOWN != 0 {
        return Err(Error::unsupported(format!(
            "ext: the journal uses features BeeZip doesn't replay ({:#x})",
            features & !KNOWN
        )));
    }
    let mut last = maxlen;
    if features & FAST_COMMIT != 0 {
        let fast = match be32(&block, 0x54) {
            0 => 256,
            n => u64::from(n),
        };
        last = maxlen.saturating_sub(fast);
        cx.warn(
            "the journal's fast commits aren't replayed, only its full transactions".to_owned(),
        );
    }
    if first == 0 || first >= last || last > length || !(first..last).contains(&start) {
        return Err(bad("the journal's superblock is damaged"));
    }
    let ring = last - first;
    let wide = features & jbd2::JBD2_FEATURE_INCOMPAT_64BIT != 0;
    let csum3 = features & jbd2::JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0;
    let csum2 = features & jbd2::JBD2_FEATURE_INCOMPAT_CSUM_V2 != 0;
    let tag_bytes: usize = if csum3 {
        16
    } else {
        8 + if csum2 { 2 } else { 0 } + if wide { 4 } else { 0 }
    };
    let tail: usize = if csum2 || csum3 { 4 } else { 0 };
    let size = block.len();
    let next = |i: u64| if i + 1 >= last { first } else { i + 1 };

    let mut idx = start;
    let mut seen = 0u64;
    let mut kept = 0usize;
    let mut done: Vec<Transaction> = Vec::new();
    let mut revoked: HashMap<u64, u32> = HashMap::new();
    'log: loop {
        let mut tags = Vec::new();
        let mut revokes = Vec::new();
        loop {
            cx.check()?;
            seen += 1;
            if seen > ring {
                break 'log;
            }
            let Some(at) = map.run(disk, idx)?.0 else {
                break 'log;
            };
            disk.read_at(at * bs, &mut block)?;
            if be32(&block, 0) != jbd2::JBD2_MAGIC || be32(&block, 8) != tid {
                break 'log;
            }
            idx = next(idx);
            match be32(&block, 4) {
                JBD2_DESCRIPTOR => {
                    let end = size - tail;
                    let mut off = 12;
                    while off + tag_bytes <= end {
                        let mut target = u64::from(be32(&block, off));
                        if wide {
                            target |= u64::from(be32(&block, off + 8)) << 32;
                        }
                        let flags = if csum3 {
                            be32(&block, off + 4) & 0xFFFF
                        } else {
                            u32::from(u16::from_be_bytes([block[off + 6], block[off + 7]]))
                        };
                        seen += 1;
                        kept += 1;
                        if seen > ring {
                            break 'log;
                        }
                        if kept > MAX_REPLAY {
                            return Err(bad(format!(
                                "the journal holds more than {MAX_REPLAY} blocks to replay"
                            )));
                        }
                        let Some(copy) = map.run(disk, idx)?.0 else {
                            break 'log;
                        };
                        tags.push((
                            target,
                            Copy {
                                at: copy * bs,
                                escaped: flags & FLAG_ESCAPE != 0,
                            },
                        ));
                        idx = next(idx);
                        off += tag_bytes;
                        if flags & FLAG_SAME_UUID == 0 {
                            off += 16;
                        }
                        if flags & FLAG_LAST_TAG != 0 {
                            break;
                        }
                    }
                }
                JBD2_REVOKE => {
                    let count = usize::try_from(be32(&block, 12)).unwrap_or(usize::MAX);
                    if !(16..=size - tail).contains(&count) {
                        return Err(bad("a journal revocation block is damaged"));
                    }
                    let record = if wide { 8 } else { 4 };
                    let mut off = 16;
                    while off + record <= count {
                        kept += 1;
                        if kept > MAX_REPLAY {
                            return Err(bad(format!(
                                "the journal holds more than {MAX_REPLAY} blocks to replay"
                            )));
                        }
                        let mut b = u64::from(be32(&block, off));
                        if wide {
                            b = b << 32 | u64::from(be32(&block, off + 4));
                        }
                        revokes.push(b);
                        off += record;
                    }
                }
                JBD2_COMMIT => {
                    for b in revokes {
                        revoked
                            .entry(b)
                            .and_modify(|t| {
                                if tid_geq(tid, *t) {
                                    *t = tid;
                                }
                            })
                            .or_insert(tid);
                    }
                    done.push((tid, tags));
                    tid = tid.wrapping_add(1);
                    continue 'log;
                }
                _ => break 'log,
            }
        }
    }
    if done.is_empty() {
        return Ok(None);
    }
    let mut out = HashMap::new();
    for (t, tags) in done {
        for (target, copy) in tags {
            if revoked.get(&target).is_some_and(|&r| tid_geq(r, t)) {
                continue;
            }
            if target >= sup.blocks {
                return Err(bad(format!(
                    "the journal replaces block {target}, past the volume's end"
                )));
            }
            out.insert(target, copy);
        }
    }
    Ok(Some(out))
}

/// The volume on `dev` (see the module's notes).
pub fn open(dev: Device, opts: &VolumeOptions, cx: &mut dyn Ctx) -> Result<Box<dyn FileSystem>> {
    let mut disk = Disk::new(dev);
    let mut sup = prepare(&mut disk, cx)?;
    let mut ext = Ext::open(&mut disk).map_err(fs_error)?;
    if sup.incompat & feature::INCOMPAT_RECOVER != 0 {
        let replayed = match replay(&ext, &sup, &mut disk, cx) {
            Ok(r) => r,
            Err(e) if fatal(&e) => return Err(e),
            Err(e) => {
                cx.warn(format!(
                    "the volume's journal can't be replayed ({}); the volume is read as last \
                     written, which may be out of date",
                    e.message
                ));
                None
            }
        };
        if let Some(blocks) = replayed {
            let mut d = disk.clone();
            d.journal = Arc::new(blocks);
            let reopened =
                prepare(&mut d, cx).and_then(|s| Ok((s, Ext::open(&mut d).map_err(fs_error)?)));
            match reopened {
                Ok((s, e)) => (disk, sup, ext) = (d, s, e),
                Err(e) if fatal(&e) => return Err(e),
                Err(e) => cx.warn(format!(
                    "the volume is damaged once its journal is replayed ({}); it's read as last \
                     written, which may be out of date",
                    e.message
                )),
            }
        }
    }
    let root = node(&ext, &mut disk, ROOT)?;
    if root.kind() != S_IFDIR {
        return Err(bad("the root isn't a folder"));
    }
    if root.flags() & ENCRYPT_FL != 0 {
        return Err(Error::unsupported(
            "ext: the whole volume is encrypted (fscrypt)",
        ));
    }
    let mut properties = Vec::new();
    if !sup.label.is_empty() {
        properties.push((
            "Label",
            opts.names.decode(&sup.label, false, SystemPage::Ansi),
        ));
    }
    properties.push(("Cluster Size", sup.bs.to_string()));
    properties.push(("Free Space", sup.free.saturating_mul(sup.bs).to_string()));
    properties.push(("ID", sup.uuid.iter().map(|b| format!("{b:02x}")).collect()));
    // Folders may read as many blocks as the image has (and a few, for a tiny one).
    let budget = disk.dev.real_len() / sup.bs + 64;
    Ok(Box::new(Fs {
        disk,
        ext,
        sup,
        names: opts.names,
        limits: opts.limits.clone(),
        files: Vec::new(),
        properties,
        budget,
    }))
}

/// An ext volume, open.
struct Fs {
    disk: Disk,
    ext: Ext,
    sup: Super,
    names: NameDecoding,
    limits: Limits,
    /// For each entry of the listing, the inode of a file.
    files: Vec<Option<u32>>,
    properties: Vec<(&'static str, String)>,
    /// The folder blocks the walk may still read.
    budget: u64,
}

impl Fs {
    /// The entries of folder `dir`: names as stored, and their inodes. `listed` entries came
    /// before, for the entry limit.
    fn read_dir(&mut self, dir: &Node, listed: usize) -> Result<Vec<(Vec<u8>, u32)>> {
        let filetype = self.sup.incompat & feature::INCOMPAT_FILETYPE != 0;
        let mut out = Vec::new();
        if dir.flags() & INLINE_DATA_FL != 0 {
            // The parent's inode, then entries; then more in the `system.data` attribute.
            dirents(&dir.iblock()[4..], filetype, &mut out);
            if let Some(more) = dir.system_data() {
                dirents(more, filetype, &mut out);
            }
            return Ok(out);
        }
        let bs = self.sup.bs;
        let count = dir.size().div_ceil(bs).min(self.sup.blocks);
        let mut map = Map::new(dir, &self.sup);
        let mut block = vec![0u8; usize::try_from(bs).unwrap_or(0)];
        let mut n = 0;
        while n < count {
            let (at, run) = map.run(&mut self.disk, n)?;
            let run = run.min(count - n);
            if let Some(at) = at {
                for k in 0..run {
                    if self.budget == 0 {
                        return Err(bad("the folders take more blocks than the image has"));
                    }
                    self.budget -= 1;
                    self.disk.read_at((at + k) * bs, &mut block)?;
                    dirents(&block, filetype, &mut out);
                    self.limits.check_entries((listed + out.len()) as u64)?;
                }
            }
            n += run;
        }
        Ok(out)
    }

    /// Symlink `link`'s target, as stored, up to its first NUL.
    fn link_target(&mut self, link: &Node) -> Result<Vec<u8>> {
        let size = link.size();
        if size > MAX_LINK {
            return Err(bad(format!(
                "its target claims {size} bytes, more than {MAX_LINK}"
            )));
        }
        let mut target = if link.flags() & INLINE_DATA_FL != 0 {
            link.inline(size)?
        } else if link.fast_link(&self.sup) {
            if size > 60 {
                return Err(bad(format!("its target claims {size} bytes, in 60 bytes")));
            }
            link.iblock()[..size as usize].to_vec()
        } else {
            let mut data = Data {
                disk: self.disk.clone(),
                map: Map::new(link, &self.sup),
                pos: 0,
                size,
            };
            let mut v = Vec::with_capacity(size as usize);
            data.read_to_end(&mut v).map_err(|e| read_error(&e))?;
            v
        };
        if let Some(nul) = target.iter().position(|&b| b == 0) {
            target.truncate(nul);
        }
        Ok(target)
    }

    /// Every entry of the volume (see the module's notes).
    fn walk(&mut self, cx: &mut dyn Ctx) -> Result<Vec<Entry>> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut files = Vec::new();
        let mut first: HashMap<u32, usize> = HashMap::new();
        let mut visited = HashSet::from([ROOT]);
        let mut pending: Vec<(u32, Option<usize>, usize)> = vec![(ROOT, None, 0)];
        while let Some((dir_ino, dir_id, depth)) = pending.pop() {
            cx.check()?;
            let (dir_path, dir_raw) = dir_id.map_or((String::new(), Vec::new()), |i| {
                (entries[i].path.clone(), entries[i].raw_path.clone())
            });
            let listed = node(&self.ext, &mut self.disk, dir_ino)
                .and_then(|d| self.read_dir(&d, entries.len()));
            let children = match listed {
                Ok(c) => c,
                // Once the folders have read as many blocks as the image has, the rest would
                // only fail the same way.
                Err(e) if depth == 0 || fatal(&e) || self.budget == 0 => return Err(e),
                Err(e) => {
                    cx.warn(format!("`{dir_path}` can't be listed: {}", e.message));
                    continue;
                }
            };
            let mut subdirs = Vec::new();
            for (name, ino) in children {
                if name == b"." || name == b".." {
                    continue;
                }
                let shown = self.names.decode(&name, false, SystemPage::Ansi);
                let path = if dir_path.is_empty() {
                    shown
                } else {
                    format!("{dir_path}/{shown}")
                };
                if name.contains(&b'/') || name.contains(&0) {
                    cx.warn(format!(
                        "`{path}` has a `/` or NUL in its name, which ext doesn't allow; it's \
                         left out"
                    ));
                    continue;
                }
                let child = match node(&self.ext, &mut self.disk, ino) {
                    Ok(n) => n,
                    Err(e) if fatal(&e) => return Err(e),
                    Err(e) => {
                        cx.warn(format!("`{path}` can't be read: {}", e.message));
                        continue;
                    }
                };
                if child.base.links_count == 0 {
                    cx.warn(format!(
                        "`{path}` names inode {ino}, which was deleted; it's left out"
                    ));
                    continue;
                }
                self.limits.check_entries(entries.len() as u64 + 1)?;
                let id = entries.len();
                let encrypted = child.flags() & ENCRYPT_FL != 0;
                let mut file = None;
                let (kind, size, packed) = match child.kind() {
                    S_IFDIR => {
                        if encrypted {
                            cx.warn(format!(
                                "`{path}` is encrypted (fscrypt), which BeeZip doesn't read; \
                                 what's in it isn't listed"
                            ));
                        } else if depth + 1 >= MAX_DEPTH {
                            cx.warn(format!(
                                "`{path}` is more than {MAX_DEPTH} folders deep; what's in it \
                                 isn't listed"
                            ));
                        } else if visited.insert(ino) {
                            subdirs.push((ino, Some(id), depth + 1));
                        } else {
                            cx.warn(format!(
                                "`{path}` is a folder already listed; what's in it isn't listed \
                                 again"
                            ));
                        }
                        (EntryKind::Dir, None, None)
                    }
                    S_IFREG => match first.get(&ino) {
                        Some(&f) => {
                            let target = entries[f].path.clone();
                            (EntryKind::Hardlink { target }, Some(child.size()), None)
                        }
                        None => {
                            first.insert(ino, id);
                            file = Some(ino);
                            let packed = child.allocated(&self.sup);
                            (EntryKind::File, Some(child.size()), Some(packed))
                        }
                    },
                    S_IFLNK if encrypted => {
                        cx.warn(format!(
                            "`{path}` is an encrypted (fscrypt) link, which BeeZip doesn't read"
                        ));
                        (EntryKind::Other, None, None)
                    }
                    S_IFLNK => match self.link_target(&child) {
                        Ok(t) => {
                            let target = self.names.decode(&t, false, SystemPage::Ansi);
                            (EntryKind::Symlink { target }, Some(t.len() as u64), None)
                        }
                        Err(e) if fatal(&e) => return Err(e),
                        Err(e) => {
                            cx.warn(format!("`{path}`'s link can't be read: {}", e.message));
                            (EntryKind::Other, None, None)
                        }
                    },
                    S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => (EntryKind::Other, None, None),
                    _ => {
                        cx.warn(format!(
                            "`{path}` is of no kind ext has (mode {:#o}); it's left out",
                            child.mode()
                        ));
                        continue;
                    }
                };
                let mut raw = dir_raw.clone();
                if !raw.is_empty() {
                    raw.push(b'/');
                }
                raw.extend_from_slice(&name);
                let mut e = Entry::new(id, path, kind);
                e.raw_path = raw;
                e.size = size;
                e.packed_size = packed;
                e.modified = inode_times(&child.slot).modified;
                e.unix_mode = Some(u32::from(child.mode()));
                e.encrypted = encrypted && file.is_some();
                entries.push(e);
                files.push(file);
            }
            pending.extend(subdirs.into_iter().rev());
        }
        self.files = files;
        Ok(entries)
    }
}

impl FileSystem for Fs {
    fn kind(&self) -> External {
        External::Ext
    }

    fn entries(&mut self, cx: &mut dyn Ctx) -> Result<Vec<Entry>> {
        self.walk(cx)
    }

    fn open(&mut self, id: usize) -> Result<Box<dyn Read + '_>> {
        let Some(&Some(ino)) = self.files.get(id) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("ext: entry {id} isn't a file"),
            ));
        };
        let file = node(&self.ext, &mut self.disk, ino)?;
        let size = file.size();
        if file.flags() & ENCRYPT_FL != 0 {
            return Ok(Box::new(Refused(Some(Error::unsupported(
                "ext: the file is encrypted (fscrypt), which BeeZip doesn't read",
            )))));
        }
        if file.flags() & INLINE_DATA_FL != 0 {
            return Ok(Box::new(Cursor::new(file.inline(size)?)));
        }
        Ok(Box::new(Data {
            disk: self.disk.clone(),
            map: Map::new(&file, &self.sup),
            pos: 0,
            size,
        }))
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.properties.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{OpenOptions, SimpleCtx, open as open_path};

    fn fixture(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(rel)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn sha256(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    /// An image opened natively: its entries, each file's data (or the error reading it) by path,
    /// and the warnings.
    struct Listing {
        entries: Vec<Entry>,
        data: HashMap<String, crate::Result<Vec<u8>>>,
        warnings: Vec<String>,
    }

    impl Listing {
        fn entry(&self, path: &str) -> &Entry {
            self.entries
                .iter()
                .find(|e| e.path == path)
                .unwrap_or_else(|| panic!("no `{path}` in {:?}", self.paths()))
        }

        fn data(&self, path: &str) -> &[u8] {
            match &self.data[path] {
                Ok(d) => d,
                Err(e) => panic!("`{path}`: {e}"),
            }
        }

        fn paths(&self) -> Vec<&str> {
            self.entries.iter().map(|e| e.path.as_str()).collect()
        }

        /// What's directly in folder `dir`.
        fn children(&self, dir: &str) -> Vec<&str> {
            let mut v: Vec<&str> = self
                .entries
                .iter()
                .filter_map(|e| e.path.strip_prefix(dir)?.strip_prefix('/'))
                .filter(|p| !p.contains('/'))
                .collect();
            v.sort_unstable();
            v
        }
    }

    fn listing_with(path: &Path, opts: &OpenOptions) -> crate::Result<Listing> {
        let mut cx = SimpleCtx::new();
        let mut opened = open_path(path, opts, &mut cx)?;
        let entries = opened.reader.entries(&mut cx)?.to_vec();
        let mut data = HashMap::new();
        for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
            let mut bytes = Vec::new();
            let read = opened
                .reader
                .open_entry(e.id, &mut cx)
                .and_then(|mut r| r.read_to_end(&mut bytes).map_err(|e| read_error(&e)));
            data.insert(e.path.clone(), read.map(|_| bytes));
        }
        Ok(Listing {
            entries,
            data,
            warnings: cx.warnings,
        })
    }

    fn listing(rel: &str) -> Listing {
        listing_with(&fixture(rel), &OpenOptions::default())
            .unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// The volume in `rel`, set up as `open` sets it up, for looking at its inodes.
    fn volume(rel: &str) -> (Disk, Super, Ext) {
        let bytes = std::fs::read(fixture(rel)).unwrap();
        let len = bytes.len() as u64;
        let mut disk = Disk::new(Device::new(Box::new(Cursor::new(bytes)), len));
        let sup = prepare(&mut disk, &mut SimpleCtx::new()).unwrap();
        let ext = Ext::open(&mut disk).unwrap();
        (disk, sup, ext)
    }

    /// The entries and warnings of the volume in `bytes`.
    fn entries_of(bytes: Vec<u8>) -> crate::Result<(Vec<Entry>, Vec<String>)> {
        let len = bytes.len() as u64;
        let dev = Device::new(Box::new(Cursor::new(bytes)), len);
        let mut cx = SimpleCtx::new();
        let opts = VolumeOptions {
            limits: Limits::default(),
            names: NameDecoding::default(),
        };
        let mut fs = open(dev, &opts, &mut cx)?;
        let entries = fs.entries(&mut cx)?;
        Ok((entries, cx.warnings))
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn at(secs: i64, nanos: u32) -> Option<SystemTime> {
        from_unix(secs, nanos)
    }

    /// The committed images list every file of their manifest records (7-Zip's listings), with
    /// the same sizes, data and times, every symlink with its target, and the hard link as a
    /// link to the other name. `[SYS]/Journal` is 7-Zip's alone. The GPT disk's ext4 partition
    /// is the same tree without a journal, in a folder of its own.
    #[test]
    fn the_committed_images_list_as_their_records_say() {
        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(fixture("manifest.json")).unwrap())
                .unwrap();
        let record = |file: &str| {
            manifest["fixtures"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["file"] == file)
                .unwrap()
                .clone()
        };
        for (image, file, prefix) in [
            ("thirdparty/7zip/ext4.img", "7zip/ext4.img", ""),
            ("thirdparty/7zip/ext2.img", "7zip/ext2.img", ""),
            (
                "thirdparty/7zip/gpt-fat-ext4.img",
                "7zip/ext4.img",
                "1.linux/",
            ),
        ] {
            let l = listing(image);
            let mut links = 0;
            let mut listed = 0;
            for want in record(file)["entries"].as_array().unwrap() {
                let path = want["path"].as_str().unwrap();
                if path.starts_with("[SYS]") {
                    continue;
                }
                let full = format!("{prefix}{path}");
                let e = l.entry(&full);
                listed += 1;
                match want["kind"].as_str().unwrap() {
                    "folder" => assert_eq!(e.kind, EntryKind::Dir, "{image}: {full}"),
                    "symlink" => assert_eq!(
                        e.kind,
                        EntryKind::Symlink {
                            target: want["target"].as_str().unwrap().to_owned()
                        },
                        "{image}: {full}"
                    ),
                    _ => {
                        let source = match &e.kind {
                            EntryKind::File => full.as_str(),
                            EntryKind::Hardlink { target } => {
                                links += 1;
                                target.as_str()
                            }
                            k => panic!("{image}: `{full}` is {k:?}"),
                        };
                        let size = want["size"].as_u64().unwrap();
                        assert_eq!(e.size, Some(size), "{image}: {full}");
                        assert_eq!(l.data(source).len() as u64, size, "{image}: {full}");
                        assert_eq!(sha256(l.data(source)), want["sha256"], "{image}: {full}");
                        // The time 7-Zip lists, in UTC, to the nanosecond (to 100 ns on
                        // Windows, as `SystemTime` holds it).
                        let mtime = want["mtime"].as_str().unwrap().replacen('T', " ", 1);
                        assert_eq!(
                            e.modified,
                            crate::time::parse_utc(&mtime),
                            "{image}: {full}"
                        );
                    }
                }
            }
            assert_eq!(
                links, 1,
                "{image}: readme.txt and hard-readme.txt share an inode"
            );
            // Besides the record's entries, only the folders it leaves out.
            let extra: Vec<&Entry> = l
                .entries
                .iter()
                .filter(|e| e.path.starts_with(prefix) && e.kind != EntryKind::Dir)
                .collect();
            assert!(extra.len() <= listed, "{image}: {:?}", l.paths());
            let ns = if image.contains("ext2") {
                0
            } else {
                123_456_789
            };
            assert_eq!(
                l.entry(&format!("{prefix}mtime.txt")).modified,
                at(1_714_979_289, ns)
            );
            assert!(
                l.warnings.iter().all(|w| w.contains("partition `0.data`")),
                "{image}: {:?}",
                l.warnings
            );
        }
        let l = listing("thirdparty/7zip/ext4.img");
        assert_eq!(l.entry("readme.txt").unix_mode, Some(0o100_644));
        assert_eq!(l.entry("sub").unix_mode, Some(0o040_755));
        assert_eq!(l.entry("random.bin").packed_size, Some(65536));
    }

    /// inline_data: files in `i_block` and on into `system.data`, folders in `i_block`, on into
    /// `system.data` (as the kernel writes them) and in blocks, and a symlink of 80 bytes.
    #[test]
    fn inline_data_is_read_from_the_inode() {
        let l = listing("thirdparty/ext/inline.img");
        assert_eq!(l.data("tiny.txt"), b"tiny\n");
        let mut medium = vec![b'm'; 99];
        medium.push(b'\n');
        assert_eq!(l.data("medium.txt"), medium);
        assert_eq!(l.entry("medium.txt").packed_size, Some(0));
        assert_eq!(
            sha256(l.data("big.bin")),
            "0ff3b7458f733a358332c1f79d2eef1ab43c822112d7defa02340062edd34031"
        );
        assert_eq!(
            l.children("dir-small"),
            ["a.txt", "spill-1.txt", "spill-2.txt"]
        );
        assert_eq!(l.data("dir-small/a.txt"), b"a\n");
        assert_eq!(l.data("dir-small/spill-2.txt"), b"spilled\n");
        assert_eq!(l.children("dir-mid").len(), 6);
        assert_eq!(l.data("dir-mid/file-6.txt"), b"6\n");
        assert_eq!(l.children("dir-many").len(), 40);
        assert_eq!(
            l.entry("long-link").kind,
            EntryKind::Symlink {
                target: format!("{}xy", "l/".repeat(39))
            }
        );
        assert_eq!(
            l.entry("short-link").kind,
            EntryKind::Symlink {
                target: "tiny.txt".into()
            }
        );
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
    }

    #[test]
    fn a_casefolded_folder_is_read() {
        let l = listing("thirdparty/ext/casefold.img");
        assert_eq!(l.data("Folded/MixedCase.TXT"), b"folded\n");
        assert_eq!(l.data("plain.txt"), b"plain\n");
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
    }

    /// meta_bg: the last files' inodes are in group 16, whose descriptor is in the second meta
    /// group's block.
    #[test]
    fn meta_bg_groups_past_the_first_meta_group() {
        let (mut disk, _, ext) = volume("thirdparty/ext/metabg.img");
        assert_eq!(ext.layout.groups.len(), 17);
        assert_eq!(ext.layout.descs_per_block(), 16);
        let ino = ext.path_to_inode(&mut disk, "/d23/more-71.txt").unwrap();
        assert!(ino > 16 * ext.layout.inodes_per_group, "inode {ino}");
        let l = listing("thirdparty/ext/metabg.img");
        assert_eq!(l.entries.len(), 122);
        assert_eq!(l.data("d23/more-71.txt"), b"more 71\n");
        assert_eq!(l.data("d00/f.txt"), b"file 00\n");
        assert_eq!(l.data("big.bin").len(), 1 << 20);
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
    }

    /// A journal that needs recovery (ext4 with checksums and 64-bit tags; ext3 with classic
    /// ones): the first transaction rewrites readme.txt's block, the second other.txt's, which the
    /// third revokes. Read as e2fsck replays it, the image untouched.
    #[test]
    fn a_journal_that_needs_recovery_is_replayed_in_memory() {
        for image in [
            "thirdparty/ext/journal.img",
            "thirdparty/ext/journal-ext3.img",
        ] {
            let before = sha256(&std::fs::read(fixture(image)).unwrap());
            let l = listing(image);
            assert_eq!(l.data("readme.txt"), b"JOURNALED-BLOCK", "{image}");
            assert_eq!(l.data("other.txt"), b"other\n", "{image}");
            assert_eq!(l.data("kept.txt"), b"kept\n", "{image}");
            assert!(l.warnings.is_empty(), "{image}: {:?}", l.warnings);
            assert_eq!(sha256(&std::fs::read(fixture(image)).unwrap()), before);

            // One block replaced, and without it readme.txt is as last written.
            let (mut disk, sup, ext) = volume(image);
            let mut cx = SimpleCtx::new();
            let blocks = replay(&ext, &sup, &mut disk, &mut cx).unwrap().unwrap();
            assert_eq!(blocks.len(), 1, "{image}");
            let ino = ext.path_to_inode(&mut disk, "/readme.txt").unwrap();
            let readme = node(&ext, &mut disk, ino).unwrap();
            let mut data = Data {
                disk: disk.clone(),
                map: Map::new(&readme, &sup),
                pos: 0,
                size: readme.size(),
            };
            let mut written = Vec::new();
            data.read_to_end(&mut written).unwrap();
            assert_eq!(written, b"Hello, BeeZip!\n", "{image}");
        }
    }

    /// Times before 1970 and after 2038 (the epoch bits), with nanoseconds, in each field.
    #[test]
    fn times_before_1970_and_after_2038() {
        let l = listing("thirdparty/ext/times.img");
        assert_eq!(l.entry("old.txt").modified, at(-315_619_200, 250_000_000));
        assert_eq!(
            l.entry("future.txt").modified,
            at(4_102_444_800, 500_000_000)
        );
        assert_eq!(l.entry("y2038.txt").modified, at(2_147_483_648, 0));
        let (mut disk, _, ext) = volume("thirdparty/ext/times.img");
        let mut times = |path: &str| {
            let ino = ext.path_to_inode(&mut disk, path).unwrap();
            inode_times(&node(&ext, &mut disk, ino).unwrap().slot)
        };
        let future = times("/future.txt");
        assert_eq!(future.accessed, at(4_102_444_801, 0));
        assert_eq!(future.changed, at(4_102_444_802, 1));
        assert_eq!(future.created, at(1_767_225_600, 0));
        assert_eq!(times("/old.txt").created, at(-315_619_200, 1));
    }

    #[test]
    fn inode_times_without_room_for_the_extra_fields() {
        // 128 bytes: signed 32-bit seconds, no creation time.
        let mut slot = vec![0u8; 128];
        put32(&mut slot, 0x10, (-86_400i32).cast_unsigned());
        put32(&mut slot, 0x08, 0x8000_0000);
        let t = inode_times(&slot);
        assert_eq!(t.modified, at(-86_400, 0));
        assert_eq!(t.accessed, at(-(1 << 31), 0));
        assert_eq!(t.created, None);
        // 256 bytes, but `i_extra_isize` reaches only the change time's extra field.
        let mut slot = vec![0u8; 256];
        slot[0x80] = 8;
        put32(&mut slot, 0x0C, 7);
        put32(&mut slot, 0x84, (5 << 2) | 1);
        put32(&mut slot, 0x88, (9 << 2) | 1);
        let t = inode_times(&slot);
        assert_eq!(t.changed, at(7 + (1 << 32), 5));
        assert_eq!(t.modified, at(0, 0));
        assert_eq!(t.created, None);
    }

    /// fscrypt's flag: a folder listed but not entered, a file listed as encrypted that can't be
    /// read, a link listed as `Other`.
    #[test]
    fn fscrypt_entries_are_listed_without_their_data() {
        let l = listing("thirdparty/ext/encrypt.img");
        assert_eq!(l.entry("secret").kind, EntryKind::Dir);
        assert!(l.children("secret").is_empty());
        assert!(l.entry("locked.bin").encrypted);
        let err = l.data["locked.bin"].as_ref().unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation, "{err}");
        assert_eq!(l.entry("locked-link").kind, EntryKind::Other);
        assert_eq!(l.data("open.txt"), b"open\n");
        assert_eq!(l.warnings.len(), 2, "{:?}", l.warnings);
        assert!(
            l.warnings
                .iter()
                .any(|w| w.contains("`secret` is encrypted"))
        );
    }

    /// Each superblock check, on ext2.img (no checksum to keep right): damage is `Corrupt`, what
    /// BeeZip doesn't read is `UnsupportedOperation`, and fstool never sees either.
    #[test]
    fn superblock_checks_come_before_fstool() {
        let base = std::fs::read(fixture("thirdparty/7zip/ext2.img")).unwrap();
        const SB: usize = 1024;
        let incompat = |b: &mut Vec<u8>, bits: u32| {
            let v = le32(b, SB + 0x60) | bits;
            put32(b, SB + 0x60, v);
        };
        type Patch = Box<dyn Fn(&mut Vec<u8>)>;
        let cases: Vec<(&str, Patch, ErrorKind)> = vec![
            (
                "2^17 bytes",
                Box::new(|b| put32(b, SB + 0x18, 7)),
                ErrorKind::Corrupt,
            ),
            (
                "high block count",
                Box::new(|b| put32(b, SB + 0x150, 1)),
                ErrorKind::Corrupt,
            ),
            (
                "block groups",
                Box::new(move |b| {
                    incompat(b, feature::INCOMPAT_64BIT);
                    put32(b, SB + 0x150, 1);
                }),
                ErrorKind::Corrupt,
            ),
            (
                "1 blocks",
                Box::new(|b| put32(b, SB + 0x20, 1)),
                ErrorKind::Corrupt,
            ),
            (
                "9000 blocks",
                Box::new(|b| put32(b, SB + 0x20, 9000)),
                ErrorKind::Corrupt,
            ),
            (
                "2^40 groups",
                Box::new(move |b| {
                    incompat(b, feature::INCOMPAT_FLEX_BG);
                    b[SB + 0x174] = 40;
                }),
                ErrorKind::Corrupt,
            ),
            (
                "unknown (0x80000000)",
                Box::new(move |b| incompat(b, 0x8000_0000)),
                ErrorKind::UnsupportedOperation,
            ),
            (
                "compression",
                Box::new(move |b| incompat(b, feature::INCOMPAT_COMPRESSION)),
                ErrorKind::UnsupportedOperation,
            ),
            (
                "external journal",
                Box::new(move |b| incompat(b, feature::INCOMPAT_JOURNAL_DEV)),
                ErrorKind::UnsupportedOperation,
            ),
        ];
        for (says, patch, kind) in cases {
            let mut b = base.clone();
            patch(&mut b);
            let err = entries_of(b).err().unwrap();
            assert_eq!(err.kind, kind, "{says}: {err}");
            assert!(err.message.contains(says), "{says}: {err}");
        }
    }

    /// bigalloc with a group whose bitmap was never written and whose block bitmap is past what
    /// a bitmap covers: fstool's `synth_block_bitmap` indexes past the bitmap it makes up there.
    #[test]
    fn a_bigalloc_group_with_metadata_past_its_bitmap_is_refused() {
        let mut b = std::fs::read(fixture("thirdparty/7zip/ext2.img")).unwrap();
        let sb = 1024;
        let ro = le32(&b, sb + 0x64) | feature::RO_COMPAT_BIGALLOC | feature::RO_COMPAT_GDT_CSUM;
        put32(&mut b, sb + 0x64, ro);
        put32(&mut b, sb + 0x04, 10_000); // blocks, all in one group
        put32(&mut b, sb + 0x1C, 4); // clusters of 16 KiB
        put32(&mut b, sb + 0x20, 16_384); // blocks per group
        put32(&mut b, sb + 0x24, 1024); // clusters per group
        // Group 0's descriptor (block 2): its block bitmap 9000 blocks in, never written.
        put32(&mut b, 2048, 9001);
        b[2048 + 18] |= BG_BLOCK_UNINIT as u8;
        let err = entries_of(b).err().unwrap();
        assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
        assert!(err.message.contains("past what its bitmap covers"), "{err}");
    }

    /// A folder entry that points back at the root: listed, not entered again.
    #[test]
    fn a_folder_that_loops_back_is_listed_once() {
        let mut b = std::fs::read(fixture("thirdparty/7zip/ext2.img")).unwrap();
        let name = b"\x06\x02nested";
        let at = b.windows(name.len()).position(|w| w == name).unwrap();
        put32(&mut b, at - 6, ROOT);
        let (entries, warnings) = entries_of(b).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"sub/nested"), "{paths:?}");
        assert!(
            !paths.iter().any(|p| p.starts_with("sub/nested/")),
            "{paths:?}"
        );
        assert_eq!(paths.iter().filter(|p| **p == "readme.txt").count(), 1);
        assert!(
            warnings.iter().any(|w| w.contains("already listed")),
            "{warnings:?}"
        );
    }

    /// An image cut short reads zeros past its end, with a warning.
    #[test]
    fn a_truncated_image_reads_zeros_past_its_end() {
        let mut b = std::fs::read(fixture("thirdparty/7zip/ext4.img")).unwrap();
        b.truncate(1 << 20);
        let (entries, warnings) = entries_of(b).unwrap();
        assert!(entries.iter().any(|e| e.path == "mtime.txt"));
        assert!(warnings[0].contains("cut short"), "{warnings:?}");
    }

    /// Copies of the ext images with bytes flipped, set to edge values or cut short, opened,
    /// listed and read: nothing panics (overflow checks included, in a test build) or takes long.
    /// `BEEZIP_EXT_MUTATIONS` sets the copies per image (default 150).
    #[test]
    fn mutated_images_never_panic() {
        let images = [
            "thirdparty/7zip/ext2.img",
            "thirdparty/7zip/ext4.img",
            "thirdparty/ext/inline.img",
            "thirdparty/ext/journal.img",
            "thirdparty/ext/journal-ext3.img",
            "thirdparty/ext/times.img",
            "thirdparty/ext/encrypt.img",
            "thirdparty/ext/casefold.img",
            "malicious/ext4-hostile.img",
            "malicious/ext4-sparse-100g.img",
        ];
        let copies: usize = std::env::var("BEEZIP_EXT_MUTATIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(150);
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut problems = Vec::new();
        for rel in images {
            let base = std::fs::read(fixture(rel)).unwrap();
            for i in 0..copies {
                let mut b = base.clone();
                // Half the time only where the metadata is, near the start.
                let span = if next() % 2 == 0 {
                    b.len().min(96 * 1024)
                } else {
                    b.len()
                };
                for _ in 0..1 + next() % 6 {
                    let at = (next() % span as u64) as usize;
                    match next() % 5 {
                        0 => b[at] ^= 1 << (next() % 8),
                        1 => b[at] = next() as u8,
                        2 if at + 4 <= b.len() => {
                            let edge = [0u32, 1, 2, u32::MAX, 1 << 31, i32::MAX as u32, 4096];
                            let v = edge.get((next() % 8) as usize).copied();
                            put32(&mut b, at, v.unwrap_or(next() as u32));
                        }
                        3 if at + 2 <= b.len() => {
                            let v = [0u16, u16::MAX, 1 << 15, 12, i16::MAX as u16]
                                [(next() % 5) as usize];
                            b[at..at + 2].copy_from_slice(&v.to_le_bytes());
                        }
                        _ => b[SB_OFFSET as usize + (next() % 1024) as usize] = next() as u8,
                    }
                }
                if next() % 10 == 0 {
                    let cut = (next() % b.len() as u64) as usize;
                    b.truncate(cut.max(2048));
                }
                // Mostly with the superblock's checksum made right again, to get past fstool's.
                if le32(&b, 1024 + 0x64) & feature::RO_COMPAT_METADATA_CSUM != 0 && next() % 8 != 0
                {
                    let c = fstool::fs::ext::csum::superblock(&b[1024..2048]);
                    put32(&mut b, 1024 + 1020, c);
                }
                let start = std::time::Instant::now();
                let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let len = b.len() as u64;
                    let dev = Device::new(Box::new(Cursor::new(b)), len);
                    let mut cx = SimpleCtx::new();
                    let opts = VolumeOptions {
                        limits: Limits {
                            max_entries: Some(10_000),
                            ..Limits::default()
                        },
                        names: NameDecoding::default(),
                    };
                    let Ok(mut fs) = open(dev, &opts, &mut cx) else {
                        return;
                    };
                    let Ok(entries) = fs.entries(&mut cx) else {
                        return;
                    };
                    for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
                        if let Ok(mut r) = fs.open(e.id) {
                            let _ = io::copy(&mut r.by_ref().take(1 << 20), &mut io::sink());
                        }
                    }
                }));
                if run.is_err() {
                    problems.push(format!("{rel}, copy {i}: a panic"));
                }
                if start.elapsed() > std::time::Duration::from_secs(10) {
                    problems.push(format!("{rel}, copy {i}: {:?}", start.elapsed()));
                }
            }
        }
        assert!(problems.is_empty(), "{problems:?}");
    }

    fn secs(t: SystemTime) -> f64 {
        t.duration_since(std::time::UNIX_EPOCH)
            .map_or_else(|e| -e.duration().as_secs_f64(), |d| d.as_secs_f64())
    }

    #[test]
    #[ignore = "prints a listing and its time: BEEZIP_EXT_DUMP=<image>"]
    fn dump() {
        let path = std::env::var("BEEZIP_EXT_DUMP").unwrap();
        let start = std::time::Instant::now();
        let l = match listing_with(Path::new(&path), &OpenOptions::default()) {
            Ok(l) => l,
            Err(e) => return println!("ERROR {:?} {e}", e.kind),
        };
        let took = start.elapsed();
        for e in &l.entries {
            let data = match l.data.get(&e.path) {
                Some(Ok(d)) => sha256(d),
                Some(Err(e)) => format!("ERR {e}"),
                None => String::new(),
            };
            println!(
                "{:?}\t{:?}\tsize={:?}\tpacked={:?}\tmode={:?}\tmtime={:?}\t{data}",
                e.path,
                e.kind,
                e.size,
                e.packed_size,
                e.unix_mode.map(|m| format!("{m:o}")),
                e.modified.map(secs),
            );
        }
        for w in &l.warnings {
            println!("WARN {w}");
        }
        println!("{} entries in {took:?}", l.entries.len());
    }

    /// The spike's feature images (`target/m7-spikes/ext/features`) against its `tree.tsv`: every
    /// path, kind, size, link target and file hash, files over 64 MiB unread.
    #[test]
    #[ignore = "the spike's 64 MiB images: BEEZIP_EXT_FEATURES=<features dir>"]
    fn spike_features() {
        let dir = PathBuf::from(std::env::var("BEEZIP_EXT_FEATURES").unwrap());
        let tree = std::fs::read_to_string(dir.join("tree.tsv")).unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let want: std::collections::BTreeMap<String, Vec<String>> = tree
            .lines()
            .map(|l| {
                let f: Vec<String> = l.split('\t').map(str::to_owned).collect();
                (f[0].clone(), f)
            })
            .collect();
        let mut images: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "img"))
            .collect();
        images.sort();
        for img in images {
            let mut cx = SimpleCtx::new();
            let opts = OpenOptions {
                limits: Limits {
                    max_ratio: None,
                    ..Limits::default()
                },
                ..OpenOptions::default()
            };
            let mut opened = match open_path(&img, &opts, &mut cx) {
                Ok(o) => o,
                Err(e) => {
                    println!("{}: OPEN {e}", img.display());
                    continue;
                }
            };
            let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
            let mut seen = std::collections::BTreeSet::new();
            let mut bad = Vec::new();
            for e in &entries {
                let key = hex(&e.raw_path);
                seen.insert(key.clone());
                let Some(w) = want.get(&key) else {
                    if !e.path.starts_with("lost+found") {
                        bad.push(format!("extra {}", e.path));
                    }
                    continue;
                };
                let kind = match &e.kind {
                    EntryKind::File | EntryKind::Hardlink { .. } => "file",
                    EntryKind::Dir => "dir",
                    EntryKind::Symlink { .. } => "symlink",
                    EntryKind::Other => "other",
                };
                let wkind = match w[1].as_str() {
                    "char" | "block" | "fifo" | "socket" => "other",
                    k => k,
                };
                if kind != wkind {
                    bad.push(format!("{}: kind {kind} vs {wkind}", e.path));
                    continue;
                }
                if let EntryKind::Symlink { target } = &e.kind
                    && hex(target.as_bytes()) != w[9]
                {
                    bad.push(format!("{}: target {target}", e.path));
                }
                if kind == "file" && e.size != w[2].parse().ok() {
                    bad.push(format!("{}: size {:?} vs {}", e.path, e.size, w[2]));
                }
                if e.kind == EntryKind::File && e.size.unwrap_or(0) <= 64 << 20 {
                    let mut data = Vec::new();
                    let got = opened
                        .reader
                        .open_entry(e.id, &mut cx)
                        .and_then(|mut r| r.read_to_end(&mut data).map_err(|e| read_error(&e)));
                    match got {
                        Ok(_) if hex(&Sha256::digest(&data)) == w[10] => {}
                        Ok(_) => bad.push(format!("{}: sha256", e.path)),
                        Err(err) => bad.push(format!("{}: {err}", e.path)),
                    }
                }
            }
            for (k, w) in &want {
                if !seen.contains(k) {
                    bad.push(format!("missing {k} ({})", w[1]));
                }
            }
            println!(
                "{}: {} entries, {} problems, {} warnings",
                img.file_name().unwrap().to_string_lossy(),
                entries.len(),
                bad.len(),
                cx.warnings.len()
            );
            for b in bad.iter().take(8) {
                println!("    {b}");
            }
            for w in cx.warnings.iter().take(4) {
                println!("    WARN {w}");
            }
        }
    }
}
