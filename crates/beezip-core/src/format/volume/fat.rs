//! FAT12, FAT16 and FAT32 (docs/M7.md §4), read by BeeZip's own code: fatfs and fstool refuse a
//! small FAT32 such as 7-Zip's `fat32.img`, and read wrong data from damaged chains without an
//! error.
//!
//! - **The boot sector** gives the layout, read as Windows' fastfat and 7-Zip read it: FAT32 when
//!   the 16-bit sectors-per-FAT field is 0, otherwise FAT12 below 4,087 clusters and FAT16 from
//!   there. Every field is checked before it's used: sectors of 512 bytes to 4 KiB, clusters of
//!   a power of two of them, a FAT with an entry for every cluster, a root folder on the volume.
//!   An image shorter than its volume reads zeros past its end, with a warning.
//! - **The FAT** is read as it's needed, [`PAGE`] bytes at a time, with at most [`MAX_PAGES`]
//!   pages kept: a FAT32's FAT can take a GiB.
//! - **Chains.** Every cluster number is checked against the volume's. A file is read a run of
//!   adjacent clusters at a time, and only as far as its size needs. A file whose chain ends
//!   early, holds a free, bad or reserved cluster or one past the volume, or comes back to a
//!   cluster it already went through is `Corrupt`: fatfs and fstool read wrong bytes there. A
//!   folder is read up to the cluster holding its end marker, at most [`MAX_FOLDER`] bytes. One
//!   whose chain is broken, or runs into a cluster a folder already went through (a loop, or two
//!   folders sharing clusters), is listed as far as it goes, with a warning. So no cluster is
//!   read twice as a folder, and the walk ends.
//! - **Folders:** deleted slots are skipped and the end marker ends the folder; `.` and `..` are
//!   skipped. A folder already listed isn't listed again, nor what's in a folder more than
//!   [`MAX_DEPTH`] deep or whose path is longer than [`MAX_PATH`]. Cancelling is checked between
//!   folders.
//! - **Names:** a long name counts when its parts come in sequence and their checksum matches
//!   the 8.3 name; otherwise the 8.3 name is shown, as Windows does. Long names are UTF-16, an
//!   unpaired surrogate becoming U+FFFD. 8.3 names are OEM bytes through BeeZip's name decoding
//!   (fstool knows CP437 only), with NT's lowercase flags applied. A name holding `/` or NUL is
//!   left out with a warning.
//! - **Entries** are the files and folders, parents before what's in them; the root and the
//!   volume label aren't entries. A file's packed size is its size in whole clusters, since FAT
//!   isn't sparse. Its time is its modified time, local with no zone as FAT stores it, read as
//!   zip's DOS times are; FAT's creation and access times have no place in an entry.
//! - **Info** shows the FAT type, the cluster size, the label (the root folder's label entry,
//!   else the boot sector's) and the sector size, named as 7-Zip names them.

use std::{
    collections::HashMap,
    io::{self, Read},
};

use super::{Device, FileSystem, VolumeOptions};
use crate::{
    Ctx, Error, ErrorKind, Result,
    backend::External,
    format::{Entry, EntryKind},
    limits::Limits,
    names::{NameDecoding, SystemPage},
    time::{DosClock, DosTime},
};

/// The deepest folder the walk goes into, as for DMGs.
pub const MAX_DEPTH: usize = 256;
/// The longest path of a folder the walk goes into, in bytes. Windows' longest path is 32,767
/// UTF-16 units.
pub const MAX_PATH: usize = 32 * 1024;
/// The most bytes of a folder read: 65,536 slots of 32 bytes, as many as FAT allows.
pub const MAX_FOLDER: usize = 65_536 * 32;
/// The most bytes the paths of a volume's entries may add up to. Folders deep in folders give
/// long paths, and a few MiB of crafted volume could otherwise list gigabytes of them.
pub const MAX_NAMES: u64 = 512 << 20;
/// How much of the FAT is read at once.
pub const PAGE: u64 = 64 * 1024;
/// The most pages of the FAT kept in memory (16 MiB).
pub const MAX_PAGES: usize = 256;

/// The FAT's entries: 12, 16 or 32 bits (FAT32's top 4 are reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bits {
    Fat12,
    Fat16,
    Fat32,
}

impl Bits {
    fn name(self) -> &'static str {
        match self {
            Self::Fat12 => "FAT12",
            Self::Fat16 => "FAT16",
            Self::Fat32 => "FAT32",
        }
    }

    /// The FAT entry that marks a bad cluster. Entries above it end a chain, and cluster numbers
    /// stop below it.
    fn bad(self) -> u32 {
        match self {
            Self::Fat12 => 0xFF7,
            Self::Fat16 => 0xFFF7,
            Self::Fat32 => 0x0FFF_FFF7,
        }
    }

    /// Where cluster `c`'s entry starts in the FAT, and how many bytes hold it.
    fn place(self, c: u32) -> (u64, usize) {
        let c = u64::from(c);
        match self {
            Self::Fat12 => (c + c / 2, 2),
            Self::Fat16 => (c * 2, 2),
            Self::Fat32 => (c * 4, 4),
        }
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// The volume is damaged: `what` is wrong.
fn corrupt(what: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("fat: {what}"))
}

/// Where the root folder is.
#[derive(Debug, Clone, Copy)]
enum At {
    /// FAT12 and FAT16: a fixed region, at a byte offset with a length.
    Fixed { at: u64, len: usize },
    /// A chain of clusters from this one: FAT32's root, and every other folder.
    Chain(u32),
}

/// What the boot sector says, checked.
#[derive(Debug, Clone)]
struct Layout {
    bits: Bits,
    sector: u32,
    /// Bytes in a cluster: at most 128 sectors of 4 KiB.
    cluster: u64,
    /// Where the FAT that's read starts (the active one on FAT32), in bytes.
    fat: u64,
    /// The FAT's bytes that hold an entry, from cluster 0 to the last.
    fat_len: u64,
    root: At,
    /// Where cluster 2 starts, in bytes.
    data: u64,
    /// The data clusters, numbered from 2.
    count: u32,
    /// The volume's bytes.
    size: u64,
    /// The boot sector's 11-byte label, if it has one.
    label: Option<[u8; 11]>,
}

impl Layout {
    /// Whether `c` is one of the volume's data clusters.
    fn on_volume(&self, c: u32) -> bool {
        (2..=u64::from(self.count) + 1).contains(&u64::from(c))
    }

    /// Where cluster `c` starts, in bytes.
    fn offset(&self, c: u32) -> Result<u64> {
        u64::from(c)
            .checked_sub(2)
            .and_then(|i| i.checked_mul(self.cluster))
            .and_then(|o| o.checked_add(self.data))
            .ok_or_else(|| corrupt(format!("cluster {c} isn't on the volume")))
    }
}

/// The layout of the volume whose boot sector is `b`.
fn layout(b: &[u8; 512]) -> Result<Layout> {
    let sector = le16(b, 11);
    match sector {
        512 | 1024 | 2048 | 4096 => {}
        // Windows reads these; nothing has made them for decades.
        128 | 256 => {
            return Err(Error::unsupported(format!(
                "fat: sectors of {sector} bytes, which BeeZip doesn't read"
            )));
        }
        _ => {
            return Err(corrupt(format!(
                "the boot sector gives sectors of {sector} bytes"
            )));
        }
    }
    let spc = b[13];
    if !spc.is_power_of_two() {
        return Err(corrupt(format!(
            "the boot sector gives clusters of {spc} sectors"
        )));
    }
    let reserved = le16(b, 14);
    if reserved == 0 {
        return Err(corrupt("the boot sector reserves no sector for itself"));
    }
    let fats = b[16];
    if fats == 0 {
        return Err(corrupt("the boot sector gives no FAT"));
    }
    let root_entries = le16(b, 17);
    let total = match le16(b, 19) {
        0 => le32(b, 32),
        n => u32::from(n),
    };
    if total == 0 {
        return Err(corrupt("the boot sector gives the volume no sectors"));
    }
    let fat16_sectors = le16(b, 22);
    let fat32 = fat16_sectors == 0;
    let fat_sectors = if fat32 {
        le32(b, 36)
    } else {
        u32::from(fat16_sectors)
    };
    if fat_sectors == 0 {
        return Err(corrupt("the boot sector gives the FAT no sectors"));
    }
    if fat32 && root_entries != 0 {
        return Err(corrupt(format!(
            "the boot sector says FAT32 but gives a root folder of {root_entries} entries"
        )));
    }
    if !fat32 && root_entries == 0 {
        return Err(corrupt("the boot sector gives the root folder no room"));
    }
    // FAT32 can say that only one FAT is kept up to date.
    let flags = le16(b, 40);
    let active = if fat32 && flags & 0x80 != 0 {
        flags & 0x0F
    } else {
        0
    };
    if active >= u16::from(fats) {
        return Err(corrupt(format!(
            "the boot sector names FAT {active} as the one in use, of {fats}"
        )));
    }

    // In sectors, none of these sums can overflow: 2^16 + 255 · 2^32 + 2^16 < 2^41.
    let sector = u64::from(sector);
    let fat_start = u64::from(reserved);
    let root_start = fat_start + u64::from(fats) * u64::from(fat_sectors);
    let root_bytes = u64::from(root_entries) * 32;
    let data_start = root_start + root_bytes.div_ceil(sector);
    let total = u64::from(total);
    if data_start >= total {
        return Err(corrupt(format!(
            "the FATs and the root folder take {data_start} sectors, and the volume has {total}"
        )));
    }
    let clusters = (total - data_start) / u64::from(spc);
    let bits = if fat32 {
        Bits::Fat32
    } else if clusters < 4087 {
        Bits::Fat12
    } else {
        Bits::Fat16
    };
    // Cluster numbers stop below the bad-cluster mark; clusters past it can't be used.
    let count = clusters.min(u64::from(bits.bad()) - 2);
    if count == 0 {
        return Err(corrupt("the volume has no room for clusters"));
    }
    let entries = count + 2;
    let fat_len = match bits {
        Bits::Fat12 => (entries * 3).div_ceil(2),
        Bits::Fat16 => entries * 2,
        Bits::Fat32 => entries * 4,
    };
    let fat_bytes = u64::from(fat_sectors) * sector;
    if fat_len > fat_bytes {
        return Err(corrupt(format!(
            "the FAT of {fat_bytes} bytes is too small for the volume's {count} clusters"
        )));
    }
    let count = u32::try_from(count).map_err(|_| corrupt("too many clusters"))?;
    let root = if fat32 {
        let c = le32(b, 44);
        if !(2..=u64::from(count) + 1).contains(&u64::from(c)) {
            return Err(corrupt(format!(
                "the root folder starts at cluster {c}, which isn't on the volume"
            )));
        }
        At::Chain(c)
    } else {
        At::Fixed {
            at: root_start * sector,
            len: usize::from(root_entries) * 32,
        }
    };
    // The label is there when the extended boot signature is 0x29.
    let (signature, label_at) = if fat32 { (66, 71) } else { (38, 43) };
    let label = (b[signature] == 0x29)
        .then(|| b[label_at..label_at + 11].try_into().ok())
        .flatten();
    Ok(Layout {
        bits,
        sector: u32::try_from(sector).unwrap_or(512),
        cluster: sector * u64::from(spc),
        fat: (fat_start + u64::from(active) * u64::from(fat_sectors)) * sector,
        fat_len,
        root,
        data: data_start * sector,
        count,
        size: total * sector,
        label,
    })
}

/// What cluster `c`'s FAT entry says comes after it.
enum Link {
    /// The chain ends.
    End,
    Next(u32),
    /// The entry can't be in a chain: what's wrong, for a message.
    Broken(String),
}

/// The FAT, read a page at a time as it's needed.
struct Table {
    bits: Bits,
    /// Where it starts on the device.
    start: u64,
    /// Its bytes that hold entries.
    len: u64,
    /// The volume's data clusters.
    count: u32,
    pages: HashMap<u64, Vec<u8>>,
}

impl Table {
    /// Cluster `c`'s entry.
    fn entry(&mut self, dev: &mut Device, c: u32) -> Result<u32> {
        let (at, width) = self.bits.place(c);
        let page = at / PAGE;
        if !self.pages.contains_key(&page) {
            if self.pages.len() >= MAX_PAGES {
                self.pages.clear();
            }
            let from = page * PAGE;
            let n = self.len.saturating_sub(from).min(PAGE);
            let mut buf = vec![0u8; usize::try_from(n).unwrap_or(0)];
            dev.read_exact_at(self.start + from, &mut buf)?;
            self.pages.insert(page, buf);
        }
        let within = usize::try_from(at % PAGE).unwrap_or(usize::MAX);
        let b = self
            .pages
            .get(&page)
            .and_then(|p| p.get(within..within.saturating_add(width)))
            .ok_or_else(|| corrupt(format!("cluster {c} has no entry in the FAT")))?;
        Ok(match self.bits {
            Bits::Fat12 => {
                let v = le16(b, 0);
                u32::from(if c % 2 == 1 { v >> 4 } else { v & 0xFFF })
            }
            Bits::Fat16 => u32::from(le16(b, 0)),
            Bits::Fat32 => le32(b, 0) & 0x0FFF_FFFF,
        })
    }

    /// What comes after cluster `c`.
    fn link(&mut self, dev: &mut Device, c: u32) -> Result<Link> {
        let v = self.entry(dev, c)?;
        let bad = self.bits.bad();
        Ok(if v > bad {
            Link::End
        } else if v == bad {
            Link::Broken(format!("cluster {c} is marked bad"))
        } else if v == 0 {
            Link::Broken(format!("cluster {c} is marked free"))
        } else if v < 2 || u64::from(v) > u64::from(self.count) + 1 {
            Link::Broken(format!(
                "cluster {c} leads to cluster {v}, which isn't on the volume"
            ))
        } else {
            Link::Next(v)
        })
    }
}

/// Clusters already gone through: a bit for each, in pages of 4,096 made as they're needed, so
/// a few clusters of a large volume take a page or two.
#[derive(Default)]
struct Seen(HashMap<u32, Box<[u64; 64]>>);

impl Seen {
    /// Marks `c`: false when it was marked already.
    fn insert(&mut self, c: u32) -> bool {
        let page = self.0.entry(c >> 12).or_insert_with(|| Box::new([0; 64]));
        let word = &mut page[((c >> 6) & 63) as usize];
        let bit = 1u64 << (c & 63);
        let new = *word & bit == 0;
        *word |= bit;
        new
    }
}

/// Where a long name's UTF-16 units are in its slot.
const UNITS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

/// A long name being gathered from its slots, which come last part first: the first slot is
/// flagged 0x40 and numbers the parts, and each after it is the part before, down to 1. All
/// carry the checksum of the 8.3 name they belong to.
struct Long {
    units: [u16; 20 * 13],
    /// Its parts; 0 when no name is being gathered.
    parts: u8,
    /// The part the next slot must be: 0 once the name is whole.
    next: u8,
    sum: u8,
}

impl Default for Long {
    fn default() -> Self {
        Self {
            units: [0; 20 * 13],
            parts: 0,
            next: 0,
            sum: 0,
        }
    }
}

impl Long {
    fn reset(&mut self) {
        self.parts = 0;
        self.next = 0;
    }

    /// The long-name slot `s`. One out of sequence drops the name gathered so far.
    fn push(&mut self, s: &[u8; 32]) {
        let part = s[0] & 0x3F;
        if s[0] & 0x40 != 0 {
            // At most 20 parts: 255 characters.
            if !(1..=20).contains(&part) {
                self.reset();
                return;
            }
            self.parts = part;
            self.sum = s[13];
        } else if self.parts == 0 || part == 0 || part != self.next || s[13] != self.sum {
            self.reset();
            return;
        }
        let at = usize::from(part - 1) * 13;
        for (k, &o) in UNITS.iter().enumerate() {
            self.units[at + k] = u16::from_le_bytes([s[o], s[o + 1]]);
        }
        self.next = part - 1;
    }

    /// The name gathered, if it's whole and belongs to the 8.3 name whose checksum is `sum`.
    fn take(&mut self, sum: u8) -> Option<String> {
        let whole = self.parts > 0 && self.next == 0 && self.sum == sum;
        let n = usize::from(self.parts) * 13;
        self.reset();
        if !whole {
            return None;
        }
        let units = self.units.get(..n)?;
        let end = units.iter().position(|&u| u == 0).unwrap_or(n);
        (end > 0).then(|| {
            char::decode_utf16(units[..end].iter().copied())
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        })
    }
}

/// The checksum of an 8.3 name, as its long name's slots carry it.
fn checksum(s: &[u8; 32]) -> u8 {
    s[..11]
        .iter()
        .fold(0u8, |sum, &b| sum.rotate_right(1).wrapping_add(b))
}

/// What a folder's slots hold, up to its end marker.
#[derive(Default)]
struct Scan {
    /// Each live entry's slot, with its long name when one checks out.
    entries: Vec<(Option<String>, [u8; 32])>,
    /// The first volume label's 11 bytes.
    label: Option<[u8; 11]>,
}

fn scan(slots: &[u8]) -> Scan {
    let mut out = Scan::default();
    let mut long = Long::default();
    for s in slots.as_chunks::<32>().0 {
        match s[0] {
            0 => break,
            0xE5 => {
                long.reset();
                continue;
            }
            _ => {}
        }
        if s[11] & 0x3F == 0x0F {
            long.push(s);
            continue;
        }
        if s[11] & 0x08 != 0 {
            if out.label.is_none() {
                out.label = s[..11].try_into().ok();
            }
            long.reset();
            continue;
        }
        let name = long.take(checksum(s));
        out.entries.push((name, *s));
    }
    out
}

/// The `.` and `..` entries every folder but the root starts with.
fn is_dot(s: &[u8; 32]) -> bool {
    s[..11] == *b".          " || s[..11] == *b"..         "
}

/// An 8.3 name: its OEM bytes decoded, base and extension each lowercased when NT's flags (byte
/// 12) say so. A first byte of 0x05 stands for 0xE5, which marks a deleted slot.
fn short_name(s: &[u8; 32], names: &NameDecoding) -> String {
    let mut base = [0u8; 8];
    base.copy_from_slice(&s[..8]);
    if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let part = |raw: &[u8], lower: bool| {
        let end = raw.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        let text = names.decode(&raw[..end], false, SystemPage::Oem);
        if lower { text.to_lowercase() } else { text }
    };
    let mut name = part(&base, s[12] & 0x08 != 0);
    let ext = part(&s[8..11], s[12] & 0x10 != 0);
    if !ext.is_empty() {
        name.push('.');
        name.push_str(&ext);
    }
    name
}

/// A volume label's bytes, decoded; none when it's empty or `NO NAME`, mkfs's and Windows'
/// placeholder.
fn label(raw: &[u8], names: &NameDecoding) -> Option<String> {
    let end = raw
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |i| i + 1);
    let raw = &raw[..end];
    (!raw.is_empty() && raw != b"NO NAME").then(|| names.decode(raw, false, SystemPage::Oem))
}

/// A folder still to be read.
struct Folder {
    at: At,
    /// Its path; empty for the root.
    path: String,
    depth: usize,
}

/// A FAT volume.
struct Volume {
    dev: Device,
    layout: Layout,
    table: Table,
    names: NameDecoding,
    limits: Limits,
    label: Option<String>,
    /// For each entry, a file's first cluster and size; `None` for a folder.
    items: Vec<Option<(u32, u64)>>,
}

/// The volume on `dev`.
pub fn open(dev: Device, opts: &VolumeOptions, cx: &mut dyn Ctx) -> Result<Box<dyn FileSystem>> {
    let mut dev = dev;
    if dev.len() < 512 {
        return Err(corrupt("the volume is shorter than its boot sector"));
    }
    let mut boot = [0u8; 512];
    dev.read_exact_at(0, &mut boot)?;
    let layout = layout(&boot)?;
    if dev.real_len() < layout.size {
        // A partition the image cuts short has been warned about already.
        if dev.len() == dev.real_len() {
            cx.warn(format!(
                "the image is cut short: it holds {} of the FAT volume's {} bytes, and reads \
                 zeros past them",
                dev.real_len(),
                layout.size
            ));
        }
        dev = dev.padded(layout.size);
    }
    let table = Table {
        bits: layout.bits,
        start: layout.fat,
        len: layout.fat_len,
        count: layout.count,
        pages: HashMap::new(),
    };
    let label = layout.label.and_then(|l| label(&l, &opts.names));
    Ok(Box::new(Volume {
        dev,
        layout,
        table,
        names: opts.names,
        limits: opts.limits.clone(),
        label,
        items: Vec::new(),
    }))
}

impl Volume {
    /// A folder's slots: the fixed root, or its clusters up to the one holding its end marker
    /// (see the module's notes). `None` when there's nothing to read, with a warning.
    fn folder(&mut self, f: &Folder, seen: &mut Seen, cx: &mut dyn Ctx) -> Result<Option<Vec<u8>>> {
        let what = if f.path.is_empty() {
            "the root folder".to_owned()
        } else {
            format!("`{}`", f.path)
        };
        let first = match f.at {
            At::Fixed { at, len } => {
                let mut b = vec![0u8; len];
                self.dev.read_exact_at(at, &mut b)?;
                return Ok(Some(b));
            }
            At::Chain(c) => c,
        };
        if first == 0 {
            cx.warn(format!("{what} has no clusters; it's listed empty"));
            return Ok(None);
        }
        if !self.layout.on_volume(first) {
            cx.warn(format!(
                "{what} starts at cluster {first}, which isn't on the volume; what's in it isn't \
                 listed"
            ));
            return Ok(None);
        }
        if !seen.insert(first) {
            cx.warn(format!(
                "{what} is a folder already listed; what's in it isn't listed again"
            ));
            return Ok(None);
        }
        // At most 512 KiB.
        let cluster = usize::try_from(self.layout.cluster).unwrap_or(usize::MAX);
        let mut out = Vec::new();
        let mut c = first;
        loop {
            let start = out.len();
            out.resize(start + cluster, 0);
            self.dev
                .read_exact_at(self.layout.offset(c)?, &mut out[start..])?;
            if out[start..].as_chunks::<32>().0.iter().any(|s| s[0] == 0) {
                break;
            }
            match self.table.link(&mut self.dev, c)? {
                Link::End => break,
                Link::Next(_) if out.len() >= MAX_FOLDER => {
                    cx.warn(format!(
                        "{what} holds more than 65,536 entries; the rest aren't listed"
                    ));
                    break;
                }
                Link::Next(n) if seen.insert(n) => c = n,
                Link::Next(n) => {
                    cx.warn(format!(
                        "{what} runs into cluster {n}, which a folder already went through; the \
                         rest of it isn't listed"
                    ));
                    break;
                }
                Link::Broken(why) => {
                    cx.warn(format!(
                        "{what}'s chain of clusters is broken ({why}); the rest of it isn't \
                         listed"
                    ));
                    break;
                }
            }
        }
        Ok(Some(out))
    }
}

impl FileSystem for Volume {
    fn kind(&self) -> External {
        External::Fat
    }

    fn entries(&mut self, cx: &mut dyn Ctx) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        self.items.clear();
        let mut clock = DosClock::default();
        let mut seen = Seen::default();
        let mut names = 0u64;
        let mut pending = vec![Folder {
            at: self.layout.root,
            path: String::new(),
            depth: 0,
        }];
        while let Some(folder) = pending.pop() {
            cx.check()?;
            let Some(slots) = self.folder(&folder, &mut seen, cx)? else {
                continue;
            };
            let found = scan(&slots);
            if folder.depth == 0
                && let Some(l) = found.label.and_then(|l| label(&l, &self.names))
            {
                self.label = Some(l);
            }
            let mut subs = Vec::new();
            for (long, s) in found.entries {
                if is_dot(&s) {
                    continue;
                }
                let name = long.unwrap_or_else(|| short_name(&s, &self.names));
                if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
                    let within = if folder.path.is_empty() {
                        "the root folder".to_owned()
                    } else {
                        format!("`{}`", folder.path)
                    };
                    cx.warn(format!(
                        "an entry in {within} is named {name:?}, which can't be a file's name; \
                         it's left out"
                    ));
                    continue;
                }
                let path = if folder.path.is_empty() {
                    name
                } else {
                    format!("{}/{name}", folder.path)
                };
                names = names.saturating_add(path.len() as u64);
                if names > MAX_NAMES {
                    return Err(Error::limit(format!(
                        "fat: the volume's paths add up to more than {} MiB",
                        MAX_NAMES >> 20
                    )));
                }
                self.limits.check_entries(entries.len() as u64 + 1)?;
                let attrs = s[11];
                let high = if self.layout.bits == Bits::Fat32 {
                    u32::from(le16(&s, 20)) << 16
                } else {
                    0
                };
                let first = high | u32::from(le16(&s, 26));
                let dir = attrs & 0x10 != 0;
                let kind = if dir { EntryKind::Dir } else { EntryKind::File };
                let mut e = Entry::new(entries.len(), path, kind);
                e.modified = clock.read(DosTime {
                    date: le16(&s, 24),
                    time: le16(&s, 22),
                });
                // Read-only, hidden, system, folder and archive.
                e.dos_attrs = Some(u32::from(attrs & 0x37));
                if dir {
                    if folder.depth + 1 >= MAX_DEPTH {
                        cx.warn(format!(
                            "`{}` is more than {MAX_DEPTH} folders deep; what's in it isn't \
                             listed",
                            e.path
                        ));
                    } else if e.path.len() > MAX_PATH {
                        cx.warn(format!(
                            "`{}`'s path is longer than {MAX_PATH} bytes; what's in it isn't \
                             listed",
                            e.path
                        ));
                    } else {
                        subs.push(Folder {
                            at: At::Chain(first),
                            path: e.path.clone(),
                            depth: folder.depth + 1,
                        });
                    }
                    self.items.push(None);
                } else {
                    let size = u64::from(le32(&s, 28));
                    e.size = Some(size);
                    e.packed_size = Some(size.div_ceil(self.layout.cluster) * self.layout.cluster);
                    self.items.push(Some((first, size)));
                }
                entries.push(e);
            }
            // The first subfolder is read next.
            pending.extend(subs.into_iter().rev());
        }
        Ok(entries)
    }

    fn open(&mut self, id: usize) -> Result<Box<dyn Read + '_>> {
        let Some(&Some((first, size))) = self.items.get(id) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("fat: entry {id} isn't a file"),
            ));
        };
        if size == 0 {
            return Ok(Box::new(io::empty()));
        }
        Ok(Box::new(Chain {
            dev: &mut self.dev,
            table: &mut self.table,
            layout: &self.layout,
            seen: Seen::default(),
            first,
            last: None,
            at: 0,
            run: 0,
            left: size,
        }))
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![
            ("File System", self.layout.bits.name().to_owned()),
            ("Cluster Size", self.layout.cluster.to_string()),
        ];
        if let Some(l) = &self.label {
            p.push(("Label", l.clone()));
        }
        p.push(("Sector Size", self.layout.sector.to_string()));
        p
    }
}

/// A file's data, read along its chain of clusters a run of adjacent ones at a time.
struct Chain<'a> {
    dev: &'a mut Device,
    table: &'a mut Table,
    layout: &'a Layout,
    seen: Seen,
    first: u32,
    /// The last cluster of the run being read; `None` before the first run.
    last: Option<u32>,
    /// Where the run goes on in the volume, and its bytes left.
    at: u64,
    run: u64,
    /// The file's bytes left.
    left: u64,
}

impl Chain<'_> {
    /// The next run: as many adjacent clusters as the chain has, up to what the file still needs.
    /// A file that can't be on the volume fails here, at its first read, like any other damage
    /// to its chain, so that a test reports it and goes on.
    fn next_run(&mut self) -> Result<()> {
        let start = match self.last {
            None => {
                let clusters = self.left.div_ceil(self.layout.cluster);
                if clusters > u64::from(self.layout.count) {
                    return Err(corrupt(format!(
                        "a file of {} bytes needs {clusters} clusters, and the volume has {}",
                        self.left, self.layout.count
                    )));
                }
                if !self.layout.on_volume(self.first) {
                    return Err(corrupt(format!(
                        "the file starts at cluster {}, which isn't on the volume",
                        self.first
                    )));
                }
                self.first
            }
            Some(last) => match self.table.link(self.dev, last)? {
                Link::Next(c) => c,
                Link::End => {
                    return Err(corrupt(format!(
                        "the file's chain of clusters ends before its last {} bytes",
                        self.left
                    )));
                }
                Link::Broken(why) => {
                    return Err(corrupt(format!(
                        "the file's chain of clusters is broken: {why}"
                    )));
                }
            },
        };
        self.mark(start)?;
        let want = self.left.div_ceil(self.layout.cluster);
        let (mut end, mut len) = (start, 1u64);
        while len < want {
            match self.table.link(self.dev, end)? {
                Link::Next(c) if Some(c) == end.checked_add(1) => {
                    self.mark(c)?;
                    end = c;
                    len += 1;
                }
                _ => break,
            }
        }
        self.last = Some(end);
        self.at = self.layout.offset(start)?;
        self.run = len * self.layout.cluster;
        Ok(())
    }

    fn mark(&mut self, c: u32) -> Result<()> {
        if self.seen.insert(c) {
            Ok(())
        } else {
            Err(corrupt(format!(
                "the file's chain of clusters comes back to cluster {c}"
            )))
        }
    }
}

impl Read for Chain<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        if self.run == 0 {
            self.next_run().map_err(Error::into_io)?;
        }
        let n = usize::try_from(self.run.min(self.left))
            .unwrap_or(usize::MAX)
            .min(buf.len());
        self.dev
            .read_exact_at(self.at, &mut buf[..n])
            .map_err(Error::into_io)?;
        self.at += n as u64;
        self.run -= n as u64;
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::{Cursor, Seek, SeekFrom},
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{OpenOptions, SimpleCtx, format::volume::Exact};

    fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// 2026-01-01, as a DOS date.
    const DATE: u16 = (46 << 9) | (1 << 5) | 1;
    /// The end of a chain, and a bad cluster, as FAT32 writes them; [`Mk::set`] cuts them to 12
    /// or 16 bits.
    const EOC: u32 = 0x0FFF_FFFF;
    const BAD: u32 = 0x0FFF_FFF7;

    /// A FAT volume made in memory, laid out as mkfs.fat lays it out: two FATs, a root folder of
    /// 512 entries on FAT12 and FAT16, FAT32's from cluster 2, `BOOTLABEL` in the boot sector.
    /// Folders and files take the next free clusters.
    struct Mk {
        b: Vec<u8>,
        bits: u32,
        cluster: usize,
        fat_at: usize,
        fat_len: usize,
        root_at: usize,
        data_at: usize,
        /// The next free cluster.
        next: u32,
        /// Each folder's next free slot, by its first cluster; 0 is the fixed root.
        fill: HashMap<u32, usize>,
        root: u32,
        /// Where the last 8.3 slot went.
        last: usize,
    }

    impl Mk {
        fn new(bits: u32, bps: usize, spc: usize, sectors: usize) -> Self {
            let fat32 = bits == 32;
            let reserved = if fat32 { 32 } else { 1 };
            let root_entries = if fat32 { 0 } else { 512 };
            let root_sectors = (root_entries * 32usize).div_ceil(bps);
            let most = (sectors - reserved - root_sectors) / spc;
            let fat_sectors = ((most + 2) * bits as usize).div_ceil(8).div_ceil(bps);
            let mut b = vec![0u8; sectors * bps];
            b[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
            b[3..11].copy_from_slice(b"MSWIN4.1");
            put16(&mut b, 11, bps as u16);
            b[13] = spc as u8;
            put16(&mut b, 14, reserved as u16);
            b[16] = 2;
            put16(&mut b, 17, root_entries as u16);
            if sectors < 0x10000 {
                put16(&mut b, 19, sectors as u16);
            } else {
                put32(&mut b, 32, sectors as u32);
            }
            b[21] = 0xF8;
            if fat32 {
                put32(&mut b, 36, fat_sectors as u32);
                put32(&mut b, 44, 2);
                put16(&mut b, 48, 1);
                put16(&mut b, 50, 6);
                b[66] = 0x29;
                b[71..82].copy_from_slice(b"BOOTLABEL  ");
                b[82..90].copy_from_slice(b"FAT32   ");
            } else {
                put16(&mut b, 22, fat_sectors as u16);
                b[38] = 0x29;
                b[43..54].copy_from_slice(b"BOOTLABEL  ");
                b[54..62].copy_from_slice(b"FAT     ");
            }
            b[510] = 0x55;
            b[511] = 0xAA;
            let fat_at = reserved * bps;
            let fat_len = fat_sectors * bps;
            let root_at = fat_at + 2 * fat_len;
            let mut mk = Self {
                b,
                bits,
                cluster: bps * spc,
                fat_at,
                fat_len,
                root_at,
                data_at: root_at + root_sectors * bps,
                next: 2,
                fill: HashMap::new(),
                root: 0,
                last: 0,
            };
            mk.set(0, 0x0FFF_FFF8);
            mk.set(1, EOC);
            // Four clusters for FAT32's root, which holds more than one of 512 bytes.
            if fat32 {
                mk.root = mk.alloc(4);
            }
            mk
        }

        /// Cluster `c`'s entry in both FATs.
        fn set(&mut self, c: u32, v: u32) {
            for k in 0..2 {
                let base = self.fat_at + k * self.fat_len;
                let c = c as usize;
                match self.bits {
                    12 => {
                        let at = base + c + c / 2;
                        let old = u16::from_le_bytes([self.b[at], self.b[at + 1]]);
                        let v = (v & 0xFFF) as u16;
                        let new = if c.is_multiple_of(2) {
                            (old & 0xF000) | v
                        } else {
                            (old & 0x000F) | (v << 4)
                        };
                        put16(&mut self.b, at, new);
                    }
                    16 => put16(&mut self.b, base + 2 * c, v as u16),
                    _ => put32(&mut self.b, base + 4 * c, v & 0x0FFF_FFFF),
                }
            }
        }

        /// The links of a chain through `clusters`, ended.
        fn chain(&mut self, clusters: &[u32]) {
            for w in clusters.windows(2) {
                self.set(w[0], w[1]);
            }
            if let Some(&last) = clusters.last() {
                self.set(last, EOC);
            }
        }

        /// `n` adjacent free clusters, chained; 0 for none.
        fn alloc(&mut self, n: usize) -> u32 {
            if n == 0 {
                return 0;
            }
            let first = self.next;
            let clusters: Vec<u32> = (first..first + n as u32).collect();
            self.chain(&clusters);
            self.next += n as u32;
            first
        }

        /// Where cluster `c` starts.
        fn at(&self, c: u32) -> usize {
            self.data_at + (c as usize - 2) * self.cluster
        }

        /// The root folder, as [`Mk::add`] names it.
        fn root(&self) -> u32 {
            self.root
        }

        /// Puts `slot` in the next free slot of folder `dir`, and says where.
        fn add(&mut self, dir: u32, slot: [u8; 32]) -> usize {
            let i = self.fill.entry(dir).or_default();
            let at = if dir == 0 {
                self.root_at
            } else {
                self.data_at + (dir as usize - 2) * self.cluster
            } + 32 * *i;
            *i += 1;
            self.b[at..at + 32].copy_from_slice(&slot);
            at
        }

        /// An entry in `dir`: its long name's slots, then its 8.3 slot, whose place it gives.
        fn entry(
            &mut self,
            dir: u32,
            long: Option<&str>,
            short: &[u8; 11],
            attrs: u8,
            first: u32,
            size: u32,
        ) -> usize {
            if let Some(l) = long {
                for s in lfn(&l.encode_utf16().collect::<Vec<_>>(), short) {
                    self.add(dir, s);
                }
            }
            self.last = self.add(dir, slot(short, attrs, first, size));
            self.last
        }

        /// A file in adjacent clusters.
        fn file(&mut self, dir: u32, long: Option<&str>, short: &[u8; 11], data: &[u8]) -> usize {
            let first = self.alloc(data.len().div_ceil(self.cluster));
            if first != 0 {
                let at = self.at(first);
                self.b[at..at + data.len()].copy_from_slice(data);
            }
            self.entry(dir, long, short, 0x20, first, data.len() as u32)
        }

        /// A file in runs of two clusters with a free one after each.
        fn fragmented(
            &mut self,
            dir: u32,
            long: Option<&str>,
            short: &[u8; 11],
            data: &[u8],
        ) -> Vec<u32> {
            let base = self.next;
            let n = data.len().div_ceil(self.cluster) as u32;
            let clusters: Vec<u32> = (0..n).map(|i| base + i + i / 2).collect();
            self.chain(&clusters);
            self.next = clusters.last().map_or(base, |c| c + 2);
            for (c, chunk) in clusters.iter().zip(data.chunks(self.cluster)) {
                let at = self.at(*c);
                self.b[at..at + chunk.len()].copy_from_slice(chunk);
            }
            self.entry(dir, long, short, 0x20, clusters[0], data.len() as u32);
            clusters
        }

        /// A folder of `clusters` adjacent clusters in `dir`, with its `.` and `..`.
        fn folder(
            &mut self,
            dir: u32,
            long: Option<&str>,
            short: &[u8; 11],
            clusters: usize,
        ) -> u32 {
            let first = self.alloc(clusters);
            let at = self.entry(dir, long, short, 0x10, first, 0);
            let parent = if dir == self.root { 0 } else { dir };
            self.add(first, slot(b".          ", 0x10, first, 0));
            self.add(first, slot(b"..         ", 0x10, parent, 0));
            self.last = at;
            first
        }
    }

    /// An 8.3 slot, modified 2026-01-01 00:00.
    fn slot(short: &[u8; 11], attrs: u8, first: u32, size: u32) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..11].copy_from_slice(short);
        s[11] = attrs;
        put16(&mut s, 16, DATE);
        put16(&mut s, 18, DATE);
        put16(&mut s, 20, (first >> 16) as u16);
        put16(&mut s, 24, DATE);
        put16(&mut s, 26, first as u16);
        put32(&mut s, 28, size);
        s
    }

    /// The long-name slots of `units` for the 8.3 name `short`, in the order they're stored.
    fn lfn(units: &[u16], short: &[u8; 11]) -> Vec<[u8; 32]> {
        let mut units = units.to_vec();
        if !units.len().is_multiple_of(13) {
            units.push(0);
        }
        while !units.len().is_multiple_of(13) {
            units.push(0xFFFF);
        }
        let n = units.len() / 13;
        let sum = checksum(&slot(short, 0, 0, 0));
        (1..=n)
            .rev()
            .map(|k| {
                let mut s = [0u8; 32];
                s[0] = k as u8 | if k == n { 0x40 } else { 0 };
                s[11] = 0x0F;
                s[13] = sum;
                for (j, &o) in UNITS.iter().enumerate() {
                    s[o..o + 2].copy_from_slice(&units[(k - 1) * 13 + j].to_le_bytes());
                }
                s
            })
            .collect()
    }

    fn units(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// Bytes that don't repeat in a cluster.
    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9u32;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    fn dev(img: Vec<u8>) -> Device {
        let len = img.len() as u64;
        Device::new(Box::new(Cursor::new(img)), len)
    }

    fn options(names: NameDecoding) -> VolumeOptions {
        VolumeOptions {
            limits: Limits::default(),
            names,
        }
    }

    /// A volume opened and listed.
    struct Vol {
        fs: Box<dyn FileSystem>,
        list: Vec<Entry>,
        warnings: Vec<String>,
    }

    impl Vol {
        fn paths(&self) -> Vec<&str> {
            self.list.iter().map(|e| e.path.as_str()).collect()
        }

        fn entry(&self, path: &str) -> &Entry {
            self.list
                .iter()
                .find(|e| e.path == path)
                .unwrap_or_else(|| panic!("no `{path}` in {:?}", self.paths()))
        }

        /// A file's data, held to its size as the disk reader holds it.
        fn data(&mut self, path: &str) -> Result<Vec<u8>> {
            let e = self.entry(path).clone();
            let mut out = Vec::new();
            Exact::new(self.fs.open(e.id)?, e.size.unwrap_or(0), path)
                .read_to_end(&mut out)
                .map_err(|e| Error::from_io(&e))?;
            Ok(out)
        }

        fn property(&self, name: &str) -> Option<String> {
            self.fs
                .properties()
                .into_iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v)
        }
    }

    fn mount_with(img: Vec<u8>, names: NameDecoding) -> Result<Vol> {
        let mut cx = SimpleCtx::new();
        let mut fs = open(dev(img), &options(names), &mut cx)?;
        let list = fs.entries(&mut cx)?;
        for (i, e) in list.iter().enumerate() {
            assert_eq!(e.id, i);
        }
        Ok(Vol {
            fs,
            list,
            warnings: cx.warnings,
        })
    }

    fn mount(img: Vec<u8>) -> Result<Vol> {
        mount_with(img, NameDecoding::default())
    }

    type Want = Vec<(String, Option<Vec<u8>>)>;

    /// A file in `dir`, and what it lists as: its 8.3 slot's place.
    fn put(
        mk: &mut Mk,
        want: &mut Want,
        dir: u32,
        long: Option<&str>,
        short: &[u8; 11],
        path: &str,
        data: &[u8],
    ) -> usize {
        want.push((path.to_owned(), Some(data.to_vec())));
        mk.file(dir, long, short, data)
    }

    /// The tree every layout gets, and what it lists: each path with its data, or `None` for a
    /// folder.
    fn tree(mk: &mut Mk) -> Want {
        let root = mk.root();
        let mut want = Vec::new();
        mk.add(root, slot(b"BEEZIP     ", 0x08, 0, 0));
        // 8.3 names with NT's lowercase flags, as Windows and mtools write `readme.txt`.
        let w = &mut want;
        let at = put(mk, w, root, None, b"README  TXT", "readme.txt", b"Hello!\n");
        mk.b[at + 12] = 0x18;
        let at = put(mk, w, root, None, b"EMPTY   TXT", "empty.txt", b"");
        mk.b[at + 12] = 0x18;
        put(mk, w, root, None, b"UPPER   TXT", "UPPER.TXT", b"UPPER\n");
        let long = "with space.txt";
        put(mk, w, root, Some(long), b"WITHSP~1TXT", long, b"a space\n");
        let long = "bee-🐝.txt";
        put(mk, w, root, Some(long), b"BEE-~1  TXT", long, b"emoji\n");
        let long = "a long name that takes more than one slot, and then some more.txt";
        put(mk, w, root, Some(long), b"ALONGN~1TXT", long, b"long\n");
        let random = noise(mk.cluster * 5 + 100);
        mk.fragmented(root, Some("random.bin"), b"RANDOM  BIN", &random);
        w.push(("random.bin".to_owned(), Some(random)));
        let sub = mk.folder(root, None, b"SUB        ", 1);
        mk.b[mk.last + 12] = 0x08;
        w.push(("sub".to_owned(), None));
        let nested = mk.folder(sub, Some("Ünïcödé dir"), b"UNICOD~1   ", 1);
        w.push(("sub/Ünïcödé dir".to_owned(), None));
        let path = "sub/Ünïcödé dir/日本語.txt";
        put(
            mk,
            w,
            nested,
            Some("日本語.txt"),
            b"___     TXT",
            path,
            b"deep\n",
        );
        want
    }

    #[test]
    fn every_layout_lists_and_reads_its_tree() {
        for (bits, bps, spc, sectors, kind) in [
            (12, 512, 4, 512, "FAT12"),
            (16, 512, 1, 4400, "FAT16"),
            (32, 512, 1, 2048, "FAT32"),
            // 4 KiB sectors.
            (12, 4096, 1, 64, "FAT12"),
            (32, 4096, 2, 1024, "FAT32"),
        ] {
            let mut mk = Mk::new(bits, bps, spc, sectors);
            let want = tree(&mut mk);
            let mut v = mount(mk.b).unwrap();
            assert!(v.warnings.is_empty(), "{kind}: {:?}", v.warnings);
            let mut got: Vec<&str> = v.paths();
            let mut paths: Vec<&str> = want.iter().map(|(p, _)| p.as_str()).collect();
            got.sort_unstable();
            paths.sort_unstable();
            assert_eq!(got, paths, "{kind}");
            // Parents come before what's in them.
            let at = |p: &str| v.paths().iter().position(|q| *q == p).unwrap();
            assert!(at("sub") < at("sub/Ünïcödé dir"));
            assert!(at("sub/Ünïcödé dir") < at("sub/Ünïcödé dir/日本語.txt"));
            for (path, data) in &want {
                let e = v.entry(path).clone();
                match data {
                    Some(d) => {
                        assert_eq!(e.kind, EntryKind::File, "{kind} {path}");
                        assert_eq!(e.size, Some(d.len() as u64), "{kind} {path}");
                        let cluster = (bps * spc) as u64;
                        assert_eq!(
                            e.packed_size,
                            Some((d.len() as u64).div_ceil(cluster) * cluster)
                        );
                        assert_eq!(e.dos_attrs, Some(0x20));
                        assert_eq!(&v.data(path).unwrap(), d, "{kind} {path}");
                    }
                    None => {
                        assert_eq!(e.kind, EntryKind::Dir, "{kind} {path}");
                        assert_eq!(e.dos_attrs, Some(0x10));
                    }
                }
                // Local time, as written.
                let t = ::time::OffsetDateTime::from(e.modified.unwrap());
                let offset =
                    ::time::UtcOffset::local_offset_at(t).unwrap_or(::time::UtcOffset::UTC);
                let local = t.to_offset(offset);
                assert_eq!((local.year(), local.hour()), (2026, 0), "{kind} {path}");
            }
            assert_eq!(v.property("File System").as_deref(), Some(kind));
            let cluster = (bps * spc).to_string();
            assert_eq!(v.property("Cluster Size"), Some(cluster), "{kind}");
            assert_eq!(v.property("Sector Size"), Some(bps.to_string()));
            assert_eq!(v.property("Label").as_deref(), Some("BEEZIP"));
        }
    }

    /// FAT32 by the boot sector, whatever the cluster count; FAT12 below 4,087 clusters and FAT16
    /// from there, as fastfat decides.
    #[test]
    fn the_boot_sector_decides_the_fat_type() {
        let v = mount(Mk::new(32, 512, 1, 300).b).unwrap();
        assert_eq!(v.property("File System").as_deref(), Some("FAT32"));
        // 1 reserved sector, 2 FATs of 17 and 32 for the root, then 4,086 or 4,087 clusters.
        for (sectors, kind) in [(4153, "FAT12"), (4154, "FAT16")] {
            let mk = Mk::new(16, 512, 1, sectors);
            assert_eq!(le16(&mk.b, 22), 17);
            let v = mount(mk.b).unwrap();
            assert_eq!(v.property("File System").as_deref(), Some(kind));
        }
    }

    #[test]
    fn the_label_is_the_root_folders_then_the_boot_sectors() {
        let label = |b: Vec<u8>| mount(b).unwrap().property("Label");
        let mut mk = Mk::new(12, 512, 4, 512);
        mk.add(0, slot(b"ROOT LABEL ", 0x08, 0, 0));
        assert_eq!(label(mk.b).as_deref(), Some("ROOT LABEL"));

        let mut mk = Mk::new(12, 512, 4, 512);
        let mut gone = slot(b"OLD LABEL  ", 0x08, 0, 0);
        gone[0] = 0xE5;
        mk.add(0, gone);
        assert_eq!(label(mk.b).as_deref(), Some("BOOTLABEL"));

        let mut mk = Mk::new(32, 512, 1, 2048);
        mk.b[71..82].copy_from_slice(b"NO NAME    ");
        assert_eq!(label(mk.b), None);

        // No extended boot signature: the boot sector has no label.
        let mut mk = Mk::new(16, 512, 1, 4400);
        mk.b[38] = 0;
        assert_eq!(label(mk.b), None);
    }

    /// The spike's long-name cases: a name whose checksum, sequence or parts don't hold up gives
    /// way to the 8.3 name, and a stray part doesn't stick to the next name.
    #[test]
    fn long_names_must_check_out() {
        let mut mk = Mk::new(12, 512, 1, 1024);
        let root = mk.root();
        let at = mk.file(root, Some("with space.txt"), b"WITHSP~1TXT", b"1");
        mk.b[at - 32 + 13] ^= 0x5A;
        let at = mk.file(root, Some("file-number-001.txt"), b"FILE-N~1TXT", b"2");
        assert_eq!(mk.b[at - 64], 0x42);
        mk.b[at - 64] = 0x43;
        // A stray part, then a name without one and a name with one.
        let mut stray = lfn(&units("STRAY"), b"XXXXXXXXXXX")[0];
        stray[13] = 0x99;
        mk.add(root, stray);
        mk.file(root, None, b"PLAIN   TXT", b"3");
        mk.add(root, stray);
        mk.file(root, Some("after stray.txt"), b"AFTERS~1TXT", b"4");
        // An unpaired surrogate.
        let lone: Vec<u16> = units("bee-")
            .into_iter()
            .chain([0xD83D])
            .chain(units("A.txt"))
            .collect();
        for s in lfn(&lone, b"BEE-~1  TXT") {
            mk.add(root, s);
        }
        let first = mk.alloc(1);
        mk.add(root, slot(b"BEE-~1  TXT", 0x20, first, 1));
        // A deleted slot between the parts of a name.
        let parts = lfn(&units("two parts, cut in the middle"), b"TWOPAR~1TXT");
        mk.add(root, parts[0]);
        let mut gone = parts[1];
        gone[0] = 0xE5;
        mk.add(root, gone);
        mk.add(root, parts[2]);
        let first = mk.alloc(1);
        mk.add(root, slot(b"TWOPAR~1TXT", 0x20, first, 1));
        let v = mount(mk.b).unwrap();
        assert!(v.warnings.is_empty(), "{:?}", v.warnings);
        assert_eq!(
            v.paths(),
            [
                "WITHSP~1.TXT",
                "FILE-N~1.TXT",
                "PLAIN.TXT",
                "after stray.txt",
                "bee-\u{FFFD}A.txt",
                "TWOPAR~1.TXT",
            ]
        );
    }

    #[test]
    fn short_names_go_through_the_oem_code_page() {
        let mut mk = Mk::new(12, 512, 1, 1024);
        let root = mk.root();
        mk.file(root, None, b"CAF\x82    TXT", b"1");
        // 0x05 stands for 0xE5, which marks a deleted slot.
        mk.file(root, None, b"\x05PPER   TXT", b"2");
        let at = mk.file(root, None, b"MIXED   TXT", b"3");
        mk.b[at + 12] = 0x08;
        let at = mk.file(root, None, b"MIXED2  TXT", b"4");
        mk.b[at + 12] = 0x10;
        mk.file(root, None, b"NOEXT      ", b"5");
        let img = mk.b;
        let v = mount(img.clone()).unwrap();
        assert_eq!(
            v.paths(),
            ["CAFé.TXT", "σPPER.TXT", "mixed.TXT", "MIXED2.txt", "NOEXT"]
        );
        let cp850 = NameDecoding {
            oem: 850,
            ..NameDecoding::default()
        };
        assert_eq!(mount_with(img, cp850).unwrap().paths()[1], "ÕPPER.TXT");
    }

    /// Names that can't be a file's are left out, with a warning; so are `.` and `..` other
    /// than the folder's own.
    #[test]
    fn names_with_a_slash_or_nul_are_left_out() {
        let mut mk = Mk::new(12, 512, 1, 1024);
        let root = mk.root();
        mk.file(root, Some("a/b.txt"), b"AB~1    TXT", b"1");
        mk.file(root, Some(".."), b"DOTDOT~1   ", b"2");
        mk.file(root, None, b"NUL\0    TXT", b"3");
        mk.file(root, None, b"           ", b"4");
        mk.file(root, None, b"FINE    TXT", b"5");
        let v = mount(mk.b).unwrap();
        assert_eq!(v.paths(), ["FINE.TXT"]);
        assert_eq!(v.warnings.len(), 4, "{:?}", v.warnings);
        assert!(v.warnings[0].contains("\"a/b.txt\""), "{:?}", v.warnings);
    }

    /// Two names that differ only in case are two files, each with its own data (fstool's
    /// hosted reader finds files by name, and read the wrong one).
    #[test]
    fn case_twins_are_two_files() {
        let mut mk = Mk::new(12, 512, 1, 1024);
        let root = mk.root();
        mk.file(root, Some("MiXed.Txt"), b"MIXED~1 TXT", b"MiXed\n");
        mk.file(root, Some("mixed.txt"), b"MIXED~2 TXT", b"Hello!\n");
        let mut v = mount(mk.b).unwrap();
        assert_eq!(v.data("MiXed.Txt").unwrap(), b"MiXed\n");
        assert_eq!(v.data("mixed.txt").unwrap(), b"Hello!\n");
    }

    /// A FAT12 volume of 512-byte clusters with `README.TXT` and `random.bin`, 64 KiB in one
    /// run: the volume, that run's clusters, the place of its 8.3 slot, and its data.
    fn chained() -> (Mk, Vec<u32>, usize, Vec<u8>) {
        let mut mk = Mk::new(12, 512, 1, 2880);
        mk.file(0, None, b"README  TXT", b"Hello!\n");
        let random = noise(65536);
        let first = mk.next;
        let at = mk.file(0, Some("random.bin"), b"RANDOM  BIN", &random);
        let clusters = (first..first + 128).collect();
        (mk, clusters, at, random)
    }

    fn assert_corrupt(r: Result<Vec<u8>>, says: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
        assert!(e.message.contains(says), "{e}");
    }

    /// The spike's chain cases: a file whose chain doesn't hold it is `Corrupt`, never short or
    /// wrong data (fatfs gave 5,120 bytes of 65,536, or wrong bytes, without an error).
    #[test]
    fn a_chain_that_doesnt_hold_its_file_is_corrupt() {
        let (mk, _, _, random) = chained();
        let mut v = mount(mk.b).unwrap();
        assert!(v.warnings.is_empty());
        assert_eq!(v.data("random.bin").unwrap(), random);

        let broken = |link: usize, to: u32, says: &str| {
            let (mut mk, ch, _, _) = chained();
            mk.set(ch[link], if to == u32::MAX { ch[9] } else { to });
            assert_corrupt(mount(mk.b).unwrap().data("random.bin"), says);
        };
        broken(9, BAD, "is marked bad");
        broken(9, EOC, "ends before its last 60416 bytes");
        // Back to the 10th cluster.
        broken(49, u32::MAX, "comes back to cluster");
        broken(3, 0, "is marked free");
        broken(3, 0xFF0, "isn't on the volume");
        broken(3, 1, "isn't on the volume");

        // A size the chain can't reach, and sizes past it with the chain looping.
        let sized = |size: u32, looping: bool, says: &str| {
            let (mut mk, ch, at, _) = chained();
            put32(&mut mk.b, at + 28, size);
            if looping {
                mk.set(ch[127], ch[0]);
            }
            assert_corrupt(mount(mk.b).unwrap().data("random.bin"), says);
        };
        sized(128 * 512 + 1, false, "ends before its last 1 bytes");
        sized(u32::MAX, true, "needs 8388608 clusters");
        sized(1000 * 512, true, "comes back to cluster");

        // The first cluster reserved, and past the volume.
        for first in [1u16, 0xFF0] {
            let (mut mk, _, at, _) = chained();
            put16(&mut mk.b, at + 26, first);
            let mut v = mount(mk.b).unwrap();
            assert_corrupt(v.data("random.bin"), "isn't on the volume");
            assert_eq!(v.data("README.TXT").unwrap(), b"Hello!\n");
        }
    }

    /// Reads that count the device's reads.
    struct Counted {
        inner: Cursor<Vec<u8>>,
        reads: Arc<AtomicUsize>,
    }

    impl Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.read(buf)
        }
    }

    impl Seek for Counted {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// A run of adjacent clusters is one read, not one a cluster.
    #[test]
    fn runs_of_clusters_are_read_at_once() {
        let (mut mk, _, _, random) = chained();
        let pieces = noise(512 * 10);
        mk.fragmented(0, None, b"PIECES  BIN", &pieces);
        let reads = Arc::new(AtomicUsize::new(0));
        let len = mk.b.len() as u64;
        let input = Counted {
            inner: Cursor::new(mk.b),
            reads: Arc::clone(&reads),
        };
        let mut cx = SimpleCtx::new();
        let opts = options(NameDecoding::default());
        let mut fs = open(Device::new(Box::new(input), len), &opts, &mut cx).unwrap();
        let list = fs.entries(&mut cx).unwrap();
        // The FAT, then the run; then five runs of two.
        for (name, want, most) in [("random.bin", &random, 2), ("PIECES.BIN", &pieces, 5)] {
            let e = list.iter().find(|e| e.path == name).unwrap();
            let before = reads.load(Ordering::Relaxed);
            let mut got = Vec::new();
            let mut r = fs.open(e.id).unwrap();
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = r.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            drop(r);
            assert_eq!(&got, want);
            let n = reads.load(Ordering::Relaxed) - before;
            assert!(n <= most, "{name}: {n} reads");
        }
    }

    /// `many/` in 4 clusters of 16 slots, full: `.`, `..` and 62 files.
    fn many(mk: &mut Mk) -> (u32, Vec<String>) {
        let m = mk.folder(0, None, b"MANY       ", 4);
        let mut names = Vec::new();
        for i in 0..62 {
            let short = format!("F{i:02}     TXT");
            mk.file(m, None, short.as_bytes().try_into().unwrap(), b"x");
            names.push(format!("MANY/F{i:02}.TXT"));
        }
        (m, names)
    }

    /// The spike's folder cases: a folder inside itself, chains that loop or break, and slots
    /// past the end marker. Each is listed as far as it goes, once, with a warning.
    #[test]
    fn folders_are_listed_once_and_the_walk_ends() {
        // `SUB/NESTED` is `SUB` again.
        let mut mk = Mk::new(12, 512, 1, 1024);
        let sub = mk.folder(0, None, b"SUB        ", 1);
        mk.file(sub, None, b"A       TXT", b"a");
        mk.folder(sub, None, b"NESTED     ", 1);
        put16(&mut mk.b, mk.last + 26, sub as u16);
        let v = mount(mk.b).unwrap();
        assert_eq!(v.paths(), ["SUB", "SUB/A.TXT", "SUB/NESTED"]);
        assert_eq!(v.warnings.len(), 1, "{:?}", v.warnings);
        assert!(v.warnings[0].contains("already listed"), "{:?}", v.warnings);

        // Its 4th cluster links back to its 1st.
        let mut mk = Mk::new(12, 512, 1, 1024);
        let (m, names) = many(&mut mk);
        mk.set(m + 3, m);
        let v = mount(mk.b).unwrap();
        assert_eq!(v.paths()[1..], names);
        assert!(
            v.warnings[0].contains("runs into cluster"),
            "{:?}",
            v.warnings
        );

        // Its 2nd holds only deleted slots and links to itself.
        let mut mk = Mk::new(12, 512, 1, 1024);
        let (m, names) = many(&mut mk);
        let at = mk.at(m + 1);
        for s in 0..16 {
            mk.b[at + 32 * s] = 0xE5;
        }
        mk.set(m + 1, m + 1);
        let v = mount(mk.b).unwrap();
        assert_eq!(v.paths()[1..], names[..14]);
        assert!(
            v.warnings[0].contains("runs into cluster"),
            "{:?}",
            v.warnings
        );

        // Its 2nd links to cluster 1.
        let mut mk = Mk::new(12, 512, 1, 1024);
        let (m, names) = many(&mut mk);
        mk.set(m + 1, 1);
        let v = mount(mk.b).unwrap();
        assert_eq!(v.paths()[1..], names[..30]);
        assert!(v.warnings[0].contains("is broken"), "{:?}", v.warnings);

        // A deleted slot, two live ones, the end marker, and a live-looking slot after it.
        let mut mk = Mk::new(12, 512, 1, 1024);
        let gone = mk.file(0, None, b"GONE    TXT", b"g");
        mk.file(0, None, b"README  TXT", b"r");
        mk.b[gone] = 0xE5;
        let readme = mk.last;
        mk.b.copy_within(readme..readme + 32, readme + 64);
        mk.b[readme + 64] = b'G';
        let v = mount(mk.b).unwrap();
        assert_eq!(v.paths(), ["README.TXT"]);

        // Folders at cluster 0, past the volume, and at the root's.
        let mut mk = Mk::new(32, 512, 1, 2048);
        let root = mk.root();
        mk.entry(root, None, b"ZERO       ", 0x10, 0, 0);
        mk.entry(root, None, b"PAST       ", 0x10, 0x0FFF_0000, 0);
        mk.entry(root, None, b"ROOT       ", 0x10, root, 0);
        let v = mount(mk.b).unwrap();
        assert_eq!(v.paths(), ["ZERO", "PAST", "ROOT"]);
        assert_eq!(v.warnings.len(), 3, "{:?}", v.warnings);
    }

    #[test]
    fn the_walk_stops_at_the_depth_cap_and_when_cancelled() {
        let mut mk = Mk::new(12, 512, 1, 1024);
        let mut dir = 0;
        for _ in 0..300 {
            dir = mk.folder(dir, None, b"D          ", 1);
        }
        let v = mount(mk.b.clone()).unwrap();
        assert_eq!(v.list.len(), MAX_DEPTH);
        let deep = "more than 256 folders deep";
        assert!(v.warnings[0].contains(deep), "{:?}", v.warnings);

        let flag = Arc::new(AtomicBool::new(true));
        let mut cx = SimpleCtx::new().with_cancel(flag);
        let opts = options(NameDecoding::default());
        let mut fs = open(dev(mk.b), &opts, &mut cx).unwrap();
        assert_eq!(fs.entries(&mut cx).unwrap_err().kind, ErrorKind::Cancelled);
    }

    /// An image cut short reads zeros past its end, with a warning, instead of being refused.
    #[test]
    fn a_truncated_image_reads_zeros_past_its_end() {
        let mut mk = Mk::new(16, 512, 1, 4400);
        mk.file(0, None, b"EARLY   TXT", b"early");
        mk.next = 4000;
        mk.file(0, None, b"LATE    TXT", b"late");
        let half = mk.b.len() / 2;
        mk.b.truncate(half);
        let mut v = mount(mk.b).unwrap();
        assert!(v.warnings[0].contains("cut short"), "{:?}", v.warnings);
        assert_eq!(v.data("EARLY.TXT").unwrap(), b"early");
        assert_eq!(v.data("LATE.TXT").unwrap(), [0; 4]);
    }

    /// FAT32's details: a root folder moved off cluster 2, an FSInfo sector zeroed, dirty flags,
    /// a FAT over two pages, and only the second FAT in use.
    #[test]
    fn fat32_details() {
        let mut mk = Mk::new(32, 512, 1, 17_000);
        let moved = mk.alloc(1);
        put32(&mut mk.b, 44, moved);
        mk.set(2, 0);
        mk.root = moved;
        mk.b[512..1024].fill(0);
        mk.b[0x41] |= 1;
        mk.set(1, EOC & !0x0800_0000);
        mk.file(moved, None, b"README  TXT", b"Hello\n");
        // The entries of clusters 16,380 to 16,387 are in the FAT's first two pages.
        mk.next = 16_380;
        let data = noise(512 * 8);
        mk.file(moved, None, b"ACROSS  BIN", &data);
        let mut v = mount(mk.b.clone()).unwrap();
        assert!(v.warnings.is_empty(), "{:?}", v.warnings);
        assert_eq!(v.paths(), ["README.TXT", "ACROSS.BIN"]);
        assert_eq!(v.data("ACROSS.BIN").unwrap(), data);

        // Only FAT 1 kept up to date: FAT 0's chain is wrong.
        put16(&mut mk.b, 40, 0x81);
        put32(&mut mk.b, mk.fat_at + 4 * 16_381, 0);
        let mut v = mount(mk.b.clone()).unwrap();
        assert_eq!(v.data("ACROSS.BIN").unwrap(), data);
        put16(&mut mk.b, 40, 0x80);
        assert_corrupt(mount(mk.b).unwrap().data("ACROSS.BIN"), "is marked free");
    }

    /// A boot sector whose fields don't add up is `Corrupt`; sectors of 128 or 256 bytes, which
    /// Windows reads, are `UnsupportedOperation`.
    #[test]
    fn boot_sectors_that_dont_add_up_are_refused() {
        let fat16 = Mk::new(16, 512, 1, 4400).b;
        let fat32 = Mk::new(32, 512, 1, 2048).b;
        type Change = fn(&mut [u8]);
        let cases: [(&[u8], Change, ErrorKind); 15] = [
            (&fat16, |b| put16(b, 11, 0), ErrorKind::Corrupt),
            (&fat16, |b| put16(b, 11, 1000), ErrorKind::Corrupt),
            (&fat16, |b| put16(b, 11, 8192), ErrorKind::Corrupt),
            (
                &fat16,
                |b| put16(b, 11, 256),
                ErrorKind::UnsupportedOperation,
            ),
            (&fat16, |b| b[13] = 0, ErrorKind::Corrupt),
            (&fat16, |b| b[13] = 3, ErrorKind::Corrupt),
            (&fat16, |b| put16(b, 14, 0), ErrorKind::Corrupt),
            (&fat16, |b| b[16] = 0, ErrorKind::Corrupt),
            (&fat16, |b| put16(b, 19, 0), ErrorKind::Corrupt),
            (&fat16, |b| put16(b, 17, 0), ErrorKind::Corrupt),
            (&fat16, |b| put16(b, 22, 1), ErrorKind::Corrupt),
            (&fat16, |b| put16(b, 19, 60), ErrorKind::Corrupt),
            (&fat32, |b| put32(b, 44, 5000), ErrorKind::Corrupt),
            (&fat32, |b| put16(b, 17, 16), ErrorKind::Corrupt),
            (&fat32, |b| put16(b, 40, 0x82), ErrorKind::Corrupt),
        ];
        for (i, (img, change, kind)) in cases.into_iter().enumerate() {
            let mut b = img.to_vec();
            change(&mut b);
            let e = mount(b).err().unwrap_or_else(|| panic!("case {i} opened"));
            assert_eq!(e.kind, kind, "case {i}: {e}");
        }
        assert_eq!(mount(vec![0; 100]).err().unwrap().kind, ErrorKind::Corrupt);
    }

    /// Bytes changed at random in a small volume's boot sector, FATs and folders: whatever it
    /// gives, nothing panics and every walk ends.
    #[test]
    fn changed_bytes_never_panic() {
        // `BEEZIP_FAT_MUTATIONS` runs more, on a release build.
        let runs = std::env::var("BEEZIP_FAT_MUTATIONS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1000);
        let mut x = 12345u32;
        let mut rand = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as usize
        };
        for (bits, sectors) in [(12, 256), (32, 600)] {
            let mut mk = Mk::new(bits, 512, 1, sectors);
            tree(&mut mk);
            let root = mk.root();
            mk.folder(root, Some("more"), b"MORE       ", 2);
            let hot = mk.data_at + 16 * 512;
            let img = mk.b;
            for _ in 0..runs {
                let mut b = img.clone();
                for _ in 0..1 + rand() % 8 {
                    let at = rand() % hot;
                    b[at] = rand() as u8;
                }
                let Ok(mut v) = mount(b) else {
                    continue;
                };
                let files: Vec<String> = v
                    .list
                    .iter()
                    .filter(|e| e.kind == EntryKind::File)
                    .map(|e| e.path.clone())
                    .collect();
                for p in files {
                    let _ = v.data(&p);
                }
            }
        }
    }

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn sha256(data: &[u8]) -> String {
        Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// 7-Zip's FAT images, through detection and the disk reader: every file their records list,
    /// with the same size and data, and the folders.
    #[test]
    fn seven_zip_images_read_as_recorded() {
        let text = std::fs::read_to_string(fixture("manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
        for (file, kind, levels) in [
            ("7zip/fat12.img", "FAT12", vec!["fat"]),
            ("7zip/fat32.img", "FAT32", vec!["fat"]),
            ("7zip/mbr-fat.img", "FAT12", vec!["mbr", "fat"]),
        ] {
            let record = manifest["fixtures"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["file"] == file)
                .unwrap();
            let mut want: Vec<(String, u64, String)> = record["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["path"].as_str().unwrap().to_owned(),
                        e["size"].as_u64().unwrap(),
                        e["sha256"].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            want.sort();
            let mut cx = SimpleCtx::new();
            let path = fixture("thirdparty").join(file);
            let mut opened = crate::open(&path, &OpenOptions::default(), &mut cx).unwrap();
            let r = &mut opened.reader;
            let list = r.entries(&mut cx).unwrap().to_vec();
            let mut got = Vec::new();
            let mut dirs = Vec::new();
            for e in &list {
                if e.kind == EntryKind::Dir {
                    dirs.push(e.path.clone());
                    continue;
                }
                let mut data = Vec::new();
                r.open_entry(e.id, &mut cx)
                    .unwrap()
                    .read_to_end(&mut data)
                    .unwrap();
                got.push((e.path.clone(), e.size.unwrap(), sha256(&data)));
            }
            got.sort();
            dirs.sort();
            assert_eq!(got, want, "{file}");
            assert!(got.iter().any(|(p, ..)| p == "bee-\u{F41D}.txt"), "{file}");
            assert_eq!(dirs, ["sub", "sub/nested", "Ünïcödé dir"], "{file}");
            let info = r.info(&mut cx).unwrap().external.unwrap();
            assert_eq!(info.levels, levels, "{file}");
            let prop = |n: &str| {
                info.properties
                    .iter()
                    .find(|p| p.name == n)
                    .map(|p| p.value.clone())
            };
            assert_eq!(prop("File System").as_deref(), Some(kind), "{file}");
            let label = format!("BEEZIP{kind}");
            assert_eq!(prop("Label"), Some(label), "{file}");
            assert!(cx.warnings.is_empty(), "{file}: {:?}", cx.warnings);
        }
    }

    /// The FAT spike's images (`target/m7-spikes/fat`) when `BEEZIP_FAT_SPIKE` names that folder:
    /// the kernel-made volumes give every file of `tree.sha256` they hold, and the edge images
    /// behave as their README says.
    #[test]
    fn the_spikes_images() {
        let Ok(dir) = std::env::var("BEEZIP_FAT_SPIKE") else {
            return;
        };
        let dir = Path::new(&dir).join("images");
        let tree: HashMap<String, String> = std::fs::read_to_string(dir.join("tree.sha256"))
            .unwrap()
            .lines()
            .map(|l| {
                let (sha, path) = l.split_once("  ").unwrap();
                (path.trim_start_matches("./").to_owned(), sha.to_owned())
            })
            .collect();
        let read = |name: &str| mount(std::fs::read(dir.join(name)).unwrap());
        for (name, files) in [
            ("fat16.img", 617),
            ("fat32big.img", 617),
            ("fat12-4k.img", 4),
        ] {
            let mut v = read(name).unwrap();
            assert!(v.warnings.is_empty(), "{name}: {:?}", v.warnings);
            let paths: Vec<String> = v
                .list
                .iter()
                .filter(|e| e.kind == EntryKind::File)
                .map(|e| e.path.clone())
                .collect();
            assert_eq!(paths.len(), files, "{name}");
            for p in paths {
                let data = v.data(&p).unwrap();
                assert_eq!(Some(&sha256(&data)), tree.get(&p), "{name}: {p}");
            }
        }
        let edge = |name: &str| read(&format!("edge/{name}.img")).unwrap();
        let has = |v: &Vol, p: &str| v.paths().contains(&p);
        let all = read("fat16.img").unwrap().list.len();
        assert!(has(&edge("lfn-bad-checksum"), "WITHSP~1.TXT"));
        let v = edge("lfn-bad-sequence");
        assert!(!has(&v, "many/file-number-001.txt") && v.list.len() == all);
        assert_eq!(
            edge("lfn-orphan").paths(),
            read("fat16.img").unwrap().paths()
        );
        assert!(has(&edge("lfn-unpaired-surrogate"), "bee-\u{FFFD}A.txt"));
        assert!(has(&edge("sfn-oem-byte"), "CAFé.TXT"));
        assert!(has(&edge("sfn-05-lead"), "σPPER.TXT"));
        let label = edge("label-differs").property("Label");
        assert_eq!(label.as_deref(), Some("BEEZIPFAT16"));
        for (name, file, says) in [
            ("chain-bad-cluster", "random.bin", "marked bad"),
            ("chain-short", "random.bin", "ends before"),
            ("chain-loop-file", "random.bin", "comes back"),
            ("size-huge", "random.bin", "clusters"),
            ("size-huge-loop", "random.bin", "clusters"),
            ("file-cluster1", "readme.txt", "isn't on the volume"),
            ("file-cluster-past-end", "readme.txt", "isn't on the volume"),
        ] {
            assert_corrupt(edge(name).data(file), says);
        }
        for name in [
            "dir-cycle",
            "dir-chain-loop",
            "dir-loop-deleted",
            "dir-chain-cluster1",
        ] {
            let v = edge(name);
            assert_eq!(v.warnings.len(), 1, "{name}: {:?}", v.warnings);
        }
        let mut v = edge("case-twins");
        assert_eq!(v.data("MiXed.Txt").unwrap(), b"MiXed\n");
        assert_eq!(v.data("mixed.txt").unwrap(), b"Hello, BeeZip!\n");
        let v = edge("after-end-marker");
        assert!(
            !v.paths()
                .iter()
                .any(|p| p.eq_ignore_ascii_case("geadme.txt"))
        );
        assert!(edge("truncated-half").warnings[0].contains("cut short"));
        for name in [
            "dirty",
            "fat32-dirty",
            "fat32-fsinfo-zero",
            "fat32-root-moved",
            "fat32-fsver",
        ] {
            let mut v = edge(name);
            assert!(v.warnings.is_empty(), "{name}: {:?}", v.warnings);
            let readme = v.data("readme.txt").unwrap();
            assert_eq!(readme, b"Hello, BeeZip!\n", "{name}");
        }
    }
}
