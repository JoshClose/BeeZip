//! DMG (docs/M5.md §5.11): an Apple disk image, listed by the HFS+ or APFS volume inside, and
//! written as an HFS+ volume in a UDZO image.
//!
//! - **The container** is BeeZip's own ([`udif`]). An image with `encrcdsa` at its start or
//!   `cdsaencr` at its end is encrypted, and refused. Behind a codec (`.dmg.gz`) the image is
//!   spooled to a temporary file first, since it's read at offsets.
//! - **The volume** is read through fstool 0.5.2, which only this file names. The UDIF disk goes
//!   in through fstool's `BlockDevice`, whose writes fail. The partition map (GPT, APM or none)
//!   comes from `detect_partition_table`, then each of the image's own partitions is a candidate
//!   too, and the largest with an HFS+, HFSX or APFS signature that opens is the volume
//!   (`AnyFs::open`; an APFS container's first volume). The walk lists folders, files and
//!   symlinks, with their sizes, times and modes; it goes at most [`MAX_DEPTH`] folders deep and
//!   never into a folder twice. HFS+ hard links are files with their data (fstool follows them),
//!   and HFS+'s private-data folder, where that data lives, is listed as `[HFS+ Private Data]` as
//!   7-Zip shows it. HFS+ stores names decomposed; they're listed composed again (dmg/nfc.rs).
//! - **Apple-compressed files** (decmpfs) are BeeZip's to decode ([`decmpfs`]): fstool reads their
//!   header in the wrong byte order and fails them. Their attribute comes from fstool, and an
//!   HFS+ file's resource fork from fstool's catalog and fork readers. fstool doesn't reach APFS
//!   resource forks, so an APFS file compressed into one is `UnsupportedOperation`. They're
//!   listed at their size uncompressed.
//! - **Without HFS+ or APFS**, the image's partitions are the entries, named as 7-Zip names them
//!   (`0.MBR`, `3.free`, `4.hfs`), and extract as their sectors.
//! - **Writing:** the entries go onto an HFS+ volume through fstool's writer, in a temporary file
//!   beside the output, sized from [`ArchiveWriter::expect`]'s entries with 1/64 more and a MiB
//!   spare. It's case-sensitive (HFSX) when two paths differ only in case. Then
//!   [`udif::write_udzo`] compresses it. The volume is named after the output file. Entries are
//!   owned by 501:20 (the first macOS user and `staff`, as hdiutil's image of a user's folder
//!   is), with their modes or 0644 for files and 0755 for folders and links; HFS+ holds times
//!   from 1970 to 2040 through fstool, and others are clamped. A file announced as empty but
//!   with data (a bare stream's, whose size wasn't known) is spooled to learn its size, and a
//!   file that doesn't fit in the volume is refused rather than written into a broken one.

mod decmpfs;
mod lzvn;
mod nfc;

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use fstool::{
    block::BlockDevice,
    fs::{
        EntryKind as FsKind, FsSizePlan, SetAttrs,
        hfs_plus::{
            FormatOpts, HfsPlus,
            btree::ForkReader,
            catalog::{Catalog, CatalogKey, CatalogRecord, UniStr},
            extents::ExtentsOverflow,
            hfs_date_from_unix,
            size_plan::HfsPlusSizePlan,
            volume_header::read_volume_header,
        },
    },
    inspect::{AnyFs, detect_partition_table},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, NewEntry, NewKind, Selection, udif,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, Checked, CountingReader, WriteSeek, copy, read_error, write_error},
    limits::Limits,
    safefs::Partial,
    source::Source,
    time::{from_unix, to_unix},
};

pub struct Dmg;

/// The UDIF trailer's magic, at the start of the last 512 bytes.
pub const KOLY: &[u8; 4] = b"koly";
/// An encrypted image: `encrcdsa` at the start (version 2), `cdsaencr` at the end (version 1).
pub const ENCRYPTED_HEAD: &[u8; 8] = b"encrcdsa";
pub const ENCRYPTED_TAIL: &[u8; 8] = b"cdsaencr";

/// The deepest folder the walk goes into.
pub const MAX_DEPTH: usize = 256;
/// The owner of what BeeZip writes: the first macOS user, and `staff`.
const UID: u32 = 501;
const GID: u32 = 20;
/// The latest time HFS+ holds, 2040-02-06 06:28:15 UTC, in Unix seconds.
const HFS_LAST: i64 = u32::MAX as i64 - 2_082_844_800;
/// HFS+'s folder for the data of hard links, and how 7-Zip shows it.
const PRIVATE_DATA: &str = "\0\0\0\0HFS+ Private Data";
const PRIVATE_DATA_SHOWN: &str = "[HFS+ Private Data]";

const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

impl ArchiveFormat for Dmg {
    fn id(&self) -> FormatId {
        FormatId::Dmg
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".dmg"]
    }

    /// A `koly` trailer of version 4 and 512 bytes is certain. An encrypted image is likely, so
    /// it opens to be refused with a reason.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        if probe.head.starts_with(ENCRYPTED_HEAD) || probe.tail.ends_with(ENCRYPTED_TAIL) {
            return Some(Confidence::Likely);
        }
        let t = probe.tail;
        let koly = t.len().checked_sub(512).map(|at| &t[at..])?;
        if !koly.starts_with(KOLY) {
            return None;
        }
        let version = u32::from_be_bytes([koly[4], koly[5], koly[6], koly[7]]);
        let size = u32::from_be_bytes([koly[8], koly[9], koly[10], koly[11]]);
        if version == 4 && size == 512 {
            Some(Confidence::Certain)
        } else {
            Some(Confidence::Likely)
        }
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}

/// How to write a DMG: an HFS+ volume, as UDZO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DmgWriteOptions {}

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("dmg: {message}"))
}

/// An fstool error met while reading. Errors of the disk come back as they were.
fn fs_error(e: fstool::Error) -> Error {
    match e {
        fstool::Error::Io(e) => read_error(&e),
        fstool::Error::Unsupported(m) => Error::unsupported(format!("dmg: {m}")),
        e => bad(e),
    }
}

/// An fstool error met while writing `what`. Errors of the data come back as they were.
fn write_fs_error(e: fstool::Error, what: &str) -> Error {
    match e {
        fstool::Error::Io(e) => {
            let err = Error::from_io(&e);
            if err.kind == ErrorKind::Corrupt && e.get_ref().is_none_or(|i| !i.is::<Error>()) {
                Error::new(ErrorKind::Io, format!("dmg: `{what}`: {}", err.message))
            } else {
                err
            }
        }
        fstool::Error::InvalidArgument(m) => Error::invalid_args(format!("dmg: `{what}`: {m}")),
        fstool::Error::Unsupported(m) => Error::unsupported(format!("dmg: `{what}`: {m}")),
        e => Error::new(ErrorKind::Io, format!("dmg: `{what}`: {e}")),
    }
}

trait Input: Read + Seek + Send {}

impl<T: Read + Seek + Send> Input for T {}

/// The UDIF disk as fstool's block device. Reading only: a write fails.
struct Device(udif::Disk<Box<dyn Input>>);

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for Device {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl Write for Device {
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

impl BlockDevice for Device {
    fn block_size(&self) -> u32 {
        udif::SECTOR as u32
    }

    fn total_size(&self) -> u64 {
        self.0.len()
    }

    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}

/// The device as fstool's attribute reader sees it. fstool sizes an attribute's buffer from the
/// length the volume claims, checked only against the device's size, so here the device looks
/// [`decmpfs::MAX_ATTR`] long; reads still reach all of it.
struct Capped<'a>(&'a mut Device);

impl Read for Capped<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for Capped<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl Write for Capped<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BlockDevice for Capped<'_> {
    fn block_size(&self) -> u32 {
        self.0.block_size()
    }

    fn total_size(&self) -> u64 {
        self.0.total_size().min(decmpfs::MAX_ATTR as u64)
    }

    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> fstool::Result<()> {
        self.0.read_at(offset, buf)
    }
}

/// What an entry's data is.
enum Item {
    /// A folder, a link or a special file: none.
    None,
    /// A file of the volume, at `path` in fstool's terms.
    File {
        path: String,
        size: u64,
        compressed: bool,
    },
    /// One of the image's partitions, by index.
    Partition(usize),
}

/// What the entries come from.
enum Volume {
    Fs {
        fs: Box<AnyFs>,
        /// The HFS+ catalog, opened the first time a resource fork is needed.
        forks: Option<HfsForks>,
    },
    Partitions,
}

/// HFS+'s catalog and extents-overflow trees, for resource forks, which fstool's own readers
/// refuse for compressed files.
struct HfsForks {
    catalog: Catalog,
    overflow: Option<ExtentsOverflow>,
    block_size: u32,
}

impl HfsForks {
    fn open(dev: &mut Device) -> Result<Self> {
        let vh = read_volume_header(dev).map_err(fs_error)?;
        let fork = ForkReader::from_inline(&vh.catalog_file, vh.block_size, "catalog")
            .map_err(fs_error)?;
        let catalog = Catalog::open(dev, fork, vh.is_hfsx()).map_err(fs_error)?;
        let overflow = if vh.extents_file.total_blocks > 0 {
            let fork = ForkReader::from_inline(&vh.extents_file, vh.block_size, "extents")
                .map_err(fs_error)?;
            Some(ExtentsOverflow::open(dev, fork).map_err(fs_error)?)
        } else {
            None
        };
        Ok(Self {
            catalog,
            overflow,
            block_size: vh.block_size,
        })
    }

    /// The resource fork of the file record `cnid`, found through its thread record.
    fn resource_fork(&self, dev: &mut Device, cnid: u32) -> Result<ForkReader> {
        let key = CatalogKey {
            parent_id: cnid,
            name: UniStr::default(),
            encoded_len: 0,
        };
        let Some(CatalogRecord::Thread(t)) = self.catalog.lookup(dev, &key).map_err(fs_error)?
        else {
            return Err(bad(format!("file {cnid} has no thread record")));
        };
        let key = CatalogKey {
            parent_id: t.parent_id,
            name: t.name,
            encoded_len: 0,
        };
        let Some(CatalogRecord::File(f)) = self.catalog.lookup(dev, &key).map_err(fs_error)? else {
            return Err(bad(format!("file {cnid} has no file record")));
        };
        let fork = f.resource_fork;
        if u64::from(fork.total_blocks) <= fork.inline_blocks() {
            return ForkReader::from_inline(&fork, self.block_size, "resource").map_err(fs_error);
        }
        let overflow = self.overflow.as_ref().ok_or_else(|| {
            bad("a resource fork needs the extents-overflow file, which is empty")
        })?;
        let first = u32::try_from(fork.inline_blocks()).map_err(|_| bad("a fork too large"))?;
        let extra = overflow
            .find_extents(dev, cnid, 0xFF, first)
            .map_err(fs_error)?;
        ForkReader::from_inline_plus_overflow(&fork, &extra, self.block_size, "resource")
            .map_err(fs_error)
    }
}

/// An HFS+ resource fork for [`decmpfs`].
struct HfsFork<'a> {
    dev: &'a mut Device,
    reader: ForkReader,
}

impl decmpfs::Fork for HfsFork<'_> {
    fn len(&self) -> u64 {
        self.reader.logical_size
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.reader.logical_size)
        {
            return Err(bad("a read past the end of a resource fork"));
        }
        self.reader.read(self.dev, offset, buf).map_err(fs_error)
    }
}

/// Exactly `left` bytes of `inner`: a file whose data ends early is `Corrupt`.
struct Exact<R> {
    inner: R,
    left: u64,
    path: String,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(bad(format!("`{}` ends {} bytes short", self.path, self.left)).into_io());
        }
        self.left -= n as u64;
        Ok(n)
    }
}

pub struct DmgReader {
    source: Source,
    image: udif::Image,
    dev: Device,
    volume: Volume,
    entries: Vec<Entry>,
    items: Vec<Item>,
    /// Keeps an image spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl DmgReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (mut input, len, spool) = open_input(&source, cx)?;
        refuse_encrypted(&mut *input, len)?;
        let image = udif::read_image(&mut *input, len)?;
        let disk = udif::Disk::new(input, &image, &source.limits)?;
        let mut dev = Device(disk);
        let (volume, entries, items) = match find_volume(&mut dev, &image, cx) {
            Some(mut fs) => {
                let (entries, items) = walk(&mut fs, &mut dev, &source.limits, cx)?;
                (Volume::Fs { fs, forks: None }, entries, items)
            }
            None => {
                let (entries, items) = partition_entries(&image, &source.limits)?;
                (Volume::Partitions, entries, items)
            }
        };
        Ok(Self {
            source,
            image,
            dev,
            volume,
            entries,
            items,
            _spool: spool,
        })
    }
}

/// The image to read at offsets, counted: the file, or the stream spooled out of its codecs.
fn open_input(source: &Source, cx: &mut dyn Ctx) -> Result<(Box<dyn Input>, u64, Option<Partial>)> {
    if source.codecs.is_empty() {
        let input = source.input()?;
        let len = input.len();
        let counted = CountingReader::new(input, source.counter.clone());
        return Ok((Box::new(counted), len, None));
    }
    let mut tmp = Partial::create_temp("beezip-spool.dmg")?;
    let mut stream = source.guard(source.open_stream()?);
    copy(&mut stream, tmp.file_mut(), cx)?;
    tmp.close();
    let file = tmp.reopen()?;
    let len = file
        .metadata()
        .map_err(|e| Error::io(format!("reading {}", tmp.path().display()), &e))?
        .len();
    let counted = CountingReader::new(file, source.counter.clone());
    Ok((Box::new(counted), len, Some(tmp)))
}

fn refuse_encrypted(input: &mut dyn Input, len: u64) -> Result<()> {
    let mut head = [0u8; 8];
    let mut tail = [0u8; 8];
    if len >= 8 {
        input.seek(SeekFrom::Start(0)).map_err(|e| read_error(&e))?;
        input.read_exact(&mut head).map_err(|e| read_error(&e))?;
        input
            .seek(SeekFrom::Start(len - 8))
            .map_err(|e| read_error(&e))?;
        input.read_exact(&mut tail).map_err(|e| read_error(&e))?;
    }
    if &head == ENCRYPTED_HEAD || &tail == ENCRYPTED_TAIL {
        return Err(Error::unsupported_format(
            "encrypted disk images aren't supported",
        ));
    }
    Ok(())
}

/// The volume's filesystem's name, from its signature, when it's one fstool reads here.
fn signature(dev: &mut Device, base: u64, len: u64) -> Option<&'static str> {
    if len < 1026 {
        return None;
    }
    dev.0.set_window(base, len).ok()?;
    let mut head = [0u8; 1026];
    dev.read_at(0, &mut head).ok()?;
    if &head[1024..] == b"H+" || &head[1024..] == b"HX" {
        Some("HFS+")
    } else if &head[32..36] == b"NXSB" {
        Some("APFS")
    } else {
        None
    }
}

/// The HFS+ or APFS volume to list: the partitions of the partition map, or the whole disk when
/// there's none, and then the image's own partitions, largest first; the first with a signature
/// that opens. Volumes that don't open are warned about. The device is left windowed to it.
fn find_volume(dev: &mut Device, image: &udif::Image, cx: &mut dyn Ctx) -> Option<Box<AnyFs>> {
    let size = dev.0.disk_size();
    let mut spans: Vec<(u64, u64)> = Vec::new();
    if dev.0.set_window(0, size).is_ok() {
        match detect_partition_table(dev) {
            Ok(Some(table)) => spans.extend(table.partitions().iter().filter_map(|p| {
                let base = p.start_lba.checked_mul(udif::SECTOR)?;
                let len = p.size_lba.checked_mul(udif::SECTOR)?;
                (base.checked_add(len)? <= size).then_some((base, len))
            })),
            Ok(None) => spans.push((0, size)),
            Err(_) => {}
        }
    }
    let mut own: Vec<&udif::Partition> = image.partitions.iter().collect();
    own.sort_by_key(|p| Reverse(p.sectors));
    for p in own {
        let span = (p.first_sector * udif::SECTOR, p.bytes());
        if !spans.contains(&span) {
            spans.push(span);
        }
    }
    let mut found: Vec<(u64, u64, &str)> = spans
        .into_iter()
        .filter_map(|(base, len)| signature(dev, base, len).map(|kind| (base, len, kind)))
        .collect();
    found.sort_by_key(|&(_, len, _)| Reverse(len));
    for (base, len, kind) in found {
        if dev.0.set_window(base, len).is_err() {
            continue;
        }
        match AnyFs::open(dev) {
            Ok(fs) => return Some(Box::new(fs)),
            Err(e) => cx.warn(format!(
                "the {kind} volume at byte {base} can't be read ({}); the image's partitions are \
                 listed instead",
                fs_error(e)
            )),
        }
    }
    None
}

/// A name as stored: HFS+'s decomposed names composed again.
fn shown_name(name: &str, hfs: bool) -> String {
    if hfs {
        nfc::compose(name, fstool::fs::hfs_plus::unicode::normalize_name)
    } else {
        name.to_owned()
    }
}

/// The `com.apple.decmpfs` attribute of the file at `path`, if it has one.
fn decmpfs_attr(fs: &mut AnyFs, dev: &mut Device, path: &str) -> Result<Option<Vec<u8>>> {
    match fs {
        AnyFs::HfsPlus(h) => h
            .get_xattr(&mut Capped(dev), path, decmpfs::XATTR)
            .map_err(fs_error),
        AnyFs::Apfs(a) => Ok(a
            .read_xattrs(dev, path)
            .map_err(fs_error)?
            .remove(decmpfs::XATTR)),
        _ => Ok(None),
    }
}

/// Every folder, file, link and special file of the volume, parents before their contents.
fn walk(
    fs: &mut AnyFs,
    dev: &mut Device,
    limits: &Limits,
    cx: &mut dyn Ctx,
) -> Result<(Vec<Entry>, Vec<Item>)> {
    let hfs = matches!(fs, AnyFs::HfsPlus(_));
    let mut entries: Vec<Entry> = Vec::new();
    let mut items = Vec::new();
    // Both filesystems number the root folder 2.
    let mut visited = HashSet::from([2u32]);
    let mut pending = vec![(String::from("/"), String::new(), 0usize)];
    while let Some((dir, rel, depth)) = pending.pop() {
        cx.check()?;
        let children = match fs.list(dev, &dir) {
            Ok(c) => c,
            Err(e) if depth == 0 => return Err(fs_error(e)),
            Err(e) => {
                cx.warn(format!("`{rel}` can't be listed: {}", fs_error(e)));
                continue;
            }
        };
        let mut subdirs = Vec::new();
        for c in children {
            if c.name == "." || c.name == ".." {
                continue;
            }
            let path = if dir == "/" {
                format!("/{}", c.name)
            } else {
                format!("{dir}/{}", c.name)
            };
            let shown = if hfs && depth == 0 && c.name == PRIVATE_DATA {
                PRIVATE_DATA_SHOWN.to_owned()
            } else {
                shown_name(&c.name, hfs)
            };
            let rel_path = if rel.is_empty() {
                shown
            } else {
                format!("{rel}/{shown}")
            };
            limits.check_entries(entries.len() as u64 + 1)?;
            let attrs = match fs.getattr(dev, Path::new(&path)) {
                Ok(a) => Some(a),
                Err(e) => {
                    cx.warn(format!(
                        "`{rel_path}`'s attributes can't be read: {}",
                        fs_error(e)
                    ));
                    None
                }
            };
            let perm = attrs.as_ref().map(|a| u32::from(a.mode & 0o7777));
            let mut size = None;
            let mut method = None;
            let (kind, item, type_bits) = match c.kind {
                FsKind::Dir => {
                    if depth + 1 >= MAX_DEPTH {
                        cx.warn(format!(
                            "`{rel_path}` is more than {MAX_DEPTH} folders deep; what's in it \
                             isn't listed"
                        ));
                    } else if visited.insert(c.inode) {
                        subdirs.push((path, rel_path.clone(), depth + 1));
                    } else {
                        cx.warn(format!(
                            "`{rel_path}` is a folder already listed; what's in it isn't listed \
                             again"
                        ));
                    }
                    (EntryKind::Dir, Item::None, S_IFDIR)
                }
                FsKind::Symlink => match fs.read_symlink(dev, &path) {
                    Ok(target) => {
                        size = Some(target.len() as u64);
                        (EntryKind::Symlink { target }, Item::None, S_IFLNK)
                    }
                    Err(e) => {
                        cx.warn(format!(
                            "`{rel_path}`'s link can't be read: {}",
                            fs_error(e)
                        ));
                        (EntryKind::Other, Item::None, 0)
                    }
                },
                FsKind::Regular => {
                    let mut bytes = attrs.as_ref().map_or(c.size, |a| a.size);
                    let mut compressed = false;
                    // A compressed file's data fork is empty.
                    if bytes == 0
                        && let Some(x) = decmpfs_attr(fs, dev, &path)?
                    {
                        compressed = true;
                        match decmpfs::Header::parse(&x) {
                            Ok(h) => {
                                bytes = h.size;
                                method = h.method();
                            }
                            Err(e) => cx.warn(format!("`{rel_path}`: {e}")),
                        }
                    }
                    size = Some(bytes);
                    let item = Item::File {
                        path,
                        size: bytes,
                        compressed,
                    };
                    (EntryKind::File, item, S_IFREG)
                }
                _ => (EntryKind::Other, Item::None, 0),
            };
            let mut e = Entry::new(entries.len(), rel_path, kind);
            e.size = size;
            e.method = method;
            e.modified = attrs
                .as_ref()
                .map(|a| a.mtime)
                .filter(|&t| t > 0)
                .and_then(|t| from_unix(i64::from(t), 0));
            e.unix_mode = perm.map(|p| type_bits | p);
            entries.push(e);
            items.push(item);
        }
        pending.extend(subdirs.into_iter().rev());
    }
    Ok((entries, items))
}

/// The name of 7-Zip's for a partition named `name`, the `i`th of `count`: the index, padded
/// to the width of the largest, then what's in the name's parentheses before the colon, with
/// the filesystem types shortened (`disk image (Apple_HFS : 4)` → `4.hfs`).
fn partition_name(i: usize, count: usize, name: &str) -> String {
    const SHORT: [(&str, &str); 7] = [
        ("Apple_HFS", "hfs"),
        ("Apple_HFSX", "hfsx"),
        ("Apple_UFS", "ufs"),
        ("Apple_APFS", "apfs"),
        ("Apple_ISO", "iso"),
        ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "efi_sys"),
        ("Apple_Free", "free"),
    ];
    let mut digits = 1;
    let mut n = 10;
    while n < count {
        digits += 1;
        n *= 10;
    }
    let index = format!("{i:0digits$}");
    let inner = name
        .find('(')
        .and_then(|open| {
            let rest = &name[open + 1..];
            rest.find(')').map(|close| &rest[..close])
        })
        .map(|s| s.split(':').next().unwrap_or(s).trim())
        .unwrap_or_default();
    if inner.is_empty() {
        if name.is_empty() {
            index
        } else {
            format!("{index} - {name}")
        }
    } else {
        let short = SHORT
            .iter()
            .find(|(full, _)| *full == inner)
            .map_or(inner, |(_, s)| s);
        format!("{index}.{short}")
    }
}

/// The image's partitions as entries.
fn partition_entries(image: &udif::Image, limits: &Limits) -> Result<(Vec<Entry>, Vec<Item>)> {
    let count = image.partitions.len();
    limits.check_entries(count as u64)?;
    let mut entries = Vec::with_capacity(count);
    let mut items = Vec::with_capacity(count);
    for (i, p) in image.partitions.iter().enumerate() {
        let mut e = Entry::new(i, partition_name(i, count, &p.name), EntryKind::File);
        e.size = Some(p.bytes());
        e.crc32 = p.crc;
        entries.push(e);
        items.push(Item::Partition(i));
    }
    Ok((entries, items))
}

/// An HFS+ file's resource fork, for a compressed file whose data is in it. `None` on APFS.
fn resource_fork<'a>(
    fs: &AnyFs,
    forks: &mut Option<HfsForks>,
    dev: &'a mut Device,
    path: &str,
) -> Result<Option<Box<dyn decmpfs::Fork + 'a>>> {
    let AnyFs::HfsPlus(h) = fs else {
        return Ok(None);
    };
    if forks.is_none() {
        *forks = Some(HfsForks::open(dev)?);
    }
    let Some(forks) = forks.as_ref() else {
        return Ok(None);
    };
    // A hard link's information is its data's, so this is the file that has the fork.
    let cnid = h.entry_info(path).map_err(fs_error)?.cnid;
    let reader = forks.resource_fork(dev, cnid)?;
    Ok(Some(Box::new(HfsFork { dev, reader })))
}

/// The data of the entry `item` describes.
fn open_data<'a>(
    volume: &'a mut Volume,
    dev: &'a mut Device,
    image: &udif::Image,
    item: &Item,
) -> Result<Box<dyn Read + 'a>> {
    match item {
        Item::None => Ok(Box::new(io::empty())),
        Item::Partition(i) => {
            let p = image
                .partitions
                .get(*i)
                .ok_or_else(|| bad("no such partition"))?;
            dev.0.set_window(p.first_sector * udif::SECTOR, p.bytes())?;
            Ok(Box::new(Exact {
                inner: dev,
                left: p.bytes(),
                path: p.name.clone(),
            }))
        }
        Item::File {
            path,
            size,
            compressed,
        } => {
            let Volume::Fs { fs, forks } = volume else {
                return Err(bad("a file without a volume"));
            };
            let data: Box<dyn Read + 'a> = if *compressed {
                let x = decmpfs_attr(fs, dev, path)?
                    .ok_or_else(|| bad(format!("`{path}` has lost its decmpfs attribute")))?;
                let fork = if decmpfs::Header::parse(&x)?.in_fork() {
                    resource_fork(fs, forks, dev, path)?
                } else {
                    None
                };
                decmpfs::open(&x, fork, path)?
            } else {
                fs.open_body_reader(dev, path).map_err(fs_error)?
            };
            Ok(Box::new(Exact {
                inner: data,
                left: *size,
                path: path.trim_start_matches('/').to_owned(),
            }))
        }
    }
}

impl ArchiveReader for DmgReader {
    fn format(&self) -> FormatId {
        FormatId::Dmg
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Dmg,
            codecs: self.source.codecs.clone(),
            methods: self.image.methods(),
            comment: None,
            encryption: Encryption::None,
            solid: false,
            sfx: false,
            volumes: 1,
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        self.source.counter.set(0);
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
        meter.entries_total = Some(self.entries.len() as u64);
        let mut done = 0u64;
        for (entry, item) in self.entries.iter().zip(&self.items) {
            if !sel.matches(entry) {
                continue;
            }
            cx.check()?;
            meter.entries_done = done;
            meter.current = Some(entry.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            let data = open_data(&mut self.volume, &mut self.dev, &self.image, item)?;
            let mut data = self.source.guard(data);
            sink.entry(entry, &mut data, &mut mcx)?;
            done += 1;
        }
        meter.entries_done = done;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let item = self
            .items
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        self.source.counter.set(0);
        let data = open_data(&mut self.volume, &mut self.dev, &self.image, item)?;
        Ok(Box::new(self.source.guard(data)))
    }
}

/// The temporary HFS+ image as fstool's block device.
struct FileDevice {
    file: File,
    size: u64,
}

impl Read for FileDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for FileDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for FileDevice {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

impl BlockDevice for FileDevice {
    fn block_size(&self) -> u32 {
        udif::SECTOR as u32
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}

/// A path as the writer keeps it: `/`-separated, without leading or trailing slashes.
fn clean(path: &str) -> String {
    super::normalize(path)
}

/// `a`, `a/b` for `a/b/c`.
fn parents(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

/// A time as fstool takes it: Unix seconds HFS+ can hold.
fn hfs_time(t: SystemTime) -> u32 {
    to_unix(t).clamp(1, HFS_LAST) as u32
}

/// The HFS+ volume being filled.
struct Building {
    tmp: Partial,
    dev: FileDevice,
    hfs: HfsPlus,
    /// Folders made so far.
    dirs: HashSet<String>,
    /// The volume's date: for folders made for a path's parents and entries without a time.
    date: u32,
}

impl Building {
    fn new(dir: &Path, name: &str, size: u64, opts: &FormatOpts, date: u32) -> Result<Self> {
        let tmp = Partial::create(dir, &format!(".{name}.hfs"))?;
        tmp.file()
            .set_len(size)
            .map_err(|e| Error::io(format!("writing {}", tmp.path().display()), &e))?;
        let mut dev = FileDevice {
            file: tmp.try_clone()?,
            size,
        };
        let hfs = HfsPlus::format(&mut dev, opts).map_err(|e| write_fs_error(e, "the volume"))?;
        Ok(Self {
            tmp,
            dev,
            hfs,
            dirs: HashSet::new(),
            date,
        })
    }

    /// Makes the folders `path` is in, as far as they aren't yet.
    fn parents(&mut self, path: &str) -> Result<()> {
        for p in parents(path) {
            if self.dirs.contains(p) {
                continue;
            }
            self.hfs
                .create_dir(&mut self.dev, &format!("/{p}"), 0o755, UID, GID, self.date)
                .map_err(|e| write_fs_error(e, p))?;
            self.dirs.insert(p.to_owned());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn file(
        &mut self,
        path: &str,
        size: u64,
        data: &mut dyn Read,
        mode: u16,
        mtime: u32,
        dir: &Path,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut spool = None;
        let mut first = [0u8; 1];
        let len = if size == 0 {
            // A size of 0 may be one nobody knew (a bare stream's): see whether there's data.
            if read_some(data, &mut first)? == 0 {
                0
            } else {
                let mut tmp = Partial::create(dir, ".beezip-dmg-spool")?;
                tmp.file_mut()
                    .write_all(&first)
                    .map_err(|e| write_error(&e))?;
                let n = copy(data, tmp.file_mut(), cx)? + 1;
                tmp.file_mut()
                    .seek(SeekFrom::Start(0))
                    .map_err(|e| read_error(&e))?;
                spool = Some(tmp);
                n
            }
        } else {
            size
        };
        let bs = u64::from(self.hfs.block_size());
        let free = self.hfs.free_bytes();
        if len.div_ceil(bs) * bs > free {
            return Err(Error::unsupported(format!(
                "dmg: `{path}` ({len} bytes) doesn't fit in the image's volume, which was sized \
                 from the sizes known before writing ({free} bytes are free)"
            )));
        }
        {
            let src: &mut dyn Read = match spool.as_mut() {
                Some(t) => t.file_mut(),
                None => &mut *data,
            };
            let mut src = Checked::new(src, cx);
            self.hfs
                .create_file(
                    &mut self.dev,
                    &format!("/{path}"),
                    &mut src,
                    len,
                    mode,
                    UID,
                    GID,
                    mtime,
                )
                .map_err(|e| write_fs_error(e, path))?;
        }
        if spool.is_none() && read_some(data, &mut first)? > 0 {
            return Err(Error::new(
                ErrorKind::Io,
                format!("dmg: `{path}` has more data than its size, {len} bytes"),
            ));
        }
        Ok(())
    }
}

/// One read, retried when interrupted.
fn read_some(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    loop {
        match r.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(read_error(&e)),
        }
    }
}

pub struct DmgWriter {
    out: Box<dyn WriteSeek>,
    /// Where the temporary files go: the output's folder.
    dir: PathBuf,
    /// The output's file name, for the temporary files'.
    name: String,
    volume_name: String,
    building: Option<Building>,
    /// Paths given more than once, and how many more times each will come: only the last is
    /// written.
    repeats: HashMap<String, usize>,
}

impl DmgWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: DmgWriteOptions, output: &Path) -> Result<Self> {
        let _ = opts;
        let dir = match output.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let name = output
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem = output
            .file_stem()
            .map(|n| n.to_string_lossy().trim().to_owned())
            .unwrap_or_default();
        let volume_name: String = if stem.is_empty() {
            "Untitled".to_owned()
        } else {
            stem.chars().take(255).collect()
        };
        Ok(Self {
            out,
            dir,
            name,
            volume_name,
            building: None,
            repeats: HashMap::new(),
        })
    }

    /// Formats the volume for `entries` (the last of each path).
    fn start(&mut self, entries: &[&NewEntry]) -> Result<()> {
        let mut opts = FormatOpts::default();
        opts.volume_name = self.volume_name.clone();
        let mut dirs: HashSet<String> = entries
            .iter()
            .filter(|e| e.kind == NewKind::Dir)
            .map(|e| clean(&e.path))
            .collect();
        let mut implicit = Vec::new();
        for e in entries {
            let path = clean(&e.path);
            for p in parents(&path) {
                if dirs.insert(p.to_owned()) {
                    implicit.push(p.to_owned());
                }
            }
        }
        // HFS+ compares names ignoring case: two that differ only in case need HFSX.
        let mut folded = HashSet::new();
        opts.case_sensitive = entries
            .iter()
            .map(|e| clean(&e.path))
            .chain(implicit.iter().cloned())
            .any(|p| !folded.insert(p.to_lowercase()));
        let date = entries
            .iter()
            .filter_map(|e| e.modified)
            .max()
            .map_or_else(|| hfs_time(SystemTime::now()), hfs_time);
        opts.create_date = hfs_date_from_unix(i64::from(date));
        let mut plan = HfsPlusSizePlan::new(&opts);
        for p in &implicit {
            plan.add_dir(&format!("/{p}"));
        }
        for e in entries {
            let path = format!("/{}", clean(&e.path));
            match &e.kind {
                NewKind::Dir => plan.add_dir(&path),
                NewKind::File => plan.add_file(&path, e.size),
                NewKind::Symlink { target } => plan.add_symlink(&path, target),
            }
        }
        plan.apply_to(&mut opts);
        let bs = u64::from(opts.block_size);
        let need = plan.total_size();
        let size = need
            .saturating_add(need / 64)
            .saturating_add(1 << 20)
            .div_ceil(bs)
            .saturating_mul(bs);
        self.building = Some(Building::new(&self.dir, &self.name, size, &opts, date)?);
        Ok(())
    }
}

impl ArchiveWriter for DmgWriter {
    fn expect(&mut self, entries: &[NewEntry]) -> Result<()> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for e in entries {
            *counts.entry(clean(&e.path)).or_default() += 1;
        }
        let mut seen = HashSet::new();
        let mut last: Vec<&NewEntry> = entries
            .iter()
            .rev()
            .filter(|e| {
                let p = clean(&e.path);
                !p.is_empty() && seen.insert(p)
            })
            .collect();
        last.reverse();
        self.repeats = counts.into_iter().filter(|(_, n)| *n > 1).collect();
        self.start(&last)
    }

    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let path = clean(&entry.path);
        if path.is_empty() {
            return Ok(());
        }
        if let Some(n) = self.repeats.get_mut(&path)
            && *n > 1
        {
            *n -= 1;
            cx.warn(format!(
                "`{path}` is given more than once; the last one is written"
            ));
            return Ok(());
        }
        if self.building.is_none() {
            self.start(&[])?;
        }
        let Some(b) = self.building.as_mut() else {
            return Err(bad("the volume wasn't made"));
        };
        b.parents(&path)?;
        let mtime = entry.modified.map_or(b.date, hfs_time);
        let mode = |default: u16| entry.unix_mode.map_or(default, |m| (m & 0o7777) as u16);
        let fs_path = format!("/{path}");
        match &entry.kind {
            NewKind::Dir => {
                let made = if b.dirs.contains(&path) {
                    let attrs = SetAttrs {
                        mode: Some(mode(0o755)),
                        mtime: Some(mtime),
                        ..SetAttrs::default()
                    };
                    b.hfs.set_attrs(&mut b.dev, &fs_path, attrs)
                } else {
                    b.hfs
                        .create_dir(&mut b.dev, &fs_path, mode(0o755), UID, GID, mtime)
                        .map(drop)
                };
                made.map_err(|e| write_fs_error(e, &path))?;
                b.dirs.insert(path);
            }
            NewKind::Symlink { target } => {
                b.hfs
                    .create_symlink(&mut b.dev, &fs_path, target, mode(0o755), UID, GID, mtime)
                    .map_err(|e| write_fs_error(e, &path))?;
            }
            NewKind::File => {
                b.file(&path, entry.size, data, mode(0o644), mtime, &self.dir, cx)?;
            }
        }
        Ok(())
    }

    fn finish(self: Box<Self>, cx: &mut dyn Ctx) -> Result<()> {
        let mut this = *self;
        if this.building.is_none() {
            this.start(&[])?;
        }
        let Some(mut b) = this.building.take() else {
            return Err(bad("the volume wasn't made"));
        };
        b.hfs
            .flush(&mut b.dev)
            .map_err(|e| write_fs_error(e, "the volume"))?;
        let size = b.dev.size;
        drop(b.dev);
        let mut volume = BufReader::with_capacity(BUF_SIZE, b.tmp.reopen()?);
        let mut out = BufWriter::with_capacity(BUF_SIZE, this.out);
        udif::write_udzo(
            &mut volume,
            size,
            &udif::whole_disk_name("Apple_HFS"),
            &mut out,
            cx,
        )?;
        out.flush().map_err(|e| write_error(&e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_are_named_as_7zip_names_them() {
        let names = [
            "Protective Master Boot Record (MBR : 0)",
            "GPT Header (Primary GPT Header : 1)",
            "GPT Partition Data (Primary GPT Table : 2)",
            " (Apple_Free : 3)",
            "disk image (Apple_HFS : 4)",
            "EFI System Partition (C12A7328-F81F-11D2-BA4B-00A0C93EC93B : 5)",
            "something else",
            "",
        ];
        let got: Vec<String> = names
            .iter()
            .enumerate()
            .map(|(i, n)| partition_name(i, names.len(), n))
            .collect();
        assert_eq!(
            got,
            [
                "0.MBR",
                "1.Primary GPT Header",
                "2.Primary GPT Table",
                "3.free",
                "4.hfs",
                "5.efi_sys",
                "6 - something else",
                "7",
            ]
        );
        assert_eq!(partition_name(3, 12, "x (Apple_APFS : 3)"), "03.apfs");
        assert_eq!(partition_name(0, 1, "whole disk (Apple_HFS : 0)"), "0.hfs");
    }

    fn hfs(name: &str) -> String {
        fstool::fs::hfs_plus::unicode::normalize_name(name)
    }

    #[test]
    fn hfs_names_compose_back() {
        for (name, want) in [
            ("café.txt", "café.txt"),
            ("Ünïcödé — 日本語 ñ", "Ünïcödé — 日本語 ñ"),
            ("ǘ ǜ ḉ Ḝ", "ǘ ǜ ḉ Ḝ"),
            ("ά έ ή ί ό ύ ώ ΐ", "ά έ ή ί ό ύ ώ ΐ"),
            ("한국어 파일", "한국어 파일"),
            ("がぎぐ パピプ", "がぎぐ パピプ"),
            ("Ångström", "Ångström"),
            ("plain ascii", "plain ascii"),
            ("e\u{301}", "é"),
        ] {
            let stored = hfs(name);
            assert_eq!(
                shown_name(&stored, true),
                want,
                "{name:?} stored as {stored:?}"
            );
            assert_eq!(shown_name(&stored, false), stored);
        }
    }

    #[test]
    fn composition_exclusions_stay_decomposed() {
        // क़ (U+0958) is excluded from composition: NFC keeps क and the nukta.
        let name = "\u{915}\u{93C}";
        assert_eq!(shown_name(&hfs(name), true), name);
        // A diaeresis and an acute after a letter with no composite stay as they are.
        let name = "q\u{308}\u{301}";
        assert_eq!(shown_name(&hfs(name), true), name);
    }

    #[test]
    fn parents_of_a_path() {
        assert_eq!(parents("a/b/c").collect::<Vec<_>>(), ["a", "a/b"]);
        assert_eq!(parents("a").count(), 0);
    }
}
