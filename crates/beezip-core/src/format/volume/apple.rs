//! HFS+, HFSX and APFS volumes (docs/M5.md §5.11, docs/M7.md §7): the volume inside a DMG, and
//! a bare one (`H+`/`HX` at 1024, `NXSB` at 32), on a disk or alone.
//!
//! - **The volume** is read through fstool 0.5.2's `AnyFs` (an APFS container's first volume).
//!   The walk lists folders, files and symlinks, with their sizes, times and modes; it goes at
//!   most [`MAX_DEPTH`] folders deep and never into a folder twice. HFS+ hard links are files
//!   with their data (fstool follows them), and HFS+'s private-data folder, where that data
//!   lives, is listed as `[HFS+ Private Data]` as 7-Zip shows it. HFS+ stores names decomposed;
//!   they're listed composed again (`dmg/nfc.rs`).
//! - **Apple-compressed files** (decmpfs) are BeeZip's to decode (`dmg/decmpfs.rs`): fstool
//!   reads their header in the wrong byte order and fails them. Their attribute comes from
//!   fstool, and an HFS+ file's resource fork from fstool's catalog and fork readers. fstool
//!   doesn't reach APFS resource forks, so an APFS file compressed into one is
//!   `UnsupportedOperation`. They're listed at their size uncompressed.

use std::{
    collections::HashSet,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use fstool::{
    block::BlockDevice,
    fs::{
        EntryKind as FsKind,
        hfs_plus::{
            btree::ForkReader,
            catalog::{Catalog, CatalogKey, CatalogRecord, UniStr},
            extents::ExtentsOverflow,
            volume_header::read_volume_header,
        },
    },
    inspect::AnyFs,
};

use super::{Device, FileSystem, VolumeOptions};
use crate::{
    Ctx, Error, Result,
    backend::External,
    format::{
        Entry, EntryKind,
        dmg::{MAX_DEPTH, decmpfs, nfc},
    },
    io::read_error,
    limits::Limits,
    time::from_unix,
};

/// HFS+'s folder for the data of hard links, and how 7-Zip shows it.
const PRIVATE_DATA: &str = "\0\0\0\0HFS+ Private Data";
const PRIVATE_DATA_SHOWN: &str = "[HFS+ Private Data]";

const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("hfs: {message}"))
}

/// An fstool error met while reading. Errors of the disk come back as they were.
pub fn fs_error(e: fstool::Error) -> Error {
    match e {
        fstool::Error::Io(e) => read_error(&e),
        fstool::Error::Unsupported(m) => Error::unsupported(m),
        e => Error::corrupt(e.to_string()),
    }
}

/// The volume on `dev`: HFS+, HFSX or APFS. Another file system fstool knows is
/// `UnsupportedOperation` here.
pub fn open(dev: Device, opts: &VolumeOptions, cx: &mut dyn Ctx) -> Result<Box<dyn FileSystem>> {
    let _ = cx;
    Ok(Box::new(Apple::open(dev, &opts.limits)?))
}

/// An HFS+ or APFS volume.
pub struct Apple {
    fs: Box<AnyFs>,
    dev: Device,
    /// The HFS+ catalog, opened the first time a resource fork is needed.
    forks: Option<HfsForks>,
    limits: Limits,
    items: Vec<Item>,
}

impl Apple {
    pub fn open(mut dev: Device, limits: &Limits) -> Result<Self> {
        let fs = AnyFs::open(&mut dev).map_err(fs_error)?;
        if !matches!(fs, AnyFs::HfsPlus(_) | AnyFs::Apfs(_)) {
            return Err(Error::unsupported(
                "the volume isn't HFS+ or APFS".to_owned(),
            ));
        }
        Ok(Self {
            fs: Box::new(fs),
            dev,
            forks: None,
            limits: limits.clone(),
            items: Vec::new(),
        })
    }
}

impl FileSystem for Apple {
    fn kind(&self) -> External {
        if matches!(*self.fs, AnyFs::Apfs(_)) {
            External::Apfs
        } else {
            External::Hfs
        }
    }

    fn entries(&mut self, cx: &mut dyn Ctx) -> Result<Vec<Entry>> {
        let (entries, items) = walk(&mut self.fs, &mut self.dev, &self.limits, cx)?;
        self.items = items;
        Ok(entries)
    }

    fn open(&mut self, id: usize) -> Result<Box<dyn Read + '_>> {
        let item = self
            .items
            .get(id)
            .ok_or_else(|| bad(format!("no entry {id}")))?;
        let Item::File { path, compressed } = item else {
            return Ok(Box::new(io::empty()));
        };
        open_data(
            &mut self.fs,
            &mut self.forks,
            &mut self.dev,
            path,
            *compressed,
        )
    }
}

/// What an entry's data is.
enum Item {
    /// A folder, a link or a special file: none.
    None,
    /// A file of the volume, at `path` in fstool's terms.
    File { path: String, compressed: bool },
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

/// An HFS+ resource fork for decmpfs.
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

/// A name as stored: HFS+'s decomposed names composed again.
pub fn shown_name(name: &str, hfs: bool) -> String {
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
                    (EntryKind::File, Item::File { path, compressed }, S_IFREG)
                }
                _ => (EntryKind::Other, Item::None, 0),
            };
            let mut e = Entry::new(entries.len(), rel_path, kind);
            e.size = size;
            e.method = method.map(Into::into);
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

/// The data of the file at `path`.
fn open_data<'a>(
    fs: &'a mut AnyFs,
    forks: &mut Option<HfsForks>,
    dev: &'a mut Device,
    path: &str,
    compressed: bool,
) -> Result<Box<dyn Read + 'a>> {
    if compressed {
        let x = decmpfs_attr(fs, dev, path)?
            .ok_or_else(|| bad(format!("`{path}` has lost its decmpfs attribute")))?;
        let fork = if decmpfs::Header::parse(&x)?.in_fork() {
            resource_fork(fs, forks, dev, path)?
        } else {
            None
        };
        decmpfs::open(&x, fork, path)
    } else {
        fs.open_body_reader(dev, path).map_err(fs_error)
    }
}
