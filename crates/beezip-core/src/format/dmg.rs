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

pub(crate) mod decmpfs;
mod lzvn;
pub(crate) mod nfc;

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
        FsSizePlan, SetAttrs,
        hfs_plus::{FormatOpts, HfsPlus, hfs_date_from_unix, size_plan::HfsPlusSizePlan},
    },
    inspect::detect_partition_table,
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, NewEntry, NewKind, Selection, udif,
    volume::{Device, Exact, FileSystem, Input, apple::Apple, open_input, unreadable},
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, Checked, WriteSeek, copy, read_error, write_error},
    limits::Limits,
    safefs::Partial,
    source::Source,
    time::to_unix,
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

/// What an entry's data is.
enum Item {
    /// A folder, a link or a special file: none.
    None,
    /// Entry `id` of the volume, a file.
    Fs(usize),
    /// One of the image's partitions, by index.
    Partition(usize),
}

pub struct DmgReader {
    source: Source,
    image: udif::Image,
    /// The image's whole disk.
    disk: Device,
    /// The HFS+ or APFS volume, when there's one; otherwise the entries are the partitions.
    volume: Option<Box<dyn FileSystem>>,
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
        let size = disk.disk_size();
        let disk = Device::new(Box::new(disk), size);
        let (volume, entries, items) = match find_volume(&disk, &image, &source.limits, cx) {
            Some(mut fs) => {
                let entries = fs.entries(cx)?;
                let items = entries
                    .iter()
                    .map(|e| {
                        if e.kind == EntryKind::File {
                            Item::Fs(e.id)
                        } else {
                            Item::None
                        }
                    })
                    .collect();
                (Some(fs), entries, items)
            }
            None => {
                let (entries, items) = partition_entries(&image, &source.limits)?;
                (None, entries, items)
            }
        };
        Ok(Self {
            source,
            image,
            disk,
            volume,
            entries,
            items,
            _spool: spool,
        })
    }
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
fn signature(disk: &Device, base: u64, len: u64) -> Option<&'static str> {
    if len < 1026 {
        return None;
    }
    let mut win = disk.window(base, len).ok()?;
    let mut head = [0u8; 1026];
    win.read_exact_at(0, &mut head).ok()?;
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
/// that opens. Volumes that don't open are warned about.
fn find_volume(
    disk: &Device,
    image: &udif::Image,
    limits: &Limits,
    cx: &mut dyn Ctx,
) -> Option<Box<dyn FileSystem>> {
    let size = disk.len();
    let mut spans: Vec<(u64, u64)> = Vec::new();
    match detect_partition_table(&mut disk.clone()) {
        Ok(Some(table)) => spans.extend(table.partitions().iter().filter_map(|p| {
            let base = p.start_lba.checked_mul(udif::SECTOR)?;
            let len = p.size_lba.checked_mul(udif::SECTOR)?;
            (base.checked_add(len)? <= size).then_some((base, len))
        })),
        Ok(None) => spans.push((0, size)),
        Err(_) => {}
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
        .filter_map(|(base, len)| signature(disk, base, len).map(|kind| (base, len, kind)))
        .collect();
    found.sort_by_key(|&(_, len, _)| Reverse(len));
    for (base, len, kind) in found {
        let Ok(win) = disk.window(base, len) else {
            continue;
        };
        match Apple::open(win, limits) {
            Ok(fs) => return Some(Box::new(fs)),
            Err(e) => cx.warn(format!(
                "the {kind} volume at byte {base} can't be read ({}); the image's partitions are \
                 listed instead",
                e.message
            )),
        }
    }
    None
}

/// A resource fork held in memory.
struct MemFork<'a>(&'a [u8]);

impl decmpfs::Fork for MemFork<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let src = usize::try_from(offset)
            .ok()
            .and_then(|at| self.0.get(at..at.checked_add(buf.len())?))
            .ok_or_else(|| bad("a read past the end of a resource fork"))?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

/// Decodes up to `max` bytes of the Apple-compressed file whose `com.apple.decmpfs` attribute
/// is `attr` and whose resource fork is `fork`, as a volume's files are decoded. For the fuzz
/// target.
#[doc(hidden)]
pub fn decode_decmpfs(attr: &[u8], fork: Option<&[u8]>, max: u64) -> Result<Vec<u8>> {
    let fork = fork.map(|f| Box::new(MemFork(f)) as Box<dyn decmpfs::Fork + '_>);
    let mut out = Vec::new();
    decmpfs::open(attr, fork, "input")?
        .take(max)
        .read_to_end(&mut out)
        .map_err(|e| read_error(&e))?;
    Ok(out)
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
        e.packed_size = Some(p.runs.iter().map(|r| r.len).sum());
        e.crc32 = p.data_crc();
        entries.push(e);
        items.push(Item::Partition(i));
    }
    Ok((entries, items))
}

/// The data of the entry `item` describes.
fn open_data<'a>(
    volume: &'a mut Option<Box<dyn FileSystem>>,
    disk: &Device,
    image: &udif::Image,
    entries: &[Entry],
    item: &Item,
) -> Result<Box<dyn Read + 'a>> {
    match item {
        Item::None => Ok(Box::new(io::empty())),
        Item::Partition(i) => {
            let p = image
                .partitions
                .get(*i)
                .ok_or_else(|| bad("no such partition"))?;
            let win = disk.window(p.first_sector * udif::SECTOR, p.bytes())?;
            Ok(Box::new(Exact::new(win, p.bytes(), &p.name)))
        }
        Item::Fs(id) => {
            let e = entries.get(*id).ok_or_else(|| bad("no such entry"))?;
            let fs = volume
                .as_mut()
                .ok_or_else(|| bad("a file without a volume"))?;
            Ok(Box::new(Exact::new(
                fs.open(*id)?,
                e.size.unwrap_or(0),
                &e.path,
            )))
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
            methods: self.image.methods().into_iter().map(Into::into).collect(),
            comment: None,
            encryption: Encryption::None,
            solid: false,
            sfx: false,
            volumes: 1,
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: None,
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
            let data = match open_data(
                &mut self.volume,
                &self.disk,
                &self.image,
                &self.entries,
                item,
            ) {
                Ok(d) => d,
                // As on a bare volume: skipped when written to disk, recorded by a test.
                Err(e) => match unreadable(e, entry, sink, &mut mcx)? {
                    Some(d) => d,
                    None => {
                        done += 1;
                        continue;
                    }
                },
            };
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
        let data = open_data(
            &mut self.volume,
            &self.disk,
            &self.image,
            &self.entries,
            item,
        )?;
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
    use crate::{format::volume::apple::shown_name, time::from_unix};

    /// HFS+'s private-data folder as 7-Zip shows it.
    const PRIVATE_DATA_SHOWN: &str = "[HFS+ Private Data]";

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

    use fstool::{block::MemoryBackend, fs::Filesystem as _};

    use crate::{OpenOptions, SimpleCtx};

    /// `volume` as the one partition of a UDZO image, opened.
    fn open_image(volume: &[u8], name: &str) -> (tempfile::TempDir, DmgReader) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.dmg");
        let mut out = Vec::new();
        udif::write_udzo(
            &mut &volume[..],
            volume.len() as u64,
            name,
            &mut out,
            &mut SimpleCtx::new(),
        )
        .unwrap();
        std::fs::write(&path, out).unwrap();
        let source = Source::new(&path, Vec::new(), &OpenOptions::default()).unwrap();
        let reader = DmgReader::open(source, &mut SimpleCtx::new()).unwrap();
        (dir, reader)
    }

    fn read(r: &mut DmgReader, path: &str) -> Result<Vec<u8>> {
        let id = r
            .entries
            .iter()
            .find(|e| e.path == path)
            .unwrap_or_else(|| panic!("{path}: {:#?}", r.entries))
            .id;
        let mut data = Vec::new();
        r.open_entry(id, &mut SimpleCtx::new())?
            .read_to_end(&mut data)
            .map_err(Error::from)?;
        Ok(data)
    }

    fn decmpfs_header(kind: u32, size: u64) -> Vec<u8> {
        let mut x = b"fpmc".to_vec();
        x.extend_from_slice(&kind.to_le_bytes());
        x.extend_from_slice(&size.to_le_bytes());
        x
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    /// A type-4 resource fork: the resource header, the resource's length, then the count, the
    /// `(offset, length)` pairs and the blocks.
    fn fork4(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut f = vec![0u8; 256];
        f[..4].copy_from_slice(&256u32.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        let mut off = 4 + blocks.len() * 8;
        for b in blocks {
            f.extend_from_slice(&(off as u32).to_le_bytes());
            f.extend_from_slice(&(b.len() as u32).to_le_bytes());
            off += b.len();
        }
        for b in blocks {
            f.extend_from_slice(b);
        }
        f
    }

    #[test]
    fn hfs_hard_links_and_compressed_files() {
        let mut dev = MemoryBackend::new(8 << 20);
        let mut opts = FormatOpts::default();
        opts.volume_name = "Links".into();
        let mut vol = HfsPlus::format(&mut dev, &opts).unwrap();
        let t = 1_750_000_000;
        vol.create_dir(&mut dev, "/d", 0o755, UID, GID, t).unwrap();
        let body = b"shared by two names".to_vec();
        vol.create_file(
            &mut dev,
            "/d/a.txt",
            &mut &body[..],
            body.len() as u64,
            0o644,
            UID,
            GID,
            t,
        )
        .unwrap();
        vol.create_hardlink(&mut dev, "/d/a.txt", "/b.txt").unwrap();
        // Inline zlib.
        let small = b"inline and compressed ".repeat(50);
        vol.create_file(&mut dev, "/inline", &mut &[][..], 0, 0o644, UID, GID, t)
            .unwrap();
        let mut x = decmpfs_header(3, small.len() as u64);
        x.extend_from_slice(&zlib(&small));
        vol.set_xattr(&mut dev, "/inline", decmpfs::XATTR, &x)
            .unwrap();
        // zlib in the resource fork, two blocks.
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let fork = fork4(&big.chunks(64 * 1024).map(zlib).collect::<Vec<_>>());
        vol.create_file(&mut dev, "/forked", &mut &[][..], 0, 0o644, UID, GID, t)
            .unwrap();
        vol.write_resource_fork(&mut dev, "/forked", &mut &fork[..], fork.len() as u64)
            .unwrap();
        vol.set_xattr(
            &mut dev,
            "/forked",
            decmpfs::XATTR,
            &decmpfs_header(4, big.len() as u64),
        )
        .unwrap();
        // A type BeeZip doesn't read.
        vol.create_file(&mut dev, "/odd", &mut &[][..], 0, 0o644, UID, GID, t)
            .unwrap();
        vol.set_xattr(&mut dev, "/odd", decmpfs::XATTR, &decmpfs_header(5, 10))
            .unwrap();
        vol.flush(&mut dev).unwrap();

        let (_dir, mut r) = open_image(dev.as_slice(), "whole disk (Apple_HFS : 0)");
        let paths: Vec<&str> = r.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&PRIVATE_DATA_SHOWN), "{paths:?}");
        assert_eq!(read(&mut r, "d/a.txt").unwrap(), body);
        assert_eq!(read(&mut r, "b.txt").unwrap(), body);
        let size = |r: &DmgReader, p: &str| r.entries.iter().find(|e| e.path == p).unwrap().size;
        assert_eq!(size(&r, "b.txt"), Some(body.len() as u64));
        assert_eq!(size(&r, "inline"), Some(small.len() as u64));
        assert_eq!(size(&r, "forked"), Some(big.len() as u64));
        assert_eq!(read(&mut r, "inline").unwrap(), small);
        assert_eq!(read(&mut r, "forked").unwrap(), big);
        let method = r
            .entries
            .iter()
            .find(|e| e.path == "forked")
            .unwrap()
            .method
            .clone();
        assert_eq!(method.as_deref(), Some("decmpfs zlib"));
        assert_eq!(
            read(&mut r, "odd").unwrap_err().kind,
            ErrorKind::UnsupportedOperation
        );
    }

    #[test]
    fn apfs_volumes() {
        let mut dev = MemoryBackend::new(16 << 20);
        let mut fs = fstool::fs::apfs::Apfs::format(&mut dev, 4096, 4096, "APFS Test").unwrap();
        fs.flush(&mut dev).unwrap();
        let mut fs = fstool::fs::apfs::Apfs::open_writable(&mut dev).unwrap();
        let ns = 1_750_000_000u64 * 1_000_000_000;
        fs.create_dir_at(&mut dev, "/dir", 0o755, ns).unwrap();
        fs.create_file_at(&mut dev, "/dir/a.txt", b"apfs data", 0o640, ns)
            .unwrap();
        fs.create_symlink_at(&mut dev, "/link", "dir/a.txt", 0o755, ns)
            .unwrap();
        let small = b"compressed on apfs ".repeat(40);
        fs.create_file_at(&mut dev, "/inline", b"", 0o644, ns)
            .unwrap();
        let mut x = decmpfs_header(3, small.len() as u64);
        x.extend_from_slice(&zlib(&small));
        fs.set_xattr(&mut dev, "/inline", decmpfs::XATTR, &x)
            .unwrap();
        fs.create_file_at(&mut dev, "/forked", b"", 0o644, ns)
            .unwrap();
        fs.set_xattr(
            &mut dev,
            "/forked",
            decmpfs::XATTR,
            &decmpfs_header(4, 70_000),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        let (_dir, mut r) = open_image(dev.as_slice(), "disk image (Apple_APFS : 0)");
        let e = |r: &DmgReader, p: &str| r.entries.iter().find(|e| e.path == p).cloned().unwrap();
        assert_eq!(e(&r, "dir").kind, EntryKind::Dir);
        assert_eq!(e(&r, "dir/a.txt").unix_mode, Some(0o100_640));
        assert_eq!(e(&r, "dir/a.txt").modified, from_unix(1_750_000_000, 0));
        assert_eq!(
            e(&r, "link").kind,
            EntryKind::Symlink {
                target: "dir/a.txt".into()
            }
        );
        assert_eq!(read(&mut r, "dir/a.txt").unwrap(), b"apfs data");
        assert_eq!(e(&r, "inline").size, Some(small.len() as u64));
        assert_eq!(read(&mut r, "inline").unwrap(), small);
        // fstool doesn't reach APFS resource forks.
        assert_eq!(
            read(&mut r, "forked").unwrap_err().kind,
            ErrorKind::UnsupportedOperation
        );
        // A test records it and goes on; extracting skips it and writes the rest.
        let mut test = crate::TestSink::default();
        r.extract(&crate::Selection::all(), &mut test, &mut SimpleCtx::new())
            .unwrap();
        let failed: Vec<&str> = test.report.errors.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(failed, ["forked"]);
        let dest = tempfile::tempdir().unwrap();
        let mut sink = crate::FsSink::new(dest.path(), crate::FsOptions::default()).unwrap();
        let mut cx = SimpleCtx::new();
        r.extract(&crate::Selection::all(), &mut sink, &mut cx)
            .unwrap();
        let report = sink.finish(&mut cx).unwrap();
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path == "forked" && s.reason == crate::SkipReason::Unreadable),
            "{report:?}"
        );
        assert!(!dest.path().join("forked").exists());
        assert_eq!(
            std::fs::read(dest.path().join("dir/a.txt")).unwrap(),
            b"apfs data"
        );
        assert_eq!(std::fs::read(dest.path().join("inline")).unwrap(), small);
    }

    #[test]
    #[ignore = "a timing, run by hand"]
    fn fstool_writer_timing() {
        let n = 10_000u32;
        let mut opts = FormatOpts::default();
        let mut plan = HfsPlusSizePlan::new(&opts);
        for d in 0..100 {
            plan.add_dir(&format!("/d{d}"));
        }
        for i in 0..n {
            plan.add_file(&format!("/d{}/f{i}.txt", i % 100), 1000);
        }
        plan.apply_to(&mut opts);
        let size = (plan.total_size() + (4 << 20)).div_ceil(4096) * 4096;
        let dir = tempfile::tempdir().unwrap();
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.path().join("v.hfs"))
            .unwrap();
        file.set_len(size).unwrap();
        let mut dev = FileDevice { file, size };
        let t = std::time::Instant::now();
        let mut vol = HfsPlus::format(&mut dev, &opts).unwrap();
        println!("format {:?}", t.elapsed());
        for d in 0..100 {
            vol.create_dir(&mut dev, &format!("/d{d}"), 0o755, UID, GID, 1)
                .unwrap();
        }
        let body = vec![7u8; 1000];
        let t = std::time::Instant::now();
        for i in 0..n {
            let path = format!("/d{}/f{i}.txt", i % 100);
            vol.create_file(&mut dev, &path, &mut &body[..], 1000, 0o644, UID, GID, 1)
                .unwrap();
            if i % 2500 == 2499 {
                println!("{} files {:?}", i + 1, t.elapsed());
            }
        }
        let t = std::time::Instant::now();
        vol.flush(&mut dev).unwrap();
        println!("flush {:?}", t.elapsed());
    }

    #[test]
    fn parents_of_a_path() {
        assert_eq!(parents("a/b/c").collect::<Vec<_>>(), ["a", "a/b"]);
        assert_eq!(parents("a").count(), 0);
    }
}
