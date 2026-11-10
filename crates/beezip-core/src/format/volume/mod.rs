//! Disks and volumes BeeZip reads itself (docs/M7.md §2): partitioned disks (GPT, MBR) and the
//! file systems FAT, NTFS, ext2/3/4, HFS+ and APFS, bare or in a disk's partitions.
//!
//! - **The device** ([`Device`]) is the archive's input as fstool's block device, seen through a
//!   window: the whole file, or one partition. Clones share the input and each keeps its own
//!   window and position, so every partition's file system stays open at once. It's read only.
//!   Behind a codec (`disk.img.gz`) the image is spooled to a temporary file first, since it's
//!   read at offsets, as a DMG is.
//! - **File systems** implement [`FileSystem`]: they list every entry when they open and read a
//!   file's data by its index. Paths are from the volume's root; a hard link names its target by
//!   such a path. Each file's `packed_size` is what the volume has allocated to it, so a sparse
//!   file that claims far more than that is refused before any byte is read (the ratio limit,
//!   [`check_claim`]); while it's read, the ratio counts the bytes read from the image, as for
//!   every format.
//! - **A disk** ([`part`]) with one partition whose file system BeeZip reads opens straight into
//!   it. With several, each such partition is a folder named as 7-Zip names the partition,
//!   without its extension (`0.data/`), and the others are files of their raw sectors
//!   (`2.swap.img`), to open in turn. A file system that can't be read in a disk of several
//!   partitions is listed as such a file, with a warning.
//! - **What a reader doesn't support** (`UnsupportedOperation`) in a bare volume or a disk's only
//!   partition fails the open, so that `source::open` can hand the file to 7-Zip when it's
//!   installed (docs/M7.md decision 7). A damaged volume never goes to 7-Zip.

pub mod apple;
pub mod ext;
pub mod fat;
pub mod ntfs;
pub mod part;

use std::{
    borrow::Cow,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};

use fstool::block::BlockDevice;

use super::{
    ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    backend::{External, ExternalInfo, LevelProperty},
    io::{CountingReader, copy, read_error},
    limits::Limits,
    names::NameDecoding,
    safefs::Partial,
    source::Source,
};

/// What a [`Device`] reads: the archive's input, or a DMG's decoded disk.
pub trait Input: Read + Seek + Send {}

impl<T: Read + Seek + Send> Input for T {}

/// The input as fstool's block device, through a window (see the module's notes). Writes fail.
#[derive(Clone)]
pub struct Device {
    input: Arc<Mutex<Box<dyn Input>>>,
    /// Where the window starts in the input.
    base: u64,
    len: u64,
    /// The window's bytes the input really has; past them it reads zeros ([`Device::padded`]).
    real: u64,
    pos: u64,
    sector: u32,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("base", &self.base)
            .field("len", &self.len)
            .field("real", &self.real)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// The first `len` bytes of `input`, in sectors of 512 bytes.
    pub fn new(input: Box<dyn Input>, len: u64) -> Self {
        Self {
            input: Arc::new(Mutex::new(input)),
            base: 0,
            len,
            real: len,
            pos: 0,
            sector: 512,
        }
    }

    /// The window's length.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes of the window the input really has: less than [`Device::len`] for a truncated
    /// image.
    pub fn real_len(&self) -> u64 {
        self.real
    }

    /// Where the window starts in the input.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The `len` bytes from `base` of this window as a device of their own, at their start.
    pub fn window(&self, base: u64, len: u64) -> Result<Self> {
        if base.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(Error::corrupt(format!(
                "{len} bytes at {base} reach past the end of the volume ({} bytes)",
                self.len
            )));
        }
        Ok(Self {
            input: Arc::clone(&self.input),
            base: self.base + base,
            len,
            real: self.real.saturating_sub(base).min(len),
            pos: 0,
            sector: self.sector,
        })
    }

    /// The same window made `len` long, reading zeros past what the input has: a volume whose
    /// image was cut short.
    pub fn padded(self, len: u64) -> Self {
        Self {
            len: len.max(self.len),
            ..self
        }
    }

    /// The same, with sectors of `sector` bytes (fstool's advisory block size).
    pub fn with_sector(self, sector: u32) -> Self {
        Self { sector, ..self }
    }

    /// Exactly `buf.len()` bytes at `offset` of the window. Past its end is `Corrupt`.
    pub fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(Error::corrupt(format!(
                "a read of {} bytes at {offset} past the end of the volume ({} bytes)",
                buf.len(),
                self.len
            )));
        }
        self.pos = offset;
        self.read_exact(buf).map_err(|e| read_error(&e))
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let left = usize::try_from(self.len - self.pos).unwrap_or(usize::MAX);
        let want = buf.len().min(left);
        let n = if self.pos >= self.real {
            buf[..want].fill(0);
            want
        } else {
            let real = usize::try_from(self.real - self.pos).unwrap_or(usize::MAX);
            let want = want.min(real);
            let mut input = self
                .input
                .lock()
                .map_err(|_| io::Error::other("a reader of this image failed earlier"))?;
            input.seek(SeekFrom::Start(self.base + self.pos))?;
            input.read(&mut buf[..want])?
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Device {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
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
        self.sector
    }

    fn total_size(&self) -> u64 {
        self.len
    }

    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}

/// The image to read at offsets, counted: the file, or the stream spooled out of its codecs.
pub fn open_input(
    source: &Source,
    cx: &mut dyn Ctx,
) -> Result<(Box<dyn Input>, u64, Option<Partial>)> {
    if source.codecs.is_empty() {
        let input = source.input()?;
        let len = input.len();
        let counted = CountingReader::new(input, source.counter.clone());
        return Ok((Box::new(counted), len, None));
    }
    let mut tmp = Partial::create_temp("beezip-spool.img")?;
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

/// What a file system is opened with.
#[derive(Debug, Clone)]
pub struct VolumeOptions {
    pub limits: Limits,
    /// How names stored as bytes are read: ext's, FAT's 8.3 names.
    pub names: NameDecoding,
}

/// A file system BeeZip reads (see the module's notes).
pub trait FileSystem: Send {
    /// Which it is.
    fn kind(&self) -> External;

    /// Every folder, file, link and special file, parents before what's in them, with ids from
    /// 0 in this order and `/`-separated paths from the volume's root. Called once, when the
    /// volume opens; it checks `cx` for cancellation between folders.
    fn entries(&mut self, cx: &mut dyn Ctx) -> Result<Vec<Entry>>;

    /// The data of entry `id` of [`FileSystem::entries`], a file. It may end early or run long:
    /// the disk reader holds it to the entry's size and fails a short one.
    fn open(&mut self, id: usize) -> Result<Box<dyn Read + Send + '_>>;

    /// What Info shows of the volume: its label, cluster size. Names as 7-Zip's (`Label`).
    fn properties(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    /// The compression methods its files use (NTFS's `LZNT1`), for Info.
    fn methods(&self) -> Vec<Cow<'static, str>> {
        Vec::new()
    }
}

/// The file system on `dev`, opened.
pub fn open_fs(
    kind: External,
    dev: Device,
    opts: &VolumeOptions,
    cx: &mut dyn Ctx,
) -> Result<Box<dyn FileSystem>> {
    match kind {
        External::Fat => fat::open(dev, opts, cx),
        External::Ntfs => ntfs::open(dev, opts, cx),
        External::Ext => ext::open(dev, opts, cx),
        External::Hfs | External::Apfs => apple::open(dev, opts, cx),
        k => Err(Error::unsupported(format!(
            "a {} isn't a file system BeeZip reads",
            k.display_name()
        ))),
    }
}

/// The file system whose boot sector or superblock starts `dev`, among those BeeZip reads.
pub fn identify(dev: &Device) -> Option<External> {
    let mut head = vec![0u8; usize::try_from(dev.len().min(64 * 1024)).ok()?];
    let mut d = dev.clone();
    d.read_exact_at(0, &mut head).ok()?;
    crate::backend::sniff::file_system(&head)
}

/// Refuses an entry that claims more than the ratio limit allows from what the volume allocated
/// to it: a sparse file of 100 GB in an image of 256 KiB (docs/M7.md §2).
pub fn check_claim(entry: &Entry, limits: &Limits) -> Result<()> {
    let (Some(size), Some(packed), Some(max)) = (entry.size, entry.packed_size, limits.max_ratio)
    else {
        return Ok(());
    };
    if size > limits.ratio_grace && size / packed.max(1) > max {
        return Err(Error::limit(format!(
            "`{}` claims {size} bytes from {packed} on the volume, more than {max}:1 (limit \
             `max_ratio`)",
            entry.path
        )));
    }
    Ok(())
}

/// Exactly `left` bytes of `inner`: one that ends early is `Corrupt`, and what runs past is cut.
pub struct Exact<R> {
    inner: R,
    left: u64,
    path: String,
}

impl<R> Exact<R> {
    pub fn new(inner: R, len: u64, path: &str) -> Self {
        Self {
            inner,
            left: len,
            path: path.to_owned(),
        }
    }
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
            return Err(
                Error::corrupt(format!("`{}` ends {} bytes short", self.path, self.left)).into_io(),
            );
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// What the entries come from: a file system, or a partition's raw sectors.
enum Part {
    Fs(Box<dyn FileSystem>),
    Raw(Device),
}

/// What an entry's data is.
#[derive(Debug, Clone, Copy)]
enum Item {
    /// A folder, a link or a special file: none.
    None,
    /// Entry `id` of part `part`'s file system, a file.
    Fs { part: usize, id: usize },
    /// Part `part`'s sectors.
    Raw { part: usize },
}

/// A disk or a bare volume (see the module's notes).
pub struct DiskReader {
    kind: External,
    source: Source,
    parts: Vec<Part>,
    entries: Vec<Entry>,
    items: Vec<Item>,
    levels: Vec<String>,
    properties: Vec<LevelProperty>,
    notes: Vec<String>,
    methods: Vec<Cow<'static, str>>,
    /// Keeps an image spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl DiskReader {
    /// Opens the image `kind` says it is: a disk or a bare file system.
    pub fn open(source: Source, kind: External, cx: &mut dyn Ctx) -> Result<Self> {
        let (input, len, spool) = open_input(&source, cx)?;
        let dev = Device::new(input, len);
        let opts = VolumeOptions {
            limits: source.limits.clone(),
            names: source.names,
        };
        let mut r = Self {
            kind,
            source,
            parts: Vec::new(),
            entries: Vec::new(),
            items: Vec::new(),
            levels: Vec::new(),
            properties: Vec::new(),
            notes: Vec::new(),
            methods: Vec::new(),
            _spool: spool,
        };
        match kind {
            External::Gpt | External::Mbr => r.disk(dev, &opts, cx)?,
            _ => {
                let fs = open_fs(kind, dev, &opts, cx)?;
                r.add_fs(fs, None, cx)?;
            }
        }
        Ok(r)
    }

    /// A partitioned disk's partitions (see the module's notes).
    fn disk(&mut self, dev: Device, opts: &VolumeOptions, cx: &mut dyn Ctx) -> Result<()> {
        let table = part::read(&dev, cx)?;
        self.levels.push(table.scheme.name().to_owned());
        let found: Vec<(part::Partition, Device, Option<External>)> = table
            .partitions
            .into_iter()
            .filter_map(|p| {
                let win = match dev.window(p.start, p.len.min(dev.len().saturating_sub(p.start))) {
                    Ok(w) => w.padded(p.len),
                    Err(e) => {
                        cx.warn(format!("partition `{}`: {}", p.name, e.message));
                        return None;
                    }
                };
                if win.real_len() < p.len {
                    cx.warn(format!(
                        "partition `{}` is cut short by the image's end; it reads zeros past it",
                        p.name
                    ));
                }
                let fs = identify(&win);
                Some((p, win, fs))
            })
            .collect();
        if let [(p, win, Some(fs_kind))] = &found[..] {
            match open_fs(*fs_kind, win.clone(), opts, cx) {
                Ok(fs) => return self.add_fs(fs, None, cx),
                Err(e) if !matches!(e.kind, ErrorKind::Corrupt | ErrorKind::Io) => return Err(e),
                Err(e) => cx.warn(format!(
                    "the {} in partition `{}` can't be read ({}); it's listed as a file",
                    fs_kind.display_name(),
                    p.name,
                    e.message
                )),
            }
        }
        let several = found.len() > 1;
        for (p, win, fs_kind) in found {
            cx.check()?;
            if several && let Some(k) = fs_kind {
                match open_fs(k, win.clone(), opts, cx) {
                    Ok(fs) => {
                        self.add_fs(fs, Some(&p.name), cx)?;
                        continue;
                    }
                    Err(e) if matches!(e.kind, ErrorKind::Cancelled | ErrorKind::LimitExceeded) => {
                        return Err(e);
                    }
                    Err(e) => cx.warn(format!(
                        "the {} in partition `{}` can't be read ({}); it's listed as a file",
                        k.display_name(),
                        p.name,
                        e.message
                    )),
                }
            }
            let name = format!("{}.{}", p.name, part::extension(fs_kind));
            self.source
                .limits
                .check_entries(self.entries.len() as u64 + 1)?;
            let mut e = Entry::new(self.entries.len(), name, EntryKind::File);
            e.size = Some(p.len);
            e.packed_size = Some(win.real_len());
            self.entries.push(e);
            self.items.push(Item::Raw {
                part: self.parts.len(),
            });
            self.parts.push(Part::Raw(win));
        }
        Ok(())
    }

    /// `fs`'s entries, under the folder `folder` when it's a partition of several.
    fn add_fs(
        &mut self,
        mut fs: Box<dyn FileSystem>,
        folder: Option<&str>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let kind = fs.kind();
        let list = fs.entries(cx)?;
        let base = self.entries.len();
        let part = self.parts.len();
        let level = match folder {
            Some(f) => {
                self.source.limits.check_entries(base as u64 + 1)?;
                self.entries
                    .push(Entry::new(base, f.to_owned(), EntryKind::Dir));
                self.items.push(Item::None);
                format!("{f} ({})", kind.name())
            }
            None => {
                self.levels.push(kind.name().to_owned());
                kind.name().to_owned()
            }
        };
        let base = self.entries.len();
        self.source
            .limits
            .check_entries((base + list.len()) as u64)?;
        for (i, mut e) in list.into_iter().enumerate() {
            e.id = base + i;
            if let Some(f) = folder {
                e.path = format!("{f}/{}", e.path);
                let mut raw = f.as_bytes().to_vec();
                raw.push(b'/');
                raw.extend_from_slice(&e.raw_path);
                e.raw_path = raw;
                if let EntryKind::Hardlink { target } = &mut e.kind {
                    *target = format!("{f}/{target}");
                }
            }
            let item = if e.kind == EntryKind::File {
                Item::Fs { part, id: i }
            } else {
                Item::None
            };
            self.entries.push(e);
            self.items.push(item);
        }
        for (name, value) in fs.properties() {
            self.properties.push(LevelProperty {
                level: level.clone(),
                name: name.to_owned(),
                value,
            });
        }
        for m in fs.methods() {
            if !self.methods.contains(&m) {
                self.methods.push(m);
            }
        }
        self.parts.push(Part::Fs(fs));
        Ok(())
    }
}

/// The data of entry `idx`, checked against the ratio limit and held to its size.
fn open_data<'a>(
    parts: &'a mut [Part],
    entries: &[Entry],
    items: &[Item],
    limits: &Limits,
    idx: usize,
) -> Result<Box<dyn Read + 'a>> {
    let (Some(entry), Some(item)) = (entries.get(idx), items.get(idx)) else {
        return Err(Error::new(ErrorKind::NotFound, format!("no entry {idx}")));
    };
    let size = entry.size.unwrap_or(0);
    match *item {
        Item::None => Ok(Box::new(io::empty())),
        Item::Fs { part, id } => {
            check_claim(entry, limits)?;
            let Some(Part::Fs(fs)) = parts.get_mut(part) else {
                return Err(Error::corrupt("an entry without its volume"));
            };
            Ok(Box::new(Exact::new(fs.open(id)?, size, &entry.path)))
        }
        Item::Raw { part } => {
            let Some(Part::Raw(dev)) = parts.get(part) else {
                return Err(Error::corrupt("an entry without its partition"));
            };
            Ok(Box::new(Exact::new(dev.clone(), size, &entry.path)))
        }
    }
}

impl ArchiveReader for DiskReader {
    fn format(&self) -> FormatId {
        FormatId::External(self.kind)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::External(self.kind),
            codecs: self.source.codecs.clone(),
            methods: self.methods.clone(),
            comment: None,
            encryption: Encryption::None,
            solid: false,
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: Some(ExternalInfo {
                backend: None,
                levels: self.levels.clone(),
                properties: self.properties.clone(),
                notes: self.notes.clone(),
            }),
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
        for idx in 0..self.entries.len() {
            if !sel.matches(&self.entries[idx]) {
                continue;
            }
            cx.check()?;
            meter.entries_done = done;
            meter.current = Some(self.entries[idx].path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            let data = open_data(
                &mut self.parts,
                &self.entries,
                &self.items,
                &self.source.limits,
                idx,
            )?;
            let mut data = self.source.guard(data);
            sink.entry(&self.entries[idx], &mut data, &mut mcx)?;
            done += 1;
        }
        meter.entries_done = done;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        self.source.counter.set(0);
        let data = open_data(
            &mut self.parts,
            &self.entries,
            &self.items,
            &self.source.limits,
            id,
        )?;
        Ok(Box::new(self.source.guard(data)))
    }
}
