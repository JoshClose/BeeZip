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
//! - **A virtual disk** ([`vdisk`]: VHD, VHDX, VMDK, QCOW2, VDI) is one more level, opened first
//!   (docs/M8.md §2): inside it, a bare file system opens straight through, a partition table as
//!   above, and anything else is listed as one raw file, `<file stem>.img`, as 7-Zip names it.
//!   Info gives the levels, `vhdx > gpt > ntfs`. The ratio limit reads such a disk as it would a
//!   raw image, counting the disk's bytes rather than its files' (holes and compressed grains read
//!   little of them); a raw item is claim-checked against what the disk's files hold for it; and
//!   one disk yields at most `max_ratio` times its files' size in a pass (docs/M8.md §3.7).

pub mod apple;
pub mod ext;
pub mod fat;
pub mod ntfs;
pub mod part;
pub mod vdisk;
pub mod wof;

use std::{
    borrow::Cow,
    collections::HashMap,
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
    io::{Counter, CountingReader, copy, read_error},
    limits::{Guarded, Limits, RatioGuard},
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

/// A virtual disk as its device reads it: every byte counts toward the ratio limit's input, and
/// toward the disk-wide cap of the current pass (docs/M8.md §3.7).
struct Metered {
    disk: vdisk::VirtualDisk,
    /// Bytes of the disk read: what each entry's ratio is measured against.
    read: Counter,
    /// Bytes of the disk read in this pass: an extraction, or every `open_entry` together.
    used: Counter,
    /// `max_ratio` times the disk's files' size, plus the grace.
    cap: Option<u64>,
}

impl Read for Metered {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.disk.read(buf)?;
        self.read.add(n as u64);
        self.used.add(n as u64);
        if let Some(cap) = self.cap
            && self.used.get() > cap
        {
            return Err(Error::limit(format!(
                "the {} gives more than {cap} bytes in one go, past the ratio limit for its \
                 files' {} bytes (limit `max_ratio`)",
                self.disk.format().display_name(),
                self.disk.file_bytes()
            ))
            .into_io());
        }
        Ok(n)
    }
}

impl Seek for Metered {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.disk.seek(pos)
    }
}

/// A [`Metered`] disk shared by its device and the reader, which asks it what its files hold.
#[derive(Clone)]
struct SharedDisk(Arc<Mutex<Metered>>);

impl SharedDisk {
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Metered>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("a reader of this disk failed earlier"))
    }
}

impl Read for SharedDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lock()?.read(buf)
    }
}

impl Seek for SharedDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.lock()?.seek(pos)
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
    fn open(&mut self, id: usize) -> Result<Box<dyn Read + '_>>;

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
    /// A hard link to the file that is entry `file` of the archive: no data when extracting,
    /// since the sink links it to the file already written, and the file's when opened alone.
    Link { file: usize },
}

/// A disk or a bare volume (see the module's notes).
pub struct DiskReader {
    kind: External,
    source: Source,
    /// What each entry's ratio is measured against: the image's bytes read, or a virtual
    /// disk's.
    ratio: Counter,
    /// The bytes progress runs to: the image's, or every file of a virtual disk.
    size: u64,
    /// A virtual disk, read through its device.
    vdisk: Option<SharedDisk>,
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
        let opts = VolumeOptions {
            limits: source.limits.clone(),
            names: source.names,
        };
        let mut r = Self {
            kind,
            ratio: source.counter.clone(),
            size: source.size,
            vdisk: None,
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
            External::Gpt | External::Mbr => {
                let dev = Device::new(input, len);
                let table = part::read(&dev, cx)?;
                r.disk(table, dev, &opts, cx)?;
            }
            External::Vhd | External::Vhdx | External::Vmdk | External::Qcow2 | External::Vdi => {
                r.virtual_disk(kind, input, len, &opts, cx)?;
            }
            _ => {
                let fs = open_fs(kind, Device::new(input, len), &opts, cx)?;
                r.add_fs(fs, None, cx)?;
            }
        }
        Ok(r)
    }

    /// A virtual disk, then what's inside it (see the module's notes).
    fn virtual_disk(
        &mut self,
        kind: External,
        input: Box<dyn Input>,
        len: u64,
        opts: &VolumeOptions,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        // A disk spooled out of a codec looks for its parents beside the original.
        let origin = vdisk::Origin::of(&self.source.path);
        let mut files = vdisk::Files::new(&origin, self.source.counter.clone())
            .with_memory(self.source.limits.decoder_memory);
        let disk = vdisk::open(kind, vdisk::Handle::new(input, len), origin, &mut files)?;
        let level = kind.name().to_owned();
        for (name, value) in disk.properties() {
            self.properties.push(LevelProperty {
                level: level.clone(),
                name: name.to_owned(),
                value,
            });
        }
        self.notes.extend(disk.notes());
        self.levels.push(level);
        let files_size = disk.file_bytes();
        self.size = files_size.max(self.source.size);
        let (disk_len, sector) = (disk.len(), disk.sector());
        let limits = &self.source.limits;
        let cap = limits.max_ratio.map(|max| {
            max.saturating_mul(files_size)
                .saturating_add(limits.ratio_grace)
        });
        let read = Counter::new();
        let shared = SharedDisk(Arc::new(Mutex::new(Metered {
            disk,
            read: read.clone(),
            used: Counter::new(),
            cap,
        })));
        self.ratio = read;
        self.vdisk = Some(shared.clone());
        let dev = Device::new(Box::new(shared), disk_len).with_sector(sector);
        // A bare file system first: FAT's and NTFS's boot sectors end as an MBR does.
        if let Some(fs_kind) = identify(&dev) {
            match open_fs(fs_kind, dev.clone(), opts, cx) {
                Ok(fs) => return self.add_fs(fs, None, cx),
                Err(e) if !matches!(e.kind, ErrorKind::Corrupt | ErrorKind::Io) => return Err(e),
                Err(e) => cx.warn(format!(
                    "the {} in the disk can't be read ({}); the disk is listed as a file",
                    fs_kind.display_name(),
                    e.message
                )),
            }
        } else {
            match part::read(&dev, cx) {
                Ok(table) => return self.disk(table, dev, opts, cx),
                Err(e) if e.kind != ErrorKind::Corrupt => return Err(e),
                Err(_) => {}
            }
        }
        let stem = self.stem();
        self.raw(format!("{stem}.img"), dev, disk_len)
    }

    /// The image's file name without its extension, nor its codecs' (`disk` for `disk.vhdx.gz`).
    fn stem(&self) -> String {
        let mut p = self.source.path.clone();
        for _ in &self.source.codecs {
            p.set_extension("");
        }
        p.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "disk".to_owned())
    }

    /// Bytes of `start..start + len` of `win` its virtual disk's files hold; of an image, what
    /// of it the file has.
    fn held(&self, win: &Device, start: u64, len: u64) -> u64 {
        match &self.vdisk {
            Some(d) => d
                .lock()
                .map_or(len, |m| m.disk.held_in(win.base() + start, len)),
            None => win.real_len(),
        }
    }

    /// `win` listed as one raw file `name` of `len` bytes.
    fn raw(&mut self, name: String, win: Device, len: u64) -> Result<()> {
        self.source
            .limits
            .check_entries(self.entries.len() as u64 + 1)?;
        let mut e = Entry::new(self.entries.len(), name, EntryKind::File);
        e.size = Some(len);
        e.packed_size = Some(self.held(&win, 0, len));
        self.entries.push(e);
        self.items.push(Item::Raw {
            part: self.parts.len(),
        });
        self.parts.push(Part::Raw(win));
        Ok(())
    }

    /// A partitioned disk's partitions (see the module's notes).
    fn disk(
        &mut self,
        table: part::Table,
        dev: Device,
        opts: &VolumeOptions,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
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
            self.raw(name, win, p.len)?;
        }
        Ok(())
    }

    /// The ratio check of an entry's data, against [`DiskReader::ratio`].
    fn ratio_guard(&self) -> RatioGuard {
        RatioGuard::new(&self.ratio, &self.source.limits)
    }

    /// Starts a pass over a virtual disk: an extraction's yield is capped on its own.
    fn new_pass(&self) {
        if let Some(d) = &self.vdisk
            && let Ok(m) = d.lock()
        {
            m.used.set(0);
        }
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
        // The files hard links name, by their paths in the volume.
        let files: HashMap<&str, usize> = if list
            .iter()
            .any(|e| matches!(e.kind, EntryKind::Hardlink { .. }))
        {
            list.iter()
                .filter(|e| e.kind == EntryKind::File)
                .map(|e| (e.path.as_str(), e.id))
                .collect()
        } else {
            HashMap::new()
        };
        let links: Vec<Option<usize>> = list
            .iter()
            .map(|e| match &e.kind {
                EntryKind::Hardlink { target } => files.get(target.as_str()).copied(),
                _ => None,
            })
            .collect();
        drop(files);
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
            let item = match (&e.kind, links[i]) {
                (EntryKind::File, _) => Item::Fs { part, id: i },
                (EntryKind::Hardlink { .. }, Some(id)) => Item::Link { file: base + id },
                _ => Item::None,
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

/// Data that can't be read: the reason, at the first read.
struct Unreadable(Option<Error>);

impl Read for Unreadable {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self
            .0
            .take()
            .unwrap_or_else(|| Error::corrupt("an entry that can't be read"))
            .into_io())
    }
}

/// What extracting does with a file whose data couldn't be opened, `e` saying why. Written to
/// disk, a file BeeZip doesn't read (`UnsupportedOperation`: on NTFS, EFS, WOF or deduplicated)
/// is skipped and reported, as a device is, and the rest extracts: `None` then. Otherwise a
/// file that can't be read, damaged or unsupported, fails at its first read, so a test records
/// it and goes on and an extraction stops there. Any other error stops at once.
pub(crate) fn unreadable(
    e: Error,
    entry: &Entry,
    sink: &mut dyn EntrySink,
    cx: &mut dyn Ctx,
) -> Result<Option<Box<dyn Read>>> {
    match e.kind {
        ErrorKind::UnsupportedOperation => match sink.as_fs_sink() {
            Some(fs) => {
                fs.skip_unreadable(entry, &e, cx)?;
                Ok(None)
            }
            None => Ok(Some(Box::new(Unreadable(Some(e))))),
        },
        ErrorKind::Corrupt => Ok(Some(Box::new(Unreadable(Some(e))))),
        _ => Err(e),
    }
}

/// The data of entry `idx`, checked against the ratio limit and held to its size. A hard link
/// has its file's data only when `links` says so: `open_entry`'s, not `extract`'s. A raw item
/// is claim-checked too with `claim_raw`: a virtual disk's, whose holes cost nothing to read.
fn open_data<'a>(
    parts: &'a mut [Part],
    entries: &[Entry],
    items: &[Item],
    limits: &Limits,
    idx: usize,
    links: bool,
    claim_raw: bool,
) -> Result<Box<dyn Read + 'a>> {
    let (Some(entry), Some(item)) = (entries.get(idx), items.get(idx)) else {
        return Err(Error::new(ErrorKind::NotFound, format!("no entry {idx}")));
    };
    let size = entry.size.unwrap_or(0);
    match *item {
        Item::None => Ok(Box::new(io::empty())),
        Item::Link { .. } if !links => Ok(Box::new(io::empty())),
        Item::Link { file } => open_data(parts, entries, items, limits, file, false, claim_raw),
        Item::Fs { part, id } => {
            check_claim(entry, limits)?;
            let Some(Part::Fs(fs)) = parts.get_mut(part) else {
                return Err(Error::corrupt("an entry without its volume"));
            };
            Ok(Box::new(Exact::new(fs.open(id)?, size, &entry.path)))
        }
        Item::Raw { part } => {
            if claim_raw {
                check_claim(entry, limits)?;
            }
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
        // A sparse file, or a virtual disk's raw item, that claims too much is refused before
        // anything is written.
        let claim_raw = self.vdisk.is_some();
        for (e, item) in self.entries.iter().zip(&self.items) {
            let claimed = match item {
                Item::Fs { .. } => true,
                Item::Raw { .. } => claim_raw,
                _ => false,
            };
            if claimed && sel.matches(e) {
                check_claim(e, &self.source.limits)?;
            }
        }
        self.source.counter.set(0);
        self.new_pass();
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.size));
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
            let data = match open_data(
                &mut self.parts,
                &self.entries,
                &self.items,
                &self.source.limits,
                idx,
                false,
                claim_raw,
            ) {
                Ok(d) => d,
                Err(e) => match unreadable(e, &self.entries[idx], sink, &mut mcx)? {
                    Some(d) => d,
                    None => {
                        done += 1;
                        continue;
                    }
                },
            };
            let ratio = RatioGuard::new(&self.ratio, &self.source.limits);
            let mut data = Guarded::new(data, ratio, self.source.budget.clone());
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
        let ratio = self.ratio_guard();
        let data = open_data(
            &mut self.parts,
            &self.entries,
            &self.items,
            &self.source.limits,
            id,
            true,
            self.vdisk.is_some(),
        )?;
        Ok(Box::new(Guarded::new(
            data,
            ratio,
            self.source.budget.clone(),
        )))
    }
}
