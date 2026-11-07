//! Writing squashfs with backhand 0.25.5 (docs/M5.md §5.10).
//!
//! - **The codecs** are BeeZip's, behind backhand's `CompressionAction`. backhand doesn't tell
//!   the action which compressor and level it was set up with, so each method and level is a
//!   static of its own.
//! - **Files** are read only when the image is written, in backhand's order. Each one backhand
//!   gets is a reader that opens its file (`NewEntry::source`) on its first read and closes it at
//!   its end, so one file is open at a time, and fails with `Corrupt` if the file's length isn't
//!   what was planned. Entries decoded from another archive have no file: their data is spooled,
//!   end to end, into one temporary file beside the output.
//! - **What mksquashfs writes is matched:** 128 KiB blocks, fragments for files under a block,
//!   holes for blocks of zeros, padding to 4 KiB, and the compressor's options only where
//!   mksquashfs 4.6.1 writes them (gzip below level 9, zstd at a level other than 15, lz4
//!   always), written here since backhand writes gzip's as 7 bytes instead of 8. Duplicate files
//!   aren't looked for: backhand compares only sizes and a 64-bit hash, and leaves stale bytes
//!   after the image when it finds one.
//! - **Entries:** folders, files and symlinks, owned by root, with their modes (0644 and 0755
//!   when unknown) and times. Folders an entry needs but wasn't given are made, as is the root,
//!   whose time backhand leaves at 1970. The image's time is its newest entry's, so the same
//!   files make the same image.
//! - **Progress and cancelling:** `finish` reports the files' bytes read against their total,
//!   and every read and write checks for cancellation.

use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use backhand::{
    BackhandError, FilesystemCompressor, FilesystemWriter, Flags, NodeHeader, SuperBlock,
    compression::{self, CompressionAction, CompressionOptions, Compressor as BhCompressor},
    kind::Kind,
};

use super::{
    SquashfsMethod, SquashfsWriteOptions,
    codec::{self as sqcodec, Compressor, Decoder},
};
use crate::{
    Ctx, Error, ErrorKind, Limits, Meter, MeteredCtx, Result,
    format::{ArchiveWriter, NewEntry, NewKind},
    io::{BUF_SIZE, Counter, WriteSeek, copy, write_error},
    safefs::Partial,
    time::to_unix,
};

/// squashfs names are at most 256 bytes.
const MAX_NAME: usize = 256;

/// One method at one level, as backhand's compression hook.
#[derive(Debug, Clone, Copy)]
struct Codec {
    method: SquashfsMethod,
    level: Option<i32>,
}

const fn levels<const N: usize>(method: SquashfsMethod, first: i32) -> [Codec; N] {
    let mut out = [Codec {
        method,
        level: Some(first),
    }; N];
    let mut i = 0;
    while i < N {
        out[i].level = Some(first + i as i32);
        i += 1;
    }
    out
}

static GZIP: [Codec; 9] = levels(SquashfsMethod::Gzip, 1);
static XZ: [Codec; 10] = levels(SquashfsMethod::Xz, 0);
static ZSTD: [Codec; 22] = levels(SquashfsMethod::Zstd, 1);
static LZ4: Codec = Codec {
    method: SquashfsMethod::Lz4,
    level: None,
};
static LZO: Codec = Codec {
    method: SquashfsMethod::Lzo,
    level: None,
};

/// The static for `method` at `level` (already resolved, so in range).
fn codec(method: SquashfsMethod, level: Option<i32>) -> Result<&'static Codec> {
    let pick = |table: &'static [Codec]| {
        table.iter().find(|c| c.level == level).ok_or_else(|| {
            Error::invalid_args(format!("squashfs {}: no level {level:?}", method.name()))
        })
    };
    match method {
        SquashfsMethod::Gzip => pick(&GZIP),
        SquashfsMethod::Xz => pick(&XZ),
        SquashfsMethod::Zstd => pick(&ZSTD),
        SquashfsMethod::Lz4 => Ok(&LZ4),
        SquashfsMethod::Lzo => Ok(&LZO),
    }
}

impl Codec {
    fn id(self) -> BhCompressor {
        match self.method {
            SquashfsMethod::Gzip => BhCompressor::Gzip,
            SquashfsMethod::Xz => BhCompressor::Xz,
            SquashfsMethod::Zstd => BhCompressor::Zstd,
            SquashfsMethod::Lz4 => BhCompressor::Lz4,
            SquashfsMethod::Lzo => BhCompressor::Lzo,
        }
    }

    /// The options block's contents, where mksquashfs writes one.
    fn options(self) -> Option<Vec<u8>> {
        let level = self.level.and_then(|l| u32::try_from(l).ok());
        match (self.method, level) {
            // struct gzip_comp_opts { int compression_level; short window_size; short strategy; }
            (SquashfsMethod::Gzip, Some(l)) if l != 9 => Some(
                [
                    &l.to_le_bytes()[..],
                    &15u16.to_le_bytes(),
                    &0u16.to_le_bytes(),
                ]
                .concat(),
            ),
            // struct zstd_comp_opts { int compression_level; }
            (SquashfsMethod::Zstd, Some(l)) if l != 15 => Some(l.to_le_bytes().to_vec()),
            // struct lz4_comp_opts { int version; int flags; }: the legacy format, not HC.
            (SquashfsMethod::Lz4, _) => Some([1u32.to_le_bytes(), 0u32.to_le_bytes()].concat()),
            _ => None,
        }
    }

    /// The options as backhand's writer wants them: only so that it asks for them.
    fn backhand_options(self) -> Option<CompressionOptions> {
        self.options()?;
        let level = self.level.and_then(|l| u32::try_from(l).ok()).unwrap_or(0);
        Some(match self.method {
            SquashfsMethod::Gzip => CompressionOptions::Gzip(compression::Gzip {
                compression_level: level,
                window_size: 15,
                strategies: 0,
            }),
            SquashfsMethod::Zstd => CompressionOptions::Zstd(compression::Zstd {
                compression_level: level,
            }),
            _ => CompressionOptions::Lz4(compression::Lz4 {
                version: 1,
                flags: 0,
            }),
        })
    }
}

impl CompressionAction for Codec {
    type Error = BackhandError;
    type Compressor = BhCompressor;
    type FilesystemCompressor = FilesystemCompressor;
    type SuperBlock = SuperBlock;

    /// Not used when writing a new image; bounded by the largest block all the same.
    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        compressor: BhCompressor,
    ) -> Result<(), BackhandError> {
        let comp = Compressor::from_id(compressor as u16)
            .ok_or(BackhandError::CorruptedOrInvalidSquashfs)?;
        let mut d = Decoder::new(comp, &Limits::default())
            .map_err(|_| BackhandError::CorruptedOrInvalidSquashfs)?;
        let mut block = Vec::new();
        d.decode(bytes, &mut block, 1 << 20)
            .map_err(|_| BackhandError::CorruptedOrInvalidSquashfs)?;
        out.extend_from_slice(&block);
        Ok(())
    }

    fn compress(
        &self,
        bytes: &[u8],
        _: FilesystemCompressor,
        block_size: u32,
    ) -> Result<Vec<u8>, BackhandError> {
        sqcodec::encode(self.method, self.level, block_size, bytes).map_err(BackhandError::StdIo)
    }

    /// One uncompressed metadata block, as mksquashfs writes them.
    fn compression_options(
        &self,
        superblock: &mut SuperBlock,
        _: &Kind,
        _: FilesystemCompressor,
    ) -> Result<Option<Vec<u8>>, BackhandError> {
        let Some(body) = self.options() else {
            return Ok(None);
        };
        superblock.flags |= Flags::CompressorOptionsArePresent as u16;
        let mut block = (0x8000 | body.len() as u16).to_le_bytes().to_vec();
        block.extend(body);
        Ok(Some(block))
    }
}

/// Where a file's data comes from.
#[derive(Debug, Clone)]
enum Data {
    /// A file on disk, which must still be `size` bytes long.
    Source { path: PathBuf, size: u64 },
    /// A run of the spool file.
    Spooled { offset: u64, len: u64 },
}

#[derive(Debug, Clone)]
enum ItemKind {
    Dir,
    File(Data),
    Symlink(String),
}

#[derive(Debug, Clone)]
struct Item {
    /// The path's names, without empty ones and `.`.
    names: Vec<String>,
    kind: ItemKind,
    mode: u16,
    /// `None` for a folder BeeZip made: it takes the image's time.
    mtime: Option<u32>,
}

/// The data of entries that have no file, end to end.
struct Spool {
    partial: Partial,
    w: BufWriter<File>,
    len: u64,
}

pub struct SquashfsWriter {
    out: Box<dyn WriteSeek>,
    opts: SquashfsWriteOptions,
    /// The folder the image goes in, for the spool.
    dir: PathBuf,
    name: String,
    items: Vec<Item>,
    /// Each path's item.
    by_path: HashMap<Vec<String>, usize>,
    spool: Option<Spool>,
}

impl SquashfsWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: SquashfsWriteOptions, output: &Path) -> Result<Self> {
        codec(opts.method, opts.level)?;
        let dir = match output.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let name = output
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(Self {
            out,
            opts,
            dir,
            name,
            items: Vec::new(),
            by_path: HashMap::new(),
            spool: None,
        })
    }

    /// `data` appended to the spool, made beside the image on first use.
    fn spool(&mut self, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<Data> {
        let spool = match &mut self.spool {
            Some(s) => s,
            None => {
                let partial = Partial::create(&self.dir, &format!(".{}.spool", self.name))?;
                let w = BufWriter::with_capacity(BUF_SIZE, partial.try_clone()?);
                self.spool.insert(Spool { partial, w, len: 0 })
            }
        };
        let offset = spool.len;
        let len = copy(data, &mut spool.w, cx)?;
        spool.len += len;
        Ok(Data::Spooled { offset, len })
    }

    /// Adds `item`, after the folders above it that aren't there yet. A folder given twice
    /// takes the later one's mode and time; so does a file or link, whose earlier data is then
    /// left out.
    fn insert(&mut self, item: Item, cx: &mut dyn Ctx) -> Result<()> {
        for depth in 1..item.names.len() {
            let parent = item.names[..depth].to_vec();
            match self.by_path.get(&parent).map(|&i| &self.items[i].kind) {
                Some(ItemKind::Dir) => {}
                Some(_) => {
                    return Err(Error::invalid_args(format!(
                        "`{}` is inside `{}`, which isn't a folder",
                        item.names.join("/"),
                        parent.join("/")
                    )));
                }
                None => {
                    self.by_path.insert(parent.clone(), self.items.len());
                    self.items.push(Item {
                        names: parent,
                        kind: ItemKind::Dir,
                        mode: 0o755,
                        mtime: None,
                    });
                }
            }
        }
        match self.by_path.get(&item.names).copied() {
            None => {
                self.by_path.insert(item.names.clone(), self.items.len());
                self.items.push(item);
            }
            Some(i) => {
                let old = &mut self.items[i];
                match (&old.kind, &item.kind) {
                    (ItemKind::Dir, ItemKind::Dir) => {
                        old.mode = item.mode;
                        old.mtime = item.mtime;
                    }
                    (ItemKind::Dir, _) | (_, ItemKind::Dir) => {
                        return Err(Error::invalid_args(format!(
                            "`{}` is both a folder and a file",
                            item.names.join("/")
                        )));
                    }
                    _ => {
                        cx.warn(format!(
                            "`{}` was given twice: the image holds the later one",
                            item.names.join("/")
                        ));
                        *old = item;
                    }
                }
            }
        }
        Ok(())
    }
}

/// The names of `path`, or why squashfs (through backhand, on this system) can't hold it.
fn names(path: &str) -> std::result::Result<Vec<String>, &'static str> {
    let mut out = Vec::new();
    for name in path.split('/') {
        match name {
            "" | "." => {}
            ".." => return Err("its path leads out of the image"),
            n if n.len() > MAX_NAME => return Err("a name in it is longer than 256 bytes"),
            // backhand takes paths as the system's paths: on Windows, `\` separates folders and
            // a name like `C:` is a drive.
            n if cfg!(windows) && (n.contains('\\') || n.as_bytes().get(1) == Some(&b':')) => {
                return Err("a name in it can't be written on Windows (`\\`, or a drive's `:`)");
            }
            n => out.push(n.to_owned()),
        }
    }
    Ok(out)
}

fn mtime(t: Option<SystemTime>) -> Option<u32> {
    t.map(|t| u32::try_from(to_unix(t).max(0)).unwrap_or(u32::MAX))
}

impl ArchiveWriter for SquashfsWriter {
    /// Names squashfs can't hold are refused before anything is written.
    fn expect(&mut self, entries: &[NewEntry]) -> Result<()> {
        for e in entries {
            if e.path.split('/').any(|n| n.len() > MAX_NAME) {
                return Err(Error::invalid_args(format!(
                    "`{}`: squashfs names are at most 256 bytes",
                    e.path
                )));
            }
        }
        Ok(())
    }

    fn reads_sources(&self) -> bool {
        true
    }

    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let names = match names(&entry.path) {
            Ok(n) if n.is_empty() => return Ok(()),
            Ok(n) => n,
            Err(why) => {
                cx.warn(format!("left out `{}`: {why}", entry.path));
                return Ok(());
            }
        };
        let perms = |default: u32| (entry.unix_mode.unwrap_or(default) & 0o7777) as u16;
        let (kind, mode) = match &entry.kind {
            NewKind::Dir => (ItemKind::Dir, perms(0o755)),
            NewKind::Symlink { target } => (ItemKind::Symlink(target.clone()), perms(0o777)),
            NewKind::File => {
                let data = match &entry.source {
                    Some(path) => Data::Source {
                        path: path.clone(),
                        size: entry.size,
                    },
                    None => self.spool(data, cx)?,
                };
                (ItemKind::File(data), perms(0o644))
            }
        };
        let item = Item {
            names,
            kind,
            mode,
            mtime: mtime(entry.modified),
        };
        self.insert(item, cx)
    }

    fn finish(self: Box<Self>, cx: &mut dyn Ctx) -> Result<()> {
        let Self {
            out,
            opts,
            items,
            spool,
            ..
        } = *self;
        let codec = codec(opts.method, opts.level)?;
        // The spool is read back through one handle; the partial file goes when this returns.
        let (spool_file, _spool) = match spool {
            Some(Spool { partial, mut w, .. }) => {
                w.flush().map_err(|e| write_error(&e))?;
                drop(w);
                (Some(partial.reopen()?), Some(partial))
            }
            None => (None, None),
        };
        let image_time = items
            .iter()
            .filter_map(|i| i.mtime)
            .max()
            .or_else(|| mtime(Some(SystemTime::now())))
            .unwrap_or(0);

        let files = items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::File(_)))
            .count() as u64;
        let total: u64 = items
            .iter()
            .map(|i| match &i.kind {
                ItemKind::File(Data::Source { size, .. }) => *size,
                ItemKind::File(Data::Spooled { len, .. }) => *len,
                _ => 0,
            })
            .sum();
        let mut meter = Meter::new(Counter::new(), Some(total));
        meter.entries_total = Some(items.len() as u64);
        meter.entries_done = items.len() as u64 - files;
        let shared = Shared {
            cx: RefCell::new(cx),
            meter: RefCell::new(meter),
            spool: RefCell::new(spool_file),
            failed: RefCell::new(None),
        };

        let mut fs = FilesystemWriter::default();
        fs.set_kind(Kind::new_v4(codec));
        let compressor = FilesystemCompressor::new(codec.id(), codec.backhand_options())
            .map_err(|e| backhand_error(e, "setting up the compressor"))?;
        fs.set_compressor(compressor);
        fs.set_no_duplicate_files(false);
        fs.set_time(image_time);
        fs.set_root_mode(0o755);
        for item in &items {
            let path = format!("/{}", item.names.join("/"));
            let header = NodeHeader::new(item.mode, 0, 0, item.mtime.unwrap_or(image_time));
            let pushed = match &item.kind {
                ItemKind::Dir => fs.push_dir(&path, header),
                ItemKind::Symlink(target) => fs.push_symlink(target.as_str(), &path, header),
                ItemKind::File(data) => fs.push_file(
                    Deferred {
                        shared: &shared,
                        path: item.names.join("/"),
                        data: data.clone(),
                        file: None,
                        read: 0,
                        done: false,
                    },
                    &path,
                    header,
                ),
            };
            pushed.map_err(|e| backhand_error(e, &item.names.join("/")))?;
        }
        let written = fs.write(Out {
            inner: BufWriter::with_capacity(BUF_SIZE, out),
            pos: 0,
            shared: &shared,
        });
        drop(fs);
        if let Err(e) = written {
            // backhand writes some headers through deku, which keeps only an I/O error's kind, so
            // the first error a reader or the output gave is the one to report.
            return Err(shared
                .failed
                .into_inner()
                .unwrap_or_else(|| backhand_error(e, "writing the image")));
        }
        let Shared { cx, meter, .. } = shared;
        let mut meter = meter.into_inner();
        meter.entries_done = items.len() as u64;
        meter.current = None;
        MeteredCtx::new(cx.into_inner(), &meter).report();
        Ok(())
    }
}

/// A backhand error as a core one: a core error smuggled through one of BeeZip's readers or
/// writers comes back as it was; an I/O error is `Io`.
fn backhand_error(e: BackhandError, doing: &str) -> Error {
    match e {
        BackhandError::StdIo(e) => match e.get_ref().and_then(|x| x.downcast_ref::<Error>()) {
            Some(inner) => inner.clone(),
            None => Error::io(format!("squashfs: {doing}"), &e),
        },
        BackhandError::InvalidFilePath
        | BackhandError::DuplicatedFileName
        | BackhandError::UndefineFileName => Error::invalid_args(format!("squashfs: {doing}: {e}")),
        e => Error::new(ErrorKind::Io, format!("squashfs: {doing}: {e}")),
    }
}

/// What the readers and the output share while the image is written: the job, its progress,
/// the spool's handle, and the first error.
struct Shared<'c> {
    cx: RefCell<&'c mut dyn Ctx>,
    meter: RefCell<Meter>,
    spool: RefCell<Option<File>>,
    failed: RefCell<Option<Error>>,
}

impl Shared<'_> {
    /// Reports progress and fails once the job is cancelled.
    fn check(&self) -> io::Result<()> {
        let mut cx = self.cx.borrow_mut();
        let meter = self.meter.borrow();
        MeteredCtx::new(&mut **cx, &meter)
            .check()
            .map_err(Error::into_io)
    }

    /// Records `e` as the first error, if it is: a core error smuggled through it as it was,
    /// an I/O one with what was being done.
    fn fail(&self, e: io::Error, doing: impl FnOnce() -> String) -> io::Error {
        let mut failed = self.failed.borrow_mut();
        if failed.is_none() {
            *failed = Some(match e.get_ref().and_then(|x| x.downcast_ref::<Error>()) {
                Some(inner) => inner.clone(),
                None => Error::io(doing(), &e),
            });
        }
        e
    }
}

/// A file's data, opened on its first read and closed at its end.
struct Deferred<'s, 'c> {
    shared: &'s Shared<'c>,
    path: String,
    data: Data,
    file: Option<File>,
    /// Bytes given so far.
    read: u64,
    done: bool,
}

impl Deferred<'_, '_> {
    fn len(&self) -> u64 {
        match &self.data {
            Data::Source { size, .. } => *size,
            Data::Spooled { len, .. } => *len,
        }
    }

    fn changed(&self) -> io::Error {
        Error::corrupt(format!(
            "`{}` changed size while the image was being written",
            self.path
        ))
        .into_io()
    }

    fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.len() - self.read;
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        match &self.data {
            Data::Source { path, .. } => {
                if self.file.is_none() {
                    let f = File::open(path).map_err(|e| {
                        Error::io(format!("reading {}", path.display()), &e).into_io()
                    })?;
                    self.file = Some(f);
                    self.shared.meter.borrow_mut().current = Some(self.path.clone());
                }
                let Some(f) = self.file.as_mut() else {
                    return Ok(0);
                };
                if want == 0 {
                    // At the planned length: the file must end here too.
                    let mut probe = [0u8; 1];
                    if f.read(&mut probe)? != 0 {
                        return Err(self.changed());
                    }
                    return Ok(0);
                }
                let n = f.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(self.changed());
                }
                Ok(n)
            }
            Data::Spooled { offset, .. } => {
                if want == 0 {
                    return Ok(0);
                }
                let mut spool = self.shared.spool.borrow_mut();
                let Some(f) = spool.as_mut() else {
                    return Err(Error::corrupt("the spool is gone").into_io());
                };
                f.seek(SeekFrom::Start(offset + self.read))?;
                let n = f.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(Error::corrupt("the spool is shorter than its entries").into_io());
                }
                Ok(n)
            }
        }
    }
}

impl Read for Deferred<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let n = self
            .shared
            .check()
            .and_then(|()| self.read_some(buf))
            .map_err(|e| self.shared.fail(e, || format!("reading `{}`", self.path)))?;
        self.read += n as u64;
        self.shared.meter.borrow().bytes.add(n as u64);
        if n == 0 {
            self.done = true;
            self.file = None;
            let mut meter = self.shared.meter.borrow_mut();
            meter.entries_done += 1;
        }
        Ok(n)
    }
}

/// backhand's output: buffered, with the position kept here so that backhand's frequent
/// `stream_position` doesn't flush the buffer, and a check for cancellation on every write.
struct Out<'s, 'c> {
    inner: BufWriter<Box<dyn WriteSeek>>,
    pos: u64,
    shared: &'s Shared<'c>,
}

impl Write for Out<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self
            .shared
            .check()
            .and_then(|()| self.inner.write(buf))
            .map_err(|e| self.shared.fail(e, || "writing the image".into()))?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .flush()
            .map_err(|e| self.shared.fail(e, || "writing the image".into()))
    }
}

impl Seek for Out<'_, '_> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        if to == SeekFrom::Current(0) {
            return Ok(self.pos);
        }
        self.pos = self
            .inner
            .seek(to)
            .map_err(|e| self.shared.fail(e, || "writing the image".into()))?;
        Ok(self.pos)
    }
}
