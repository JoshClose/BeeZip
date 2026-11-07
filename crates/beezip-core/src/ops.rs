//! Whole operations on top of the readers, writers and sinks: create, extract and test, and
//! the edits and convert of [`crate::edit`]. The commands in `beezip-commands` call these.

use std::{
    fs::{self, File},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    CodecId, Ctx, EncodeOpts, Error, ErrorKind, ExtractReport, FsOptions, FsSink, Meter,
    MeteredCtx, Result, Selection, TestReport, TestSink,
    codec::{FinishWrite, finisher},
    format::{
        ArchiveWriter, Entry, EntryKind, FormatId, NewEntry, NewKind,
        ar::ArWriter,
        cab::{CabWriteOptions, CabWriter},
        cpio::CpioWriter,
        sevenz::{SevenZWriteOptions, SevenZWriter},
        tar::TarWriter,
        zip::{ZipWriteOptions, ZipWriter},
    },
    io::{BUF_SIZE, Counter, CountingReader, WriteSeek},
    safefs::Partial,
    source::{OpenOptions, open},
    volume::VolumeWriter,
};

pub use crate::edit::{convert, edit, rewrite};

/// The archive kinds BeeZip writes: zip, 7z, tar and cpio, each of those two under one codec too,
/// ar and CAB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveKind {
    Zip,
    SevenZ,
    Tar(Option<CodecId>),
    /// newc, as initramfs images are: plain or under a codec (`.cpio.gz`).
    Cpio(Option<CodecId>),
    Ar,
    Cab,
}

/// The codecs a tar or cpio can be wrapped in when creating (`-f tar.gz` and so on).
pub const TAR_CODECS: [CodecId; 11] = [
    CodecId::Gzip,
    CodecId::Bzip2,
    CodecId::Xz,
    CodecId::Lzma,
    CodecId::Lzip,
    CodecId::Zstd,
    CodecId::Lz4,
    CodecId::Brotli,
    CodecId::Snappy,
    CodecId::Compress,
    CodecId::Lzop,
];

impl ArchiveKind {
    pub fn all() -> impl Iterator<Item = ArchiveKind> {
        [Self::Zip, Self::SevenZ, Self::Tar(None)]
            .into_iter()
            .chain(TAR_CODECS.map(|c| Self::Tar(Some(c))))
            .chain([Self::Cpio(None)])
            .chain(TAR_CODECS.map(|c| Self::Cpio(Some(c))))
            .chain([Self::Ar, Self::Cab])
    }

    /// `zip`, `7z`, `tar`, `tar.gz`, `tar.bz2`, `tar.xz`, `tar.lzma`, `tar.lz`, `tar.zst`,
    /// `tar.lz4`, `tar.br`, `tar.sz`, `tar.Z`, `tar.lzo`, `cpio` and `cpio.gz` and the rest, `ar`,
    /// `cab`.
    pub fn name(self) -> String {
        match self {
            Self::Zip => "zip".into(),
            Self::SevenZ => "7z".into(),
            Self::Tar(None) => "tar".into(),
            Self::Tar(Some(c)) => format!("tar{}", c.extension()),
            Self::Cpio(None) => "cpio".into(),
            Self::Cpio(Some(c)) => format!("cpio{}", c.extension()),
            Self::Ar => "ar".into(),
            Self::Cab => "cab".into(),
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::all().find(|k| k.name() == name)
    }

    /// From an output file name: `.zip`, `.7z`, `.tar`, `.tar.<codec>` or a shorthand such as
    /// `.tgz`, `.cpio` or `.cpio.<codec>`, `.ar`, `.cab`.
    pub fn from_file_name(name: &str) -> Option<Self> {
        let lower = name.to_lowercase();
        for (ext, kind) in [
            (".zip", Self::Zip),
            (".7z", Self::SevenZ),
            (".tar", Self::Tar(None)),
            (".cpio", Self::Cpio(None)),
            (".ar", Self::Ar),
            (".cab", Self::Cab),
        ] {
            if lower.ends_with(ext) {
                return Some(kind);
            }
        }
        if let Some(c) = TAR_CODECS.into_iter().find(|c| {
            c.codec()
                .extensions()
                .iter()
                .any(|ext| lower.ends_with(&format!(".cpio{ext}")))
        }) {
            return Some(Self::Cpio(Some(c)));
        }
        TAR_CODECS.into_iter().find_map(|c| {
            c.codec().extensions().iter().find_map(|ext| {
                let shorthand = crate::codec::TAR_SHORTHANDS.contains(ext);
                let tar_ext = format!(".tar{ext}");
                (lower.ends_with(&tar_ext) || (shorthand && lower.ends_with(ext)))
                    .then_some(Self::Tar(Some(c)))
            })
        })
    }

    pub fn format(self) -> FormatId {
        match self {
            Self::Zip => FormatId::Zip,
            Self::SevenZ => FormatId::SevenZ,
            Self::Tar(_) => FormatId::Tar,
            Self::Cpio(_) => FormatId::Cpio,
            Self::Ar => FormatId::Ar,
            Self::Cab => FormatId::Cab,
        }
    }
}

/// How to write the archive.
#[derive(Debug, Clone)]
pub enum WriteSpec {
    Zip(ZipWriteOptions),
    SevenZ(SevenZWriteOptions),
    /// A tar, under `codec` if there is one, encoded with `opts`.
    Tar {
        codec: Option<CodecId>,
        opts: EncodeOpts,
    },
    /// A newc cpio, likewise.
    Cpio {
        codec: Option<CodecId>,
        opts: EncodeOpts,
    },
    /// A GNU ar.
    Ar,
    Cab(CabWriteOptions),
}

/// A plain output file as a [`FinishWrite`].
fn plain(out: Box<dyn WriteSeek>) -> Box<dyn FinishWrite> {
    finisher(BufWriter::with_capacity(BUF_SIZE, out), |mut w| w.flush())
}

/// A writer for `spec` on `out`.
pub fn create_writer(spec: &WriteSpec, out: Box<dyn WriteSeek>) -> Result<Box<dyn ArchiveWriter>> {
    Ok(match spec {
        WriteSpec::Zip(opts) => Box::new(ZipWriter::new(out, opts.clone())?),
        WriteSpec::SevenZ(opts) => Box::new(SevenZWriter::new(out, opts)?),
        WriteSpec::Tar { codec: None, .. } => Box::new(TarWriter::new(plain(out))),
        WriteSpec::Tar {
            codec: Some(c),
            opts,
        } => {
            let w = Box::new(BufWriter::with_capacity(BUF_SIZE, out));
            Box::new(TarWriter::compressed(c.codec().encoder(w, opts)?))
        }
        WriteSpec::Cpio { codec: None, .. } => Box::new(CpioWriter::new(plain(out))),
        WriteSpec::Cpio {
            codec: Some(c),
            opts,
        } => {
            let w = Box::new(BufWriter::with_capacity(BUF_SIZE, out));
            Box::new(CpioWriter::compressed(c.codec().encoder(w, opts)?))
        }
        WriteSpec::Ar => Box::new(ArWriter::new(plain(out))),
        WriteSpec::Cab(opts) => Box::new(CabWriter::new(out, opts.clone())?),
    })
}

#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// Follow symlinks in the inputs instead of storing them as links (`-L`).
    pub follow_links: bool,
    /// Patterns to leave out, matched like a [`Selection`]'s.
    pub exclude: Vec<String>,
    /// Replace an existing output file.
    pub overwrite: bool,
    /// Split the archive into `<output>.001`, `.002`… of this many bytes (docs/M3.md §3.1).
    pub volume_size: Option<u64>,
}

/// One input file or directory, as it will be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub entry: NewEntry,
    pub source: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateReport {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// The volumes written, first part first; empty when the archive is one file.
    pub volumes: Vec<PathBuf>,
}

/// What `inputs` become: each input under its own name (`src/` → `src/…`), directories walked
/// in name order. `output` itself is never included.
pub fn plan(inputs: &[PathBuf], output: &Path, opts: &CreateOptions) -> Result<Vec<Planned>> {
    let exclude = Selection::new(&[], &[], &opts.exclude)?;
    let output = fs::canonicalize(output).ok();
    let mut planned = Vec::new();
    for input in inputs {
        let base = match input.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => fs::canonicalize(input)
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_default(),
        };
        let walk = walkdir::WalkDir::new(input)
            .follow_links(opts.follow_links)
            .sort_by_file_name()
            .into_iter();
        let walk = walk.filter_entry(|d| {
            let rel = archive_path(&base, input, d.path());
            !excluded(&exclude, &rel, d.file_type().is_dir())
        });
        for item in walk {
            let d = item.map_err(|e| {
                let path = e
                    .path()
                    .map(Path::display)
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                match e.into_io_error() {
                    Some(io) => Error::io(format!("reading {path}"), &io),
                    None => Error::new(ErrorKind::Io, format!("a symlink loop at {path}")),
                }
            })?;
            if output.is_some() && fs::canonicalize(d.path()).ok() == output {
                continue;
            }
            let path = archive_path(&base, input, d.path());
            if path.is_empty() {
                continue;
            }
            let meta = if opts.follow_links {
                fs::metadata(d.path())
            } else {
                fs::symlink_metadata(d.path())
            }
            .map_err(|e| Error::io(format!("reading {}", d.path().display()), &e))?;
            let ft = meta.file_type();
            let kind = if ft.is_symlink() {
                let target = fs::read_link(d.path())
                    .map_err(|e| Error::io(format!("reading {}", d.path().display()), &e))?;
                NewKind::Symlink {
                    target: target.to_string_lossy().replace('\\', "/"),
                }
            } else if ft.is_dir() {
                NewKind::Dir
            } else {
                NewKind::File
            };
            planned.push(Planned {
                entry: NewEntry {
                    path,
                    size: if kind == NewKind::File { meta.len() } else { 0 },
                    kind,
                    modified: meta.modified().ok(),
                    unix_mode: unix_mode(&meta),
                    dos_attrs: dos_attrs(&meta),
                },
                source: d.path().to_path_buf(),
            });
        }
    }
    Ok(planned)
}

fn excluded(exclude: &Selection, path: &str, dir: bool) -> bool {
    if exclude.is_all() || path.is_empty() {
        return false;
    }
    let kind = if dir { EntryKind::Dir } else { EntryKind::File };
    !exclude.matches(&Entry::new(0, path.to_owned(), kind))
}

fn archive_path(base: &str, root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut parts: Vec<String> = Vec::new();
    if !base.is_empty() {
        parts.push(base.to_owned());
    }
    parts.extend(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned()),
    );
    parts.join("/")
}

#[cfg(unix)]
fn unix_mode(meta: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode())
}

#[cfg(not(unix))]
fn unix_mode(_: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(windows)]
fn dos_attrs(meta: &fs::Metadata) -> Option<u32> {
    use std::os::windows::fs::MetadataExt;
    Some(meta.file_attributes() & 0xFFFF)
}

#[cfg(not(windows))]
fn dos_attrs(_: &fs::Metadata) -> Option<u32> {
    None
}

/// Writes `inputs` to `output` as `spec`. The archive is written to
/// `.<name>.<random>.beezip-partial` next to `output` and renamed into place only when complete,
/// so a cancelled or failed create leaves nothing behind.
pub fn create(
    output: &Path,
    inputs: &[PathBuf],
    spec: &WriteSpec,
    opts: &CreateOptions,
    cx: &mut dyn Ctx,
) -> Result<CreateReport> {
    if opts.volume_size.is_none() && !opts.overwrite && fs::symlink_metadata(output).is_ok() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("`{}` already exists", output.display()),
        ));
    }
    let planned = plan(inputs, output, opts)?;
    let total: u64 = planned.iter().map(|p| p.entry.size).sum();
    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = output
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let target = match opts.volume_size {
        Some(size) => Target::Volumes(VolumeWriter::create(output, size, opts.overwrite)?),
        None => Target::Single(Partial::create(&dir, &format!(".{name}"))?),
    };
    let out: Box<dyn WriteSeek> = match &target {
        Target::Single(tmp) => Box::new(tmp.try_clone()?),
        Target::Volumes(v) => Box::new(v.clone()),
    };

    let spec = with_size_hint(spec, total);
    let mut writer = create_writer(&spec, out)?;
    let expected: Vec<NewEntry> = planned
        .iter()
        .map(|p| p.entry.clone())
        .filter(|e| writer.holds(&e.kind))
        .collect();
    writer.expect(&expected)?;
    let counter = Counter::new();
    let mut meter = Meter::new(counter.clone(), Some(total));
    meter.entries_total = Some(planned.len() as u64);
    let mut report = CreateReport::default();
    let added = add_planned(&mut *writer, &planned, &counter, &mut meter, 0, cx)?;
    report.files = added.files;
    report.dirs = added.dirs;
    report.links = added.links;
    writer.finish()?;
    meter.entries_done = planned.len() as u64;
    MeteredCtx::new(cx, &meter).report();

    report.bytes_in = counter.get();
    match target {
        Target::Single(tmp) => {
            tmp.persist(output)?;
            report.bytes_out = fs::metadata(output).map(|m| m.len()).unwrap_or(0);
        }
        Target::Volumes(v) => {
            report.volumes = v.finish()?;
            report.bytes_out = report
                .volumes
                .iter()
                .filter_map(|p| fs::metadata(p).ok())
                .map(|m| m.len())
                .sum();
        }
    }
    Ok(report)
}

/// How many of each kind [`add_planned`] wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Added {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
}

/// Adds `planned` to `writer`, reading each file from disk through `counter`. A solid writer
/// gets non-empty files in groups of up to its block limit (7z, docs/M3.md §3.3); everything
/// else goes one entry at a time, in plan order. `first` is the progress count before them.
pub fn add_planned(
    writer: &mut dyn ArchiveWriter,
    planned: &[Planned],
    counter: &Counter,
    meter: &mut Meter,
    first: u64,
    cx: &mut dyn Ctx,
) -> Result<Added> {
    let mut added = Added::default();
    let open = |p: &Planned| -> Result<Box<dyn Read>> {
        let file = File::open(&p.source)
            .map_err(|e| Error::io(format!("reading {}", p.source.display()), &e))?;
        Ok(Box::new(CountingReader::new(file, counter.clone())))
    };
    let limit = writer.solid_block_limit();
    let mut group: Vec<usize> = Vec::new();
    let mut group_bytes = 0u64;
    let flush = |group: &mut Vec<usize>,
                 writer: &mut dyn ArchiveWriter,
                 meter: &mut Meter,
                 cx: &mut dyn Ctx|
     -> Result<()> {
        let Some(&at) = group.first() else {
            return Ok(());
        };
        meter.entries_done = first + at as u64;
        meter.current = Some(planned[at].entry.path.clone());
        let entries: Vec<NewEntry> = group.iter().map(|&i| planned[i].entry.clone()).collect();
        let mut opener = |k: usize| open(&planned[group[k]]);
        let mut mcx = MeteredCtx::new(cx, meter);
        writer.add_solid(&entries, &mut opener, &mut mcx)?;
        group.clear();
        Ok(())
    };
    for (i, p) in planned.iter().enumerate() {
        cx.check()?;
        if !writer.holds(&p.entry.kind) {
            // ar and CAB: folders come from their files' paths, and links are left out.
            if let NewKind::Symlink { .. } = p.entry.kind {
                cx.warn(format!(
                    "left out `{}`: the archive can't hold symbolic links",
                    p.entry.path
                ));
            }
            continue;
        }
        if let Some(limit) = limit
            && p.entry.kind == NewKind::File
            && p.entry.size > 0
        {
            if !group.is_empty() && group_bytes.saturating_add(p.entry.size) > limit {
                flush(&mut group, writer, meter, cx)?;
                group_bytes = 0;
            }
            group.push(i);
            group_bytes += p.entry.size;
            added.files += 1;
            continue;
        }
        meter.entries_done = first + i as u64;
        meter.current = Some(p.entry.path.clone());
        let mut mcx = MeteredCtx::new(cx, meter);
        match p.entry.kind {
            NewKind::File => {
                let mut r = open(p)?;
                writer.add(&p.entry, &mut r, &mut mcx)?;
                added.files += 1;
            }
            NewKind::Dir => {
                writer.add(&p.entry, &mut io::empty(), &mut mcx)?;
                added.dirs += 1;
            }
            NewKind::Symlink { .. } => {
                writer.add(&p.entry, &mut io::empty(), &mut mcx)?;
                added.links += 1;
            }
        }
    }
    flush(&mut group, writer, meter, cx)?;
    Ok(added)
}

/// Where `create` writes: one partial file, or a volume set of them.
enum Target {
    Single(Partial),
    Volumes(VolumeWriter),
}

fn with_size_hint(spec: &WriteSpec, total: u64) -> WriteSpec {
    match spec {
        WriteSpec::Tar { codec, opts } if opts.size_hint.is_none() => WriteSpec::Tar {
            codec: *codec,
            opts: EncodeOpts {
                size_hint: Some(total),
                size_exact: false,
                ..opts.clone()
            },
        },
        WriteSpec::Cpio { codec, opts } if opts.size_hint.is_none() => WriteSpec::Cpio {
            codec: *codec,
            opts: EncodeOpts {
                size_hint: Some(total),
                size_exact: false,
                ..opts.clone()
            },
        },
        other => other.clone(),
    }
}

/// Extracts the `sel`ected entries of `archive` into `dest`. `fs.input` and `fs.budget` are
/// set from the open archive. Files completed before an error stay.
pub fn extract(
    archive: &Path,
    dest: &Path,
    sel: &Selection,
    open_opts: &OpenOptions,
    fs: FsOptions,
    cx: &mut dyn Ctx,
) -> Result<ExtractReport> {
    let mut opened = open(archive, open_opts, cx)?;
    let fs = FsOptions {
        input: opened.input.clone(),
        budget: open_opts.budget.clone(),
        ..fs
    };
    let mut sink = FsSink::new(dest, fs)?;
    opened.reader.extract(sel, &mut sink, cx)?;
    sink.finish(cx)
}

/// Reads every selected entry to the end, recording the ones that fail. A stream that breaks
/// part-way (a damaged `tar.gz`) is recorded too; only cancellation, limits, passwords and I/O
/// errors stop the test.
pub fn test(
    archive: &Path,
    sel: &Selection,
    open_opts: &OpenOptions,
    cx: &mut dyn Ctx,
) -> Result<TestReport> {
    let mut opened = open(archive, open_opts, cx)?;
    let mut sink = TestSink::default();
    match opened.reader.extract(sel, &mut sink, cx) {
        Ok(()) => {}
        Err(e) if e.kind == ErrorKind::Corrupt => sink.report.record("", &e),
        Err(e) => return Err(e),
    }
    Ok(sink.report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_from_names() {
        assert_eq!(
            ArchiveKind::from_name("tar.zst"),
            Some(ArchiveKind::Tar(Some(CodecId::Zstd)))
        );
        assert_eq!(
            ArchiveKind::from_name("tar.sz"),
            Some(ArchiveKind::Tar(Some(CodecId::Snappy)))
        );
        assert_eq!(
            ArchiveKind::from_name("tar.lz"),
            Some(ArchiveKind::Tar(Some(CodecId::Lzip)))
        );
        assert_eq!(ArchiveKind::from_name("tar.zz"), None);
        assert_eq!(
            ArchiveKind::from_name("tar.Z"),
            Some(ArchiveKind::Tar(Some(CodecId::Compress)))
        );
        assert_eq!(
            ArchiveKind::from_name("cpio.lzo"),
            Some(ArchiveKind::Cpio(Some(CodecId::Lzop)))
        );
        assert_eq!(ArchiveKind::all().count(), 28);
        for k in ArchiveKind::all() {
            assert_eq!(ArchiveKind::from_name(&k.name()), Some(k));
        }
    }

    #[test]
    fn kinds_from_file_names() {
        let f = ArchiveKind::from_file_name;
        assert_eq!(f("a.zip"), Some(ArchiveKind::Zip));
        assert_eq!(f("a.TAR"), Some(ArchiveKind::Tar(None)));
        assert_eq!(f("a.tar.zst"), Some(ArchiveKind::Tar(Some(CodecId::Zstd))));
        assert_eq!(f("a.tgz"), Some(ArchiveKind::Tar(Some(CodecId::Gzip))));
        assert_eq!(f("a.tbz2"), Some(ArchiveKind::Tar(Some(CodecId::Bzip2))));
        assert_eq!(f("a.tar.br"), Some(ArchiveKind::Tar(Some(CodecId::Brotli))));
        assert_eq!(f("a.gz"), None);
        assert_eq!(f("a.7z"), Some(ArchiveKind::SevenZ));
        assert_eq!(
            f("a.tar.Z"),
            Some(ArchiveKind::Tar(Some(CodecId::Compress)))
        );
        assert_eq!(f("a.taz"), Some(ArchiveKind::Tar(Some(CodecId::Compress))));
        assert_eq!(f("a.tzo"), Some(ArchiveKind::Tar(Some(CodecId::Lzop))));
        assert_eq!(f("initrd.cpio"), Some(ArchiveKind::Cpio(None)));
        assert_eq!(
            f("initrd.cpio.gz"),
            Some(ArchiveKind::Cpio(Some(CodecId::Gzip)))
        );
        assert_eq!(
            f("a.cpio.Z"),
            Some(ArchiveKind::Cpio(Some(CodecId::Compress)))
        );
        assert_eq!(f("a.ar"), Some(ArchiveKind::Ar));
        assert_eq!(f("a.cab"), Some(ArchiveKind::Cab));
        assert_eq!(f("libx.a"), None);
        assert_eq!(f("a.deb"), None);
    }
}
