//! Opening an archive: input → codec decoders → format (docs/M1.md §2, docs/M3.md §3.2).
//!
//! The input is an [`Input`]: a file, a numbered volume set joined by [`VolumeReader`], or
//! either seen from an offset (the 7z inside an SFX). Every format reads through it, so zip,
//! tar and the stream view read volume sets with no code of their own.

use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    CodecId, Ctx, Error, ErrorKind, Limits, Result,
    backend::{External, SevenZipOptions, SevenZipReader},
    detect::{Detection, detect_path},
    format::{
        ArchiveReader, FormatId, ace::AceReader, ar::ArReader, arc::ArcReader, arj::ArjReader,
        cab::CabReader, cpio::CpioReader, deb::DebReader, dmg::DmgReader, iso::IsoReader,
        lzh::LzhReader, msi, pkg::PkgReader, rar::RarReader, rpm::RpmReader, sevenz::SevenZReader,
        squashfs::SquashfsReader, stream::StreamReader, tar::TarReader, volume::DiskReader, wim,
        xar::XarReader, zip::ZipReader, zoo::ZooReader,
    },
    io::{BUF_SIZE, Counter, CountingReader},
    limits::{Budget, Guarded, RatioGuard},
    names::NameDecoding,
    volume::{VolumeReader, numbered_name, truncated_hint},
};

/// How to open an archive.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    pub limits: Limits,
    /// The job's `max_total_bytes` budget; share it with the `FsSink`.
    pub budget: Budget,
    /// How names stored as bytes are read (docs/M5.md §6).
    pub names: NameDecoding,
    /// Workers for reading: extracting a zip to disk and decoding xz (docs/M6.md §6.3, §6.4).
    /// `0` is one per logical core; `1`, the default here, reads on the job's thread only.
    pub threads: u32,
    /// A zip with fewer files than this to extract is extracted on the job's thread: workers
    /// cost more than they save on a few files. 64; tests lower it.
    pub min_parallel_files: usize,
    /// The 7-Zip that reads the formats BeeZip leaves to it (docs/M6.md §3.1).
    pub seven_zip: SevenZipOptions,
    /// Read the disks, file systems and installers with BeeZip's own readers (docs/M7.md), the
    /// default. `false` reads them through 7-Zip, as before M7: the tests compare the two.
    pub native: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            budget: Budget::default(),
            names: NameDecoding::default(),
            threads: 1,
            min_parallel_files: 64,
            seven_zip: SevenZipOptions::default(),
            native: true,
        }
    }
}

impl OpenOptions {
    pub fn new(limits: Limits) -> Self {
        let budget = Budget::new(&limits);
        Self {
            limits,
            budget,
            ..Self::default()
        }
    }

    /// The same, reading names with `names`.
    pub fn with_names(self, names: NameDecoding) -> Self {
        Self { names, ..self }
    }

    /// The same, with `threads` workers for reading.
    pub fn with_threads(self, threads: u32) -> Self {
        Self { threads, ..self }
    }

    /// The same, running the 7-Zip `seven_zip` says.
    pub fn with_seven_zip(self, seven_zip: SevenZipOptions) -> Self {
        Self { seven_zip, ..self }
    }
}

#[derive(Debug)]
enum InputKind {
    File(File),
    Volumes(VolumeReader),
}

/// One `Read + Seek` input. Positions are relative to `start`, so an archive inside an SFX
/// reads as if it began the file.
#[derive(Debug)]
pub struct Input {
    inner: InputKind,
    start: u64,
    /// Bytes from `start` to the end.
    len: u64,
}

impl Input {
    /// A plain file, from its start.
    pub fn file(file: File) -> Result<Self> {
        let len = file
            .metadata()
            .map_err(|e| Error::io("reading the file", &e))?
            .len();
        Ok(Self {
            inner: InputKind::File(file),
            start: 0,
            len,
        })
    }

    /// From `start` on: the archive inside a self-extracting executable.
    pub fn from_offset(mut self, start: u64) -> Result<Self> {
        let start = self.start + start.min(self.len);
        self.len = self.len.saturating_sub(start - self.start);
        self.start = start;
        self.seek(SeekFrom::Start(0))
            .map_err(|e| Error::io("seeking in the file", &e))?;
        Ok(self)
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            InputKind::File(f) => f.read(buf),
            InputKind::Volumes(v) => v.read(buf),
        }
    }
}

impl Seek for Input {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let abs = match pos {
            SeekFrom::Start(n) => SeekFrom::Start(self.start.saturating_add(n)),
            SeekFrom::End(d) => SeekFrom::End(d),
            SeekFrom::Current(d) => SeekFrom::Current(d),
        };
        let at = match &mut self.inner {
            InputKind::File(f) => f.seek(abs)?,
            InputKind::Volumes(v) => v.seek(abs)?,
        };
        if at < self.start {
            let back = SeekFrom::Start(self.start);
            match &mut self.inner {
                InputKind::File(f) => f.seek(back)?,
                InputKind::Volumes(v) => v.seek(back)?,
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the archive",
            ));
        }
        Ok(at - self.start)
    }
}

/// An input and the codecs to decode it with. Readers reopen it to make another pass.
#[derive(Debug, Clone)]
pub struct Source {
    /// The file, or a set's first part.
    pub path: PathBuf,
    /// Every part of a volume set, first part first; just `path` for a plain file.
    pub volumes: Vec<PathBuf>,
    /// The volumes are a numbered set, read joined. RAR's own volumes aren't joined: UnRAR
    /// opens them one by one.
    pub joined: bool,
    /// Where the archive starts in the input (inside an SFX).
    pub offset: u64,
    pub codecs: Vec<CodecId>,
    pub limits: Limits,
    pub budget: Budget,
    /// How names stored as bytes are read.
    pub names: NameDecoding,
    /// Workers for reading, as [`OpenOptions::threads`] gives them.
    pub threads: u32,
    pub min_parallel_files: usize,
    /// Bytes of the input read so far in the current pass: progress and the ratio limit.
    pub counter: Counter,
    /// The input's size: the whole set's for a volume set.
    pub size: u64,
    pub modified: Option<SystemTime>,
    /// The joined set's reader, kept so each pass reuses the sizes taken when it opened.
    set: Option<std::sync::Arc<VolumeReader>>,
}

impl Source {
    /// A plain file.
    pub fn new(path: &Path, codecs: Vec<CodecId>, opts: &OpenOptions) -> Result<Self> {
        Self::with_volumes(&[path.to_path_buf()], false, codecs, opts)
    }

    /// `volumes`, joined when `joined` (a numbered set).
    pub fn with_volumes(
        volumes: &[PathBuf],
        joined: bool,
        codecs: Vec<CodecId>,
        opts: &OpenOptions,
    ) -> Result<Self> {
        let path = volumes
            .first()
            .cloned()
            .ok_or_else(|| Error::invalid_args("no input"))?;
        let meta = std::fs::metadata(&path)
            .map_err(|e| Error::io(format!("opening {}", path.display()), &e))?;
        let (size, set) = if joined {
            let set = VolumeReader::open(volumes)?;
            (set.len(), Some(std::sync::Arc::new(set)))
        } else {
            (meta.len(), None)
        };
        Ok(Self {
            path,
            volumes: volumes.to_vec(),
            joined,
            offset: 0,
            codecs,
            limits: opts.limits.clone(),
            budget: opts.budget.clone(),
            names: opts.names,
            threads: opts.threads,
            min_parallel_files: opts.min_parallel_files,
            counter: Counter::new(),
            size,
            modified: meta.modified().ok(),
            set,
        })
    }

    /// The input from the archive's start, not counted.
    pub fn input(&self) -> Result<Input> {
        let input = match &self.set {
            Some(set) => {
                let r = set.reopen();
                let len = r.len();
                Input {
                    inner: InputKind::Volumes(r),
                    start: 0,
                    len,
                }
            }
            None => {
                let file = File::open(&self.path)
                    .map_err(|e| Error::io(format!("opening {}", self.path.display()), &e))?;
                Input::file(file)?
            }
        };
        if self.offset > 0 {
            input.from_offset(self.offset)
        } else {
            Ok(input)
        }
    }

    /// The raw input, counted from zero.
    pub fn open_file(&self) -> Result<CountingReader<Input>> {
        let input = self.input()?;
        self.counter.set(0);
        Ok(CountingReader::new(input, self.counter.clone()))
    }

    /// The decoded stream, from the start. An outermost xz layer is decoded on several
    /// threads when `threads` allows and the file has the blocks for it (docs/M6.md §6.4).
    pub fn open_stream(&self) -> Result<Box<dyn Read + Send>> {
        let mt = match self.codecs.split_first() {
            Some((CodecId::Xz, rest)) if self.threads != 1 => crate::codec::xz_decoder_mt(
                self.input()?,
                &self.limits,
                self.threads,
                &self.counter,
            )
            .map(|r| (r, rest)),
            _ => None,
        };
        let (mut r, rest) = match mt {
            Some(mt) => mt,
            None => {
                let file = BufReader::with_capacity(BUF_SIZE, self.open_file()?);
                (Box::new(file) as Box<dyn Read + Send>, &self.codecs[..])
            }
        };
        for c in rest {
            r = c.decoder(r, &self.limits)?;
        }
        Ok(r)
    }

    /// Wraps an entry's data in the ratio and total-size checks.
    pub fn guard<R: Read>(&self, data: R) -> Guarded<R> {
        Guarded::new(
            data,
            RatioGuard::new(&self.counter, &self.limits),
            self.budget.clone(),
        )
    }

    /// The input's name: the joined name for a numbered set (`a.7z` for `a.7z.001`).
    pub fn file_name(&self) -> String {
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if self.joined
            && let Some((base, _, _)) = numbered_name(&name)
        {
            return base.to_owned();
        }
        name
    }
}

/// An open archive.
pub struct Opened {
    pub detection: Detection,
    pub reader: Box<dyn ArchiveReader>,
    /// Counts the input's bytes read in the current pass; give it to `FsOptions::input`.
    pub input: Counter,
    pub size: u64,
}

/// A disk, file system, installer or WIM image through BeeZip's own reader (docs/M7.md §2,
/// docs/M8.md §2). One that uses
/// something the reader doesn't support goes to 7-Zip, with a note in Info; one that's damaged
/// doesn't. Without 7-Zip, the error is 7-Zip's `BackendUnavailable`, which offers to install
/// it, saying what BeeZip couldn't read.
fn native(
    source: Source,
    kind: External,
    opts: &OpenOptions,
    cx: &mut dyn Ctx,
) -> Result<Box<dyn ArchiveReader>> {
    let opened = match kind {
        External::Msi => msi::open(source.clone(), cx),
        External::Wim => wim::open(source.clone(), cx),
        _ => DiskReader::open(source.clone(), kind, cx).map(|r| Box::new(r) as Box<_>),
    };
    let Err(e) = opened else {
        return opened;
    };
    if e.kind != ErrorKind::UnsupportedOperation {
        return Err(e);
    }
    match SevenZipReader::open(source, kind, &opts.seven_zip, cx) {
        Ok(r) => Ok(Box::new(r.with_fallback(format!(
            "BeeZip can't read this one itself ({}), so 7-Zip reads it.",
            e.message
        )))),
        Err(mut missing) if missing.kind == ErrorKind::BackendUnavailable => {
            missing.message = format!(
                "BeeZip can't read this one itself ({}). {}",
                e.message, missing.message
            );
            Err(missing)
        }
        Err(other) => Err(other),
    }
}

/// Detects `path` and opens it. Any part of a volume set opens the whole set.
pub fn open(path: &Path, opts: &OpenOptions, cx: &mut dyn Ctx) -> Result<Opened> {
    let detection = detect_path(path, &opts.limits)?;
    let (format, codecs) = detection.require_archive()?;
    let mut source = Source::with_volumes(&detection.volumes, detection.joined, codecs, opts)?;
    if matches!(format, FormatId::SevenZ | FormatId::Cab | FormatId::Lzh) {
        // The archive inside an SFX, seen from its start.
        source.offset = detection.offset;
    }
    let input = source.counter.clone();
    let size = source.size;
    let parts = source.volumes.len();
    let joined = source.joined;
    let opened = (|| -> Result<Box<dyn ArchiveReader>> {
        Ok(match format {
            FormatId::Zip => Box::new(ZipReader::open(source, detection.sfx, cx)?),
            FormatId::Tar => Box::new(TarReader::new(source)),
            FormatId::Stream => Box::new(StreamReader::open(source)?),
            FormatId::SevenZ => Box::new(SevenZReader::open(source, detection.sfx, cx)?),
            FormatId::Rar => RarReader::open(source, detection.sfx, cx)?,
            FormatId::Cpio => Box::new(CpioReader::new(source)),
            FormatId::Ar => Box::new(ArReader::open(source, cx)?),
            FormatId::Deb => Box::new(DebReader::open(source, cx)?),
            FormatId::Rpm => Box::new(RpmReader::open(source, cx)?),
            FormatId::Cab => Box::new(CabReader::open(source, cx)?),
            FormatId::Lzh => Box::new(LzhReader::open(source, cx)?),
            FormatId::Iso => Box::new(IsoReader::open(source, cx)?),
            FormatId::Squashfs => Box::new(SquashfsReader::open(source, cx)?),
            FormatId::Dmg => Box::new(DmgReader::open(source, cx)?),
            FormatId::Arj => Box::new(ArjReader::open(source, cx)?),
            FormatId::Ace => Box::new(AceReader::open(source, cx)?),
            FormatId::Zoo => Box::new(ZooReader::open(source, cx)?),
            FormatId::Arc => Box::new(ArcReader::open(source, cx)?),
            FormatId::Pkg => Box::new(PkgReader::open(source, cx)?),
            FormatId::Xar => Box::new(XarReader::open(source, cx)?),
            FormatId::External(kind) if kind.native() && opts.native => {
                native(source, kind, opts, cx)?
            }
            FormatId::External(kind) => {
                Box::new(SevenZipReader::open(source, kind, &opts.seven_zip, cx)?)
            }
        })
    })();
    let reader = opened.map_err(|e| if joined { truncated_hint(e, parts) } else { e })?;
    Ok(Opened {
        detection,
        reader,
        input,
        size,
    })
}
