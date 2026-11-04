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
    CodecId, Ctx, Error, Limits, Result,
    detect::{Detection, detect_path},
    format::{
        ArchiveReader, FormatId, sevenz::SevenZReader, stream::StreamReader, tar::TarReader,
        zip::ZipReader,
    },
    io::{BUF_SIZE, Counter, CountingReader},
    limits::{Budget, Guarded, RatioGuard},
    volume::{VolumeReader, numbered_name, truncated_hint},
};

/// How to open an archive.
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub limits: Limits,
    /// The job's `max_total_bytes` budget; share it with the `FsSink`.
    pub budget: Budget,
}

impl OpenOptions {
    pub fn new(limits: Limits) -> Self {
        let budget = Budget::new(&limits);
        Self { limits, budget }
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

    /// The decoded stream, from the start.
    pub fn open_stream(&self) -> Result<Box<dyn Read>> {
        let mut r: Box<dyn Read> = Box::new(BufReader::with_capacity(BUF_SIZE, self.open_file()?));
        for c in &self.codecs {
            r = c.codec().decoder(r, &self.limits)?;
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

/// Detects `path` and opens it. Any part of a volume set opens the whole set.
pub fn open(path: &Path, opts: &OpenOptions, cx: &mut dyn Ctx) -> Result<Opened> {
    let detection = detect_path(path, &opts.limits)?;
    let (format, codecs) = detection.require_archive()?;
    let mut source = Source::with_volumes(&detection.volumes, detection.joined, codecs, opts)?;
    if format == FormatId::SevenZ {
        // The 7z inside an SFX, seen from its start.
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
