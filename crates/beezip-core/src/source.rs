//! Opening an archive: file → codec decoders → format (docs/M1.md §2, `source.rs`).

use std::{
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    CodecId, Ctx, Error, Limits, Result,
    detect::{Detection, detect_path},
    format::{ArchiveReader, FormatId, stream::StreamReader, tar::TarReader, zip::ZipReader},
    io::{BUF_SIZE, Counter, CountingReader},
    limits::{Budget, Guarded, RatioGuard},
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

/// A file and the codecs to decode it with. Readers reopen it to make another pass.
#[derive(Debug, Clone)]
pub struct Source {
    pub path: PathBuf,
    pub codecs: Vec<CodecId>,
    pub limits: Limits,
    pub budget: Budget,
    /// Bytes of the file read so far in the current pass: progress and the ratio limit.
    pub counter: Counter,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

impl Source {
    pub fn new(path: &Path, codecs: Vec<CodecId>, opts: &OpenOptions) -> Result<Self> {
        let meta = std::fs::metadata(path)
            .map_err(|e| Error::io(format!("opening {}", path.display()), &e))?;
        Ok(Self {
            path: path.to_path_buf(),
            codecs,
            limits: opts.limits.clone(),
            budget: opts.budget.clone(),
            counter: Counter::new(),
            size: meta.len(),
            modified: meta.modified().ok(),
        })
    }

    /// The raw file, counted from zero.
    pub fn open_file(&self) -> Result<CountingReader<File>> {
        let file = File::open(&self.path)
            .map_err(|e| Error::io(format!("opening {}", self.path.display()), &e))?;
        self.counter.set(0);
        Ok(CountingReader::new(file, self.counter.clone()))
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

    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// An open archive.
pub struct Opened {
    pub detection: Detection,
    pub reader: Box<dyn ArchiveReader>,
    /// Counts the archive file's bytes read in the current pass; give it to `FsOptions::input`.
    pub input: Counter,
    pub size: u64,
}

/// Detects `path` and opens it.
pub fn open(path: &Path, opts: &OpenOptions, cx: &mut dyn Ctx) -> Result<Opened> {
    let detection = detect_path(path, &opts.limits)?;
    let (format, codecs) = detection.require_archive()?;
    let source = Source::new(path, codecs, opts)?;
    let input = source.counter.clone();
    let size = source.size;
    let reader: Box<dyn ArchiveReader> = match format {
        FormatId::Zip => Box::new(ZipReader::open(source, detection.sfx, cx)?),
        FormatId::Tar => Box::new(TarReader::new(source)),
        FormatId::Stream => Box::new(StreamReader::open(source)?),
    };
    Ok(Opened {
        detection,
        reader,
        input,
        size,
    })
}
