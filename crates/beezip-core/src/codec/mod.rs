//! Single-stream codecs: gzip, zlib, raw deflate, bzip2, xz, lzma, lzip, zstd, lz4, brotli
//! and snappy (docs/M1.md §3.2), and Unix `.Z` and lzop (docs/M5.md §5.7, §5.8). gzip, zlib
//! and raw deflate compress on several threads with `deflate_par` (docs/M6.md §6.1).

mod brotli;
mod bzip2;
mod compress;
mod deflate;
pub(crate) mod deflate_par;
mod gzip;
mod lz4;
mod lzip;
mod lzma;
mod lzop;
mod snappy;
mod xz;
mod xz_mt;
mod zlib;
mod zstd;

use std::{
    fmt,
    io::{self, Read, Write},
    num::NonZeroU64,
    time::SystemTime,
};

use crate::{
    Error, Limits, Result,
    detect::{Confidence, Probe},
    io::LatchReader,
};

/// Every codec BeeZip knows, in the order `formats.list` shows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CodecId {
    Gzip,
    Zlib,
    Deflate,
    Bzip2,
    Xz,
    Lzma,
    Lzip,
    Zstd,
    Lz4,
    Brotli,
    Snappy,
    /// Unix `compress` (`.Z`).
    Compress,
    Lzop,
}

impl CodecId {
    pub const ALL: [CodecId; 13] = [
        Self::Gzip,
        Self::Zlib,
        Self::Deflate,
        Self::Bzip2,
        Self::Xz,
        Self::Lzma,
        Self::Lzip,
        Self::Zstd,
        Self::Lz4,
        Self::Brotli,
        Self::Snappy,
        Self::Compress,
        Self::Lzop,
    ];

    /// The stable lowercase id, as the CLI and the wire use it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Deflate => "deflate",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Lzma => "lzma",
            Self::Lzip => "lzip",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
            Self::Brotli => "brotli",
            Self::Snappy => "snappy",
            Self::Compress => "compress",
            Self::Lzop => "lzop",
        }
    }

    /// A name for people.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Deflate => "raw deflate",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Lzma => "LZMA (lzma-alone)",
            Self::Lzip => "lzip",
            Self::Zstd => "Zstandard",
            Self::Lz4 => "LZ4 frame",
            Self::Brotli => "Brotli",
            Self::Snappy => "Snappy (framed)",
            Self::Compress => "Unix compress (.Z)",
            Self::Lzop => "lzop",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The extension a file of this codec is given: the first of its extensions, except `.Z`, which
    /// is upper case by convention (extensions are matched in lower case).
    pub fn extension(self) -> &'static str {
        match self {
            Self::Compress => ".Z",
            _ => self.codec().extensions().first().copied().unwrap_or(""),
        }
    }

    /// The codec's decoder over `r`, never read again once it fails ([`LatchReader`]).
    pub fn decoder<'a>(
        self,
        r: Box<dyn Read + Send + 'a>,
        limits: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        let d = self.codec().decoder(r, limits)?;
        Ok(Box::new(LatchReader::new(d)))
    }

    pub fn codec(self) -> &'static dyn Codec {
        match self {
            Self::Gzip => &gzip::Gzip,
            Self::Zlib => &zlib::Zlib,
            Self::Deflate => &deflate::Deflate,
            Self::Bzip2 => &bzip2::Bzip2,
            Self::Xz => &xz::Xz,
            Self::Lzma => &lzma::Lzma,
            Self::Lzip => &lzip::Lzip,
            Self::Zstd => &zstd::Zstd,
            Self::Lz4 => &lz4::Lz4,
            Self::Brotli => &brotli::Brotli,
            Self::Snappy => &snappy::Snappy,
            Self::Compress => &compress::Compress,
            Self::Lzop => &lzop::Lzop,
        }
    }
}

impl fmt::Display for CodecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// gzip header fields the stream format reads.
pub use gzip::{header_name as gzip_header_name, trailer_size as gzip_trailer_size};
/// The file name in an lzop header, which the stream view names its entry after.
pub use lzop::header_name as lzop_header_name;
/// xz on several threads, for a file BeeZip can seek (docs/M6.md §6.4).
pub use xz_mt::decoder as xz_decoder_mt;

/// Every codec, in [`CodecId::ALL`] order.
pub fn codecs() -> impl Iterator<Item = &'static dyn Codec> {
    CodecId::ALL.into_iter().map(CodecId::codec)
}

/// A codec's level range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Levels {
    pub min: i32,
    pub max: i32,
    pub default: i32,
}

/// How to encode.
#[derive(Debug, Clone, Default)]
pub struct EncodeOpts {
    /// `None` is the codec's default. Out of range, or given to a codec without levels, is
    /// `InvalidArgs`.
    pub level: Option<i32>,
    /// Worker threads for the codecs that have them; `0` means one per core, `1` is
    /// single-threaded.
    pub threads: u32,
    /// The input size, if known. LZMA-family dictionaries shrink to fit small inputs.
    pub size_hint: Option<u64>,
    /// `size_hint` is exact: zstd pledges it, which lets it pick small tables.
    pub size_exact: bool,
    /// Uncompressed bytes per block for the multithreaded xz and lzip writers. The default is
    /// three dictionaries, at least 1 MiB.
    pub block_size: Option<u64>,
    /// gzip's FNAME and MTIME header fields.
    pub gzip_name: Option<String>,
    pub gzip_mtime: Option<SystemTime>,
}

impl EncodeOpts {
    pub fn with_level(level: i32) -> Self {
        Self {
            level: Some(level),
            ..Self::default()
        }
    }

    /// The level to use, checked against `levels`.
    pub fn resolve_level(&self, id: CodecId, levels: Option<Levels>) -> Result<i32> {
        match (levels, self.level) {
            (None, None) => Ok(0),
            (None, Some(_)) => Err(Error::invalid_args(format!(
                "{} has no compression levels",
                id.name()
            ))),
            (Some(l), None) => Ok(l.default),
            (Some(l), Some(level)) if (l.min..=l.max).contains(&level) => Ok(level),
            (Some(l), Some(level)) => Err(Error::invalid_args(format!(
                "level {level} is out of range for {} ({}–{})",
                id.name(),
                l.min,
                l.max
            ))),
        }
    }

    /// The thread count to use: `0` becomes the number of cores.
    pub fn resolve_threads(&self) -> u32 {
        resolve_threads(self.threads)
    }
}

/// A thread count as the settings give it: `0` becomes the number of logical cores.
pub fn resolve_threads(threads: u32) -> u32 {
    match threads {
        0 => std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(1))
            .unwrap_or(1),
        n => n,
    }
}

/// An encoder that must be finished: `finish` writes the trailer and reports the errors a drop
/// would hide. Output from an encoder that was dropped instead is incomplete, which is why
/// writers only commit files after `finish` succeeds.
pub trait FinishWrite: Write {
    fn finish(self: Box<Self>) -> io::Result<()>;
}

/// A single-stream codec.
pub trait Codec: Sync {
    fn id(&self) -> CodecId;

    /// Lowercase, with the dot: `.gz`, plus tar shorthands such as `.tgz`.
    fn extensions(&self) -> &'static [&'static str];

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence>;

    fn levels(&self) -> Option<Levels>;

    fn threads(&self) -> bool {
        false
    }

    fn decoder<'a>(
        &self,
        r: Box<dyn Read + Send + 'a>,
        limits: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>>;

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>>;
}

/// Tar shorthand extensions, which stand for `.tar` plus a codec extension.
pub const TAR_SHORTHANDS: [&str; 8] = [
    ".tgz", ".tbz", ".tbz2", ".txz", ".tzst", ".tlz", ".taz", ".tzo",
];

/// The file name without `codec`'s extension: `a.tar.zst` → `a.tar`, `a.tgz` → `a.tar`.
/// `None` if the name doesn't end in one of the codec's extensions.
pub fn strip_extension(name: &str, codec: CodecId) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let ext = codec
        .codec()
        .extensions()
        .iter()
        .filter(|ext| lower.ends_with(**ext) && lower.len() > ext.len())
        .max_by_key(|ext| ext.len())?;
    let stem = &name[..name.len() - ext.len()];
    if TAR_SHORTHANDS.contains(ext) {
        Some(format!("{stem}.tar"))
    } else {
        Some(stem.to_owned())
    }
}

/// Adapts an encoder with its own `finish` to [`FinishWrite`].
struct Finisher<W, F> {
    w: W,
    finish: F,
}

impl<W: Write, F> Write for Finisher<W, F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl<W: Write, F: FnOnce(W) -> io::Result<()>> FinishWrite for Finisher<W, F> {
    fn finish(self: Box<Self>) -> io::Result<()> {
        let this = *self;
        (this.finish)(this.w)
    }
}

pub(crate) fn finisher<'a, W, F>(w: W, finish: F) -> Box<dyn FinishWrite + 'a>
where
    W: Write + 'a,
    F: FnOnce(W) -> io::Result<()> + 'a,
{
    Box::new(Finisher { w, finish })
}

/// A dictionary size for an LZMA-family encoder: the preset's, shrunk to fit a known small
/// input (at least 4 KiB). The decoder needs no more memory than the dictionary.
pub(crate) fn fit_dict(preset_dict: u32, size_hint: Option<u64>) -> u32 {
    match size_hint {
        Some(n) if n < u64::from(preset_dict) => {
            let fit = n.max(4096).next_power_of_two();
            u32::try_from(fit).unwrap_or(preset_dict).min(preset_dict)
        }
        _ => preset_dict,
    }
}

/// The block size for a multithreaded LZMA-family writer.
pub(crate) fn mt_block_size(opts: &EncodeOpts, dict: u32) -> Option<NonZeroU64> {
    let default = (u64::from(dict) * 3).max(1024 * 1024);
    NonZeroU64::new(opts.block_size.unwrap_or(default).max(u64::from(dict)))
}

/// Maps an lzma-rust2 or other decoder construction error.
pub(crate) fn open_error(codec: CodecId, e: &io::Error) -> Error {
    let err = crate::io::read_error(e);
    err.context(format!("{} stream", codec.name()))
}

pub(crate) fn has_ext(probe: &Probe<'_>, exts: &[&str]) -> bool {
    probe
        .name
        .is_some_and(|n| exts.iter().any(|e| n.ends_with(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for id in CodecId::ALL {
            assert_eq!(CodecId::from_name(id.name()), Some(id));
            assert_eq!(id.codec().id(), id);
        }
    }

    #[test]
    fn strips_extensions() {
        assert_eq!(
            strip_extension("a.tar.zst", CodecId::Zstd).as_deref(),
            Some("a.tar")
        );
        assert_eq!(
            strip_extension("A.TGZ", CodecId::Gzip).as_deref(),
            Some("A.tar")
        );
        assert_eq!(
            strip_extension("notes.txt.gz", CodecId::Gzip).as_deref(),
            Some("notes.txt")
        );
        assert_eq!(strip_extension("x.zip", CodecId::Gzip), None);
        assert_eq!(strip_extension(".gz", CodecId::Gzip), None);
    }

    #[test]
    fn levels_are_checked() {
        let gz = CodecId::Gzip;
        let levels = gz.codec().levels();
        assert_eq!(EncodeOpts::default().resolve_level(gz, levels), Ok(6));
        assert!(
            EncodeOpts::with_level(10)
                .resolve_level(gz, levels)
                .is_err()
        );
        let lz4 = CodecId::Lz4;
        assert!(
            EncodeOpts::with_level(1)
                .resolve_level(lz4, lz4.codec().levels())
                .is_err()
        );
    }

    #[test]
    fn dictionaries_fit_small_inputs() {
        assert_eq!(fit_dict(1 << 23, Some(100)), 4096);
        assert_eq!(fit_dict(1 << 23, Some(70_000)), 1 << 17);
        assert_eq!(fit_dict(1 << 23, None), 1 << 23);
        assert_eq!(fit_dict(1 << 16, Some(1 << 20)), 1 << 16);
    }
}
