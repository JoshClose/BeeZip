//! ZIP, through the `zip` crate (=9.4.1). This is the only file that names `zip::`.
//!
//! - Opening detects where the archive starts (zip SFX), refuses archives whose entries share
//!   compressed data (the overlapping-entry bomb), and reads the index from the central
//!   directory without touching the data.
//! - Times: the NTFS extra field (UTC, 100 ns), then the extended timestamp (UTC, 1 s), then
//!   the DOS time (local, 2 s). zip 9.2.2–9.4.1 exposes extra fields only on an opened entry,
//!   so they are read from the central directory here.
//! - Encrypted entries ask `Ctx::password`; a password that worked is tried first for the rest.
//!   ZipCrypto's one-byte check lets 1 wrong password in 256 through, so a CRC failure on a
//!   ZipCrypto entry reads "wrong password or damaged data".
//! - New zips get Zip64 when needed, a DOS time and an extended timestamp per entry, and
//!   AES-256 for a password, or ZipCrypto for tools that can't read AES.

use std::{
    borrow::Cow,
    collections::BTreeSet,
    fs::File,
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use zip::{
    AesMode, CompressionMethod, DateTime, HasZipMetadata, ZipArchive, ZipReadOptions,
    read::{ArchiveOffset, Config},
    result::ZipError,
    unstable::write::FileOptionsExt,
    write::{FullFileOptions, SimpleFileOptions},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Copied, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, Keep, NewEntry, NewKind, Selection,
    zip_edit::{self, CentralRecord, OffsetView},
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, Checked, CountingReader, WriteSeek, copy, read_error, write_error},
    names::SystemPage,
    safefs::Partial,
    source::{Input, Source},
    time::{DosClock, DosTime, from_ntfs, from_unix, to_dos, to_unix},
};

#[path = "zip_par.rs"]
mod par;

/// How many extractions this process has run on workers: lets tests see the parallel path ran.
pub fn parallel_extractions() -> usize {
    par::RUNS.load(std::sync::atomic::Ordering::Relaxed)
}

pub struct Zip;

const LOCAL: &[u8; 4] = b"PK\x03\x04";
const EOCD: &[u8; 4] = b"PK\x05\x06";
const SPANNED: &[u8; 4] = b"PK\x07\x08";

impl ArchiveFormat for Zip {
    fn id(&self) -> FormatId {
        FormatId::Zip
    }

    fn extensions(&self) -> &'static [&'static str] {
        // Formats that are zips underneath open as zips.
        &[
            ".zip", ".cbz", ".jar", ".war", ".apk", ".aab", ".ipa", ".xpi", ".vsix", ".nupkg",
            ".whl", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".appx", ".msix",
        ]
    }

    /// `PK\3\4` with an end-of-central-directory record in the tail, an empty archive (just
    /// the EOCD), or an executable with an EOCD in its tail (a zip SFX).
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let head = probe.head;
        let eocd = eocd_in(probe.tail).is_some();
        if head.starts_with(LOCAL) || (head.starts_with(SPANNED) && head[4..].starts_with(LOCAL)) {
            // Inside a codec there is no tail to check, so it stays likely.
            return Some(if eocd {
                Confidence::Certain
            } else {
                Confidence::Likely
            });
        }
        if head.starts_with(EOCD) && eocd_in(head).is_some() {
            return Some(Confidence::Certain);
        }
        is_sfx(probe).then_some(Confidence::Certain)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            append: true,
            delete: true,
            rename: true,
            encrypt: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}

/// An executable (`MZ`) whose tail holds a zip end-of-central-directory record.
pub fn is_sfx(probe: &Probe<'_>) -> bool {
    probe.head.starts_with(b"MZ") && eocd_in(probe.tail).is_some()
}

/// The offset of the last EOCD record in `buf` whose comment fits in what follows it.
fn eocd_in(buf: &[u8]) -> Option<usize> {
    if buf.len() < 22 {
        return None;
    }
    (0..=buf.len() - 22).rev().find(|&i| {
        &buf[i..i + 4] == EOCD && {
            let comment = usize::from(u16::from_le_bytes([buf[i + 20], buf[i + 21]]));
            i + 22 + comment <= buf.len()
        }
    })
}

/// The zip methods BeeZip writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZipMethod {
    Store,
    #[default]
    Deflate,
    Bzip2,
    Zstd,
    Xz,
    Ppmd,
}

impl ZipMethod {
    pub const ALL: [ZipMethod; 6] = [
        Self::Store,
        Self::Deflate,
        Self::Bzip2,
        Self::Zstd,
        Self::Xz,
        Self::Ppmd,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Deflate => "deflate",
            Self::Bzip2 => "bzip2",
            Self::Zstd => "zstd",
            Self::Xz => "xz",
            Self::Ppmd => "ppmd",
        }
    }

    /// Level range and default, as the zip crate accepts them. Deflate goes through flate2,
    /// whose fastest level is 1.
    pub const fn levels(self) -> Option<crate::Levels> {
        let (min, max, default) = match self {
            Self::Store => return None,
            Self::Deflate => (1, 9, 6),
            Self::Bzip2 => (1, 9, 9),
            Self::Zstd => (1, 22, 3),
            Self::Xz => (0, 9, 6),
            Self::Ppmd => (1, 9, 7),
        };
        Some(crate::Levels { min, max, default })
    }

    fn method(self) -> CompressionMethod {
        match self {
            Self::Store => CompressionMethod::Stored,
            Self::Deflate => CompressionMethod::Deflated,
            Self::Bzip2 => CompressionMethod::Bzip2,
            Self::Zstd => CompressionMethod::Zstd,
            Self::Xz => CompressionMethod::Xz,
            Self::Ppmd => CompressionMethod::Ppmd,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZipEncryption {
    #[default]
    Aes256,
    /// The legacy scheme, for tools such as Windows Explorer that can't read AES.
    ZipCrypto,
}

#[derive(Debug, Clone, Default)]
pub struct ZipWriteOptions {
    pub method: ZipMethod,
    pub level: Option<i32>,
    pub password: Option<String>,
    pub encryption: ZipEncryption,
    /// Workers that compress entries side by side (docs/M6.md §6.2): `0` is one per logical
    /// core, `1` writes on the job's thread, through the zip crate alone.
    pub threads: u32,
}

impl ZipWriteOptions {
    /// Checks the level against the method's range and the password, as the writer would.
    pub fn check(&self) -> Result<()> {
        ZipWriter::check(self.clone()).map(|_| ())
    }
}

fn method_name(m: CompressionMethod) -> &'static str {
    #[allow(deprecated)]
    match m {
        CompressionMethod::Stored => "Store",
        CompressionMethod::Deflated => "Deflate",
        CompressionMethod::Deflate64 => "Deflate64",
        CompressionMethod::Bzip2 => "BZip2",
        CompressionMethod::Lzma => "LZMA",
        CompressionMethod::Zstd => "Zstd",
        CompressionMethod::Xz => "XZ",
        CompressionMethod::Ppmd => "PPMd",
        CompressionMethod::Shrink => "Shrink",
        CompressionMethod::Reduce(_) => "Reduce",
        CompressionMethod::Implode => "Implode",
        CompressionMethod::AES => "AES",
        _ => "Unknown",
    }
}

fn zip_error(e: ZipError) -> Error {
    match e {
        ZipError::Io(e) => read_error(&e),
        ZipError::InvalidArchive(m) => Error::corrupt(format!("zip: {m}")),
        ZipError::UnsupportedArchive(m) if m == ZipError::PASSWORD_REQUIRED => {
            Error::new(ErrorKind::PasswordRequired, "the entry is encrypted")
        }
        ZipError::UnsupportedArchive(m) => Error::unsupported(format!("zip: {m}")),
        ZipError::CompressionMethodNotSupported(n) => {
            Error::unsupported(format!("zip: compression method {n} is not supported"))
        }
        ZipError::InvalidPassword => Error::new(ErrorKind::WrongPassword, "wrong password"),
        ZipError::FileNotFound => Error::new(ErrorKind::NotFound, "no such entry"),
        other => Error::corrupt(format!("zip: {other}")),
    }
}

type ZipFileReader = BufReader<CountingReader<Input>>;

/// Why a zip is part of a spanned set (`.z01`, `.z02`… plus `.zip`), which BeeZip can't read
/// in v1 (docs/M3.md §3.5): its end record names another disk, or a `.z01` sits beside it.
/// 7-Zip's byte splits (`a.zip.001`) are ordinary zips once joined, and aren't spanned.
fn spanned(source: &Source) -> Option<String> {
    const MSG: &str = "spanned zip archives (.z01, .z02… with .zip) aren't supported";
    if !source.joined
        && source.codecs.is_empty()
        && source
            .path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
        && source.path.with_extension("z01").is_file()
    {
        return Some(format!("{MSG}; {} is one part", source.path.display()));
    }
    let mut input = source.input().ok()?;
    let len = input.len();
    let want = len.min(64 * 1024 + 22);
    input.seek(SeekFrom::Start(len - want)).ok()?;
    let mut tail = Vec::new();
    input.take(want).read_to_end(&mut tail).ok()?;
    let at = eocd_in(&tail)?;
    let disk = u16::from_le_bytes([tail[at + 4], tail[at + 5]]);
    let cd_disk = u16::from_le_bytes([tail[at + 6], tail[at + 7]]);
    // 0xFFFF means the Zip64 record has the real numbers; zip itself checks those.
    ((disk != 0 && disk != 0xFFFF) || (cd_disk != 0 && cd_disk != 0xFFFF))
        .then(|| format!("{MSG}; this is disk {} of a set", u32::from(disk) + 1))
}

pub struct ZipReader {
    source: Source,
    archive: ZipArchive<ZipFileReader>,
    entries: Vec<Entry>,
    zipcrypto: Vec<bool>,
    /// Where each entry's bytes are, by id.
    layouts: Vec<Layout>,
    sfx: bool,
    comment: Option<String>,
    /// The last password that worked.
    password: Option<String>,
    /// Keeps a spooled zip (one that came out of a codec) alive.
    _spool: Option<Partial>,
}

/// Flag bit 11: the name and comment are UTF-8. zip also sets it when an Info-ZIP Unicode Path
/// extra (0x7075) replaced the name.
const UTF8_FLAG: u16 = 1 << 11;
/// Flag bit 3: the sizes and CRC follow the data, in a data descriptor.
const DESCRIPTOR_FLAG: u16 = 1 << 3;

impl ZipReader {
    pub fn open(source: Source, sfx: bool, cx: &mut dyn Ctx) -> Result<Self> {
        if let Some(why) = spanned(&source) {
            return Err(Error::unsupported_format(why));
        }
        let (file, mut cd_file, spool) = if source.codecs.is_empty() {
            (source.open_file()?, source.input()?, None)
        } else {
            // zip needs Seek: spool the decoded stream to a temp file, under the usual limits.
            let mut tmp = Partial::create_temp("beezip-spool.zip")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            let reopened = Input::file(tmp.reopen()?)?;
            let cd_file = Input::file(tmp.reopen()?)?;
            let file = CountingReader::new(reopened, source.counter.clone());
            (file, cd_file, Some(tmp))
        };
        let reader = BufReader::with_capacity(BUF_SIZE, file);
        let config = Config {
            archive_offset: ArchiveOffset::Detect,
        };
        let archive = ZipArchive::with_config(config, reader).map_err(zip_error)?;
        source.limits.check_entries(archive.len() as u64)?;
        // Replaces zip's `has_overlapping_files`, which seeks to every local header through a
        // buffer it empties each time: 5 s of the 5.2 s a million entries took (#54).
        let layouts = scan_local_headers(&archive, &mut cd_file)?;
        let times = central_times(&archive, &mut cd_file);
        let names = source.names;
        let mut clock = DosClock::default();
        let mut entries = Vec::with_capacity(archive.len());
        let mut zipcrypto = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            let f = archive.by_index_data(i).map_err(zip_error)?;
            let raw = f.name_raw();
            let utf8 = f.flags().as_u16() & UTF8_FLAG != 0;
            let path = names.decode(raw, utf8, SystemPage::Oem);
            let kind = if f.is_dir() {
                EntryKind::Dir
            } else if f.is_symlink() {
                EntryKind::Symlink {
                    target: String::new(),
                }
            } else {
                EntryKind::File
            };
            let unix = matches!(f.system(), zip::System::Unix);
            // The DOS time is local, so reading it takes a time zone lookup: only when the
            // entry has no NTFS or Unix time.
            let modified = times.get(i).copied().flatten().or_else(|| {
                f.last_modified().and_then(|d| {
                    clock.read(DosTime {
                        date: d.datepart(),
                        time: d.timepart(),
                    })
                })
            });
            zipcrypto.push(f.encrypted() && f.get_metadata().aes_settings().is_none());
            entries.push(Entry {
                id: i,
                raw_path: raw.to_vec(),
                path,
                size: Some(f.size()),
                packed_size: Some(f.compressed_size()),
                modified,
                crc32: Some(f.crc32()),
                method: Some(method_name(f.compression()).into()),
                encrypted: f.encrypted(),
                unix_mode: if unix { f.unix_mode() } else { None },
                dos_attrs: (!unix).then(|| f.external_attributes() & 0xFFFF),
                kind,
            });
        }
        let mut archive = archive;
        // Symlink targets are the entry data; read the unencrypted ones now (they are short).
        for (i, entry) in entries.iter_mut().enumerate() {
            if matches!(entry.kind, EntryKind::Symlink { .. }) && !entry.encrypted {
                let mut target = Vec::new();
                let mut utf8 = false;
                if let Ok(f) = archive.by_index(i) {
                    utf8 = f.flags().as_u16() & UTF8_FLAG != 0;
                    let _ = f.take(4096).read_to_end(&mut target);
                }
                entry.kind = EntryKind::Symlink {
                    target: names.decode(&target, utf8, SystemPage::Oem),
                };
            }
        }
        // The archive comment has no flag of its own; it's in the code page the names are.
        let comment =
            Some(names.decode(archive.comment(), false, SystemPage::Oem)).filter(|c| !c.is_empty());
        let sfx = sfx || archive.offset() > 0;
        Ok(Self {
            source,
            archive,
            entries,
            zipcrypto,
            layouts,
            sfx,
            comment,
            password: None,
            _spool: spool,
        })
    }

    /// Where entry `id`'s bytes are in the input: its local header, data and data
    /// descriptor. `None` for an empty entry whose local header couldn't be read.
    pub fn span(&self, id: usize) -> Option<ZipSpan> {
        let l = self.layouts.get(id)?;
        (l.head != 0).then(|| {
            let data = l.header + u64::from(l.head);
            let data_end = data + l.packed;
            ZipSpan {
                header: l.header,
                data,
                data_end,
                end: data_end + u64::from(l.tail),
            }
        })
    }

    /// The central directory holds two entries with one name. The zip crate keeps one entry per
    /// name, so an edit would drop the other (docs/M5.md §16, PR 1 item 8).
    pub fn has_duplicate_names(&self) -> bool {
        self.archive.has_duplicate_names()
    }

    /// Entry `id`'s central directory record, as stored.
    pub fn central_record(&self, id: usize) -> Result<Vec<u8>> {
        let start = self
            .archive
            .by_index_data(id)
            .map_err(zip_error)?
            .central_header_start();
        let mut input = self.source.input()?;
        let mut fixed = [0u8; 46];
        input
            .seek(SeekFrom::Start(start))
            .and_then(|_| input.read_exact(&mut fixed))
            .map_err(|e| read_error(&e))?;
        let len = 46
            + usize::from(u16_at(&fixed, 28))
            + usize::from(u16_at(&fixed, 30))
            + usize::from(u16_at(&fixed, 32));
        let mut rec = vec![0u8; len];
        input
            .seek(SeekFrom::Start(start))
            .and_then(|_| input.read_exact(&mut rec))
            .map_err(|e| read_error(&e))?;
        Ok(rec)
    }

    /// The bytes of entry `id`'s span (local header, data, descriptor), as stored.
    pub fn span_bytes(&self, id: usize) -> Result<Option<Vec<u8>>> {
        let Some(span) = self.span(id) else {
            return Ok(None);
        };
        let mut input = self.source.input()?;
        let len = usize::try_from(span.end - span.header)
            .map_err(|_| Error::limit("an entry too large to hold"))?;
        let mut b = vec![0u8; len];
        input
            .seek(SeekFrom::Start(span.header))
            .and_then(|_| input.read_exact(&mut b))
            .map_err(|e| read_error(&e))?;
        Ok(Some(b))
    }

    /// Copies `keep` byte for byte to `ed`'s file, renaming those whose path changed, and
    /// keeps their central records for the merged directory (docs/M5.md §3.3). Entries whose
    /// bytes it can't place (an empty entry without a readable local header) are left over.
    fn copy_into(&mut self, ed: &mut Editor, keep: &[Keep], cx: &mut dyn Ctx) -> Result<Copied> {
        let mut input = self.source.input()?;
        let mut cd_input = self.source.input()?;
        let mut central = HeaderReader {
            file: &mut cd_input,
            buf: Vec::new(),
            at: 0,
            filled: 0,
        };
        ed.comment = self.archive.comment().to_vec();
        ed.file
            .seek(SeekFrom::Start(ed.pos))
            .map_err(|e| write_error(&e))?;
        let mut out = BufWriter::with_capacity(BUF_SIZE, &mut ed.file);
        let mut copied = Copied::default();
        // Kept entries next to each other in the source are copied as one run: a million small
        // entries are one copy, not a million seeks.
        let mut run: Option<(u64, u64)> = None;
        for k in keep {
            cx.check()?;
            let (Some(span), Some(entry)) = (self.span(k.id), self.entries.get(k.id)) else {
                copied.rest.push(k.id);
                continue;
            };
            let start = self
                .archive
                .by_index_data(k.id)
                .map_err(zip_error)?
                .central_header_start();
            let fixed = central.bytes(start, 46).map_err(|e| read_error(&e))?;
            if fixed.len() < 46 {
                return Err(Error::corrupt(
                    "zip: a central directory record is cut short",
                ));
            }
            let len = 46
                + usize::from(u16_at(fixed, 28))
                + usize::from(u16_at(fixed, 30))
                + usize::from(u16_at(fixed, 32));
            let raw = central.bytes(start, len).map_err(|e| read_error(&e))?;
            let (mut rec, _) = CentralRecord::parse(raw)?;
            let at = ed.pos;
            if k.path == entry.path {
                let n = span.end - span.header;
                run = match run {
                    Some((s, len)) if s + len == span.header => Some((s, len + n)),
                    other => {
                        if let Some((s, len)) = other {
                            copy_range(&mut input, s, len, &mut out, cx)?;
                        }
                        Some((span.header, n))
                    }
                };
                ed.pos += n;
            } else {
                if let Some((s, len)) = run.take() {
                    copy_range(&mut input, s, len, &mut out, cx)?;
                }
                let head_len = usize::try_from(span.data - span.header)
                    .map_err(|_| Error::corrupt("zip: a local header is too long"))?;
                let mut head = vec![0u8; head_len];
                input
                    .seek(SeekFrom::Start(span.header))
                    .and_then(|_| input.read_exact(&mut head))
                    .map_err(|e| read_error(&e))?;
                let head = zip_edit::renamed_local(&head, &k.path)?;
                out.write_all(&head).map_err(|e| write_error(&e))?;
                ed.pos += head.len() as u64;
                let n = span.end - span.data;
                ed.pos += copy_range(&mut input, span.data, n, &mut out, cx)?;
                // A comment in the code page is written in UTF-8, as the flag now says.
                let comment_at = 46 + usize::from(u16_at(raw, 28)) + usize::from(u16_at(raw, 30));
                let comment_raw = &raw[comment_at.min(raw.len())..];
                let utf8 = rec.flags() & UTF8_FLAG != 0;
                let recode = (!utf8 && std::str::from_utf8(comment_raw).is_err()).then(|| {
                    self.source
                        .names
                        .decode(comment_raw, false, SystemPage::Oem)
                });
                rec.rename(&k.path, recode.as_deref())?;
            }
            rec.set_offset(at)?;
            ed.kept.push(rec);
            copied.copied += 1;
        }
        if let Some((s, len)) = run.take() {
            copy_range(&mut input, s, len, &mut out, cx)?;
        }
        out.flush().map_err(|e| write_error(&e))?;
        Ok(copied)
    }

    /// Finds a password that opens entry `i`: the last one that worked, then whatever the
    /// context offers, until it gives up.
    fn unlock(&mut self, i: usize, cx: &mut dyn Ctx) -> Result<Option<String>> {
        if !self.entries[i].encrypted {
            return Ok(None);
        }
        let mut failed = 0u32;
        let mut candidate = self.password.clone();
        loop {
            let pw = match candidate.take() {
                Some(pw) => pw,
                None => cx.password(Some(&self.entries[i].path), failed)?,
            };
            let opts = ZipReadOptions::new().password(Some(pw.as_bytes()));
            match self.archive.by_index_with_options(i, opts) {
                Ok(_) => {
                    self.password = Some(pw.clone());
                    return Ok(Some(pw));
                }
                Err(ZipError::InvalidPassword) => failed += 1,
                Err(e) => return Err(zip_error(e)),
            }
        }
    }

    fn open_data(&mut self, i: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let pw = self.unlock(i, cx)?;
        let zipcrypto = self.zipcrypto[i];
        let encrypted = pw.is_some();
        let opts = ZipReadOptions::new().password(pw.as_ref().map(|p| p.as_bytes()));
        let file = self
            .archive
            .by_index_with_options(i, opts)
            .map_err(zip_error)?;
        Ok(Box::new(self.source.guard(CrcHint {
            inner: file,
            zipcrypto,
            encrypted,
        })))
    }
}

/// Turns a CRC failure on a ZipCrypto entry, a failed AES authentication code, or data an
/// encrypted entry's method can't decode, into "wrong password or damaged data": the password
/// checks pass a wrong one now and then (1 in 256 for ZipCrypto, 1 in 65 536 for AES), and then
/// the garbage fails wherever it fails first, usually in the decompressor (docs/M5.md §16, PR 4),
/// and now and then by running out before its stream ends ("incomplete deflate stream", an
/// `UnexpectedEof`; docs/M6.md §16, PR 5).
struct CrcHint<R> {
    inner: R,
    zipcrypto: bool,
    encrypted: bool,
}

impl<R: Read> Read for CrcHint<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            let text = e.to_string();
            if (self.zipcrypto && text.contains("Invalid checksum"))
                || text.contains("Invalid authentication code")
                || (self.encrypted
                    && e.get_ref().is_none_or(|x| !x.is::<Error>())
                    && crate::io::read_error(&e).kind == ErrorKind::Corrupt)
            {
                Error::new(ErrorKind::WrongPassword, "wrong password or damaged data").into_io()
            } else {
                e
            }
        })
    }
}

/// Where an entry's bytes are in a zip, from its local header (docs/M5.md §3.3, §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipSpan {
    /// The local header.
    pub header: u64,
    /// The data, after the header's name and extra fields.
    pub data: u64,
    pub data_end: u64,
    /// The end of the entry: after its data descriptor, when it has one.
    pub end: u64,
}

/// A [`ZipSpan`], kept small: a million entries hold a million of them.
#[derive(Debug, Clone, Copy, Default)]
struct Layout {
    header: u64,
    packed: u64,
    /// The local header's length; 0 when it couldn't be read.
    head: u32,
    /// The data descriptor's length.
    tail: u8,
}

/// Reads the local headers in file order, through a buffer it moves forward, so a million
/// small entries take one pass over the file rather than a million seeks and refills. Far
/// jumps (past a large entry's data) read only a little at the new place.
struct HeaderReader<'a> {
    file: &'a mut Input,
    buf: Vec<u8>,
    /// Where `buf` starts in the file, and how much of it holds data.
    at: u64,
    filled: usize,
}

impl HeaderReader<'_> {
    /// What a jump to just past the buffer reads.
    const NEAR: usize = 64 * 1024;
    /// What a jump further away reads.
    const FAR: usize = 4 * 1024;

    /// Up to `want` bytes at `pos`; fewer at the end of the file.
    fn bytes(&mut self, pos: u64, want: usize) -> io::Result<&[u8]> {
        let end = self.at + self.filled as u64;
        if pos >= self.at && pos.saturating_add(want as u64) <= end {
            let s = usize::try_from(pos - self.at).unwrap_or(usize::MAX);
            return Ok(&self.buf[s..s + want]);
        }
        let near = pos >= self.at && pos <= end + Self::NEAR as u64;
        let chunk = if near { Self::NEAR } else { Self::FAR }.max(want);
        if self.buf.len() < chunk {
            self.buf.resize(chunk, 0);
        }
        self.file.seek(SeekFrom::Start(pos))?;
        let mut n = 0;
        while n < chunk {
            match self.file.read(&mut self.buf[n..chunk]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.at = pos;
        self.filled = n;
        Ok(&self.buf[..want.min(n)])
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// Reads every entry's local header, in file order, and refuses archives whose entries share
/// compressed data. The check is zip's `has_overlapping_files`: the data of entries with any
/// must not overlap, or run into the central directory. An empty entry's header is read too,
/// but not required, as zip doesn't read it either.
fn scan_local_headers(
    archive: &ZipArchive<ZipFileReader>,
    file: &mut Input,
) -> Result<Vec<Layout>> {
    let n = archive.len();
    let mut order: Vec<(u64, usize)> = Vec::with_capacity(n);
    for i in 0..n {
        let f = archive.by_index_data(i).map_err(zip_error)?;
        order.push((f.header_start(), i));
    }
    if !order.is_sorted() {
        order.sort_unstable();
    }
    let mut reader = HeaderReader {
        file,
        buf: Vec::new(),
        at: 0,
        filled: 0,
    };
    let mut layouts = vec![Layout::default(); n];
    let mut ranges: Vec<std::ops::Range<u64>> = Vec::with_capacity(n);
    for (start, i) in order {
        let f = archive.by_index_data(i).map_err(zip_error)?;
        let packed = f.compressed_size();
        match local_header(&mut reader, start, packed, f.crc32(), f.size()) {
            Ok(layout) => {
                if packed > 0 {
                    let data = start + u64::from(layout.head);
                    ranges.push(data..data + packed);
                }
                layouts[i] = layout;
            }
            Err(_) if packed == 0 => {}
            Err(e) => {
                let name = String::from_utf8_lossy(f.name_raw()).into_owned();
                return Err(Error::corrupt(format!("zip: {name}: {}", e.message)));
            }
        }
    }
    if !ranges.is_sorted_by_key(|r| (r.start, r.end)) {
        ranges.sort_unstable_by_key(|r| (r.start, r.end));
    }
    let dir_start = archive.central_directory_start();
    if ranges.iter().any(|r| r.end > dir_start) || ranges.windows(2).any(|w| w[0].end > w[1].start)
    {
        return Err(Error::new(
            ErrorKind::Unsafe,
            "entries share compressed data (an overlapping-entry zip bomb)",
        ));
    }
    Ok(layouts)
}

/// One entry's local header at `start`, and the data descriptor after its data.
fn local_header(
    reader: &mut HeaderReader<'_>,
    start: u64,
    packed: u64,
    crc: u32,
    size: u64,
) -> Result<Layout> {
    let damaged = |what: &str| Error::corrupt(format!("the local header {what}"));
    let h = reader.bytes(start, 30).map_err(|e| read_error(&e))?;
    if h.len() < 30 || &h[..4] != LOCAL {
        return Err(damaged("is missing"));
    }
    let flags = u16_at(h, 6);
    let name_len = usize::from(u16_at(h, 26));
    let extra_len = usize::from(u16_at(h, 28));
    let head = 30 + name_len + extra_len;
    let data_end = start
        .checked_add(head as u64)
        .and_then(|d| d.checked_add(packed))
        .ok_or_else(|| damaged("is past the end"))?;
    let mut tail = 0;
    if flags & DESCRIPTOR_FLAG != 0 {
        let extra = reader
            .bytes(start + 30 + name_len as u64, extra_len)
            .map_err(|e| read_error(&e))?;
        let zip64 = has_zip64(extra);
        let d = reader.bytes(data_end, 24).map_err(|e| read_error(&e))?;
        tail = descriptor_len(d, crc, packed, size, zip64);
    }
    Ok(Layout {
        header: start,
        packed,
        head: u32::try_from(head).unwrap_or(0),
        tail,
    })
}

/// Whether a local header's extra fields hold a Zip64 field (0x0001).
fn has_zip64(mut extra: &[u8]) -> bool {
    while extra.len() >= 4 {
        if u16_at(extra, 0) == 1 {
            return true;
        }
        let size = usize::from(u16_at(extra, 2));
        extra = extra.get(4 + size..).unwrap_or_default();
    }
    false
}

/// The length of the data descriptor `d` starts with: an optional `PK\7\8`, the CRC, then the
/// two sizes in 4 bytes each, or 8 when the entry is Zip64. Which layout it is comes from the
/// values matching the central directory's, since writers don't agree on when to use the
/// signature or the wide sizes; when none matches, the spec's layout for the header.
fn descriptor_len(d: &[u8], crc: u32, packed: u64, size: u64, zip64: bool) -> u8 {
    let signed = d.len() >= 4 && &d[..4] == SPANNED;
    let offsets: &[usize] = if signed { &[4, 0] } else { &[0] };
    let widths: [bool; 2] = if zip64 { [true, false] } else { [false, true] };
    for &off in offsets {
        for wide in widths {
            let len = off + if wide { 20 } else { 12 };
            if d.len() < len || u32_at(d, off) != crc {
                continue;
            }
            let matches = if wide {
                u64_at(d, off + 4) == packed && u64_at(d, off + 12) == size
            } else {
                u32::try_from(packed).is_ok_and(|p| u32_at(d, off + 4) == p)
                    && u32::try_from(size).is_ok_and(|s| u32_at(d, off + 8) == s)
            };
            if matches {
                return len as u8;
            }
        }
    }
    let off = if signed { 4 } else { 0 };
    (off + if zip64 { 20 } else { 12 }) as u8
}

/// The NTFS (0x000A) or extended-timestamp (0x5455) mtime of each entry, from the central
/// directory, read through `file` (a second handle: zip 9.2.2–9.4.1 doesn't lend its reader out).
/// Directories over 512 MiB are skipped, and DOS times are used instead.
fn central_times(
    archive: &ZipArchive<ZipFileReader>,
    file: &mut Input,
) -> Vec<Option<std::time::SystemTime>> {
    let Ok(starts) = (0..archive.len())
        .map(|i| archive.by_index_data(i).map(|f| f.central_header_start()))
        .collect::<std::result::Result<Vec<u64>, _>>()
    else {
        return Vec::new();
    };
    let Some(first) = starts.iter().copied().min() else {
        return Vec::new();
    };
    let Ok(end) = file.seek(SeekFrom::End(0)) else {
        return Vec::new();
    };
    let len = end.saturating_sub(first);
    if len > 512 << 20 || file.seek(SeekFrom::Start(first)).is_err() {
        return Vec::new();
    }
    let mut cd = Vec::new();
    if file.take(len).read_to_end(&mut cd).is_err() {
        return Vec::new();
    }
    starts
        .iter()
        .map(|&s| {
            usize::try_from(s - first)
                .ok()
                .and_then(|at| header_time(&cd, at))
        })
        .collect()
}

fn header_time(cd: &[u8], at: usize) -> Option<std::time::SystemTime> {
    let h = cd.get(at..at + 46)?;
    if &h[..4] != b"PK\x01\x02" {
        return None;
    }
    let name = usize::from(u16::from_le_bytes([h[28], h[29]]));
    let extra = usize::from(u16::from_le_bytes([h[30], h[31]]));
    let mut fields = cd.get(at + 46 + name..at + 46 + name + extra)?;
    let (mut ntfs, mut ut) = (None, None);
    while fields.len() >= 4 {
        let id = u16::from_le_bytes([fields[0], fields[1]]);
        let size = usize::from(u16::from_le_bytes([fields[2], fields[3]]));
        let Some(data) = fields.get(4..4 + size) else {
            break;
        };
        match id {
            0x000A => ntfs = ntfs_mtime(data),
            0x5455 if data.len() >= 5 && data[0] & 1 != 0 => {
                let secs = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                ut = from_unix(i64::from(secs), 0);
            }
            _ => {}
        }
        fields = &fields[4 + size..];
    }
    ntfs.or(ut)
}

/// NTFS extra field: 4 reserved bytes, then tags; tag 1 holds mtime, atime and ctime.
fn ntfs_mtime(data: &[u8]) -> Option<std::time::SystemTime> {
    let mut tags = data.get(4..)?;
    while tags.len() >= 4 {
        let tag = u16::from_le_bytes([tags[0], tags[1]]);
        let size = usize::from(u16::from_le_bytes([tags[2], tags[3]]));
        let body = tags.get(4..4 + size)?;
        if tag == 1 && size >= 8 {
            let ticks = u64::from_le_bytes(body[..8].try_into().ok()?);
            return from_ntfs(ticks);
        }
        tags = &tags[4 + size..];
    }
    None
}

impl ArchiveReader for ZipReader {
    fn format(&self) -> FormatId {
        FormatId::Zip
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let methods: BTreeSet<Cow<'static, str>> = self
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .filter_map(|e| e.method.clone())
            .collect();
        let encrypted = self.entries.iter().filter(|e| e.encrypted).count();
        let files = self
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count();
        Ok(ArchiveInfo {
            format: FormatId::Zip,
            codecs: self.source.codecs.clone(),
            methods: methods.into_iter().collect(),
            comment: self.comment.clone(),
            encryption: match encrypted {
                0 => Encryption::None,
                n if n >= files => Encryption::All,
                _ => Encryption::Some,
            },
            solid: false,
            sfx: self.sfx,
            volumes: self.source.volumes.len(),
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
        if let Some(fs) = sink.as_fs_sink() {
            let mut workers = par::workers(self, sel);
            // Left to BeeZip, a spinning disk gets one worker; a count that was set is kept.
            if workers > 1
                && self.source.threads == 0
                && crate::safefs::disk::seek_penalty(fs.dest()) == Some(true)
            {
                workers = 1;
            }
            if workers > 1 {
                return par::extract(self, sel, fs, cx, workers);
            }
        }
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
        meter.entries_total = Some(self.entries.len() as u64);
        for i in 0..self.entries.len() {
            cx.check()?;
            if !sel.matches(&self.entries[i]) {
                continue;
            }
            let entry = self.entries[i].clone();
            meter.entries_done = i as u64;
            meter.current = Some(entry.path.clone());
            if entry.kind == EntryKind::File {
                let mut data = self.open_data(i, cx)?;
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.report();
                sink.entry(&entry, &mut data, &mut mcx)?;
            } else {
                let mut mcx = MeteredCtx::new(cx, &meter);
                sink.entry(&entry, &mut io::empty(), &mut mcx)?;
            }
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        match &entry.kind {
            EntryKind::File => self.open_data(id, cx),
            EntryKind::Symlink { target } => {
                Ok(Box::new(io::Cursor::new(target.clone().into_bytes())))
            }
            _ => Ok(Box::new(io::empty())),
        }
    }
}

/// Copies `len` bytes at `start` of `input` to `out`, checking for cancellation as it goes.
fn copy_range(
    input: &mut Input,
    start: u64,
    len: u64,
    out: &mut dyn Write,
    cx: &mut dyn Ctx,
) -> Result<u64> {
    input
        .seek(SeekFrom::Start(start))
        .map_err(|e| read_error(&e))?;
    let n = copy(&mut input.take(len), out, cx)?;
    if n != len {
        return Err(Error::corrupt("zip: an entry is cut short"));
    }
    Ok(n)
}

/// Where a zip writer writes.
enum Out {
    /// A new zip, nothing in it yet: the first `add` hands it to the zip crate, the first
    /// `add_all` with workers to [`Spans`].
    Fresh(Box<dyn WriteSeek>),
    /// A new zip: the zip crate writes all of it.
    Plain(Box<zip::ZipWriter<Box<dyn WriteSeek>>>),
    /// A new zip of entries made on workers (docs/M6.md §6.2).
    Spans(Box<Spans>),
    /// An edit: kept entries copied first, then the new ones after them (docs/M5.md §3.3).
    Edit(Box<Editor>),
    /// Only while changing from one to another.
    Gone,
}

/// A new zip written from one-entry zips the workers make ([`par::Blob`]): each one's local
/// part copied here, its central record moved to where it landed.
struct Spans {
    /// Buffered: a zip of small files is many small appends.
    out: BufWriter<Box<dyn WriteSeek>>,
    pos: u64,
    recs: Vec<CentralRecord>,
}

impl Spans {
    fn append(&mut self, blob: par::Blob) -> Result<()> {
        let par::Blob { span, mut rec } = blob;
        rec.set_offset(self.pos)?;
        self.pos += span.write_to(&mut self.out)?;
        self.recs.push(rec);
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        zip_edit::write_directory(&mut self.out, self.pos, &self.recs, b"")?;
        self.out.flush().map_err(|e| write_error(&e))
    }
}

/// A zip being written from another one's entries and new ones.
struct Editor {
    /// The output, which is read back for the new entries' central directory.
    file: File,
    /// Where the copied entries end.
    pos: u64,
    /// The copied entries' central records, pointing at their new places.
    kept: Vec<CentralRecord>,
    /// The archive comment's bytes, as the source had them.
    comment: Vec<u8>,
    /// The zip crate, writing the new entries after the copied ones, from their first `add`.
    zip: Option<zip::ZipWriter<OffsetView<File>>>,
}

impl Editor {
    /// Writes a one-entry zip's local part after the copied entries, before the zip crate
    /// writes anything ([`ZipWriter::add_all`] checks).
    fn append(&mut self, blob: par::Blob) -> Result<()> {
        let par::Blob { span, mut rec } = blob;
        rec.set_offset(self.pos)?;
        self.file
            .seek(SeekFrom::Start(self.pos))
            .map_err(|e| write_error(&e))?;
        self.pos += span.write_to(&mut self.file)?;
        self.kept.push(rec);
        Ok(())
    }

    /// The zip crate, writing after the copied entries.
    fn zip(&mut self) -> Result<&mut zip::ZipWriter<OffsetView<File>>> {
        if self.zip.is_none() {
            let file = self
                .file
                .try_clone()
                .map_err(|e| Error::io("opening the zip being written", &e))?;
            let mut view = OffsetView {
                inner: file,
                base: self.pos,
            };
            view.seek(SeekFrom::Start(0)).map_err(|e| write_error(&e))?;
            self.zip = Some(zip::ZipWriter::new(view).set_auto_large_file());
        }
        self.zip
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Io, "the zip writer is gone"))
    }

    /// The central directory: the copied entries' records, then the new ones' (read back from
    /// what the zip crate wrote, and moved by where it started), then the end records.
    fn finish(mut self) -> Result<()> {
        let (start, mut recs) = match self.zip.take() {
            None => (self.pos, Vec::new()),
            Some(zip) => {
                let mut view = zip.finish().map_err(write_zip_error)?;
                view.flush().map_err(|e| write_error(&e))?;
                let len = view.seek(SeekFrom::End(0)).map_err(|e| write_error(&e))?;
                let (at, size) = zip_edit::find_directory(&mut view, len)?;
                let size = usize::try_from(size)
                    .map_err(|_| Error::limit("the new entries' directory is too large"))?;
                let mut cd = vec![0u8; size];
                view.seek(SeekFrom::Start(at))
                    .and_then(|_| view.read_exact(&mut cd))
                    .map_err(|e| Error::io("reading the zip being written", &e))?;
                let mut recs = zip_edit::records(&cd)?;
                for r in &mut recs {
                    let offset = r
                        .offset()
                        .ok_or_else(|| Error::corrupt("zip: a new entry has no offset"))?;
                    r.set_offset(offset + self.pos)?;
                }
                (self.pos + at, recs)
            }
        };
        let mut all = std::mem::take(&mut self.kept);
        all.append(&mut recs);
        self.file
            .seek(SeekFrom::Start(start))
            .map_err(|e| write_error(&e))?;
        let mut out = BufWriter::with_capacity(BUF_SIZE, &mut self.file);
        let end = zip_edit::write_directory(&mut out, start, &all, &self.comment)?;
        out.flush().map_err(|e| write_error(&e))?;
        drop(out);
        self.file.set_len(end).map_err(|e| write_error(&e))?;
        Ok(())
    }
}

/// Writes a zip to a seekable output: a file, or a volume set.
pub struct ZipWriter {
    out: Out,
    opts: ZipWriteOptions,
    level: Option<i64>,
    /// Where workers make entries too big to hold in memory: beside the archive.
    spool: PathBuf,
}

impl ZipWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: ZipWriteOptions) -> Result<Self> {
        let (opts, level) = Self::check(opts)?;
        Ok(Self {
            out: Out::Fresh(out),
            opts,
            level,
            spool: std::env::temp_dir(),
        })
    }

    /// Big entries made on workers go into temporary files in `dir`, the archive's folder,
    /// rather than the system's temp folder.
    #[must_use]
    pub fn spool_in(mut self, dir: &Path) -> Self {
        self.spool = dir.to_path_buf();
        self
    }

    /// The zip crate, from the first entry added one at a time.
    fn plain(&mut self) {
        if matches!(self.out, Out::Fresh(_))
            && let Out::Fresh(out) = std::mem::replace(&mut self.out, Out::Gone)
        {
            self.out = Out::Plain(Box::new(zip::ZipWriter::new(out).set_auto_large_file()));
        }
    }

    /// Adds a one-entry zip a worker made.
    fn append(&mut self, blob: par::Blob) -> Result<()> {
        match &mut self.out {
            Out::Spans(s) => s.append(blob),
            Out::Edit(ed) => ed.append(blob),
            _ => Err(Error::new(
                ErrorKind::Io,
                "zip: no place for a worker's entry",
            )),
        }
    }

    /// A zip written to `file` for an edit or a convert: [`ArchiveWriter::copy_from`] copies a
    /// zip's entries byte for byte, then new ones are added after them.
    pub fn editing(file: File, opts: ZipWriteOptions) -> Result<Self> {
        let (opts, level) = Self::check(opts)?;
        Ok(Self {
            out: Out::Edit(Box::new(Editor {
                file,
                pos: 0,
                kept: Vec::new(),
                comment: Vec::new(),
                zip: None,
            })),
            opts,
            level,
            spool: std::env::temp_dir(),
        })
    }

    fn check(opts: ZipWriteOptions) -> Result<(ZipWriteOptions, Option<i64>)> {
        let level = match (opts.method.levels(), opts.level) {
            (None, None) => None,
            (None, Some(_)) => {
                return Err(Error::invalid_args("the store method has no levels"));
            }
            (Some(l), None) => Some(i64::from(l.default)),
            (Some(l), Some(v)) if (l.min..=l.max).contains(&v) => Some(i64::from(v)),
            (Some(l), Some(v)) => {
                return Err(Error::invalid_args(format!(
                    "level {v} is out of range for zip {} ({}–{})",
                    opts.method.name(),
                    l.min,
                    l.max
                )));
            }
        };
        if opts.password.as_deref() == Some("") {
            return Err(Error::invalid_args("the password is empty"));
        }
        Ok((opts, level))
    }
}

/// The options for one entry. A free function borrowing only the write options, so the
/// password can be lent to the options while the writer itself is borrowed mutably.
fn entry_options<'k>(
    opts: &'k ZipWriteOptions,
    level: Option<i64>,
    entry: &NewEntry,
) -> Result<FullFileOptions<'k, 'static>> {
    // Empty files are stored, as 7-Zip and Info-ZIP do: an empty compressed stream is just
    // overhead, and 7-Zip rejects zip's empty xz stream ("data after the end of the payload").
    let compressed = entry.kind == NewKind::File && entry.size > 0;
    let method = if compressed {
        opts.method.method()
    } else {
        CompressionMethod::Stored
    };
    let mut o: FullFileOptions<'k, 'static> = SimpleFileOptions::default()
        .compression_method(method)
        .into_full_options();
    if compressed {
        o = o.compression_level(level);
    }
    let mode = match (&entry.kind, entry.unix_mode) {
        (_, Some(m)) if cfg!(unix) => m & 0o7777,
        (NewKind::Dir, _) => 0o755,
        (NewKind::Symlink { .. }, _) => 0o777,
        (NewKind::File, _) if entry.dos_attrs.is_some_and(|a| a & 1 != 0) => 0o444,
        (NewKind::File, _) => 0o644,
    };
    o = o.unix_permissions(mode);
    if let Some(t) = entry.modified {
        if let Some(dos) = to_dos(t)
            && let Ok(dt) = DateTime::try_from_msdos(dos.date, dos.time)
        {
            o = o.last_modified_time(dt);
        }
        // The extended timestamp: flags (mtime present), then the UTC mtime.
        if let Ok(secs) = u32::try_from(to_unix(t)) {
            let mut ut = vec![1u8];
            ut.extend_from_slice(&secs.to_le_bytes());
            o.add_extra_field(0x5455, ut, false)
                .map_err(|e| Error::invalid_args(format!("zip extra field: {e}")))?;
        }
    }
    if let (Some(pw), NewKind::File) = (&opts.password, &entry.kind) {
        o = match opts.encryption {
            ZipEncryption::Aes256 => o.with_aes_encryption(AesMode::Aes256, pw),
            ZipEncryption::ZipCrypto => o
                .with_deprecated_encryption(pw.as_bytes())
                .map_err(|e| Error::invalid_args(format!("ZipCrypto: {e}")))?,
        };
    }
    Ok(o)
}

fn write_zip_error(e: ZipError) -> Error {
    match e {
        ZipError::Io(e) => write_error(&e),
        other => Error::invalid_args(format!("zip: {other}")),
    }
}

/// Adds one entry through the zip crate.
fn add_to<W: Write + Seek>(
    zip: &mut zip::ZipWriter<W>,
    opts: FullFileOptions<'_, 'static>,
    entry: &NewEntry,
    data: &mut dyn Read,
    cx: &mut dyn Ctx,
) -> Result<()> {
    match &entry.kind {
        NewKind::Dir => zip
            .add_directory(format!("{}/", entry.path.trim_end_matches('/')), opts)
            .map_err(write_zip_error),
        NewKind::Symlink { target } => zip
            .add_symlink(&entry.path, target, opts)
            .map_err(write_zip_error),
        NewKind::File => {
            zip.start_file(&entry.path, opts).map_err(write_zip_error)?;
            let mut checked = Checked::new(data, cx);
            io::copy(&mut checked, zip).map_err(|e| read_error(&e))?;
            Ok(())
        }
    }
}

impl ArchiveWriter for ZipWriter {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        self.plain();
        if matches!(self.out, Out::Spans(_)) {
            // After entries from workers, one more the same way, on this thread.
            let blob = par::one_entry(&self.opts, self.level, entry, data, cx, &self.spool)?;
            return self.append(blob);
        }
        let opts = entry_options(&self.opts, self.level, entry)?;
        match &mut self.out {
            Out::Plain(zip) => add_to(zip, opts, entry, data, cx),
            Out::Edit(ed) => add_to(ed.zip()?, opts, entry, data, cx),
            _ => Err(Error::new(ErrorKind::Io, "zip: the writer is gone")),
        }
    }

    fn workers(&self) -> usize {
        crate::codec::resolve_threads(self.opts.threads) as usize
    }

    /// On workers when there are two or more files with data and nothing has gone through
    /// the zip crate yet (an edit's copies may have); otherwise one by one.
    fn add_all(
        &mut self,
        entries: &[NewEntry],
        open: &super::Opener<'_>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let workers = self.workers();
        let files = entries
            .iter()
            .filter(|e| e.kind == NewKind::File && e.size > 0)
            .count();
        let ready = match &self.out {
            Out::Fresh(_) | Out::Spans(_) => true,
            Out::Edit(ed) => ed.zip.is_none(),
            Out::Plain(_) | Out::Gone => false,
        };
        if workers < 2 || files < 2 || !ready {
            for (k, e) in entries.iter().enumerate() {
                let mut data: Box<dyn Read + Send> = match e.kind {
                    NewKind::File => open(k)?,
                    _ => Box::new(io::empty()),
                };
                self.add(e, &mut data, cx)?;
            }
            return Ok(());
        }
        if matches!(self.out, Out::Fresh(_))
            && let Out::Fresh(out) = std::mem::replace(&mut self.out, Out::Gone)
        {
            self.out = Out::Spans(Box::new(Spans {
                out: BufWriter::with_capacity(BUF_SIZE, out),
                pos: 0,
                recs: Vec::new(),
            }));
        }
        par::write(self, entries, open, cx, workers)
    }

    fn copy_from(
        &mut self,
        source: &mut dyn ArchiveReader,
        keep: &[Keep],
        cx: &mut dyn Ctx,
    ) -> Result<Copied> {
        let Out::Edit(ed) = &mut self.out else {
            return Ok(Copied::nothing(keep));
        };
        // Copies go before the new entries, so the zip crate's view starts after them.
        if ed.zip.is_some() {
            return Ok(Copied::nothing(keep));
        }
        match source.as_any_mut().downcast_mut::<ZipReader>() {
            Some(r) => r.copy_into(ed, keep, cx),
            None => Ok(Copied::nothing(keep)),
        }
    }

    fn finish(mut self: Box<Self>, _: &mut dyn Ctx) -> Result<()> {
        // An empty zip is the zip crate's.
        self.plain();
        match self.out {
            Out::Plain(zip) => {
                let mut file = zip.finish().map_err(write_zip_error)?;
                file.flush().map_err(|e| write_error(&e))
            }
            Out::Spans(s) => s.finish(),
            Out::Edit(ed) => ed.finish(),
            Out::Fresh(_) | Out::Gone => Err(Error::new(ErrorKind::Io, "zip: the writer is gone")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A data descriptor: the signature if `signed`, the CRC, then sizes of 4 or 8 bytes.
    fn descriptor(signed: bool, crc: u32, packed: u64, size: u64, wide: bool) -> Vec<u8> {
        let mut d = Vec::new();
        if signed {
            d.extend_from_slice(SPANNED);
        }
        d.extend_from_slice(&crc.to_le_bytes());
        if wide {
            d.extend_from_slice(&packed.to_le_bytes());
            d.extend_from_slice(&size.to_le_bytes());
        } else {
            d.extend_from_slice(&(packed as u32).to_le_bytes());
            d.extend_from_slice(&(size as u32).to_le_bytes());
        }
        // The next entry's local header follows.
        d.extend_from_slice(LOCAL);
        d.resize(24, 0);
        d
    }

    #[test]
    fn descriptor_layouts() {
        let (crc, packed, size) = (0x1234_5678, 1000, 4000);
        for signed in [true, false] {
            for wide in [true, false] {
                let d = descriptor(signed, crc, packed, size, wide);
                let want = u8::from(signed) * 4 + if wide { 20 } else { 12 };
                // Whatever the local header suggests, the values decide.
                for zip64 in [true, false] {
                    assert_eq!(
                        descriptor_len(&d, crc, packed, size, zip64),
                        want,
                        "{signed} {wide} {zip64}"
                    );
                }
            }
        }
        // A CRC that happens to be the signature, unsigned.
        let sig = u32::from_le_bytes(*SPANNED);
        let d = descriptor(false, sig, packed, size, false);
        assert_eq!(descriptor_len(&d, sig, packed, size, false), 12);
        // Nothing matches (a damaged descriptor): the spec's layout for the header.
        let d = descriptor(true, 1, 2, 3, false);
        assert_eq!(descriptor_len(&d, crc, packed, size, false), 16);
        assert_eq!(descriptor_len(&d, crc, packed, size, true), 24);
        // Cut short by the end of the file.
        assert_eq!(descriptor_len(&[0x50, 0x4B], crc, packed, size, false), 12);
        // Sizes of 4 GiB and more only fit the wide layout.
        let big = 5 << 30;
        let d = descriptor(true, crc, big, big, false);
        assert_eq!(
            descriptor_len(&d, crc, big, big, false),
            16,
            "no false match"
        );
    }

    #[test]
    fn zip64_fields_are_found_among_the_extras() {
        assert!(!has_zip64(&[]));
        assert!(has_zip64(&[0x01, 0x00, 0x00, 0x00]));
        // NTFS first, then Zip64.
        let mut extra = vec![0x0A, 0x00, 0x04, 0x00, 0, 0, 0, 0];
        assert!(!has_zip64(&extra));
        extra.extend_from_slice(&[0x01, 0x00, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(has_zip64(&extra));
        // A field claiming more than is there ends the walk.
        assert!(!has_zip64(&[0x0A, 0x00, 0xFF, 0x00, 0x01, 0x00]));
    }

    /// A reader that fails with `err`.
    struct Fails(Option<io::Error>);

    impl Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(self.0.take().unwrap_or_else(|| io::Error::other("again")))
        }
    }

    #[test]
    fn an_encrypted_entrys_garbage_is_a_wrong_password_however_it_fails() {
        let kind = |encrypted: bool, err: io::Error| {
            let mut hint = CrcHint {
                inner: Fails(Some(err)),
                zipcrypto: encrypted,
                encrypted,
            };
            let e = hint.read(&mut [0; 16]).expect_err("it fails");
            crate::io::read_error(&e).kind
        };
        let cases = [
            || io::Error::new(io::ErrorKind::InvalidData, "invalid block type"),
            // Garbage that inflates until the entry's data runs out (seen on CI, 1 run in many).
            || io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete deflate stream"),
        ];
        for err in cases {
            assert_eq!(kind(true, err()), ErrorKind::WrongPassword, "{}", err());
            assert_eq!(kind(false, err()), ErrorKind::Corrupt, "{}", err());
        }
        // BeeZip's own errors pass through: a missing volume is still that.
        let missing = Error::new(ErrorKind::NotFound, "part 2 is missing").into_io();
        assert_eq!(kind(true, missing), ErrorKind::NotFound);
    }
}
