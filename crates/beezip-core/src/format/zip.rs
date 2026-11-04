//! ZIP, through the `zip` crate (=9.2.2). This is the only file that names `zip::`.
//!
//! - Opening detects where the archive starts (zip SFX), refuses archives whose entries share
//!   compressed data (the overlapping-entry bomb), and reads the index from the central
//!   directory without touching the data.
//! - Times: the NTFS extra field (UTC, 100 ns), then the extended timestamp (UTC, 1 s), then
//!   the DOS time (local, 2 s). zip 9.2.2 only exposes extra fields on an opened entry, so they
//!   are read from the central directory here.
//! - Encrypted entries ask `Ctx::password`; a password that worked is tried first for the rest.
//!   ZipCrypto's one-byte check lets 1 wrong password in 256 through, so a CRC failure on a
//!   ZipCrypto entry reads "wrong password or damaged data".
//! - New zips get Zip64 when needed, a DOS time and an extended timestamp per entry, and
//!   AES-256 for a password, or ZipCrypto for tools that can't read AES.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
};

use zip::{
    AesMode, CompressionMethod, DateTime, HasZipMetadata, ZipArchive, ZipReadOptions,
    read::{ArchiveOffset, Config},
    result::ZipError,
    unstable::write::FileOptionsExt,
    write::{FullFileOptions, SimpleFileOptions},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, NewEntry, NewKind, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, Checked, CountingReader, copy, read_error, write_error},
    safefs::Partial,
    source::Source,
    time::{DosTime, from_dos, from_ntfs, from_unix, to_dos, to_unix},
};

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
            ".zip", ".jar", ".war", ".apk", ".aab", ".ipa", ".xpi", ".vsix", ".nupkg", ".whl",
            ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".appx", ".msix",
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

type ZipFileReader = BufReader<CountingReader<File>>;

pub struct ZipReader {
    source: Source,
    archive: ZipArchive<ZipFileReader>,
    entries: Vec<Entry>,
    zipcrypto: Vec<bool>,
    sfx: bool,
    comment: Option<String>,
    /// The last password that worked.
    password: Option<String>,
    /// Keeps a spooled zip (one that came out of a codec) alive.
    _spool: Option<Partial>,
}

impl ZipReader {
    pub fn open(source: Source, sfx: bool, cx: &mut dyn Ctx) -> Result<Self> {
        let reopen = |e: io::Error| Error::io(format!("reading {}", source.path.display()), &e);
        let (file, mut cd_file, spool) = if source.codecs.is_empty() {
            let cd_file = File::open(&source.path).map_err(reopen)?;
            (source.open_file()?, cd_file, None)
        } else {
            // zip needs Seek: spool the decoded stream to a temp file, under the usual limits.
            let mut tmp = Partial::create_temp("beezip-spool.zip")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            let reopened = tmp.reopen()?;
            let cd_file = tmp.reopen()?;
            let file = CountingReader::new(reopened, source.counter.clone());
            (file, cd_file, Some(tmp))
        };
        let reader = BufReader::with_capacity(BUF_SIZE, file);
        let config = Config {
            archive_offset: ArchiveOffset::Detect,
        };
        let mut archive = ZipArchive::with_config(config, reader).map_err(zip_error)?;
        source.limits.check_entries(archive.len() as u64)?;
        if archive.has_overlapping_files().map_err(zip_error)? {
            return Err(Error::new(
                ErrorKind::Unsafe,
                "entries share compressed data (an overlapping-entry zip bomb)",
            ));
        }
        let times = central_times(&archive, &mut cd_file);
        let mut entries = Vec::with_capacity(archive.len());
        let mut zipcrypto = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            let f = archive.by_index_data(i).map_err(zip_error)?;
            let raw = f.name_raw().to_vec();
            let path = f
                .name()
                .map(|n| n.into_owned())
                .unwrap_or_else(|_| String::from_utf8_lossy(&raw).into_owned());
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
            let dos_time = f.last_modified().and_then(|d| {
                from_dos(DosTime {
                    date: d.datepart(),
                    time: d.timepart(),
                })
            });
            zipcrypto.push(f.encrypted() && f.get_metadata().aes_settings().is_none());
            entries.push(Entry {
                id: i,
                path,
                raw_path: raw,
                size: Some(f.size()),
                packed_size: Some(f.compressed_size()),
                modified: times.get(i).copied().flatten().or(dos_time),
                crc32: Some(f.crc32()),
                method: Some(method_name(f.compression())),
                encrypted: f.encrypted(),
                unix_mode: if unix { f.unix_mode() } else { None },
                dos_attrs: (!unix).then(|| f.external_attributes() & 0xFFFF),
                kind,
            });
        }
        // Symlink targets are the entry data; read the unencrypted ones now (they are short).
        for (i, entry) in entries.iter_mut().enumerate() {
            if matches!(entry.kind, EntryKind::Symlink { .. }) && !entry.encrypted {
                let mut target = String::new();
                if let Ok(f) = archive.by_index(i) {
                    let _ = f.take(4096).read_to_string(&mut target);
                }
                entry.kind = EntryKind::Symlink { target };
            }
        }
        let comment =
            Some(String::from_utf8_lossy(archive.comment()).into_owned()).filter(|c| !c.is_empty());
        let sfx = sfx || archive.offset() > 0;
        Ok(Self {
            source,
            archive,
            entries,
            zipcrypto,
            sfx,
            comment,
            password: None,
            _spool: spool,
        })
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
        let opts = ZipReadOptions::new().password(pw.as_ref().map(|p| p.as_bytes()));
        let file = self
            .archive
            .by_index_with_options(i, opts)
            .map_err(zip_error)?;
        Ok(Box::new(self.source.guard(CrcHint {
            inner: file,
            zipcrypto,
        })))
    }
}

/// Turns a CRC failure on a ZipCrypto entry, or a failed AES authentication code, into "wrong
/// password or damaged data": both checks pass a wrong password now and then (1 in 256 and
/// 1 in 65 536), so the failure at the end can't tell the two apart.
struct CrcHint<R> {
    inner: R,
    zipcrypto: bool,
}

impl<R: Read> Read for CrcHint<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            let text = e.to_string();
            if (self.zipcrypto && text.contains("Invalid checksum"))
                || text.contains("Invalid authentication code")
            {
                Error::new(ErrorKind::WrongPassword, "wrong password or damaged data").into_io()
            } else {
                e
            }
        })
    }
}

/// The NTFS (0x000A) or extended-timestamp (0x5455) mtime of each entry, from the central
/// directory, read through `file` (a second handle: zip 9.2.2 doesn't lend its reader out).
/// Directories over 512 MiB are skipped, and DOS times are used instead.
fn central_times(
    archive: &ZipArchive<ZipFileReader>,
    file: &mut File,
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

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let methods: BTreeSet<&'static str> = self
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .filter_map(|e| e.method)
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
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
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

/// Writes a zip to a seekable file.
pub struct ZipWriter {
    zip: zip::ZipWriter<File>,
    opts: ZipWriteOptions,
    level: Option<i64>,
}

impl ZipWriter {
    pub fn new(out: File, opts: ZipWriteOptions) -> Result<Self> {
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
        Ok(Self {
            zip: zip::ZipWriter::new(out).set_auto_large_file(),
            opts,
            level,
        })
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

impl ArchiveWriter for ZipWriter {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let opts = entry_options(&self.opts, self.level, entry)?;
        match &entry.kind {
            NewKind::Dir => self
                .zip
                .add_directory(format!("{}/", entry.path), opts)
                .map_err(write_zip_error),
            NewKind::Symlink { target } => self
                .zip
                .add_symlink(&entry.path, target, opts)
                .map_err(write_zip_error),
            NewKind::File => {
                self.zip
                    .start_file(&entry.path, opts)
                    .map_err(write_zip_error)?;
                let mut checked = Checked::new(data, cx);
                io::copy(&mut checked, &mut self.zip).map_err(|e| read_error(&e))?;
                Ok(())
            }
        }
    }

    fn finish(self: Box<Self>) -> Result<()> {
        let mut file = self.zip.finish().map_err(write_zip_error)?;
        file.flush().map_err(|e| write_error(&e))
    }
}
