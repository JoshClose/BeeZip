//! 7z, through sevenz-rust2 (=0.24.2). This is the only file that names `sevenz_rust2::`
//! (docs/M3.md §3.3).
//!
//! - **Opening:** `sevenz_header::check` refuses a header that would decode past
//!   `decoder_memory` before sevenz-rust2 reads it. An encrypted header asks `Ctx::password`;
//!   a wrong one shows as a decode or CRC error, and is asked again.
//! - **The index:** `archive.files` in order, minus anti-items. A link is a file with 7-Zip's
//!   Unix extension (`0x8000`) and `S_IFLNK` in the high 16 bits, whose data is the target, or,
//!   as 7-Zip on Windows stores `-snl` links, one with the reparse-point attribute (`0x400`),
//!   whose data is a reparse buffer. Either target is read when the entry is extracted.
//! - **Extracting:** block by block through `BlockDecoder::for_each_entries`. A block with
//!   nothing selected isn't decoded. Each block's coders are checked against `decoder_memory`
//!   first. 7z has no password check value, so a wrong password shows as a failing entry; the
//!   block is decoded again with the next answer, and after the last one it is `WrongPassword`,
//!   "wrong password or damaged data".
//! - **`open_entry`:** the block decoder only calls back, so it runs on a helper thread with
//!   its own input, feeding a bounded pipe.
//! - **Writing:** `ArchiveWriter` on a file or a volume set. AES-256 goes before the method,
//!   and encrypts the header too unless told not to. Solid blocks come from `add_solid`.

use std::{
    cell::RefCell,
    collections::BTreeSet,
    io::{self, Read},
    ops::Range,
    sync::Arc,
};

use sevenz_rust2::{
    Archive, ArchiveEntry, BlockDecoder, EncoderConfiguration, EncoderMethod, NtTime, Password,
    SourceReader,
    encoder_options::{
        AesEncoderOptions, Bzip2Options, DeflateOptions, Lzma2Options, LzmaOptions, PpmdOptions,
    },
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Copied, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, Keep, NewEntry, NewKind, Selection,
    sevenz_header::{self, HeaderInfo, SIGNATURE},
};
use crate::{
    Ctx, Error, ErrorKind, Levels, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, CountingReader, PipeWriter, WriteSeek, pipe, read_error, write_error},
    source::{Input, Source},
    time::{from_ntfs, to_ntfs},
};

pub struct SevenZ;

/// 7-Zip's flag for Unix permissions in the high 16 bits of the attributes.
const UNIX_EXTENSION: u32 = 0x8000;
const ATTR_READONLY: u32 = 0x01;
const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_ARCHIVE: u32 = 0x20;
const ATTR_REPARSE_POINT: u32 = 0x400;
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;
/// A link's data is short; anything longer isn't read as a target.
const MAX_LINK: u64 = 64 * 1024;

impl ArchiveFormat for SevenZ {
    fn id(&self) -> FormatId {
        FormatId::SevenZ
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".7z", ".cb7"]
    }

    /// The signature with major version 0 is likely; with the start header's CRC, certain.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        start_header(probe.head)
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
            encrypt_headers: true,
            solid: true,
            volumes: true,
            // A solid block decodes from its start.
            random_access: false,
        }
    }
}

/// How sure `head` (from the archive's first byte) is a 7z.
pub fn start_header(head: &[u8]) -> Option<Confidence> {
    if head.len() < 8 || head[..6] != SIGNATURE || head[6] != 0 {
        return None;
    }
    let crc_ok = head.len() >= 32
        && crc32fast::hash(&head[12..32])
            == u32::from_le_bytes([head[8], head[9], head[10], head[11]]);
    Some(if crc_ok {
        Confidence::Certain
    } else {
        Confidence::Likely
    })
}

/// The 7z methods BeeZip writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SevenZMethod {
    #[default]
    Lzma2,
    Lzma,
    Ppmd,
    Bzip2,
    Deflate,
    Copy,
}

impl SevenZMethod {
    pub const ALL: [SevenZMethod; 6] = [
        Self::Lzma2,
        Self::Lzma,
        Self::Ppmd,
        Self::Bzip2,
        Self::Deflate,
        Self::Copy,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Lzma2 => "lzma2",
            Self::Lzma => "lzma",
            Self::Ppmd => "ppmd",
            Self::Bzip2 => "bzip2",
            Self::Deflate => "deflate",
            Self::Copy => "copy",
        }
    }

    /// The ranges 7-Zip itself accepts, and its defaults.
    pub const fn levels(self) -> Option<Levels> {
        let (min, max, default) = match self {
            Self::Lzma2 | Self::Lzma => (0, 9, 5),
            Self::Ppmd => (1, 9, 6),
            Self::Bzip2 => (1, 9, 9),
            Self::Deflate => (1, 9, 6),
            Self::Copy => return None,
        };
        Some(Levels { min, max, default })
    }
}

#[derive(Debug, Clone)]
pub struct SevenZWriteOptions {
    pub method: SevenZMethod,
    pub level: Option<i32>,
    /// LZMA2 compression threads; 0 is one per core.
    pub threads: u32,
    pub password: Option<String>,
    /// Encrypt the names too (only with a password).
    pub encrypt_headers: bool,
    pub solid: bool,
}

impl Default for SevenZWriteOptions {
    fn default() -> Self {
        Self {
            method: SevenZMethod::Lzma2,
            level: None,
            threads: 1,
            password: None,
            encrypt_headers: true,
            solid: true,
        }
    }
}

impl SevenZWriteOptions {
    /// The level, checked against the method's range.
    pub fn resolve_level(&self) -> Result<Option<i32>> {
        match (self.method.levels(), self.level) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(Error::invalid_args("the copy method has no levels")),
            (Some(l), None) => Ok(Some(l.default)),
            (Some(l), Some(v)) if (l.min..=l.max).contains(&v) => Ok(Some(v)),
            (Some(l), Some(v)) => Err(Error::invalid_args(format!(
                "level {v} is out of range for 7z {} ({}–{})",
                self.method.name(),
                l.min,
                l.max
            ))),
        }
    }

    /// The dictionary the method uses at this level (LZMA and LZMA2), or 0.
    pub fn dictionary(&self) -> u64 {
        match (self.method, self.resolve_level()) {
            (SevenZMethod::Lzma2 | SevenZMethod::Lzma, Ok(Some(l))) => u64::from(
                lzma_rust2::LzmaOptions::with_preset(u32::try_from(l).unwrap_or(5)).dict_size,
            ),
            _ => 0,
        }
    }

    /// The largest solid block: max(64 MiB, 4 × the dictionary), at most 1 GiB (§10).
    pub fn block_limit(&self) -> u64 {
        (4 * self.dictionary()).clamp(64 << 20, 1 << 30)
    }
}

/// A coder's name, for the method lists.
fn coder_name(id: &[u8]) -> Option<&'static str> {
    Some(match id {
        EncoderMethod::ID_COPY => "Copy",
        EncoderMethod::ID_LZMA => "LZMA",
        EncoderMethod::ID_LZMA2 => "LZMA2",
        EncoderMethod::ID_PPMD => "PPMd",
        EncoderMethod::ID_BZIP2 => "BZip2",
        EncoderMethod::ID_DEFLATE => "Deflate",
        EncoderMethod::ID_DEFLATE64 => "Deflate64",
        EncoderMethod::ID_LZ4 => "LZ4",
        EncoderMethod::ID_BROTLI => "Brotli",
        EncoderMethod::ID_ZSTD => "Zstd",
        EncoderMethod::ID_AES256_SHA256 => "AES-256",
        EncoderMethod::ID_BCJ_X86 => "BCJ",
        EncoderMethod::ID_BCJ2 => "BCJ2",
        EncoderMethod::ID_BCJ_ARM => "ARM",
        EncoderMethod::ID_BCJ_ARM64 => "ARM64",
        EncoderMethod::ID_BCJ_ARM_THUMB => "ARMT",
        EncoderMethod::ID_BCJ_PPC => "PPC",
        EncoderMethod::ID_BCJ_IA64 => "IA64",
        EncoderMethod::ID_BCJ_SPARC => "SPARC",
        EncoderMethod::ID_BCJ_RISCV => "RISCV",
        EncoderMethod::ID_DELTA => "Delta",
        _ => return None,
    })
}

fn is_filter_or_aes(name: &str) -> bool {
    !matches!(
        name,
        "Copy"
            | "LZMA"
            | "LZMA2"
            | "PPMd"
            | "BZip2"
            | "Deflate"
            | "Deflate64"
            | "LZ4"
            | "Brotli"
            | "Zstd"
    )
}

fn wrong_password() -> Error {
    Error::new(ErrorKind::WrongPassword, "wrong password or damaged data")
}

/// A sevenz-rust2 error as a core error. `encrypted`: the data or header being decoded is
/// encrypted, so damage most likely means a wrong password.
fn sz_error(e: sevenz_rust2::Error, encrypted: bool) -> Error {
    use sevenz_rust2::Error as E;
    match e {
        E::PasswordRequired => Error::new(ErrorKind::PasswordRequired, "the 7z is encrypted"),
        E::MaybeBadPassword(_) if encrypted => wrong_password(),
        E::MaybeBadPassword(e) | E::FileOpen(e, _) => read_error(&e),
        E::Io(e, _) => {
            let err = read_error(&e);
            if encrypted && err.kind == ErrorKind::Corrupt {
                wrong_password()
            } else {
                err
            }
        }
        E::MaxMemLimited { max_kb, actaul_kb } => Error::limit(format!(
            "7z needs {actaul_kb} KiB to decode, over {max_kb} KiB (`decoder_memory`)"
        )),
        E::UnsupportedCompressionMethod(m) => {
            Error::unsupported(format!("7z: the {m} method isn't supported"))
        }
        E::Unsupported(m) => Error::unsupported(format!("7z: {m}")),
        E::ExternalUnsupported => Error::unsupported("7z: external header data isn't supported"),
        E::UnsupportedVersion { major, minor } => {
            Error::unsupported_format(format!("7z version {major}.{minor} isn't supported"))
        }
        _ if encrypted => wrong_password(),
        E::ChecksumVerificationFailed | E::NextHeaderCrcMismatch => {
            Error::corrupt("7z: CRC mismatch")
        }
        E::Other(m) => Error::corrupt(format!("7z: {m}")),
        other => Error::corrupt(format!("7z: {other:?}")),
    }
}

/// What extraction needs to know about one block.
#[derive(Debug, Clone)]
struct BlockInfo {
    /// The files of the block, as indexes into `archive.files`.
    files: Range<usize>,
    encrypted: bool,
    /// Memory its coders need.
    memory: u64,
    /// The LZMA2 dictionary, for the decoding threads.
    lzma2_dict: Option<u64>,
}

pub struct SevenZReader {
    source: Source,
    archive: Arc<Archive>,
    entries: Vec<Entry>,
    /// `archive.files` index → entry id (`None` for anti-items).
    entry_of: Vec<Option<usize>>,
    /// Entry id → `archive.files` index.
    file_of: Vec<usize>,
    blocks: Vec<BlockInfo>,
    header: HeaderInfo,
    sfx: bool,
    /// The last password that worked.
    password: Option<String>,
}

impl SevenZReader {
    /// `source.offset` says where the archive starts (inside an SFX).
    pub fn open(source: Source, sfx: bool, cx: &mut dyn Ctx) -> Result<Self> {
        let header = {
            let mut input = source.input()?;
            sevenz_header::check(&mut input, source.limits.decoder_memory)?.unwrap_or_default()
        };
        let mut need_password = header.encrypted;
        let mut failed = 0u32;
        let (archive, password) = loop {
            if failed > crate::ctx::MAX_PASSWORD_TRIES {
                return Err(wrong_password());
            }
            let pw = if need_password {
                Some(match cx.password(None, failed) {
                    Err(e) if e.kind == ErrorKind::WrongPassword && failed > 0 => {
                        return Err(wrong_password());
                    }
                    other => other?,
                })
            } else {
                None
            };
            let password = pw.as_deref().map_or_else(Password::empty, Password::new);
            let mut input = source.open_file()?;
            match Archive::read(&mut input, &password) {
                Ok(a) => break (a, pw),
                Err(sevenz_rust2::Error::PasswordRequired) if !need_password => {
                    need_password = true;
                }
                Err(e) if pw.is_some() => {
                    let err = sz_error(e, true);
                    if err.kind != ErrorKind::WrongPassword {
                        return Err(err);
                    }
                    failed += 1;
                }
                Err(e) => return Err(sz_error(e, false)),
            }
        };
        source.limits.check_entries(archive.files.len() as u64)?;

        let mut blocks = Vec::with_capacity(archive.blocks.len());
        let mut ranges: Vec<Option<Range<usize>>> = vec![None; archive.blocks.len()];
        for (i, b) in archive.stream_map.file_block_index.iter().enumerate() {
            if let Some(b) = *b
                && let Some(r) = ranges.get_mut(b)
            {
                *r = Some(match r.take() {
                    Some(r) => r.start..i + 1,
                    None => i..i + 1,
                });
            }
        }
        for (b, block) in archive.blocks.iter().enumerate() {
            let mut memory = 0u64;
            let mut lzma2_dict = None;
            let mut encrypted = false;
            for c in &block.coders {
                let id = c.encoder_method_id();
                memory = memory.saturating_add(sevenz_header::coder_memory(id, c.properties()));
                if id == sevenz_header::ID_LZMA2 {
                    lzma2_dict = Some(sevenz_header::coder_memory(id, c.properties()));
                }
                encrypted |= id == sevenz_header::ID_AES;
            }
            blocks.push(BlockInfo {
                files: ranges[b].clone().unwrap_or(0..0),
                encrypted,
                memory,
                lzma2_dict,
            });
        }

        let mut entries = Vec::with_capacity(archive.files.len());
        let mut entry_of = Vec::with_capacity(archive.files.len());
        let mut file_of = Vec::with_capacity(archive.files.len());
        let mut anti = 0u64;
        for (i, f) in archive.files.iter().enumerate() {
            if f.is_anti_item {
                anti += 1;
                entry_of.push(None);
                continue;
            }
            let block = archive.stream_map.file_block_index[i];
            let id = entries.len();
            entry_of.push(Some(id));
            file_of.push(i);
            entries.push(make_entry(
                id,
                f,
                block.and_then(|b| blocks.get(b)),
                &archive,
                block,
            ));
        }
        if anti > 0 {
            cx.warn(format!(
                "skipped {anti} anti-item(s): deletion markers from an update, not files"
            ));
        }
        Ok(Self {
            source,
            archive: Arc::new(archive),
            entries,
            entry_of,
            file_of,
            blocks,
            header,
            sfx,
            password,
        })
    }

    fn check_memory(&self, b: usize) -> Result<()> {
        let need = self.blocks[b].memory;
        let max = self.source.limits.decoder_memory;
        if need > max {
            return Err(Error::limit(format!(
                "a 7z block needs {need} bytes to decode, over the {max}-byte limit \
                 (`decoder_memory`)"
            )));
        }
        Ok(())
    }

    /// LZMA2 decoding threads: as many as fit in `decoder_memory`, at most one per core.
    fn threads(&self, b: usize) -> u32 {
        let Some(dict) = self.blocks[b].lzma2_dict else {
            return 1;
        };
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get() as u64);
        let fit = self.source.limits.decoder_memory / dict.max(1);
        u32::try_from(fit.min(cores).max(1)).unwrap_or(1)
    }

    /// The password to try for a block after `failed` wrong ones: the last one that worked,
    /// then whatever the context offers (the input's first, then prompts), until it gives up.
    fn block_password(&self, entry: &str, failed: u32, cx: &mut dyn Ctx) -> Result<String> {
        if failed > crate::ctx::MAX_PASSWORD_TRIES {
            return Err(wrong_password());
        }
        if failed == 0
            && let Some(pw) = &self.password
        {
            return Ok(pw.clone());
        }
        match cx.password(Some(entry), failed) {
            Err(e) if e.kind == ErrorKind::WrongPassword && failed > 0 => Err(wrong_password()),
            other => other,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_block(
        &self,
        b: usize,
        selected: &[bool],
        last: usize,
        password: &Password,
        input: &mut CountingReader<Input>,
        sink: &mut dyn EntrySink,
        meter: &mut Meter,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let info = &self.blocks[b];
        let encrypted = info.encrypted;
        let range = info.files.clone();
        let decoder = BlockDecoder::new(self.threads(b), b, &self.archive, password, input);
        let mut slot: Option<Error> = None;
        let mut k = 0usize;
        let result = decoder.for_each_entries(&mut |_, data: &mut dyn Read| {
            let at = k;
            k += 1;
            let Some(id) = self.entry_of[range.start + at] else {
                return Ok(true);
            };
            if !selected[at] {
                return Ok(true);
            }
            let entry = &self.entries[id];
            meter.entries_done = id as u64;
            meter.current = Some(entry.path.clone());
            let mut mcx = MeteredCtx::new(cx, meter);
            mcx.report();
            let mut tagged = DecodeTag::new(data, encrypted);
            let sent = match &entry.kind {
                EntryKind::Symlink { .. } => link_entry(entry, &mut tagged)
                    .and_then(|(entry, mut body)| sink.entry(&entry, &mut body, &mut mcx)),
                _ => {
                    let mut data = self.source.guard(&mut tagged);
                    sink.entry(entry, &mut data, &mut mcx)
                }
            };
            // A sink that records a damaged entry goes on. If the block's decoder failed, going
            // on means sevenz-rust2 reads it again, for the rest of this entry and the next one,
            // so the block fails here instead. The sink has the entry's own error.
            let data_follows = || {
                self.archive.files[range.start + at + 1..range.end]
                    .iter()
                    .any(|f| f.has_stream && f.size > 0)
            };
            match sent {
                Ok(()) if at < last && data_follows() => match tagged.failed.take() {
                    Some(e) => {
                        slot = Some(Error::new(
                            e.kind,
                            format!(
                                "the rest of the solid block after {} can't be decoded",
                                entry.path
                            ),
                        ));
                        Err(sevenz_rust2::Error::Other("the decoder failed".into()))
                    }
                    None => Ok(true),
                },
                Ok(()) => Ok(at < last),
                Err(e) => {
                    slot = Some(e);
                    Err(sevenz_rust2::Error::Other("the sink failed".into()))
                }
            }
        });
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(slot.take().unwrap_or_else(|| sz_error(e, encrypted))),
        }
    }

    fn extract_block(
        &mut self,
        b: usize,
        sel: &Selection,
        input: &mut CountingReader<Input>,
        sink: &mut dyn EntrySink,
        meter: &mut Meter,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let range = self.blocks[b].files.clone();
        let selected: Vec<bool> = range
            .clone()
            .map(|f| self.entry_of[f].is_some_and(|id| sel.matches(&self.entries[id])))
            .collect();
        let Some(last) = selected.iter().rposition(|&s| s) else {
            return Ok(());
        };
        self.check_memory(b)?;
        let first = self.entry_of[range.start + selected.iter().position(|&s| s).unwrap_or(0)]
            .map(|id| self.entries[id].path.clone())
            .unwrap_or_default();
        let mut failed = 0u32;
        loop {
            cx.check()?;
            let pw = if self.blocks[b].encrypted {
                Some(self.block_password(&first, failed, cx)?)
            } else {
                None
            };
            let password = pw.as_deref().map_or_else(Password::empty, Password::new);
            match self.decode_block(b, &selected, last, &password, input, sink, meter, cx) {
                Ok(()) => {
                    if pw.is_some() {
                        self.password = pw;
                    }
                    return Ok(());
                }
                Err(e) if pw.is_some() && e.kind == ErrorKind::WrongPassword => {
                    failed += 1;
                    self.password = None;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn make_entry(
    id: usize,
    f: &ArchiveEntry,
    block: Option<&BlockInfo>,
    archive: &Archive,
    block_index: Option<usize>,
) -> Entry {
    let attrs = if f.has_windows_attributes {
        f.windows_attributes
    } else {
        0
    };
    let unix = (attrs & UNIX_EXTENSION != 0).then_some(attrs >> 16);
    let has_data = f.has_stream && f.size > 0;
    let kind = if f.is_directory || (attrs & ATTR_DIRECTORY != 0 && !f.has_stream) {
        EntryKind::Dir
    } else if has_data
        && f.size <= MAX_LINK
        && (unix.is_some_and(|m| m & S_IFMT == S_IFLNK) || attrs & ATTR_REPARSE_POINT != 0)
    {
        EntryKind::Symlink {
            target: String::new(),
        }
    } else {
        EntryKind::File
    };
    let mut e = Entry::new(id, f.name.replace('\\', "/"), kind);
    if e.kind != EntryKind::Dir {
        e.size = Some(f.size);
    }
    e.modified = f
        .has_last_modified_date
        .then(|| from_ntfs(u64::from(f.last_modified_date)))
        .flatten();
    e.crc32 = (f.has_crc && has_data).then_some(f.crc as u32);
    e.dos_attrs = f.has_windows_attributes.then_some(attrs & 0xFFFF);
    e.unix_mode = unix;
    if let (Some(info), Some(b)) = (block, block_index) {
        e.encrypted = info.encrypted;
        e.method = archive.blocks[b]
            .coders
            .iter()
            .filter_map(|c| coder_name(c.encoder_method_id()))
            .find(|n| !is_filter_or_aes(n));
        // Only a block of one entry has a packed size of its own.
        let streams = archive.stream_map.file_block_index[info.files.clone()]
            .iter()
            .zip(&archive.files[info.files.clone()])
            .filter(|(_, f)| f.has_stream)
            .count();
        if streams == 1 {
            e.packed_size = Some(f.compressed_size);
        }
    }
    e
}

/// Turns decoder errors into "wrong password or damaged data" for an encrypted block, so the
/// sinks stop and the reader can ask again, or into `Corrupt`.
///
/// Once the block's decoder fails, it gives that error back instead of reading the decoder
/// again, as [`crate::io::LatchReader`] does for the codecs: sevenz-rust2 builds its own, and
/// libbz2-rs-sys 0.2.6 aborts when read after an error. An entry's CRC mismatch is kept out of
/// that: it comes after the entry's last byte and leaves the decoder sound.
struct DecodeTag<'a> {
    inner: &'a mut dyn Read,
    encrypted: bool,
    /// The block's decoder failed, with this error.
    failed: Option<Error>,
}

impl<'a> DecodeTag<'a> {
    fn new(inner: &'a mut dyn Read, encrypted: bool) -> Self {
        Self {
            inner,
            encrypted,
            failed: None,
        }
    }
}

impl Read for DecodeTag<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(err) = &self.failed {
            return Err(err.clone().into_io());
        }
        let e = match self.inner.read(buf) {
            Err(e) if e.kind() != io::ErrorKind::Interrupted => e,
            other => return other,
        };
        let crc = crc_mismatch(&e);
        let mut err = if crc {
            Error::corrupt("7z: CRC mismatch")
        } else {
            read_error(&e)
        };
        if self.encrypted && err.kind == ErrorKind::Corrupt {
            err = wrong_password();
        }
        if !crc {
            self.failed = Some(err.clone());
        }
        Err(err.into_io())
    }
}

/// sevenz-rust2's check of an entry's CRC, which it makes after the entry's last byte.
fn crc_mismatch(e: &io::Error) -> bool {
    matches!(
        e.get_ref()
            .and_then(|x| x.downcast_ref::<sevenz_rust2::Error>()),
        Some(sevenz_rust2::Error::ChecksumVerificationFailed)
    )
}

/// A link entry with its target read from its data. Data that isn't a link after all (a
/// reparse point of another kind) comes back as a file, with the bytes read.
fn link_entry(entry: &Entry, data: &mut dyn Read) -> Result<(Entry, io::Cursor<Vec<u8>>)> {
    let mut raw = Vec::new();
    data.take(MAX_LINK + 1)
        .read_to_end(&mut raw)
        .map_err(|e| read_error(&e))?;
    let target = if entry.unix_mode.is_some_and(|m| m & S_IFMT == S_IFLNK) {
        Some(String::from_utf8_lossy(&raw).into_owned())
    } else {
        reparse_target(&raw)
    };
    let mut e = entry.clone();
    match target {
        Some(target) => {
            e.kind = EntryKind::Symlink { target };
            Ok((e, io::Cursor::new(Vec::new())))
        }
        None => {
            e.kind = EntryKind::File;
            Ok((e, io::Cursor::new(raw)))
        }
    }
}

/// The target of a Windows symlink or junction reparse buffer, `/`-separated: the print name,
/// else the substitute name without its `\??\` prefix.
pub fn reparse_target(buf: &[u8]) -> Option<String> {
    const SYMLINK: u32 = 0xA000_000C;
    const MOUNT_POINT: u32 = 0xA000_0003;
    let u16_at = |i: usize| Some(u16::from_le_bytes([*buf.get(i)?, *buf.get(i + 1)?]));
    let tag = u32::from_le_bytes(buf.get(..4)?.try_into().ok()?);
    let path_start = match tag {
        SYMLINK => 20,
        MOUNT_POINT => 16,
        _ => return None,
    };
    let name = |off: usize, len: usize| -> Option<String> {
        let s = buf.get(path_start + off..path_start + off + len)?;
        let wide: Vec<u16> = s
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        Some(String::from_utf16_lossy(&wide))
    };
    let (sub_off, sub_len) = (usize::from(u16_at(8)?), usize::from(u16_at(10)?));
    let (print_off, print_len) = (usize::from(u16_at(12)?), usize::from(u16_at(14)?));
    let print = name(print_off, print_len).filter(|s| !s.is_empty());
    let target = match print {
        Some(p) => p,
        None => {
            let s = name(sub_off, sub_len)?;
            s.strip_prefix(r"\??\").map(str::to_owned).unwrap_or(s)
        }
    };
    (!target.is_empty()).then(|| target.replace('\\', "/"))
}

impl ArchiveReader for SevenZReader {
    fn format(&self) -> FormatId {
        FormatId::SevenZ
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods = BTreeSet::new();
        for b in &self.archive.blocks {
            for c in &b.coders {
                if let Some(n) = coder_name(c.encoder_method_id()) {
                    methods.insert(n);
                }
            }
        }
        // Only entries with data are in a block, so only they can be encrypted.
        let with_data: Vec<&Entry> = self
            .file_of
            .iter()
            .zip(&self.entries)
            .filter(|(f, _)| self.archive.stream_map.file_block_index[**f].is_some())
            .map(|(_, e)| e)
            .collect();
        let files = with_data.len();
        let encrypted = with_data.iter().filter(|e| e.encrypted).count();
        let mut per_block = vec![0u64; self.archive.blocks.len()];
        for (b, f) in self
            .archive
            .stream_map
            .file_block_index
            .iter()
            .zip(&self.archive.files)
        {
            if let Some(n) = b.and_then(|b| per_block.get_mut(b))
                && f.has_stream
            {
                *n += 1;
            }
        }
        let solid_blocks = per_block.into_iter().filter(|&n| n > 1).count() as u64;
        Ok(ArchiveInfo {
            format: FormatId::SevenZ,
            codecs: self.source.codecs.clone(),
            methods: methods.into_iter().collect(),
            comment: None,
            encryption: match encrypted {
                _ if self.header.encrypted => Encryption::All,
                0 => Encryption::None,
                n if n >= files => Encryption::All,
                _ => Encryption::Some,
            },
            solid: self.archive.is_solid,
            sfx: self.sfx,
            volumes: self.source.volumes.len(),
            solid_blocks: Some(solid_blocks),
            encrypted_headers: self.header.encrypted,
            locked: false,
            recovery_record: false,
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
        let mut input = self.source.open_file()?;
        let mut f = 0usize;
        while f < self.archive.files.len() {
            cx.check()?;
            match self.archive.stream_map.file_block_index[f] {
                Some(b) if self.blocks[b].files.start == f => {
                    self.extract_block(b, sel, &mut input, sink, &mut meter, cx)?;
                    f = self.blocks[b].files.end.max(f + 1);
                }
                _ => {
                    if let Some(id) = self.entry_of[f]
                        && sel.matches(&self.entries[id])
                    {
                        let entry = self.entries[id].clone();
                        meter.entries_done = id as u64;
                        meter.current = Some(entry.path.clone());
                        let mut mcx = MeteredCtx::new(cx, &meter);
                        sink.entry(&entry, &mut io::empty(), &mut mcx)?;
                    }
                    f += 1;
                }
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
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?
            .clone();
        let file = self.file_of[id];
        let Some(b) = self.archive.stream_map.file_block_index[file] else {
            return Ok(Box::new(io::empty()));
        };
        if !self.archive.files[file].has_stream || entry.kind == EntryKind::Dir {
            return Ok(Box::new(io::empty()));
        }
        self.check_memory(b)?;
        let encrypted = self.blocks[b].encrypted;
        let mut failed = 0u32;
        let mut reader = loop {
            let pw = if encrypted {
                Some(self.block_password(&entry.path, failed, cx)?)
            } else {
                None
            };
            let mut r = self.spawn_decoder(b, file, pw.clone())?;
            match r.first_error() {
                Some(e) if encrypted && e.kind == ErrorKind::WrongPassword => {
                    failed += 1;
                    self.password = None;
                }
                Some(e) => return Err(e),
                None => {
                    if pw.is_some() {
                        self.password = pw;
                    }
                    break r;
                }
            }
        };
        if matches!(entry.kind, EntryKind::Symlink { .. }) {
            let (e, body) = link_entry(&entry, &mut reader)?;
            return Ok(match e.kind {
                EntryKind::Symlink { target } => Box::new(io::Cursor::new(target.into_bytes())),
                _ => Box::new(body),
            });
        }
        Ok(Box::new(self.source.guard(reader)))
    }
}

impl SevenZReader {
    /// Decodes block `b` on a helper thread with its own input, up to file `target`, whose
    /// data it writes to a pipe. The reader that comes back pulls from it; dropping the reader
    /// stops the thread.
    fn spawn_decoder(
        &self,
        b: usize,
        target: usize,
        password: Option<String>,
    ) -> Result<crate::io::PipeReader> {
        let archive = Arc::clone(&self.archive);
        let mut input = self.source.open_file()?;
        let threads = self.threads(b);
        let start = self.blocks[b].files.start;
        let encrypted = self.blocks[b].encrypted;
        let (writer, reader) = pipe(4, BUF_SIZE);
        std::thread::Builder::new()
            .name("beezip-7z".into())
            .spawn(move || {
                let mut writer = writer;
                let result = decode_one(
                    &archive,
                    b,
                    start,
                    target,
                    threads,
                    password,
                    encrypted,
                    &mut input,
                    &mut writer,
                );
                writer.finish(result);
            })
            .map_err(|e| Error::io("starting the 7z decoder", &e))?;
        Ok(reader)
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_one(
    archive: &Archive,
    b: usize,
    start: usize,
    target: usize,
    threads: u32,
    password: Option<String>,
    encrypted: bool,
    input: &mut CountingReader<Input>,
    out: &mut PipeWriter,
) -> Result<()> {
    let password = password
        .as_deref()
        .map_or_else(Password::empty, Password::new);
    let decoder = BlockDecoder::new(threads, b, archive, &password, input);
    let mut slot: Option<Error> = None;
    let mut k = 0usize;
    let result = decoder.for_each_entries(&mut |_, data: &mut dyn Read| {
        let file = start + k;
        k += 1;
        let mut tagged = DecodeTag::new(data, encrypted);
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            if out.stopped() {
                slot = Some(Error::cancelled());
                return Err(sevenz_rust2::Error::Other("stopped".into()));
            }
            let n = match tagged.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    slot = Some(read_error(&e));
                    return Err(sevenz_rust2::Error::Other("decode".into()));
                }
            };
            if file == target
                && let Err(e) = io::Write::write_all(out, &buf[..n])
            {
                slot = Some(Error::from_io(&e));
                return Err(sevenz_rust2::Error::Other("pipe".into()));
            }
        }
        Ok(file < target)
    });
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(slot.take().unwrap_or_else(|| sz_error(e, encrypted))),
    }
}

/// Writes a 7z to a seekable output: a file, or a volume set.
pub struct SevenZWriter {
    w: sevenz_rust2::ArchiveWriter<Box<dyn WriteSeek>>,
    block_limit: Option<u64>,
    /// The content methods new blocks get: AES first when there is a password.
    methods: Vec<EncoderConfiguration>,
    /// The compression method alone, for blocks encoded again with their own password.
    method: EncoderConfiguration,
}

fn sz_write_error(e: sevenz_rust2::Error) -> Error {
    match e {
        sevenz_rust2::Error::Io(e, _) | sevenz_rust2::Error::FileOpen(e, _) => {
            // Errors smuggled through a reader (cancelled, a file that changed) come back as
            // they were; anything else is the output failing.
            if e.get_ref().is_some_and(|x| x.is::<Error>()) {
                read_error(&e)
            } else {
                write_error(&e)
            }
        }
        other => Error::invalid_args(format!("7z: {other:?}")),
    }
}

impl SevenZWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: &SevenZWriteOptions) -> Result<Self> {
        let level = opts.resolve_level()?;
        let level_u = level.and_then(|l| u32::try_from(l).ok()).unwrap_or(0);
        let method: EncoderConfiguration = match opts.method {
            SevenZMethod::Lzma2 => {
                let threads = match opts.threads {
                    0 => std::thread::available_parallelism()
                        .map(|n| u32::try_from(n.get()).unwrap_or(1))
                        .unwrap_or(1),
                    n => n,
                };
                if threads > 1 {
                    // Chunks of three dictionaries, as xz does.
                    Lzma2Options::from_level_mt(level_u, threads, 3 * opts.dictionary()).into()
                } else {
                    Lzma2Options::from_level(level_u).into()
                }
            }
            SevenZMethod::Lzma => LzmaOptions::from_level(level_u).into(),
            SevenZMethod::Ppmd => PpmdOptions::from_level(level_u).into(),
            SevenZMethod::Bzip2 => Bzip2Options::from_level(level_u).into(),
            SevenZMethod::Deflate => DeflateOptions::from_level(level_u).into(),
            SevenZMethod::Copy => EncoderConfiguration::new(EncoderMethod::COPY),
        };
        let mut methods = Vec::new();
        if let Some(pw) = &opts.password {
            if pw.is_empty() {
                return Err(Error::invalid_args("the password is empty"));
            }
            methods.push(AesEncoderOptions::new(Password::new(pw)).into());
        }
        methods.push(method.clone());
        let mut w = sevenz_rust2::ArchiveWriter::new(out).map_err(sz_write_error)?;
        w.set_content_methods(methods.clone());
        w.set_encrypt_header(opts.encrypt_headers && opts.password.is_some());
        Ok(Self {
            w,
            block_limit: opts.solid.then(|| opts.block_limit()),
            methods,
            method,
        })
    }

    /// Encodes `entries` (a block's kept entries, renamed, with their metadata) as one block,
    /// reading their data from `feed` in order. An encrypted block is encrypted again with the
    /// password that decoded it; the others get the method alone.
    fn push_reencoded(
        &mut self,
        entries: Vec<ArchiveEntry>,
        feed: BlockFeed,
        password: Option<&str>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut methods = Vec::new();
        if let Some(pw) = password {
            methods.push(AesEncoderOptions::new(Password::new(pw)).into());
        }
        methods.push(self.method.clone());
        self.w.set_content_methods(methods);
        let shared = RefCell::new(FeedShared {
            first: Some(feed.first),
            rx: feed.rx,
            cx,
        });
        let shared = &shared;
        let readers: Vec<SourceReader<FeedRead<'_, '_>>> = (0..entries.len())
            .map(|_| SourceReader::new(FeedRead { shared, cur: None }))
            .collect();
        let pushed = self
            .w
            .push_archive_entries(entries, readers)
            .map(|_| ())
            .map_err(sz_write_error);
        self.w.set_content_methods(self.methods.clone());
        pushed
    }
}

/// A block being decoded on a helper thread for [`SevenZWriter::push_reencoded`]: the first
/// kept entry's data, already started, then the others' as the thread reaches them.
struct BlockFeed {
    first: crate::io::PipeReader,
    rx: std::sync::mpsc::Receiver<Result<crate::io::PipeReader>>,
}

struct FeedShared<'c> {
    first: Option<crate::io::PipeReader>,
    rx: std::sync::mpsc::Receiver<Result<crate::io::PipeReader>>,
    cx: &'c mut dyn Ctx,
}

/// One kept entry's data from a [`BlockFeed`], taken on its first read. Checks for
/// cancellation (which reports progress) before every read.
struct FeedRead<'s, 'c> {
    shared: &'s RefCell<FeedShared<'c>>,
    cur: Option<crate::io::PipeReader>,
}

impl Read for FeedRead<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cur.is_none() {
            let mut shared = self.shared.borrow_mut();
            shared.cx.check().map_err(Error::into_io)?;
            let next = match shared.first.take() {
                Some(r) => r,
                None => match shared.rx.recv() {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => return Err(e.into_io()),
                    Err(_) => {
                        return Err(Error::corrupt("the 7z decoder stopped early").into_io());
                    }
                },
            };
            self.cur = Some(next);
        } else {
            self.shared
                .borrow_mut()
                .cx
                .check()
                .map_err(Error::into_io)?;
        }
        match self.cur.as_mut() {
            Some(r) => r.read(buf),
            None => Ok(0),
        }
    }
}

/// The archive input for `push_raw_block`, checking for cancellation (and reporting progress)
/// before every read.
struct CheckedInput<'a> {
    inner: &'a mut Input,
    cx: &'a mut dyn Ctx,
}

impl Read for CheckedInput<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.cx.check().map_err(Error::into_io)?;
        self.inner.read(buf)
    }
}

impl io::Seek for CheckedInput<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl SevenZReader {
    /// The password that opened the archive or decoded a block, which the header and new blocks
    /// of an edit are encrypted with when the archive's header was (docs/M5.md §3.7).
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// The names are encrypted.
    pub fn encrypted_header(&self) -> bool {
        self.header.encrypted
    }

    /// Writes `keep` into `w` (docs/M5.md §3.4): blocks whose entries all stay are copied as they
    /// are, renamed through `push_raw_block`; entries without data are written again with their
    /// metadata; a block that loses an entry is decoded, and the entries it keeps are encoded
    /// again into one block.
    fn copy_into(
        &mut self,
        w: &mut SevenZWriter,
        keep: &[Keep],
        cx: &mut dyn Ctx,
    ) -> Result<Copied> {
        let archive = Arc::clone(&self.archive);
        let files = &archive.files;
        let map = &archive.stream_map.file_block_index;
        // The name each kept file is written under: its own bytes when unchanged.
        let mut names: Vec<Option<String>> = vec![None; files.len()];
        for k in keep {
            if let (Some(&f), Some(e)) = (self.file_of.get(k.id), self.entries.get(k.id)) {
                names[f] = Some(if k.path == e.path {
                    files[f].name.clone()
                } else {
                    k.path.clone()
                });
            }
        }
        let mut copied = Copied::default();
        let mut input = self.source.input()?;
        let mut done = vec![false; archive.blocks.len()];
        for f in 0..files.len() {
            cx.check()?;
            let file = &files[f];
            if file.is_anti_item {
                continue;
            }
            match map[f] {
                Some(b) if file.has_stream => {
                    if done.get(b).copied().unwrap_or(true) {
                        continue;
                    }
                    done[b] = true;
                    let members: Vec<usize> = self.blocks[b]
                        .files
                        .clone()
                        .filter(|&i| files[i].has_stream && map[i] == Some(b))
                        .collect();
                    let kept = members.iter().filter(|&&i| names[i].is_some()).count();
                    if kept == 0 {
                        continue;
                    }
                    if kept == members.len() {
                        let mut order = members
                            .iter()
                            .map(|&i| names[i].clone().unwrap_or_default())
                            .collect::<Vec<_>>()
                            .into_iter();
                        let mut src = CheckedInput {
                            inner: &mut input,
                            cx,
                        };
                        w.w.push_raw_block(&archive, b, &mut src, |_| {
                            order.next().unwrap_or_default()
                        })
                        .map_err(sz_write_error)?;
                        copied.copied += kept as u64;
                    } else {
                        self.reencode(w, b, &names, cx)?;
                        copied.recompressed += kept as u64;
                    }
                }
                _ => {
                    if let Some(name) = &names[f] {
                        let mut e = file.clone();
                        e.name = name.clone();
                        w.w.push_archive_entry::<&[u8]>(e, None)
                            .map_err(sz_write_error)?;
                        copied.copied += 1;
                    }
                }
            }
        }
        Ok(copied)
    }

    /// Decodes block `b` and encodes the entries `names` keeps again, as one block. A wrong
    /// password shows before anything is written, so it is asked again.
    fn reencode(
        &mut self,
        w: &mut SevenZWriter,
        b: usize,
        names: &[Option<String>],
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        self.check_memory(b)?;
        let archive = Arc::clone(&self.archive);
        let range = self.blocks[b].files.clone();
        let keep: Vec<bool> = range
            .clone()
            .map(|i| {
                archive.files[i].has_stream
                    && archive.stream_map.file_block_index[i] == Some(b)
                    && names[i].is_some()
            })
            .collect();
        let entries: Vec<ArchiveEntry> = range
            .clone()
            .zip(&keep)
            .filter(|(_, k)| **k)
            .map(|(i, _)| {
                let mut e = archive.files[i].clone();
                e.name = names[i].clone().unwrap_or_default();
                e
            })
            .collect();
        let first = range
            .clone()
            .zip(&keep)
            .find(|(_, k)| **k)
            .and_then(|(i, _)| self.entry_of[i])
            .map(|id| self.entries[id].path.clone())
            .unwrap_or_default();
        let encrypted = self.blocks[b].encrypted;
        let mut failed = 0u32;
        loop {
            cx.check()?;
            let pw = if encrypted {
                Some(self.block_password(&first, failed, cx)?)
            } else {
                None
            };
            let rx = self.spawn_block_copy(b, keep.clone(), pw.clone())?;
            let started = match rx.recv() {
                Ok(Ok(mut r)) => match r.first_error() {
                    Some(e) => Err(e),
                    None => Ok(r),
                },
                Ok(Err(e)) => Err(e),
                Err(_) => Err(Error::corrupt("the 7z decoder stopped early")),
            };
            match started {
                Err(e) if encrypted && e.kind == ErrorKind::WrongPassword => {
                    failed += 1;
                    self.password = None;
                }
                Err(e) => return Err(e),
                Ok(first) => {
                    if pw.is_some() {
                        self.password.clone_from(&pw);
                    }
                    let feed = BlockFeed { first, rx };
                    return w.push_reencoded(entries, feed, pw.as_deref(), cx);
                }
            }
        }
    }

    /// Decodes block `b` on a helper thread with its own input. Each file of the block's range
    /// that `keep` marks gets a pipe, sent before its data is written to it; the others are
    /// read and dropped. A failure outside an entry's data comes through the channel.
    fn spawn_block_copy(
        &self,
        b: usize,
        keep: Vec<bool>,
        password: Option<String>,
    ) -> Result<std::sync::mpsc::Receiver<Result<crate::io::PipeReader>>> {
        let archive = Arc::clone(&self.archive);
        let mut input = self.source.open_file()?;
        let threads = self.threads(b);
        let encrypted = self.blocks[b].encrypted;
        let last = keep.iter().rposition(|&k| k).unwrap_or(0);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("beezip-7z-edit".into())
            .spawn(move || {
                let password = password
                    .as_deref()
                    .map_or_else(Password::empty, Password::new);
                let decoder = BlockDecoder::new(threads, b, &archive, &password, &mut input);
                let mut slot: Option<Error> = None;
                let mut k = 0usize;
                let result = decoder.for_each_entries(&mut |_, data: &mut dyn Read| {
                    let at = k;
                    k += 1;
                    let mut tagged = DecodeTag::new(data, encrypted);
                    if keep.get(at).copied().unwrap_or(false) {
                        let (mut out, reader) = pipe(4, BUF_SIZE);
                        if tx.send(Ok(reader)).is_err() {
                            slot = Some(Error::cancelled());
                            return Err(sevenz_rust2::Error::Other("stopped".into()));
                        }
                        match io::copy(&mut tagged, &mut out) {
                            Ok(_) => out.finish(Ok(())),
                            Err(e) => {
                                let err = read_error(&e);
                                out.finish(Err(err.clone()));
                                slot = Some(err);
                                return Err(sevenz_rust2::Error::Other("decode".into()));
                            }
                        }
                    } else if let Err(e) = io::copy(&mut tagged, &mut io::sink()) {
                        slot = Some(read_error(&e));
                        return Err(sevenz_rust2::Error::Other("decode".into()));
                    }
                    Ok(at < last)
                });
                if let Err(e) = result {
                    let err = slot.take().unwrap_or_else(|| sz_error(e, encrypted));
                    let _ = tx.send(Err(err));
                }
            })
            .map_err(|e| Error::io("starting the 7z decoder", &e))?;
        Ok(rx)
    }
}

fn new_entry(entry: &NewEntry) -> ArchiveEntry {
    let mut e = match entry.kind {
        NewKind::Dir => ArchiveEntry::new_directory(&entry.path),
        _ => ArchiveEntry::new_file(&entry.path),
    };
    if let Some(t) = entry.modified {
        e.last_modified_date = NtTime::from(to_ntfs(t));
        e.has_last_modified_date = true;
    }
    let dos = entry.dos_attrs.unwrap_or(0) & 0xFFFF;
    let attrs = match (&entry.kind, entry.unix_mode) {
        (NewKind::Symlink { .. }, _) => UNIX_EXTENSION | ((S_IFLNK | 0o777) << 16) | ATTR_ARCHIVE,
        (kind, Some(mode)) if cfg!(unix) => {
            let mut a = UNIX_EXTENSION | ((mode & 0xFFFF) << 16);
            if *kind == NewKind::Dir {
                a |= ATTR_DIRECTORY;
            } else {
                a |= ATTR_ARCHIVE;
            }
            if mode & 0o200 == 0 {
                a |= ATTR_READONLY;
            }
            a
        }
        (NewKind::Dir, _) => dos | ATTR_DIRECTORY,
        (_, _) => dos & !ATTR_DIRECTORY,
    };
    e.windows_attributes = attrs;
    e.has_windows_attributes = true;
    e
}

/// What every reader of a solid block shares: they are read one after another.
struct SolidShared<'o, 'c> {
    open: &'o mut dyn FnMut(usize) -> Result<Box<dyn Read>>,
    cx: &'c mut dyn Ctx,
}

/// Opens its file on first read, and checks for cancellation (which reports progress) before
/// every read, for `add_solid`.
struct LazyRead<'s, 'o, 'c> {
    i: usize,
    shared: &'s RefCell<SolidShared<'o, 'c>>,
    file: Option<Box<dyn Read>>,
}

impl Read for LazyRead<'_, '_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut shared = self.shared.borrow_mut();
        shared.cx.check().map_err(Error::into_io)?;
        if self.file.is_none() {
            let f = (shared.open)(self.i).map_err(Error::into_io)?;
            self.file = Some(f);
        }
        drop(shared);
        match self.file.as_mut() {
            Some(f) => f.read(buf),
            None => Ok(0),
        }
    }
}

impl ArchiveWriter for SevenZWriter {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let e = new_entry(entry);
        let pushed = match &entry.kind {
            NewKind::Dir => self.w.push_archive_entry::<&[u8]>(e, None),
            NewKind::Symlink { target } => self.w.push_archive_entry(e, Some(target.as_bytes())),
            NewKind::File if entry.size == 0 => {
                // Drain it anyway, so a file that grew isn't silently cut: 7-Zip stores empty
                // files without a stream.
                let mut probe = [0u8; 1];
                if data.read(&mut probe).map_err(|e| read_error(&e))? > 0 {
                    let rest = io::Cursor::new(probe).chain(data);
                    self.w
                        .push_archive_entry(e, Some(crate::io::Checked::new(rest, cx)))
                } else {
                    self.w.push_archive_entry::<&[u8]>(e, None)
                }
            }
            NewKind::File => self
                .w
                .push_archive_entry(e, Some(crate::io::Checked::new(data, cx))),
        };
        pushed.map(|_| ()).map_err(sz_write_error)
    }

    fn solid_block_limit(&self) -> Option<u64> {
        self.block_limit
    }

    fn copy_from(
        &mut self,
        source: &mut dyn ArchiveReader,
        keep: &[Keep],
        cx: &mut dyn Ctx,
    ) -> Result<Copied> {
        match source.as_any_mut().downcast_mut::<SevenZReader>() {
            Some(r) => r.copy_into(self, keep, cx),
            None => Ok(Copied::nothing(keep)),
        }
    }

    fn add_solid(
        &mut self,
        entries: &[NewEntry],
        open: &mut dyn FnMut(usize) -> Result<Box<dyn Read>>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let shared = RefCell::new(SolidShared { open, cx });
        let shared = &shared;
        let items: Vec<ArchiveEntry> = entries.iter().map(new_entry).collect();
        let readers: Vec<SourceReader<LazyRead<'_, '_, '_>>> = (0..entries.len())
            .map(move |i| {
                SourceReader::new(LazyRead {
                    i,
                    shared,
                    file: None,
                })
            })
            .collect();
        self.w
            .push_archive_entries(items, readers)
            .map(|_| ())
            .map_err(sz_write_error)
    }

    fn finish(self: Box<Self>) -> Result<()> {
        let mut out = self.w.finish().map_err(|e| write_error(&e))?;
        io::Write::flush(&mut out).map_err(|e| write_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reparse_buffers() {
        // `link -> hello.txt`, as 7-Zip 26.00 stores a Windows symlink with -snl.
        let name: Vec<u8> = "hello.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
        buf.extend_from_slice(&((12 + 2 * name.len()) as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        for v in [
            0u16,
            name.len() as u16,
            name.len() as u16,
            name.len() as u16,
        ] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&name);
        buf.extend_from_slice(&name);
        assert_eq!(buf.len(), 56);
        assert_eq!(reparse_target(&buf).as_deref(), Some("hello.txt"));
        assert_eq!(reparse_target(b"\x01\x02\x03\x04rest"), None);
        assert_eq!(reparse_target(b""), None);
    }

    #[test]
    fn signatures() {
        let mut head = SIGNATURE.to_vec();
        head.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
        head.resize(32, 0);
        assert_eq!(start_header(&head[..8]), Some(Confidence::Likely));
        let crc = crc32fast::hash(&head[12..32]);
        head[8..12].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(start_header(&head), Some(Confidence::Certain));
        head[6] = 1;
        assert_eq!(start_header(&head), None);
    }

    #[test]
    fn block_limits() {
        let o = SevenZWriteOptions::default();
        assert_eq!(o.resolve_level().unwrap(), Some(5));
        assert_eq!(o.dictionary(), 8 << 20);
        assert_eq!(o.block_limit(), 64 << 20);
        let nine = SevenZWriteOptions {
            level: Some(9),
            ..o.clone()
        };
        assert_eq!(nine.block_limit(), 256 << 20);
        let bad = SevenZWriteOptions {
            level: Some(10),
            ..o
        };
        assert!(bad.resolve_level().is_err());
    }
}
