//! LHA, also called LZH (docs/M5.md §5.6), read only, through delharc 0.8.0. This is the only
//! file that names `delharc`.
//!
//! - **delharc** reads lh0, lh1, lh4–lh7, lhx, lzs, lz4, lz5, pm0–pm2 and directories, with
//!   header levels 0–3, from a plain `Read`. Its `no-unsafe-assertions` turns its unchecked
//!   bounds hints into checks.
//! - **Names** come from the raw bytes (the name field, and the extended headers `0x01` and
//!   `0x02`) through the source's `NameDecoding` (docs/M5.md §6), since delharc's own paths
//!   escape non-ASCII and split Shift-JIS names at a `0x5C` trail byte: each part is decoded,
//!   then its `\` become `/`. The UTF-16 name headers `0x44` and `0x45` win when present.
//! - **Symlinks** are `-lhd-` entries with a link's mode and a name `name|target`; delharc
//!   reports them as folders.
//! - **The CRC-16** of each file is checked when its data has been read.
//! - **LHA SFX** executables are found through detection's overlay scan.

use std::io::{self, BufReader, Read, Seek, SeekFrom};

use delharc::{LhaDecodeReader, LhaHeader, header::TimestampResult};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, Counter, CountingReader},
    names::{NameDecoding, SystemPage},
    source::Source,
    time::{DosClock, DosTime, from_unix},
};

pub struct Lzh;

const EXT_FILENAME: u8 = 0x01;
const EXT_PATH: u8 = 0x02;
/// UTF-16LE file and directory names (LHA for Windows, LHAPLUS), as libarchive reads them.
const EXT_UTF16_FILENAME: u8 = 0x44;
const EXT_UTF16_PATH: u8 = 0x45;
const OS_AMIGA: u8 = b'A';
const OS_GENERIC: u8 = 0;
const S_IFMT: u16 = 0o170_000;
const S_IFLNK: u16 = 0o120_000;

impl ArchiveFormat for Lzh {
    fn id(&self) -> FormatId {
        FormatId::Lzh
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".lzh", ".lha"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        header_at(probe.head)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}

/// An LHA header at the start of `head`: `-lh?-`, `-lz?-` or `-pm?-` at offset 2, and a header
/// delharc parses, checksum included. Detection also looks at a PE overlay with it (LHA SFX).
pub fn header_at(head: &[u8]) -> Option<Confidence> {
    let m = head.get(2..7)?;
    let method = m[0] == b'-'
        && m[4] == b'-'
        && matches!((m[1], m[2]), (b'l', b'h' | b'z') | (b'p', b'm'))
        && m[3].is_ascii_alphanumeric();
    if !method {
        return None;
    }
    let mut r = head;
    matches!(LhaHeader::read(&mut r), Ok(Some(_))).then_some(Confidence::Certain)
}

fn lha_error(e: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("lzh: {e}"))
}

/// The method's name, for the listing.
fn method_name(m: &[u8; 5]) -> Option<&'static str> {
    Some(match m {
        b"-lh0-" => "lh0",
        b"-lh1-" => "lh1",
        b"-lh2-" => "lh2",
        b"-lh3-" => "lh3",
        b"-lh4-" => "lh4",
        b"-lh5-" => "lh5",
        b"-lh6-" => "lh6",
        b"-lh7-" => "lh7",
        b"-lhx-" => "lhx",
        b"-lhd-" => "lhd",
        b"-lzs-" => "lzs",
        b"-lz4-" => "lz4",
        b"-lz5-" => "lz5",
        b"-pm0-" => "pm0",
        b"-pm1-" => "pm1",
        b"-pm2-" => "pm2",
        _ => return None,
    })
}

fn utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .collect();
    String::from_utf16_lossy(&units)
        .replace(['\u{FFFF}', '\\'], "/")
        .trim_end_matches('\0')
        .to_owned()
}

/// The entry's path, raw bytes and a symlink's target, from the header's own bytes.
fn names(h: &LhaHeader, nd: &NameDecoding) -> (String, Vec<u8>, Option<String>) {
    let decode = |b: &[u8]| nd.decode(b, false, SystemPage::Ansi).replace('\\', "/");
    let mut dir: Option<&[u8]> = None;
    let mut name: Option<&[u8]> = None;
    let (mut udir, mut uname) = (None, None);
    for ext in h.iter_extra() {
        match ext {
            [EXT_FILENAME, data @ ..] => name = Some(data),
            [EXT_PATH, data @ ..] => dir = Some(data),
            [EXT_UTF16_FILENAME, data @ ..] => uname = Some(utf16(data)),
            [EXT_UTF16_PATH, data @ ..] => udir = Some(utf16(data)),
            _ => {}
        }
    }
    let field: &[u8] = &h.filename;
    // Amiga's, and level 0's from unknown systems, may hold a comment after a NUL.
    let field = if h.os_type == OS_AMIGA || (h.level == 0 && h.os_type == OS_GENERIC) {
        field.split(|&b| b == 0).next().unwrap_or_default()
    } else {
        field
    };
    let name_bytes = name.unwrap_or(field);
    let name_bytes = name_bytes.split(|&b| b == 0).next().unwrap_or_default();
    // The directory header separates its parts with 0xFF, which no code page uses in a name.
    let dir_parts: Vec<&[u8]> = dir
        .map(|d| {
            d.split(|&b| b == 0)
                .next()
                .unwrap_or_default()
                .split(|&b| b == 0xFF)
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let mut raw: Vec<u8> = dir_parts.join(&b'/');
    if !raw.is_empty() && !name_bytes.is_empty() {
        raw.push(b'/');
    }
    raw.extend_from_slice(name_bytes);

    // Each part from its UTF-16 header when it has one: a writer may give the folder in UTF-16
    // and the name only in bytes (libarchive's `filename_utf16` does).
    let dir = udir.unwrap_or_else(|| {
        dir_parts
            .iter()
            .map(|d| decode(d))
            .collect::<Vec<_>>()
            .join("/")
    });
    let name = uname.unwrap_or_else(|| decode(name_bytes));
    let dir = dir.trim_end_matches('/');
    let mut path = match (dir.is_empty(), name.is_empty()) {
        (true, _) => name,
        (false, true) => dir.to_owned(),
        (false, false) => format!("{dir}/{name}"),
    };
    let link = h
        .parse_unix_permissions()
        .is_some_and(|p| p.bits() & S_IFMT == S_IFLNK);
    let mut target = None;
    if link && let Some((p, t)) = path.split_once('|') {
        target = Some(t.to_owned());
        path = p.to_owned();
        if let Some(i) = raw.iter().position(|&b| b == b'|') {
            raw.truncate(i);
        }
    }
    (path, raw, target)
}

fn modified(h: &LhaHeader, clock: &mut DosClock) -> Option<std::time::SystemTime> {
    match h.parse_last_modified() {
        TimestampResult::Utc(t) => from_unix(t.timestamp(), t.timestamp_subsec_nanos()),
        // Levels 0 and 1 store an MS-DOS time, which is local.
        TimestampResult::Naive(_) => clock.read(DosTime {
            date: (h.last_modified >> 16) as u16,
            time: h.last_modified as u16,
        }),
        TimestampResult::None => None,
    }
}

fn entry_for(id: usize, h: &LhaHeader, nd: &NameDecoding, clock: &mut DosClock) -> Entry {
    let (path, raw, target) = names(h, nd);
    let kind = match target {
        Some(target) => EntryKind::Symlink { target },
        None if h.is_directory() => EntryKind::Dir,
        None => EntryKind::File,
    };
    let is_file = kind == EntryKind::File;
    let path = if kind == EntryKind::Dir && !path.ends_with('/') {
        format!("{path}/")
    } else {
        path
    };
    Entry {
        id,
        path,
        raw_path: raw,
        size: is_file.then_some(h.original_size),
        packed_size: is_file.then_some(h.compressed_size),
        modified: modified(h, clock),
        crc32: None,
        method: method_name(&h.compression),
        encrypted: false,
        unix_mode: h.parse_unix_permissions().map(|p| u32::from(p.bits())),
        dos_attrs: Some(u32::from(h.msdos_attrs.bits())),
        kind,
    }
}

/// Reads the decoder to its end, checking the CRC-16 there.
struct Checked<'a, R: Read> {
    lha: &'a mut LhaDecodeReader<R>,
    path: String,
}

impl<R: Read> Read for Checked<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.lha.read(buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("lzh: `{}`: {e}", self.path),
            )
        })?;
        if n == 0 && !buf.is_empty() && !self.lha.crc_is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("lzh: `{}` doesn't match its CRC-16", self.path),
            ));
        }
        Ok(n)
    }
}

pub struct LzhReader {
    source: Source,
    entries: Vec<Entry>,
    /// Each header's place in the file, for a plain one.
    offsets: Vec<u64>,
    lha: Option<LhaDecodeReader<Box<dyn Read + Send>>>,
}

impl LzhReader {
    /// Reads every header, skipping the data where the file can seek.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let mut r = Self {
            source,
            entries: Vec::new(),
            offsets: Vec::new(),
            lha: None,
        };
        r.list(cx)?;
        Ok(r)
    }

    fn plain(&self) -> bool {
        self.source.codecs.is_empty()
    }

    fn stream(&self) -> Result<Box<dyn Read + Send>> {
        if self.plain() {
            Ok(Box::new(BufReader::with_capacity(
                BUF_SIZE,
                self.source.open_file()?,
            )))
        } else {
            self.source.open_stream()
        }
    }

    fn list(&mut self, cx: &mut dyn Ctx) -> Result<()> {
        let pos = Counter::new();
        let mut r = CountingReader::new(self.stream()?, pos.clone());
        let mut clock = DosClock::default();
        let names = self.source.names;
        loop {
            cx.check()?;
            let at = pos.get();
            let h = match LhaHeader::read(&mut r) {
                Ok(Some(h)) => h,
                // A zero byte, or the end of the file, ends the archive. Anything else must be a
                // header, as libarchive requires too.
                Ok(None) => break,
                Err(e) => return Err(lha_error(format!("the header at byte {at}: {e}"))),
            };
            let id = self.entries.len();
            self.source.limits.check_entries(id as u64 + 1)?;
            if self.plain() && pos.get().saturating_add(h.compressed_size) > self.source.size {
                return Err(lha_error(format!(
                    "an entry of {} bytes runs past the end of the file",
                    h.compressed_size
                )));
            }
            self.entries.push(entry_for(id, &h, &names, &mut clock));
            self.offsets.push(at);
            let n = io::copy(&mut (&mut r).take(h.compressed_size), &mut io::sink())
                .map_err(|e| crate::io::read_error(&e).context("lzh"))?;
            if n != h.compressed_size {
                return Err(lha_error("the archive is cut short"));
            }
        }
        if self.entries.is_empty() {
            return Err(lha_error("the archive has no entries"));
        }
        Ok(())
    }

    /// A decoder positioned at entry `id`'s header.
    fn decoder_at(
        &self,
        id: usize,
        cx: &mut dyn Ctx,
    ) -> Result<LhaDecodeReader<Box<dyn Read + Send>>> {
        if self.plain() {
            let mut file = BufReader::with_capacity(BUF_SIZE, self.source.open_file()?);
            file.seek(SeekFrom::Start(self.offsets[id]))
                .map_err(|e| Error::io("seeking in the archive", &e))?;
            let r: Box<dyn Read + Send> = Box::new(file);
            return LhaDecodeReader::new(r).map_err(lha_error);
        }
        let mut lha = LhaDecodeReader::new(self.stream()?).map_err(lha_error)?;
        for _ in 0..id {
            cx.check()?;
            if !lha.next_file().map_err(lha_error)? {
                return Err(lha_error("an entry vanished on a second pass"));
            }
        }
        Ok(lha)
    }
}

/// An entry's data: delharc's decoder with the CRC-16 checked, or an error for a method it
/// doesn't have.
fn data<'a, R: Read>(lha: &'a mut LhaDecodeReader<R>, e: &Entry) -> Result<Checked<'a, R>> {
    if !lha.is_decoder_supported() {
        return Err(Error::unsupported_format(format!(
            "`{}` is compressed with {}, which BeeZip can't decode",
            e.path,
            String::from_utf8_lossy(&lha.header().compression)
        )));
    }
    Ok(Checked {
        lha,
        path: e.path.clone(),
    })
}

impl ArchiveReader for LzhReader {
    fn format(&self) -> FormatId {
        FormatId::Lzh
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods: Vec<&'static str> = Vec::new();
        for m in self
            .entries
            .iter()
            .filter(|e| e.is_file())
            .filter_map(|e| e.method)
        {
            if !methods.contains(&m) {
                methods.push(m);
            }
        }
        Ok(ArchiveInfo {
            format: FormatId::Lzh,
            codecs: self.source.codecs.clone(),
            methods,
            comment: None,
            encryption: Encryption::None,
            solid: false,
            sfx: self.source.offset > 0,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
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
        let mut lha = LhaDecodeReader::new(self.stream()?).map_err(lha_error)?;
        for (id, e) in self.entries.iter().enumerate() {
            cx.check()?;
            if id > 0 && !lha.next_file().map_err(lha_error)? {
                return Err(lha_error("an entry vanished on a second pass"));
            }
            if !sel.matches(e) {
                continue;
            }
            meter.entries_done = id as u64;
            meter.current = Some(e.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            if e.kind == EntryKind::File {
                let mut d = self.source.guard(data(&mut lha, e)?);
                sink.entry(e, &mut d, &mut mcx)?;
            } else {
                sink.entry(e, &mut io::empty(), &mut mcx)?;
            }
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let e = self
            .entries
            .get(id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        if e.kind != EntryKind::File {
            return Ok(Box::new(io::empty()));
        }
        let lha = self.decoder_at(id, cx)?;
        let lha = self.lha.insert(lha);
        Ok(Box::new(self.source.guard(data(lha, &e)?)))
    }
}

trait IsFile {
    fn is_file(&self) -> bool;
}

impl IsFile for Entry {
    fn is_file(&self) -> bool {
        self.kind == EntryKind::File
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A level-0 header: size, checksum, method, sizes, DOS time, attribute, level, name, CRC.
    fn level0(name: &[u8], method: &[u8; 5], data: &[u8], crc: u16) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(method);
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&0x5A21_6000u32.to_le_bytes());
        h.push(0x20);
        h.push(0);
        h.push(name.len() as u8);
        h.extend_from_slice(name);
        h.extend_from_slice(&crc.to_le_bytes());
        let sum = h.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        let mut out = vec![h.len() as u8, sum];
        out.extend(h);
        out.extend_from_slice(data);
        out
    }

    fn crc16(data: &[u8]) -> u16 {
        let mut crc = 0u16;
        for &b in data {
            crc ^= u16::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xA001
                } else {
                    crc >> 1
                };
            }
        }
        crc
    }

    #[test]
    fn sniffs_headers() {
        let a = level0(b"a.txt", b"-lh0-", b"hi", crc16(b"hi"));
        assert_eq!(header_at(&a), Some(Confidence::Certain));
        let mut bad = a.clone();
        bad[1] ^= 1;
        assert_eq!(header_at(&bad), None, "checksum");
        assert_eq!(header_at(b"\0\0-lh5-"), None);
        assert_eq!(header_at(b"MZ"), None);
    }

    /// An LHA archive at the overlay of an executable, where LHA SFX modules put theirs.
    #[test]
    fn an_lha_sfx_is_found_in_the_overlay() {
        let mut lzh = level0(b"a.txt", b"-lh0-", b"hello", crc16(b"hello"));
        lzh.extend(level0(b"b.txt", b"-lh0-", b"", crc16(b"")));
        lzh.push(0);
        // The least PE image: one section, ending at 0x400, where the overlay starts.
        let mut exe = vec![0u8; 0x400];
        exe[..2].copy_from_slice(b"MZ");
        exe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        exe[0x80..0x84].copy_from_slice(b"PE\0\0");
        exe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        let section = 0x80 + 24;
        exe[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        exe[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        exe.extend_from_slice(&lzh);
        let det = crate::detect_bytes(&exe, Some("setup.exe"), &crate::Limits::default());
        assert_eq!(det.format(), Some(FormatId::Lzh));
        assert!(det.sfx);
        assert_eq!(det.offset, 0x400);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.exe");
        std::fs::write(&path, &exe).unwrap();
        let mut cx = crate::SimpleCtx::new();
        let mut opened = crate::open(&path, &crate::OpenOptions::default(), &mut cx).unwrap();
        assert!(opened.reader.info(&mut cx).unwrap().sfx);
        let names: Vec<String> = opened
            .reader
            .entries(&mut cx)
            .unwrap()
            .iter()
            .map(|e| e.path.clone())
            .collect();
        assert_eq!(names, ["a.txt", "b.txt"]);
        let mut data = Vec::new();
        opened
            .reader
            .open_entry(0, &mut cx)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn shift_jis_names_keep_their_trail_bytes() {
        // ソ is 83 5C in Shift-JIS: its trail byte is a backslash.
        let name = [0x83, 0x5C, b'\\', b'a'];
        let a = level0(&name, b"-lh0-", b"x", crc16(b"x"));
        let h = LhaHeader::read(&mut &a[..]).unwrap().unwrap();
        let nd = NameDecoding {
            encoding: crate::NameEncoding::from_name("cp932").unwrap(),
            ..NameDecoding::default()
        };
        assert_eq!(names(&h, &nd).0, "ソ/a");
    }
}
