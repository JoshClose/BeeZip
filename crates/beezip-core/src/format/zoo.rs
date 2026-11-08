//! ZOO (docs/M6.md §4), read only. Headers taken in from unarc-rs 0.8.1's `zoo` module,
//! © Mike Krüger, MIT, as BeeZip's own code; its LZW is BeeZip's `.Z` decoder
//! ([`Lzw::ZOO`]), and LH5 is delharc's.
//!
//! - **The archive** is a header (text, the tag `0xFDC4A7DC` at 20, the first directory entry's
//!   offset and its negation, an archive comment), then a chain of directory entries linked by
//!   offsets, ending at one whose `next` is 0. The chain must go forward: a cycle, or a link
//!   back, is `Corrupt`, as is an offset past the end of the file. Entries whose data overlaps
//!   are `Unsafe`, as in zip.
//! - **Entries:** type 1 (zoo 1.x) has an 8.3 name; type 2 adds a variable part with a long name,
//!   a folder, the system's attributes and a generation number, and a time zone. unarc-rs read
//!   that part with the wrong field sizes (`var_dir_len` and `dir_crc` are two bytes) and left
//!   the long names and folders out. Names are bytes, decoded as OEM through `NameDecoding`, `\`
//!   read as `/`; type 2 ends each with a NUL.
//! - **Deleted entries** are skipped. **Generations:** an archive with them on keeps older copies
//!   of a file; as `zoo l` does, BeeZip lists only the latest of each path (the highest
//!   generation number), and extracts that.
//! - **Times** are DOS local times. A type-2 entry's time zone (quarter hours west of UTC) makes
//!   one a known UTC time, except 127 (none) and 0: Debian's zoo 2.10 writes 0 whatever the
//!   zone, beside a local time.
//! - **Methods:** 0 stored, 1 LZW, 2 LH5. Each entry's CRC-16 is checked when its data has been
//!   read, and its size.
//! - A ZOO behind a codec (`.zoo.gz`) is spooled to a temporary file first: entries are found
//!   by offset.

use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    time::{Duration, SystemTime},
};

use delharc::decode::{Decoder as _, DecoderAny};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    codec::compress::{Check16, Decoder as Lzd, Lzw},
    detect::{Confidence, Probe},
    io::{BUF_SIZE, CountingReader, copy},
    names::SystemPage,
    safefs::Partial,
    source::Source,
    time::{DosClock, DosTime},
};

pub struct Zoo;

/// The tag in a ZOO header and in each directory entry.
pub const ZOO_TAG: u32 = 0xFDC4_A7DC;
/// Size of header text
const SIZ_TEXT: usize = 20;
/// The header up to the versions, which every ZOO has.
const MIN_HEADER: usize = SIZ_TEXT + 4 + 10;
/// With a type-1 header's archive comment and version data.
const ZOO_HEADER_SIZE: usize = MIN_HEADER + 8;
/// Size of DOS filename
const FNAMESIZE: usize = 13;
/// End of the `next` field in a directory entry (tag: 4, type: 1, method: 1, next: 4)
const DIRENT_NEXT_END: usize = 10;
/// A type-1 directory entry.
const DIRENT_SIZE: usize = 38 + FNAMESIZE;
/// A type-2 entry's fixed part: then the variable part's length (2), the time zone (1) and the
/// entry's CRC (2).
const DIRENT2_SIZE: usize = DIRENT_SIZE + 5;
/// The most of a variable part read: its two lengths, two names of up to 255 bytes, the system,
/// attributes, version flags and generation.
const VAR_MAX: usize = 2 + 255 + 255 + 8;
/// The time zone of an entry that has none.
const NO_TZ: i8 = 127;
/// `fattr >> 22`: the low bits are Unix permissions.
const FATTR_UNIX: u32 = 1;
/// Version flags: generations are on for this file.
const VFL_ON: u8 = 0x80;
const S_IFREG: u32 = 0o100_000;

impl ArchiveFormat for Zoo {
    fn id(&self) -> FormatId {
        FormatId::Zoo
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".zoo"]
    }

    /// The tag at 20: with `ZOO ` text before it and a first entry where the header says,
    /// checked against its negation and the file's size, `Certain`; the tag alone, `Likely`.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let head = probe.head;
        if le32(head, SIZ_TEXT)? != ZOO_TAG {
            return None;
        }
        let start = le32(head, 24);
        let minus = le32(head, 28);
        let sane = matches!((start, minus), (Some(s), Some(m))
            if s.wrapping_add(m) == 0
                && s as usize >= MIN_HEADER
                && probe.len.is_none_or(|len| u64::from(s) < len));
        Some(if head.starts_with(b"ZOO ") && sane {
            Confidence::Certain
        } else {
            Confidence::Likely
        })
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn zoo_error(msg: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("zoo: {msg}"))
}

/// Up to a NUL.
fn cstr(b: &[u8]) -> &[u8] {
    b.split(|&c| c == 0).next().unwrap_or_default()
}

/// A directory entry, as far as BeeZip uses it.
#[derive(Debug, Clone, Default)]
struct DirectoryEntry {
    compression_method: u8,
    /// pos'n of next directory entry
    next: u32,
    /// position of this file
    offset: u32,
    date: u16,
    time: u16,
    file_crc16: u16,
    org_size: u32,
    size_now: u32,
    deleted: bool,
    /// The 8.3 name, without its NUL.
    name: Vec<u8>,
    /// timezone where file was archived (type 2)
    tz: Option<i8>,
    /// long filename (type 2), without its NUL
    lfname: Vec<u8>,
    /// directory name (type 2), without its NUL
    dirname: Vec<u8>,
    /// File attributes -- 24 bits
    fattr: Option<u32>,
    /// version flag bits
    vflag: u8,
    /// file version number if any
    version_no: u16,
}

impl DirectoryEntry {
    /// The entry in `b`, which holds what of it the file has, or `None` for the one that ends
    /// the chain.
    fn load_from(b: &[u8]) -> Result<Option<Self>> {
        let short = || zoo_error("a directory entry is cut short");
        if b.len() < DIRENT_NEXT_END {
            return Err(short());
        }
        if le32(b, 0) != Some(ZOO_TAG) {
            return Err(zoo_error("a directory entry has no ZOO tag"));
        }
        let next = le32(b, 6).ok_or_else(short)?;
        if next == 0 {
            return Ok(None);
        }
        if b.len() < DIRENT_SIZE {
            return Err(short());
        }
        let u16_at = |at| le16(b, at).unwrap_or_default();
        let u32_at = |at| le32(b, at).unwrap_or_default();
        let mut d = Self {
            compression_method: b[5],
            next,
            offset: u32_at(10),
            date: u16_at(14),
            time: u16_at(16),
            file_crc16: u16_at(18),
            org_size: u32_at(20),
            size_now: u32_at(24),
            deleted: b[30] != 0,
            name: cstr(&b[38..38 + FNAMESIZE]).to_vec(),
            ..Self::default()
        };
        if b[4] != 2 {
            return Ok(Some(d));
        }
        if b.len() < DIRENT2_SIZE {
            return Err(short());
        }
        let var_len = usize::from(u16_at(51)).min(VAR_MAX);
        d.tz = Some(b[53] as i8);
        let var = b
            .get(DIRENT2_SIZE..DIRENT2_SIZE + var_len)
            .ok_or_else(short)?;
        let namlen = usize::from(var.first().copied().unwrap_or(0));
        let dirlen = usize::from(var.get(1).copied().unwrap_or(0));
        let names = 2 + namlen + dirlen;
        if namlen + dirlen > 0 && var.len() < names {
            return Err(zoo_error("a long name runs past its directory entry"));
        }
        if namlen > 0 {
            d.lfname = cstr(&var[2..2 + namlen]).to_vec();
        }
        if dirlen > 0 {
            d.dirname = cstr(&var[2 + namlen..names]).to_vec();
        }
        // The system (2 bytes), attributes (3), version flags (1) and generation (2), each
        // there if the part is long enough.
        let rest = var.get(names..).unwrap_or_default();
        if let Some(a) = rest.get(2..5) {
            d.fattr = Some(u32::from(a[0]) | u32::from(a[1]) << 8 | u32::from(a[2]) << 16);
        }
        if let Some(v) = rest.get(5..8) {
            d.vflag = v[0];
            d.version_no = u16::from_le_bytes([v[1], v[2]]);
        }
        Ok(Some(d))
    }

    /// The path's bytes: the folder, a `/`, the long name or else the short one.
    fn raw_path(&self) -> Vec<u8> {
        let name = if self.lfname.is_empty() {
            &self.name
        } else {
            &self.lfname
        };
        let mut raw = self.dirname.clone();
        if !raw.is_empty() && !name.is_empty() && !matches!(raw.last(), Some(b'/' | b'\\')) {
            raw.push(b'/');
        }
        raw.extend_from_slice(name);
        raw
    }

    fn modified(&self, clock: &mut DosClock) -> Option<SystemTime> {
        let dos = DosTime {
            date: self.date,
            time: self.time,
        };
        match self.tz {
            Some(tz) if tz != NO_TZ && tz != 0 && (-56..=56).contains(&tz) => {
                let utc = dos_as_utc(dos)?;
                let shift = Duration::from_secs(u64::from(tz.unsigned_abs()) * 900);
                // West of UTC is positive: the time there is behind.
                if tz > 0 {
                    utc.checked_add(shift)
                } else {
                    utc.checked_sub(shift)
                }
            }
            _ => clock.read(dos),
        }
    }
}

/// A DOS date and time read as UTC.
fn dos_as_utc(dos: DosTime) -> Option<SystemTime> {
    use time::{Date, Month, PrimitiveDateTime, Time};
    let year = 1980 + i32::from(dos.date >> 9);
    let month = Month::try_from(u8::try_from((dos.date >> 5) & 0x0F).ok()?).ok()?;
    let day = u8::try_from(dos.date & 0x1F).ok()?;
    let hour = u8::try_from(dos.time >> 11).ok()?;
    let minute = u8::try_from((dos.time >> 5) & 0x3F).ok()?;
    let second = u8::try_from((dos.time & 0x1F) * 2).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let t = Time::from_hms(hour, minute, second.min(59)).ok()?;
    Some(PrimitiveDateTime::new(date, t).assume_utc().into())
}

fn method_name(m: u8) -> Cow<'static, str> {
    match m {
        0 => "Store".into(),
        1 => "LZW".into(),
        2 => "LH5".into(),
        m => format!("method {m}").into(),
    }
}

/// Where an entry's data is.
#[derive(Debug, Clone, Copy)]
struct Item {
    offset: u64,
    packed: u64,
    size: u64,
    crc: u16,
    method: u8,
}

trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// The archive through a buffer that a seek keeps when it lands inside it: a `BufReader`
/// drops its buffer on every absolute seek, and entries and their data are close together.
struct Archive {
    r: BufReader<Box<dyn ReadSeek>>,
    pos: u64,
}

impl Read for Archive {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Archive {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let relative = match to {
            SeekFrom::Start(at) => i64::try_from(at)
                .ok()
                .zip(i64::try_from(self.pos).ok())
                .map(|(a, p)| a - p),
            _ => None,
        };
        match relative {
            Some(d) => {
                self.r.seek_relative(d)?;
                self.pos = self.pos.saturating_add_signed(d);
            }
            None => self.pos = self.r.seek(to)?,
        }
        Ok(self.pos)
    }
}

/// LH5 through delharc, which needs to be told how much to decode: there is no end code.
struct Lh5<R: Read> {
    dec: DecoderAny<R>,
    left: u64,
}

impl<R: Read> Read for Lh5<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if n == 0 {
            return Ok(0);
        }
        self.dec
            .fill_buffer(&mut buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("LH5: {e}")))?;
        self.left -= n as u64;
        Ok(n)
    }
}

/// A reader that fails at once: an entry whose method BeeZip refuses, handed to the sink so a
/// test records it and goes on.
struct Refused(Option<Error>);

impl Read for Refused {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self
            .0
            .take()
            .unwrap_or_else(|| Error::unsupported("refused"))
            .into_io())
    }
}

/// Entry `e`'s data at `item` in `r`, decoded, with its size and CRC-16 checked at the end.
fn data<'a, R: Read + Seek + 'a>(mut r: R, item: Item, e: &Entry) -> Result<Box<dyn Read + 'a>> {
    let packed = match item.method {
        0..=2 => {
            r.seek(SeekFrom::Start(item.offset))
                .map_err(|err| Error::io("seeking in the archive", &err))?;
            r.take(item.packed)
        }
        m => {
            return Err(Error::unsupported(format!(
                "`{}` is compressed with ZOO method {m}, which BeeZip can't decode",
                e.path
            )));
        }
    };
    let decoded: Box<dyn Read + 'a> = match item.method {
        1 => Box::new(Lzd::raw(packed, Lzw::ZOO).map_err(|err| Error::from_io(&err))?),
        2 => Box::new(Lh5 {
            dec: DecoderAny::new_from_compression(delharc::CompressionMethod::Lh5, packed),
            left: item.size,
        }),
        _ => Box::new(packed),
    };
    let what = format!("zoo: `{}`", e.path);
    Ok(Box::new(Check16::new(decoded, item.size, item.crc, what)))
}

pub struct ZooReader {
    source: Source,
    entries: Vec<Entry>,
    items: Vec<Item>,
    comment: Option<String>,
    /// The archive spooled out of its codecs, read in place of the input.
    spool: Option<Partial>,
}

impl ZooReader {
    /// Reads the header and walks the directory chain.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let spool = if source.codecs.is_empty() {
            None
        } else {
            let mut tmp = Partial::create_temp("beezip-spool.zoo")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            Some(tmp)
        };
        let mut r = Self {
            source,
            entries: Vec::new(),
            items: Vec::new(),
            comment: None,
            spool,
        };
        r.list(cx)?;
        Ok(r)
    }

    /// The archive from its start, counted, and its length.
    fn input(&self) -> Result<(Archive, u64)> {
        let (inner, len): (Box<dyn ReadSeek>, u64) = match &self.spool {
            None => {
                let input = self.source.input()?;
                let len = input.len();
                (Box::new(input), len)
            }
            Some(tmp) => {
                let p = tmp.path();
                let file =
                    File::open(p).map_err(|e| Error::io(format!("opening {}", p.display()), &e))?;
                let len = file
                    .metadata()
                    .map_err(|e| Error::io(format!("reading {}", p.display()), &e))?
                    .len();
                (Box::new(file), len)
            }
        };
        self.source.counter.set(0);
        let counted: Box<dyn ReadSeek> =
            Box::new(CountingReader::new(inner, self.source.counter.clone()));
        let r = BufReader::with_capacity(BUF_SIZE, counted);
        Ok((Archive { r, pos: 0 }, len))
    }

    fn list(&mut self, cx: &mut dyn Ctx) -> Result<()> {
        let (mut r, len) = self.input()?;
        let mut head = Vec::with_capacity(ZOO_HEADER_SIZE);
        (&mut r)
            .take(ZOO_HEADER_SIZE as u64)
            .read_to_end(&mut head)
            .map_err(|e| crate::io::read_error(&e).context("zoo"))?;
        if head.len() < MIN_HEADER || le32(&head, SIZ_TEXT) != Some(ZOO_TAG) {
            return Err(zoo_error("no ZOO header"));
        }
        let start = le32(&head, 24).unwrap_or_default();
        let minus = le32(&head, 28).unwrap_or_default();
        if start.wrapping_add(minus) != 0 {
            return Err(zoo_error("the header's first offset fails its check"));
        }
        let start = u64::from(start);
        if start < MIN_HEADER as u64 || start > len {
            return Err(zoo_error(format!(
                "the first directory entry is at byte {start}, outside the file"
            )));
        }
        // A type-1 header (zoo 2.x) holds the archive comment's place; its length is 16 bits.
        if start >= ZOO_HEADER_SIZE as u64
            && head.len() >= ZOO_HEADER_SIZE
            && head[34] >= 1
            && let (Some(at), Some(n)) = (le32(&head, 35), le16(&head, 39))
            && n > 0
            && u64::from(at) + u64::from(n) <= len
        {
            let mut c = Vec::new();
            r.seek(SeekFrom::Start(u64::from(at)))
                .and_then(|_| (&mut r).take(u64::from(n)).read_to_end(&mut c))
                .map_err(|e| crate::io::read_error(&e).context("zoo"))?;
            let text = self.source.names.decode(&c, false, SystemPage::Oem);
            let text = text.trim_end_matches(['\0', '\r', '\n']);
            if !text.is_empty() {
                self.comment = Some(text.replace("\r\n", "\n"));
            }
        }

        let mut found: Vec<DirectoryEntry> = Vec::new();
        let mut buf = vec![0u8; DIRENT2_SIZE + VAR_MAX];
        let mut pos = start;
        let mut steps = 0u64;
        loop {
            cx.check()?;
            if pos.saturating_add(DIRENT_NEXT_END as u64) > len {
                return Err(zoo_error(format!(
                    "the directory runs past the end of the file, at byte {pos}"
                )));
            }
            steps += 1;
            self.source.limits.check_entries(steps)?;
            let n = usize::try_from((len - pos).min(buf.len() as u64)).unwrap_or(buf.len());
            r.seek(SeekFrom::Start(pos))
                .and_then(|_| r.read_exact(&mut buf[..n]))
                .map_err(|e| crate::io::read_error(&e).context("zoo"))?;
            let Some(d) = DirectoryEntry::load_from(&buf[..n])
                .map_err(|e| e.context(format!("at byte {pos}")))?
            else {
                break;
            };
            let next = u64::from(d.next);
            if next <= pos {
                return Err(zoo_error(format!(
                    "the directory goes back from byte {pos} to {next}: a loop"
                )));
            }
            if !d.deleted {
                let end = u64::from(d.offset) + u64::from(d.size_now);
                if end > len {
                    return Err(zoo_error(format!(
                        "an entry's {} bytes at {} run past the end of the file",
                        d.size_now, d.offset
                    )));
                }
                found.push(d);
            }
            pos = next;
        }

        // The latest generation of each path, where generations are on.
        let raws: Vec<Vec<u8>> = found.iter().map(DirectoryEntry::raw_path).collect();
        let mut latest: HashMap<&[u8], (u16, usize)> = HashMap::new();
        for (i, d) in found.iter().enumerate() {
            if d.vflag & VFL_ON != 0 {
                let best = latest
                    .entry(raws[i].as_slice())
                    .or_insert((d.version_no, i));
                if d.version_no >= best.0 {
                    *best = (d.version_no, i);
                }
            }
        }
        let mut clock = DosClock::default();
        let names = self.source.names;
        for (i, d) in found.iter().enumerate() {
            if d.vflag & VFL_ON != 0 && latest.get(&raws[i][..]).is_some_and(|&(_, k)| k != i) {
                continue;
            }
            let raw = raws[i].clone();
            let mut path = names
                .decode(&raw, false, SystemPage::Oem)
                .replace('\\', "/");
            let name_empty = d.lfname.is_empty() && d.name.is_empty();
            let kind = if name_empty && !d.dirname.is_empty() {
                if !path.ends_with('/') {
                    path.push('/');
                }
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let is_file = kind == EntryKind::File;
            let id = self.entries.len();
            self.entries.push(Entry {
                id,
                path,
                raw_path: raw,
                kind,
                size: is_file.then_some(u64::from(d.org_size)),
                packed_size: is_file.then_some(u64::from(d.size_now)),
                modified: d.modified(&mut clock),
                crc32: None,
                method: is_file.then(|| method_name(d.compression_method)),
                encrypted: false,
                unix_mode: d
                    .fattr
                    .filter(|a| a >> 22 == FATTR_UNIX && is_file)
                    .map(|a| S_IFREG | (a & 0o777)),
                dos_attrs: None,
            });
            self.items.push(Item {
                offset: u64::from(d.offset),
                packed: u64::from(d.size_now),
                size: u64::from(d.org_size),
                crc: d.file_crc16,
                method: d.compression_method,
            });
        }

        // Data is found by offset, so entries could share it, as in zip's overlapping-entry
        // bomb: refused as zip refuses it. zoo never writes that.
        let mut ranges: Vec<(u64, u64)> = self
            .items
            .iter()
            .filter(|i| i.packed > 0)
            .map(|i| (i.offset, i.offset + i.packed))
            .collect();
        ranges.sort_unstable();
        if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
            return Err(Error::new(
                ErrorKind::Unsafe,
                "zoo: entries share compressed data (an overlapping-entry bomb)",
            ));
        }
        Ok(())
    }
}

impl ArchiveReader for ZooReader {
    fn format(&self) -> FormatId {
        FormatId::Zoo
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods: Vec<Cow<'static, str>> = Vec::new();
        for m in self.entries.iter().filter_map(|e| e.method.as_ref()) {
            if !methods.contains(m) {
                methods.push(m.clone());
            }
        }
        Ok(ArchiveInfo {
            format: FormatId::Zoo,
            codecs: self.source.codecs.clone(),
            methods,
            comment: self.comment.clone(),
            encryption: Encryption::None,
            solid: false,
            sfx: false,
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
        let (mut r, len) = self.input()?;
        let mut meter = Meter::new(self.source.counter.clone(), Some(len));
        meter.entries_total = Some(self.entries.len() as u64);
        for (id, e) in self.entries.iter().enumerate() {
            cx.check()?;
            if !sel.matches(e) {
                continue;
            }
            meter.entries_done = id as u64;
            meter.current = Some(e.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            if e.kind != EntryKind::File {
                sink.entry(e, &mut io::empty(), &mut mcx)?;
                continue;
            }
            match data(&mut r, self.items[id], e) {
                Ok(d) => sink.entry(e, &mut self.source.guard(d), &mut mcx)?,
                Err(err) if err.kind == ErrorKind::UnsupportedOperation => {
                    sink.entry(e, &mut Refused(Some(err)), &mut mcx)?;
                }
                Err(err) => return Err(err),
            }
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let e = self
            .entries
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        if e.kind != EntryKind::File {
            return Ok(Box::new(io::empty()));
        }
        let (r, _) = self.input()?;
        let d = data(r, self.items[id], e)?;
        Ok(Box::new(self.source.guard(d)))
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::{
        SimpleCtx, TestSink,
        codec::compress::{crc16, encode_raw},
        time::from_dos,
    };

    /// 2020-06-15 08:45:30 as a DOS date and time.
    const DATE: u16 = 0x50CF;
    const TIME: u16 = 0x45AF;

    #[derive(Clone)]
    struct Spec<'a> {
        name: &'a [u8],
        long: &'a [u8],
        dir: &'a [u8],
        data: &'a [u8],
        method: u8,
        deleted: bool,
        tz: i8,
        fattr: u32,
        vflag: u8,
        vno: u16,
    }

    fn spec<'a>(name: &'a [u8], data: &'a [u8]) -> Spec<'a> {
        Spec {
            name,
            long: b"",
            dir: b"",
            data,
            method: 0,
            deleted: false,
            tz: NO_TZ,
            fattr: 0,
            vflag: 0,
            vno: 0,
        }
    }

    /// A ZOO 2.x archive of type-2 entries, each one's data after it and an empty entry to end
    /// the chain, as zoo writes them.
    fn zoo(entries: &[Spec<'_>]) -> Vec<u8> {
        let mut out = b"ZOO 2.10 Archive.\x1a\0\0".to_vec();
        out.extend(ZOO_TAG.to_le_bytes());
        out.extend(42u32.to_le_bytes());
        out.extend(42u32.wrapping_neg().to_le_bytes());
        out.extend([2, 0, 1, 0, 0, 0, 0, 0, 0, 3]);
        for s in entries {
            let packed = match s.method {
                1 => encode_raw(s.data, Lzw::ZOO),
                _ => s.data.to_vec(),
            };
            let with_nul = |b: &[u8]| {
                let mut v = b.to_vec();
                if !v.is_empty() {
                    v.push(0);
                }
                v
            };
            let (long, dir) = (with_nul(s.long), with_nul(s.dir));
            let mut var = vec![long.len() as u8, dir.len() as u8];
            var.extend(&long);
            var.extend(&dir);
            var.extend([0, 0]);
            var.extend(&s.fattr.to_le_bytes()[..3]);
            var.push(s.vflag);
            var.extend(s.vno.to_le_bytes());
            let offset = out.len() + DIRENT2_SIZE + var.len();
            let next = offset + packed.len();
            out.extend(ZOO_TAG.to_le_bytes());
            out.extend([2, s.method]);
            out.extend((next as u32).to_le_bytes());
            out.extend((offset as u32).to_le_bytes());
            out.extend(DATE.to_le_bytes());
            out.extend(TIME.to_le_bytes());
            out.extend(crc16(0, s.data).to_le_bytes());
            out.extend((s.data.len() as u32).to_le_bytes());
            out.extend((packed.len() as u32).to_le_bytes());
            out.extend([1, 0, u8::from(s.deleted), 0]);
            out.extend([0; 6]);
            let mut fname = [0u8; FNAMESIZE];
            fname[..s.name.len()].copy_from_slice(s.name);
            out.extend(fname);
            out.extend((var.len() as u16).to_le_bytes());
            out.push(s.tz as u8);
            out.extend([0, 0]);
            out.extend(&var);
            out.extend(&packed);
        }
        out.extend(ZOO_TAG.to_le_bytes());
        out.push(2);
        out.extend([0; DIRENT2_SIZE - 5 + 10]);
        out
    }

    struct Opened {
        _dir: tempfile::TempDir,
        reader: ZooReader,
    }

    fn open(bytes: &[u8]) -> Result<Opened> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.zoo");
        std::fs::write(&path, bytes).unwrap();
        let source = Source::new(&path, Vec::new(), &crate::OpenOptions::default())?;
        let reader = ZooReader::open(source, &mut SimpleCtx::new())?;
        Ok(Opened { _dir: dir, reader })
    }

    fn read(o: &mut Opened, id: usize) -> Result<Vec<u8>> {
        let mut cx = SimpleCtx::new();
        let mut out = Vec::new();
        o.reader
            .open_entry(id, &mut cx)?
            .read_to_end(&mut out)
            .map_err(|e| Error::from_io(&e))?;
        Ok(out)
    }

    fn paths(o: &mut Opened) -> Vec<String> {
        let mut cx = SimpleCtx::new();
        let entries = o.reader.entries(&mut cx).unwrap();
        entries.iter().map(|e| e.path.clone()).collect()
    }

    fn probe(head: &[u8]) -> Option<Confidence> {
        Zoo.sniff(&Probe {
            head,
            len: Some(head.len() as u64),
            ..Probe::default()
        })
    }

    #[test]
    fn sniffs_the_header() {
        let a = zoo(&[spec(b"a.txt", b"hi")]);
        assert_eq!(probe(&a), Some(Confidence::Certain));
        let mut b = a.clone();
        b[28] ^= 1;
        assert_eq!(probe(&b), Some(Confidence::Likely), "the offset's check");
        let mut c = a.clone();
        c[0] = b'X';
        assert_eq!(probe(&c), Some(Confidence::Likely), "no text");
        let mut d = a;
        d[20] ^= 1;
        assert_eq!(probe(&d), None);
        assert_eq!(probe(b"ZOO "), None);
    }

    #[test]
    fn reads_names_methods_and_data() {
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(200);
        let mut long = spec(b"LONGFILE.TXT", &text);
        long.long = b"Long File Name.txt";
        long.dir = b"docs/deep";
        long.method = 1;
        long.fattr = 1 << 22 | 0o755;
        let mut back = spec(b"b.txt", b"x");
        back.dir = b"win\\dir";
        // CP437's 0x81 is ü.
        let a = zoo(&[spec(b"a.txt", b"hello"), long, back, spec(b"\x81.txt", b"")]);
        let mut o = open(&a).unwrap();
        assert_eq!(
            paths(&mut o),
            [
                "a.txt",
                "docs/deep/Long File Name.txt",
                "win/dir/b.txt",
                "ü.txt"
            ]
        );
        let mut cx = SimpleCtx::new();
        let e = &o.reader.entries(&mut cx).unwrap()[1];
        assert_eq!(e.raw_path, b"docs/deep/Long File Name.txt");
        assert_eq!(e.method.as_deref(), Some("LZW"));
        assert_eq!(e.size, Some(text.len() as u64));
        assert!(e.packed_size.unwrap() < text.len() as u64 / 4);
        assert_eq!(e.unix_mode, Some(0o100_755));
        assert_eq!(read(&mut o, 0).unwrap(), b"hello");
        assert_eq!(read(&mut o, 1).unwrap(), text);
        assert_eq!(read(&mut o, 3).unwrap(), b"");
        let info = o.reader.info(&mut cx).unwrap();
        assert_eq!(info.methods, ["Store", "LZW"]);

        let mut sink = TestSink::default();
        o.reader
            .extract(&Selection::all(), &mut sink, &mut cx)
            .unwrap();
        assert!(sink.report.ok(), "{:?}", sink.report);
        assert_eq!(sink.report.entries, 4);
    }

    #[test]
    fn deleted_files_and_older_generations_are_left_out() {
        let mut gone = spec(b"gone.txt", b"old");
        gone.deleted = true;
        let generation = |data: &'static [u8], vno: u16| {
            let mut s = spec(b"a.txt", data);
            s.vflag = VFL_ON;
            s.vno = vno;
            s
        };
        let mut other = generation(b"other", 1);
        other.dir = b"d";
        let a = zoo(&[
            gone,
            generation(b"one", 1),
            generation(b"three", 3),
            other,
            generation(b"two", 2),
        ]);
        let mut o = open(&a).unwrap();
        assert_eq!(paths(&mut o), ["a.txt", "d/a.txt"]);
        assert_eq!(read(&mut o, 0).unwrap(), b"three");
    }

    #[test]
    fn a_time_zone_gives_utc() {
        let mut west = spec(b"a", b"");
        west.tz = 20;
        let mut east = spec(b"b", b"");
        east.tz = -22;
        let mut zero = spec(b"c", b"");
        zero.tz = 0;
        let a = zoo(&[west, east, zero, spec(b"d", b"")]);
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new();
        let times: Vec<_> = o
            .reader
            .entries(&mut cx)
            .unwrap()
            .iter()
            .map(|e| e.modified.unwrap())
            .collect();
        // 08:45:30 five hours west of UTC is 13:45:30 UTC; 5½ hours east, 03:15:30.
        let secs = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs(times[0]), 1_592_228_730);
        assert_eq!(secs(times[1]), 1_592_228_730 - 10 * 3600 - 1800);
        let local = from_dos(DosTime {
            date: DATE,
            time: TIME,
        });
        assert_eq!(Some(times[2]), local, "0: local, as Debian's zoo writes it");
        assert_eq!(Some(times[3]), local, "127: none");
    }

    #[test]
    fn a_chain_that_loops_or_leaves_the_file_is_corrupt() {
        let a = zoo(&[spec(b"a.txt", b"one"), spec(b"b.txt", b"two")]);
        let second = 42 + DIRENT2_SIZE + 10 + 3;
        let corrupt = |bytes: &[u8]| {
            let err = open(bytes).err().expect("must fail");
            assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
            err.message
        };
        // The second entry's `next` back to the first, then to itself.
        let mut cyc = a.clone();
        cyc[second + 6..second + 10].copy_from_slice(&42u32.to_le_bytes());
        assert!(corrupt(&cyc).contains("loop"));
        cyc[second + 6..second + 10].copy_from_slice(&(second as u32).to_le_bytes());
        assert!(corrupt(&cyc).contains("loop"));
        // Past the end.
        let mut far = a.clone();
        far[second + 6..second + 10].copy_from_slice(&u32::MAX.to_le_bytes());
        corrupt(&far);
        let mut data = a.clone();
        data[second + 24..second + 28].copy_from_slice(&1000u32.to_le_bytes());
        assert!(corrupt(&data).contains("past the end"));
        let mut start = a.clone();
        start[24..28].copy_from_slice(&9999u32.to_le_bytes());
        start[28..32].copy_from_slice(&9999u32.wrapping_neg().to_le_bytes());
        corrupt(&start);
        let mut check = a.clone();
        check[28] ^= 1;
        corrupt(&check);
        // Cut in the last entry's data, and in the header. The entry that ends the chain may be
        // short: only its `next` is read.
        corrupt(&a[..a.len() - 68]);
        corrupt(&a[..30]);
        assert!(open(&a[..a.len() - 30]).is_ok());
    }

    /// Two entries pointing at the same data: zip's overlapping-entry bomb.
    #[test]
    fn entries_sharing_data_are_unsafe() {
        let mut a = zoo(&[spec(b"a.txt", b"one"), spec(b"b.txt", b"two")]);
        let first_data = 42 + DIRENT2_SIZE + 10;
        let second = first_data + 3;
        a[second + 10..second + 14].copy_from_slice(&(first_data as u32).to_le_bytes());
        let err = open(&a).err().unwrap();
        assert_eq!(err.kind, ErrorKind::Unsafe, "{err}");
        // Empty entries may share a place.
        let mut b = zoo(&[spec(b"a.txt", b""), spec(b"b.txt", b"")]);
        b[42 + DIRENT2_SIZE + 10 + 10..][..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(open(&b).is_ok());
    }

    #[test]
    fn a_bad_crc_or_size_fails_the_entry() {
        let text = b"some text, some text, some text".repeat(10);
        let mut lzw = spec(b"b.txt", &text);
        lzw.method = 1;
        let a = zoo(&[spec(b"a.txt", b"hello"), lzw]);
        let mut bad = a.clone();
        let at = bad.windows(5).position(|w| w == b"hello").unwrap();
        bad[at] ^= 1;
        let mut o = open(&bad).unwrap();
        let err = read(&mut o, 0).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Corrupt);
        assert!(err.message.contains("CRC-16"), "{err}");
        assert_eq!(read(&mut o, 1).unwrap(), text);
        let mut sink = TestSink::default();
        let mut cx = SimpleCtx::new();
        o.reader
            .extract(&Selection::all(), &mut sink, &mut cx)
            .unwrap();
        assert_eq!(sink.report.errors_total, 1);
        assert_eq!(sink.report.errors[0].path, "a.txt");

        // An original size one more than the data.
        let mut short = a;
        short[42 + 20] += 1;
        let mut o = open(&short).unwrap();
        let err = read(&mut o, 0).unwrap_err();
        assert!(err.message.contains("ends after 5"), "{err}");
    }

    #[test]
    fn an_unknown_method_is_listed_and_refused() {
        let mut odd = spec(b"odd.bin", b"data");
        odd.method = 7;
        let a = zoo(&[odd, spec(b"a.txt", b"fine")]);
        let mut o = open(&a).unwrap();
        let mut cx = SimpleCtx::new();
        assert_eq!(
            o.reader.entries(&mut cx).unwrap()[0].method.as_deref(),
            Some("method 7")
        );
        let err = read(&mut o, 0).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
        assert!(err.message.contains("odd.bin") && err.message.contains("method 7"));
        let mut sink = TestSink::default();
        o.reader
            .extract(&Selection::all(), &mut sink, &mut cx)
            .unwrap();
        assert_eq!(sink.report.entries, 2);
        assert_eq!(sink.report.errors[0].kind, ErrorKind::UnsupportedOperation);
    }

    /// zoo 1.x's type-1 entries: the 8.3 name only.
    #[test]
    fn reads_type_1_entries() {
        let mut a = b"ZOO 1.50 Archive.\x1a\0\0".to_vec();
        a.extend(ZOO_TAG.to_le_bytes());
        a.extend(34u32.to_le_bytes());
        a.extend(34u32.wrapping_neg().to_le_bytes());
        a.extend([1, 0]);
        let data = b"old data";
        let offset = 34 + DIRENT_SIZE;
        let next = offset + data.len();
        a.extend(ZOO_TAG.to_le_bytes());
        a.extend([1, 0]);
        a.extend((next as u32).to_le_bytes());
        a.extend((offset as u32).to_le_bytes());
        a.extend(DATE.to_le_bytes());
        a.extend(TIME.to_le_bytes());
        a.extend(crc16(0, data).to_le_bytes());
        a.extend((data.len() as u32).to_le_bytes());
        a.extend((data.len() as u32).to_le_bytes());
        a.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        a.extend(b"OLD.TXT\0\0\0\0\0\0");
        a.extend(data);
        a.extend(ZOO_TAG.to_le_bytes());
        a.extend([1, 0, 0, 0, 0, 0]);
        let mut o = open(&a).unwrap();
        assert_eq!(paths(&mut o), ["OLD.TXT"]);
        assert_eq!(read(&mut o, 0).unwrap(), data);
    }
}
