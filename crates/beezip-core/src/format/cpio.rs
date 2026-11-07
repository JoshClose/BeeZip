//! cpio (docs/M5.md §5.2): BeeZip's own reader and newc writer.
//!
//! - **Reading** from a plain `Read`, so a `.cpio.gz` needs no spooling: newc (`070701`), crc
//!   (`070702`, whose checksum is checked), odc (`070707`, bsdcpio's default), the old binary
//!   format in both byte orders, and RPM's stripped `07070X` headers (inside RPMs only, whose
//!   header gives their names and sizes). `TRAILER!!!` ends the archive; anything after it is
//!   ignored.
//! - **Hard links:** in newc and crc, the members that share an inode (regular files with
//!   `nlink` > 1) carry the data once, in the last of them. Every other member of the group is a
//!   `Hardlink` to the one with the data: the last before it, else the next after it, which is
//!   how extraction finds them in one pass (it holds a link back until its data has been
//!   written). In odc and binary archives each member carries its own data.
//! - **Names** are bytes, read through the source's `NameDecoding` (docs/M5.md §6). A symlink's
//!   target is its data, at most 64 KiB.
//! - **Writing** is newc. A file of 4 GiB or more can't be stored in it, so it fails with
//!   `InvalidArgs` before anything is written ([`ArchiveWriter::expect`]).
//! - **Editing** copies members as they are: a newc or crc member byte for byte, a renamed one
//!   with a new header in its own format. Members of odc and binary archives get newc headers,
//!   so the archive stays one format, each with its own inode.

use std::{
    collections::HashMap,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Copied, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, Keep, NewEntry, NewKind, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    codec::FinishWrite,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, CountingReader, ExactReader, read_error, write_error},
    names::{NameDecoding, SystemPage},
    source::{Input, Source},
    time::{from_unix, to_unix},
};

pub struct Cpio;

impl ArchiveFormat for Cpio {
    fn id(&self) -> FormatId {
        FormatId::Cpio
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".cpio"]
    }

    /// A first header that parses is certain; the ASCII magic alone is likely. The old binary
    /// format's magic is two bytes and its fields any numbers, so its header must also end its
    /// name with the NUL its name size counts, and give a file type.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let kind = magic(probe.head)?;
        if kind == Kind::Stripped {
            return None;
        }
        let binary = matches!(kind, Kind::BinLe | Kind::BinBe);
        if binary && !binary_plausible(probe.head, kind) {
            return None;
        }
        let mut r = probe.head;
        let mut m = Members::new(&mut r);
        match m.next(&|_| None) {
            Ok(Some(_)) => Some(Confidence::Certain),
            _ if binary => None,
            _ => Some(Confidence::Likely),
        }
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            append: true,
            delete: true,
            rename: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}

/// A member header's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Newc,
    Crc,
    Odc,
    BinLe,
    BinBe,
    /// RPM's `07070X`: the magic and an index into the package header's file list.
    Stripped,
}

const NEWC_LEN: usize = 110;
const ODC_LEN: usize = 76;
const BIN_LEN: usize = 26;
const STRIPPED_LEN: usize = 14;
const TRAILER: &[u8] = b"TRAILER!!!";
/// The longest name read: GNU cpio's PATH_MAX is 4 KiB, libarchive's limit 1 MiB.
const MAX_NAME: u64 = 64 * 1024;
/// The longest symlink target read.
const MAX_LINK: u64 = 64 * 1024;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

fn magic(head: &[u8]) -> Option<Kind> {
    match head.get(..2)? {
        [0xC7, 0x71] => return Some(Kind::BinLe),
        [0x71, 0xC7] => return Some(Kind::BinBe),
        _ => {}
    }
    match head.get(..6)? {
        b"070701" => Some(Kind::Newc),
        b"070702" => Some(Kind::Crc),
        b"070707" => Some(Kind::Odc),
        b"07070X" => Some(Kind::Stripped),
        _ => None,
    }
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::corrupt(format!("cpio: {}", msg.into()))
}

/// An old binary header at the start of `head` that looks like one: a name of at least one byte
/// ending with the NUL its size counts, and no NUL before it, and a mode with a file type.
fn binary_plausible(head: &[u8], kind: Kind) -> bool {
    let w = |i: usize| -> Option<usize> {
        let b = [*head.get(i)?, *head.get(i + 1)?];
        Some(usize::from(if kind == Kind::BinLe {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }))
    };
    let (Some(mode), Some(namesize)) = (w(6), w(20)) else {
        return false;
    };
    let typed = matches!(
        mode as u32 & S_IFMT,
        0o010_000 | 0o020_000 | S_IFDIR | 0o060_000 | S_IFREG | S_IFLNK | 0o140_000
    );
    match head.get(BIN_LEN..BIN_LEN + namesize) {
        Some([name @ .., 0]) => {
            (typed || name == TRAILER) && !name.is_empty() && !name.contains(&0)
        }
        // A name past what the probe holds: the header alone decides.
        None => typed,
        _ => false,
    }
}

fn hex(field: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(field).ok()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn oct(field: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(field).ok()?;
    if s.is_empty() || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    u64::from_str_radix(s, 8).ok()
}

/// A member's header, decoded.
#[derive(Debug, Clone)]
pub(crate) struct Header {
    pub kind: Kind,
    pub ino: u64,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub nlink: u64,
    pub mtime: u64,
    pub size: u64,
    pub dev: (u64, u64),
    pub rdev: (u64, u64),
    pub check: u32,
    /// The name as stored, without its NUL. Empty for a stripped header.
    pub name: Vec<u8>,
    /// A stripped header's index into the RPM header's files.
    pub index: Option<u32>,
    /// The header, name and padding as stored, for copies.
    pub raw: Vec<u8>,
}

impl Header {
    pub fn is_trailer(&self) -> bool {
        self.kind != Kind::Stripped && self.name == TRAILER
    }

    /// The group a newc or crc member belongs to when it shares its inode.
    fn link_key(&self) -> Option<(u64, u64, u64)> {
        let shared = matches!(self.kind, Kind::Newc | Kind::Crc)
            && self.mode & S_IFMT == S_IFREG
            && self.nlink > 1;
        shared.then_some((self.dev.0, self.dev.1, self.ino))
    }

    /// The bytes between data and the next header, `pos` being where the data ends.
    fn data_pad(&self, end: u64) -> u64 {
        match self.kind {
            Kind::Newc | Kind::Crc | Kind::Stripped => (4 - end % 4) % 4,
            Kind::BinLe | Kind::BinBe => end % 2,
            Kind::Odc => 0,
        }
    }
}

/// Walks a cpio's members in order. `pos` counts from the archive's start, which newc's
/// alignment is relative to.
pub(crate) struct Members<R> {
    r: R,
    pos: u64,
    /// The current member's data and padding still unread.
    left: u64,
    pad: u64,
    /// Whether the archive ended with its trailer.
    pub ended: bool,
}

/// Reads exactly `buf.len()` bytes, `false` at the end of the input before the first.
fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) if n == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

impl<R: Read> Members<R> {
    pub fn new(r: R) -> Self {
        Self {
            r,
            pos: 0,
            left: 0,
            pad: 0,
            ended: false,
        }
    }

    fn io(e: &io::Error) -> Error {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            corrupt("the archive is cut short")
        } else {
            read_error(e).context("cpio")
        }
    }

    fn skip(&mut self, n: u64) -> Result<()> {
        let got =
            io::copy(&mut (&mut self.r).take(n), &mut io::sink()).map_err(|e| Self::io(&e))?;
        self.pos += got;
        if got != n {
            return Err(corrupt("the archive is cut short"));
        }
        Ok(())
    }

    /// Skips what's left of the current member.
    pub fn finish_member(&mut self) -> Result<()> {
        let n = self.left + self.pad;
        self.left = 0;
        self.pad = 0;
        self.skip(n)
    }

    /// The current member's data. Reading past it gives nothing.
    pub fn data(&mut self) -> MemberData<'_, R> {
        MemberData { m: self }
    }

    /// The next member's header, or `None` after the trailer. `stripped` gives a stripped
    /// header's data size from its index (RPM's header); elsewhere there are none.
    pub fn next(&mut self, stripped: &dyn Fn(u32) -> Option<u64>) -> Result<Option<Header>> {
        if self.ended {
            return Ok(None);
        }
        self.finish_member()?;
        let start = self.pos;
        let mut raw = vec![0u8; 2];
        if !read_full(&mut self.r, &mut raw).map_err(|e| Self::io(&e))? {
            return Err(corrupt("the archive ends without its trailer"));
        }
        let kind = match &raw[..] {
            [0xC7, 0x71] => Kind::BinLe,
            [0x71, 0xC7] => Kind::BinBe,
            _ => {
                raw.resize(6, 0);
                read_full(&mut self.r, &mut raw[2..]).map_err(|e| Self::io(&e))?;
                magic(&raw).ok_or_else(|| {
                    corrupt(format!("no header where one should be, at byte {start}"))
                })?
            }
        };
        let len = match kind {
            Kind::Newc | Kind::Crc => NEWC_LEN,
            Kind::Odc => ODC_LEN,
            Kind::BinLe | Kind::BinBe => BIN_LEN,
            Kind::Stripped => STRIPPED_LEN,
        };
        let have = raw.len();
        raw.resize(len, 0);
        read_full(&mut self.r, &mut raw[have..]).map_err(|e| Self::io(&e))?;
        self.pos += len as u64;
        let bad = || corrupt(format!("a damaged header at byte {start}"));
        let mut h = Header {
            kind,
            ino: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            size: 0,
            dev: (0, 0),
            rdev: (0, 0),
            check: 0,
            name: Vec::new(),
            index: None,
            raw: Vec::new(),
        };
        let namesize: u64;
        match kind {
            Kind::Newc | Kind::Crc => {
                let f = |i: usize| hex(&raw[6 + i * 8..14 + i * 8]).ok_or_else(bad);
                h.ino = f(0)?;
                h.mode = u32::try_from(f(1)?).map_err(|_| bad())?;
                h.uid = f(2)?;
                h.gid = f(3)?;
                h.nlink = f(4)?;
                h.mtime = f(5)?;
                h.size = f(6)?;
                h.dev = (f(7)?, f(8)?);
                h.rdev = (f(9)?, f(10)?);
                namesize = f(11)?;
                h.check = u32::try_from(f(12)?).map_err(|_| bad())?;
            }
            Kind::Odc => {
                let f = |a: usize, b: usize| oct(&raw[a..b]).ok_or_else(bad);
                let dev = f(6, 12)?;
                h.dev = (dev >> 8, dev & 0xFF);
                h.ino = f(12, 18)?;
                h.mode = u32::try_from(f(18, 24)?).map_err(|_| bad())?;
                h.uid = f(24, 30)?;
                h.gid = f(30, 36)?;
                h.nlink = f(36, 42)?;
                let rdev = f(42, 48)?;
                h.rdev = (rdev >> 8, rdev & 0xFF);
                h.mtime = f(48, 59)?;
                namesize = f(59, 65)?;
                h.size = f(65, 76)?;
            }
            Kind::BinLe | Kind::BinBe => {
                let w = |i: usize| -> u64 {
                    let b = [raw[i], raw[i + 1]];
                    u64::from(if kind == Kind::BinLe {
                        u16::from_le_bytes(b)
                    } else {
                        u16::from_be_bytes(b)
                    })
                };
                // 32-bit values are two 16-bit words, the high one first.
                let dw = |i: usize| w(i) << 16 | w(i + 2);
                let dev = w(2);
                h.dev = (dev >> 8, dev & 0xFF);
                h.ino = w(4);
                h.mode = u32::try_from(w(6)).map_err(|_| bad())?;
                h.uid = w(8);
                h.gid = w(10);
                h.nlink = w(12);
                let rdev = w(14);
                h.rdev = (rdev >> 8, rdev & 0xFF);
                h.mtime = dw(16);
                namesize = w(20);
                h.size = dw(22);
            }
            Kind::Stripped => {
                let index = hex(&raw[6..14]).ok_or_else(bad)?;
                let index = u32::try_from(index).map_err(|_| bad())?;
                h.index = Some(index);
                h.size = stripped(index)
                    .ok_or_else(|| corrupt(format!("a stripped header for file {index}")))?;
                namesize = 0;
            }
        }
        if kind != Kind::Stripped {
            if namesize == 0 || namesize > MAX_NAME {
                return Err(corrupt(format!(
                    "a name of {namesize} bytes at byte {start}"
                )));
            }
            let mut name = vec![0u8; namesize as usize];
            read_full(&mut self.r, &mut name).map_err(|e| Self::io(&e))?;
            self.pos += namesize;
            raw.extend_from_slice(&name);
            // The NUL that ends the name, and anything a writer left after it.
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            name.truncate(end);
            h.name = name;
        }
        let head_pad = match kind {
            Kind::Newc | Kind::Crc | Kind::Stripped => (4 - self.pos % 4) % 4,
            Kind::BinLe | Kind::BinBe => self.pos % 2,
            Kind::Odc => 0,
        };
        if head_pad > 0 {
            let mut pad = vec![0u8; head_pad as usize];
            read_full(&mut self.r, &mut pad).map_err(|e| Self::io(&e))?;
            self.pos += head_pad;
            raw.extend_from_slice(&pad);
        }
        h.raw = raw;
        if h.is_trailer() {
            self.ended = true;
            return Ok(Some(h));
        }
        self.left = h.size;
        self.pad = h.data_pad(self.pos + h.size);
        Ok(Some(h))
    }
}

/// One member's data, from [`Members::data`].
pub(crate) struct MemberData<'a, R> {
    m: &'a mut Members<R>,
}

impl<R: Read> Read for MemberData<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.m.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.m.left).unwrap_or(usize::MAX));
        let n = self.m.r.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "cpio: a member's data is cut short",
            ));
        }
        self.m.left -= n as u64;
        self.m.pos += n as u64;
        Ok(n)
    }
}

/// Checks a crc member's data against its header: the sum of its bytes.
struct SumCheck<R> {
    inner: R,
    want: u32,
    sum: u32,
}

impl<R: Read> Read for SumCheck<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() && self.sum != self.want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cpio: a member's data doesn't match its checksum",
            ));
        }
        for &b in &buf[..n] {
            self.sum = self.sum.wrapping_add(u32::from(b));
        }
        Ok(n)
    }
}

/// `data`, checked against the header's checksum when it has one.
fn checked<'a, R: Read + 'a>(h: &Header, data: R) -> Box<dyn Read + 'a> {
    if h.kind == Kind::Crc {
        Box::new(SumCheck {
            inner: data,
            want: h.check,
            sum: 0,
        })
    } else {
        Box::new(data)
    }
}

/// The entry a member is, before hard links are worked out. `target` is a symlink's.
pub(crate) fn entry_for(id: usize, h: &Header, names: &NameDecoding, target: String) -> Entry {
    let path = names.decode(&h.name, false, SystemPage::Ansi);
    let kind = match h.mode & S_IFMT {
        S_IFDIR => EntryKind::Dir,
        S_IFREG | 0 => EntryKind::File,
        S_IFLNK => EntryKind::Symlink { target },
        _ => EntryKind::Other,
    };
    let is_file = kind == EntryKind::File;
    Entry {
        id,
        path,
        raw_path: h.name.clone(),
        size: is_file.then_some(h.size),
        packed_size: is_file.then_some(h.size),
        modified: i64::try_from(h.mtime).ok().and_then(|s| from_unix(s, 0)),
        crc32: None,
        method: None,
        encrypted: false,
        unix_mode: Some(h.mode),
        dos_attrs: None,
        kind,
    }
}

/// A symlink's target: its data, at most [`MAX_LINK`] bytes.
pub(crate) fn read_target<R: Read>(
    data: &mut R,
    size: u64,
    names: &NameDecoding,
) -> Result<String> {
    if size > MAX_LINK {
        return Err(corrupt(format!("a link target of {size} bytes")));
    }
    let mut t = Vec::new();
    data.take(size)
        .read_to_end(&mut t)
        .map_err(|e| read_error(&e).context("cpio"))?;
    Ok(names.decode(&t, false, SystemPage::Ansi))
}

/// What a member is to the listing, beyond its entry.
#[derive(Debug, Clone, Default)]
struct Meta {
    /// Where a plain cpio keeps the member's data.
    data: Option<u64>,
    /// The member with the data, for a hard link.
    link_to: Option<usize>,
    kind: Option<Kind>,
    check: u32,
    ino: u64,
}

pub struct CpioReader {
    source: Source,
    index: Option<Vec<Entry>>,
    meta: Vec<Meta>,
    scan: Option<Members<Box<dyn Read + Send>>>,
    file: Option<BufReader<CountingReader<Input>>>,
}

/// Links held back until their group's data has been handed out.
#[derive(Default)]
struct Groups {
    /// The latest member with data, by group.
    data: HashMap<(u64, u64, u64), usize>,
    /// Members without data waiting for it, by group.
    pending: HashMap<(u64, u64, u64), Vec<usize>>,
}

impl CpioReader {
    pub fn new(source: Source) -> Self {
        Self {
            source,
            index: None,
            meta: Vec::new(),
            scan: None,
            file: None,
        }
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

    /// One pass: builds the index if there is none yet, and hands selected entries to the sink
    /// on the way, a hard link after the member with its data.
    fn pass(
        &mut self,
        mut visit: Option<(&Selection, &mut dyn EntrySink)>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
        meter.entries_total = self.index.as_ref().map(|i| i.len() as u64);
        let names = self.source.names;
        let mut m = Members::new(self.stream()?);
        let mut entries: Vec<Entry> = Vec::new();
        let mut meta: Vec<Meta> = Vec::new();
        let mut groups = Groups::default();
        while let Some(h) = m.next(&|_| None)? {
            cx.check()?;
            if h.is_trailer() {
                break;
            }
            if h.kind == Kind::Stripped {
                return Err(corrupt("a stripped header outside an RPM"));
            }
            let id = entries.len();
            self.source.limits.check_entries(id as u64 + 1)?;
            let target = if h.mode & S_IFMT == S_IFLNK {
                read_target(&mut m.data(), h.size, &names)?
            } else {
                String::new()
            };
            let mut e = entry_for(id, &h, &names, target);
            let mut info = Meta {
                data: (self.plain() && e.kind == EntryKind::File).then_some(m.pos),
                kind: Some(h.kind),
                check: h.check,
                ino: h.ino,
                link_to: None,
            };
            match h.link_key() {
                Some(key) if h.size == 0 => {
                    if let Some(&d) = groups.data.get(&key) {
                        e.kind = EntryKind::Hardlink {
                            target: entries[d].path.clone(),
                        };
                        e.size = None;
                        e.packed_size = None;
                        info.link_to = Some(d);
                        emit(&e, &mut io::empty(), &mut meter, &mut visit, cx)?;
                    } else {
                        groups.pending.entry(key).or_default().push(id);
                    }
                }
                Some(key) => {
                    {
                        let mut data = self.source.guard(checked(&h, m.data()));
                        emit(&e, &mut data, &mut meter, &mut visit, cx)?;
                    }
                    groups.data.insert(key, id);
                    for p in groups.pending.remove(&key).unwrap_or_default() {
                        let link: &mut Entry = &mut entries[p];
                        link.kind = EntryKind::Hardlink {
                            target: e.path.clone(),
                        };
                        link.size = None;
                        link.packed_size = None;
                        meta[p].link_to = Some(id);
                        let link = link.clone();
                        emit(&link, &mut io::empty(), &mut meter, &mut visit, cx)?;
                    }
                }
                None if e.kind == EntryKind::File => {
                    let mut data = self.source.guard(checked(&h, m.data()));
                    emit(&e, &mut data, &mut meter, &mut visit, cx)?;
                }
                None => emit(&e, &mut io::empty(), &mut meter, &mut visit, cx)?,
            }
            entries.push(e);
            meta.push(info);
        }
        if !m.ended {
            return Err(corrupt("the archive ends without its trailer"));
        }
        // Members whose group never had data: empty files.
        let mut rest: Vec<usize> = groups.pending.into_values().flatten().collect();
        rest.sort_unstable();
        for p in rest {
            let e = entries[p].clone();
            emit(&e, &mut io::empty(), &mut meter, &mut visit, cx)?;
        }
        meter.entries_done = entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        if self.index.is_none() {
            self.index = Some(entries);
            self.meta = meta;
        }
        Ok(())
    }

    fn index(&mut self, cx: &mut dyn Ctx) -> Result<&[Entry]> {
        if self.index.is_none() {
            self.pass(None, cx)?;
        }
        Ok(self.index.as_deref().unwrap_or_default())
    }

    /// Writes the `keep` members to `w`, as they are stored where it can, and returns how many.
    fn copy_into(&mut self, w: &mut NewcOut<'_>, keep: &[Keep], cx: &mut dyn Ctx) -> Result<u64> {
        let index = self.index(cx)?.to_vec();
        let mut paths: Vec<Option<String>> = vec![None; index.len()];
        for k in keep {
            if let Some(p) = paths.get_mut(k.id) {
                *p = Some(k.path.clone());
            }
        }
        // Kept inodes stay; fresh ones start after them.
        for (id, p) in paths.iter().enumerate() {
            if p.is_some()
                && let Some(meta) = self.meta.get(id)
                && matches!(meta.kind, Some(Kind::Newc | Kind::Crc))
            {
                w.next_ino = w.next_ino.max(meta.ino.saturating_add(1));
            }
        }
        let mut m = Members::new(self.stream()?);
        let mut id = 0usize;
        let mut copied = 0u64;
        while let Some(h) = m.next(&|_| None)? {
            cx.check()?;
            if h.is_trailer() {
                break;
            }
            let entry = index
                .get(id)
                .ok_or_else(|| corrupt("more members than the listing has"))?;
            if let Some(p) = &paths[id] {
                let renamed = normalize_member(p) != normalize_member(&entry.path);
                let name = if renamed {
                    p.trim_end_matches('/').as_bytes().to_vec()
                } else {
                    h.name.clone()
                };
                match h.kind {
                    Kind::Newc | Kind::Crc if !renamed => w.raw(&h.raw)?,
                    Kind::Newc | Kind::Crc => w.header(&h, &name, h.ino)?,
                    _ => {
                        let ino = w.fresh_ino();
                        let one = Header {
                            nlink: 1,
                            ..h.clone()
                        };
                        w.header(&one, &name, ino)?;
                    }
                }
                let n = crate::io::copy(&mut m.data(), w, cx)?;
                if n != h.size {
                    return Err(corrupt("a member's data is cut short"));
                }
                w.pad()?;
                copied += 1;
            }
            id += 1;
        }
        if id != index.len() {
            return Err(corrupt("fewer members than the listing has"));
        }
        Ok(copied)
    }
}

/// `r`, checked against a crc member's checksum.
fn with_check<'a>(r: Box<dyn Read + 'a>, meta: &Meta) -> Box<dyn Read + 'a> {
    if meta.kind == Some(Kind::Crc) {
        Box::new(SumCheck {
            inner: r,
            want: meta.check,
            sum: 0,
        })
    } else {
        r
    }
}

/// Hands one entry to the sink, if it's selected.
fn emit(
    e: &Entry,
    data: &mut dyn Read,
    meter: &mut Meter,
    visit: &mut Option<(&Selection, &mut dyn EntrySink)>,
    cx: &mut dyn Ctx,
) -> Result<()> {
    if let Some((sel, sink)) = visit.as_mut()
        && sel.matches(e)
    {
        meter.entries_done = e.id as u64;
        meter.current = Some(e.path.clone());
        let mut mcx = MeteredCtx::new(cx, meter);
        mcx.report();
        sink.entry(e, data, &mut mcx)?;
    }
    Ok(())
}

/// A path as two members' names compare: `./` and trailing `/` don't count.
fn normalize_member(p: &str) -> String {
    super::normalize(p)
}

impl ArchiveReader for CpioReader {
    fn format(&self) -> FormatId {
        FormatId::Cpio
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, cx: &mut dyn Ctx) -> Result<&[Entry]> {
        self.index(cx)
    }

    fn info(&mut self, cx: &mut dyn Ctx) -> Result<ArchiveInfo> {
        self.index(cx)?;
        Ok(ArchiveInfo {
            format: FormatId::Cpio,
            codecs: self.source.codecs.clone(),
            methods: Vec::new(),
            comment: None,
            encryption: Encryption::None,
            solid: !self.plain(),
            sfx: false,
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
        self.pass(Some((sel, sink)), cx)
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let entry = self
            .index(cx)?
            .get(id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        let id = match &entry.kind {
            EntryKind::File => id,
            EntryKind::Hardlink { target } => {
                self.meta.get(id).and_then(|m| m.link_to).ok_or_else(|| {
                    corrupt(format!("the data of hard link `{target}` is missing"))
                })?
            }
            _ => return Ok(Box::new(io::empty())),
        };
        let size = self
            .index
            .as_ref()
            .and_then(|i| i.get(id))
            .and_then(|e| e.size)
            .unwrap_or(0);
        let meta = self.meta.get(id).cloned().unwrap_or_default();
        let crc = |r| with_check(r, &meta);
        if let Some(offset) = meta.data {
            let mut file = BufReader::with_capacity(BUF_SIZE, self.source.open_file()?);
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| Error::io("seeking in the cpio", &e))?;
            let file = self.file.insert(file);
            let data: Box<dyn Read + '_> = Box::new(file.take(size));
            return Ok(Box::new(self.source.guard(crc(data))));
        }
        let mut m = Members::new(self.source.open_stream()?);
        for _ in 0..id {
            cx.check()?;
            m.next(&|_| None)?
                .ok_or_else(|| corrupt("a member vanished on a second pass"))?;
        }
        m.next(&|_| None)?
            .ok_or_else(|| corrupt("a member vanished on a second pass"))?;
        let m = self.scan.insert(m);
        let data: Box<dyn Read + '_> = Box::new(m.data());
        Ok(Box::new(self.source.guard(crc(data))))
    }
}

/// newc output: tracks the position, for padding, and hands out inodes.
struct NewcOut<'a> {
    out: Box<dyn FinishWrite + 'a>,
    pos: u64,
    next_ino: u64,
}

impl NewcOut<'_> {
    fn fresh_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_all(bytes).map_err(|e| write_error(&e))
    }

    /// A newc header (or crc, keeping the checksum) for `h` under `name`, with its padding.
    fn header(&mut self, h: &Header, name: &[u8], ino: u64) -> Result<()> {
        let magic = if h.kind == Kind::Crc {
            "070702"
        } else {
            "070701"
        };
        let check = if h.kind == Kind::Crc { h.check } else { 0 };
        let f = |v: u64| format!("{:08X}", v.min(u64::from(u32::MAX)));
        let mut out = format!(
            "{magic}{}{}{}{}{}{}{}{}{}{}{}{}{}",
            f(ino),
            f(u64::from(h.mode)),
            f(h.uid),
            f(h.gid),
            f(h.nlink),
            f(h.mtime),
            f(h.size),
            f(h.dev.0),
            f(h.dev.1),
            f(h.rdev.0),
            f(h.rdev.1),
            f(name.len() as u64 + 1),
            f(u64::from(check)),
        )
        .into_bytes();
        out.extend_from_slice(name);
        out.push(0);
        self.raw(&out)?;
        self.pad()
    }

    /// Zeros to the next multiple of 4.
    fn pad(&mut self) -> Result<()> {
        let n = ((4 - self.pos % 4) % 4) as usize;
        self.raw(&[0u8; 3][..n])
    }
}

impl Write for NewcOut<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Writes a newc cpio to `out`, which a codec's encoder may wrap.
pub struct CpioWriter<'a> {
    out: NewcOut<'a>,
    /// `out` is a codec's encoder, so copied members are encoded again.
    compressed: bool,
}

/// newc's sizes are 32-bit.
const MAX_SIZE: u64 = u32::MAX as u64;

impl<'a> CpioWriter<'a> {
    pub fn new(out: Box<dyn FinishWrite + 'a>) -> Self {
        Self {
            out: NewcOut {
                out,
                pos: 0,
                next_ino: 1,
            },
            compressed: false,
        }
    }

    /// The same, writing through a codec's encoder.
    pub fn compressed(out: Box<dyn FinishWrite + 'a>) -> Self {
        Self {
            compressed: true,
            ..Self::new(out)
        }
    }
}

fn too_big(path: &str) -> Error {
    Error::invalid_args(format!(
        "`{path}` is 4 GiB or more, which a cpio can't hold; use tar, zip or 7z"
    ))
}

fn mode_for(entry: &NewEntry) -> u32 {
    let (kind, default) = match entry.kind {
        NewKind::Dir => (S_IFDIR, 0o755),
        NewKind::Symlink { .. } => (S_IFLNK, 0o777),
        NewKind::File => (S_IFREG, 0o644),
    };
    kind | entry.unix_mode.map_or(default, |m| m & 0o7777)
}

impl ArchiveWriter for CpioWriter<'_> {
    fn expect(&mut self, entries: &[NewEntry]) -> Result<()> {
        match entries
            .iter()
            .find(|e| e.kind == NewKind::File && e.size > MAX_SIZE)
        {
            Some(e) => Err(too_big(&e.path)),
            None => Ok(()),
        }
    }

    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let (size, target) = match &entry.kind {
            NewKind::File if entry.size > MAX_SIZE => return Err(too_big(&entry.path)),
            NewKind::File => (entry.size, None),
            NewKind::Dir => (0, None),
            NewKind::Symlink { target } => (target.len() as u64, Some(target.as_bytes())),
        };
        let mtime = entry.modified.map(to_unix).unwrap_or(0).max(0);
        let h = Header {
            kind: Kind::Newc,
            ino: 0,
            mode: mode_for(entry),
            uid: 0,
            gid: 0,
            nlink: if entry.kind == NewKind::Dir { 2 } else { 1 },
            mtime: mtime.unsigned_abs(),
            size,
            dev: (0, 0),
            rdev: (0, 0),
            check: 0,
            name: Vec::new(),
            index: None,
            raw: Vec::new(),
        };
        let ino = self.out.fresh_ino();
        self.out
            .header(&h, entry.path.trim_end_matches('/').as_bytes(), ino)?;
        match target {
            Some(t) => self.out.raw(t)?,
            None if entry.kind == NewKind::File => {
                // Exactly `size` bytes, or an error: the header is already written.
                crate::io::copy(&mut ExactReader::new(data, size), &mut self.out, cx)?;
            }
            None => {}
        }
        self.out.pad()
    }

    fn copy_from(
        &mut self,
        source: &mut dyn ArchiveReader,
        keep: &[Keep],
        cx: &mut dyn Ctx,
    ) -> Result<Copied> {
        let Some(r) = source.as_any_mut().downcast_mut::<CpioReader>() else {
            return Ok(Copied::nothing(keep));
        };
        let n = r.copy_into(&mut self.out, keep, cx)?;
        Ok(if self.compressed {
            Copied {
                recompressed: n,
                ..Copied::default()
            }
        } else {
            Copied {
                copied: n,
                ..Copied::default()
            }
        })
    }

    fn finish(mut self: Box<Self>) -> Result<()> {
        let trailer = Header {
            kind: Kind::Newc,
            ino: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            size: 0,
            dev: (0, 0),
            rdev: (0, 0),
            check: 0,
            name: Vec::new(),
            index: None,
            raw: Vec::new(),
        };
        self.out.header(&trailer, TRAILER, 0)?;
        // GNU cpio fills the last 512-byte block.
        let n = ((512 - self.out.pos % 512) % 512) as usize;
        self.out.raw(&vec![0u8; n])?;
        let out = self.out.out;
        out.finish().map_err(|e| write_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimpleCtx, codec::finisher};

    fn newc(name: &str, mode: u32, nlink: u32, ino: u32, data: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "070701{ino:08X}{mode:08X}{:08X}{:08X}{nlink:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            0,
            0,
            1_700_000_000u32,
            data.len(),
            0,
            1,
            0,
            0,
            name.len() + 1,
            0
        )
        .into_bytes();
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn archive(members: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = members.concat();
        out.extend(newc("TRAILER!!!", 0, 1, 0, b""));
        out
    }

    fn reader(bytes: &[u8]) -> (tempfile::TempDir, CpioReader) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.cpio");
        std::fs::write(&path, bytes).unwrap();
        let source = Source::new(&path, Vec::new(), &crate::OpenOptions::default()).unwrap();
        (dir, CpioReader::new(source))
    }

    fn read(r: &mut CpioReader, id: usize) -> Vec<u8> {
        let mut out = Vec::new();
        r.open_entry(id, &mut SimpleCtx::new())
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn newc_links_point_at_the_member_with_the_data() {
        let bytes = archive(&[
            newc("a", 0o100_644, 3, 7, b""),
            newc("dir", 0o040_755, 2, 8, b""),
            newc("b", 0o100_644, 3, 7, b""),
            newc("c", 0o100_644, 3, 7, b"shared"),
            newc("ln", 0o120_777, 1, 9, b"c"),
        ]);
        let (_d, mut r) = reader(&bytes);
        let mut cx = SimpleCtx::new();
        let entries = r.entries(&mut cx).unwrap().to_vec();
        let kinds: Vec<_> = entries.iter().map(|e| e.kind.clone()).collect();
        let link = EntryKind::Hardlink { target: "c".into() };
        assert_eq!(
            kinds,
            [
                link.clone(),
                EntryKind::Dir,
                link,
                EntryKind::File,
                EntryKind::Symlink { target: "c".into() }
            ]
        );
        assert_eq!(read(&mut r, 0), b"shared");
        assert_eq!(read(&mut r, 3), b"shared");

        // Extraction hands out the data first, then the links that waited for it.
        struct Order(Vec<String>);
        impl EntrySink for Order {
            fn entry(&mut self, e: &Entry, d: &mut dyn Read, _: &mut dyn Ctx) -> Result<()> {
                io::copy(d, &mut io::sink()).unwrap();
                self.0.push(e.path.clone());
                Ok(())
            }
        }
        let mut order = Order(Vec::new());
        r.extract(&Selection::all(), &mut order, &mut cx).unwrap();
        assert_eq!(order.0, ["dir", "c", "a", "b", "ln"]);
    }

    #[test]
    fn crc_members_are_checked() {
        let mut m = newc("f", 0o100_644, 1, 1, b"abc");
        m[..6].copy_from_slice(b"070702");
        let sum = u32::from(b'a') + u32::from(b'b') + u32::from(b'c');
        m[102..110].copy_from_slice(format!("{sum:08X}").as_bytes());
        let (_d, mut r) = reader(&archive(std::slice::from_ref(&m)));
        assert_eq!(read(&mut r, 0), b"abc");
        m[102..110].copy_from_slice(b"00000001");
        let (_d, mut r) = reader(&archive(&[m]));
        let mut out = Vec::new();
        let err = r
            .open_entry(0, &mut SimpleCtx::new())
            .unwrap()
            .read_to_end(&mut out);
        assert!(err.is_err());
    }

    #[test]
    fn damaged_archives_are_refused() {
        let good = archive(&[newc("f", 0o100_644, 1, 1, b"hello")]);
        for cut in [3, 50, 112, 120, good.len() - 4] {
            let (_d, mut r) = reader(&good[..cut]);
            let e = r.entries(&mut SimpleCtx::new()).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Corrupt, "cut at {cut}: {e}");
        }
        // A name size past the end, and one far too large to allocate.
        let mut huge = good.clone();
        huge[94..102].copy_from_slice(b"7FFFFFFF");
        let (_d, mut r) = reader(&huge);
        assert_eq!(
            r.entries(&mut SimpleCtx::new()).unwrap_err().kind,
            ErrorKind::Corrupt
        );
        let mut bad = good;
        bad[10] = b'Z';
        let (_d, mut r) = reader(&bad);
        assert_eq!(
            r.entries(&mut SimpleCtx::new()).unwrap_err().kind,
            ErrorKind::Corrupt
        );
    }

    #[test]
    fn old_formats_read() {
        // odc: dev ino mode uid gid nlink rdev mtime namesize filesize.
        let mut odc = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0, 5, 0o100_644, 0, 0, 1, 0, 1_700_000_000u32, 2, 3
        )
        .into_bytes();
        odc.extend_from_slice(b"x\0abc");
        odc.extend(
            format!(
                "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}TRAILER!!!\0",
                0, 0, 0, 0, 0, 1, 0, 0, 11, 0
            )
            .into_bytes(),
        );
        let (_d, mut r) = reader(&odc);
        assert_eq!(r.entries(&mut SimpleCtx::new()).unwrap()[0].path, "x");
        assert_eq!(read(&mut r, 0), b"abc");

        // Binary, little-endian: 16-bit words, 32-bit values high word first.
        let bin = |name: &[u8], mode: u16, data: &[u8]| {
            let w = |v: u16| v.to_le_bytes();
            let mut h = Vec::new();
            for v in [0o070_707u16, 0, 1, mode, 0, 0, 1, 0, 0, 0] {
                h.extend_from_slice(&w(v));
            }
            h.extend_from_slice(&w(name.len() as u16 + 1));
            h.extend_from_slice(&w(0));
            h.extend_from_slice(&w(data.len() as u16));
            h.extend_from_slice(name);
            h.push(0);
            if h.len() % 2 == 1 {
                h.push(0);
            }
            h.extend_from_slice(data);
            if h.len() % 2 == 1 {
                h.push(0);
            }
            h
        };
        let mut b = bin(b"y", 0o100_644, b"hello");
        b.extend(bin(b"TRAILER!!!", 0, b""));
        let probe = |head: &[u8]| {
            Cpio.sniff(&Probe {
                head,
                len: Some(head.len() as u64),
                ..Probe::default()
            })
        };
        assert_eq!(probe(&b), Some(Confidence::Certain));
        assert_eq!(
            probe(&bin(b"TRAILER!!!", 0, b"")),
            Some(Confidence::Certain)
        );
        // The binary magic and numbers alone aren't a cpio: the name must end at its size.
        let mut fake = b.clone();
        fake[20] = 9;
        assert_eq!(probe(&fake), None);
        let mut typeless = b.clone();
        typeless[6..8].copy_from_slice(&0o000_644u16.to_le_bytes());
        assert_eq!(probe(&typeless), None);
        let (_d, mut r) = reader(&b);
        assert_eq!(r.entries(&mut SimpleCtx::new()).unwrap()[0].path, "y");
        assert_eq!(read(&mut r, 0), b"hello");
    }

    #[test]
    fn writes_newc_that_reads_back() {
        let mut buf = Vec::new();
        {
            let out = finisher(&mut buf, |w: &mut Vec<u8>| w.flush());
            let mut w = Box::new(CpioWriter::new(out));
            let mut cx = SimpleCtx::new();
            let file = |path: &str, size| NewEntry {
                path: path.into(),
                kind: NewKind::File,
                size,
                modified: None,
                unix_mode: Some(0o600),
                dos_attrs: None,
            };
            let big = NewEntry {
                size: 5 << 30,
                ..file("big", 0)
            };
            assert_eq!(w.expect(&[big]).unwrap_err().kind, ErrorKind::InvalidArgs);
            w.add(&file("a.txt", 5), &mut &b"hello"[..], &mut cx)
                .unwrap();
            let dir = NewEntry {
                kind: NewKind::Dir,
                ..file("d", 0)
            };
            w.add(&dir, &mut io::empty(), &mut cx).unwrap();
            let link = NewEntry {
                kind: NewKind::Symlink {
                    target: "a.txt".into(),
                },
                ..file("d/l", 0)
            };
            w.add(&link, &mut io::empty(), &mut cx).unwrap();
            assert!(w.add(&file("short", 9), &mut &b"abc"[..], &mut cx).is_err());
            w.finish().unwrap();
        }
        // The short file left a header behind; read up to it.
        assert_eq!(buf.len() % 4, 0);
        let mut m = Members::new(&buf[..]);
        let h = m.next(&|_| None).unwrap().unwrap();
        assert_eq!(
            (h.name.as_slice(), h.mode, h.size),
            (&b"a.txt"[..], 0o100_600, 5)
        );
        let mut data = Vec::new();
        m.data().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"hello");
        let h = m.next(&|_| None).unwrap().unwrap();
        assert_eq!(h.mode & S_IFMT, S_IFDIR);
        let h = m.next(&|_| None).unwrap().unwrap();
        assert_eq!(h.mode & S_IFMT, S_IFLNK);
    }
}
