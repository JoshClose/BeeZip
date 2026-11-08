//! XAR (docs/M6.md §5), read only: BeeZip's own reader. macOS packages are XARs too; pkg.rs
//! lists them through [`Archive`].
//!
//! - **Layout:** a big-endian header (`xar!`, its size, version 1, the table of contents'
//!   packed and unpacked lengths, the table's checksum algorithm), the zlib-compressed XML
//!   table, then the heap. Data offsets count from the heap's start, and the table's own
//!   checksum lies in the heap where `<toc><checksum>` says.
//! - **The table** is parsed by quick-xml's pull parser as it inflates, bounded: at most
//!   [`MAX_TOC_PACKED`] packed and [`MAX_TOC`] unpacked, and exactly its declared length;
//!   [`MAX_FILES`] files nested [`MAX_DEPTH`] deep, texts of [`MAX_TEXT`] and paths of
//!   [`MAX_PATH`]. Nothing recurses, and only XML's five entities are expanded: a table that
//!   declares entities (a billion laughs) fails at once.
//! - **Entries:** files, folders, symlinks, hard links (by id, to the file that holds the data;
//!   each is listed after its target, so extraction meets the target first) and others
//!   (devices, FIFOs). Names in base64 are decoded; Apple's doubled `<name>` is one name. Modes
//!   and times are kept, owners not.
//! - **Data** is stored, or zlib (`x-gzip`), bzip2, xz or lzma through BeeZip's codecs.
//!   `x-lzma` is xz from Apple's xar and `.lzma` from libarchive, told apart by the magic.
//! - **Checksums:** the table's (SHA-1, MD5, or the one `<checksum style>` names, such as
//!   SHA-256 or SHA-512) is checked on open: a mismatch is a warning, and every read then fails
//!   as `Corrupt`. Each file's archived and extracted checksums and its size are checked when
//!   its data ends, which `archive.test` and extraction both reach.
//! - **Offsets** and lengths are checked against the file when it opens. Files may share data
//!   only whole (xar's `--link-same`), and what the copies decode to is held to the ratio limit
//!   against the file's size; sharing part of it is the overlapping-entry bomb, refused as
//!   `Unsafe` as in zips.

use std::{
    borrow::Cow,
    cell::Cell,
    collections::HashMap,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    sync::{Arc, Mutex, PoisonError},
};

use quick_xml::{
    Reader, XmlVersion,
    escape::resolve_xml_entity,
    events::{BytesRef, BytesStart, Event},
};
use sha2::Digest;

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
};
use crate::{
    CodecId, Ctx, Error, ErrorKind, Limits, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{Counter, read_error},
    names::{NameDecoding, SystemPage},
    safefs::Partial,
    source::Source,
    time::from_unix,
};

pub struct Xar;

impl ArchiveFormat for Xar {
    fn id(&self) -> FormatId {
        FormatId::Xar
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".xar"]
    }

    /// The header with sane fields: version 1, a table of contents that fits in the file, a
    /// known checksum algorithm.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        Header::parse(probe.head, probe.len)
            .ok()
            .map(|_| Confidence::Certain)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}

pub(crate) const MAGIC: &[u8; 4] = b"xar!";
const HEADER_LEN: usize = 28;
/// The table of contents' bounds: packed, unpacked.
pub(crate) const MAX_TOC_PACKED: u64 = 64 << 20;
pub(crate) const MAX_TOC: u64 = 256 << 20;
/// Files in the table, and how deep they nest.
const MAX_FILES: usize = 1_000_000;
const MAX_DEPTH: usize = 1024;
/// The longest text (a name, a link target) and the longest path built from names.
const MAX_TEXT: usize = 1 << 20;
const MAX_PATH: usize = 64 << 10;

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

fn corrupt(msg: impl Into<String>) -> Error {
    Error::corrupt(format!("xar: {}", msg.into()))
}

fn be64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(a)
}

/// The fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// Where the table of contents starts.
    pub size: u16,
    pub toc_packed: u64,
    pub toc_len: u64,
    /// 0 none, 1 SHA-1, 2 MD5; 3 and 4 (xar's "other", Apple's SHA-256 and SHA-512) are named
    /// by the table's `<checksum style>`.
    pub cksum: u32,
}

impl Header {
    /// The header at the start of `b`, checked against the file's length when it's known.
    pub(crate) fn parse(b: &[u8], len: Option<u64>) -> Result<Self> {
        let b = b
            .get(..HEADER_LEN)
            .filter(|b| b.starts_with(MAGIC))
            .ok_or_else(|| corrupt("no XAR header"))?;
        let h = Header {
            size: u16::from_be_bytes([b[4], b[5]]),
            toc_packed: be64(b, 8),
            toc_len: be64(b, 16),
            cksum: u32::from_be_bytes([b[24], b[25], b[26], b[27]]),
        };
        let version = u16::from_be_bytes([b[6], b[7]]);
        if version != 1 {
            return Err(Error::unsupported_format(format!(
                "a XAR of version {version}, where BeeZip reads 1"
            )));
        }
        if usize::from(h.size) < HEADER_LEN || h.toc_packed == 0 || h.cksum > 4 {
            return Err(corrupt("a damaged header"));
        }
        if let Some(len) = len
            && u64::from(h.size)
                .checked_add(h.toc_packed)
                .is_none_or(|end| end > len)
        {
            return Err(corrupt(
                "the table of contents runs past the end of the file",
            ));
        }
        Ok(h)
    }

    /// Where the heap starts.
    fn heap(&self) -> u64 {
        u64::from(self.size) + self.toc_packed
    }
}

// ---------------------------------------------------------------------------------------------
// Checksums

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algo {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Algo {
    /// `None` for `none` and for styles BeeZip doesn't know.
    fn from_name(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "md5" => Self::Md5,
            "sha1" => Self::Sha1,
            "sha224" => Self::Sha224,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    fn len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn hasher(self) -> Hasher {
        match self {
            Self::Md5 => Hasher::Md5(md5::Md5::new()),
            Self::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            Self::Sha224 => Hasher::Sha224(sha2::Sha224::new()),
            Self::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Self::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            Self::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        }
    }
}

enum Hasher {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl Hasher {
    fn update(&mut self, d: &[u8]) {
        match self {
            Self::Md5(h) => h.update(d),
            Self::Sha1(h) => h.update(d),
            Self::Sha224(h) => h.update(d),
            Self::Sha256(h) => h.update(d),
            Self::Sha384(h) => h.update(d),
            Self::Sha512(h) => h.update(d),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Md5(h) => h.finalize().to_vec(),
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha224(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// A checksum from the table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sum {
    algo: Algo,
    value: Box<[u8]>,
}

// ---------------------------------------------------------------------------------------------
// The table of contents

/// `<encoding style>`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Encoding {
    Store,
    /// `x-gzip` and RFC 6713's `zlib`: zlib, or gzip by its magic.
    Zlib,
    Bzip2,
    Xz,
    /// xz or `.lzma`, by the magic.
    Lzma,
    Unknown(Box<str>),
}

impl Encoding {
    fn from_style(s: &str) -> Self {
        match s.trim() {
            "" | "application/octet-stream" => Self::Store,
            "application/x-gzip" | "application/zlib" => Self::Zlib,
            "application/x-bzip2" => Self::Bzip2,
            "application/x-xz" => Self::Xz,
            "application/x-lzma" => Self::Lzma,
            other => Self::Unknown(other.into()),
        }
    }

    /// The method's name, for the listing.
    fn method(&self) -> Cow<'static, str> {
        match self {
            Self::Store => "Store".into(),
            Self::Zlib => "Deflate".into(),
            Self::Bzip2 => "BZip2".into(),
            Self::Xz => "XZ".into(),
            Self::Lzma => "LZMA".into(),
            Self::Unknown(s) => s.to_string().into(),
        }
    }
}

/// A file's `<data>`, checked against the heap.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Data {
    offset: u64,
    length: u64,
    size: u64,
    encoding: Encoding,
    archived: Option<Sum>,
    extracted: Option<Sum>,
}

#[derive(Debug, Default)]
pub(crate) struct RecData {
    offset: Option<u64>,
    length: Option<u64>,
    size: Option<u64>,
    encoding: Option<Encoding>,
    archived: Option<Sum>,
    extracted: Option<Sum>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecKind {
    File,
    Dir,
    Symlink,
    Hardlink,
    Other,
}

/// `<type link="…">`: the file that holds a hard link's data, or this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Link {
    Original,
    To(u64),
    Bad,
}

/// One `<file>`, in document order.
#[derive(Debug, Default)]
pub(crate) struct Rec {
    pub(crate) id: Option<u64>,
    /// The enclosing `<file>`, which comes first.
    pub(crate) parent: Option<usize>,
    /// The name's bytes: its text, or what its base64 decodes to.
    pub(crate) name: Option<Vec<u8>>,
    pub(crate) b64: bool,
    pub(crate) kind: Option<RecKind>,
    pub(crate) link: Option<Link>,
    pub(crate) target: Option<String>,
    pub(crate) mode: Option<u32>,
    pub(crate) mtime: Option<i64>,
    pub(crate) data: Option<Box<RecData>>,
}

#[derive(Debug, Default)]
struct TocSum {
    style: String,
    offset: Option<u64>,
    size: Option<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct Toc {
    pub(crate) recs: Vec<Rec>,
    checksum: Option<TocSum>,
}

/// What an open element is to the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Xar,
    Toc,
    TocChecksum,
    File,
    Data,
    Other,
}

/// The field whose text is being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Name,
    Type,
    Target,
    Mode,
    Mtime,
    Offset,
    Length,
    Size,
    Archived,
    Extracted,
    TocOffset,
    TocSize,
}

#[derive(Default)]
struct Parser {
    toc: Toc,
    stack: Vec<Tag>,
    /// The open `<file>`s, innermost last.
    files: Vec<usize>,
    field: Option<Field>,
    /// The stack's depth inside the field's element.
    field_depth: usize,
    text: String,
    /// The `<name>` being read is base64.
    b64: bool,
    /// The style of the checksum being read; `None` for `none` and unknown ones.
    algo: Option<Algo>,
    saw_toc: bool,
}

fn attr(e: &BytesStart<'_>, key: &str) -> Result<Option<String>> {
    let bad = |e: &dyn std::fmt::Display| corrupt(format!("a bad attribute: {e}"));
    match e.try_get_attribute(key).map_err(|e| bad(&e))? {
        Some(a) => Ok(Some(
            a.normalized_value_with(XmlVersion::Implicit1_0, 1, resolve_xml_entity)
                .map_err(|e| bad(&e))?
                .into_owned(),
        )),
        None => Ok(None),
    }
}

fn num(s: &str) -> Result<u64> {
    s.trim()
        .parse()
        .map_err(|_| corrupt(format!("`{}` isn't a number", s.trim())))
}

impl Parser {
    fn rec(&mut self) -> Result<&mut Rec> {
        self.files
            .last()
            .and_then(|&i| self.toc.recs.get_mut(i))
            .ok_or_else(|| corrupt("a misplaced field"))
    }

    fn data(&mut self) -> Result<&mut RecData> {
        self.rec()?
            .data
            .as_deref_mut()
            .ok_or_else(|| corrupt("a misplaced field"))
    }

    fn start(&mut self, e: &BytesStart<'_>, empty: bool) -> Result<()> {
        let parent = self.stack.last().copied();
        let qname = e.name();
        let mut tag = Tag::Other;
        let mut field = None;
        match (parent, qname.as_ref()) {
            (None, "xar") => tag = Tag::Xar,
            (Some(Tag::Xar), "toc") => {
                tag = Tag::Toc;
                self.saw_toc = true;
            }
            (Some(Tag::Toc), "checksum") => {
                tag = Tag::TocChecksum;
                self.toc.checksum = Some(TocSum {
                    style: attr(e, "style")?.unwrap_or_default(),
                    ..TocSum::default()
                });
            }
            (Some(Tag::TocChecksum), "offset") => field = Some(Field::TocOffset),
            (Some(Tag::TocChecksum), "size") => field = Some(Field::TocSize),
            (Some(Tag::Toc | Tag::File), "file") => {
                if self.toc.recs.len() >= MAX_FILES {
                    return Err(Error::limit(format!(
                        "xar: the table of contents lists more than {MAX_FILES} files"
                    )));
                }
                if self.files.len() >= MAX_DEPTH {
                    return Err(corrupt(format!(
                        "files are nested more than {MAX_DEPTH} deep"
                    )));
                }
                let id = attr(e, "id")?.and_then(|s| s.trim().parse().ok());
                self.toc.recs.push(Rec {
                    id,
                    parent: self.files.last().copied(),
                    ..Rec::default()
                });
                tag = Tag::File;
                if !empty {
                    self.files.push(self.toc.recs.len() - 1);
                }
            }
            (Some(Tag::File), "name") => {
                self.b64 = attr(e, "enctype")?.as_deref() == Some("base64");
                field = Some(Field::Name);
            }
            (Some(Tag::File), "type") => {
                let link = attr(e, "link")?.map(|l| match l.trim() {
                    "original" => Link::Original,
                    id => id.parse().map_or(Link::Bad, Link::To),
                });
                self.rec()?.link = link;
                field = Some(Field::Type);
            }
            (Some(Tag::File), "link") => field = Some(Field::Target),
            (Some(Tag::File), "mode") => field = Some(Field::Mode),
            (Some(Tag::File), "mtime") => field = Some(Field::Mtime),
            (Some(Tag::File), "data") => {
                let rec = self.rec()?;
                if rec.data.is_some() {
                    return Err(corrupt("a file with two <data>s"));
                }
                rec.data = Some(Box::default());
                tag = Tag::Data;
            }
            (Some(Tag::Data), "offset") => field = Some(Field::Offset),
            (Some(Tag::Data), "length") => field = Some(Field::Length),
            (Some(Tag::Data), "size") => field = Some(Field::Size),
            (Some(Tag::Data), "encoding") => {
                let style = attr(e, "style")?.unwrap_or_default();
                self.data()?.encoding = Some(Encoding::from_style(&style));
            }
            (Some(Tag::Data), which @ ("archived-checksum" | "extracted-checksum")) => {
                self.algo = Algo::from_name(&attr(e, "style")?.unwrap_or_default());
                field = Some(if which == "archived-checksum" {
                    Field::Archived
                } else {
                    Field::Extracted
                });
            }
            _ => {}
        }
        if empty {
            if let Some(f) = field {
                self.commit(f, "")?;
            }
        } else {
            self.stack.push(tag);
            if field.is_some() {
                self.field = field;
                self.field_depth = self.stack.len();
                self.text.clear();
            }
        }
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        let depth = self.stack.len();
        let tag = self
            .stack
            .pop()
            .ok_or_else(|| corrupt("an end tag without a start"))?;
        if let Some(f) = self.field
            && depth == self.field_depth
        {
            self.field = None;
            let text = std::mem::take(&mut self.text);
            self.commit(f, &text)?;
        }
        if tag == Tag::File {
            self.files.pop();
        }
        Ok(())
    }

    fn collecting(&self) -> bool {
        self.field.is_some() && self.stack.len() == self.field_depth
    }

    fn text(&mut self, s: &str) -> Result<()> {
        if !self.collecting() {
            return Ok(());
        }
        if self.text.len() + s.len() > MAX_TEXT {
            return Err(corrupt(
                "a text in the table of contents is longer than 1 MiB",
            ));
        }
        self.text.push_str(s);
        Ok(())
    }

    /// `&…;` in a text: a character, or one of XML's five entities. Others fail.
    fn reference(&mut self, r: &BytesRef<'_>) -> Result<()> {
        if !self.collecting() {
            return Ok(());
        }
        if r.is_char_ref() {
            let c = r
                .resolve_char_ref()
                .ok()
                .flatten()
                .ok_or_else(|| corrupt(format!("a bad character reference `&{};`", &**r)))?;
            return self.text(c.encode_utf8(&mut [0; 4]));
        }
        let v = resolve_xml_entity(r)
            .ok_or_else(|| corrupt(format!("an unknown entity `&{};`", &**r)))?;
        self.text(v)
    }

    fn commit(&mut self, f: Field, text: &str) -> Result<()> {
        let b64 = self.b64;
        let algo = self.algo;
        match f {
            Field::TocOffset | Field::TocSize => {
                let n = num(text)?;
                let sum = self
                    .toc
                    .checksum
                    .as_mut()
                    .ok_or_else(|| corrupt("a misplaced field"))?;
                if f == Field::TocOffset {
                    sum.offset = Some(n);
                } else {
                    sum.size = Some(n);
                }
            }
            Field::Name => {
                let name = if b64 {
                    base64(text)?
                } else {
                    text.as_bytes().to_vec()
                };
                let rec = self.rec()?;
                rec.name = Some(name);
                rec.b64 = b64;
            }
            Field::Type => {
                self.rec()?.kind = Some(match text.trim() {
                    "file" => RecKind::File,
                    "directory" => RecKind::Dir,
                    "symlink" => RecKind::Symlink,
                    "hardlink" => RecKind::Hardlink,
                    _ => RecKind::Other,
                });
            }
            Field::Target => self.rec()?.target = Some(text.to_owned()),
            Field::Mode => {
                self.rec()?.mode = u32::from_str_radix(text.trim(), 8).ok().map(|m| m & 0o7777);
            }
            Field::Mtime => self.rec()?.mtime = parse_time(text),
            Field::Offset => self.data()?.offset = Some(num(text)?),
            Field::Length => self.data()?.length = Some(num(text)?),
            Field::Size => self.data()?.size = Some(num(text)?),
            Field::Archived | Field::Extracted => {
                let value = hex(text)?;
                let sum = match algo {
                    Some(a) if value.len() != a.len() => {
                        return Err(corrupt(format!(
                            "a {} checksum of {} bytes",
                            a.name(),
                            value.len()
                        )));
                    }
                    Some(a) => Some(Sum {
                        algo: a,
                        value: value.into(),
                    }),
                    None => None,
                };
                let d = self.data()?;
                if f == Field::Archived {
                    d.archived = sum;
                } else {
                    d.extracted = sum;
                }
            }
        }
        Ok(())
    }
}

/// Parses a table of contents. `partial` reads what it can of a prefix (for sniffing): an error
/// or the end ends the parse, and the files read so far are returned. `check` is called now
/// and then, for cancelling.
pub(crate) fn parse_toc<R: BufRead>(
    r: R,
    partial: bool,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<Toc> {
    let mut rd = Reader::from_reader(r);
    let mut p = Parser::default();
    let mut buf = Vec::new();
    let mut events = 0u32;
    loop {
        events = events.wrapping_add(1);
        if events.is_multiple_of(4096) {
            check()?;
        }
        buf.clear();
        let ev = match rd.read_event_into(&mut buf) {
            Ok(ev) => ev,
            Err(_) if partial => break,
            Err(e) => return Err(toc_error(&e)),
        };
        let step = match ev {
            Event::Start(e) => p.start(&e, false),
            Event::Empty(e) => p.start(&e, true),
            Event::End(_) => p.end(),
            Event::Text(t) => p.text(&t.xml10_content()),
            Event::CData(t) => p.text(&t.xml10_content()),
            Event::GeneralRef(r) => p.reference(&r),
            Event::DocType(d) if d.contains("ENTITY") => Err(corrupt(
                "the table of contents declares entities, which BeeZip doesn't expand",
            )),
            Event::Eof => break,
            _ => Ok(()),
        };
        match step {
            Err(_) if partial => break,
            step => step?,
        }
    }
    if !partial {
        if !p.stack.is_empty() {
            return Err(corrupt("the table of contents ends inside an element"));
        }
        if !p.saw_toc {
            return Err(corrupt("the table of contents has no <toc>"));
        }
    }
    Ok(p.toc)
}

/// A parse error: one from the inflater (smuggled through quick-xml) comes back as it was.
fn toc_error(e: &quick_xml::Error) -> Error {
    if let quick_xml::Error::Io(io) = e {
        let err = read_error(io);
        if err.kind != ErrorKind::Corrupt || err.message.starts_with("xar:") {
            return err;
        }
        return corrupt(format!(
            "the table of contents doesn't inflate: {}",
            err.message
        ));
    }
    corrupt(format!("the table of contents isn't valid XML: {e}"))
}

/// `YYYY-MM-DDTHH:MM:SS`, with an optional fraction and `Z`, in seconds since 1970.
fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches('Z');
    let s = s.split('.').next()?;
    let b = s.as_bytes();
    if b.len() != 19
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let n = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

fn base64(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            c if c.is_ascii_whitespace() => continue,
            _ => return Err(corrupt("a name isn't base64")),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().as_bytes();
    let digit = |c: u8| (c as char).to_digit(16);
    if !s.len().is_multiple_of(2) {
        return Err(corrupt("a checksum isn't hex"));
    }
    s.as_chunks::<2>()
        .0
        .iter()
        .map(|&[a, b]| match (digit(a), digit(b)) {
            (Some(a), Some(b)) => Ok((a * 16 + b) as u8),
            _ => Err(corrupt("a checksum isn't hex")),
        })
        .collect()
}

/// The inflated table of contents, as quick-xml reads it: no more than its declared length,
/// and no run of more than [`MAX_TEXT`] bytes without a `<`, so a text or a tag can't grow
/// quick-xml's buffer without bound.
struct Bounded<'a, R> {
    inner: R,
    count: &'a Cell<u64>,
    max: u64,
    run: usize,
}

impl<R: Read> Read for Bounded<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let room = usize::try_from(self.max - self.count.get())
            .unwrap_or(usize::MAX)
            .saturating_add(1)
            .min(buf.len());
        let n = self.inner.read(&mut buf[..room])?;
        let total = self.count.get() + n as u64;
        if total > self.max {
            return Err(corrupt(format!(
                "the table of contents is longer than the {} bytes its header says",
                self.max
            ))
            .into_io());
        }
        self.count.set(total);
        let got = &buf[..n];
        self.run = match memchr::memrchr(b'<', got) {
            Some(at) => n - at - 1,
            None => self.run + n,
        };
        if self.run > MAX_TEXT + 4096 {
            return Err(corrupt("a text in the table of contents is longer than 1 MiB").into_io());
        }
        Ok(n)
    }
}

/// Inflates up to `max` bytes of a table of contents' start, for sniffing.
pub(crate) fn toc_prefix(packed: &[u8], max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut z = flate2::read::ZlibDecoder::new(packed).take(max as u64);
    let mut buf = [0u8; 8192];
    while let Ok(n) = z.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The archive

pub(crate) trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// An open XAR: its listing, and each entry's data where it lies in the heap.
pub(crate) struct Archive {
    input: Box<dyn ReadSeek>,
    /// A XAR decoded out of a codec, spooled to a file, kept while it's read.
    _spool: Option<Partial>,
    /// The file's length, and where the heap starts.
    pub(crate) len: u64,
    pub(crate) heap: u64,
    /// In table order, except that a hard link follows the file it links to.
    pub(crate) entries: Vec<Entry>,
    /// Each entry's data, by id: a hard link's is its target's.
    data: Vec<Option<Data>>,
    /// The table failed its checksum: every read fails with this.
    pub(crate) bad_toc: Option<Error>,
    counter: Counter,
    limits: Limits,
}

impl Archive {
    pub(crate) fn open(source: &Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (mut input, spool): (Box<dyn ReadSeek>, _) = if source.codecs.is_empty() {
            (Box::new(source.input()?), None)
        } else {
            // Data is read by offset: spool the decoded stream, under the usual limits.
            let mut tmp = Partial::create_temp("beezip-spool.xar")?;
            let mut stream = source.guard(source.open_stream()?);
            crate::io::copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            let file = std::fs::File::open(tmp.path())
                .map_err(|e| Error::io(format!("opening {}", tmp.path().display()), &e))?;
            (Box::new(file), Some(tmp))
        };
        let io_err = |e: io::Error| Error::io("reading the XAR", &e);
        let len = input.seek(SeekFrom::End(0)).map_err(io_err)?;
        input.seek(SeekFrom::Start(0)).map_err(io_err)?;
        let mut head = [0u8; HEADER_LEN];
        input
            .read_exact(&mut head)
            .map_err(|_| corrupt("the file is too short for a XAR header"))?;
        let h = Header::parse(&head, Some(len))?;
        if h.toc_packed > MAX_TOC_PACKED || h.toc_len > MAX_TOC {
            return Err(Error::limit(format!(
                "xar: the table of contents claims {} bytes ({} packed), where BeeZip reads at most {} MiB ({} MiB packed)",
                h.toc_len,
                h.toc_packed,
                MAX_TOC >> 20,
                MAX_TOC_PACKED >> 20
            )));
        }
        // Bounded by the file's length and MAX_TOC_PACKED.
        input
            .seek(SeekFrom::Start(u64::from(h.size)))
            .map_err(io_err)?;
        let mut packed = Vec::with_capacity(usize::try_from(h.toc_packed).unwrap_or(0));
        (&mut input)
            .take(h.toc_packed)
            .read_to_end(&mut packed)
            .map_err(io_err)?;
        if packed.len() as u64 != h.toc_packed {
            return Err(corrupt("the table of contents is cut short"));
        }
        let got = Cell::new(0u64);
        let xml = Bounded {
            inner: flate2::read::ZlibDecoder::new(&packed[..]),
            count: &got,
            max: h.toc_len,
            run: 0,
        };
        let toc = parse_toc(BufReader::with_capacity(64 << 10, xml), false, &mut || {
            cx.check()
        })?;
        if got.get() != h.toc_len {
            return Err(corrupt(format!(
                "the table of contents is {} bytes, where its header says {}",
                got.get(),
                h.toc_len
            )));
        }
        let heap = h.heap();
        let heap_len = len - heap;
        let bad_toc = check_toc(&h, toc.checksum.as_ref(), &packed, &mut input, heap_len, cx)?;
        drop(packed);
        let (entries, data) = build(&toc.recs, &source.names, &source.limits, len, heap_len)?;
        drop(toc);
        Ok(Self {
            input,
            _spool: spool,
            len,
            heap,
            entries,
            data,
            bad_toc,
            counter: source.counter.clone(),
            limits: source.limits.clone(),
        })
    }

    /// Where entry `id`'s data lies in the heap, when it has any.
    pub(crate) fn data_range(&self, id: usize) -> Option<(u64, u64)> {
        self.data
            .get(id)?
            .as_ref()
            .filter(|d| d.length > 0)
            .map(|d| (d.offset, d.length))
    }

    /// The compression methods the entries use, in the order met.
    pub(crate) fn methods(&self) -> Vec<Cow<'static, str>> {
        let mut out: Vec<Cow<'static, str>> = Vec::new();
        for m in self.entries.iter().filter_map(|e| e.method.as_ref()) {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
        out
    }

    /// Entry `id`'s data, decoded, and checked against its size and checksums as it ends.
    pub(crate) fn reader(&mut self, id: usize) -> Result<Box<dyn Read + Send + '_>> {
        if let Some(e) = &self.bad_toc {
            return Err(e.clone());
        }
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        let Some(d) = self.data.get(id).cloned().flatten() else {
            return Ok(Box::new(io::empty()));
        };
        let path = match &entry.kind {
            EntryKind::Hardlink { target } => target.clone(),
            _ => entry.path.clone(),
        };
        let at = self.heap + d.offset;
        let io_err = |e: io::Error| Error::io("reading the XAR", &e);
        let mut magic = [0u8; 6];
        if matches!(d.encoding, Encoding::Zlib | Encoding::Lzma) {
            let n = usize::try_from(d.length.min(6)).unwrap_or(0);
            self.input.seek(SeekFrom::Start(at)).map_err(io_err)?;
            self.input
                .read_exact(&mut magic[..n])
                .map_err(|e| read_error(&e))?;
        }
        let codec = match &d.encoding {
            Encoding::Store => None,
            Encoding::Zlib if magic.starts_with(&[0x1F, 0x8B]) => Some(CodecId::Gzip),
            Encoding::Zlib => Some(CodecId::Zlib),
            Encoding::Bzip2 => Some(CodecId::Bzip2),
            Encoding::Xz => Some(CodecId::Xz),
            Encoding::Lzma if magic == *b"\xFD7zXZ\0" => Some(CodecId::Xz),
            Encoding::Lzma => Some(CodecId::Lzma),
            Encoding::Unknown(s) => {
                return Err(Error::unsupported(format!(
                    "xar: `{path}` is encoded as `{s}`, which BeeZip doesn't decode"
                )));
            }
        };
        self.input.seek(SeekFrom::Start(at)).map_err(io_err)?;
        let raw = Shared(Arc::new(Mutex::new(Raw {
            r: (&mut self.input).take(d.length),
            hash: d.archived.as_ref().map(|s| s.algo.hasher()),
            counter: self.counter.clone(),
            read: 0,
        })));
        let dec: Box<dyn Read + Send + '_> = match codec {
            None => Box::new(raw.clone()),
            Some(c) => {
                let cap = usize::try_from(d.length.clamp(1, 64 << 10)).unwrap_or(1);
                let buffered = Box::new(BufReader::with_capacity(cap, raw.clone()));
                c.decoder(buffered, &self.limits)
                    .map_err(|e| e.context(format!("xar: `{path}`")))?
            }
        };
        Ok(Box::new(Verify {
            dec,
            raw,
            hash: d.extracted.as_ref().map(|s| s.algo.hasher()),
            data: d,
            path,
            out: 0,
            done: false,
        }))
    }

    /// Hands the selected entries to `sink`, in listing order.
    fn extract(
        &mut self,
        source: &Source,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        if let Some(e) = &self.bad_toc {
            return Err(e.clone());
        }
        let mut meter = Meter::new(self.counter.clone(), Some(self.len));
        meter.entries_total = Some(self.entries.len() as u64);
        self.counter.set(self.heap);
        for id in 0..self.entries.len() {
            cx.check()?;
            if !sel.matches(&self.entries[id]) {
                continue;
            }
            let e = self.entries[id].clone();
            meter.entries_done = id as u64;
            meter.current = Some(e.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            let data: Box<dyn Read + '_> = if e.kind == EntryKind::File {
                match self.reader(id) {
                    Ok(r) => r,
                    Err(err) => Box::new(Failing(err)),
                }
            } else {
                Box::new(io::empty())
            };
            let mut data = source.guard(data);
            sink.entry(&e, &mut data, &mut mcx)?;
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }
}

/// Checks the table's checksum. `Ok(Some(error))` when it doesn't match: the listing stands,
/// with a warning, and reads fail with the error.
fn check_toc(
    h: &Header,
    sum: Option<&TocSum>,
    packed: &[u8],
    input: &mut dyn ReadSeek,
    heap_len: u64,
    cx: &mut dyn Ctx,
) -> Result<Option<Error>> {
    let Some(sum) = sum.filter(|_| h.cksum != 0) else {
        return Ok(None);
    };
    let algo = match (h.cksum, Algo::from_name(&sum.style)) {
        (1, _) => Algo::Sha1,
        (2, _) => Algo::Md5,
        (_, Some(a)) => a,
        (_, None) => {
            cx.warn(format!(
                "xar: the table of contents' checksum `{}` isn't one BeeZip checks",
                sum.style
            ));
            return Ok(None);
        }
    };
    let (Some(offset), Some(size)) = (sum.offset, sum.size) else {
        return Err(corrupt("the table of contents' checksum has no place"));
    };
    if size != algo.len() as u64 || offset.checked_add(size).is_none_or(|e| e > heap_len) {
        return Err(corrupt("the table of contents' checksum is out of place"));
    }
    let mut stored = vec![0u8; algo.len()];
    input
        .seek(SeekFrom::Start(h.heap() + offset))
        .and_then(|_| input.read_exact(&mut stored))
        .map_err(|e| Error::io("reading the XAR", &e))?;
    let mut hasher = algo.hasher();
    hasher.update(packed);
    if hasher.finish() == stored {
        return Ok(None);
    }
    let msg = format!(
        "the table of contents doesn't match its {} checksum",
        algo.name()
    );
    cx.warn(format!("xar: {msg}: its entries can't be read"));
    Ok(Some(corrupt(msg)))
}

/// What a record is, once hard links are resolved.
enum Kind {
    File,
    Dir,
    Symlink,
    /// To the record with the data.
    Hardlink(usize),
    Other,
}

/// The listing from the table's records: paths from the parents, hard links resolved and put
/// after their targets, data checked against the heap.
#[allow(clippy::type_complexity)]
fn build(
    recs: &[Rec],
    names: &NameDecoding,
    limits: &Limits,
    file_len: u64,
    heap_len: u64,
) -> Result<(Vec<Entry>, Vec<Option<Data>>)> {
    let n = recs.len();
    limits.check_entries(n as u64)?;
    let mut paths: Vec<(String, Vec<u8>)> = Vec::with_capacity(n);
    for (i, r) in recs.iter().enumerate() {
        let Some(name) = r.name.as_ref().filter(|n| !n.is_empty()) else {
            return Err(corrupt(format!(
                "file {} has no name",
                r.id.unwrap_or(i as u64)
            )));
        };
        let text = if r.b64 {
            names.decode(name, false, SystemPage::Ansi)
        } else {
            String::from_utf8_lossy(name).into_owned()
        };
        let joined = match r.parent.and_then(|p| paths.get(p)) {
            Some((pp, pr)) => {
                let mut raw = Vec::with_capacity(pr.len() + 1 + name.len());
                raw.extend_from_slice(pr);
                raw.push(b'/');
                raw.extend_from_slice(name);
                (format!("{pp}/{text}"), raw)
            }
            None => (text, name.clone()),
        };
        if joined.1.len() > MAX_PATH {
            return Err(corrupt("a path is longer than 64 KiB"));
        }
        paths.push(joined);
    }
    let mut by_id: HashMap<u64, usize> = HashMap::with_capacity(n);
    for (i, r) in recs.iter().enumerate() {
        if let Some(id) = r.id {
            by_id.entry(id).or_insert(i);
        }
    }
    // A file, or the hard link that holds its group's data.
    let holds_data = |r: &Rec| match r.kind {
        None | Some(RecKind::File) => true,
        Some(RecKind::Hardlink) => !matches!(r.link, Some(Link::To(_))),
        _ => false,
    };
    let mut kinds = Vec::with_capacity(n);
    for (i, r) in recs.iter().enumerate() {
        kinds.push(match r.kind {
            None | Some(RecKind::File) => Kind::File,
            Some(RecKind::Dir) => Kind::Dir,
            Some(RecKind::Symlink) => Kind::Symlink,
            Some(RecKind::Other) => Kind::Other,
            Some(RecKind::Hardlink) => match r.link {
                None | Some(Link::Original) => Kind::File,
                Some(Link::To(id)) => match by_id.get(&id) {
                    Some(&t) if t != i && holds_data(&recs[t]) => Kind::Hardlink(t),
                    _ => {
                        return Err(corrupt(format!(
                            "`{}` is a hard link to file {id}, which isn't a file in the archive",
                            paths[i].0
                        )));
                    }
                },
                Some(Link::Bad) => {
                    return Err(corrupt(format!(
                        "`{}` is a hard link to nothing",
                        paths[i].0
                    )));
                }
            },
        });
    }
    // Hard links after their targets: the order the entries are listed and extracted in.
    let mut order = Vec::with_capacity(n);
    let mut waiting: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, k) in kinds.iter().enumerate() {
        match k {
            Kind::Hardlink(t) if *t > i => waiting.entry(*t).or_default().push(i),
            _ => {
                order.push(i);
                if let Some(links) = waiting.remove(&i) {
                    order.extend(links);
                }
            }
        }
    }
    let mut new_id = vec![0usize; n];
    for (id, &i) in order.iter().enumerate() {
        new_id[i] = id;
    }
    // Each file's data, checked against the heap.
    let mut datas: Vec<Option<Data>> = Vec::with_capacity(n);
    for (i, r) in recs.iter().enumerate() {
        let d = match (&kinds[i], r.data.as_deref()) {
            (Kind::File, Some(d)) => {
                let path = &paths[i].0;
                let missing = |what: &str| corrupt(format!("`{path}`'s data has no {what}"));
                let d = Data {
                    offset: d.offset.ok_or_else(|| missing("offset"))?,
                    length: d.length.ok_or_else(|| missing("length"))?,
                    size: d.size.ok_or_else(|| missing("size"))?,
                    encoding: d.encoding.clone().unwrap_or(Encoding::Store),
                    archived: d.archived.clone(),
                    extracted: d.extracted.clone(),
                };
                if d.offset
                    .checked_add(d.length)
                    .is_none_or(|end| end > heap_len)
                {
                    return Err(corrupt(format!(
                        "`{path}`'s data lies past the end of the file"
                    )));
                }
                Some(d)
            }
            _ => None,
        };
        datas.push(d);
    }
    // Files sharing part of their data are the overlapping-entry bomb, refused as in zips
    // (docs/M1.md §3). The same range twice is xar's `--link-same`, allowed, but what the
    // second and later copies decode to is held to the ratio limit against the whole file, so
    // a few bytes can't stand for any number of copies of one big stream.
    let mut ranges: Vec<(u64, u64, u64)> = datas
        .iter()
        .flatten()
        .filter(|d| d.length > 0)
        .map(|d| (d.offset, d.offset + d.length, d.size))
        .collect();
    ranges.sort_unstable();
    let mut shared = 0u64;
    for w in ranges.windows(2) {
        if (w[0].0, w[0].1) == (w[1].0, w[1].1) {
            shared = shared.saturating_add(w[1].2);
        } else if w[1].0 < w[0].1 {
            return Err(Error::new(
                ErrorKind::Unsafe,
                "xar: files share parts of their data (an overlapping-entry bomb)",
            ));
        }
    }
    if let Some(ratio) = limits.max_ratio
        && shared > limits.ratio_grace.max(ratio.saturating_mul(file_len))
    {
        return Err(Error::limit(format!(
            "xar: files sharing their data decode to {shared} bytes more, over {ratio} times the archive's size (limit `max_ratio`)"
        )));
    }
    // The entries, in the new order: a hard link's target is already listed when it's met.
    let mut entries: Vec<Entry> = Vec::with_capacity(n);
    let mut data = Vec::with_capacity(n);
    for (id, &i) in order.iter().enumerate() {
        let r = &recs[i];
        let (path, raw) = std::mem::take(&mut paths[i]);
        let (kind, d, ifmt) = match &kinds[i] {
            Kind::File => (EntryKind::File, datas[i].clone(), S_IFREG),
            Kind::Dir => (EntryKind::Dir, None, S_IFDIR),
            Kind::Symlink => (
                EntryKind::Symlink {
                    target: r.target.clone().unwrap_or_default(),
                },
                None,
                S_IFLNK,
            ),
            Kind::Hardlink(t) => (
                EntryKind::Hardlink {
                    target: entries[new_id[*t]].path.clone(),
                },
                datas[*t].clone(),
                S_IFREG,
            ),
            Kind::Other => (EntryKind::Other, None, 0),
        };
        let mut e = Entry::new(id, path, kind);
        e.raw_path = raw;
        if e.kind == EntryKind::Dir {
            e.path.push('/');
        }
        if e.kind == EntryKind::File {
            e.size = Some(d.as_ref().map_or(0, |d| d.size));
            e.packed_size = Some(d.as_ref().map_or(0, |d| d.length));
            e.method = d.as_ref().map(|d| d.encoding.method());
        }
        e.modified = r.mtime.and_then(|s| from_unix(s, 0));
        e.unix_mode = r.mode.map(|m| ifmt | m);
        entries.push(e);
        data.push(d);
    }
    Ok((entries, data))
}

/// A file's raw bytes in the heap, hashed and counted as they're read.
struct Raw<'a> {
    r: io::Take<&'a mut Box<dyn ReadSeek>>,
    hash: Option<Hasher>,
    counter: Counter,
    read: u64,
}

impl Read for Raw<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(buf)?;
        if let Some(h) = &mut self.hash {
            h.update(&buf[..n]);
        }
        self.counter.add(n as u64);
        self.read += n as u64;
        Ok(n)
    }
}

/// [`Raw`], shared by the decoder that reads it and the [`Verify`] that drains and checks it.
#[derive(Clone)]
struct Shared<'a>(Arc<Mutex<Raw<'a>>>);

impl Read for Shared<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read(buf)
    }
}

/// A file's decoded data. When the decoder ends: the size must be the table's, the raw bytes
/// must all have been there, and both checksums must match.
struct Verify<'a> {
    dec: Box<dyn Read + Send + 'a>,
    raw: Shared<'a>,
    hash: Option<Hasher>,
    data: Data,
    path: String,
    out: u64,
    done: bool,
}

impl Verify<'_> {
    fn fail(&self, msg: impl std::fmt::Display) -> io::Error {
        corrupt(format!("`{}`: {msg}", self.path)).into_io()
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.out != self.data.size {
            return Err(self.fail(format_args!(
                "its data decodes to {} bytes, where the table says {}",
                self.out, self.data.size
            )));
        }
        let mut raw = self.raw.0.lock().unwrap_or_else(PoisonError::into_inner);
        io::copy(&mut *raw, &mut io::sink())?;
        if raw.read != self.data.length {
            let read = raw.read;
            drop(raw);
            return Err(self.fail(format_args!(
                "its data is cut short ({read} of {} bytes)",
                self.data.length
            )));
        }
        let archived = raw.hash.take();
        drop(raw);
        for (which, h, sum) in [
            ("archived", archived, &self.data.archived),
            ("extracted", self.hash.take(), &self.data.extracted),
        ] {
            if let (Some(h), Some(sum)) = (h, sum)
                && *h.finish() != *sum.value
            {
                return Err(self.fail(format_args!(
                    "its {which} data doesn't match its {} checksum",
                    sum.algo.name()
                )));
            }
        }
        Ok(())
    }
}

impl Read for Verify<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        // One byte more than the size, to see a stream that decodes to more.
        let room = usize::try_from(self.data.size - self.out)
            .unwrap_or(usize::MAX)
            .saturating_add(1)
            .min(buf.len());
        let k = match self.dec.read(&mut buf[..room]) {
            Ok(k) => k,
            Err(e) => {
                let err = read_error(&e);
                return Err(if err.kind == ErrorKind::Corrupt {
                    self.fail(err.message)
                } else {
                    err.into_io()
                });
            }
        };
        if k == 0 {
            self.done = true;
            self.finish()?;
            return Ok(0);
        }
        self.out = self.out.saturating_add(k as u64);
        if self.out > self.data.size {
            self.done = true;
            return Err(self.fail(format_args!(
                "its data decodes to more than the {} bytes the table says",
                self.data.size
            )));
        }
        if let Some(h) = &mut self.hash {
            h.update(&buf[..k]);
        }
        Ok(k)
    }
}

/// An entry whose data can't be read: the error, on every read.
pub(crate) struct Failing(pub(crate) Error);

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self.0.clone().into_io())
    }
}

// ---------------------------------------------------------------------------------------------
// The reader

pub struct XarReader {
    source: Source,
    xar: Archive,
}

impl XarReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let xar = Archive::open(&source, cx)?;
        Ok(Self { source, xar })
    }
}

impl ArchiveReader for XarReader {
    fn format(&self) -> FormatId {
        FormatId::Xar
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.xar.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Xar,
            codecs: self.source.codecs.clone(),
            methods: self.xar.methods(),
            comment: None,
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
        self.xar.extract(&self.source, sel, sink, cx)
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let kind = self
            .xar
            .entries
            .get(id)
            .map(|e| e.kind.clone())
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        match kind {
            EntryKind::File | EntryKind::Hardlink { .. } => {
                Ok(Box::new(self.source.guard(self.xar.reader(id)?)))
            }
            _ => Ok(Box::new(io::empty())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(size: u16, version: u16, packed: u64, len: u64, cksum: u32) -> Vec<u8> {
        let mut h = MAGIC.to_vec();
        h.extend_from_slice(&size.to_be_bytes());
        h.extend_from_slice(&version.to_be_bytes());
        h.extend_from_slice(&packed.to_be_bytes());
        h.extend_from_slice(&len.to_be_bytes());
        h.extend_from_slice(&cksum.to_be_bytes());
        h
    }

    #[test]
    fn headers_are_checked() {
        let ok = header(28, 1, 100, 400, 1);
        assert!(Header::parse(&ok, None).is_ok());
        assert!(Header::parse(&ok, Some(128)).is_ok());
        // The table past the end of the file.
        assert!(Header::parse(&ok, Some(127)).is_err());
        assert!(Header::parse(&header(27, 1, 100, 400, 1), None).is_err());
        assert!(Header::parse(&header(28, 1, 0, 400, 1), None).is_err());
        assert!(Header::parse(&header(28, 1, 100, 400, 5), None).is_err());
        assert_eq!(
            Header::parse(&header(28, 2, 100, 400, 1), None)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedFormat
        );
        assert!(Header::parse(&ok[..27], None).is_err());
        // Lengths whose sum overflows.
        assert!(Header::parse(&header(28, 1, u64::MAX, 400, 1), Some(1 << 20)).is_err());
        let probe = Probe {
            head: &ok,
            len: Some(4096),
            ..Probe::default()
        };
        assert_eq!(Xar.sniff(&probe), Some(Confidence::Certain));
    }

    #[test]
    fn times_names_and_sums_parse() {
        assert_eq!(parse_time("2021-03-04T05:06:07Z"), Some(1_614_834_367));
        assert_eq!(parse_time(" 1970-01-01T00:00:00.123Z "), Some(0));
        assert_eq!(parse_time("1969-12-31T23:59:59Z"), Some(-1));
        assert_eq!(parse_time("2021-13-04T05:06:07Z"), None);
        assert_eq!(parse_time("2021-03-04 05:06:07"), None);
        assert_eq!(parse_time("+021-03-04T05:06:07Z"), None);
        assert_eq!(parse_time(""), None);
        assert_eq!(
            base64("ZW1vamkg8J+QnS50eHQ=").unwrap(),
            "emoji 🐝.txt".as_bytes()
        );
        assert_eq!(base64("YQ\n==").unwrap(), b"a");
        assert!(base64("a*b").is_err());
        assert_eq!(hex(" 00ff10 ").unwrap(), [0, 255, 16]);
        assert!(hex("abc").is_err());
        assert!(hex("zz").is_err());
    }

    fn parse(xml: &str) -> Result<Toc> {
        parse_toc(xml.as_bytes(), false, &mut || Ok(()))
    }

    #[test]
    fn the_table_is_parsed_without_entities_or_recursion() {
        let toc = parse(concat!(
            "<?xml version=\"1.0\"?><xar><toc>",
            "<checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>",
            "<file id=\"1\"><name>a &amp; &#x62;</name><name>a &amp; &#x62;</name>",
            "<type>directory</type>",
            "<file id=\"2\"><name enctype=\"base64\">eA==</name><mode>0755</mode>",
            "<data><offset>0</offset><length>3</length><size>3</size>",
            "<encoding style=\"application/x-xz\"/>",
            "<extracted-checksum style=\"md5\">00112233445566778899aabbccddeeff</extracted-checksum>",
            "<archived-checksum style=\"crc32\">00</archived-checksum></data>",
            "</file></file></toc></xar>"
        ))
        .unwrap();
        assert_eq!(toc.recs.len(), 2);
        assert_eq!(toc.recs[0].name.as_deref(), Some(&b"a & b"[..]));
        assert_eq!(toc.recs[0].kind, Some(RecKind::Dir));
        assert_eq!(toc.recs[1].parent, Some(0));
        assert_eq!(toc.recs[1].name.as_deref(), Some(&b"x"[..]));
        assert_eq!(toc.recs[1].mode, Some(0o755));
        let d = toc.recs[1].data.as_deref().unwrap();
        assert_eq!(d.encoding, Some(Encoding::Xz));
        assert_eq!(d.extracted.as_ref().map(|s| s.algo), Some(Algo::Md5));
        // A checksum of a style BeeZip doesn't know isn't checked.
        assert_eq!(d.archived, None);
        let sum = toc.checksum.unwrap();
        assert_eq!(
            (sum.style.as_str(), sum.offset, sum.size),
            ("sha1", Some(0), Some(20))
        );

        // Nesting that isn't files costs nothing; files nest at most MAX_DEPTH deep.
        let deep = format!(
            "<xar><toc>{}{}</toc></xar>",
            "<a>".repeat(100_000),
            "</a>".repeat(100_000)
        );
        assert!(parse(&deep).unwrap().recs.is_empty());
        let deep = format!(
            "<xar><toc>{}</toc></xar>",
            "<file><name>d</name>".repeat(MAX_DEPTH + 1)
        );
        assert!(parse(&deep).is_err());
        // A prefix parses as far as it goes.
        let cut = "<xar><toc><file><name>Distribution</name></file><file><na";
        let toc = parse_toc(cut.as_bytes(), true, &mut || Ok(())).unwrap();
        assert_eq!(toc.recs[0].name.as_deref(), Some(&b"Distribution"[..]));
        assert!(parse(cut).is_err());
        // A checksum of the wrong length for its style.
        assert!(
            parse(concat!(
                "<xar><toc><file><data>",
                "<extracted-checksum style=\"sha1\">00</extracted-checksum>",
                "</data></file></toc></xar>"
            ))
            .is_err()
        );
    }

    #[test]
    fn a_long_text_stops_the_inflater() {
        let xml = format!(
            "<xar><toc><file><name>{}</name></file></toc></xar>",
            "n".repeat(3 << 20)
        );
        let count = Cell::new(0);
        let r = Bounded {
            inner: xml.as_bytes(),
            count: &count,
            max: xml.len() as u64,
            run: 0,
        };
        let e = parse_toc(BufReader::new(r), false, &mut || Ok(()))
            .err()
            .unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt);
        assert!(e.message.contains("1 MiB"), "{e}");
        // It stopped well before the end.
        assert!(count.get() < 2 << 20);
    }
}
