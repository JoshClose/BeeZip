//! An MSI's compound file and its tables (docs/M7.md §8.1).
//!
//! - **Streams** are found by their compressed names: Windows Installer packs two characters of
//!   `[0-9A-Za-z._]` into one code point (and one into another range), and puts U+4840 before a
//!   table's name. A stream is read whole only when it's a table or the string pool, after its
//!   length is checked against the file and a cap.
//! - **The string pool** (`_StringPool`, `_StringData`): a header with the code page and whether
//!   references take three bytes, then each string's length and reference count; a length of 0
//!   with references means the next four bytes hold a length of 64 KiB or more. Strings stay
//!   bytes until a name is wanted, and are then read in the database's code page
//!   ([`NameDecoding::decode_in`]): 0 is the system's ANSI page, as Windows reads it.
//! - **The catalog**: `_Columns` gives each table's columns in order with their types, and
//!   `_Tables` which tables there are; only the tables BeeZip reads are kept, their names
//!   compared as bytes. A table's stream is its columns one after another, each
//!   holding every row's value: 2 bytes for a short integer, 4 for a long one, 2 or 3 for a
//!   string reference. Its rows are counted from its length. Cells are read where they lie, so a
//!   table takes the memory of its stream.
//! - **The summary information** gives the word count: short or long source names, and whether
//!   files are compressed by default; and the text Info shows ([`summary`]).
//!
//! A null cell in the catalog is skipped, and nothing here can panic on what it reads (the msi
//! crate's eight panics were all on such cells).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{self, Read, Seek, SeekFrom},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{Error, Result, names::NameDecoding, source::Input};

/// The compound file, shared by everything that reads one of its streams.
pub type Compound = cfb::CompoundFile<Input>;

/// The most a table's stream may hold: QGIS's largest, its File table, is under 1 MiB.
const MAX_TABLE: u64 = 64 << 20;
/// The most `_StringPool` may hold: four bytes a string, so 4 million of them.
const MAX_POOL: u64 = 16 << 20;
/// The most `_StringData` may hold.
const MAX_STRING_DATA: u64 = 128 << 20;
/// The most the summary information may hold; it's a few hundred bytes.
const MAX_SUMMARY: u64 = 1 << 20;
/// The columns a table may have. Windows Installer allows 32.
const MAX_COLUMNS: usize = 255;

/// The summary information stream, named as it is in every compound file.
const SUMMARY: &str = "\u{5}SummaryInformation";
/// The word count's property id.
const PID_WORDCOUNT: u32 = 15;

const TABLE_PREFIX: char = '\u{4840}';

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("msi: {message}"))
}

/// One character's place among the 64 Windows Installer packs.
fn to_b64(ch: char) -> Option<u32> {
    match ch {
        '0'..='9' => Some(ch as u32 - '0' as u32),
        'A'..='Z' => Some(ch as u32 - 'A' as u32 + 10),
        'a'..='z' => Some(ch as u32 - 'a' as u32 + 36),
        '.' => Some(62),
        '_' => Some(63),
        _ => None,
    }
}

/// A stream's name as the compound file stores it, `/`-rooted for cfb. Two characters of the
/// 64 become one code point from U+3800, one alone one from U+4800; others stay as they are.
pub fn stream_path(name: &str, table: bool) -> String {
    let mut out = String::from("/");
    if table {
        out.push(TABLE_PREFIX);
    }
    let mut chars = name.chars().peekable();
    while let Some(c1) = chars.next() {
        let Some(v1) = to_b64(c1) else {
            out.push(c1);
            continue;
        };
        let pair = chars.peek().copied().and_then(to_b64);
        let packed = match pair {
            Some(v2) => {
                chars.next();
                0x3800 + (v2 << 6) + v1
            }
            None => 0x4800 + v1,
        };
        out.extend(char::from_u32(packed));
    }
    out
}

/// Locks the compound file. A lock poisoned by a panic elsewhere is still the file: cfb keeps
/// no state between calls that a panic could leave half done.
pub fn lock(file: &Mutex<Compound>) -> MutexGuard<'_, Compound> {
    file.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One stream of the compound file, readable from any thread: cfb's own stream can't move
/// between threads, so each read opens it again under the lock, at the position kept here.
/// Callers read through a buffer, so that's one open per 64 KiB.
pub struct CfbStream {
    file: Arc<Mutex<Compound>>,
    path: String,
    len: u64,
    pos: u64,
}

impl CfbStream {
    /// The stream at `path` ([`stream_path`]); `None` when there's no such stream.
    pub fn open(file: &Arc<Mutex<Compound>>, path: &str) -> Option<Self> {
        let len = {
            let comp = lock(file);
            if !comp.is_stream(path) {
                return None;
            }
            comp.entry(path).ok()?.len()
        };
        Some(Self {
            file: Arc::clone(file),
            path: path.to_owned(),
            len,
            pos: 0,
        })
    }

    /// Its length, as the compound file's directory claims it.
    pub fn len(&self) -> u64 {
        self.len
    }
}

impl Read for CfbStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let left = usize::try_from(self.len - self.pos).unwrap_or(usize::MAX);
        let want = buf.len().min(left);
        let mut comp = lock(&self.file);
        let mut s = comp.open_stream(&self.path)?;
        s.seek(SeekFrom::Start(self.pos))?;
        let n = s.read(&mut buf[..want])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for CfbStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = to.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a seek before the stream's start",
            )
        })?;
        Ok(self.pos)
    }
}

/// The whole stream `name` (a table's when `table`), at most `cap` bytes; `None` when there's
/// no such stream. Its length is the directory's claim: it's checked against the file before
/// anything is read, and what's read must be all of it.
fn read_stream(
    file: &Arc<Mutex<Compound>>,
    name: &str,
    table: bool,
    cap: u64,
    file_len: u64,
) -> Result<Option<Vec<u8>>> {
    let path = if table {
        stream_path(name, true)
    } else {
        format!("/{name}")
    };
    let Some(s) = CfbStream::open(file, &path) else {
        return Ok(None);
    };
    let len = s.len();
    if len > file_len {
        return Err(bad(format!(
            "{name} claims {len} bytes, in a file of {file_len}"
        )));
    }
    if len > cap {
        return Err(Error::limit(format!(
            "msi: {name} is {len} bytes, more than BeeZip reads ({cap})"
        )));
    }
    let mut data = Vec::new();
    io::BufReader::with_capacity(64 * 1024, s)
        .take(len)
        .read_to_end(&mut data)
        .map_err(|e| bad(format!("reading {name}: {e}")))?;
    if data.len() as u64 != len {
        return Err(bad(format!(
            "{name} claims {len} bytes, and holds {}",
            data.len()
        )));
    }
    Ok(Some(data))
}

/// A column's type, as its width in a table's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    /// A short integer, or a binary column's placeholder: 2 bytes.
    I16,
    /// A long integer: 4 bytes.
    I32,
    /// A string reference: 2 or 3 bytes.
    Str,
}

/// The type `_Columns` gives in its bits: the string bit, else a size of 4 (without the
/// non-binary bit) for a long integer. A binary column holds a 2-byte placeholder.
fn ty(bits: i32) -> Ty {
    if bits & !0x1000 == 0x0900 {
        Ty::I16
    } else if bits & 0x0800 != 0 {
        Ty::Str
    } else if bits & 0xFF == 4 && bits & 0x400 == 0 {
        Ty::I32
    } else {
        Ty::I16
    }
}

/// One table, read: its rows' cells are read from its stream where they lie.
#[derive(Debug, Default)]
pub struct Table {
    pub rows: usize,
    /// Each column's name, type and where it starts in `data`.
    cols: Vec<(String, Ty, usize)>,
    data: Vec<u8>,
    /// String references take 3 bytes.
    long_refs: bool,
}

impl Table {
    /// The column called `name`.
    pub fn col(&self, name: &str) -> Option<usize> {
        self.cols.iter().position(|(n, _, _)| n == name)
    }

    fn cell(&self, row: usize, col: Option<usize>) -> Option<(Ty, &[u8])> {
        let &(_, t, start) = self.cols.get(col?)?;
        let w = width(t, self.long_refs);
        let at = start.checked_add(row.checked_mul(w)?)?;
        Some((t, self.data.get(at..at.checked_add(w)?)?))
    }

    /// An integer cell; `None` when it's null, or the column isn't an integer's.
    pub fn int(&self, row: usize, col: Option<usize>) -> Option<i32> {
        match self.cell(row, col)? {
            (Ty::I16, &[a, b]) => match u16::from_le_bytes([a, b]) {
                0 => None,
                v => Some(i32::from((v ^ 0x8000) as i16)),
            },
            (Ty::I32, &[a, b, c, d]) => match u32::from_le_bytes([a, b, c, d]) {
                0 => None,
                v => Some((v ^ 0x8000_0000) as i32),
            },
            _ => None,
        }
    }

    /// A string cell's reference into the pool; `None` when it's null.
    pub fn str(&self, row: usize, col: Option<usize>) -> Option<u32> {
        let (t, b) = self.cell(row, col)?;
        if t != Ty::Str {
            return None;
        }
        let id = b
            .iter()
            .rev()
            .fold(0u32, |id, &byte| (id << 8) | u32::from(byte));
        (id != 0).then_some(id)
    }
}

fn width(t: Ty, long_refs: bool) -> usize {
    match t {
        Ty::I16 => 2,
        Ty::I32 => 4,
        Ty::Str if long_refs => 3,
        Ty::Str => 2,
    }
}

/// The database: its string pool and catalog.
pub struct Db {
    file: Arc<Mutex<Compound>>,
    file_len: u64,
    /// The code page the strings are stored in; 0 is the system's ANSI one.
    pub codepage: u32,
    names: NameDecoding,
    long_refs: bool,
    /// Each string's place in `data`, by id - 1.
    strings: Vec<(u32, u32)>,
    data: Vec<u8>,
    /// Each table's columns in order, by name, with their types.
    columns: HashMap<&'static str, Vec<(String, Ty)>>,
    /// Tables whose `_Columns` rows don't number their columns 1, 2, 3…
    damaged: HashSet<&'static str>,
}

/// The tables BeeZip reads; the catalog keeps no others.
const TABLES: &[&str] = &[
    "Directory",
    "Component",
    "File",
    "Media",
    "MsiFileHash",
    "Binary",
    "Icon",
    "Property",
    "ModuleSignature",
    // A patch's own: its display name and the like (docs/M11.md §4.2).
    "MsiPatchMetadata",
];

impl Db {
    /// Reads the string pool and the catalog.
    pub fn open(file: Arc<Mutex<Compound>>, file_len: u64, names: NameDecoding) -> Result<Self> {
        let pool = read_stream(&file, "_StringPool", true, MAX_POOL, file_len)?
            .ok_or_else(|| bad("the package has no string pool (_StringPool)"))?;
        let data =
            read_stream(&file, "_StringData", true, MAX_STRING_DATA, file_len)?.unwrap_or_default();
        let (head, entries) = pool
            .split_first_chunk::<4>()
            .ok_or_else(|| bad("the string pool is too short for its header"))?;
        let head = u32::from_le_bytes(*head);
        let mut strings = Vec::with_capacity(entries.len() / 4);
        let mut at = 0usize;
        let mut chunks = entries.as_chunks::<4>().0.iter();
        while let Some(&[a, b, c, d]) = chunks.next() {
            let len = u16::from_le_bytes([a, b]);
            let refs = u16::from_le_bytes([c, d]);
            let len = if len == 0 && refs != 0 {
                // A string of 64 KiB or more: the next entry holds its length.
                let Some(l) = chunks.next() else {
                    return Err(bad("the string pool ends inside a long string's length"));
                };
                u32::from_le_bytes(*l)
            } else {
                u32::from(len)
            };
            let end = (at as u64) + u64::from(len);
            if end > data.len() as u64 {
                return Err(bad(format!(
                    "string {} of the pool is {len} bytes, past the end of _StringData ({} \
                     bytes)",
                    strings.len() + 1,
                    data.len()
                )));
            }
            // `data` is at most MAX_STRING_DATA long, so these fit.
            strings.push((at as u32, len));
            at = end as usize;
        }
        let mut db = Self {
            file,
            file_len,
            codepage: head & 0x7FFF_FFFF,
            names,
            long_refs: head & 0x8000_0000 != 0,
            strings,
            data,
            columns: HashMap::new(),
            damaged: HashSet::new(),
        };
        db.catalog()?;
        Ok(db)
    }

    /// The table a pool string names, among those BeeZip reads: compared as bytes, so a
    /// catalog of millions of rows costs no memory for the tables it doesn't want.
    fn wanted(&self, id: u32) -> Option<&'static str> {
        let name = self.bytes(id)?;
        TABLES.iter().copied().find(|t| t.as_bytes() == name)
    }

    /// `_Columns` (and `_Tables`, which says which tables there are), for the tables BeeZip
    /// reads.
    fn catalog(&mut self) -> Result<()> {
        let cols = self.raw_table(
            "_Columns",
            vec![
                ("Table".into(), Ty::Str),
                ("Number".into(), Ty::I16),
                ("Name".into(), Ty::Str),
                ("Type".into(), Ty::I16),
            ],
        )?;
        let (c_table, c_num, c_name, c_type) = (Some(0), Some(1), Some(2), Some(3));
        let mut by_table: BTreeMap<&'static str, BTreeMap<i32, (String, Ty)>> = BTreeMap::new();
        let mut damaged = HashSet::new();
        for r in 0..cols.rows {
            // A row with a null cell describes nothing: skip it.
            let (Some(t), Some(n), Some(c), Some(bits)) = (
                cols.str(r, c_table),
                cols.int(r, c_num),
                cols.str(r, c_name),
                cols.int(r, c_type),
            ) else {
                continue;
            };
            let (Some(t), Some(c)) = (self.wanted(t), self.string(c)) else {
                continue;
            };
            let table = by_table.entry(t).or_default();
            if table.len() >= MAX_COLUMNS || table.insert(n, (c, ty(bits))).is_some() {
                damaged.insert(t);
            }
        }
        let listed: Option<HashSet<&'static str>> = {
            let t = self.raw_table("_Tables", vec![("Name".into(), Ty::Str)])?;
            (t.rows > 0).then(|| {
                (0..t.rows)
                    .filter_map(|r| t.str(r, Some(0)).and_then(|id| self.wanted(id)))
                    .collect()
            })
        };
        for (table, cols) in by_table {
            if listed.as_ref().is_some_and(|l| !l.contains(table)) {
                continue;
            }
            // Numbered 1, 2, 3… with no gap.
            if damaged.contains(table) || cols.keys().copied().ne(1..=cols.len() as i32) {
                self.damaged.insert(table);
                continue;
            }
            self.columns.insert(table, cols.into_values().collect());
        }
        Ok(())
    }

    /// A string by its id, decoded; `None` for an id the pool doesn't have.
    pub fn string(&self, id: u32) -> Option<String> {
        self.bytes(id)
            .map(|b| self.names.decode_in(b, self.codepage))
    }

    /// A string's bytes, as the pool stores them.
    fn bytes(&self, id: u32) -> Option<&[u8]> {
        let i = usize::try_from(id).ok()?.checked_sub(1)?;
        let &(at, len) = self.strings.get(i)?;
        let at = at as usize;
        self.data.get(at..at.checked_add(len as usize)?)
    }

    /// A string cell, decoded; `None` when it's null.
    pub fn text(&self, t: &Table, row: usize, col: Option<usize>) -> Option<String> {
        t.str(row, col).and_then(|id| self.string(id))
    }

    /// Whether the package has the table.
    pub fn has(&self, table: &str) -> bool {
        self.columns.contains_key(table)
    }

    /// The table `name`: no rows when the package hasn't got it, and `Corrupt` when its
    /// columns can't be read.
    pub fn table(&self, name: &str) -> Result<Table> {
        if self.damaged.contains(name) {
            return Err(bad(format!(
                "the catalog's columns for the {name} table are damaged"
            )));
        }
        let Some(cols) = self.columns.get(name) else {
            return Ok(Table::default());
        };
        self.raw_table(name, cols.clone())
    }

    fn raw_table(&self, name: &str, cols: Vec<(String, Ty)>) -> Result<Table> {
        let data =
            read_stream(&self.file, name, true, MAX_TABLE, self.file_len)?.unwrap_or_default();
        let row: usize = cols.iter().map(|(_, t)| width(*t, self.long_refs)).sum();
        let rows = data.len().checked_div(row).unwrap_or(0);
        let mut at = 0;
        let cols = cols
            .into_iter()
            .map(|(n, t)| {
                let start = at;
                at += rows * width(t, self.long_refs);
                (n, t, start)
            })
            .collect();
        Ok(Table {
            rows,
            cols,
            data,
            long_refs: self.long_refs,
        })
    }
}

/// The summary information's word count: bit 0 says the source image has short names, bit 1
/// that files are compressed by default, bit 2 that it's an administrative image. `None` when
/// the stream or the property isn't there or can't be read.
pub fn word_count(file: &Arc<Mutex<Compound>>, file_len: u64) -> Option<i32> {
    let s = read_stream(file, SUMMARY, false, MAX_SUMMARY, file_len).ok()??;
    let mut found = None;
    for_each_property(&s, |pid, ty, value| {
        if pid == PID_WORDCOUNT {
            found = match ty {
                // VT_I4, and VT_I2 from some writers.
                3 => le32(value, 0).map(|v| v as i32),
                2 => le32(value, 0).map(|v| i32::from(v as u16 as i16)),
                _ => None,
            };
        }
    });
    found
}

/// The summary information's text properties, named as Windows Installer names them and read
/// in the summary's own code page (its property 1); times and counts are left out. Empty when
/// the stream can't be read.
pub fn summary(
    file: &Arc<Mutex<Compound>>,
    file_len: u64,
    names: NameDecoding,
) -> Vec<(String, String)> {
    let Ok(Some(s)) = read_stream(file, SUMMARY, false, MAX_SUMMARY, file_len) else {
        return Vec::new();
    };
    let mut codepage = 0u32;
    let mut texts: Vec<(u32, &[u8])> = Vec::new();
    for_each_property(&s, |pid, ty, value| match ty {
        // VT_I2: the code page.
        2 if pid == 1 => codepage = le32(value, 0).map_or(0, |v| v & 0xFFFF),
        // VT_LPSTR: a length, then the bytes, ending at a NUL.
        30 => {
            let Some(len) = le32(value, 0).and_then(|l| usize::try_from(l).ok()) else {
                return;
            };
            let Some(bytes) = value.get(4..4 + len.min(64 * 1024)) else {
                return;
            };
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            texts.push((pid, &bytes[..end]));
        }
        _ => {}
    });
    texts
        .into_iter()
        .filter_map(|(pid, b)| {
            let name = match pid {
                2 => "Title",
                3 => "Subject",
                4 => "Author",
                5 => "Keywords",
                6 => "Comments",
                7 => "Template",
                8 => "Last saved by",
                9 => "Revision",
                18 => "Application",
                _ => return None,
            };
            let v = names.decode_in(b, codepage);
            (!v.is_empty()).then(|| (name.to_owned(), v))
        })
        .collect()
}

fn le32(s: &[u8], at: usize) -> Option<u32> {
    let b = s.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Calls `f` with each property of the summary's first set: its id, its type and the bytes
/// from its value to the stream's end. Stops quietly at anything out of place.
fn for_each_property<'s>(s: &'s [u8], mut f: impl FnMut(u32, u32, &'s [u8])) {
    let mut walk = || -> Option<()> {
        // The header: byte order, version, system, CLSID, then the sets: FMTID and offset.
        if s.get(..2)? != [0xFE, 0xFF] || le32(s, 24)? == 0 {
            return None;
        }
        let section = usize::try_from(le32(s, 28 + 16)?).ok()?;
        let count = le32(s, section.checked_add(4)?)?;
        for i in 0..count.min(4096) as usize {
            let at = section.checked_add(8)?.checked_add(i.checked_mul(8)?)?;
            let (pid, off) = (le32(s, at)?, le32(s, at.checked_add(4)?)?);
            let prop = section.checked_add(usize::try_from(off).ok()?)?;
            let ty = le32(s, prop)?;
            f(pid, ty, s.get(prop.checked_add(4)?..)?);
        }
        Some(())
    };
    let _ = walk();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_names_are_packed_as_windows_installer_packs_them() {
        // Two characters of the 64 in one code point, one alone in another range: `a` is 36,
        // `b` 37.
        let ab = char::from_u32(0x3800 + (37 << 6) + 36).unwrap();
        assert_eq!(stream_path("ab", false), format!("/{ab}"));
        assert_eq!(
            stream_path("ab.", false),
            format!("/{ab}{}", char::from_u32(0x4800 + 62).unwrap())
        );
        assert_eq!(
            stream_path("a", true),
            format!("/\u{4840}{}", char::from_u32(0x4800 + 36).unwrap())
        );
        // Others stay as they are.
        assert_eq!(stream_path("é", false), "/é");
        assert_eq!(stream_path("", true), "/\u{4840}");
    }

    #[test]
    fn column_types() {
        // Strings (localizable, nullable, primary key or not), integers, binary.
        assert_eq!(ty(0x0D48), Ty::Str);
        assert_eq!(ty(0x1D48), Ty::Str);
        assert_eq!(ty(0x0502), Ty::I16);
        assert_eq!(ty(0x0104), Ty::I32);
        assert_eq!(ty(0x0900), Ty::I16);
        assert_eq!(ty(0x1900), Ty::I16);
        assert_eq!(ty(0x0504), Ty::I16);
    }

    #[test]
    fn cells_never_read_past_the_table() {
        let t = Table {
            rows: 3,
            cols: vec![("A".into(), Ty::I32, 0), ("B".into(), Ty::Str, 12)],
            data: vec![1; 13],
            long_refs: false,
        };
        assert_eq!(
            t.int(0, t.col("A")),
            Some(0x0101_0101 ^ 0x8000_0000_u32 as i32)
        );
        assert_eq!(t.str(0, t.col("B")), None, "half a cell");
        assert_eq!(t.int(9, t.col("A")), None);
        assert_eq!(t.int(0, t.col("C")), None);
        assert_eq!(t.int(usize::MAX, Some(0)), None);
        assert_eq!(t.str(0, t.col("A")), None, "not a string column");
    }
}
