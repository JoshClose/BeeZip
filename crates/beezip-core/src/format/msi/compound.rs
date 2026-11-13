//! Installer patches (`.msp`) and transforms (`.mst`), and any other compound file that reaches
//! the MSI reader, listed as their compound file (docs/M11.md §4.2): each storage a folder, each
//! stream a file.
//!
//! - **Names** are 7-Zip's for them (its `MsiName_To_FileName`), so a listing reads as 7-Zip's:
//!   Windows Installer packs two characters of `[0-9A-Za-z._]` into one code point from U+3800
//!   (one alone from U+4800) and marks a table with U+4840; these are unpacked, the mark written
//!   as `!` (`!File`), a control character as `[n]` (`[5]SummaryInformation`) and an empty name
//!   as `[]`. A stream holding a cabinet gets `.cab` added (`PCW_CAB_ACR.cab`), so it opens as
//!   one (decision 3). Names unsafe on disk are left to `SafeFs`, as in every format.
//! - **Order:** folders first, then files, each by path ignoring case (decision 4).
//! - **Data:** each stream as it's stored, held to the length the directory gives it. A stream
//!   claiming more than the file is listed and fails alone when it's read. A compound file
//!   stores no checksums, so a test reads every stream and says so.
//! - **Caps:** at most 64 levels and 4,096 bytes a path, as for an MSI's folders, deeper ones left
//!   out with a warning; the names together at most 128 MiB; `max_entries`.

use std::{
    io::{BufReader, Read},
    sync::{Arc, Mutex},
    time::UNIX_EPOCH,
};

use super::{
    CLSID_PATCH, CLSID_TRANSFORM, Failing, bad,
    tables::{self, CfbStream, Compound, Db},
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result, TestReport, TestSink,
    backend::{External, ExternalInfo, LevelProperty},
    format::{
        ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
    },
    io::{BUF_SIZE, CountingReader},
    safefs::Partial,
    source::Source,
};

/// The most levels of storages listed, and the longest path.
const MAX_DEPTH: usize = 64;
const MAX_PATH: usize = 4096;
/// The most the names may hold together.
const MAX_NAMES: u64 = 128 << 20;

/// The 64 characters Windows Installer packs, in its order.
const CHARS: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

const NO_CHECKSUMS: &str = "A compound file stores no checksums of its streams, so the test \
shows that BeeZip can read every stream, not that their contents are intact.";

/// A stream or storage name as 7-Zip writes it (`MsiName_To_FileName`, `ComHandler.cpp`).
pub fn seven_zip_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let c = ch as u32;
        if c < 0x20 {
            out.push_str(&format!("[{c}]"));
        } else if (0x3800..=0x4840).contains(&c) {
            let v = c - 0x3800;
            let hi = v >> 6;
            if hi <= 64 {
                out.push(char::from(CHARS[(v & 63) as usize]));
                if hi < 64 {
                    out.push(char::from(CHARS[hi as usize]));
                }
            } else {
                out.push('!');
            }
        } else if ch == '/' || ch == '\\' {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push_str("[]");
    }
    out
}

/// What kind of compound file it is, by its root CLSID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Patch,
    Transform,
    Other,
}

impl Kind {
    fn level(self) -> &'static str {
        match self {
            Self::Patch => "msp",
            Self::Transform => "mst",
            Self::Other => "compound",
        }
    }
}

/// Where an entry's data is.
enum Item {
    Dir,
    /// A stream at its cfb path, with the length its directory entry claims.
    Stream {
        path: String,
        len: u64,
    },
    /// A stream that can't be read, and why.
    Missing(Error),
}

pub struct CompoundReader {
    source: Source,
    file: Arc<Mutex<Compound>>,
    entries: Vec<Entry>,
    items: Vec<Item>,
    level: &'static str,
    properties: Vec<LevelProperty>,
    notes: Vec<String>,
    /// The bytes a full extraction reads.
    total: u64,
    /// Keeps a file spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl CompoundReader {
    /// Lists `comp`, whose root CLSID is `clsid` (as cfb prints it).
    pub(super) fn new(
        source: Source,
        comp: Compound,
        file_len: u64,
        spool: Option<Partial>,
        clsid: &str,
        cx: &mut dyn Ctx,
    ) -> Result<Self> {
        let kind = match clsid {
            CLSID_PATCH => Kind::Patch,
            CLSID_TRANSFORM => Kind::Transform,
            _ => Kind::Other,
        };
        let walked: Vec<cfb::Entry> = comp.walk().filter(|e| !e.is_root()).collect();
        let file = Arc::new(Mutex::new(comp));
        let mut found: Vec<(Entry, Item)> = Vec::new();
        let mut total = 0u64;
        let mut cut = 0usize;
        let mut names = 0u64;
        for e in walked {
            if found.len().is_multiple_of(1024) {
                cx.check()?;
            }
            // cfb refuses `/` and `\` in a name, so these split it into its names.
            let cfb_path = e.path().to_string_lossy().into_owned();
            let raw: Vec<&str> = cfb_path
                .split(['/', '\\'])
                .filter(|n| !n.is_empty())
                .collect();
            if raw.len() > MAX_DEPTH {
                cut += 1;
                continue;
            }
            let mut path = raw
                .iter()
                .map(|n| seven_zip_name(n))
                .collect::<Vec<_>>()
                .join("/");
            if path.len() > MAX_PATH {
                cut += 1;
                continue;
            }
            names += path.len() as u64;
            if names > MAX_NAMES {
                return Err(Error::limit(
                    "msi: the compound file's names pass 128 MiB".to_owned(),
                ));
            }
            source.limits.check_entries(found.len() as u64 + 1)?;
            if e.is_storage() {
                let mut entry = Entry::new(0, path, EntryKind::Dir);
                let t = e.modified();
                if t.duration_since(UNIX_EPOCH).is_ok_and(|d| !d.is_zero()) {
                    entry.modified = Some(t);
                }
                found.push((entry, Item::Dir));
                continue;
            }
            let len = e.len();
            // cfb follows a name `..` or `.` up or nowhere, so such a path names another stream.
            let item = if raw.iter().any(|n| *n == "." || *n == "..") {
                Item::Missing(bad(format!(
                    "`{path}` is under a storage named `.` or `..`, which can't be followed"
                )))
            } else if len > file_len {
                Item::Missing(bad(format!(
                    "`{path}` claims {len} bytes, in a file of {file_len}"
                )))
            } else {
                total += len;
                // A cabinet gets `.cab`, so it opens as one (decision 3).
                if len >= 36
                    && !path.to_ascii_lowercase().ends_with(".cab")
                    && let Some(mut s) = CfbStream::open(&file, &cfb_path)
                {
                    let mut magic = [0u8; 4];
                    if s.read_exact(&mut magic).is_ok() && &magic == b"MSCF" {
                        path.push_str(".cab");
                    }
                }
                Item::Stream {
                    path: cfb_path,
                    len,
                }
            };
            let mut entry = Entry::new(0, path, EntryKind::File);
            entry.size = Some(len);
            found.push((entry, item));
        }
        found.sort_by_cached_key(|(e, _)| (!e.is_dir(), e.path.to_lowercase()));
        let (mut entries, items): (Vec<Entry>, Vec<Item>) = found.into_iter().unzip();
        for (i, e) in entries.iter_mut().enumerate() {
            e.id = i;
        }
        if cut > 0 {
            cx.warn(format!(
                "{}: {cut} storages or streams nested more than {MAX_DEPTH} deep or with paths \
                 over {MAX_PATH} bytes aren't listed",
                source.file_name()
            ));
        }
        let level = kind.level();
        let summary = tables::summary(&file, file_len, source.names);
        let properties = properties(kind, clsid, &summary, &file, file_len, &source)
            .into_iter()
            .map(|(name, value)| LevelProperty {
                level: level.to_owned(),
                name,
                value,
            })
            .collect();
        let notes = vec![match kind {
            Kind::Patch => "A patch is listed as its compound file: its own tables, a folder of \
                            tables for each transform it carries, and its cabinets, which hold \
                            the patched files under the target installer's File keys, most as \
                            changes to the installed files that only Windows Installer applies."
                .to_owned(),
            Kind::Transform => "A transform is listed as its compound file: a stream for each \
                                table it changes, holding the changes in Windows Installer's own \
                                form."
                .to_owned(),
            Kind::Other => "Named like an installer, but a compound file of another kind: listed \
                            as its storages and streams."
                .to_owned(),
        }];
        Ok(Self {
            source,
            file,
            entries,
            items,
            level,
            properties,
            notes,
            total,
            _spool: spool,
        })
    }

    /// Entry `idx`'s data: a stream held to its length, counted and guarded.
    fn data(&self, idx: usize) -> Result<Box<dyn Read + Send + '_>> {
        let (Some(entry), Some(item)) = (self.entries.get(idx), self.items.get(idx)) else {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {idx}")));
        };
        match item {
            Item::Dir => Ok(Box::new(std::io::empty())),
            Item::Missing(e) => Err(e.clone()),
            Item::Stream { path, len } => {
                let s = CfbStream::open(&self.file, path)
                    .ok_or_else(|| bad(format!("`{}`'s stream vanished", entry.path)))?;
                let counted = CountingReader::new(
                    BufReader::with_capacity(BUF_SIZE, s),
                    self.source.counter.clone(),
                );
                let held = Held {
                    inner: counted,
                    path: entry.path.clone(),
                    len: *len,
                    got: 0,
                };
                Ok(Box::new(self.source.guard(held)))
            }
        }
    }
}

/// What Info shows (docs/M11.md §4.2), from the summary and a patch's own MsiPatchMetadata.
fn properties(
    kind: Kind,
    clsid: &str,
    summary: &[(String, String)],
    file: &Arc<Mutex<Compound>>,
    file_len: u64,
    source: &Source,
) -> Vec<(String, String)> {
    let get = |name: &str| {
        summary
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let count = |v: &str| v.split(';').filter(|s| !s.trim().is_empty()).count();
    let mut out: Vec<(String, String)> = Vec::new();
    match kind {
        Kind::Patch => {
            if let Ok(db) = Db::open(Arc::clone(file), file_len, source.names)
                && let Ok(t) = db.table("MsiPatchMetadata")
            {
                let (c_p, c_v) = (t.col("Property"), t.col("Value"));
                let rows: Vec<(String, String)> = (0..t.rows)
                    .filter_map(|r| Some((db.text(&t, r, c_p)?, db.text(&t, r, c_v)?)))
                    .collect();
                for want in [
                    "DisplayName",
                    "Description",
                    "ManufacturerName",
                    "Classification",
                    "TargetProductName",
                    "MoreInfoURL",
                ] {
                    if let Some((_, v)) = rows.iter().find(|(p, _)| p == want)
                        && !v.is_empty()
                    {
                        out.push((want.to_owned(), v.chars().take(500).collect()));
                    }
                }
            }
            // Revision: the patch code, then the codes of the patches it replaces.
            if let Some(code) = get("Revision").and_then(|r| guids(r).into_iter().next()) {
                out.push(("Patch code".to_owned(), code));
            }
            if let Some(t) = get("Template") {
                out.push(("Target products".to_owned(), count(t).to_string()));
            }
            if let Some(t) = get("Last saved by") {
                out.push(("Transforms".to_owned(), count(t).to_string()));
            }
        }
        Kind::Transform => {
            for want in ["Title", "Subject", "Author"] {
                if let Some(v) = get(want) {
                    out.push((want.to_owned(), v.to_owned()));
                }
            }
            // Revision: `{target}version;{result}version;{upgrade code}`.
            if let Some(r) = get("Revision") {
                let parts: Vec<&str> = r.split(';').collect();
                let product = |p: Option<&&str>| -> Option<(String, String)> {
                    let p = p?.trim();
                    let end = p.find('}')?;
                    Some((p[..=end].to_owned(), p[end + 1..].trim().to_owned()))
                };
                if let Some((code, version)) = product(parts.first()) {
                    out.push(("Target product code".to_owned(), code));
                    if !version.is_empty() {
                        out.push(("Target version".to_owned(), version));
                    }
                }
                if let Some((code, version)) = product(parts.get(1)) {
                    out.push(("Result product code".to_owned(), code));
                    if !version.is_empty() {
                        out.push(("Result version".to_owned(), version));
                    }
                }
                if let Some(up) = parts.get(2).map(|u| u.trim()).filter(|u| !u.is_empty()) {
                    out.push(("Upgrade code".to_owned(), up.to_owned()));
                }
            }
            if let Some(t) = get("Template") {
                out.push(("Platform and language".to_owned(), t.to_owned()));
            }
        }
        Kind::Other => out.push(("CLSID".to_owned(), format!("{{{clsid}}}"))),
    }
    out
}

/// The `{GUID}`s in `s`, in order.
fn guids(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        let Some(len) = rest[start..].find('}') else {
            break;
        };
        out.push(rest[start..=start + len].to_owned());
        rest = &rest[start + len + 1..];
    }
    out
}

/// A stream held to the length its directory entry gives it: one that ends early is `Corrupt`.
struct Held<R> {
    inner: R,
    path: String,
    len: u64,
    got: u64,
}

impl<R: Read> Read for Held<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.got += n as u64;
        if n == 0 && !buf.is_empty() && self.got < self.len {
            return Err(bad(format!(
                "`{}` ends after {} of its {} bytes",
                self.path, self.got, self.len
            ))
            .into_io());
        }
        Ok(n)
    }
}

impl ArchiveReader for CompoundReader {
    fn format(&self) -> FormatId {
        FormatId::External(External::Msi)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::External(External::Msi),
            codecs: self.source.codecs.clone(),
            methods: Vec::new(),
            comment: None,
            encryption: Encryption::None,
            solid: false,
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: Some(ExternalInfo {
                backend: None,
                levels: vec![self.level.to_owned()],
                properties: self.properties.clone(),
                notes: self.notes.clone(),
            }),
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let selected: Vec<usize> = (0..self.entries.len())
            .filter(|&id| sel.matches(&self.entries[id]))
            .collect();
        // Many small streams: written on other threads, as an MSI's files are.
        if let Some(fs) = sink.as_fs_sink() {
            fs.write_behind(self.source.threads);
        }
        self.source.counter.set(0);
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.total));
        meter.entries_total = Some(selected.len() as u64);
        for (done, &id) in selected.iter().enumerate() {
            cx.check()?;
            meter.entries_done = done as u64;
            meter.current = Some(self.entries[id].path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            // A stream that can't be read fails alone; the rest go on.
            let mut data: Box<dyn Read + Send + '_> = match self.data(id) {
                Ok(d) => d,
                Err(e) if e.kind == ErrorKind::Corrupt => Box::new(Failing(e)),
                Err(e) => return Err(e),
            };
            sink.entry(&self.entries[id], &mut data, &mut mcx)?;
        }
        meter.entries_done = selected.len() as u64;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        self.source.counter.set(0);
        Ok(self.data(id)?)
    }

    /// Every stream read in one pass; a compound file has no checksums to check.
    fn test(&mut self, cx: &mut dyn Ctx) -> Option<Result<TestReport>> {
        let mut sink = TestSink::default();
        let done = match self.extract(&Selection::all(), &mut sink, cx) {
            Ok(()) => Ok(()),
            Err(e) if e.kind == ErrorKind::Corrupt => {
                sink.report.record("", &e);
                Ok(())
            }
            Err(e) => Err(e),
        };
        Some(done.map(|()| {
            let mut report = sink.report;
            report.note = Some(NO_CHECKSUMS.to_owned());
            report
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_written_as_7zip_writes_them() {
        let pack = |a: u32, b: u32| char::from_u32(0x3800 + (b << 6) + a).unwrap();
        // `ab` packed in one, then `.` alone, then the table mark before a packed name.
        let raw: String = [pack(36, 37), char::from_u32(0x4800 + 62).unwrap()]
            .into_iter()
            .collect();
        assert_eq!(seven_zip_name(&raw), "ab.");
        assert_eq!(seven_zip_name("\u{4840}"), "!");
        let file: String = ['\u{4840}', pack(15, 44), pack(47, 40)]
            .into_iter()
            .collect();
        assert_eq!(seven_zip_name(&file), "!File");
        assert_eq!(
            seven_zip_name("\u{5}SummaryInformation"),
            "[5]SummaryInformation"
        );
        assert_eq!(seven_zip_name("a/b\\c"), "a_b_c");
        assert_eq!(seven_zip_name(""), "[]");
        // Past the packed ranges, as it is.
        assert_eq!(seven_zip_name("\u{4841}x"), "\u{4841}x");
        assert_eq!(seven_zip_name("名前"), "名前");
    }

    #[test]
    fn guids_are_found_in_order() {
        assert_eq!(
            guids("{A}1.0;{B}2.0;{C}"),
            ["{A}", "{B}", "{C}"].map(str::to_owned)
        );
        assert!(guids("none {here").is_empty());
    }
}
