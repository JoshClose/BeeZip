//! MSI installers, BeeZip's own reader (docs/M7.md §8), read only.
//!
//! - **The package** is a Compound File (cfb) holding the installer's database: its tables
//!   ([`tables`]) and the cabinets its files are packed in. A patch (`.msp`) or transform
//!   (`.mst`), by the root CLSID, and a merge module (`.msm`), by its ModuleSignature table, are
//!   `UnsupportedOperation`, for 7-Zip to read when it's installed.
//! - **The listing** has each file where the installer puts it, under its Windows Installer
//!   folder property ([`names`]): `ProgramFiles64Folder/RustDesk/RustDesk.exe`. The folders
//!   holding files come first, parents before children, then the files in the order their data
//!   is read, then the custom actions' and icons' streams as `[Binary]/<name>` and
//!   `[Icon]/<name>`. The tables, the cabinets and the signature aren't listed. Sizes are the
//!   File table's; times are the cabinet's (DOS local times, as for a `.cab`).
//! - **The data:** the cabinets the Media table names are read in its order through BeeZip's
//!   CAB reader, an embedded one (`#name`) straight from its stream, an external one from beside
//!   the MSI. A file that isn't compressed is read from the source image beside the MSI, at its
//!   source path. When one of these isn't there, opening warns once, saying where it looked, and
//!   each file it holds fails when it's read (`NotFound`).
//! - **Integrity:** every file is checked against the File table's size and against MsiFileHash's
//!   MD5 where there is one (WiX stores zeros as an empty file's hash: that one isn't checked).
//!   A mismatch is `Corrupt`.
//! - **Extracting** decodes each cabinet once, in the order of its folders, as a `.cab` is;
//!   `open_entry` decodes a file's folder from its start.

mod names;
mod tables;

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeSet, HashMap},
    fs::File,
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use md5::Digest as _;

use self::{
    names::{DirRow, Layout},
    tables::{CfbStream, Compound, Db},
};
use super::{
    ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
    cab::{CabReader, CabStream, ReadSeek, find_sibling},
};
use crate::{
    Ctx, Error, ErrorKind, OverwriteChoice, Progress, Result,
    backend::{External, ExternalInfo, LevelProperty},
    io::{BUF_SIZE, Counter, CountingReader, copy},
    safefs::Partial,
    source::{Input, Source},
};

/// The root CLSIDs Windows Installer gives its packages, as cfb prints them.
const CLSID_PACKAGE: &str = "000c1084-0000-0000-c000-000000000046";
const CLSID_PATCH: &str = "000c1086-0000-0000-c000-000000000046";
const CLSID_TRANSFORM: &str = "000c1082-0000-0000-c000-000000000046";
const CLSID_NONE: &str = "00000000-0000-0000-0000-000000000000";

/// File attributes: read-only, hidden and system, kept; and how it's stored.
const ATTR_KEPT: i32 = 0x1 | 0x2 | 0x4;
const ATTR_NONCOMPRESSED: i32 = 0x2000;
const ATTR_COMPRESSED: i32 = 0x4000;

/// Word count bits: the source image has short names; files are compressed by default.
const WORD_SHORT_NAMES: i32 = 0x1;
const WORD_COMPRESSED: i32 = 0x2;

/// Warnings about single files beyond this are summed up in one.
const MAX_FILE_WARNINGS: usize = 20;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("msi: {message}"))
}

/// Opens a Windows Installer package. Patches, transforms and merge modules are
/// `UnsupportedOperation`, for 7-Zip to read when it's installed.
pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(MsiReader::open(source, cx)?))
}

/// What a file's data is held to.
#[derive(Debug, Clone, Copy)]
struct Check {
    size: u64,
    md5: Option<[u8; 16]>,
}

/// Where an entry's data is.
#[derive(Debug)]
enum Item {
    /// A folder: none.
    Dir,
    /// Entry `id` of cabinet `cab`.
    Cab { cab: usize, id: usize, check: Check },
    /// A file of the source image beside the MSI.
    Source { path: PathBuf, check: Check },
    /// A Binary or Icon stream of the package, at its compound file path.
    Stream { path: String, len: u64 },
    /// A file whose data can't be read, and why.
    Missing(Error),
}

/// A Media row: the files up to `last` are in its cabinet, if it has one.
#[derive(Debug)]
struct Media {
    last: i32,
    disk: i32,
    cabinet: Option<String>,
    /// Its cabinet, opened, or why it couldn't be.
    cab: Option<std::result::Result<usize, Error>>,
}

/// A File row, laid out.
struct FileRow {
    key: String,
    path: String,
    sequence: i32,
    attrs: i32,
    check: Check,
    /// Where it sorts: its media, then its place in the cabinet's data or its sequence.
    order: (usize, u8, i64),
    item: Item,
    modified: Option<std::time::SystemTime>,
    method: Option<Cow<'static, str>>,
}

/// A cabinet's file, by its name (the File key).
#[derive(Debug, Clone)]
struct InCab {
    id: usize,
    /// Its place in the order the cabinet's data is read.
    pos: usize,
    modified: Option<std::time::SystemTime>,
    method: Option<Cow<'static, str>>,
}

pub struct MsiReader {
    source: Source,
    file: Arc<Mutex<Compound>>,
    /// The compound file's length: what its directory's claims are held to.
    file_len: u64,
    entries: Vec<Entry>,
    items: Vec<Item>,
    cabs: Vec<CabReader>,
    methods: Vec<Cow<'static, str>>,
    solid_blocks: u64,
    properties: Vec<LevelProperty>,
    notes: Vec<String>,
    /// The bytes a full extraction reads: the cabinets, source files and streams.
    total: u64,
    /// Keeps a package spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl MsiReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (input, spool) = if source.codecs.is_empty() {
            (source.input()?, None)
        } else {
            // The compound file is read at offsets: spool the decoded stream.
            let mut tmp = Partial::create_temp("beezip-spool.msi")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            (Input::file(tmp.reopen()?)?, Some(tmp))
        };
        let file_len = input.len();
        let comp = cfb::CompoundFile::open(input)
            .map_err(|e| bad(format!("the package's compound file can't be read ({e})")))?;
        let clsid = comp.root_entry().clsid().to_string();
        match clsid.as_str() {
            CLSID_PACKAGE | CLSID_NONE => {}
            CLSID_PATCH => {
                return Err(Error::unsupported(
                    "it's an installer patch (.msp), which BeeZip doesn't read itself",
                ));
            }
            CLSID_TRANSFORM => {
                return Err(Error::unsupported(
                    "it's an installer transform (.mst), which BeeZip doesn't read itself",
                ));
            }
            _ => {
                return Err(Error::unsupported(format!(
                    "it's a compound file of another kind ({{{clsid}}}), not an installer"
                )));
            }
        }
        let file = Arc::new(Mutex::new(comp));
        let db = Db::open(Arc::clone(&file), file_len, source.names)?;
        if db.has("ModuleSignature") {
            return Err(Error::unsupported(
                "it's a merge module (.msm), which BeeZip doesn't read itself",
            ));
        }
        let mut r = Self {
            source,
            file,
            file_len,
            entries: Vec::new(),
            items: Vec::new(),
            cabs: Vec::new(),
            methods: Vec::new(),
            solid_blocks: 0,
            properties: Vec::new(),
            notes: vec![
                "Files are listed where the installer puts them, under Windows Installer's \
                 folder names (ProgramFiles64Folder…); its custom actions and icons are under \
                 [Binary] and [Icon]."
                    .to_owned(),
            ],
            total: 0,
            _spool: spool,
        };
        r.load(&db, cx)?;
        Ok(r)
    }

    /// Reads the tables, opens the cabinets and lays the files out.
    fn load(&mut self, db: &Db, cx: &mut dyn Ctx) -> Result<()> {
        let words = tables::word_count(&self.file, self.file_len).unwrap_or(0);
        let media = self.media(db, cx)?;
        let files = self.files(db, words, &media, cx)?;
        let streams = self.streams(db)?;

        // Folders first, parents before children.
        let mut dirs = BTreeSet::new();
        for p in files
            .iter()
            .map(|f| f.path.as_str())
            .chain(streams.iter().map(|s| s.0.as_str()))
        {
            let mut at = p;
            while let Some(i) = at.rfind('/') {
                at = &at[..i];
                if !dirs.insert(at.to_owned()) {
                    break;
                }
            }
        }
        let limits = self.source.limits.clone();
        for d in dirs {
            limits.check_entries(self.entries.len() as u64 + 1)?;
            self.entries
                .push(Entry::new(self.entries.len(), d, EntryKind::Dir));
            self.items.push(Item::Dir);
        }
        for f in files {
            limits.check_entries(self.entries.len() as u64 + 1)?;
            let mut e = Entry::new(self.entries.len(), f.path, EntryKind::File);
            e.size = Some(f.check.size);
            e.modified = f.modified;
            e.method = f.method;
            e.dos_attrs = Some((f.attrs & ATTR_KEPT) as u32);
            self.entries.push(e);
            self.items.push(f.item);
        }
        for (path, item, size) in streams {
            limits.check_entries(self.entries.len() as u64 + 1)?;
            let mut e = Entry::new(self.entries.len(), path, EntryKind::File);
            e.size = Some(size);
            self.entries.push(e);
            self.items.push(item);
        }

        // What Info shows: a damaged Property table only leaves it out.
        let props = db.table("Property").unwrap_or_default();
        let (c_name, c_value) = (props.col("Property"), props.col("Value"));
        for want in ["ProductName", "ProductVersion", "Manufacturer"] {
            if let Some(value) = (0..props.rows)
                .find(|&r| db.text(&props, r, c_name).as_deref() == Some(want))
                .and_then(|r| db.text(&props, r, c_value))
            {
                self.properties.push(LevelProperty {
                    level: "msi".to_owned(),
                    name: want.to_owned(),
                    value,
                });
            }
        }
        for cab in &mut self.cabs {
            let info = cab.info(cx)?;
            for m in info.methods {
                if !self.methods.contains(&m) {
                    self.methods.push(m);
                }
            }
            self.solid_blocks += info.solid_blocks.unwrap_or(0);
        }
        Ok(())
    }

    /// The Media table in its order, each row's cabinet opened.
    fn media(&mut self, db: &Db, cx: &mut dyn Ctx) -> Result<Vec<Media>> {
        let t = db.table("Media")?;
        let (c_disk, c_last, c_cab) = (t.col("DiskId"), t.col("LastSequence"), t.col("Cabinet"));
        let mut media: Vec<Media> = (0..t.rows)
            .map(|r| Media {
                last: t.int(r, c_last).unwrap_or(0),
                disk: t.int(r, c_disk).unwrap_or(0),
                cabinet: db.text(&t, r, c_cab).filter(|c| !c.is_empty()),
                cab: None,
            })
            .collect();
        media.sort_by_key(|m| (m.last, m.disk));
        let mut opened: HashMap<String, std::result::Result<usize, Error>> = HashMap::new();
        for m in &mut media {
            cx.check()?;
            let Some(name) = m.cabinet.clone() else {
                continue;
            };
            let cab = match opened.get(&name) {
                Some(c) => c.clone(),
                None => {
                    let c = match self.open_cab(&name, cx) {
                        Ok(reader) => {
                            self.cabs.push(reader);
                            Ok(self.cabs.len() - 1)
                        }
                        Err(e)
                            if matches!(
                                e.kind,
                                ErrorKind::Cancelled | ErrorKind::LimitExceeded
                            ) =>
                        {
                            return Err(e);
                        }
                        Err(e) => {
                            let why = match e.message.strip_prefix("msi: ") {
                                Some(m) => m.to_owned(),
                                None => {
                                    format!("the cabinet `{name}` can't be read ({})", e.message)
                                }
                            };
                            cx.warn(format!(
                                "{}: {why}; the files in it can't be extracted",
                                self.source.file_name(),
                            ));
                            Err(e)
                        }
                    };
                    opened.insert(name, c.clone());
                    c
                }
            };
            m.cab = Some(cab);
        }
        Ok(media)
    }

    /// The cabinet a Media row names: `#name` in the package, else a file beside it.
    fn open_cab(&mut self, name: &str, cx: &mut dyn Ctx) -> Result<CabReader> {
        let msi = self.source.file_name();
        if let Some(stream) = name.strip_prefix('#') {
            let path = tables::stream_path(stream, false);
            if CfbStream::open(&self.file, &path).is_none() {
                return Err(bad(format!(
                    "the cabinet `{stream}` the Media table names isn't in the package"
                )));
            }
            let file = Arc::clone(&self.file);
            let limit = self.file_len;
            let name = stream.to_owned();
            let open = move || -> Result<(Box<dyn ReadSeek>, u64)> {
                let s = CfbStream::open(&file, &path)
                    .ok_or_else(|| bad(format!("the cabinet `{name}` vanished")))?;
                // The directory's claim, held to the file.
                let len = s.len();
                if len > limit {
                    return Err(bad(format!(
                        "the cabinet `{name}` claims {len} bytes, in a file of {limit}"
                    )));
                }
                Ok((Box::new(s), len))
            };
            let stream = CabStream::new(format!("{stream} in {msi}"), open);
            let reader = CabReader::open_stream(self.source.clone(), stream, cx)?;
            self.total += reader.total_size();
            return Ok(reader);
        }
        // An external cabinet: a plain file name, looked for beside the package.
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', ':']) {
            return Err(bad(format!(
                "the Media table names a cabinet, `{name}`, that isn't a plain file name"
            )));
        }
        let dir = self.dir();
        let Some(path) = find_sibling(&dir, name) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "msi: the cabinet `{name}` isn't beside the package (looked for {})",
                    dir.join(name).display()
                ),
            ));
        };
        let mut s = Source::new(
            &path,
            Vec::new(),
            &crate::OpenOptions::new(self.source.limits.clone()),
        )?;
        s.counter = self.source.counter.clone();
        s.budget = self.source.budget.clone();
        s.names = self.source.names;
        let reader = CabReader::open(s, cx)?;
        self.total += reader.total_size();
        Ok(reader)
    }

    /// The folder the package is in: external cabinets and the source image are there.
    fn dir(&self) -> PathBuf {
        self.source
            .path
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf()
    }

    /// The File table, laid out ([`names`]), each file's data found, in reading order.
    fn files(
        &mut self,
        db: &Db,
        words: i32,
        media: &[Media],
        cx: &mut dyn Ctx,
    ) -> Result<Vec<FileRow>> {
        let dirs = db.table("Directory")?;
        let (c_dir, c_parent, c_default) = (
            dirs.col("Directory"),
            dirs.col("Directory_Parent"),
            dirs.col("DefaultDir"),
        );
        let mut rows = HashMap::new();
        for r in 0..dirs.rows {
            if let Some(key) = db.text(&dirs, r, c_dir) {
                rows.insert(
                    key,
                    DirRow {
                        parent: db.text(&dirs, r, c_parent),
                        default_dir: db.text(&dirs, r, c_default).unwrap_or_default(),
                    },
                );
            }
        }
        drop(dirs);
        let short_source = words & WORD_SHORT_NAMES != 0;
        let mut layout = Layout::new(rows, short_source);

        let comps = db.table("Component")?;
        let (c_comp, c_cdir) = (comps.col("Component"), comps.col("Directory_"));
        let comp_dir: HashMap<String, String> = (0..comps.rows)
            .filter_map(|r| Some((db.text(&comps, r, c_comp)?, db.text(&comps, r, c_cdir)?)))
            .collect();
        drop(comps);

        let hashes = db.table("MsiFileHash")?;
        let c_hfile = hashes.col("File_");
        let parts = ["HashPart1", "HashPart2", "HashPart3", "HashPart4"].map(|c| hashes.col(c));
        let md5s: HashMap<String, [u8; 16]> = (0..hashes.rows)
            .filter_map(|r| {
                let key = db.text(&hashes, r, c_hfile)?;
                let mut md5 = [0u8; 16];
                for (chunk, col) in md5.as_chunks_mut::<4>().0.iter_mut().zip(parts) {
                    // A part of 0x80000000 is stored as Windows Installer's null integer.
                    *chunk = hashes.int(r, col).unwrap_or(i32::MIN).to_le_bytes();
                }
                Some((key, md5))
            })
            .collect();
        drop(hashes);

        // Each cabinet's files by name (the File key), and where each is in its data.
        let mut by_name: Vec<HashMap<String, InCab>> = Vec::with_capacity(self.cabs.len());
        for cab in &mut self.cabs {
            let order = cab.data_order();
            let entries = cab.entries(cx)?;
            let mut map = HashMap::with_capacity(entries.len());
            for (pos, id) in order.into_iter().enumerate() {
                if let Some(e) = entries.get(id) {
                    map.entry(e.path.clone()).or_insert_with(|| InCab {
                        id,
                        pos,
                        modified: e.modified,
                        method: e.method.clone(),
                    });
                }
            }
            by_name.push(map);
        }
        let cab_media: Vec<usize> = (0..self.cabs.len())
            .map(|c| {
                media
                    .iter()
                    .position(|m| matches!(m.cab, Some(Ok(i)) if i == c))
                    .unwrap_or(usize::MAX)
            })
            .collect();

        let t = db.table("File")?;
        let cols = [
            "File",
            "Component_",
            "FileName",
            "FileSize",
            "Attributes",
            "Sequence",
        ]
        .map(|c| t.col(c));
        let [c_key, c_comp, c_name, c_size, c_attrs, c_seq] = cols;
        let default_compressed = words & WORD_COMPRESSED != 0;
        let src_dir = self.dir();
        let mut out: Vec<FileRow> = Vec::with_capacity(t.rows.min(1 << 20));
        let mut problems: Vec<String> = Vec::new();
        for r in 0..t.rows {
            if r % 1024 == 0 {
                cx.check()?;
            }
            self.source.limits.check_entries(out.len() as u64 + 1)?;
            let Some(key) = db.text(&t, r, c_key) else {
                continue;
            };
            let component = db.text(&t, r, c_comp).unwrap_or_default();
            let file_name = db.text(&t, r, c_name).unwrap_or_default();
            // A size past 2 GiB is stored as a negative number.
            let size = u64::from(t.int(r, c_size).unwrap_or(0) as u32);
            let attrs = t.int(r, c_attrs).unwrap_or(0);
            let sequence = t.int(r, c_seq).unwrap_or(0);
            let dir_key = comp_dir.get(&component);
            let dir = match dir_key {
                Some(d) => layout.target(d)?,
                None => {
                    problems.push(format!(
                        "`{key}`'s component `{component}` has no row; it's listed at the top"
                    ));
                    String::new()
                }
            };
            let path = names::file_path(&dir, &file_name, &key);
            layout.count(path.len() + key.len())?;
            let md5 = md5s
                .get(&key)
                .copied()
                .filter(|h| !(size == 0 && *h == [0; 16]));
            let check = Check { size, md5 };
            let compressed = if attrs & ATTR_COMPRESSED != 0 {
                true
            } else if attrs & ATTR_NONCOMPRESSED != 0 {
                false
            } else {
                default_compressed
            };
            let at = media.iter().position(|m| m.last >= sequence);
            let mut row = FileRow {
                key: key.clone(),
                path,
                sequence,
                attrs,
                check,
                order: (at.unwrap_or(usize::MAX), 1, i64::from(sequence)),
                item: Item::Dir,
                modified: None,
                method: None,
            };
            row.item = if compressed {
                let found = match at.and_then(|m| media.get(m)) {
                    None => Err(bad(format!(
                        "`{}`: no Media row covers its sequence number, {sequence}",
                        row.path
                    ))),
                    Some(Media {
                        cab: None, disk, ..
                    }) => Err(bad(format!(
                        "`{}` is compressed, and its Media row ({disk}) names no cabinet",
                        row.path
                    ))),
                    // Its cabinet can't be read: opening said so once.
                    Some(Media {
                        cab: Some(Err(e)), ..
                    }) => Ok(Err(e.clone())),
                    Some(Media {
                        cab: Some(Ok(c)),
                        cabinet,
                        ..
                    }) => {
                        // In its own cabinet, else in another the package has.
                        let own = by_name.get(*c).and_then(|m| m.get(&key)).map(|f| (*c, f));
                        own.or_else(|| {
                            by_name
                                .iter()
                                .enumerate()
                                .find_map(|(i, m)| m.get(&key).map(|f| (i, f)))
                        })
                        .map(|(c, f)| Ok((c, f.clone())))
                        .ok_or_else(|| {
                            bad(format!(
                                "`{}`'s cabinet, {}, doesn't hold it (as `{key}`)",
                                row.path,
                                cabinet.as_deref().unwrap_or_default()
                            ))
                        })
                    }
                };
                match found {
                    Ok(Ok((cab, f))) => {
                        row.modified = f.modified;
                        row.method = f.method;
                        row.order = (
                            cab_media.get(cab).copied().unwrap_or(usize::MAX),
                            0,
                            i64::try_from(f.pos).unwrap_or(i64::MAX),
                        );
                        Item::Cab {
                            cab,
                            id: f.id,
                            check,
                        }
                    }
                    Ok(Err(e)) => Item::Missing(e),
                    Err(e) => {
                        problems.push(e.message.trim_start_matches("msi: ").to_owned());
                        Item::Missing(e)
                    }
                }
            } else {
                // From the source image: the source halves, short or long.
                let leaf = if short_source {
                    names::short_name(&file_name)
                } else {
                    names::long_name(&file_name)
                };
                let rel = match dir_key {
                    Some(d) => layout.source(d)?,
                    None => None,
                };
                match rel.filter(|_| {
                    !leaf.is_empty()
                        && leaf != "."
                        && leaf != ".."
                        && !leaf.contains(['/', '\\', ':'])
                }) {
                    Some(rel) => {
                        let want = rel
                            .split('/')
                            .filter(|n| !n.is_empty())
                            .chain([leaf])
                            .fold(src_dir.clone(), |p, n| p.join(n));
                        match find_path(&src_dir, &rel, leaf) {
                            Some(p) => {
                                self.total += size;
                                row.modified =
                                    std::fs::metadata(&p).and_then(|m| m.modified()).ok();
                                Item::Source { path: p, check }
                            }
                            None => {
                                let e = Error::new(
                                    ErrorKind::NotFound,
                                    format!(
                                        "msi: `{}` isn't in the package, and isn't beside it in \
                                         its source image either (looked for {})",
                                        row.path,
                                        want.display()
                                    ),
                                );
                                problems.push(e.message.trim_start_matches("msi: ").to_owned());
                                Item::Missing(e)
                            }
                        }
                    }
                    None => {
                        let e = bad(format!(
                            "`{}` isn't in the package, and its place in the source image can't \
                             be found from the Directory table",
                            row.path
                        ));
                        problems.push(e.message.trim_start_matches("msi: ").to_owned());
                        Item::Missing(e)
                    }
                }
            };
            out.push(row);
        }

        // The same path twice: the lowest Sequence keeps it (paths compared as Windows does).
        let mut by_path: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, f) in out.iter().enumerate() {
            by_path.entry(f.path.to_lowercase()).or_default().push(i);
        }
        let mut renamed = 0usize;
        for group in by_path.into_values().filter(|g| g.len() > 1) {
            let mut group = group;
            group.sort_by(|&a, &b| {
                (out[a].sequence, &out[a].key).cmp(&(out[b].sequence, &out[b].key))
            });
            for &i in &group[1..] {
                let p = names::with_key(&out[i].path, &out[i].key);
                layout.count(p.len())?;
                out[i].path = p;
                renamed += 1;
            }
        }
        if renamed > 0 {
            self.notes.push(format!(
                "{renamed} files share their path with another, as alternates the installer \
                 chooses between; each is listed with its File key before its extension."
            ));
        }
        out.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.key.cmp(&b.key)));

        let msi = self.source.file_name();
        for w in layout.warnings.drain(..) {
            cx.warn(format!("{msi}: {}", w.trim_start_matches("msi: ")));
        }
        if !layout.cut.is_empty() {
            cx.warn(format!(
                "{msi}: {} folders are nested more than {} deep or have paths longer than {} \
                 bytes; their files are listed under their Directory keys, such as `{}`",
                layout.cut.len(),
                names::MAX_DEPTH,
                names::MAX_PATH,
                layout.cut[0]
            ));
        }
        for p in problems.iter().take(MAX_FILE_WARNINGS) {
            cx.warn(format!("{msi}: {p}"));
        }
        if problems.len() > MAX_FILE_WARNINGS {
            cx.warn(format!(
                "{msi}: and {} more files like these",
                problems.len() - MAX_FILE_WARNINGS
            ));
        }
        Ok(out)
    }

    /// The Binary and Icon tables' streams, as `[Binary]/<name>` and `[Icon]/<name>`.
    fn streams(&mut self, db: &Db) -> Result<Vec<(String, Item, u64)>> {
        let file_len = self.file_len;
        let mut out = Vec::new();
        for table in ["Binary", "Icon"] {
            let t = db.table(table)?;
            let c_name = t.col("Name");
            for r in 0..t.rows {
                let Some(name) = db.text(&t, r, c_name) else {
                    continue;
                };
                let path = format!("[{table}]/{}", names::component(&name));
                let stream = tables::stream_path(&format!("{table}.{name}"), false);
                let (item, len) = match CfbStream::open(&self.file, &stream).map(|s| s.len()) {
                    Some(len) if len <= file_len => {
                        self.total += len;
                        (Item::Stream { path: stream, len }, len)
                    }
                    Some(len) => (
                        Item::Missing(bad(format!(
                            "`{path}` claims {len} bytes, in a file of {file_len}"
                        ))),
                        0,
                    ),
                    None => (
                        Item::Missing(bad(format!(
                            "`{path}` is in the {table} table, and its stream isn't in the package"
                        ))),
                        0,
                    ),
                };
                out.push((path, item, len));
            }
        }
        Ok(out)
    }

    /// Entry `idx`'s data, when it isn't in a cabinet: checked, counted and guarded.
    fn plain_data(&self, idx: usize) -> Result<Box<dyn Read + Send + '_>> {
        let (Some(entry), Some(item)) = (self.entries.get(idx), self.items.get(idx)) else {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {idx}")));
        };
        let counter = self.source.counter.clone();
        let data: Box<dyn Read + Send> = match item {
            Item::Dir => return Ok(Box::new(io::empty())),
            Item::Missing(e) => return Ok(Box::new(Failing(e.clone()))),
            Item::Cab { .. } => return Err(bad("a cabinet's file read as a loose one")),
            Item::Source { path, check } => {
                let f = File::open(path)
                    .map_err(|e| Error::io(format!("opening {}", path.display()), &e))?;
                let counted = CountingReader::new(BufReader::with_capacity(BUF_SIZE, f), counter);
                Box::new(Checked::new(counted, &entry.path, *check))
            }
            Item::Stream { path, len } => {
                let s = CfbStream::open(&self.file, path)
                    .ok_or_else(|| bad(format!("`{}`'s stream vanished", entry.path)))?;
                let counted = CountingReader::new(BufReader::with_capacity(BUF_SIZE, s), counter);
                let check = Check {
                    size: *len,
                    md5: None,
                };
                Box::new(Checked::new(counted, &entry.path, check))
            }
        };
        Ok(Box::new(self.source.guard(data)))
    }
}

/// `rel/leaf` under `dir`, each name matched exactly or else ignoring case, as on Windows.
fn find_path(dir: &Path, rel: &str, leaf: &str) -> Option<PathBuf> {
    let mut at = dir.to_path_buf();
    for name in rel.split('/').filter(|n| !n.is_empty()).chain([leaf]) {
        let exact = at.join(name);
        at = if exact.exists() {
            exact
        } else {
            let lower = name.to_lowercase();
            let base = if at.as_os_str().is_empty() {
                Path::new(".")
            } else {
                at.as_path()
            };
            std::fs::read_dir(base)
                .ok()?
                .flatten()
                .find(|e| e.file_name().to_string_lossy().to_lowercase() == lower)?
                .path()
        };
    }
    at.is_file().then_some(at)
}

/// A reader that fails with its error: a file whose data isn't there.
struct Failing(Error);

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self.0.clone().into_io())
    }
}

/// A file's data held to the File table: its size, and MsiFileHash's MD5 where there is one.
struct Checked<R> {
    inner: R,
    path: String,
    check: Check,
    got: u64,
    md5: Option<md5::Md5>,
    failed: Option<Error>,
    done: bool,
}

impl<R: Read> Checked<R> {
    fn new(inner: R, path: &str, check: Check) -> Self {
        Self {
            inner,
            path: path.to_owned(),
            check,
            got: 0,
            md5: check.md5.map(|_| md5::Md5::new()),
            failed: None,
            done: false,
        }
    }

    fn fail(&mut self, e: Error) -> io::Error {
        self.failed = Some(e.clone());
        e.into_io()
    }

    /// At the end: the size and the hash.
    fn finish(&mut self) -> Option<Error> {
        if self.got != self.check.size {
            return Some(bad(format!(
                "`{}` is {} bytes, and the File table says {}",
                self.path, self.got, self.check.size
            )));
        }
        if let (Some(h), Some(want)) = (self.md5.take(), self.check.md5)
            && h.finalize()[..] != want[..]
        {
            return Some(bad(format!(
                "`{}` doesn't match its hash in the MsiFileHash table",
                self.path
            )));
        }
        None
    }
}

impl<R: Read> Read for Checked<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.failed {
            return Err(e.clone().into_io());
        }
        if buf.is_empty() || self.done {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        if n == 0 {
            self.done = true;
            if let Some(e) = self.finish() {
                return Err(self.fail(e));
            }
            return Ok(0);
        }
        self.got += n as u64;
        if self.got > self.check.size {
            let e = bad(format!(
                "`{}` holds more than the {} bytes the File table says",
                self.path, self.check.size
            ));
            return Err(self.fail(e));
        }
        if let Some(h) = &mut self.md5 {
            h.update(&buf[..n]);
        }
        Ok(n)
    }
}

/// Progress over a whole extraction: the cabinets' readers count their bytes on the source's
/// counter, and start it again at each pass, so the passes before are added here.
struct Pass {
    counter: Counter,
    done: Cell<u64>,
    total: u64,
    entries_done: Cell<u64>,
    entries_total: u64,
    current: RefCell<Option<String>>,
}

impl Pass {
    fn snapshot(&self) -> Progress {
        Progress {
            bytes_done: self.done.get() + self.counter.get(),
            bytes_total: Some(self.total),
            entries_done: self.entries_done.get(),
            entries_total: Some(self.entries_total),
            current: self.current.borrow().clone(),
        }
    }

    /// Adds the pass just made to the bytes done.
    fn fold(&self) {
        self.done.set(self.done.get() + self.counter.get());
        self.counter.set(0);
    }

    fn start(&self, path: &str) {
        *self.current.borrow_mut() = Some(path.to_owned());
    }

    fn finished(&self) {
        self.entries_done.set(self.entries_done.get() + 1);
    }
}

/// The job's context as the reader's passes see it: whatever progress a cabinet's reader
/// reports of itself, the package's is reported instead.
struct PassCtx<'a> {
    inner: &'a mut dyn Ctx,
    pass: &'a Pass,
}

impl Ctx for PassCtx<'_> {
    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    fn progress(&mut self, _: &Progress) {
        self.inner.progress(&self.pass.snapshot());
    }

    fn warn(&mut self, message: String) {
        self.inner.warn(message);
    }

    fn password(&mut self, entry: Option<&str>, attempt: u32) -> Result<String> {
        self.inner.password(entry, attempt)
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        self.inner.overwrite(existing)
    }

    fn overwrite_entry(&mut self, archive: &Path, entry: &str) -> Result<OverwriteChoice> {
        self.inner.overwrite_entry(archive, entry)
    }

    fn check(&mut self) -> Result<()> {
        self.inner.progress(&self.pass.snapshot());
        self.inner.check()
    }
}

/// A cabinet's files handed on as the package's entries, checked.
struct ToMsi<'a> {
    sink: &'a mut dyn EntrySink,
    /// The cabinet's entry ids, selected, to the package's.
    map: &'a HashMap<usize, usize>,
    entries: &'a [Entry],
    items: &'a [Item],
    pass: &'a Pass,
}

impl EntrySink for ToMsi<'_> {
    fn entry(&mut self, cab_entry: &Entry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let Some(&idx) = self.map.get(&cab_entry.id) else {
            return Ok(());
        };
        let (Some(entry), Some(Item::Cab { check, .. })) =
            (self.entries.get(idx), self.items.get(idx))
        else {
            return Ok(());
        };
        self.pass.start(&entry.path);
        let mut data = Checked::new(data, &entry.path, *check);
        self.sink.entry(entry, &mut data, cx)?;
        self.pass.finished();
        Ok(())
    }
}

impl ArchiveReader for MsiReader {
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
        let mut levels = vec!["msi".to_owned()];
        if !self.cabs.is_empty() {
            levels.push("cab".to_owned());
        }
        Ok(ArchiveInfo {
            format: FormatId::External(External::Msi),
            codecs: self.source.codecs.clone(),
            methods: self.methods.clone(),
            comment: None,
            encryption: Encryption::None,
            solid: self.solid_blocks > 0,
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: Some(self.solid_blocks),
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: Some(ExternalInfo {
                backend: None,
                levels,
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
        let selected: Vec<bool> = self.entries.iter().map(|e| sel.matches(e)).collect();
        self.source.counter.set(0);
        let pass = Pass {
            counter: self.source.counter.clone(),
            done: Cell::new(0),
            total: self.total,
            entries_done: Cell::new(0),
            entries_total: selected.iter().filter(|s| **s).count() as u64,
            current: RefCell::new(None),
        };
        let n = self.entries.len();
        let mut i = 0;
        while i < n {
            cx.check()?;
            // A run of one cabinet's files: that cabinet, read once.
            if let Some(&Item::Cab { cab, .. }) = self.items.get(i) {
                let mut j = i;
                let mut map = HashMap::new();
                while let Some(&Item::Cab { cab: c, id, .. }) = self.items.get(j) {
                    if c != cab {
                        break;
                    }
                    if selected[j] {
                        map.insert(id, j);
                    }
                    j += 1;
                }
                if !map.is_empty()
                    && let Some(reader) = self.cabs.get_mut(cab)
                {
                    let ids = Selection::ids(map.keys().copied());
                    let mut to = ToMsi {
                        sink: &mut *sink,
                        map: &map,
                        entries: &self.entries,
                        items: &self.items,
                        pass: &pass,
                    };
                    let mut pcx = PassCtx {
                        inner: &mut *cx,
                        pass: &pass,
                    };
                    reader.extract(&ids, &mut to, &mut pcx)?;
                    pass.fold();
                }
                i = j;
                continue;
            }
            if selected[i] {
                pass.start(&self.entries[i].path);
                let mut pcx = PassCtx {
                    inner: &mut *cx,
                    pass: &pass,
                };
                pcx.inner.progress(&pass.snapshot());
                let mut data = self.plain_data(i)?;
                sink.entry(&self.entries[i], &mut data, &mut pcx)?;
                drop(data);
                pass.fold();
                pass.finished();
            }
            i += 1;
        }
        *pass.current.borrow_mut() = None;
        cx.progress(&pass.snapshot());
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let (Some(entry), Some(item)) = (self.entries.get(id), self.items.get(id)) else {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        };
        match item {
            Item::Cab { cab, id, check } => {
                let (path, check) = (entry.path.clone(), *check);
                let reader = self
                    .cabs
                    .get_mut(*cab)
                    .ok_or_else(|| bad("a file in a cabinet that isn't there"))?;
                let data = reader.open_entry(*id, cx)?;
                Ok(Box::new(Checked::new(data, &path, check)))
            }
            Item::Missing(e) => Err(e.clone()),
            _ => {
                self.source.counter.set(0);
                let data = self.plain_data(id)?;
                Ok(data)
            }
        }
    }
}
