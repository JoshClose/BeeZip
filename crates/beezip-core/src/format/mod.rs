//! Archive formats: ZIP, TAR and the one-entry stream view of a bare compressed file
//! (docs/M1.md §3.4).

pub mod rar;
pub mod sevenz;
pub mod sevenz_header;
pub mod stream;
pub mod tar;
pub mod zip;

use std::{collections::BTreeSet, fmt, io::Read, time::SystemTime};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::{
    CodecId, Ctx, Error, Result,
    detect::{Confidence, Probe},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FormatId {
    Zip,
    Tar,
    SevenZ,
    Rar,
    /// A bare compressed file, seen as an archive with one entry.
    Stream,
}

impl FormatId {
    pub const ALL: [FormatId; 5] = [Self::Zip, Self::Tar, Self::SevenZ, Self::Rar, Self::Stream];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Stream => "stream",
            Self::SevenZ => "7z",
            Self::Rar => "rar",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Zip => "ZIP",
            Self::Tar => "TAR",
            Self::Stream => "compressed file",
            Self::SevenZ => "7z",
            Self::Rar => "RAR",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    pub fn format(self) -> &'static dyn ArchiveFormat {
        match self {
            Self::Zip => &zip::Zip,
            Self::Tar => &tar::Tar,
            Self::Stream => &stream::Stream,
            Self::SevenZ => &sevenz::SevenZ,
            Self::Rar => &rar::Rar,
        }
    }
}

impl fmt::Display for FormatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What BeeZip offers for a format in this milestone, not what the crate could do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FormatCaps {
    pub list: bool,
    pub extract: bool,
    pub create: bool,
    pub append: bool,
    pub delete: bool,
    pub rename: bool,
    pub encrypt: bool,
    pub encrypt_headers: bool,
    pub solid: bool,
    pub volumes: bool,
    /// An entry can be read without decoding the ones before it.
    pub random_access: bool,
}

pub trait ArchiveFormat: Sync {
    fn id(&self) -> FormatId;
    /// Lowercase, with the dot.
    fn extensions(&self) -> &'static [&'static str];
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence>;
    /// The caps of the plain format; [`caps_for`] adjusts them for a codec chain.
    fn caps(&self) -> FormatCaps;
}

/// Every format, in [`FormatId::ALL`] order.
pub fn formats() -> impl Iterator<Item = &'static dyn ArchiveFormat> {
    FormatId::ALL.into_iter().map(FormatId::format)
}

/// The caps of `format` under `codecs`: a compressed tar must be decoded from the start to
/// reach an entry, so it has no random access.
pub fn caps_for(format: FormatId, codecs: &[CodecId]) -> FormatCaps {
    let mut caps = format.format().caps();
    if !codecs.is_empty() && format == FormatId::Tar {
        caps.random_access = false;
    }
    caps
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink {
        target: String,
    },
    /// A hard link to an earlier entry, by its archive path.
    Hardlink {
        target: String,
    },
    /// Devices, FIFOs and the like. Extraction skips them with a warning.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Index in archive order.
    pub id: usize,
    /// `/`-separated and decoded, but otherwise exactly as stored. Sanitising happens in
    /// `FsSink`.
    pub path: String,
    pub raw_path: Vec<u8>,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub packed_size: Option<u64>,
    pub modified: Option<SystemTime>,
    pub crc32: Option<u32>,
    pub method: Option<&'static str>,
    pub encrypted: bool,
    pub unix_mode: Option<u32>,
    pub dos_attrs: Option<u32>,
}

impl Entry {
    pub fn new(id: usize, path: String, kind: EntryKind) -> Self {
        Self {
            id,
            raw_path: path.as_bytes().to_vec(),
            path,
            kind,
            size: None,
            packed_size: None,
            modified: None,
            crc32: None,
            method: None,
            encrypted: false,
            unix_mode: None,
            dos_attrs: None,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir
    }
}

/// How many entries are encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encryption {
    #[default]
    None,
    Some,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveInfo {
    pub format: FormatId,
    pub codecs: Vec<CodecId>,
    /// Compression methods used by the entries, e.g. `["Deflate", "Store"]`.
    pub methods: Vec<&'static str>,
    pub comment: Option<String>,
    pub encryption: Encryption,
    pub solid: bool,
    /// A self-extracting archive (an archive inside an executable).
    pub sfx: bool,
    /// How many files the archive is split across (1 when it isn't).
    pub volumes: usize,
    /// 7z: blocks that hold more than one entry.
    pub solid_blocks: Option<u64>,
    /// Entry names are encrypted too (7z `-mhe`, RAR `-hp`).
    pub encrypted_headers: bool,
    /// RAR: locked against changes.
    pub locked: bool,
    /// RAR: has a recovery record.
    pub recovery_record: bool,
}

/// Which entries an operation applies to (docs/M1.md §4.3). Paths use `/`, and a directory
/// selects its whole subtree. A pattern without `/` matches a name at any depth (`*.txt`); one
/// with `/` matches the whole path (`docs/**/*.md`). Matching ignores case on Windows.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    ids: Option<BTreeSet<usize>>,
    paths: Vec<String>,
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
}

impl Selection {
    pub fn all() -> Self {
        Self::default()
    }

    pub fn ids(ids: impl IntoIterator<Item = usize>) -> Self {
        Self {
            ids: Some(ids.into_iter().collect()),
            ..Self::default()
        }
    }

    /// Entries under any of `paths` or matching any of `include` (all entries when both are
    /// empty), minus those matching `exclude`. Bad patterns are `InvalidArgs`.
    pub fn new(paths: &[String], include: &[String], exclude: &[String]) -> Result<Self> {
        Ok(Self {
            ids: None,
            paths: paths
                .iter()
                .map(|p| fold_case(&normalize(p)))
                .filter(|p| !p.is_empty())
                .collect(),
            include: globs(include)?,
            exclude: globs(exclude)?,
        })
    }

    pub fn is_all(&self) -> bool {
        self.ids.is_none()
            && self.paths.is_empty()
            && self.include.is_none()
            && self.exclude.is_none()
    }

    pub fn matches(&self, entry: &Entry) -> bool {
        if let Some(ids) = &self.ids
            && !ids.contains(&entry.id)
        {
            return false;
        }
        let path = normalize(&entry.path);
        let included = if self.paths.is_empty() && self.include.is_none() {
            true
        } else {
            let folded = fold_case(&path);
            self.paths
                .iter()
                .any(|p| folded == *p || folded.starts_with(&format!("{p}/")))
                || self
                    .include
                    .as_ref()
                    .is_some_and(|g| matches_tree(g, &path))
        };
        included
            && !self
                .exclude
                .as_ref()
                .is_some_and(|g| matches_tree(g, &path))
    }
}

/// `\` → `/`, without leading `./` or `/` and trailing `/`.
pub fn normalize(path: &str) -> String {
    let p = path.replace('\\', "/");
    let mut p = p.as_str();
    loop {
        if let Some(rest) = p.strip_prefix("./") {
            p = rest;
        } else if let Some(rest) = p.strip_prefix('/') {
            p = rest;
        } else {
            break;
        }
    }
    p.trim_end_matches('/').to_owned()
}

fn fold_case(path: &str) -> String {
    if cfg!(windows) {
        path.to_lowercase()
    } else {
        path.to_owned()
    }
}

/// The path or any of its parent directories matches, so a directory pattern takes its subtree.
fn matches_tree(set: &GlobSet, path: &str) -> bool {
    let mut prefix = path;
    loop {
        if set.is_match(prefix) {
            return true;
        }
        match prefix.rfind('/') {
            Some(i) => prefix = &path[..i],
            None => return false,
        }
    }
}

fn globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut set = GlobSetBuilder::new();
    for pat in patterns {
        let pat = pat.replace('\\', "/");
        let pat = pat.trim_start_matches("./");
        let full = if pat.contains('/') {
            vec![pat.trim_start_matches('/').to_owned()]
        } else {
            vec![pat.to_owned(), format!("**/{pat}")]
        };
        for p in full {
            let glob = GlobBuilder::new(&p)
                .literal_separator(true)
                .case_insensitive(cfg!(windows))
                .backslash_escape(false)
                .build()
                .map_err(|e| Error::invalid_args(format!("bad pattern `{pat}`: {e}")))?;
            set.add(glob);
        }
    }
    set.build()
        .map(Some)
        .map_err(|e| Error::invalid_args(format!("bad patterns: {e}")))
}

/// Receives entries from [`ArchiveReader::extract`]. Readers call it in archive order; `data`
/// is empty for directories and links.
pub trait EntrySink {
    fn entry(&mut self, entry: &Entry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()>;
}

/// An open archive.
pub trait ArchiveReader: Send {
    fn format(&self) -> FormatId;

    /// The entry index. Zip reads it from the central directory when it opens; tar, behind a
    /// codec, has to decode the whole stream once, so it builds it on first use.
    fn entries(&mut self, cx: &mut dyn Ctx) -> Result<&[Entry]>;

    fn info(&mut self, cx: &mut dyn Ctx) -> Result<ArchiveInfo>;

    /// Streams the selected entries to `sink` in archive order, in a single pass. It doesn't
    /// need the index first, so extracting a `tar.zst` decodes it once.
    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()>;

    /// One entry's data, by id. Entries of formats without random access are reached by
    /// decoding from the start.
    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>>;
}

/// An entry to add to a new archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEntry {
    /// `/`-separated archive path, without a trailing `/`.
    pub path: String,
    pub kind: NewKind,
    /// The data size, for files; tar writes it up front and fails if the file changes size.
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub unix_mode: Option<u32>,
    pub dos_attrs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewKind {
    File,
    Dir,
    Symlink { target: String },
}

/// Writes a new archive. `finish` must be called; until it succeeds the output is incomplete.
pub trait ArchiveWriter {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()>;

    /// For a writer that packs files into solid blocks: the most bytes one block holds.
    /// `ops::create` then hands it files in groups through [`ArchiveWriter::add_solid`].
    fn solid_block_limit(&self) -> Option<u64> {
        None
    }

    /// Adds `entries` (non-empty files) as one solid block. `open(i)` opens entry `i`'s data
    /// when the writer reaches it. The default adds them one by one.
    fn add_solid(
        &mut self,
        entries: &[NewEntry],
        open: &mut dyn FnMut(usize) -> Result<Box<dyn Read>>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        for (i, e) in entries.iter().enumerate() {
            let mut data = open(i)?;
            self.add(e, &mut data, cx)?;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> Entry {
        Entry::new(0, path.into(), EntryKind::File)
    }

    fn sel(paths: &[&str], include: &[&str], exclude: &[&str]) -> Selection {
        let v = |s: &[&str]| s.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        Selection::new(&v(paths), &v(include), &v(exclude)).unwrap()
    }

    #[test]
    fn selection_rules() {
        assert!(Selection::all().matches(&entry("a/b.txt")));

        let s = sel(&["docs"], &[], &[]);
        assert!(s.matches(&entry("docs/a.md")));
        assert!(s.matches(&entry("./docs/")));
        assert!(!s.matches(&entry("docsx/a.md")));

        let s = sel(&[], &["*.txt"], &[]);
        assert!(s.matches(&entry("a.txt")));
        assert!(s.matches(&entry("deep/er/b.txt")));
        assert!(!s.matches(&entry("c.md")));

        let s = sel(&[], &["docs/**/*.md"], &[]);
        assert!(s.matches(&entry("docs/x/y.md")));
        assert!(!s.matches(&entry("other/docs/y.md")));

        let s = sel(&[], &[], &["build"]);
        assert!(!s.matches(&entry("src/build/out.o")));
        assert!(s.matches(&entry("src/main.rs")));

        assert!(Selection::new(&[], &["[".into()], &[]).is_err());
        assert!(Selection::ids([2]).matches(&Entry::new(2, "x".into(), EntryKind::File)));
        assert!(!Selection::ids([2]).matches(&entry("x")));
    }

    #[test]
    #[cfg(windows)]
    fn selection_ignores_case_on_windows() {
        assert!(sel(&["Docs"], &[], &[]).matches(&entry("docs/A.md")));
        assert!(sel(&[], &["*.TXT"], &[]).matches(&entry("a.txt")));
    }

    #[test]
    fn compressed_tar_has_no_random_access() {
        assert!(caps_for(FormatId::Tar, &[]).random_access);
        assert!(!caps_for(FormatId::Tar, &[CodecId::Zstd]).random_access);
    }
}
