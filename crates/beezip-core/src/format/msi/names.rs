//! Where an installer puts each file (docs/M7.md §8.2).
//!
//! - **A folder's path** is its Windows Installer folder property's: the Directory table's
//!   chain of parents, each adding the long half of its `short|long` name, from the target half
//!   of `target:source`. `.` adds no level. TARGETDIR, the root, adds none either.
//! - **A standard folder property** (ProgramFiles64Folder, System64Folder…) starts again at the
//!   top wherever its row sits, under its own name, and so does a merge module's copy of one
//!   (`System64Folder.<GUID>`, which the module sets to that folder). Another root is listed
//!   under its key.
//! - **The source image** of an uncompressed file is laid out from the MSI's folder by the
//!   source halves of the same names, short or long as the summary information says. A source
//!   path never leaves that folder: one with `..`, or a name with `:`, isn't looked for.
//! - **Caps** (the spike's `deep.msi`, a valid 96 KiB package 3,000 folders deep with names of
//!   2,000 characters, drove an uncapped layout past 1 GiB): a folder more than 64 deep, or
//!   whose path would pass 4,096 bytes, is listed at the top under its key, with what's inside
//!   it; every path is held to 4,096 bytes; and all of the paths together to 128 MiB, past which
//!   the package is refused. Parents are followed in a loop, not by recursion, and a loop among
//!   them is caught.
//! - **The same path twice** (conditional alternates, such as VC++'s x64 and Arm64
//!   `msvcp140.dll`): the file with the lowest Sequence keeps it, and each other takes its File
//!   key before the extension, `msvcp140.<key>.dll` (decision 5).

use std::collections::{HashMap, HashSet};

use crate::{Error, Result};

/// The folder properties Windows Installer sets itself ("System Folder Properties"). WiX v4's
/// `ProgramFiles6432Folder` isn't one: it's a row of its own (`.` under ProgramFiles64Folder),
/// resolved through the table.
pub const STANDARD_FOLDERS: &[&str] = &[
    "AdminToolsFolder",
    "AppDataFolder",
    "CommonAppDataFolder",
    "CommonFiles64Folder",
    "CommonFilesFolder",
    "DesktopFolder",
    "FavoritesFolder",
    "FontsFolder",
    "LocalAppDataFolder",
    "MyPicturesFolder",
    "NetHoodFolder",
    "PersonalFolder",
    "PrintHoodFolder",
    "ProgramFiles64Folder",
    "ProgramFilesFolder",
    "ProgramMenuFolder",
    "RecentFolder",
    "SendToFolder",
    "StartMenuFolder",
    "StartupFolder",
    "System16Folder",
    "System64Folder",
    "SystemFolder",
    "TempFolder",
    "TemplateFolder",
    "WindowsFolder",
    "WindowsVolume",
];

/// Folders deeper than this are listed under their keys.
pub const MAX_DEPTH: usize = 64;
/// The longest path, in bytes.
pub const MAX_PATH: usize = 4096;
/// All the paths together, in bytes.
pub const MAX_NAMES: u64 = 128 << 20;

/// `short|long` → `long` (or the name, when it has one half).
pub fn long_name(name: &str) -> &str {
    name.split_once('|').map_or(name, |(_, l)| l)
}

/// `short|long` → `short`.
pub fn short_name(name: &str) -> &str {
    name.split_once('|').map_or(name, |(s, _)| s)
}

/// `target:source` → (target, source); without `:` both are the name.
pub fn split_default_dir(d: &str) -> (&str, &str) {
    d.split_once(':').unwrap_or((d, d))
}

/// A name as one path component: `/` and `\` can't be part of one.
pub fn component(name: &str) -> String {
    name.replace(['/', '\\'], "_")
}

/// `path` cut to [`MAX_PATH`] bytes, at a character's start.
fn fit(mut path: String) -> String {
    if path.len() > MAX_PATH {
        let mut end = MAX_PATH;
        while !path.is_char_boundary(end) {
            end -= 1;
        }
        path.truncate(end);
    }
    path
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// The standard folder a Directory key is, itself or as a merge module's copy.
fn standard(key: &str) -> Option<&'static str> {
    let head = key.split_once('.').map_or(key, |(h, _)| h);
    STANDARD_FOLDERS.iter().copied().find(|s| *s == head)
}

/// A Directory row.
#[derive(Debug, Clone)]
pub struct DirRow {
    pub parent: Option<String>,
    pub default_dir: String,
}

/// A folder, resolved: its path and depth, or cut (too deep, too long, or in a loop).
#[derive(Debug, Clone)]
enum Res {
    Path {
        path: String,
        depth: usize,
    },
    /// Too deep or too long (`deep`), or in a loop, or outside the MSI's folder.
    Cut {
        deep: bool,
    },
}

/// Which path is wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// Where it's installed.
    Target,
    /// Where it is in the source image, by short names or long.
    Source { short: bool },
}

/// The folders of the Directory table, resolved on demand and remembered.
pub struct Layout {
    rows: HashMap<String, DirRow>,
    target: HashMap<String, Res>,
    source: HashMap<String, Res>,
    short_source: bool,
    /// Bytes of every path so far, against [`MAX_NAMES`].
    bytes: u64,
    /// Folders listed under their keys, and why, for the warnings.
    pub cut: Vec<String>,
    pub warnings: Vec<String>,
    warned: HashSet<String>,
}

impl Layout {
    /// `short_source`: the source image has short names (the word count's bit 0).
    pub fn new(rows: HashMap<String, DirRow>, short_source: bool) -> Self {
        Self {
            rows,
            target: HashMap::new(),
            source: HashMap::new(),
            short_source,
            bytes: 0,
            cut: Vec::new(),
            warnings: Vec::new(),
            warned: HashSet::new(),
        }
    }

    /// Counts `n` more bytes of paths against [`MAX_NAMES`].
    pub fn count(&mut self, n: usize) -> Result<()> {
        self.bytes += n as u64;
        if self.bytes > MAX_NAMES {
            return Err(Error::limit(format!(
                "msi: the package's folder and file names add up to more than {MAX_NAMES} bytes"
            )));
        }
        Ok(())
    }

    fn warn_once(&mut self, key: &str, message: String) {
        if self.warned.insert(key.to_owned()) {
            self.warnings.push(message);
        }
    }

    /// Where the folder `key` is installed, `/`-separated; empty for TARGETDIR itself.
    pub fn target(&mut self, key: &str) -> Result<String> {
        match self.resolve(key, Side::Target)? {
            Res::Path { path, .. } => Ok(path),
            Res::Cut { deep } => {
                if deep && self.warned.insert(format!("cut {key}")) {
                    self.cut.push(key.to_owned());
                }
                Ok(fit(component(key)))
            }
        }
    }

    /// Where the folder `key` is in the source image, from the MSI's folder; `None` when it
    /// can't be found there.
    pub fn source(&mut self, key: &str) -> Result<Option<String>> {
        let side = Side::Source {
            short: self.short_source,
        };
        Ok(match self.resolve(key, side)? {
            Res::Path { path, .. } => Some(path),
            Res::Cut { .. } => None,
        })
    }

    /// Resolves `key` and the folders above it that aren't yet, from the top down.
    fn resolve(&mut self, key: &str, side: Side) -> Result<Res> {
        if let Some(r) = self.cache(side).get(key) {
            return Ok(r.clone());
        }
        // Up to a folder already known, a standard one, a root or one without a row.
        let mut chain: Vec<String> = Vec::new();
        let mut on_chain: HashSet<String> = HashSet::new();
        let mut cur = key.to_owned();
        let mut base = loop {
            if let Some(r) = self.cache(side).get(&cur) {
                break r.clone();
            }
            if side == Side::Target
                && let Some(top) = standard(&cur)
            {
                let r = Res::Path {
                    path: top.to_owned(),
                    depth: 1,
                };
                self.cache(side).insert(cur, r.clone());
                break r;
            }
            let Some(row) = self.rows.get(&cur) else {
                self.warn_once(
                    &format!("row {cur}"),
                    format!(
                        "msi: the folder `{cur}` has no row in the Directory table; its files \
                         are listed under its key"
                    ),
                );
                let r = match side {
                    Side::Target => Res::Path {
                        path: fit(component(&cur)),
                        depth: 1,
                    },
                    Side::Source { .. } => Res::Cut { deep: false },
                };
                self.cache(side).insert(cur, r.clone());
                break r;
            };
            let parent = row.parent.as_deref().filter(|p| *p != cur);
            let Some(parent) = parent.map(str::to_owned) else {
                // A root: TARGETDIR (SourceDir) is the top itself, in the source image too.
                let r = match side {
                    Side::Target if cur != "TARGETDIR" => Res::Path {
                        path: fit(component(&cur)),
                        depth: 1,
                    },
                    _ => Res::Path {
                        path: String::new(),
                        depth: 0,
                    },
                };
                self.cache(side).insert(cur, r.clone());
                break r;
            };
            if !on_chain.insert(cur.clone()) {
                self.warn_once(
                    &format!("loop {cur}"),
                    format!(
                        "msi: the Directory table's parents loop at `{cur}`; the folders in the \
                         loop are listed under their keys"
                    ),
                );
                break Res::Cut { deep: false };
            }
            chain.push(cur);
            cur = parent;
        };
        // Down again, each adding its name.
        for k in chain.iter().rev() {
            let name = self.rows.get(k).map(|row| {
                let (target, source) = split_default_dir(&row.default_dir);
                match side {
                    Side::Target => long_name(target).to_owned(),
                    Side::Source { short: true } => short_name(source).to_owned(),
                    Side::Source { short: false } => long_name(source).to_owned(),
                }
            });
            let r = match (&base, name) {
                (Res::Cut { deep }, _) => Res::Cut { deep: *deep },
                (_, None) => Res::Cut { deep: false },
                (Res::Path { path, depth }, Some(name)) if name.is_empty() || name == "." => {
                    Res::Path {
                        path: path.clone(),
                        depth: *depth,
                    }
                }
                // The source image is never looked for outside the MSI's folder.
                (Res::Path { .. }, Some(name))
                    if matches!(side, Side::Source { .. })
                        && (name == ".." || name.contains(':')) =>
                {
                    Res::Cut { deep: false }
                }
                (Res::Path { path, depth }, Some(name)) => {
                    let path = join(path, &component(&name));
                    if *depth >= MAX_DEPTH || path.len() > MAX_PATH {
                        Res::Cut { deep: true }
                    } else {
                        self.count(path.len())?;
                        Res::Path {
                            path,
                            depth: depth + 1,
                        }
                    }
                }
            };
            self.cache(side).insert(k.clone(), r.clone());
            base = r;
        }
        Ok(base)
    }

    fn cache(&mut self, side: Side) -> &mut HashMap<String, Res> {
        match side {
            Side::Target => &mut self.target,
            Side::Source { .. } => &mut self.source,
        }
    }
}

/// A file's path in its folder `dir`: the long half of its FileName, or its File key when the
/// name is empty (wixl leaves non-ASCII names empty). One that would pass [`MAX_PATH`] takes
/// its key instead, and is cut short if even that is too long.
pub fn file_path(dir: &str, file_name: &str, key: &str) -> String {
    let leaf = match long_name(file_name) {
        "" => component(key),
        n => component(n),
    };
    let path = join(dir, &leaf);
    if path.len() <= MAX_PATH {
        return path;
    }
    fit(join(dir, &component(key)))
}

/// `dir/name.ext` → `dir/name.<key>.ext`, and `name` → `name.<key>`: a second file at a path.
/// A name's leading dot doesn't start an extension.
pub fn with_key(path: &str, key: &str) -> String {
    let (dir, leaf) = match path.rsplit_once('/') {
        Some((d, l)) => (Some(d), l),
        None => (None, path),
    };
    let leaf = match leaf.rfind('.') {
        Some(i) if i > 0 => format!("{}.{}{}", &leaf[..i], component(key), &leaf[i..]),
        _ => format!("{leaf}.{}", component(key)),
    };
    fit(match dir {
        Some(d) => format!("{d}/{leaf}"),
        None => leaf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(rows: &[(&str, Option<&str>, &str)], short: bool) -> Layout {
        let rows = rows
            .iter()
            .map(|(k, p, d)| {
                (
                    (*k).to_owned(),
                    DirRow {
                        parent: p.map(str::to_owned),
                        default_dir: (*d).to_owned(),
                    },
                )
            })
            .collect();
        Layout::new(rows, short)
    }

    #[test]
    fn folders_resolve_as_windows_installer_lays_them_out() {
        let mut l = layout(
            &[
                ("TARGETDIR", None, "SourceDir"),
                ("ProgramFiles64Folder", Some("TARGETDIR"), "PFiles64"),
                ("ProgramFiles6432Folder", Some("ProgramFiles64Folder"), "."),
                (
                    "APPDIR",
                    Some("ProgramFiles6432Folder"),
                    "RUSTDE~1|RustDesk",
                ),
                ("BIN", Some("APPDIR"), "bin:src_bin"),
                ("SAME", Some("APPDIR"), "."),
                // A standard folder under another restarts at the top.
                ("System64Folder", Some("APPDIR"), "sys"),
                ("System64Folder.DFEF_C2FE", Some("BIN"), "."),
                ("ROOT2", None, "Other"),
                ("DOTDOT", Some("APPDIR"), ".."),
                ("SLASH", Some("APPDIR"), "a/b\\c"),
            ],
            false,
        );
        let t = |l: &mut Layout, k: &str| l.target(k).unwrap();
        assert_eq!(t(&mut l, "TARGETDIR"), "");
        assert_eq!(t(&mut l, "APPDIR"), "ProgramFiles64Folder/RustDesk");
        assert_eq!(t(&mut l, "BIN"), "ProgramFiles64Folder/RustDesk/bin");
        assert_eq!(t(&mut l, "SAME"), "ProgramFiles64Folder/RustDesk");
        assert_eq!(t(&mut l, "System64Folder"), "System64Folder");
        assert_eq!(t(&mut l, "System64Folder.DFEF_C2FE"), "System64Folder");
        assert_eq!(t(&mut l, "ROOT2"), "ROOT2");
        assert_eq!(t(&mut l, "DOTDOT"), "ProgramFiles64Folder/RustDesk/..");
        assert_eq!(t(&mut l, "SLASH"), "ProgramFiles64Folder/RustDesk/a_b_c");
        assert_eq!(t(&mut l, "NOPE"), "NOPE");
        assert_eq!(l.warnings.len(), 1, "{:?}", l.warnings);

        // The source image: source halves, long names, every root at the MSI's folder.
        let s = |l: &mut Layout, k: &str| l.source(k).unwrap();
        assert_eq!(
            s(&mut l, "BIN").as_deref(),
            Some("PFiles64/RustDesk/src_bin")
        );
        assert_eq!(
            s(&mut l, "System64Folder").as_deref(),
            Some("PFiles64/RustDesk/sys")
        );
        assert_eq!(s(&mut l, "ROOT2").as_deref(), Some(""));
        assert_eq!(s(&mut l, "DOTDOT"), None, "never outside the MSI's folder");
        assert_eq!(s(&mut l, "NOPE"), None);

        let mut short = layout(
            &[
                ("TARGETDIR", None, "SourceDir"),
                ("A", Some("TARGETDIR"), "PROGRA~1|Program Files"),
                ("C", Some("A"), "x:C:\\evil"),
            ],
            true,
        );
        assert_eq!(short.source("A").unwrap().as_deref(), Some("PROGRA~1"));
        assert_eq!(short.source("C").unwrap(), None);
    }

    #[test]
    fn loops_and_depth_are_caught() {
        let mut rows = vec![
            ("TARGETDIR".to_owned(), None, "SourceDir".to_owned()),
            ("LOOPA".to_owned(), Some("LOOPB".to_owned()), "a".to_owned()),
            ("LOOPB".to_owned(), Some("LOOPA".to_owned()), "b".to_owned()),
            (
                "SELF".to_owned(),
                Some("SELF".to_owned()),
                "self".to_owned(),
            ),
        ];
        for i in 1..=3000 {
            let parent = if i == 1 {
                "TARGETDIR".to_owned()
            } else {
                format!("D{}", i - 1)
            };
            rows.push((format!("D{i}"), Some(parent), "n".repeat(10)));
        }
        let rows: Vec<(&str, Option<&str>, &str)> = rows
            .iter()
            .map(|(k, p, d)| (k.as_str(), p.as_deref(), d.as_str()))
            .collect();
        let mut l = layout(&rows, false);
        assert_eq!(l.target("LOOPA").unwrap(), "LOOPA");
        assert_eq!(l.target("LOOPB").unwrap(), "LOOPB");
        // A row that is its own parent is a root.
        assert_eq!(l.target("SELF").unwrap(), "SELF");
        assert_eq!(l.target("D64").unwrap().split('/').count(), 64);
        assert_eq!(l.target("D65").unwrap(), "D65");
        assert_eq!(l.target("D3000").unwrap(), "D3000");
        assert!(l.cut.contains(&"D3000".to_owned()));
        assert_eq!(l.source("D3000").unwrap(), None);

        // Long names are cut by length before depth.
        let long = "n".repeat(2000);
        let rows = [
            ("TARGETDIR", None, "SourceDir"),
            ("L1", Some("TARGETDIR"), long.as_str()),
            ("L2", Some("L1"), long.as_str()),
            ("L3", Some("L2"), long.as_str()),
        ];
        let mut l = layout(&rows, false);
        assert_eq!(l.target("L2").unwrap().len(), 4001);
        assert_eq!(l.target("L3").unwrap(), "L3");
    }

    #[test]
    fn file_names() {
        assert_eq!(
            file_path("A/B", "BEEZIP~1.EXE|beezip.exe", "f1"),
            "A/B/beezip.exe"
        );
        assert_eq!(file_path("", "readme.txt", "f1"), "readme.txt");
        assert_eq!(file_path("A", "", "cjk"), "A/cjk");
        assert_eq!(file_path("A", "..\\evil.txt", "k"), "A/.._evil.txt");
        let long = "x".repeat(5000);
        assert_eq!(file_path("A", &long, "key"), "A/key");
        assert_eq!(file_path("A", &long, &long).len(), MAX_PATH);

        assert_eq!(with_key("S/msvcp140.dll", "f_arm"), "S/msvcp140.f_arm.dll");
        assert_eq!(with_key("README", "k"), "README.k");
        assert_eq!(with_key("a.b/.gitignore", "k"), "a.b/.gitignore.k");
        assert_eq!(with_key("x.tar.gz", "k"), "x.tar.k.gz");
    }

    #[test]
    fn names_add_up_to_a_cap() {
        let mut l = layout(&[], false);
        l.count(usize::try_from(MAX_NAMES).unwrap()).unwrap();
        assert_eq!(
            l.count(1).unwrap_err().kind,
            crate::ErrorKind::LimitExceeded
        );
    }
}
