//! Editing (docs/M5.md §3, §10): add, remove and rename on every format BeeZip edits, checked
//! against a model of the archive; zip entries copied byte for byte; 7z blocks re-encoded only
//! where they change; tar's headers; the safe swap; the refusals; convert.
//! `PROPTEST_CASES` raises the model test's case count (default 12 per format).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use beezip_core::{
    AddOptions, ArchiveKind, CodecId, ConvertOptions, CreateOptions, Ctx, EditOp, EditOptions,
    EncodeOpts, Entry, EntryKind, EntrySink, ErrorKind, OpenOptions, OverwriteChoice,
    OverwritePolicy, Selection, SimpleCtx, WriteSpec,
    format::{
        sevenz::SevenZWriteOptions,
        zip::{ZipEncryption, ZipMethod, ZipReader, ZipWriteOptions},
    },
    open, ops,
};
use proptest::prelude::*;

const KINDS: [ArchiveKind; 5] = [
    ArchiveKind::Zip,
    ArchiveKind::SevenZ,
    ArchiveKind::Tar(None),
    ArchiveKind::Tar(Some(CodecId::Zstd)),
    ArchiveKind::Tar(Some(CodecId::Gzip)),
];

fn ext(kind: ArchiveKind) -> String {
    match kind {
        ArchiveKind::Zip => "zip".into(),
        ArchiveKind::SevenZ => "7z".into(),
        k => k.name(),
    }
}

fn spec(kind: ArchiveKind) -> WriteSpec {
    match kind {
        ArchiveKind::Zip => WriteSpec::Zip(ZipWriteOptions::default()),
        ArchiveKind::SevenZ => WriteSpec::SevenZ(SevenZWriteOptions::default()),
        ArchiveKind::Tar(codec) => WriteSpec::Tar {
            codec,
            opts: EncodeOpts::default(),
        },
    }
}

/// Writes `files` (path → data; a path ending in `/` is a folder) under `dir`.
fn tree(dir: &Path, files: &[(&str, &[u8])]) {
    for (p, data) in files {
        let path = dir.join(p);
        if p.ends_with('/') {
            fs::create_dir_all(&path).unwrap();
        } else {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, data).unwrap();
        }
    }
}

/// An archive of `kind` holding `src`'s contents at the top (each child under its own name).
fn create(archive: &Path, kind: ArchiveKind, src: &Path) {
    let inputs: Vec<PathBuf> = fs::read_dir(src)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    ops::create(
        archive,
        &inputs,
        &spec(kind),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
}

/// Collects every entry: files' data by path, and folders.
#[derive(Default)]
struct Collect {
    files: BTreeMap<String, Vec<u8>>,
    dirs: Vec<String>,
    links: BTreeMap<String, String>,
    hardlinks: BTreeMap<String, String>,
}

impl EntrySink for Collect {
    fn entry(
        &mut self,
        entry: &Entry,
        data: &mut dyn Read,
        _cx: &mut dyn Ctx,
    ) -> beezip_core::Result<()> {
        let path = beezip_core::format::normalize(&entry.path);
        match &entry.kind {
            EntryKind::Dir => self.dirs.push(path),
            EntryKind::Symlink { target } => {
                self.links.insert(path, target.clone());
            }
            EntryKind::Hardlink { target } => {
                self.hardlinks.insert(path, target.clone());
            }
            _ => {
                let mut b = Vec::new();
                data.read_to_end(&mut b).unwrap();
                self.files.insert(path, b);
            }
        }
        Ok(())
    }
}

fn read_with(archive: &Path, cx: &mut SimpleCtx) -> Collect {
    let mut opened = open(archive, &OpenOptions::default(), cx).unwrap();
    let mut c = Collect::default();
    opened
        .reader
        .extract(&Selection::all(), &mut c, cx)
        .unwrap();
    c.dirs.sort();
    c
}

fn read(archive: &Path) -> Collect {
    read_with(archive, &mut SimpleCtx::new())
}

fn files(archive: &Path) -> BTreeMap<String, Vec<u8>> {
    read(archive).files
}

/// 7-Zip, when it's installed (Windows CI has it; `BEEZIP_REQUIRE_7Z=1` makes it required).
fn seven_zip() -> Option<PathBuf> {
    let p = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
    if p.is_file() {
        return Some(p);
    }
    // Off Windows a `7z` on the PATH is often an old p7zip; the CLI's interop tests cover it.
    let on_path = cfg!(windows)
        && std::process::Command::new("7z")
            .arg("i")
            .output()
            .is_ok_and(|o| o.status.success());
    if on_path {
        return Some(PathBuf::from("7z"));
    }
    assert!(
        std::env::var("BEEZIP_REQUIRE_7Z").as_deref() != Ok("1"),
        "7-Zip is required (BEEZIP_REQUIRE_7Z=1) but wasn't found"
    );
    None
}

/// Our own test of every entry passes, and 7-Zip's `7z t` too where 7-Zip reads the format.
fn tests_clean(archive: &Path, cx: &mut SimpleCtx) {
    let report = ops::test(archive, &Selection::all(), &OpenOptions::default(), cx).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    seven_t(archive, cx.password.as_deref());
}

/// The formats `7z i` lists, lowercased.
fn seven_formats(exe: &Path) -> &'static std::collections::HashSet<String> {
    static FORMATS: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    FORMATS.get_or_init(|| {
        let out = std::process::Command::new(exe).arg("i").output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut found = std::collections::HashSet::new();
        let mut on = false;
        for line in text.lines() {
            if line.starts_with("Formats:") {
                on = true;
                continue;
            }
            if on && line.trim().is_empty() {
                break;
            }
            if on && let Some(n) = line.split_whitespace().skip(1).find(|t| !t.contains('.')) {
                found.insert(n.to_lowercase());
            }
        }
        found
    })
}

fn seven_t(archive: &Path, password: Option<&str>) {
    let Some(exe) = seven_zip() else { return };
    let ext = archive
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let needs = match ext.as_str() {
        "gz" => "gzip",
        "zst" => "zstd",
        "bz2" => "bzip2",
        other => other,
    };
    if !seven_formats(&exe).contains(needs) {
        eprintln!("7-Zip doesn't read {}; not tested", archive.display());
        return;
    }
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("t").arg(archive);
    cmd.arg(format!("-p{}", password.unwrap_or("")));
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "7z t {}: {}",
        archive.display(),
        String::from_utf8_lossy(&out.stdout)
    );
}

fn edit_with(
    archive: &Path,
    op: &EditOp,
    cx: &mut SimpleCtx,
) -> beezip_core::Result<beezip_core::EditReport> {
    ops::edit(
        archive,
        op,
        &mut |k| Ok(spec(k)),
        &EditOptions::default(),
        cx,
    )
}

fn edit(archive: &Path, op: &EditOp) -> beezip_core::Result<beezip_core::EditReport> {
    edit_with(archive, op, &mut SimpleCtx::new())
}

fn add(inputs: &[PathBuf], dir: &str, overwrite: OverwritePolicy) -> EditOp {
    EditOp::Add(AddOptions {
        inputs: inputs.to_vec(),
        dir: dir.into(),
        overwrite,
        ..AddOptions::default()
    })
}

fn remove(paths: &[&str]) -> EditOp {
    let paths: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
    EditOp::Remove(Selection::new(&paths, &[], &[]).unwrap())
}

fn rename(from: &str, to: &str) -> EditOp {
    EditOp::Rename {
        from: from.into(),
        to: to.into(),
    }
}

fn map(pairs: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    pairs
        .iter()
        .map(|(p, d)| ((*p).to_owned(), d.to_vec()))
        .collect()
}

#[test]
fn add_rename_remove_on_every_format() {
    for kind in KINDS {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        tree(
            &src,
            &[
                ("a.txt", b"alpha"),
                ("docs/b.txt", b"bravo"),
                ("docs/c.txt", &b"charlie ".repeat(500)),
                ("empty.txt", b""),
            ],
        );
        let archive = dir.path().join(format!("a.{}", ext(kind)));
        create(&archive, kind, &src);
        let incoming = dir.path().join("in");
        tree(&incoming, &[("new.txt", b"november")]);

        let r = edit(
            &archive,
            &add(&[incoming.join("new.txt")], "docs", OverwritePolicy::Never),
        )
        .unwrap();
        assert_eq!((r.added, r.entries), (1, 6), "{kind:?}");
        let mut want = map(&[
            ("a.txt", b"alpha"),
            ("docs/b.txt", b"bravo"),
            ("docs/c.txt", &b"charlie ".repeat(500)),
            ("empty.txt", b""),
            ("docs/new.txt", b"november"),
        ]);
        assert_eq!(files(&archive), want, "{kind:?} after add");
        tests_clean(&archive, &mut SimpleCtx::new());

        let r = edit(&archive, &rename("docs", "papers")).unwrap();
        assert_eq!(r.renamed, 4, "{kind:?}: the folder and its three files");
        want = want
            .into_iter()
            .map(|(k, v)| (k.replacen("docs/", "papers/", 1), v))
            .collect();
        assert_eq!(files(&archive), want, "{kind:?} after rename");
        assert_eq!(read(&archive).dirs, ["papers"], "{kind:?}");

        let r = edit(&archive, &remove(&["papers/b.txt", "a.txt"])).unwrap();
        assert_eq!(r.removed, 2, "{kind:?}");
        want.remove("papers/b.txt");
        want.remove("a.txt");
        assert_eq!(files(&archive), want, "{kind:?} after remove");
        tests_clean(&archive, &mut SimpleCtx::new());

        // Nothing left behind.
        let left: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".beezip-partial"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }
}

// ---- The model test (docs/M5.md §10): random trees and random scripts of edits. ----

/// One step of a script. Indexes pick among the archive's entries when the step runs.
#[derive(Debug, Clone)]
enum Step {
    Add {
        name: String,
        data: Vec<u8>,
        /// Which folder to add into: 0 is the top, else one of the folders.
        dir: usize,
    },
    Remove(usize),
    Rename(usize, String),
}

fn step() -> impl Strategy<Value = Step> {
    let name = r"[a-z][a-z0-9]{0,5}(\.txt)?";
    prop_oneof![
        3 => (name, proptest::collection::vec(any::<u8>(), 0..300), 0usize..8)
            .prop_map(|(name, data, dir)| Step::Add { name, data, dir }),
        2 => (0usize..64).prop_map(Step::Remove),
        2 => (0usize..64, name).prop_map(|(i, n)| Step::Rename(i, n)),
    ]
}

/// The model: files by path, and explicit folders.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Model {
    files: BTreeMap<String, Vec<u8>>,
    dirs: std::collections::BTreeSet<String>,
}

impl Model {
    fn of(c: &Collect) -> Self {
        Self {
            files: c.files.clone(),
            dirs: c.dirs.iter().cloned().collect(),
        }
    }

    /// Every path: folders (explicit, or parents of entries) and files, sorted.
    fn paths(&self) -> Vec<String> {
        let mut all: std::collections::BTreeSet<String> = self.dirs.clone();
        for p in self.files.keys().chain(self.dirs.iter()) {
            let mut at = 0;
            while let Some(i) = p[at..].find('/') {
                all.insert(p[..at + i].to_owned());
                at += i + 1;
            }
        }
        all.extend(self.files.keys().cloned());
        all.into_iter().collect()
    }

    fn folders(&self) -> Vec<String> {
        self.paths()
            .into_iter()
            .filter(|p| !self.files.contains_key(p))
            .collect()
    }

    fn under(p: &str, root: &str) -> bool {
        p == root || p.starts_with(&format!("{root}/"))
    }

    fn remove(&mut self, root: &str) {
        self.files.retain(|p, _| !Self::under(p, root));
        self.dirs.retain(|p| !Self::under(p, root));
    }

    fn rename(&mut self, from: &str, to: &str) {
        let mv = |p: &str| format!("{to}{}", &p[from.len()..]);
        self.files = std::mem::take(&mut self.files)
            .into_iter()
            .map(|(p, d)| {
                if Self::under(&p, from) {
                    (mv(&p), d)
                } else {
                    (p, d)
                }
            })
            .collect();
        self.dirs = std::mem::take(&mut self.dirs)
            .into_iter()
            .map(|p| if Self::under(&p, from) { mv(&p) } else { p })
            .collect();
    }
}

fn run_script(kind: ArchiveKind, files: &[(String, Vec<u8>)], steps: &[Step]) {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    let pairs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, d)| (p.as_str(), d.as_slice()))
        .collect();
    tree(&src, &pairs);
    let archive = dir.path().join(format!("m.{}", ext(kind)));
    create(&archive, kind, &src);
    let mut model = Model::of(&read(&archive));
    let incoming = dir.path().join("in");
    for (n, s) in steps.iter().enumerate() {
        let before = fs::read(&archive).unwrap();
        let paths = model.paths();
        let result = match s {
            Step::Add { name, data, dir: d } => {
                let folders = model.folders();
                let target = if *d == 0 || folders.is_empty() {
                    String::new()
                } else {
                    folders[(*d - 1) % folders.len()].clone()
                };
                let full = if target.is_empty() {
                    name.clone()
                } else {
                    format!("{target}/{name}")
                };
                // Adding a file where a folder is, or under a file, is refused.
                let clash = model.folders().contains(&full)
                    || model
                        .files
                        .keys()
                        .any(|f| full.starts_with(&format!("{f}/")));
                let _ = fs::remove_dir_all(&incoming);
                fs::create_dir_all(&incoming).unwrap();
                let file = incoming.join(name);
                fs::write(&file, data).unwrap();
                let r = edit(&archive, &add(&[file], &target, OverwritePolicy::Always));
                if clash {
                    assert_eq!(r.unwrap_err().kind, ErrorKind::Conflict, "step {n}: {s:?}");
                    None
                } else {
                    r.unwrap();
                    model.files.insert(full, data.clone());
                    Some(())
                }
            }
            Step::Remove(i) => {
                if paths.is_empty() {
                    continue;
                }
                let p = paths[i % paths.len()].clone();
                edit(&archive, &remove(&[&p])).unwrap();
                model.remove(&p);
                Some(())
            }
            Step::Rename(i, new) => {
                if paths.is_empty() {
                    continue;
                }
                let from = paths[i % paths.len()].clone();
                let parent = from.rfind('/').map_or("", |k| &from[..k]);
                let to = if parent.is_empty() {
                    new.clone()
                } else {
                    format!("{parent}/{new}")
                };
                let r = edit(&archive, &rename(&from, &to));
                let taken = model.paths().iter().any(|p| Model::under(p, &to))
                    || model.files.keys().any(|f| to.starts_with(&format!("{f}/")));
                if to == from {
                    assert_eq!(r.unwrap_err().kind, ErrorKind::InvalidArgs, "step {n}");
                    None
                } else if taken {
                    assert_eq!(r.unwrap_err().kind, ErrorKind::Conflict, "step {n}: {s:?}");
                    None
                } else {
                    r.unwrap();
                    model.rename(&from, &to);
                    Some(())
                }
            }
        };
        let got = read(&archive);
        if result.is_none() {
            assert_eq!(
                fs::read(&archive).unwrap(),
                before,
                "a refused step changed it"
            );
        }
        // Folders only implied by their files may or may not have entries.
        assert_eq!(got.files, model.files, "{kind:?}, step {n}: {s:?}");
        for d in &model.dirs {
            assert!(
                Model::of(&got).paths().contains(d),
                "{kind:?}, step {n}: {d} is gone"
            );
        }
    }
    tests_clean(&archive, &mut SimpleCtx::new());
}

fn initial() -> impl Strategy<Value = Vec<(String, Vec<u8>)>> {
    proptest::collection::btree_map(
        r"[a-z]{1,4}(/[a-z]{1,4}){0,2}\.txt",
        proptest::collection::vec(any::<u8>(), 0..400),
        1..8,
    )
    .prop_map(|m| {
        // A path can't be both a file and a folder.
        let keys: Vec<String> = m.keys().cloned().collect();
        m.into_iter()
            .filter(|(k, _)| !keys.iter().any(|o| o.starts_with(&format!("{k}/"))))
            .collect()
    })
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn edits_match_the_model(files in initial(), steps in proptest::collection::vec(step(), 1..6)) {
        for kind in KINDS {
            run_script(kind, &files, &steps);
        }
    }
}

// ---- Zip: kept entries byte for byte (docs/M5.md §3.3). ----

fn thirdparty(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty")
        .join(name)
}

/// A copy of a fixture in `dir`.
fn copy_fixture(dir: &Path, name: &str) -> PathBuf {
    let to = dir.join(name);
    fs::copy(thirdparty(name), &to).unwrap();
    to
}

fn norm(p: &str) -> String {
    beezip_core::format::normalize(p)
}

/// Each entry's span and central record (its offset field zeroed), by path.
fn zip_bytes(archive: &Path, cx: &mut SimpleCtx) -> BTreeMap<String, (Vec<u8>, Vec<u8>)> {
    let mut opened = open(archive, &OpenOptions::default(), cx).unwrap();
    let entries = opened.reader.entries(cx).unwrap().to_vec();
    let z = opened
        .reader
        .as_any_mut()
        .downcast_mut::<ZipReader>()
        .unwrap();
    entries
        .iter()
        .filter_map(|e| {
            let span = z.span_bytes(e.id).unwrap()?;
            let mut rec = z.central_record(e.id).unwrap();
            rec[42..46].fill(0);
            Some((e.path.clone(), (span, rec)))
        })
        .collect()
}

/// The zip fixtures an edit must keep byte for byte: M1's and M3's from 7-Zip, bsdtar and
/// .NET, and M5's descriptor, LZMA-with-ZipCrypto and Zip64 ones. The SFX isn't edited.
const ZIPS: [(&str, Option<&str>); 17] = [
    ("7z-copy.zip", None),
    ("7z-deflate.zip", None),
    ("7z-deflate64.zip", None),
    ("7z-bzip2.zip", None),
    ("7z-lzma.zip", None),
    ("7z-ppmd.zip", None),
    ("7z-aes256.zip", Some("beezip")),
    ("7z-zipcrypto.zip", Some("beezip")),
    ("7z-lzma-zipcrypto.zip", Some("beezip")),
    ("7z-descriptors.zip", None),
    ("7z-cp932.zip", None),
    ("bsdtar.zip", None),
    ("dotnet.zip", None),
    ("dotnet-cp932.zip", None),
    ("dotnet-cp936.zip", None),
    ("dotnet-cp866.zip", None),
    ("python-zip64.zip", None),
];

#[test]
fn zip_entries_are_copied_byte_for_byte() {
    for (name, pw) in ZIPS {
        let dir = tempfile::tempdir().unwrap();
        let archive = copy_fixture(dir.path(), name);
        let mut cx = match pw {
            Some(p) => SimpleCtx::new().with_password(p),
            None => SimpleCtx::new(),
        };
        let before = zip_bytes(&archive, &mut cx);
        let contents = read_with(&archive, &mut cx).files;
        assert!(!before.is_empty(), "{name}");

        // Adding: an encrypted archive's new file gets the password the context gives.
        let incoming = dir.path().join("in");
        tree(&incoming, &[("added by beezip.txt", b"added")]);
        let op = add(
            &[incoming.join("added by beezip.txt")],
            "",
            OverwritePolicy::Never,
        );
        let r = edit_with(&archive, &op, &mut cx).unwrap();
        assert_eq!(r.copied, before.len() as u64, "{name}");
        let after = zip_bytes(&archive, &mut cx);
        for (path, bytes) in &before {
            assert_eq!(after.get(path), Some(bytes), "{name}: {path} changed");
        }
        let mut want = contents.clone();
        want.insert("added by beezip.txt".into(), b"added".to_vec());
        assert_eq!(read_with(&archive, &mut cx).files, want, "{name}");
        tests_clean(&archive, &mut cx);

        // Removing the first, then renaming the last: the rest stay as they were.
        let first = before.keys().next().unwrap().clone();
        let last = before.keys().next_back().unwrap().clone();
        edit_with(&archive, &remove(&[&first]), &mut cx).unwrap();
        let renamed = format!("{}-renamed", norm(&last));
        let (fk, lk) = (norm(&first), norm(&last));
        let moved = !Model::under(&lk, &fk);
        if moved {
            edit_with(&archive, &rename(&last, &renamed), &mut cx).unwrap();
        }
        let after = zip_bytes(&archive, &mut cx);
        for (path, bytes) in &before {
            let p = norm(path);
            if !Model::under(&p, &fk) && !(moved && Model::under(&p, &lk)) {
                assert_eq!(after.get(path), Some(bytes), "{name}: {path} changed");
            }
        }
        let got = read_with(&archive, &mut cx).files;
        for (p, d) in &contents {
            if Model::under(p, &fk) {
                assert!(!got.contains_key(p), "{name}: {p} wasn't removed");
            } else if moved && Model::under(p, &lk) {
                let to = format!("{renamed}{}", &p[lk.len()..]);
                assert_eq!(got.get(&to), Some(d), "{name}: {p} to {to}");
            } else {
                assert_eq!(got.get(p), Some(d), "{name}: {p}");
            }
        }
        tests_clean(&archive, &mut cx);
    }
}

#[test]
fn a_renamed_zip_entry_gets_a_utf8_name() {
    let dir = tempfile::tempdir().unwrap();
    let archive = copy_fixture(dir.path(), "dotnet-cp932.zip");
    let mut cx = SimpleCtx::new();
    let names = OpenOptions::default().with_names(beezip_core::NameDecoding {
        encoding: beezip_core::NameEncoding::Cp932,
        ..beezip_core::NameDecoding::default()
    });
    let mut opened = open(&archive, &names, &mut cx).unwrap();
    let mut c = Collect::default();
    opened
        .reader
        .extract(&Selection::all(), &mut c, &mut cx)
        .unwrap();
    drop(opened);
    let (old, data) = c
        .files
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    ops::edit(
        &archive,
        &rename(&old, "名前/新しい.txt"),
        &mut |k| Ok(spec(k)),
        &EditOptions {
            open: names.clone(),
            dry_run: false,
        },
        &mut cx,
    )
    .unwrap();
    // Under "auto" (and any code page) the new name reads the same: it is UTF-8, flagged.
    assert_eq!(files(&archive).get("名前/新しい.txt"), Some(&data));
}

// ---- 7z: whole blocks copied, changed blocks encoded again (docs/M5.md §3.4). ----

fn seven_entries(archive: &Path, cx: &mut SimpleCtx) -> Vec<Entry> {
    let mut opened = open(archive, &OpenOptions::default(), cx).unwrap();
    opened.reader.entries(cx).unwrap().to_vec()
}

#[test]
fn a_7z_edit_encodes_again_only_the_blocks_it_changes() {
    let dir = tempfile::tempdir().unwrap();
    // Solid: one block of every file with data.
    let solid = copy_fixture(dir.path(), "7z-lzma.7z");
    let entries = seven_entries(&solid, &mut SimpleCtx::new());
    let with_data: Vec<&Entry> = entries.iter().filter(|e| e.size.unwrap_or(0) > 0).collect();
    let no_data = entries.len() - with_data.len();
    let contents = files(&solid);
    let victim = with_data[0].path.clone();
    let r = edit(&solid, &remove(&[&victim])).unwrap();
    assert_eq!(
        r.recompressed,
        with_data.len() as u64 - 1,
        "the block's other files"
    );
    assert_eq!(
        r.copied, no_data as u64,
        "entries without data, written again"
    );
    let mut want = contents.clone();
    want.remove(&norm(&victim));
    assert_eq!(files(&solid), want);
    tests_clean(&solid, &mut SimpleCtx::new());
    // A rename copies the (new) block as it is.
    let r = edit(&solid, &rename(&with_data[1].path, "moved.bin")).unwrap();
    assert_eq!((r.copied, r.recompressed), ((entries.len() - 1) as u64, 0));
    tests_clean(&solid, &mut SimpleCtx::new());

    // Non-solid: a block per file, so a removal copies every other block.
    let plain = copy_fixture(dir.path(), "7z-nonsolid.7z");
    let entries = seven_entries(&plain, &mut SimpleCtx::new());
    let victim = entries
        .iter()
        .find(|e| e.size.unwrap_or(0) > 0)
        .unwrap()
        .path
        .clone();
    let r = edit(&plain, &remove(&[&victim])).unwrap();
    assert_eq!((r.copied, r.recompressed), ((entries.len() - 1) as u64, 0));
    tests_clean(&plain, &mut SimpleCtx::new());
}

#[test]
fn renames_over_7zips_fixtures_copy_every_block() {
    for name in [
        "7z-bcj.7z",
        "7z-bcj2.7z",
        "7z-arm64.7z",
        "7z-delta.7z",
        "7z-ppmd.7z",
        "7z-lzma2-mt.7z",
        "7z-empties.7z",
        "7z-links.7z",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let archive = copy_fixture(dir.path(), name);
        let before = read(&archive);
        let entries = seven_entries(&archive, &mut SimpleCtx::new());
        let top = norm(&entries[0].path);
        let top = top.split('/').next().unwrap().to_owned();
        let r = edit(&archive, &rename(&top, "renamed")).unwrap();
        assert_eq!(
            (r.copied, r.recompressed),
            (entries.len() as u64, 0),
            "{name}"
        );
        let after = read(&archive);
        let mv = |p: &String| format!("renamed{}", &p[top.len()..]);
        let want: BTreeMap<String, Vec<u8>> = before
            .files
            .iter()
            .map(|(k, v)| (mv(k), v.clone()))
            .collect();
        assert_eq!(after.files, want, "{name}");
        let links: BTreeMap<String, String> = before
            .links
            .iter()
            .map(|(k, v)| (mv(k), v.clone()))
            .collect();
        assert_eq!(after.links, links, "{name}");
        tests_clean(&archive, &mut SimpleCtx::new());
    }
}

#[test]
fn encrypted_7z_blocks_and_names_stay_encrypted() {
    for name in ["7z-aes.7z", "7z-aes-mhe.7z"] {
        let dir = tempfile::tempdir().unwrap();
        let archive = copy_fixture(dir.path(), name);
        let mut cx = SimpleCtx::new().with_password("beezip");
        let contents = read_with(&archive, &mut cx).files;
        let entries = seven_entries(&archive, &mut cx);
        let data: Vec<&Entry> = entries.iter().filter(|e| e.size.unwrap_or(0) > 0).collect();
        let victim = data[0].path.clone();
        // Removing one encodes its block again, encrypted with the password that decoded it.
        edit_with(&archive, &remove(&[&victim]), &mut cx).unwrap();
        let mut opened = open(&archive, &OpenOptions::default(), &mut cx).unwrap();
        let info = opened.reader.info(&mut cx).unwrap();
        assert_eq!(info.encryption, beezip_core::Encryption::All, "{name}");
        assert_eq!(info.encrypted_headers, name.contains("mhe"), "{name}");
        drop(opened);
        if name.contains("mhe") {
            let err = open(&archive, &OpenOptions::default(), &mut SimpleCtx::new())
                .err()
                .unwrap();
            assert_eq!(
                err.kind,
                ErrorKind::PasswordRequired,
                "{name}: names readable"
            );
        }
        let mut want = contents.clone();
        want.remove(&norm(&victim));
        assert_eq!(read_with(&archive, &mut cx).files, want, "{name}");
        tests_clean(&archive, &mut cx);
        // A wrong password for a block that must be decoded: refused, and nothing changes.
        if !name.contains("mhe") {
            let before = fs::read(&archive).unwrap();
            let mut wrong = SimpleCtx::new().with_password("nope");
            let err = edit_with(&archive, &remove(&[&data[1].path]), &mut wrong).unwrap_err();
            assert_eq!(err.kind, ErrorKind::WrongPassword, "{name}");
            assert_eq!(fs::read(&archive).unwrap(), before);
        }
    }
}

// ---- Encryption is never dropped (docs/M5.md §3.7). ----

#[test]
fn adding_to_an_encrypted_archive_asks_for_the_new_files_password() {
    for name in ["7z-aes256.zip", "7z-aes.7z"] {
        let dir = tempfile::tempdir().unwrap();
        let archive = copy_fixture(dir.path(), name);
        let incoming = dir.path().join("in");
        tree(&incoming, &[("new.txt", b"new")]);
        let op = add(&[incoming.join("new.txt")], "", OverwritePolicy::Never);
        // Nobody to ask.
        let err = edit(&archive, &op).unwrap_err();
        assert_eq!(err.kind, ErrorKind::PasswordRequired, "{name}");
        // With one, the new file is encrypted.
        let mut cx = SimpleCtx::new().with_password("beezip");
        let r = edit_with(&archive, &op, &mut cx).unwrap();
        assert_eq!(r.unencrypted, 0);
        let mut opened = open(&archive, &OpenOptions::default(), &mut cx).unwrap();
        let e = opened
            .reader
            .entries(&mut cx)
            .unwrap()
            .iter()
            .find(|e| e.path == "new.txt")
            .cloned()
            .unwrap();
        assert!(e.encrypted, "{name}");
        drop(opened);
        tests_clean(&archive, &mut cx);
        // `unencrypted` adds it in the clear, and says so.
        tree(&incoming, &[("plain.txt", b"plain")]);
        let op = EditOp::Add(AddOptions {
            inputs: vec![incoming.join("plain.txt")],
            unencrypted: true,
            ..AddOptions::default()
        });
        let r = edit_with(&archive, &op, &mut SimpleCtx::new()).unwrap();
        assert_eq!(r.unencrypted, 1, "{name}");
        let got = read_with(&archive, &mut cx).files;
        assert_eq!(got.get("plain.txt").map(Vec::as_slice), Some(&b"plain"[..]));
    }
}

// ---- Tar: headers kept, renamed through pax, links followed (docs/M5.md §3.5). ----

/// Each entry's headers as stored (every block from its first extension record to its data),
/// by path, read with the tar crate in raw mode.
fn tar_headers(archive: &Path) -> BTreeMap<String, Vec<u8>> {
    let bytes = fs::read(archive).unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);
    let mut out = BTreeMap::new();
    let mut start = 0usize;
    for e in ar.entries().unwrap() {
        let e = e.unwrap();
        let data = e.raw_file_position() as usize;
        let size = e.header().entry_size().unwrap() as usize;
        let name = String::from_utf8_lossy(&e.path_bytes()).into_owned();
        out.insert(name, bytes[start..data].to_vec());
        start = data + size.div_ceil(512) * 512;
    }
    out
}

#[test]
fn tar_edits_keep_headers_and_rename_through_pax() {
    let long = "links/deep/directory-with-a-long-name-0123456789/another-long-directory-name-abcdefghij/file-with-a-long-name-past-100-characters.txt";
    for name in ["gnutar-pax.tar", "gnutar-gnu.tar", "gnutar-ustar.tar"] {
        let dir = tempfile::tempdir().unwrap();
        let archive = copy_fixture(dir.path(), name);
        let before = read(&archive);
        let heads = tar_headers(&archive);
        let to = format!("links/renamed/{}-ünïcödé-{}.txt", "x".repeat(90), name);
        edit(&archive, &rename(long, &to)).unwrap();
        let after = read(&archive);
        assert_eq!(after.files.get(&to), before.files.get(long), "{name}");
        assert!(!after.files.contains_key(long), "{name}");
        // Every other entry's headers are as they were.
        let now = tar_headers(&archive);
        for (p, h) in &heads {
            if !p.ends_with("past-100-characters.txt") {
                assert_eq!(now.get(p), Some(h), "{name}: {p}");
            }
        }
        // The mtime survives the rename (pax keeps it, with any fraction).
        let times = |a: &Path| -> BTreeMap<String, Option<std::time::SystemTime>> {
            let mut o = open(a, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
            o.reader
                .entries(&mut SimpleCtx::new())
                .unwrap()
                .iter()
                .map(|e| (norm(&e.path), e.modified))
                .collect()
        };
        let (t0, t1) = (times(&thirdparty(name)), times(&archive));
        assert_eq!(t1.get(&to), t0.get(long), "{name}");
        tests_clean(&archive, &mut SimpleCtx::new());
    }
}

#[test]
fn tar_hard_links_follow_their_target_and_keep_it() {
    let dir = tempfile::tempdir().unwrap();
    let archive = copy_fixture(dir.path(), "gnutar-gnu.tar");
    let hello = files(&archive)["links/hard-hello"].clone();
    // links/hello.txt is a hard link to links/hard-hello: removing the target alone is refused.
    let before = fs::read(&archive).unwrap();
    let err = edit(&archive, &remove(&["links/hard-hello"])).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert!(err.message.contains("links/hello.txt"), "{}", err.message);
    assert_eq!(fs::read(&archive).unwrap(), before);
    // Renaming the target renames it in the link.
    edit(&archive, &rename("links/hard-hello", "links/target.txt")).unwrap();
    let mut opened = open(&archive, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
    let entries = opened
        .reader
        .entries(&mut SimpleCtx::new())
        .unwrap()
        .to_vec();
    let link = entries
        .iter()
        .find(|e| e.path == "links/hello.txt")
        .unwrap();
    assert_eq!(
        link.kind,
        EntryKind::Hardlink {
            target: "links/target.txt".into()
        }
    );
    let mut data = Vec::new();
    opened
        .reader
        .open_entry(link.id, &mut SimpleCtx::new())
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, hello);
    drop(opened);
    tests_clean(&archive, &mut SimpleCtx::new());
    // Removing both is fine.
    edit(&archive, &remove(&["links/target.txt", "links/hello.txt"])).unwrap();
    assert!(!files(&archive).contains_key("links/hello.txt"));
}

/// A GNU tar header block with `name`, type `kind` and `size` bytes stored.
fn gnu_header(name: &str, kind: u8, size: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"15000000000\0");
    h[156] = kind;
    h[257..265].copy_from_slice(b"ustar  \0");
    h
}

fn checksum(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

/// A tar with a global pax header, a GNU sparse file whose map needs an extension block, and
/// two plain files; and the sparse file's expanded contents.
fn special_tar() -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::new();
    // A global pax header.
    let records = b"20 comment=beezip!\n";
    let mut g = gnu_header("pax_global_header", b'g', records.len() as u64);
    g[257..265].copy_from_slice(b"ustar\x0000");
    checksum(&mut g);
    out.extend_from_slice(&g);
    let mut data = records.to_vec();
    data.resize(512, 0);
    out.extend_from_slice(&data);
    // A sparse file: five 512-byte regions, 4 KiB apart; the fifth is in an extension block.
    let regions: Vec<u64> = (0..5).map(|i| i * 4096).collect();
    let real = 4 * 4096 + 512;
    let mut s = gnu_header("sparse.bin", b'S', 5 * 512);
    for (i, off) in regions.iter().take(4).enumerate() {
        let at = 386 + i * 24;
        s[at..at + 12].copy_from_slice(format!("{off:011o}\0").as_bytes());
        s[at + 12..at + 24].copy_from_slice(format!("{:011o}\0", 512).as_bytes());
    }
    s[482] = 1;
    s[483..495].copy_from_slice(format!("{real:011o}\0").as_bytes());
    checksum(&mut s);
    out.extend_from_slice(&s);
    let mut ext = [0u8; 512];
    ext[..12].copy_from_slice(format!("{:011o}\0", regions[4]).as_bytes());
    ext[12..24].copy_from_slice(format!("{:011o}\0", 512).as_bytes());
    out.extend_from_slice(&ext);
    let mut expanded = vec![0u8; real as usize];
    for (i, off) in regions.iter().enumerate() {
        let block = vec![b'a' + i as u8; 512];
        out.extend_from_slice(&block);
        expanded[*off as usize..*off as usize + 512].copy_from_slice(&block);
    }
    for (n, body) in [("one.txt", &b"one"[..]), ("two.txt", &b"two"[..])] {
        let mut h = gnu_header(n, b'0', body.len() as u64);
        checksum(&mut h);
        out.extend_from_slice(&h);
        let mut d = body.to_vec();
        d.resize(512, 0);
        out.extend_from_slice(&d);
    }
    out.extend_from_slice(&[0u8; 1024]);
    (out, expanded)
}

#[test]
fn tar_global_headers_and_gnu_sparse_files_are_kept() {
    let (bytes, expanded) = special_tar();
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("special.tar");
    fs::write(&archive, &bytes).unwrap();
    assert_eq!(files(&archive)["sparse.bin"], expanded);
    // Removing a file keeps the global header (first) and the sparse file's map blocks.
    edit(&archive, &remove(&["one.txt"])).unwrap();
    let now = fs::read(&archive).unwrap();
    let kept = 512 * 2 + 512 * 2 + 5 * 512;
    let first_diff = (0..kept).find(|&i| now.get(i) != bytes.get(i));
    assert_eq!(
        first_diff, None,
        "the global header and the sparse file are kept"
    );
    assert_eq!(files(&archive)["sparse.bin"], expanded);
    // Renaming the sparse file keeps its map and data.
    edit(&archive, &rename("sparse.bin", "holes/sparse.bin")).unwrap();
    let got = files(&archive);
    assert_eq!(got["holes/sparse.bin"], expanded);
    assert_eq!(got["two.txt"], b"two");
    assert_eq!(
        &fs::read(&archive).unwrap()[..1024],
        &bytes[..1024],
        "the global header"
    );
}

// ---- The safe swap (docs/M5.md §3.1, §3.8). ----

fn partials(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".beezip-partial"))
        .collect()
}

/// Cancels after `limit` checks; `touch` changes the archive at that point instead.
struct Stopper {
    calls: std::cell::Cell<u64>,
    limit: u64,
    touch: Option<PathBuf>,
}

impl Ctx for Stopper {
    fn is_cancelled(&self) -> bool {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        if n == self.limit
            && let Some(p) = &self.touch
        {
            let mut f = fs::OpenOptions::new().append(true).open(p).unwrap();
            std::io::Write::write_all(&mut f, b"x").unwrap();
            return false;
        }
        self.touch.is_none() && n >= self.limit
    }

    fn progress(&mut self, _: &beezip_core::Progress) {}

    fn warn(&mut self, _: String) {}

    fn password(&mut self, _: Option<&str>, _: u32) -> beezip_core::Result<String> {
        Err(beezip_core::Error::new(ErrorKind::PasswordRequired, "none"))
    }

    fn overwrite(&mut self, _: &Path) -> beezip_core::Result<OverwriteChoice> {
        Ok(OverwriteChoice::Replace)
    }
}

#[test]
fn cancelling_at_any_point_leaves_the_archive_as_it_was() {
    for kind in [
        ArchiveKind::Zip,
        ArchiveKind::SevenZ,
        ArchiveKind::Tar(Some(CodecId::Zstd)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        tree(
            &src,
            &[
                ("a.txt", &b"a".repeat(300_000)),
                ("b/c.txt", b"c"),
                ("d.txt", b"d"),
            ],
        );
        let archive = dir.path().join(format!("x.{}", ext(kind)));
        create(&archive, kind, &src);
        let incoming = dir.path().join("in");
        tree(&incoming, &[("new.bin", &vec![7u8; 600_000])]);
        let original = fs::read(&archive).unwrap();
        let op = add(&[incoming.join("new.bin")], "b", OverwritePolicy::Always);
        let mut limit = 1;
        loop {
            let mut cx = Stopper {
                calls: 0.into(),
                limit,
                touch: None,
            };
            let r = ops::edit(
                &archive,
                &op,
                &mut |k| Ok(spec(k)),
                &EditOptions::default(),
                &mut cx,
            );
            assert!(partials(dir.path()).is_empty(), "{kind:?} at {limit}");
            match r {
                Err(e) => {
                    assert_eq!(e.kind, ErrorKind::Cancelled, "{kind:?} at {limit}: {e}");
                    assert_eq!(fs::read(&archive).unwrap(), original, "{kind:?} at {limit}");
                }
                Ok(_) => break,
            }
            limit += 1;
            assert!(limit < 10_000, "{kind:?} never finished");
        }
        assert!(limit > 3, "{kind:?}: cancelled at only {limit} points");
        assert!(files(&archive).contains_key("b/new.bin"));
    }
}

#[test]
fn an_archive_changed_meanwhile_is_a_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"a"), ("b.txt", b"b")]);
    let archive = dir.path().join("x.zip");
    create(&archive, ArchiveKind::Zip, &src);
    let mut cx = Stopper {
        calls: 0.into(),
        limit: 2,
        touch: Some(archive.clone()),
    };
    let before = fs::read(&archive).unwrap();
    let r = ops::edit(
        &archive,
        &remove(&["a.txt"]),
        &mut |k| Ok(spec(k)),
        &EditOptions::default(),
        &mut cx,
    );
    let e = r.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Conflict, "{e}");
    assert!(
        e.message.contains("changed while BeeZip was editing it"),
        "{e}"
    );
    assert!(partials(dir.path()).is_empty());
    // The other program's write is what's there.
    let mut want = before;
    want.push(b'x');
    assert_eq!(fs::read(&archive).unwrap(), want);
}

#[test]
fn a_read_only_archive_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"a")]);
    let archive = dir.path().join("x.zip");
    create(&archive, ArchiveKind::Zip, &src);
    let mut perms = fs::metadata(&archive).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&archive, perms.clone()).unwrap();
    let e = edit(&archive, &remove(&["a.txt"])).unwrap_err();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&archive, perms).unwrap();
    assert_eq!(e.kind, ErrorKind::Io);
    assert_eq!(e.message, "x.zip is read-only; nothing was changed");
}

#[cfg(windows)]
#[test]
fn a_swap_keeps_the_mark_of_the_web_attributes_and_creation_time() {
    use std::os::windows::fs::{FileTimesExt, MetadataExt};
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"a"), ("b.txt", b"b")]);
    let archive = dir.path().join("x.zip");
    create(&archive, ArchiveKind::Zip, &src);
    let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n";
    beezip_core::safefs::motw::write_zone(&archive, zone).unwrap();
    let created = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_500_000_000);
    fs::File::options()
        .write(true)
        .open(&archive)
        .unwrap()
        .set_times(fs::FileTimes::new().set_created(created))
        .unwrap();
    let status = std::process::Command::new("attrib")
        .arg("+h")
        .arg(&archive)
        .status()
        .unwrap();
    assert!(status.success());
    edit(&archive, &remove(&["a.txt"])).unwrap();
    let meta = fs::metadata(&archive).unwrap();
    assert_eq!(meta.file_attributes() & 0x2, 0x2, "hidden");
    assert_eq!(meta.created().unwrap(), created);
    assert_eq!(
        beezip_core::safefs::motw::read_zone(&archive).as_deref(),
        Some(&zone[..])
    );
    assert_eq!(files(&archive).keys().collect::<Vec<_>>(), ["b.txt"]);
}

#[test]
fn an_archive_reached_through_a_symlink_is_edited_at_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"a"), ("b.txt", b"b")]);
    let real = dir.path().join("real.zip");
    create(&real, ArchiveKind::Zip, &src);
    let link = dir.path().join("link.zip");
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&real, &link);
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&real, &link);
    if made.is_err() {
        eprintln!("skipping: symlinks need Developer Mode or an elevated shell");
        return;
    }
    edit(&link, &remove(&["a.txt"])).unwrap();
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(files(&real).keys().collect::<Vec<_>>(), ["b.txt"]);
}

#[cfg(windows)]
#[test]
fn an_archive_another_program_holds_open_is_refused_after_a_wait() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"a"), ("b.txt", b"b")]);
    let archive = dir.path().join("x.zip");
    create(&archive, ArchiveKind::Zip, &src);
    let before = fs::read(&archive).unwrap();
    // FILE_SHARE_READ only: the rename can't replace it.
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&archive)
        .unwrap();
    let t = std::time::Instant::now();
    let e = edit(&archive, &remove(&["a.txt"])).unwrap_err();
    assert!(
        t.elapsed() >= std::time::Duration::from_millis(1900),
        "{:?}",
        t.elapsed()
    );
    drop(held);
    assert_eq!(e.kind, ErrorKind::Io);
    assert_eq!(
        e.message,
        "x.zip is open in another program; nothing was changed"
    );
    assert_eq!(fs::read(&archive).unwrap(), before);
    assert!(partials(dir.path()).is_empty());
}

// ---- Refusals (docs/M5.md §3.7). ----

#[test]
fn split_sfx_rar_and_read_only_formats_are_refused() {
    let cases = [
        ("7z-split.7z.001", "split into volumes"),
        ("7z-sfx.exe", "self-extracting"),
        ("7z-7zsfx.exe", "self-extracting"),
        ("rars/ext_time_rar420.rar", "RAR"),
        ("7z-readme.md.gz", "compressed file"),
    ];
    for (name, why) in cases {
        let e = edit(&thirdparty(name), &remove(&["anything"])).unwrap_err();
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{name}: {e}");
        assert!(e.message.contains(why), "{name}: {e}");
    }
}

#[test]
fn a_zip_with_two_entries_of_one_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("aa.txt", b"1"), ("ab.txt", b"2")]);
    let archive = dir.path().join("dup.zip");
    create(&archive, ArchiveKind::Zip, &src);
    // Names aren't in any checksum: patch the second into the first.
    let mut b = fs::read(&archive).unwrap();
    let mut i = 0;
    while let Some(at) = b[i..].windows(6).position(|w| w == b"ab.txt") {
        b[i + at + 1] = b'a';
        i += at + 6;
    }
    fs::write(&archive, &b).unwrap();
    let e = edit(&archive, &remove(&["aa.txt"])).unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    assert!(e.message.contains("same name"), "{e}");
}

// ---- Adding over existing entries (docs/M5.md §7.1). ----

#[test]
fn adding_over_an_entry_follows_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"old"), ("docs/b.txt", b"b")]);
    let archive = dir.path().join("x.zip");
    create(&archive, ArchiveKind::Zip, &src);
    let incoming = dir.path().join("in");
    tree(&incoming, &[("a.txt", b"new")]);
    let file = incoming.join("a.txt");
    // Never: skipped, and nothing written.
    let before = fs::read(&archive).unwrap();
    let r = edit(
        &archive,
        &add(std::slice::from_ref(&file), "", OverwritePolicy::Never),
    )
    .unwrap();
    assert_eq!((r.added, r.skipped), (0, 1));
    assert_eq!(fs::read(&archive).unwrap(), before);
    // Newer: the file is older than the entry, so skipped.
    filetime::set_file_mtime(&file, filetime::FileTime::from_unix_time(1_000_000_000, 0)).unwrap();
    let r = edit(
        &archive,
        &add(std::slice::from_ref(&file), "", OverwritePolicy::Newer),
    )
    .unwrap();
    assert_eq!(r.skipped, 1);
    // Rename: added beside it.
    let r = edit(
        &archive,
        &add(std::slice::from_ref(&file), "", OverwritePolicy::Rename),
    )
    .unwrap();
    assert_eq!(r.added, 1);
    assert_eq!(files(&archive)["a (1).txt"], b"new");
    // Ask: the context says replace (ignoring case on Windows).
    let mut cx = SimpleCtx::new().with_overwrite(OverwriteChoice::Replace);
    let upper = incoming.join("A.TXT");
    fs::rename(&file, &upper).unwrap();
    let r = edit_with(&archive, &add(&[upper], "", OverwritePolicy::Ask), &mut cx).unwrap();
    if cfg!(windows) {
        assert_eq!(r.replaced, 1);
        assert!(!files(&archive).contains_key("a.txt"));
        assert_eq!(files(&archive)["A.TXT"], b"new");
    } else {
        assert_eq!(r.added, 1);
    }
    // A file where the archive has a folder is a conflict.
    tree(&incoming, &[("docs", b"not a folder")]);
    let e = edit(
        &archive,
        &add(&[incoming.join("docs")], "", OverwritePolicy::Always),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Conflict, "{e}");
}

#[test]
fn a_dry_run_changes_nothing_and_says_what_would_change() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"a"), ("docs/b.txt", b"b")]);
    let archive = dir.path().join("x.7z");
    create(&archive, ArchiveKind::SevenZ, &src);
    let before = fs::read(&archive).unwrap();
    let opts = EditOptions {
        dry_run: true,
        ..EditOptions::default()
    };
    let r = ops::edit(
        &archive,
        &rename("docs", "papers"),
        &mut |k| Ok(spec(k)),
        &opts,
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(r.dry_run);
    assert_eq!(r.renamed, 2);
    let plan: Vec<(beezip_core::Action, &str, Option<&str>)> = r
        .plan
        .iter()
        .map(|c| (c.action, c.path.as_str(), c.from.as_deref()))
        .collect();
    assert!(
        plan.contains(&(
            beezip_core::Action::Rename,
            "papers/b.txt",
            Some("docs/b.txt")
        )),
        "{plan:?}"
    );
    assert_eq!(fs::read(&archive).unwrap(), before);
    // Checks still apply.
    let e = ops::edit(
        &archive,
        &rename("docs", "a.txt"),
        &mut |k| Ok(spec(k)),
        &opts,
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Conflict);
    let e = ops::edit(
        &archive,
        &remove(&["nope"]),
        &mut |k| Ok(spec(k)),
        &opts,
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::NotFound);
    assert_eq!(e.message, "nothing in x.7z matches");
}

// ---- Convert (docs/M5.md §7.5). ----

fn convert(
    source: &Path,
    output: &Path,
    kind: ArchiveKind,
    spec: &WriteSpec,
    opts: &ConvertOptions,
    cx: &mut SimpleCtx,
) -> beezip_core::Result<beezip_core::ConvertReport> {
    ops::convert(
        source,
        output,
        kind,
        spec,
        opts,
        &OpenOptions::default(),
        cx,
    )
}

#[test]
fn convert_copies_what_it_can_and_decodes_the_rest() {
    let raw = ConvertOptions {
        raw: true,
        ..ConvertOptions::default()
    };
    let dir = tempfile::tempdir().unwrap();
    for (src, kind, copied) in [
        ("7z-deflate.zip", ArchiveKind::Zip, true),
        ("7z-deflate.zip", ArchiveKind::SevenZ, false),
        (
            "7z-deflate.zip",
            ArchiveKind::Tar(Some(CodecId::Zstd)),
            false,
        ),
        ("7z-lzma.7z", ArchiveKind::Zip, false),
        ("7z-lzma.7z", ArchiveKind::SevenZ, true),
        (
            "bsdtar.tar.gz",
            ArchiveKind::Tar(Some(CodecId::Zstd)),
            false,
        ),
        ("gnutar-pax.tar", ArchiveKind::Tar(None), true),
        ("gnutar-pax.tar", ArchiveKind::SevenZ, false),
    ] {
        let source = thirdparty(src);
        let out = dir.path().join(format!("{src}.{}", ext(kind)));
        let r = convert(
            &source,
            &out,
            kind,
            &spec(kind),
            &raw,
            &mut SimpleCtx::new(),
        )
        .unwrap();
        let src_all = read(&source);
        let want = src_all.files.clone();
        let mut got = files(&out);
        // Formats without hard links get them as files with their target's data.
        for (link, target) in &src_all.hardlinks {
            if let Some(data) = got.remove(link) {
                assert_eq!(
                    Some(&data),
                    want.get(&norm(target)),
                    "{src} to {kind:?}: {link}"
                );
            }
        }
        let diff: Vec<(&String, usize, Option<usize>)> = want
            .iter()
            .filter(|(k, v)| got.get(*k) != Some(*v))
            .map(|(k, v)| (k, v.len(), got.get(k).map(Vec::len)))
            .collect();
        assert!(
            diff.is_empty(),
            "{src} to {kind:?}: {diff:?} (got {:?})",
            got.keys().collect::<Vec<_>>()
        );
        let n = r.copied + r.recompressed;
        assert!(n > 0, "{src} to {kind:?}");
        if copied {
            assert_eq!(r.recompressed, 0, "{src} to {kind:?}");
        } else {
            assert_eq!(r.copied, 0, "{src} to {kind:?}");
        }
        tests_clean(&out, &mut SimpleCtx::new());
    }
}

#[test]
fn convert_never_drops_encryption_silently() {
    let dir = tempfile::tempdir().unwrap();
    let source = thirdparty("7z-aes256.zip");
    let out = dir.path().join("out.tar");
    let kind = ArchiveKind::Tar(None);
    let mut cx = SimpleCtx::new().with_password("beezip");
    let e = convert(
        &source,
        &out,
        kind,
        &spec(kind),
        &ConvertOptions::default(),
        &mut cx,
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidArgs);
    assert!(e.message.contains("decrypt"), "{e}");
    let decrypt = ConvertOptions {
        decrypt: true,
        ..ConvertOptions::default()
    };
    convert(&source, &out, kind, &spec(kind), &decrypt, &mut cx).unwrap();
    let want = read_with(&source, &mut cx).files;
    assert_eq!(files(&out), want);
    // Into a 7z with a new password.
    let out7 = dir.path().join("out.7z");
    let o = SevenZWriteOptions {
        password: Some("other".into()),
        ..SevenZWriteOptions::default()
    };
    let r = convert(
        &source,
        &out7,
        ArchiveKind::SevenZ,
        &WriteSpec::SevenZ(o),
        &ConvertOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert!(r.files > 0);
    assert_eq!(
        read_with(&out7, &mut SimpleCtx::new().with_password("other")).files,
        want
    );
    // A raw copy keeps the source's encryption, and needs no password at all.
    let outz = dir.path().join("copy.zip");
    let raw = ConvertOptions {
        raw: true,
        ..ConvertOptions::default()
    };
    let z = WriteSpec::Zip(ZipWriteOptions {
        method: ZipMethod::Deflate,
        encryption: ZipEncryption::Aes256,
        ..ZipWriteOptions::default()
    });
    let r = convert(
        &source,
        &outz,
        ArchiveKind::Zip,
        &z,
        &raw,
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(r.recompressed, 0);
    assert_eq!(read_with(&outz, &mut cx).files, want);
    // The output can't be the source, or a file that's there.
    let e = convert(&outz, &outz, ArchiveKind::Zip, &z, &raw, &mut cx).unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidArgs);
    let e = convert(&source, &outz, ArchiveKind::Zip, &z, &raw, &mut cx).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Conflict);
}

#[test]
fn converting_hard_links_to_zip_makes_them_files() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("links.zip");
    let r = convert(
        &thirdparty("gnutar-gnu.tar"),
        &out,
        ArchiveKind::Zip,
        &spec(ArchiveKind::Zip),
        &ConvertOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let got = files(&out);
    assert_eq!(got["links/hello.txt"], got["links/hard-hello"]);
    assert!(!got["links/hello.txt"].is_empty());
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    assert_eq!(
        read(&out)
            .links
            .get("links/link-to-hello")
            .map(String::as_str),
        Some("hello.txt")
    );
}

#[test]
fn edits_use_the_lent_cancel_flag() {
    // A cancel flag set before the edit starts stops it before anything is written.
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    tree(&src, &[("a.txt", b"a")]);
    let archive = dir.path().join("x.zip");
    create(&archive, ArchiveKind::Zip, &src);
    let flag = Arc::new(AtomicBool::new(true));
    let mut cx = SimpleCtx::new().with_cancel(flag.clone());
    let e = edit_with(&archive, &remove(&["a.txt"]), &mut cx).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Cancelled);
    flag.store(false, Ordering::Relaxed);
    edit_with(&archive, &remove(&["a.txt"]), &mut cx).unwrap();
}
