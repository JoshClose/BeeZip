//! BeeZip's own CHM reader (docs/M9.md) on `tests/fixtures/thirdparty/chm/`, made by
//! `tests/fixtures/make-chm.sh` with chmcmd and Halibut: each is read natively and compared with
//! what 7-Zip extracts from it (`expected.json`), whole, cut short and with its header or LZX
//! control data rewritten as other compilers write them. Then real help files against 7-Zip,
//! opt-in.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "oracle/seven_zip.rs"]
mod seven_zip;

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

use beezip_core::{
    ArchiveReader, Ctx, Entry, EntryKind, EntrySink, ErrorKind, OpenOptions, Selection, SimpleCtx,
    format::chm, source::Source,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty/chm")
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The help file at `path`, through BeeZip's own reader (never 7-Zip).
fn native(path: &Path) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let source = Source::new(path, Vec::new(), &OpenOptions::default())?;
    chm::open(source, &mut SimpleCtx::new())
}

/// `bytes` written to a file in `dir`, read natively.
fn native_bytes(dir: &Path, bytes: &[u8]) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let p = dir.join("t.chm");
    std::fs::write(&p, bytes).unwrap();
    native(&p)
}

/// Each file's bytes, or why it failed.
#[derive(Default)]
struct Collect(BTreeMap<String, Result<Vec<u8>, ErrorKind>>);

impl EntrySink for Collect {
    fn entry(
        &mut self,
        e: &Entry,
        data: &mut dyn Read,
        _: &mut dyn Ctx,
    ) -> beezip_core::Result<()> {
        if e.kind == EntryKind::File {
            let mut v = Vec::new();
            let r = data
                .read_to_end(&mut v)
                .map(|_| v)
                .map_err(|e| beezip_core::io::read_error(&e).kind);
            self.0.insert(e.path.clone(), r);
        }
        Ok(())
    }
}

fn extract(r: &mut dyn ArchiveReader) -> BTreeMap<String, Result<Vec<u8>, ErrorKind>> {
    let mut sink = Collect::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    sink.0
}

/// Each fixture's files as 7-Zip extracts them: path → SHA-256.
fn expected() -> BTreeMap<String, BTreeMap<String, String>> {
    let v: Value =
        serde_json::from_slice(&std::fs::read(fixtures().join("expected.json")).unwrap()).unwrap();
    v["fixtures"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, f)| {
            let files = f["files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["path"].as_str().unwrap().to_owned(),
                        e["sha256"].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            (name.clone(), files)
        })
        .collect()
}

/// Every file `got` has is what 7-Zip extracts, and nothing is missing.
fn same_files(
    what: &str,
    got: &BTreeMap<String, Result<Vec<u8>, ErrorKind>>,
    want: &BTreeMap<String, String>,
) {
    let listed: Vec<&String> = got.keys().collect();
    let wanted: Vec<&String> = want.keys().collect();
    assert_eq!(listed, wanted, "{what}: files listed");
    for (p, sum) in want {
        let data = got[p]
            .as_ref()
            .unwrap_or_else(|e| panic!("{what}: {p}: {e:?}"));
        assert_eq!(&sha256(data), sum, "{what}: {p}");
    }
}

#[test]
fn every_fixture_reads_as_7zip_extracts_it() {
    for (name, want) in expected() {
        let path = fixtures().join(&name);
        let mut r = native(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        // One pass, in data order.
        same_files(&name, &extract(&mut *r), &want);
        // One by one, last first, each from its reset point.
        let entries = r.entries(&mut SimpleCtx::new()).unwrap().to_vec();
        for e in entries.iter().rev().filter(|e| e.kind == EntryKind::File) {
            let mut v = Vec::new();
            r.open_entry(e.id, &mut SimpleCtx::new())
                .unwrap()
                .read_to_end(&mut v)
                .unwrap();
            assert_eq!(&sha256(&v), &want[&e.path], "{name}: open_entry {}", e.path);
        }
        // Folders are listed before the files under them.
        for e in entries.iter().filter(|e| e.is_dir()) {
            assert!(
                entries
                    .iter()
                    .filter(|f| f.path.starts_with(&format!("{}/", e.path)))
                    .all(|f| f.id > e.id),
                "{name}: {}",
                e.path
            );
        }
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert!(report.ok(), "{name}: {:?}", report.errors);
        assert_eq!(report.entries, entries.len() as u64, "{name}");
        assert!(report.note.unwrap().contains("no checksums"), "{name}");
        let info = r.info(&mut SimpleCtx::new()).unwrap();
        let x = info.external.unwrap();
        assert_eq!(x.levels, ["chm"]);
        assert_eq!(info.methods, ["Copy", "LZX:16"], "{name}");
    }
}

#[test]
fn chmcmds_misnamed_first_chunk_is_read() {
    // chmcmd-chunks.chm's directory header says its first listing chunk is 1; chunk 0 holds the
    // first of its 251 files (docs/UPSTREAM.md).
    let path = fixtures().join("chmcmd-chunks.chm");
    let d = std::fs::read(&path).unwrap();
    let dir = u64::from_le_bytes(d[0x48..0x50].try_into().unwrap()) as usize;
    assert_eq!(&d[dir..dir + 4], b"ITSP");
    assert_eq!(
        u32::from_le_bytes(d[dir + 0x20..dir + 0x24].try_into().unwrap()),
        1
    );
    let chunks = dir + 0x54;
    assert_eq!(&d[chunks..chunks + 4], b"PMGL");
    let mut r = native(&path).unwrap();
    let files = extract(&mut *r);
    assert_eq!(files.len(), 251);
    assert!(files.contains_key("#ITBITS") && files.contains_key("_#_README_#_"));
}

#[test]
fn a_cut_fixture_gives_the_files_before_the_cut() {
    let want = expected()["chmcmd-big.chm"].clone();
    let whole = std::fs::read(fixtures().join("chmcmd-big.chm")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    // Inside the directory: nothing can be listed.
    let e = native_bytes(dir.path(), &whole[..0x400]).err().unwrap();
    assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    for keep in [whole.len() / 2, whole.len() * 3 / 4, whole.len() - 100] {
        let mut r = native_bytes(dir.path(), &whole[..keep]).unwrap();
        let got = extract(&mut *r);
        assert_eq!(got.len(), want.len(), "{keep}: listed whole");
        // In data order, the files before the cut read whole and every one after it fails.
        let entries = r.entries(&mut SimpleCtx::new()).unwrap().to_vec();
        let mut failed = false;
        let (mut good, mut bad) = (0, 0);
        for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
            match &got[&e.path] {
                Ok(data) => {
                    assert!(!failed, "{keep}: {} reads after a failure", e.path);
                    assert_eq!(&sha256(data), &want[&e.path], "{keep}: {}", e.path);
                    good += 1;
                }
                Err(k) => {
                    assert_eq!(*k, ErrorKind::Corrupt, "{keep}: {}", e.path);
                    failed = true;
                    bad += 1;
                }
            }
        }
        assert!(good > 0 && bad > 0, "{keep}: {good} read, {bad} failed");
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert_eq!(report.errors_total, bad, "{keep}");
        assert!(report.errors[0].message.contains("cut short"), "{keep}");
    }
}

#[test]
fn a_real_file_rewritten_as_other_compilers_write_it_reads_the_same() {
    let want = expected()["chmcmd-big.chm"].clone();
    let whole = std::fs::read(fixtures().join("chmcmd-big.chm")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    // ITSF version 2: no content offset in the header; section 0 follows the directory, as
    // chmcmd lays it out anyway.
    let mut v2 = whole.clone();
    v2[4..8].copy_from_slice(&2u32.to_le_bytes());
    v2[8..12].copy_from_slice(&0x58u32.to_le_bytes());
    // LZXC version 1: the reset interval and window in bytes.
    let mut v1 = whole.clone();
    let at = v1.windows(4).position(|w| w == b"LZXC").unwrap();
    for (off, v) in [(4, 1u32), (8, 0x1_0000), (12, 0x1_0000)] {
        v1[at + off..at + off + 4].copy_from_slice(&v.to_le_bytes());
    }
    for (what, bytes) in [("ITSF version 2", v2), ("LZXC version 1", v1)] {
        let mut r = native_bytes(dir.path(), &bytes).unwrap_or_else(|e| panic!("{what}: {e}"));
        same_files(what, &extract(&mut *r), &want);
    }
}

/// 7-Zip's name for an entry on Windows: what it writes in place of what a name can't hold.
fn seven_zip_name(path: &str) -> String {
    if !cfg!(windows) {
        return path.to_owned();
    }
    path.chars()
        .map(|c| {
            if "<>:\"|?*".contains(c) || (c as u32) < 32 {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Opt-in: `BEEZIP_CHM_SAMPLES` names a folder of CHM files, each read natively and compared
/// file by file with what the installed 7-Zip extracts from it (docs/M9.md §8).
#[test]
fn real_chms_read_as_7zip_extracts_them() {
    let Some(folder) = std::env::var_os("BEEZIP_CHM_SAMPLES") else {
        return;
    };
    let seven = seven_zip::find().expect("BEEZIP_CHM_SAMPLES needs 7-Zip");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("chm")))
        .collect();
    paths.sort();
    let mut bad = Vec::new();
    let mut total = 0;
    for path in &paths {
        let out = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(&seven.exe)
            .args(["x", "-y", "-bso0", "-bsp0"])
            .arg(format!("-o{}", out.path().display()))
            .arg(path)
            .status()
            .unwrap();
        let mut want = BTreeMap::new();
        for e in walkdir::WalkDir::new(out.path()) {
            let e = e.unwrap();
            if e.file_type().is_file() {
                let rel = e.path().strip_prefix(out.path()).unwrap();
                let rel = rel.to_string_lossy().replace('\\', "/");
                want.insert(rel, sha256(&std::fs::read(e.path()).unwrap()));
            }
        }
        let got = match native(path) {
            Ok(mut r) => extract(&mut *r),
            Err(e) => {
                bad.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let got: BTreeMap<String, String> = got
            .into_iter()
            .map(|(p, r)| {
                let sum = r.map_or_else(|k| format!("{k:?}"), |d| sha256(&d));
                (seven_zip_name(&p), sum)
            })
            .collect();
        total += got.len();
        if got != want {
            let differ: Vec<_> = got
                .iter()
                .filter(|(p, s)| want.get(*p) != Some(s))
                .map(|(p, _)| p.clone())
                .chain(want.keys().filter(|p| !got.contains_key(*p)).cloned())
                .take(5)
                .collect();
            bad.push(format!(
                "{} (7z exit {:?}): {differ:?}",
                path.display(),
                status.code()
            ));
        }
    }
    eprintln!(
        "{} help files, {total} files, against {}: {} differ",
        paths.len(),
        seven.name,
        bad.len()
    );
    assert!(bad.is_empty(), "{bad:#?}");
}
