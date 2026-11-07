//! Third-party fixtures (docs/M1.md §6): archives made by 7-Zip, GNU tar, bsdtar and .NET, as
//! recorded in `tests/fixtures/manifest.json` by `make-thirdparty.ps1`. Each must be detected
//! as its chain, list its entries, extract to the right bytes, and pass its integrity test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use beezip_core::{
    EntryKind, FsOptions, Limits, NameDecoding, NameEncoding, OpenOptions, OverwritePolicy,
    Selection, SimpleCtx, SkipReason, detect_path, format::normalize, open, ops,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn manifest() -> Vec<Value> {
    let text = fs::read_to_string(fixtures().join("manifest.json")).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    v["fixtures"].as_array().unwrap().clone()
}

/// The options a fixture opens with: its `encoding`, on a US system's code pages (437, 1252).
fn options(fx: &Value) -> OpenOptions {
    let encoding = fx["encoding"]
        .as_str()
        .map(|e| NameEncoding::from_name(e).unwrap())
        .unwrap_or_default();
    OpenOptions::default().with_names(NameDecoding {
        encoding,
        ..NameDecoding::default()
    })
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn ctx(fx: &Value) -> SimpleCtx {
    // An archive with a password per entry lists them in the order they are needed.
    if let Some(list) = fx["passwords"].as_array() {
        let pws: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
        return SimpleCtx::new().with_passwords(&pws);
    }
    match fx["password"].as_str() {
        Some(pw) => SimpleCtx::new().with_password(pw),
        None => SimpleCtx::new(),
    }
}

/// 2026-01-01T00:00:00Z, the time `make-thirdparty.ps1` gives every file.
const MTIME: u64 = 1_767_225_600;

#[test]
fn every_fixture_reads_correctly() {
    let all = manifest();
    assert_eq!(all.len(), 69, "the manifest lists every fixture");
    let mut failures = Vec::new();
    for fx in &all {
        let file = fx["file"].as_str().unwrap();
        if let Err(e) = check(fx) {
            failures.push(format!("{file}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn check(fx: &Value) -> Result<(), String> {
    let path = fixtures()
        .join("thirdparty")
        .join(fx["file"].as_str().unwrap());
    let expected = fx["entries"].as_array().unwrap();

    // Detection.
    let det = detect_path(&path, &Limits::default()).map_err(|e| e.to_string())?;
    let chain = fx["chain"].as_str().unwrap();
    if det.chain() != chain {
        return Err(format!("detected `{}`, expected `{chain}`", det.chain()));
    }
    if path.extension().is_some_and(|e| e == "exe") != det.sfx {
        return Err(format!("sfx = {}", det.sfx));
    }

    // Listing.
    let mut cx = ctx(fx);
    let mut opened = open(&path, &options(fx), &mut cx).map_err(|e| e.to_string())?;
    let entries = opened
        .reader
        .entries(&mut cx)
        .map_err(|e| e.to_string())?
        .to_vec();
    let count = |pred: fn(&EntryKind) -> bool| entries.iter().filter(|e| pred(&e.kind)).count();
    let hardlinks = count(|k| matches!(k, EntryKind::Hardlink { .. }));
    let symlinks = count(|k| matches!(k, EntryKind::Symlink { .. }));
    if hardlinks as u64 != fx["hardlinks"].as_u64().unwrap()
        || symlinks as u64 != fx["symlinks"].as_u64().unwrap()
    {
        return Err(format!(
            "{hardlinks} hard links and {symlinks} symlinks listed"
        ));
    }
    for want in expected {
        let p = want["path"].as_str().unwrap();
        if p == "*" {
            continue;
        }
        let Some(e) = entries.iter().find(|e| normalize(&e.path) == p) else {
            return Err(format!("`{p}` isn't listed"));
        };
        match (want["kind"].as_str().unwrap(), &e.kind) {
            ("symlink", EntryKind::Symlink { target }) => {
                // 7z keeps a link's target in its data, which listing doesn't decode;
                // open_entry reads it.
                let target = if target.is_empty() {
                    let mut t = String::new();
                    opened
                        .reader
                        .open_entry(e.id, &mut cx)
                        .and_then(|mut r| {
                            r.read_to_string(&mut t)
                                .map_err(|e| beezip_core::io::read_error(&e))
                        })
                        .map_err(|e| format!("open_entry `{p}`: {e}"))?;
                    t
                } else {
                    target.clone()
                };
                if target != want["target"].as_str().unwrap() {
                    return Err(format!("`{p}` points at `{target}`"));
                }
            }
            ("file", EntryKind::File) => {
                if e.size != want["size"].as_u64() {
                    return Err(format!("`{p}` has size {:?}", e.size));
                }
            }
            ("file", EntryKind::Hardlink { .. }) => {}
            (k, kind) => return Err(format!("`{p}` is {kind:?}, expected {k}")),
        }
    }

    // Reading each file through open_entry.
    for want in expected.iter().filter(|w| w["kind"] == "file") {
        let p = want["path"].as_str().unwrap();
        let id = if p == "*" {
            0
        } else {
            entries
                .iter()
                .position(|e| normalize(&e.path) == p)
                .unwrap()
        };
        let mut data = Vec::new();
        opened
            .reader
            .open_entry(id, &mut cx)
            .and_then(|mut r| {
                r.read_to_end(&mut data)
                    .map_err(|e| beezip_core::io::read_error(&e))
            })
            .map_err(|e| format!("open_entry `{p}`: {e}"))?;
        if sha256(&data) != want["sha256"].as_str().unwrap() {
            return Err(format!("open_entry `{p}` read the wrong bytes"));
        }
    }

    // Extraction.
    let dest = tempfile::tempdir().unwrap();
    let opts = FsOptions {
        overwrite: OverwritePolicy::Always,
        ..FsOptions::default()
    };
    let report = ops::extract(
        &path,
        dest.path(),
        &Selection::all(),
        &options(fx),
        opts,
        &mut ctx(fx),
    )
    .map_err(|e| format!("extract: {e}"))?;
    let refused: Vec<_> = report
        .skipped
        .iter()
        .filter(|s| s.reason != SkipReason::LinksDisabled)
        .collect();
    if !refused.is_empty() || report.skipped.len() != symlinks {
        return Err(format!("skipped {:?}", report.skipped));
    }
    for want in expected.iter().filter(|w| w["kind"] == "file") {
        let p = want["path"].as_str().unwrap();
        let file = if p == "*" {
            let only: Vec<_> = fs::read_dir(dest.path()).unwrap().collect();
            if only.len() != 1 {
                return Err(format!("{} files from a compressed file", only.len()));
            }
            only.into_iter().next().unwrap().unwrap().path()
        } else {
            dest.path().join(p)
        };
        let data = fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        if sha256(&data) != want["sha256"].as_str().unwrap() {
            return Err(format!("`{p}` extracted to the wrong bytes"));
        }
        if fx["utc_mtimes"].as_bool().unwrap() {
            let t = fs::metadata(&file).unwrap().modified().unwrap();
            if t != UNIX_EPOCH + Duration::from_secs(MTIME) {
                return Err(format!("`{p}` has mtime {t:?}"));
            }
        }
    }

    // Integrity test.
    let tested = ops::test(&path, &Selection::all(), &options(fx), &mut ctx(fx))
        .map_err(|e| format!("test: {e}"))?;
    if !tested.ok() {
        return Err(format!("test found {:?}", tested.errors));
    }
    Ok(())
}

#[test]
fn a_damaged_fixture_fails_its_test() {
    let src = fixtures().join("thirdparty/7z-deflate.zip");
    let mut bytes = fs::read(src).unwrap();
    // Flip a byte in the middle of random.bin's data.
    let name = b"tree/data/random.bin";
    let header = bytes
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"PK\x03\x04")
        .map(|(i, _)| i)
        .find(|&i| bytes[i + 30..].starts_with(name))
        .unwrap();
    let extra = usize::from(u16::from_le_bytes([bytes[header + 28], bytes[header + 29]]));
    let at = header + 30 + name.len() + extra + 1000;
    bytes[at] ^= 0xFF;
    let dir = tempfile::tempdir().unwrap();
    let damaged = dir.path().join("damaged.zip");
    fs::write(&damaged, &bytes).unwrap();
    let report = ops::test(
        &damaged,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(!report.ok());
    assert_eq!(report.errors[0].kind, beezip_core::ErrorKind::Corrupt);

    let gz = fs::read(fixtures().join("thirdparty/bsdtar.tar.gz")).unwrap();
    let cut = dir.path().join("cut.tar.gz");
    fs::write(&cut, &gz[..gz.len() / 2]).unwrap();
    let report = ops::test(
        &cut,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(!report.ok(), "a truncated tar.gz must fail its test");
}

#[test]
fn info_reports_methods_and_encryption() {
    let mut cx = SimpleCtx::new();
    let path = fixtures().join("thirdparty/7z-aes256.zip");
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.encryption, beezip_core::Encryption::All);
    // 7-Zip stores the empty file.
    assert_eq!(info.methods, ["Deflate", "Store"]);

    let path = fixtures().join("thirdparty/7z-sfx.exe");
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    assert!(opened.reader.info(&mut cx).unwrap().sfx);

    let path = fixtures().join("thirdparty/bsdtar.tar.zst");
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.codecs, [beezip_core::CodecId::Zstd]);
    assert!(info.solid);
}

/// The legacy code-page fixtures read right in their own encoding, and wrong in another: as
/// UTF-8, and for zips under "auto" on a US system, which reads zip names in CP437. (A tar's
/// Latin-1 names read right under "auto" there: Windows-1252 has the same letters.)
#[test]
fn legacy_names_need_their_encoding() {
    for fx in manifest().iter().filter(|f| f["encoding"].is_string()) {
        let file = fx["file"].as_str().unwrap();
        let path = fixtures().join("thirdparty").join(file);
        let want: Vec<&str> = fx["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        let list = |opts: &OpenOptions| -> Vec<String> {
            let mut cx = SimpleCtx::new();
            let mut opened = open(&path, opts, &mut cx).unwrap();
            let entries = opened.reader.entries(&mut cx).unwrap();
            entries.iter().map(|e| normalize(&e.path)).collect()
        };
        let right = list(&options(fx));
        let utf8 = OpenOptions::default().with_names(NameDecoding {
            encoding: NameEncoding::Utf8,
            ..NameDecoding::default()
        });
        let mut wrong = vec![list(&utf8)];
        if fx["chain"] == "zip" {
            wrong.push(list(&OpenOptions::default()));
        }
        for w in &want {
            assert!(right.iter().any(|p| p == w), "{file}: {w} in {right:?}");
            for listed in &wrong {
                assert!(!listed.iter().any(|p| p == w), "{file}: {w} in {listed:?}");
            }
        }
    }
}
