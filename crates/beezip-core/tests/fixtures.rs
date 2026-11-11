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
/// A record of what 7-Zip lists (`"backend": "7-zip"`) is read through 7-Zip, even for the
/// formats BeeZip reads itself since M7, whose own records sit beside it (docs/M7.md §10).
fn options(fx: &Value) -> OpenOptions {
    let encoding = fx["encoding"]
        .as_str()
        .map(|e| NameEncoding::from_name(e).unwrap())
        .unwrap_or_default();
    OpenOptions {
        native: fx["backend"] != "7-zip",
        ..OpenOptions::default().with_names(NameDecoding {
            encoding,
            ..NameDecoding::default()
        })
    }
}

/// Four workers for reading, from the first file.
fn parallel(opts: OpenOptions) -> OpenOptions {
    OpenOptions {
        threads: 4,
        min_parallel_files: 1,
        ..opts
    }
}

/// Every file under `dir`: its path, contents' hash and, with `times`, its time.
fn tree(dir: &Path, times: bool) -> Vec<(String, String, Option<std::time::SystemTime>)> {
    let mut out: Vec<_> = walkdir::WalkDir::new(dir)
        .into_iter()
        .map(Result::unwrap)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(dir).unwrap();
            (
                rel.to_string_lossy().replace('\\', "/"),
                sha256(&fs::read(e.path()).unwrap()),
                e.metadata().unwrap().modified().ok().filter(|_| times),
            )
        })
        .collect();
    out.sort();
    out
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
    assert_eq!(all.len(), 317, "the manifest lists every fixture");
    let mut failures = Vec::new();
    for fx in &all {
        let file = fx["file"].as_str().unwrap();
        if let Err(e) = check(fx) {
            failures.push(format!("{file}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Whether a 7-Zip the backend can run is installed, for the fixtures it reads (docs/M6.md §3).
/// With `BEEZIP_REQUIRE_7Z` or `BEEZIP_REQUIRE_7Z_BACKEND` set to 1 (CI), a missing one fails.
fn seven_zip_here() -> bool {
    let found = beezip_core::backend::find(&beezip_core::SevenZipOptions::default());
    let required = ["BEEZIP_REQUIRE_7Z", "BEEZIP_REQUIRE_7Z_BACKEND"]
        .iter()
        .any(|v| std::env::var(v).as_deref() == Ok("1"));
    match found {
        Ok(_) => true,
        Err(m) if required => panic!("the 7-Zip backend's fixtures need 7-Zip: {}", m.reason()),
        Err(_) => false,
    }
}

fn check(fx: &Value) -> Result<(), String> {
    if fx["backend"] == "7-zip" && !seven_zip_here() {
        eprintln!(
            "skipping {}: no 7-Zip 25.01 or newer",
            fx["file"].as_str().unwrap_or("")
        );
        return Ok(());
    }
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
    // The formats 7-Zip opened, outermost first (docs/M6.md §3.5).
    if let Some(levels) = fx["levels"].as_array() {
        let info = opened.reader.info(&mut cx).map_err(|e| e.to_string())?;
        let got = info.external.map(|x| x.levels).unwrap_or_default();
        if got
            .iter()
            .map(String::as_str)
            .ne(levels.iter().filter_map(Value::as_str))
        {
            return Err(format!("7-Zip opened {got:?}, expected {levels:?}"));
        }
    }
    // A record of BeeZip's own reader is read by it, not handed to 7-Zip.
    if fx["native"] == true {
        let info = opened.reader.info(&mut cx).map_err(|e| e.to_string())?;
        if let Some(backend) = info.external.and_then(|x| x.backend) {
            return Err(format!("read by {backend:?}, not BeeZip's own reader"));
        }
    }
    let count = |pred: fn(&EntryKind) -> bool| entries.iter().filter(|e| pred(&e.kind)).count();
    let hardlinks = count(|k| matches!(k, EntryKind::Hardlink { .. }));
    let symlinks = count(|k| matches!(k, EntryKind::Symlink { .. }));
    // Devices and FIFOs (squashfs's), listed as `other` and skipped when extracting.
    let others = count(|k| matches!(k, EntryKind::Other));
    if hardlinks as u64 != fx["hardlinks"].as_u64().unwrap()
        || symlinks as u64 != fx["symlinks"].as_u64().unwrap()
        || others as u64 != fx["others"].as_u64().unwrap_or(0)
    {
        return Err(format!(
            "{hardlinks} hard links, {symlinks} symlinks and {others} others listed"
        ));
    }
    for want in expected {
        let p = want["path"].as_str().unwrap();
        if p == "*" {
            continue;
        }
        let Some(e) = entries.iter().find(|e| normalize(&e.path) == p) else {
            // What is listed beside it, to see how another version of a tool names it.
            let parent = p.rsplit_once('/').map_or("", |(d, _)| d);
            let beside: Vec<String> = entries
                .iter()
                .map(|e| e.path.clone())
                .filter(|q| q.rsplit_once('/').map_or("", |(d, _)| d) == parent)
                .take(20)
                .collect();
            return Err(format!("`{p:?}` isn't listed; beside it: {beside:?}"));
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
                // 7-Zip lists an NSIS installer's sizes from its script, as estimates (the
                // record has what `7z x` writes).
                if e.size != want["size"].as_u64() && chain != "nsis" {
                    return Err(format!("`{p}` has size {:?}", e.size));
                }
                // The time 7-Zip lists, in UTC (`-slmu`).
                // The record's RFC 3339 in 7-Zip's shape, with a space for the `T`.
                if let Some(t) = want["mtime"].as_str()
                    && e.modified != beezip_core::backend::slt::parse_time(&t.replacen('T', " ", 1))
                {
                    return Err(format!("`{p}` has time {:?}, not {t}", e.modified));
                }
            }
            ("file", EntryKind::Hardlink { .. })
            | ("other", EntryKind::Other)
            | ("folder", EntryKind::Dir) => {}
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
        .filter(|s| {
            !matches!(
                s.reason,
                SkipReason::LinksDisabled | SkipReason::Unsupported
            )
        })
        .collect();
    if !refused.is_empty() || report.skipped.len() != symlinks + others {
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

    // Again on four workers, from the first file (zips extract in parallel, docs/M6.md §10):
    // the same report and the same files.
    let dest4 = tempfile::tempdir().unwrap();
    let opts = FsOptions {
        overwrite: OverwritePolicy::Always,
        ..FsOptions::default()
    };
    let par = ops::extract(
        &path,
        dest4.path(),
        &Selection::all(),
        &parallel(options(fx)),
        opts,
        &mut ctx(fx),
    )
    .map_err(|e| format!("parallel extract: {e}"))?;
    if par != report {
        return Err(format!(
            "on four workers the report is {par:?}, not {report:?}"
        ));
    }
    // Entries without a time get the time they're written.
    let times = fx["utc_mtimes"].as_bool().unwrap();
    if tree(dest4.path(), times) != tree(dest.path(), times) {
        return Err("on four workers the files differ".to_owned());
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

/// How a broken fixture must fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fails {
    /// Opening, listing or testing it is one of these errors.
    With(&'static [beezip_core::ErrorKind]),
    /// It lists and tests, and extracting it refuses entries as unsafe.
    Unsafe,
    /// It reads: the damage isn't one BeeZip can see (see the case's comment).
    Reads,
}

/// The broken fixtures (not in the manifest; each folder's README says why): every one fails
/// as it should, without a panic, a hang or a large allocation.
#[test]
fn broken_fixtures_fail_as_they_should() {
    use beezip_core::ErrorKind::{Corrupt, UnsupportedFormat};
    let corrupt = Fails::With(&[Corrupt]);
    let unsupported = Fails::With(&[UnsupportedFormat]);
    // Fuzzed headers that detection doesn't take for the format at all.
    let garbage = Fails::With(&[Corrupt, UnsupportedFormat]);
    // A method BeeZip doesn't decode, refused when the entry is read.
    let refused = Fails::With(&[
        beezip_core::ErrorKind::UnsupportedOperation,
        UnsupportedFormat,
    ]);
    let cases = [
        // A match that reaches before the stream's start. lzxd 0.2.7 decoded it as zeros;
        // BeeZip's own LZX decoder refuses it (docs/M7.md §8.4).
        (
            "libarchive/cab/broken/test_read_format_cab_lzx_invalid_history.cab",
            corrupt,
        ),
        (
            "libarchive/cab/broken/test_read_format_cab_lzx_oob.cab",
            garbage,
        ),
        (
            "libarchive/cab/broken/test_read_format_cab_skip_malformed.cab",
            garbage,
        ),
        (
            "libarchive/cpio/broken/test_read_format_cpio_afio_header.part1.cpio",
            unsupported,
        ),
        (
            "libarchive/cpio/broken/test_read_format_cpio_afio_header.part2.cpio",
            unsupported,
        ),
        ("libarchive/lzh/broken/test_copy_data_warning.lzh", corrupt),
        // Ten archives run together; the first lists 29 entries and the rest is read as such.
        ("libarchive/lzh/broken/test_fuzz.lzh", Fails::Reads),
        (
            "libarchive/lzh/broken/test_read_format_lha_oversize_header.lzh",
            corrupt,
        ),
        // Its second header has no CRC field, an old variant libarchive takes and delharc
        // doesn't.
        (
            "libarchive/lzh/broken/test_read_format_lha_symlink_missing_target.lzh",
            corrupt,
        ),
        (
            "libarchive/rpm/broken/test_read_format_huge_rpm.rpm",
            corrupt,
        ),
        ("delharc/broken/regression-truncated.lzh", corrupt),
        ("delharc/broken/regression-evil_pm2.lzh", corrupt),
        ("delharc/broken/regression-dotdot.lzh", Fails::Unsafe),
        ("delharc/broken/regression-symlink2.lzh", Fails::Unsafe),
        ("delharc/broken/regression-symlink3.lzh", Fails::Unsafe),
        ("delharc/broken/regression-clusterfuzz-1.bin", garbage),
        ("delharc/broken/regression-fuzz-10-1.bin", garbage),
        ("delharc/broken/unlha32-lh2.lzh", unsupported),
        ("linux/broken/ar-thin.a", unsupported),
        // Listed with its real size; BeeZip doesn't decompress zisofs.
        (
            "libarchive/iso/broken/test_read_format_iso_zisofs.iso.Z",
            Fails::With(&[beezip_core::ErrorKind::UnsupportedOperation]),
        ),
        (
            "libarchive/iso/broken/test_read_format_iso_joliet_overlong.iso.Z",
            Fails::Reads,
        ),
        // The Joliet root loops back on itself: hadris reads it as empty.
        (
            "libarchive/iso/broken/test_read_format_iso_joliet_utf16be_cycle.iso.Z",
            Fails::Reads,
        ),
        (
            "libarchive/iso/broken/test_read_format_iso_joliet_utf16be_overflow.iso",
            Fails::Reads,
        ),
        (
            "libarchive/iso/broken/test_read_format_iso_rockridge_ce_loop.iso.Z",
            corrupt,
        ),
        (
            "libarchive/iso/broken/test_read_format_iso_rockridge_ce_overflow.iso.Z",
            corrupt,
        ),
        // Relocations that point at each other are listed where they're stored.
        (
            "libarchive/iso/broken/test_read_format_iso_rockridge_cl_re_cycle.iso.Z",
            Fails::Reads,
        ),
        (
            "libarchive/iso/broken/test_read_format_iso_rockridge_sl_leak.iso",
            corrupt,
        ),
        (
            "libarchive/iso/broken/test_read_format_iso_rockridge_zf_overflow.iso",
            corrupt,
        ),
        (
            "libarchive/iso/broken/test_read_format_iso_zisofs_overflow.iso",
            corrupt,
        ),
        // APFS files compressed into a resource fork, which fstool doesn't reach.
        (
            "dmg/broken/apfs-decmpfs-udzo.dmg",
            Fails::With(&[beezip_core::ErrorKind::UnsupportedOperation]),
        ),
        // unarc-rs's samples (unarc/README.md): CRCs wrong on purpose.
        ("unarc/broken/wrongcrc32.arj", corrupt),
        ("unarc/broken/wrongcrc16.zoo", corrupt),
        ("unarc/broken/wrongcrc16.arc", corrupt),
        // Their one file is `../license`: zoo stored its folder as `..`.
        ("unarc/zoo/high_per.zoo", Fails::Unsafe),
        ("unarc/zoo/store.zoo", Fails::Unsafe),
        // PAK's distilled and crushed methods, which BeeZip refuses (docs/M6.md §4.1).
        ("unarc/arc/license.pak", refused),
        ("unarc/arc/license_crushed.pak", refused),
    ];
    let mut failures = Vec::new();
    for (file, want) in cases {
        let path = fixtures().join("thirdparty").join(file);
        let mut cx = SimpleCtx::new();
        let tested = ops::test(&path, &Selection::all(), &OpenOptions::default(), &mut cx);
        let got = match &tested {
            Err(e) => Some(e.kind),
            Ok(r) if !r.ok() => Some(r.errors[0].kind),
            Ok(_) => None,
        };
        let ok = match want {
            Fails::With(kinds) => got.is_some_and(|k| kinds.contains(&k)),
            Fails::Reads => got.is_none(),
            Fails::Unsafe => {
                let dest = tempfile::tempdir().unwrap();
                let opts = FsOptions {
                    links: true,
                    ..FsOptions::default()
                };
                let r = ops::extract(
                    &path,
                    dest.path(),
                    &Selection::all(),
                    &OpenOptions::default(),
                    opts,
                    &mut cx,
                );
                got.is_none() && r.is_ok_and(|r| r.is_unsafe())
            }
        };
        if !ok {
            failures.push(format!("{file}: {want:?}, got {tested:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
