//! The malicious NSIS installers (docs/M10.md §8), from `xtask/src/fixtures/nsis.rs`. Each is
//! refused at once or read within its limits by BeeZip's own reader, never handed to 7-Zip.

use std::time::{Duration, Instant};

use beezip_core::{ArchiveReader, format::nsis, source::Source};

use super::*;

fn native_with(name: &str, opts: &OpenOptions) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let source = Source::new(&corpus(name), Vec::new(), opts)?;
    nsis::open(source, &mut SimpleCtx::new())
}

fn native(name: &str) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    native_with(name, &OpenOptions::default())
}

/// `..\` in an installer's names: refused, the rest extracted.
#[test]
fn nsis_traversal_is_refused() {
    assert_eq!(
        detect_path(&corpus("traversal.nsis.exe"), &Limits::default())
            .unwrap()
            .format(),
        Some(FormatId::External(beezip_core::External::Nsis))
    );
    let (r, inside) = extract("traversal.nsis.exe", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe());
    assert!(
        reasons(&r).iter().all(|&s| s == SkipReason::Traversal),
        "{r:?}"
    );
    assert_eq!(inside, ["safe.txt"]);
}

/// Headers that can't be read, or ask for too much, fail as the installer opens.
#[test]
fn nsis_headers_that_cannot_be_read_fail_at_once() {
    for (name, kind, says) in [
        (
            "nsis-header-4gib.exe",
            ErrorKind::Corrupt,
            "a header of 4294967295 bytes",
        ),
        (
            "nsis-instructions-past-end.exe",
            ErrorKind::Corrupt,
            "run past its end",
        ),
        (
            "nsis-dict-4gib.exe",
            ErrorKind::LimitExceeded,
            "decoder_memory",
        ),
        // 10,000 nested `SetOutPath "$OUTDIR\x"`: a path past 4,096 bytes, which would be
        // thousands of nested folders.
        (
            "nsis-nested-10000.exe",
            ErrorKind::Corrupt,
            "longer than 4096 bytes",
        ),
    ] {
        let t = Instant::now();
        let e = native(name)
            .err()
            .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(e.kind, kind, "{name}: {e}");
        assert!(e.message.contains(says), "{name}: {e}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, kind, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    }
}

/// A string with no end names no file; the others are listed.
#[test]
fn an_nsis_string_with_no_end_names_nothing() {
    let mut r = native("nsis-string-no-end.exe").unwrap();
    let paths: Vec<String> = r
        .entries(&mut SimpleCtx::new())
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(paths, ["first.txt", "big.bin"]);
}

/// Records that claim 4 GiB, point past the end or patch outside the stub fail their file only,
/// and nothing is allocated from them.
#[test]
fn nsis_claims_fail_their_files_only() {
    for (name, failing) in [
        ("nsis-record-4gib.exe", "big.bin"),
        ("nsis-record-past-end.exe", "past-end.bin"),
        ("nsis-patch-outside.exe", "uninstall.exe"),
    ] {
        let t = Instant::now();
        let mut r = native(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        let failed: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(failed, [failing], "{name}: {:?}", report.errors);
        assert_eq!(report.errors[0].kind, ErrorKind::Corrupt, "{name}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    }
}

/// A deflate bomb, solid or not, hits the ratio limit as the installer opens: its sizes are
/// decoded then (docs/M10.md §5.1). With the default limits, deflate's 1,032:1 is under them.
#[test]
fn nsis_bombs_hit_the_ratio_limit() {
    let tight = OpenOptions::new(Limits {
        max_ratio: Some(200),
        ratio_grace: 1 << 20,
        ..Limits::default()
    });
    for name in ["nsis-bomb.exe", "nsis-bomb-solid.exe"] {
        let e = native_with(name, &tight)
            .err()
            .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(e.kind, ErrorKind::LimitExceeded, "{name}: {e}");
        let mut r = native(name).unwrap();
        assert!(
            r.test(&mut SimpleCtx::new()).unwrap().unwrap().ok(),
            "{name}"
        );
    }
}
