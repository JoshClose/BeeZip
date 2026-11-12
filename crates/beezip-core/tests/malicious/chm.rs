//! The malicious CHM help files (docs/M9.md §8), from `xtask/src/fixtures/chm.rs`. Each is
//! refused at once or read within its limits by BeeZip's own reader, never handed to 7-Zip.

use std::time::{Duration, Instant};

use beezip_core::{ArchiveReader, format::chm, source::Source};

use super::*;

fn native(name: &str) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let source = Source::new(&corpus(name), Vec::new(), &OpenOptions::default())?;
    chm::open(source, &mut SimpleCtx::new())
}

/// `..` in a help file's names: refused, the rest extracted.
#[test]
fn chm_traversal_is_refused() {
    assert_eq!(
        detect_path(&corpus("traversal.chm"), &Limits::default())
            .unwrap()
            .format(),
        Some(FormatId::External(beezip_core::External::Chm))
    );
    let (r, inside) = extract("traversal.chm", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe());
    assert!(
        reasons(&r).iter().all(|&s| s == SkipReason::Traversal),
        "{r:?}"
    );
    assert_eq!(inside, ["safe.txt", "sub"]);
}

/// A directory that can't be read fails as the file opens.
#[test]
fn chm_directories_that_cannot_be_read_fail_at_once() {
    for name in ["chm-chunk-4gib.chm", "chm-long-encint.chm"] {
        let t = Instant::now();
        let e = native(name)
            .err()
            .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(e.kind, ErrorKind::Corrupt, "{name}: {e}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    }
}

/// A section 1 that can't be read lists whole; its files fail as damaged, the stored ones read,
/// and nothing is allocated from the claims.
#[test]
fn chm_claims_fail_their_files_only() {
    for (name, failing) in [
        ("chm-1tb.chm", vec!["index.htm"]),
        ("chm-reset-back.chm", vec!["index.htm"]),
        ("chm-window-4mib.chm", vec!["index.htm"]),
        ("chm-reset-0.chm", vec!["index.htm"]),
        ("chm-past-end.chm", vec!["packed-1tb.bin", "stored-1tb.bin"]),
    ] {
        let t = Instant::now();
        let mut r = native(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        let mut failed: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
        failed.sort_unstable();
        assert_eq!(failed, failing, "{name}");
        assert!(
            report.errors.iter().all(|e| e.kind == ErrorKind::Corrupt),
            "{name}: {:?}",
            report.errors
        );
        // Extraction stops at the first damaged file, on one worker and on four. A small file
        // written before it may be left or not: on four, one still queued behind the reader is
        // dropped with the sink (docs/M9.md §15), so the two aren't compared, as `extract` does.
        for threads in [1, 4] {
            let opts = OpenOptions {
                threads,
                ..OpenOptions::default()
            };
            let (r, inside) = extract_with(name, FsOptions::default(), &opts);
            assert_eq!(
                r.err().map(|e| e.kind),
                Some(ErrorKind::Corrupt),
                "{name} on {threads}"
            );
            assert!(
                inside.iter().all(|p| p == "#SYSTEM" || p == "index.htm"),
                "{name} on {threads}: {inside:?}"
            );
        }
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    }
}
