//! The malicious `.bhive` files (docs/M13.md §7, §8), from `xtask/src/fixtures/bhive.rs`: names
//! that leave the destination, bombs made of shared extents, an index and cells that lie about
//! their sizes, and archives cut short at every part. Each is refused as it opens, or read
//! within its limits, on one thread and on four.

use std::time::{Duration, Instant};

use beezip_core::{ArchiveReader, TestReport, format::bhive::BhiveReader, source::Source};

use super::*;

fn bhive(name: &str, opts: &OpenOptions) -> beezip_core::Result<BhiveReader> {
    let source = Source::new(&corpus(name), Vec::new(), opts)?;
    BhiveReader::open(source, &mut SimpleCtx::new())
}

fn open_error(name: &str) -> beezip_core::Error {
    let t = Instant::now();
    let e = bhive(name, &OpenOptions::default())
        .err()
        .unwrap_or_else(|| panic!("{name} opened"));
    assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    // Through detection and the front door too, and nothing is extracted.
    assert_eq!(
        detect_path(&corpus(name), &Limits::default())
            .unwrap()
            .format(),
        Some(FormatId::Bhive),
        "{name}"
    );
    let (r, inside) = extract(name, FsOptions::default());
    assert_eq!(r.unwrap_err().kind, e.kind, "{name}");
    assert!(inside.is_empty(), "{name}: {inside:?}");
    e
}

fn test(name: &str, opts: &OpenOptions) -> beezip_core::Result<TestReport> {
    ops::test(
        &corpus(name),
        &Selection::all(),
        opts,
        &mut SimpleCtx::new(),
    )
}

fn four() -> OpenOptions {
    OpenOptions {
        threads: 4,
        min_parallel_files: 1,
        ..OpenOptions::default()
    }
}

/// `..`, an absolute path, a drive: refused or brought inside; the link out isn't made.
#[test]
fn bhive_traversal_is_refused() {
    let (r, inside) = extract("traversal.bhive", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe(), "{r:?}");
    let traversal = reasons(&r)
        .iter()
        .filter(|&&s| s == SkipReason::Traversal)
        .count();
    assert_eq!(traversal, 2, "{r:?}");
    assert!(inside.contains(&"safe.txt".to_owned()), "{inside:?}");
    assert!(
        inside.contains(&"etc/beezip-abs.txt".to_owned()),
        "{inside:?}"
    );
    assert!(!inside.iter().any(|p| p.contains("evil")), "{inside:?}");
    assert!(!inside.contains(&"escape".to_owned()), "{inside:?}");
}

/// Three thousand files that are each the same 4 MiB: 12 GiB from 140 KiB. Refused before a
/// byte is written, by the ratio of the whole to the archive, and with that limit off by the
/// job's size limit.
#[test]
fn a_bomb_of_shared_extents_hits_the_limits() {
    let name = "bhive-bomb.bhive";
    let mut r = bhive(name, &OpenOptions::default()).unwrap();
    let total: u64 = r
        .entries(&mut SimpleCtx::new())
        .unwrap()
        .iter()
        .map(|e| e.size.unwrap_or(0))
        .sum();
    assert_eq!(total, 3000 * (4 << 20));
    let t = Instant::now();
    let (r, inside) = extract(name, FsOptions::default());
    let e = r.unwrap_err();
    assert_eq!(e.kind, ErrorKind::LimitExceeded);
    assert!(e.message.contains("max_ratio"), "{e}");
    assert!(inside.is_empty(), "{inside:?}");
    assert!(t.elapsed() < Duration::from_secs(5));

    // No ratio limit, and a job that may write 64 MiB: it stops there.
    let limits = Limits {
        max_ratio: None,
        max_total_bytes: Some(64 << 20),
        ..Limits::default()
    };
    for threads in [1, 4] {
        let opts = OpenOptions {
            threads,
            min_parallel_files: 1,
            ..OpenOptions::new(limits.clone())
        };
        let (r, inside) = extract_with(name, FsOptions::default(), &opts);
        let e = r.unwrap_err();
        assert_eq!(e.kind, ErrorKind::LimitExceeded, "{threads} threads");
        assert!(e.message.contains("max_total_bytes"), "{e}");
        assert!(inside.len() <= 20, "{threads} threads: {}", inside.len());
    }
    // Testing it decodes its one cell once.
    let report = test(name, &four()).unwrap();
    assert!(report.ok());
    assert_eq!(report.entries, 3000);
}

/// One file of two thousand extents, each the same 4 MiB: stopped by its own ratio, the cell's
/// few hundred stored bytes against what comes out.
#[test]
fn a_file_of_one_extent_over_and_over_hits_its_ratio() {
    let name = "bhive-bomb-one-file.bhive";
    // As a whole it is over the archive's ratio too.
    let (r, inside) = extract(name, FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::LimitExceeded);
    assert!(inside.is_empty());

    // Past the check of the whole (a grace as large as the file), the file's own ratio.
    let limits = Limits {
        ratio_grace: 128 << 20,
        ..Limits::default()
    };
    let mut r = bhive(name, &OpenOptions::new(limits.clone())).unwrap();
    let e = r.open_entry(0, &mut SimpleCtx::new()).err().unwrap();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
}

/// What breaks a rule of docs/bhive.md §9 in the index is `Corrupt` as the archive opens.
#[test]
fn an_index_that_breaks_a_rule_is_corrupt() {
    for (name, says) in [
        ("bhive-extent-past-cell.bhive", "an extent of 6 bytes at 6"),
        ("bhive-extent-no-cell.bhive", "cell 1, which isn't there"),
        ("bhive-cells-overlap.bhive", "overlaps"),
        ("bhive-entries-2-60.bhive", "entries in an index of"),
        ("bhive-cells-2-60.bhive", "a table of"),
        ("bhive-cell-over-256m.bhive", "256 MiB"),
        ("bhive-index-more.bhive", "the index doesn't decode"),
        ("bhive-footer-outside.bhive", "outside the file"),
        ("bhive-footer-in-cell.bhive", "doesn't point at an index"),
    ] {
        let e = open_error(name);
        assert_eq!(e.kind, ErrorKind::Corrupt, "{name}: {e}");
        assert!(e.message.contains(says), "{name}: {e}");
    }
}

/// An index that claims a terabyte is refused before anything is allocated for it.
#[test]
fn an_index_that_claims_a_terabyte_hits_the_memory_limit() {
    let e = open_error("bhive-index-2-40.bhive");
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    assert!(e.message.contains("decoder_memory"), "{e}");
}

/// A version or a feature this BeeZip doesn't know is refused by name, not misread.
#[test]
fn a_newer_version_or_feature_is_unsupported() {
    for (name, says) in [
        ("bhive-version-2.bhive", "version 2"),
        ("bhive-feature.bhive", "features"),
    ] {
        let e = open_error(name);
        assert_eq!(e.kind, ErrorKind::UnsupportedFormat, "{name}: {e}");
        assert!(e.message.contains(says), "{name}: {e}");
        // Recovering doesn't get round it.
        let recover = OpenOptions {
            recover: true,
            ..OpenOptions::default()
        };
        assert!(bhive(name, &recover).is_err());
    }
}

/// A cell whose raw size lies fails the file in it, as `Corrupt`; the other file is extracted,
/// and the job fails after it.
#[test]
fn a_cell_whose_size_lies_fails_only_its_files() {
    for name in ["bhive-raw-more.bhive", "bhive-raw-less.bhive"] {
        for opts in [OpenOptions::default(), four()] {
            let (r, inside) = extract_with(name, FsOptions::default(), &opts);
            let e = r.unwrap_err();
            assert_eq!(e.kind, ErrorKind::Corrupt, "{name}: {e}");
            assert!(e.message.contains("1 file couldn't be read"), "{name}: {e}");
            assert_eq!(inside, ["ok.txt"], "{name}");
            let report = test(name, &opts).unwrap();
            let failed: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
            assert_eq!(failed, ["lies.txt"], "{name}");
            assert_eq!(report.entries, 2);
        }
    }
}

/// A cell of 256 MiB, and a dictionary of 256 MiB: within the format, and over a small
/// `decoder_memory` before anything is allocated.
#[test]
fn cells_over_the_memory_limit_are_refused_before_decoding() {
    // Without the ratio limit, which the 256 MiB from 8 KiB would hit first.
    let limits = Limits {
        decoder_memory: 64 << 20,
        max_ratio: None,
        ..Limits::default()
    };
    for name in ["bhive-cell-256m.bhive", "bhive-dict-256m.bhive"] {
        for threads in [1, 4] {
            let opts = OpenOptions {
                threads,
                min_parallel_files: 1,
                ..OpenOptions::new(limits.clone())
            };
            let t = Instant::now();
            let (r, _) = extract_with(name, FsOptions::default(), &opts);
            let e = r.unwrap_err();
            assert_eq!(e.kind, ErrorKind::LimitExceeded, "{name}: {e}");
            assert!(e.message.contains("decoder_memory"), "{name}: {e}");
            assert_eq!(
                test(name, &opts).unwrap_err().kind,
                ErrorKind::LimitExceeded
            );
            assert!(t.elapsed() < Duration::from_secs(2), "{name}");
        }
    }
    // With the default limit the dictionary is allowed, and the file reads.
    let (r, inside) = extract("bhive-dict-256m.bhive", FsOptions::default());
    r.unwrap();
    assert_eq!(inside, ["small.txt"]);
}

/// Cut short anywhere, an archive is `Corrupt`; opened to recover, it lists what the records
/// before the cut hold, and tests as damaged.
#[test]
fn a_cut_archive_is_corrupt_and_recovers_its_whole_cells() {
    let recover = OpenOptions {
        recover: true,
        ..OpenOptions::default()
    };
    for (name, left) in [
        ("bhive-cut-record.bhive", 2),
        ("bhive-cut-journal.bhive", 2),
        ("bhive-cut-cell.bhive", 2),
        ("bhive-cut-index-head.bhive", 6),
        ("bhive-cut-index.bhive", 6),
        ("bhive-cut-footer.bhive", 6),
    ] {
        let e = open_error(name);
        assert_eq!(e.kind, ErrorKind::Corrupt, "{name}: {e}");
        assert!(e.message.contains("incomplete or damaged"), "{name}: {e}");

        let mut r = bhive(name, &recover).unwrap();
        assert!(r.recovered().is_some(), "{name}");
        let mut cx = SimpleCtx::new();
        assert_eq!(r.entries(&mut cx).unwrap().len(), left, "{name}");
        let report = r.test(&mut cx).unwrap().unwrap();
        assert_eq!(report.errors_total, 1, "{name}: {:?}", report.errors);
        assert_eq!(report.entries, left as u64);

        // Through the front door: what is left is extracted.
        let (r, inside) = extract_with(name, FsOptions::default(), &recover);
        r.unwrap();
        assert_eq!(inside.len(), left, "{name}: {inside:?}");
    }
    // A header cut short isn't a `.bhive` at all.
    let det = detect_path(&corpus("bhive-cut-header.bhive"), &Limits::default()).unwrap();
    assert_ne!(
        det.layers.first().map(|l| l.confidence),
        Some(beezip_core::Confidence::Certain)
    );
    assert!(bhive("bhive-cut-header.bhive", &recover).is_err());
}

/// More entries than `max_entries` is a limit, checked as the index is read.
#[test]
fn more_entries_than_the_limit_is_refused() {
    let limits = Limits {
        max_entries: Some(1000),
        ..Limits::default()
    };
    let e = bhive("bhive-bomb.bhive", &OpenOptions::new(limits))
        .err()
        .unwrap();
    assert_eq!(e.kind, ErrorKind::LimitExceeded);
    assert!(e.message.contains("max_entries"), "{e}");
}
