//! The malicious NTFS images (docs/M7.md §10), from `tests/fixtures/make-ntfs.sh`, read by
//! BeeZip's own reader: each is refused cleanly or read within its limits, and nothing lands
//! outside the destination.

use std::time::{Duration, Instant};

use beezip_core::EntryKind;

use super::*;

/// The image opened, its entries and the warnings it gave.
fn listed(name: &str) -> (Vec<beezip_core::Entry>, Vec<String>) {
    let mut cx = SimpleCtx::new();
    let mut opened = open(&corpus(name), &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    (entries, cx.warnings)
}

/// fstool 0.5.2 recurses through `$MFT`'s first record until its stack overflows, which would
/// abort this whole test process; the volumes whose root folder can't be read; each refused as
/// it opens, at once, with nothing written.
#[test]
fn damaged_ntfs_volumes_are_refused_as_they_open() {
    for name in [
        "ntfs-mft-recursion.img",
        "ntfs-index-loop.img",
        "ntfs-index-4g.img",
        "ntfs-truncated.img",
    ] {
        let t = Instant::now();
        let err = open(
            &corpus(name),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        )
        .err()
        .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(err.kind, ErrorKind::Corrupt, "{name}: {err}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
    }
}

/// One sparse file of 100 GiB in 1.25 MiB: listed with what the volume allocated to it, and
/// refused by the ratio limit before anything is written or read, by extracting and testing.
#[test]
fn an_ntfs_sparse_file_of_100_gb_hits_the_limit() {
    let name = "ntfs-sparse-100g.img";
    let (entries, _) = listed(name);
    let big = entries
        .iter()
        .find(|e| e.path == "sparse-100g.bin")
        .unwrap();
    assert_eq!(
        (big.size, big.packed_size),
        (Some(107_374_182_400), Some(8192))
    );
    let t = Instant::now();
    let (r, inside) = extract(name, FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::LimitExceeded);
    assert!(inside.is_empty(), "{inside:?}");
    let err = ops::test(
        &corpus(name),
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded);
    assert!(t.elapsed() < Duration::from_secs(10));
}

/// A record fstool would read past (a resident attribute too short for its header, which panics
/// fstool 0.5.2's `AttributeIter`), and one whose attribute list names another file's record:
/// each file is left out with a warning, and the rest extracts.
#[test]
fn ntfs_records_fstool_would_misread_are_left_out() {
    for (name, gone) in [
        ("ntfs-short-attr.img", "with space.txt"),
        ("ntfs-alist-foreign.img", "mtime.txt"),
    ] {
        let (entries, warnings) = listed(name);
        assert!(!entries.iter().any(|e| e.path == gone), "{name}");
        assert_eq!(warnings.len(), 1, "{name}: {warnings:?}");
        assert!(warnings[0].contains(gone), "{name}: {warnings:?}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap().files, 27, "{name}");
        assert!(!inside.contains(&gone.to_owned()), "{name}");
        for want in ["random.bin", "hard-readme.txt", "sub/nested/deep.txt"] {
            assert!(inside.contains(&want.to_owned()), "{name}: {want}");
        }
    }
    // The file whose records the list named reads as itself.
    let len = |name: &str| {
        let root = tempfile::tempdir().unwrap();
        ops::extract(
            &corpus(name),
            root.path(),
            &Selection::all(),
            &OpenOptions::default(),
            FsOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        fs::metadata(root.path().join("random.bin")).unwrap().len()
    };
    assert_eq!(len("ntfs-alist-foreign.img"), 65_536);
}

/// A folder whose one name points back at the root: listed as a folder already listed, not
/// walked again.
#[test]
fn an_ntfs_folder_loop_is_not_followed() {
    let (entries, warnings) = listed("ntfs-dir-cycle.img");
    let looped = entries
        .iter()
        .find(|e| e.path == "sub/nested/deep.txt")
        .unwrap();
    assert_eq!(looped.kind, EntryKind::Dir);
    assert_eq!(entries.len(), 35);
    assert!(warnings[0].contains("already listed"), "{warnings:?}");
    let (r, inside) = extract("ntfs-dir-cycle.img", FsOptions::default());
    assert_eq!(r.unwrap().files, 27);
    assert!(inside.contains(&"sub/nested/deep.txt".to_owned()));
}

/// A file whose data is stored twice, once resident: listed, and reading it is `Corrupt`; a test
/// reads the rest.
#[test]
fn ntfs_data_stored_twice_fails_that_file() {
    let name = "ntfs-dup-data.img";
    let report = ops::test(
        &corpus(name),
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let failed: Vec<(&str, ErrorKind)> = report
        .errors
        .iter()
        .map(|e| (e.path.as_str(), e.kind))
        .collect();
    assert_eq!(failed, [("random.bin", ErrorKind::Corrupt)]);
    assert_eq!(report.entries, 35);
    let (r, _) = extract(name, FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt);
}
