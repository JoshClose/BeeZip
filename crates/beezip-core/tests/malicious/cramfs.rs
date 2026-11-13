//! The malicious CramFS images (docs/M10.md §8), from `xtask/src/fixtures/cramfs.rs`. Each is
//! refused at once or read within its limits by BeeZip's own reader, never handed to 7-Zip.

use std::time::{Duration, Instant};

use beezip_core::{ArchiveReader, format::cramfs, source::Source};

use super::*;

fn native(name: &str) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let source = Source::new(&corpus(name), Vec::new(), &OpenOptions::default())?;
    cramfs::open(source, &mut SimpleCtx::new())
}

/// A name holding `/..`, and a folder named `..`: refused, the rest extracted.
#[test]
fn cramfs_traversal_is_refused() {
    assert_eq!(
        detect_path(&corpus("traversal.cramfs"), &Limits::default())
            .unwrap()
            .format(),
        Some(FormatId::External(beezip_core::External::Cramfs))
    );
    let (r, inside) = extract("traversal.cramfs", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe());
    assert!(
        reasons(&r).iter().all(|&s| s == SkipReason::Traversal),
        "{r:?}"
    );
    assert_eq!(inside, ["safe.txt"]);
}

/// Folders that can't be listed fail as the image opens.
#[test]
fn cramfs_folders_that_cannot_be_read_fail_at_once() {
    for (name, says) in [
        ("cramfs-deep.cramfs", "256 deep"),
        ("cramfs-wrapped-name.cramfs", "no length"),
    ] {
        let t = Instant::now();
        let e = native(name)
            .err()
            .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(e.kind, ErrorKind::Corrupt, "{name}: {e}");
        assert!(e.message.contains(says), "{name}: {e}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    }
}

/// A folder holding itself is listed once, with a warning.
#[test]
fn a_cramfs_folder_holding_itself_is_listed_once() {
    let source = Source::new(
        &corpus("cramfs-loop.cramfs"),
        Vec::new(),
        &OpenOptions::default(),
    )
    .unwrap();
    let mut cx = SimpleCtx::new();
    let mut r = cramfs::open(source, &mut cx).unwrap();
    assert!(
        cx.warnings.iter().any(|w| w.contains("loop")),
        "{:?}",
        cx.warnings
    );
    let paths: Vec<String> = r
        .entries(&mut cx)
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(paths, ["two-blocks.bin", "safe.txt", "sub"]);
    let (r, inside) = extract("cramfs-loop.cramfs", FsOptions::default());
    r.unwrap();
    assert_eq!(inside, ["safe.txt", "sub", "two-blocks.bin"]);
}

/// Block pointers that go backwards, past the end, or claim 4 GiB fail their file only, and
/// nothing is allocated from them; a file count of 2³² - 1 is only a number.
#[test]
fn cramfs_claims_fail_their_files_only() {
    for name in [
        "cramfs-backwards.cramfs",
        "cramfs-past-end.cramfs",
        "cramfs-block-4gib.cramfs",
    ] {
        let t = Instant::now();
        let mut r = native(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        let failed: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(failed, ["two-blocks.bin"], "{name}: {:?}", report.errors);
        assert_eq!(report.errors[0].kind, ErrorKind::Corrupt, "{name}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    }
    let mut r = native("cramfs-files-4g.cramfs").unwrap();
    assert!(r.test(&mut SimpleCtx::new()).unwrap().unwrap().ok());
}

/// 7-Zip's variant with an LZMA block claiming a 4 GiB dictionary: held to the block's size, so
/// it reads at once without allocating what it claims (docs/M11.md §8).
#[test]
fn cramfs_lzma_dictionary_claims_are_held_to_the_block() {
    let t = Instant::now();
    let mut r = native("cramfs-lzma-dict.cramfs").unwrap();
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    assert!(t.elapsed() < Duration::from_secs(2));
}
