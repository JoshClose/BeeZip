//! The malicious ZOO cases (docs/M6.md §10), built by `xtask/src/fixtures/zoo.rs`.

use std::time::{Duration, Instant};

use super::*;

/// `..` as a folder and `..\` in a long name are refused; an absolute folder lands inside.
#[test]
fn zoo_traversal_is_refused() {
    let (r, inside) = extract("traversal.zoo", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe());
    assert_eq!(
        reasons(&r),
        [SkipReason::Traversal, SkipReason::Traversal],
        "{r:?}"
    );
    assert_eq!(inside, ["etc", "etc/beezip-abs.txt", "safe.txt"]);
}

/// A directory chain that loops back is `Corrupt` when the archive opens, at once.
#[test]
fn zoo_cycle_is_corrupt_quickly() {
    let path = corpus("cycle.zoo");
    assert_eq!(
        detect_path(&path, &Limits::default()).unwrap().format(),
        Some(FormatId::Zoo)
    );
    let start = Instant::now();
    let err = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
    assert!(err.message.contains("loop"), "{err}");
    assert!(start.elapsed() < Duration::from_secs(5));
    let (r, inside) = extract("cycle.zoo", FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt);
    assert!(inside.is_empty());
}
