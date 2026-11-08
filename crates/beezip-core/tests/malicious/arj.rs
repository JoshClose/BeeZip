//! The malicious ARJ cases (docs/M6.md §10), built by `xtask/src/fixtures/arj.rs`.

use super::*;

#[test]
fn arj_traversal_is_refused() {
    let (r, inside) = extract("traversal.arj", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe());
    // `../evil.txt`, and `..\evil2.txt` once its `\` is a separator.
    assert_eq!(
        reasons(&r),
        [SkipReason::Traversal, SkipReason::Traversal],
        "{r:?}"
    );
    // The absolute path lands inside, as zip's and tar's do.
    assert_eq!(r.renamed_total, 1, "{r:?}");
    assert_eq!(
        inside,
        ["safe.txt", "tmp", "tmp/beezip-abs.txt"],
        "{inside:?}"
    );
}

#[test]
fn arj_sizes_past_the_end_are_corrupt() {
    let path = corpus("past-end.arj");
    assert!(fs::metadata(&path).unwrap().len() < 200);
    assert_eq!(
        detect_path(&path, &Limits::default()).unwrap().format(),
        Some(FormatId::Arj)
    );
    let (r, inside) = extract("past-end.arj", FsOptions::default());
    let err = r.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err:?}");
    assert!(err.message.contains("past the end"), "{err:?}");
    assert!(inside.is_empty(), "{inside:?}");
    let err = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Corrupt);
}
