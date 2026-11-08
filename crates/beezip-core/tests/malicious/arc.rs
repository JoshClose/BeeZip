//! The malicious ARC cases (docs/M6.md §10), built by `xtask/src/fixtures/arc.rs`.

use super::*;

/// `../` and `..\` names are refused; an absolute one lands inside.
#[test]
fn arc_traversal_is_refused() {
    assert_eq!(
        detect_path(&corpus("traversal.arc"), &Limits::default())
            .unwrap()
            .format(),
        Some(FormatId::Arc)
    );
    let (r, inside) = extract("traversal.arc", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe());
    assert_eq!(
        reasons(&r),
        [SkipReason::Traversal, SkipReason::Traversal],
        "{r:?}"
    );
    assert_eq!(inside, ["etc", "etc/abs.txt", "safe.txt"]);
}
