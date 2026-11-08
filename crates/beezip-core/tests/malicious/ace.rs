//! The malicious ACE cases (docs/M6.md §10), built by `xtask/src/fixtures/ace.rs`.

#[allow(unused_imports)]
use super::*;

/// `../` and `..\` are refused and the rest extracted; the absolute path lands inside.
#[test]
fn ace_traversal_is_refused() {
    let (r, inside) = extract("traversal.ace", FsOptions::default());
    let r = r.unwrap();
    assert!(r.is_unsafe());
    assert_eq!(
        reasons(&r),
        [SkipReason::Traversal, SkipReason::Traversal],
        "{r:?}"
    );
    assert_eq!(inside, ["etc", "etc/beezip-abs.txt", "safe.txt"]);
    let names: Vec<String> = {
        let mut cx = SimpleCtx::new();
        let mut opened = open(&corpus("traversal.ace"), &OpenOptions::default(), &mut cx).unwrap();
        opened
            .reader
            .entries(&mut cx)
            .unwrap()
            .iter()
            .map(|e| e.path.clone())
            .collect()
    };
    assert_eq!(
        names,
        [
            "../evil.txt",
            "../evil.txt",
            "/etc/beezip-abs.txt",
            "safe.txt"
        ]
    );
}
