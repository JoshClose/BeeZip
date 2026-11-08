//! The malicious XAR and macOS package cases (docs/M6.md §10), from `xtask/src/fixtures/xar.rs`.

use std::time::{Duration, Instant};

use super::*;

/// A billion laughs, a table claiming 4 GiB and data past the end fail as they open, at once:
/// nothing is expanded, allocated from the claims, or written.
#[test]
fn xar_bombs_fail_fast() {
    for (name, kind) in [
        ("billion-laughs.xar", ErrorKind::Corrupt),
        ("toc-4gib.xar", ErrorKind::LimitExceeded),
        ("heap-past-end.xar", ErrorKind::Corrupt),
    ] {
        assert_eq!(
            detect_path(&corpus(name), &Limits::default())
                .unwrap()
                .format(),
            Some(FormatId::Xar),
            "{name}"
        );
        let t = Instant::now();
        let err = open(
            &corpus(name),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        )
        .err()
        .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(err.kind, kind, "{name}: {err}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, kind, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
    }
}

/// `..` as a XAR name, and `../` inside a package payload's cpio: refused, the rest extracted.
#[test]
fn xar_and_pkg_traversal_is_refused() {
    for (name, format, safe) in [
        ("traversal.xar", FormatId::Xar, vec!["safe.txt"]),
        (
            "traversal.pkg",
            FormatId::Pkg,
            vec!["PackageInfo", "Payload", "Payload/safe.txt"],
        ),
    ] {
        assert_eq!(
            detect_path(&corpus(name), &Limits::default())
                .unwrap()
                .format(),
            Some(format),
            "{name}"
        );
        let (r, inside) = extract(name, FsOptions::default());
        let r = r.unwrap();
        assert!(r.is_unsafe(), "{name}");
        assert!(!reasons(&r).is_empty(), "{name}");
        assert!(
            reasons(&r).iter().all(|&s| s == SkipReason::Traversal),
            "{name}: {r:?}"
        );
        assert_eq!(inside, safe, "{name}");
    }
}
