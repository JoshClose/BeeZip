//! The malicious corpus from `cargo xtask gen-fixtures` (docs/M1.md §6). Each case must give
//! its expected error or skip reasons, and nothing may appear outside the destination: the
//! destination's parent is listed before and after.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use beezip_core::{
    ErrorKind, ExtractReport, FormatId, FsOptions, Limits, OpenOptions, Selection, SimpleCtx,
    SkipReason, detect_path, open, ops,
};

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/malicious")
        .join(name)
}

fn listing(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .map(|e| {
            let e = e.unwrap();
            e.path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    out.sort();
    out
}

/// Extracts `name` into `<tmp>/parent/dest` and checks nothing new appeared outside `dest`.
fn extract(name: &str, opts: FsOptions) -> (beezip_core::Result<ExtractReport>, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("parent");
    let dest = parent.join("dest");
    fs::create_dir_all(&dest).unwrap();
    fs::write(parent.join("sentinel"), b"").unwrap();
    let before = listing(&parent);
    let result = ops::extract(
        &corpus(name),
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        opts,
        &mut SimpleCtx::new(),
    );
    let after = listing(&parent);
    let outside: Vec<&String> = after
        .iter()
        .filter(|p| !before.contains(p) && !p.starts_with("dest/"))
        .collect();
    assert!(
        outside.is_empty(),
        "{name} wrote outside the destination: {outside:?}"
    );
    // A temp dir elsewhere on the machine is out of reach; the parent stands in for "outside".
    let inside = listing(&dest);
    (result, inside)
}

fn reasons(r: &ExtractReport) -> Vec<SkipReason> {
    r.skipped.iter().map(|s| s.reason).collect()
}

#[test]
fn traversal_is_refused() {
    for name in ["traversal.zip", "traversal.tar"] {
        let (r, inside) = extract(name, FsOptions::default());
        let r = r.unwrap();
        assert!(r.is_unsafe(), "{name}");
        assert!(
            reasons(&r).iter().all(|&s| s == SkipReason::Traversal),
            "{name}: {r:?}"
        );
        assert_eq!(inside, ["safe.txt"], "{name}");
    }
}

#[test]
fn absolute_paths_land_inside() {
    let (r, inside) = extract("absolute.zip", FsOptions::default());
    let r = r.unwrap();
    assert!(!r.is_unsafe());
    assert_eq!(r.renamed_total, 3);
    assert!(
        inside.contains(&"etc/beezip-abs.txt".to_owned()),
        "{inside:?}"
    );
    assert!(
        inside.contains(&"Windows/beezip-drive.txt".to_owned()),
        "{inside:?}"
    );
    assert!(inside.contains(&"beezip-unc.txt".to_owned()), "{inside:?}");

    let (r, inside) = extract("absolute.tar", FsOptions::default());
    assert_eq!(r.unwrap().renamed_total, 1);
    assert_eq!(inside, ["tmp", "tmp/beezip-abs.txt"]);
}

#[test]
fn reserved_names_are_rewritten() {
    let (r, inside) = extract("devices.zip", FsOptions::default());
    assert_eq!(r.unwrap().renamed_total, 3);
    assert_eq!(inside, ["_CON", "_aux.txt", "sub", "sub/_NUL.log"]);

    let (r, inside) = extract("streams.zip", FsOptions::default());
    assert_eq!(r.unwrap().renamed_total, 2);
    assert_eq!(inside, ["a_b", "x.txt_Zone.Identifier"]);

    let (_, inside) = extract("trailing.zip", FsOptions::default());
    assert_eq!(inside, ["spaces__", "trailing_"]);
}

#[test]
fn a_symlink_to_the_parent_is_refused() {
    // Links off (the default): the link is refused, and the file "through" it lands in a real
    // directory, since links are only ever created last.
    let (r, inside) = extract("symlink-escape.tar", FsOptions::default());
    let r = r.unwrap();
    assert_eq!(reasons(&r), [SkipReason::LinksDisabled]);
    assert_eq!(inside, ["link", "link/evil.txt"]);

    // Links on: refused because it leads out.
    let (r, _) = extract(
        "symlink-escape.tar",
        FsOptions {
            links: true,
            ..FsOptions::default()
        },
    );
    assert!(reasons(&r.unwrap()).contains(&SkipReason::LinkOutside));
}

#[test]
fn a_hardlink_to_an_absolute_path_is_refused() {
    let (r, inside) = extract("hardlink-absolute.tar", FsOptions::default());
    let r = r.unwrap();
    assert_eq!(reasons(&r), [SkipReason::LinkOutside]);
    assert!(r.is_unsafe());
    assert!(inside.is_empty());
}

#[test]
fn overlapping_entries_are_refused_on_open() {
    let err = open(
        &corpus("overlap.zip"),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .err()
    .unwrap();
    assert_eq!(err.kind, ErrorKind::Unsafe);
    let (r, inside) = extract("overlap.zip", FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::Unsafe);
    assert!(inside.is_empty());
}

#[test]
fn a_ratio_bomb_hits_the_limit() {
    let (r, inside) = extract("ratio.zip", FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::LimitExceeded);
    // The partial file is gone.
    assert!(inside.is_empty(), "{inside:?}");
    let err = ops::test(
        &corpus("ratio.zip"),
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded);
}

#[test]
fn deep_nesting_stops_at_max_layers() {
    let det = detect_path(&corpus("nested5.gz"), &Limits::default()).unwrap();
    assert_eq!(det.codecs().len(), 4);
    assert_eq!(det.format(), Some(FormatId::Stream));
    let (r, inside) = extract("nested5.gz", FsOptions::default());
    assert_eq!(r.unwrap().files, 1);
    assert_eq!(inside.len(), 1);
}

#[test]
fn an_empty_zip_is_fine() {
    let mut cx = SimpleCtx::new();
    let mut opened = open(&corpus("empty.zip"), &OpenOptions::default(), &mut cx).unwrap();
    assert!(opened.reader.entries(&mut cx).unwrap().is_empty());
    let (r, inside) = extract("empty.zip", FsOptions::default());
    assert_eq!(r.unwrap(), ExtractReport::default());
    assert!(inside.is_empty());
}

/// 7z and RAR (docs/M3.md §6): `../`, an absolute path, a device name and a symlink to `..`,
/// which UnRAR and sevenz-rust2 hand over unchanged (UnRAR on Windows turns `:` into `_`).
#[test]
fn sevenz_and_rar_paths_are_made_safe() {
    for name in ["traversal.7z", "traversal.rar"] {
        let (r, inside) = extract(name, FsOptions::default());
        let r = r.unwrap();
        assert!(r.is_unsafe(), "{name}");
        let mut why = reasons(&r);
        why.sort_by_key(|s| s.name());
        assert_eq!(
            why,
            [SkipReason::LinksDisabled, SkipReason::Traversal],
            "{name}"
        );
        assert!(
            inside.contains(&"safe.txt".to_owned()),
            "{name}: {inside:?}"
        );
        assert!(inside.contains(&"_CON".to_owned()), "{name}: {inside:?}");
        let abs = ["etc/beezip-abs.txt", "abs.txt", "C_/abs.txt"];
        assert!(
            inside.iter().any(|p| abs.contains(&p.as_str())),
            "{name}: {inside:?}"
        );
        assert!(
            !inside.iter().any(|p| p.contains("evil")),
            "{name}: {inside:?}"
        );

        // With links on, the link to `..` is refused for leading out.
        let (r, _) = extract(
            name,
            FsOptions {
                links: true,
                ..FsOptions::default()
            },
        );
        assert!(
            reasons(&r.unwrap()).contains(&SkipReason::LinkOutside),
            "{name}"
        );
    }
}

#[test]
fn sevenz_memory_bombs_are_refused_before_decoding() {
    let err = open(
        &corpus("bomb-header.7z"),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .err()
    .unwrap();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
    let (r, inside) = extract("huge-dict.7z", FsOptions::default());
    let err = r.unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
    assert!(err.message.contains("decoder_memory"), "{err}");
    assert!(inside.is_empty());
}

// ---- M5's formats (docs/M5.md §10). ----

/// `../` in every new archive format: refused, the rest extracted. The cpio also has an
/// absolute path, which lands inside, and a symlink to `..`, refused.
#[test]
fn m5_traversal_is_refused() {
    for (name, safe) in [
        (
            "traversal.cpio",
            vec!["etc", "etc/beezip-abs.txt", "safe.txt"],
        ),
        ("traversal.ar", vec!["safe.txt"]),
        (
            "traversal.deb",
            vec!["DEBIAN", "DEBIAN/control", "safe.txt"],
        ),
        ("traversal.rpm", vec!["safe.txt"]),
        ("traversal.cab", vec!["safe.txt"]),
        ("traversal.lzh", vec!["safe.txt"]),
        ("traversal.iso", vec!["safe.txt"]),
    ] {
        let (r, inside) = extract(name, FsOptions::default());
        let r = r.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(r.is_unsafe(), "{name}");
        let why = reasons(&r);
        assert!(why.contains(&SkipReason::Traversal), "{name}: {why:?}");
        assert!(
            why.iter()
                .all(|s| matches!(s, SkipReason::Traversal | SkipReason::LinksDisabled)),
            "{name}: {why:?}"
        );
        assert_eq!(inside, safe, "{name}");
    }
    let (r, _) = extract(
        "traversal.cpio",
        FsOptions {
            links: true,
            ..FsOptions::default()
        },
    );
    assert!(reasons(&r.unwrap()).contains(&SkipReason::LinkOutside));
}

/// An ISO folder whose record points back at the top: listed once, with a warning, and the
/// rest extracts (docs/M5.md §5.9).
#[test]
fn a_cyclic_iso_folder_is_listed_once() {
    let mut cx = SimpleCtx::new();
    let mut opened = open(&corpus("cyclic.iso"), &OpenOptions::default(), &mut cx).unwrap();
    let paths: Vec<String> = opened
        .reader
        .entries(&mut cx)
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(paths, ["a", "a/b", "top.txt"]);
    assert!(
        cx.warnings.iter().any(|w| w.contains("cycle")),
        "{:?}",
        cx.warnings
    );
    drop(opened);
    let (r, inside) = extract("cyclic.iso", FsOptions::default());
    assert!(r.unwrap().skipped.is_empty());
    assert_eq!(inside, ["a", "a/b", "top.txt"]);
}

/// A size past the end of the file is `Corrupt` when the archive opens or lists, before
/// anything is allocated for it.
#[test]
fn m5_sizes_past_the_end_are_corrupt() {
    for name in ["past-end.cpio", "past-end.ar", "past-end.rpm"] {
        let mut cx = SimpleCtx::new();
        let err = open(&corpus(name), &OpenOptions::default(), &mut cx)
            .and_then(|mut o| o.reader.entries(&mut cx).map(|_| ()))
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Corrupt, "{name}: {err}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
    }
}

/// A cabinet whose file claims 4 GiB from a folder of one block.
#[test]
fn a_cab_folder_that_claims_too_much_is_corrupt() {
    let (r, inside) = extract("folder-bomb.cab", FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt);
    assert!(inside.is_empty(), "{inside:?}");
}

/// `bomb.Z` decodes 163 KiB to over 3 GiB, with fixed memory. The default limits stop it
/// around 700 MB in (10 000:1 after the 64 MiB grace), which takes a while in a debug build, so
/// this checks with tighter ones.
#[test]
fn a_compress_bomb_hits_the_limit() {
    let opts = OpenOptions::new(Limits {
        max_ratio: Some(200),
        ratio_grace: 1024 * 1024,
        ..Limits::default()
    });
    let root = tempfile::tempdir().unwrap();
    let err = ops::extract(
        &corpus("bomb.Z"),
        root.path(),
        &Selection::all(),
        &opts,
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
    assert!(listing(root.path()).is_empty());
}

/// An lzop block claiming 64 MiB from 16 bytes is refused before anything is allocated for it.
#[test]
fn an_lzop_bomb_is_corrupt() {
    let (r, inside) = extract("bomb.lzo", FsOptions::default());
    let err = r.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
    assert!(err.message.contains("a block of 16 bytes"), "{err}");
    assert!(inside.is_empty());
}
