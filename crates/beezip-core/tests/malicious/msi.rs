//! The malicious MSIs (docs/M7.md §10), written by `write_the_malicious_msis` in `tests/msi.rs`
//! with the msi crate, then damaged:
//!
//! - `deep.msi`: the spike's bomb, a valid package whose folders nest 3,000 deep, each named
//!   with 2,000 characters, with a file halfway down and one at the bottom. An uncapped layout
//!   of its paths passed 1 GiB.
//! - `pool-4gib.msi`: the string pool's last string claims 4 GiB (the msi crate allocates it).
//! - `stream-4gib.msi`: the compound file's directory says the File table is 4 GiB long.
//! - `catalog-nulls.msi`: `_Columns` with null cells and a column numbered 32,767 (the msi crate
//!   panics on the nulls).
//! - `summary-2gib.msi`: the summary information's title claims 2 GiB, before the word count
//!   (the msi crate allocates it, then refuses the package).
//!
//! Patches, transforms and merge modules (docs/M11.md §8):
//! - `msp-names.msp`: a packed `..` storage holding a file, a control character and `CON`;
//! - `msp-slash.msp`: `/`, `\` and `:` in names, which MS-CFB forbids (cfb refuses the file);
//! - `mst-deep.mst`: 300 storages deep; `mst-many.mst`: 2,000 streams;
//! - `mst-claim.mst`: a stream whose directory entry claims 4 GiB;
//! - `msm-no-cab.msm` and `msm-not-cab.msm`: merge modules without their cabinet, and with a
//!   stream of its name that isn't one.

use std::time::{Duration, Instant};

use super::*;

/// Each opens or fails at once, without allocating what it claims: the damaged ones are
/// `Corrupt` (and don't go to 7-Zip), the others list within the caps.
#[test]
fn msi_claims_are_refused_or_read_within_caps() {
    for (name, outcome) in [
        ("deep.msi", None),
        ("summary-2gib.msi", None),
        ("pool-4gib.msi", Some(ErrorKind::Corrupt)),
        ("stream-4gib.msi", Some(ErrorKind::Corrupt)),
        ("catalog-nulls.msi", Some(ErrorKind::Corrupt)),
    ] {
        assert_eq!(
            detect_path(&corpus(name), &Limits::default())
                .unwrap()
                .format(),
            Some(FormatId::External(beezip_core::External::Msi)),
            "{name}"
        );
        let t = Instant::now();
        let mut cx = SimpleCtx::new();
        let opened = open(&corpus(name), &OpenOptions::default(), &mut cx);
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
        match (opened, outcome) {
            (Ok(mut o), None) => {
                assert_eq!(
                    o.detection.format(),
                    Some(FormatId::External(beezip_core::External::Msi))
                );
                let entries = o.reader.entries(&mut cx).unwrap();
                assert!(entries.iter().all(|e| e.path.len() <= 4096), "{name}");
            }
            (Err(e), Some(kind)) => assert_eq!(e.kind, kind, "{name}: {e}"),
            (Ok(_), Some(kind)) => panic!("{name} opened, and should be {kind:?}"),
            (Err(e), None) => panic!("{name}: {e}"),
        }
    }
}

/// The deep package extracts its two files under their folders' keys, and nothing leaves the
/// destination; the damaged ones extract nothing.
#[test]
fn msi_bombs_extract_safely() {
    let (r, inside) = extract("deep.msi", FsOptions::default());
    let r = r.unwrap();
    assert_eq!(r.files, 2);
    assert_eq!(
        inside,
        ["D1500", "D1500/f_half.txt", "D3000", "D3000/f_deep.txt"]
    );
    let (r, inside) = extract("summary-2gib.msi", FsOptions::default());
    assert_eq!(r.unwrap().files, 1);
    assert_eq!(inside, ["App", "App/a.txt"]);
    for name in ["pool-4gib.msi", "stream-4gib.msi", "catalog-nulls.msi"] {
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
    }
}

/// Patches, transforms and merge modules (docs/M11.md §5): each is detected by its CLSID; a name
/// MS-CFB forbids is `Corrupt`; the rest open at once within their caps, and what can't be read
/// fails alone.
#[test]
fn compound_files_are_refused_or_read_within_caps() {
    let msi = Some(FormatId::External(beezip_core::External::Msi));
    for name in [
        "msp-names.msp",
        "msp-slash.msp",
        "mst-deep.mst",
        "mst-many.mst",
        "mst-claim.mst",
        "msm-no-cab.msm",
        "msm-not-cab.msm",
    ] {
        let det = detect_path(&corpus(name), &Limits::default()).unwrap();
        assert_eq!(det.format(), msi, "{name}");
        let t = Instant::now();
        let opened = open(
            &corpus(name),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        );
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
        match opened {
            Err(e) => assert!(
                name == "msp-slash.msp" && e.kind == ErrorKind::Corrupt,
                "{name}: {e}"
            ),
            Ok(mut o) => {
                assert_ne!(name, "msp-slash.msp", "cfb refuses `/` in a name");
                let entries = o.reader.entries(&mut SimpleCtx::new()).unwrap();
                assert!(entries.iter().all(|e| e.path.len() <= 4096), "{name}");
                assert!(
                    entries.iter().all(|e| e.path.split('/').count() <= 64),
                    "{name}"
                );
            }
        }
    }

    // 300 storages deep: 64 levels listed, the rest left out with a warning.
    let mut cx = SimpleCtx::new();
    let mut o = open(&corpus("mst-deep.mst"), &OpenOptions::default(), &mut cx).unwrap();
    let deepest = o
        .reader
        .entries(&mut cx)
        .unwrap()
        .iter()
        .map(|e| e.path.split('/').count())
        .max();
    assert_eq!(deepest, Some(64));
    assert!(
        cx.warnings
            .iter()
            .any(|w| w.contains("nested more than 64")),
        "{:?}",
        cx.warnings
    );

    // 2,000 streams: over a limit of 1,000 entries.
    let few = OpenOptions::new(Limits {
        max_entries: Some(1000),
        ..Limits::default()
    });
    let e = open(&corpus("mst-many.mst"), &few, &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");

    // A stream claiming 4 GiB is listed, and only it fails.
    let mut cx = SimpleCtx::new();
    let mut o = open(&corpus("mst-claim.mst"), &OpenOptions::default(), &mut cx).unwrap();
    let entries = o.reader.entries(&mut cx).unwrap().to_vec();
    let id = |p: &str| entries.iter().find(|e| e.path == p).unwrap().id;
    let e = o.reader.open_entry(id("claim"), &mut cx).err().unwrap();
    assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    let mut fine = Vec::new();
    std::io::Read::read_to_end(
        &mut o.reader.open_entry(id("fine"), &mut cx).unwrap(),
        &mut fine,
    )
    .unwrap();
    assert_eq!(fine, b"reads\n");

    // A merge module's missing or broken cabinet: opening says so once.
    for name in ["msm-no-cab.msm", "msm-not-cab.msm"] {
        let mut cx = SimpleCtx::new();
        open(&corpus(name), &OpenOptions::default(), &mut cx).unwrap();
        assert!(
            cx.warnings
                .iter()
                .any(|w| w.contains("MergeModule.CABinet")),
            "{name}: {:?}",
            cx.warnings
        );
    }
}

/// Unsafe names in a patch are left to SafeFs: the packed `..` storage and its file stay inside
/// the destination, `CON` is renamed; a stream that fails doesn't stop the rest.
#[test]
fn compound_files_extract_safely() {
    let (r, inside) = extract("msp-names.msp", FsOptions::default());
    let r = r.unwrap();
    assert!(inside.iter().any(|p| p == "_CON"), "{inside:?}");
    assert!(inside.iter().any(|p| p == "[2]ctl"), "{inside:?}");
    assert!(!inside.iter().any(|p| p.contains("escaped")), "{inside:?}");
    assert!(r.renamed_total >= 1, "{r:?}");

    // Extraction stops at the stream that claims 4 GiB, as at any damaged entry, on one worker
    // and on four; a stream before it still queued on four is dropped with the sink (docs/M9.md
    // §15), so the two aren't compared, as `extract` does. A test reads past it and fails only it.
    for threads in [1, 4] {
        let opts = OpenOptions {
            threads,
            ..OpenOptions::default()
        };
        let (r, inside) = extract_with("mst-claim.mst", FsOptions::default(), &opts);
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "on {threads}");
        assert!(
            !inside.iter().any(|p| p == "claim" || p == "fine"),
            "on {threads}: {inside:?}"
        );
    }
    let report = ops::test(
        &corpus("mst-claim.mst"),
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let failed: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(failed, ["claim"]);

    let (r, inside) = extract("msp-slash.msp", FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt);
    assert!(inside.is_empty(), "{inside:?}");
}
