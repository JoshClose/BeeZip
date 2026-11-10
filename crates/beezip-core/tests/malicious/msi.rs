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
                let info = o.reader.info(&mut cx).unwrap();
                assert_eq!(
                    info.external.unwrap().backend,
                    None,
                    "{name}: read natively"
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
