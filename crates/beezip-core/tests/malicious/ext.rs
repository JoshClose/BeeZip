//! The malicious ext cases (docs/M7.md §10): the images on which fuzzing fstool 0.5.2's ext
//! module aborted the process or panicked (`target/m7-spikes/ext/REPORT.md`), now read by
//! BeeZip's own reader, which refuses each cleanly or reads it within its limits.
//!
//! - `ext4-groups.img` (the spike's `crafted/groups.img`): about 4 billion block groups, one block
//!   each. fstool's group layout asked for 128 GiB (`layout.rs:683`).
//! - `ext4-flex-shift.img` (fuzz repro `000-panic-…-layout-rs-680-9`): 2^212 groups to a flex
//!   group, and 2^42 blocks. fstool shifts past 32 bits (`layout.rs:680`), a panic with overflow
//!   checks.
//! - `ext4-symlink-size.img` (fuzz repro `001-alloc-cap-…-mod-rs-4961`, cut short) and
//!   `ext4-symlink-100g.img` (`crafted/symlink-100g.img`): a symlink claiming 100 GB. fstool read
//!   it into memory past its own 512 MiB cap (`mod.rs:4961`).

use beezip_core::{EntryKind, External, format::volume::DiskReader, source::Source};

use super::*;

/// Superblocks fstool's layout choked on are `Corrupt` when the image opens.
#[test]
fn ext_superblocks_that_fstool_choked_on_are_corrupt() {
    for (name, says) in [
        ("ext4-groups.img", "a group has 1 blocks"),
        ("ext4-flex-shift.img", "block groups"),
    ] {
        let err = open(
            &corpus(name),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        )
        .err()
        .unwrap();
        assert_eq!(err.kind, ErrorKind::Corrupt, "{name}: {err}");
        assert!(err.message.contains(says), "{name}: {err}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
    }
}

/// Opened as a bare HFS+ or APFS volume, as the `part` fuzz target opens every input, an ext
/// image is `UnsupportedOperation` without fstool's detection running fstool's ext layout,
/// which asked for 128 GiB on `ext4-groups.img` (CI's fuzz run, 2026-11-10).
#[test]
fn ext_images_opened_as_apple_volumes_never_reach_fstools_ext() {
    for name in ["ext4-groups.img", "ext4-flex-shift.img"] {
        for kind in [External::Hfs, External::Apfs] {
            let source = Source::new(&corpus(name), Vec::new(), &OpenOptions::default()).unwrap();
            let err = DiskReader::open(source, kind, &mut SimpleCtx::new())
                .err()
                .unwrap();
            assert_eq!(
                err.kind,
                ErrorKind::UnsupportedOperation,
                "{name}, {kind:?}: {err}"
            );
        }
    }
}

/// A symlink claiming 100 GB is listed as a special file, with a warning, and skipped; the rest
/// extracts.
#[test]
fn ext_symlinks_of_100_gb_are_left_out() {
    for name in ["ext4-symlink-size.img", "ext4-symlink-100g.img"] {
        let mut cx = SimpleCtx::new();
        let mut opened = open(&corpus(name), &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        let link = entries.iter().find(|e| e.path == "sparse.bin").unwrap();
        assert_eq!(link.kind, EntryKind::Other, "{name}");
        assert!(
            cx.warnings.iter().any(|w| w.contains("more than 4096")),
            "{name}: {:?}",
            cx.warnings
        );
        drop(opened);
        let (r, inside) = extract(name, FsOptions::default());
        let r = r.unwrap();
        assert_eq!(reasons(&r), [SkipReason::Unsupported], "{name}: {r:?}");
        assert_eq!(inside, ["lost+found", "safe.txt"], "{name}");
    }
}
