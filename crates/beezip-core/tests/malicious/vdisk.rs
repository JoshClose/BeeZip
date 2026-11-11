//! The malicious VMDK, QCOW2 and VDI files (docs/M8.md §9), from `tests/fixtures/make-vdisk.sh`,
//! read by BeeZip's own readers: each is refused cleanly or read within its limits.

use std::time::{Duration, Instant};

use beezip_core::{External, format::volume::DiskReader, source::Source};

use super::*;

/// The error opening `name` with BeeZip's own reader gives, at once.
fn native(name: &str, kind: External) -> beezip_core::Error {
    let t = Instant::now();
    let source = Source::new(&corpus(name), Vec::new(), &OpenOptions::default()).unwrap();
    let err = DiskReader::open(source, kind, &mut SimpleCtx::new())
        .err()
        .unwrap_or_else(|| panic!("{name} opened"));
    assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    err
}

/// `name` refused as it opens, natively and through `open` (which routes it there: none of these
/// goes to 7-Zip), and extracting it writes nothing.
fn refused(name: &str, kind: External, as_: ErrorKind) -> beezip_core::Error {
    let err = native(name, kind);
    assert_eq!(err.kind, as_, "{name}: {err}");
    let e = open(
        &corpus(name),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .err()
    .unwrap_or_else(|| panic!("{name} opened"));
    assert_eq!(e.kind, as_, "{name}: {e}");
    let (r, inside) = extract(name, FsOptions::default());
    assert_eq!(r.unwrap_err().kind, as_, "{name}");
    assert!(inside.is_empty(), "{name}: {inside:?}");
    err
}

/// Backing files that come back to the image (qemu-img 8.2.2 never ends on them), a VMDK child
/// whose parent is itself, two VDIs each the other's parent: `Corrupt` at once.
#[test]
fn chains_that_loop_are_refused_at_once() {
    for (name, kind) in [
        ("vdisk-loop-a.qcow2", External::Qcow2),
        ("vdisk-self.qcow2", External::Qcow2),
        ("vdisk-vmdk-self.vmdk", External::Vmdk),
        ("vdisk-vdi-a.vdi", External::Vdi),
    ] {
        let e = refused(name, kind, ErrorKind::Corrupt);
        assert!(e.message.contains("its chain loops"), "{name}: {e}");
    }
}

/// Backing files and extents that aren't files: qemu's json: (which qemu-img follows to any
/// file), nbd://, a UNC path (which would send the user's NTLM hash to the server), a physical
/// drive. `Unsafe`, never handed to 7-Zip.
#[test]
fn names_that_arent_files_are_never_opened() {
    for (name, kind) in [
        ("vdisk-json.qcow2", External::Qcow2),
        ("vdisk-nbd.qcow2", External::Qcow2),
        ("vdisk-unc.qcow2", External::Qcow2),
        ("vdisk-device.vmdk", External::Vmdk),
    ] {
        let e = refused(name, kind, ErrorKind::Unsafe);
        assert!(e.message.contains("never opened"), "{name}: {e}");
    }
}

/// Grains of 1 GiB (rust-img-vmdk 0.5.1 allocates one for this 157 KB file): refused from the
/// header, before any grain is read.
#[test]
fn a_grain_of_1_gib_is_refused_from_the_header() {
    let e = native("vdisk-grain-1g.vmdk", External::Vmdk);
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    assert!(e.message.contains("grains of 1073741824 bytes"), "{e}");
}

/// 2 TiB of nothing, an empty QCOW2 and a ZERO extent: listed as one raw file whose files hold
/// none of it, and refused by the ratio limit before a byte is read or written.
#[test]
fn two_tib_of_nothing_is_refused_before_it_is_read() {
    for name in ["vdisk-2t.qcow2", "vdisk-zero-2t.vmdk"] {
        let t = Instant::now();
        let mut cx = SimpleCtx::new();
        let mut opened = open(&corpus(name), &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        let stem = name.rsplit_once('.').unwrap().0;
        assert_eq!(entries.len(), 1, "{name}");
        assert_eq!(entries[0].path, format!("{stem}.img"), "{name}");
        assert_eq!(
            (entries[0].size, entries[0].packed_size),
            (Some(2 << 40), Some(0)),
            "{name}"
        );
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::LimitExceeded, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
        let err = ops::test(
            &corpus(name),
            &Selection::all(),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::LimitExceeded, "{name}");
        assert!(t.elapsed() < Duration::from_secs(10), "{name}");
    }
}

/// The other side of the ratio rule (docs/M8.md §3.7): an ordinary file of 80 MiB of zeros, which
/// the compressed QCOW2 and the VMDK keep as holes, reads none of the image, past the 64 MiB
/// grace. Counting the disk's bytes, not the image's, it extracts.
#[test]
fn a_file_of_zeros_in_holes_is_not_a_bomb() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty/vdisk");
    for name in ["z-deflate.qcow2", "z.vmdk"] {
        let dest = tempfile::tempdir().unwrap();
        let r = ops::extract(
            &dir.join(name),
            dest.path(),
            &Selection::all(),
            &OpenOptions::default(),
            FsOptions::default(),
            &mut SimpleCtx::new(),
        );
        assert!(r.is_ok(), "{name}: {r:?}");
        let zeros = dest.path().join("zeros.bin");
        assert_eq!(fs::metadata(&zeros).unwrap().len(), 80 << 20, "{name}");
    }
}
