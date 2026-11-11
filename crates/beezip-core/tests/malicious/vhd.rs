//! The malicious VHD and VHDX files (docs/M8.md §9), from `tests/fixtures/make-vhd.ps1`, read by
//! BeeZip's own reader: each is refused cleanly or read within its limits.

use std::time::{Duration, Instant};

use super::*;

/// A dynamic VHDX of 2 TiB with nothing in it: listed as one raw file of 2 TiB that its file holds
/// none of, and refused by the claim check before anything is read or written, by extracting,
/// testing and reading the entry.
#[test]
fn an_empty_2_tib_vhdx_is_refused_at_once() {
    let name = "vhdx-2t-empty.vhdx";
    let t = Instant::now();
    let mut cx = SimpleCtx::new();
    let mut opened = open(&corpus(name), &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "vhdx-2t-empty.img");
    assert_eq!(
        (entries[0].size, entries[0].packed_size),
        (Some(2 << 40), Some(0))
    );
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.external.unwrap().levels, ["vhdx"]);
    let err = opened.reader.open_entry(0, &mut cx).err().unwrap();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
    let (r, inside) = extract(name, FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::LimitExceeded);
    assert!(inside.is_empty(), "{inside:?}");
    let err = ops::test(
        &corpus(name),
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
    assert!(t.elapsed() < Duration::from_secs(5));
}

/// Two VHDs each naming the other as its parent, and one naming itself: `Corrupt` as they open,
/// at once, never followed round (qemu-img never finishes on such a loop).
#[test]
fn vhd_parent_loops_are_corrupt() {
    for name in ["vhd-loop-a.vhd", "vhd-loop-b.vhd", "vhd-self-loop.vhd"] {
        let t = Instant::now();
        let err = open(
            &corpus(name),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        )
        .err()
        .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(err.kind, ErrorKind::Corrupt, "{name}: {err}");
        assert!(err.message.contains("loops"), "{name}: {err}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
        let (r, inside) = extract(name, FsOptions::default());
        assert_eq!(r.unwrap_err().kind, ErrorKind::Corrupt, "{name}");
        assert!(inside.is_empty(), "{name}: {inside:?}");
    }
}

/// A VHD whose parent is named only by a UNC path: `Unsafe`, and the path is never opened
/// (opening it would send the user's NTLM hash to whoever wrote the disk), nor handed to 7-Zip.
#[test]
fn a_vhd_parent_on_the_network_is_unsafe() {
    let name = "vhd-unc-parent.vhd";
    let err = open(
        &corpus(name),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .err()
    .unwrap();
    assert_eq!(err.kind, ErrorKind::Unsafe, "{err}");
    assert!(err.message.contains(r"\\beezip.invalid\share"), "{err}");
    let (r, inside) = extract(name, FsOptions::default());
    assert_eq!(r.unwrap_err().kind, ErrorKind::Unsafe);
    assert!(inside.is_empty(), "{inside:?}");
}
