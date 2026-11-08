//! ARC and PAK (docs/M6.md §4): unarc-rs's samples, and archives built here byte by byte,
//! through `open`, `ops::extract` and `ops::test`. (BeeZip's reader also matched ARC 5.21q's
//! own archives, stored, crunched, squashed and encrypted, made in Docker; those aren't
//! committed.)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use beezip_core::{
    Confidence, Encryption, ErrorKind, FormatId, FsOptions, OpenOptions, Selection, SimpleCtx,
    detect_path, open, ops,
};

fn unarc(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty/unarc")
        .join(name)
}

/// What most unarc-rs samples hold: the Apache License, as unarc-rs's tests say.
fn license() -> Vec<u8> {
    fs::read(unarc("LICENSE-APACHE")).unwrap()
}

/// unarc-rs's `shifting_text`: the license, 12 000 bytes from a 23-letter alphabet, the
/// license again. ARC 5.21 clears its table part-way.
fn shifting_text() -> Vec<u8> {
    let license = license();
    let mut x: u32 = 12345;
    let noise = (0..12000).map(|_| {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
        0x41 + ((x >> 16) % 23) as u8
    });
    license
        .iter()
        .copied()
        .chain(noise)
        .chain(license.iter().copied())
        .collect()
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read_entry(path: &Path, id: usize, cx: &mut SimpleCtx) -> beezip_core::Result<Vec<u8>> {
    let mut opened = open(path, &OpenOptions::default(), cx)?;
    let mut out = Vec::new();
    opened
        .reader
        .open_entry(id, cx)?
        .read_to_end(&mut out)
        .map_err(|e| beezip_core::Error::from_io(&e))?;
    Ok(out)
}

#[test]
fn unarc_samples_read_in_every_method_they_have() {
    for (name, method) in [
        ("arc/store.arc", "Store"),
        ("arc/crunch.arc", "Crunched"),
        ("arc/crunch2.arc", "Crunched"),
        ("arc/squashed.arc", "Squashed"),
        ("arc/license_crunched.pak", "Crunched"),
        ("arc/license_squashed.pak", "Squashed"),
    ] {
        let file = unarc(name);
        let det = detect_path(&file, &Default::default()).unwrap();
        assert_eq!(det.format(), Some(FormatId::Arc), "{name}");
        assert_eq!(det.layers[0].confidence, Confidence::Certain, "{name}");
        let mut cx = SimpleCtx::new();
        let mut opened = open(&file, &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 1, "{name}");
        assert_eq!(entries[0].path, "LICENSE", "{name}");
        assert_eq!(entries[0].method.as_deref(), Some(method), "{name}");
        assert_eq!(read_entry(&file, 0, &mut cx).unwrap(), license(), "{name}");
        let report = ops::test(&file, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
        assert!(report.ok(), "{name}: {report:?}");
    }
    // ARC 5.21q's own: a CLEAR part-way through a group of codes, and 13-bit codes.
    for name in ["arc/crunch_clear.arc", "arc/squash_clear.arc"] {
        let mut cx = SimpleCtx::new();
        assert_eq!(
            read_entry(&unarc(name), 0, &mut cx).unwrap(),
            shifting_text(),
            "{name}"
        );
    }
}

/// A CP/M archive from 1985: squeezed and packed.
#[test]
fn squeezed_and_packed_entries_read() {
    let file = unarc("arc/cpm.arc");
    let mut cx = SimpleCtx::new();
    let mut opened = open(&file, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let listed: Vec<(&str, &str)> = entries
        .iter()
        .map(|e| (e.path.as_str(), e.method.as_deref().unwrap()))
        .collect();
    assert_eq!(listed, [("DDTZ.COM", "Squeezed"), ("READ.COM", "Packed")]);
    // unarc-rs's tests/arc/DDTZ.COM and READ.COM.
    let dir = tempfile::tempdir().unwrap();
    let r = ops::extract(
        &file,
        dir.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(r.files, 2);
    assert_eq!(
        sha256(&fs::read(dir.path().join("DDTZ.COM")).unwrap()),
        "fc2769fe9c0c473e8dde316112aed12970c97b38f5cef9420b21015cfac0d2c9"
    );
    assert_eq!(
        sha256(&fs::read(dir.path().join("READ.COM")).unwrap()),
        "25784f644057784a5d9e5143e07f48e2be384eb00a8619a76725e6dfcb327e79"
    );
    let t = entries[0].modified.unwrap();
    let year = 1970 + t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 31_557_600;
    assert_eq!(year, 1985);
}

/// PAK's crushed and distilled entries are listed, and refused when read (docs/M6.md §14).
#[test]
fn pak_methods_are_refused() {
    for (name, method) in [
        ("arc/license_crushed.pak", "crushed"),
        ("arc/license.pak", "distilled"),
    ] {
        let file = unarc(name);
        let mut cx = SimpleCtx::new();
        let mut opened = open(&file, &OpenOptions::default(), &mut cx).unwrap();
        let e = opened.reader.entries(&mut cx).unwrap()[0].clone();
        assert_eq!(e.path, "LICENSE");
        let err = opened.reader.open_entry(0, &mut cx).err().unwrap();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation, "{name}");
        assert!(
            err.message.contains("LICENSE") && err.message.contains(method),
            "{err}"
        );
        let report = ops::test(&file, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
        assert_eq!(report.errors_total, 1);
        assert_eq!(report.errors[0].kind, ErrorKind::UnsupportedOperation);
        let dir = tempfile::tempdir().unwrap();
        let err = ops::extract(
            &file,
            dir.path(),
            &Selection::all(),
            &OpenOptions::default(),
            FsOptions::default(),
            &mut cx,
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation, "{name}: {err}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0, "{name}");
    }
}

#[test]
fn a_wrong_crc_is_damage() {
    let file = unarc("broken/wrongcrc16.arc");
    let mut cx = SimpleCtx::new();
    let report = ops::test(&file, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(report.errors_total, 1);
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    assert!(report.errors[0].message.contains("CRC-16"), "{report:?}");
    let dir = tempfile::tempdir().unwrap();
    let err = ops::extract(
        &file,
        dir.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt);
}

/// unarc-rs's encrypted sample (crunched, password `SECRET`): asked for when its data fails.
#[test]
fn the_password_is_asked_for() {
    let file = unarc("arc/license_cypted.arc");
    let mut cx = SimpleCtx::new().with_password("SECRET");
    let report = ops::test(&file, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(read_entry(&file, 0, &mut cx).unwrap(), license());

    let dir = tempfile::tempdir().unwrap();
    let r = ops::extract(
        &file,
        dir.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new().with_passwords(&["wrong", "SECRET"]),
    )
    .unwrap();
    assert_eq!(r.files, 1);
    assert_eq!(fs::read(dir.path().join("LICENSE")).unwrap(), license());

    // Read, the entry is known to need one.
    let mut opened = open(&file, &OpenOptions::default(), &mut cx).unwrap();
    let mut sink = beezip_core::TestSink::default();
    opened
        .reader
        .extract(&Selection::all(), &mut sink, &mut cx)
        .unwrap();
    assert!(opened.reader.entries(&mut cx).unwrap()[0].encrypted);
    assert_eq!(
        opened.reader.info(&mut cx).unwrap().encryption,
        Encryption::All
    );

    // Nobody to ask: damage. A wrong password: a wrong password, and nothing left behind.
    let report = ops::test(
        &file,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    let dir = tempfile::tempdir().unwrap();
    let err = ops::extract(
        &file,
        dir.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new().with_password("nope"),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongPassword);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// One entry: `packed` under `method`, for `data`.
fn entry(method: u8, name: &[u8], packed: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = vec![0x1A, method];
    let mut n = [0u8; 13];
    n[..name.len()].copy_from_slice(name);
    h.extend(n);
    h.extend((packed.len() as u32).to_le_bytes());
    // 2026-01-01 00:00.
    h.extend((((2026u16 - 1980) << 9) | (1 << 5) | 1).to_le_bytes());
    h.extend(0u16.to_le_bytes());
    h.extend(crc16(data).to_le_bytes());
    h.extend((data.len() as u32).to_le_bytes());
    h.extend(packed);
    h
}

/// An ARC built here, under a name that doesn't say ARC: stored and packed entries.
#[test]
fn an_arc_built_here_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("files.bin");
    let mut a = entry(2, b"HELLO.TXT", b"hello", b"hello");
    // "x" ten times, then a 0x90.
    a.extend(entry(
        3,
        b"RUNS.BIN",
        b"x\x90\x0a\x90\x00",
        b"xxxxxxxxxx\x90",
    ));
    a.extend(entry(2, b"\x8ERGER.TXT", b"", b""));
    a.extend([0x1A, 0]);
    fs::write(&file, &a).unwrap();
    let det = detect_path(&file, &Default::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::Arc));
    let dest = dir.path().join("out");
    let mut cx = SimpleCtx::new();
    let r = ops::extract(
        &file,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(r.files, 3);
    assert_eq!(fs::read(dest.join("HELLO.TXT")).unwrap(), b"hello");
    assert_eq!(fs::read(dest.join("RUNS.BIN")).unwrap(), b"xxxxxxxxxx\x90");
    assert_eq!(fs::read(dest.join("ÄRGER.TXT")).unwrap(), b"");
    let report = ops::test(&file, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
    assert!(report.ok());
    assert_eq!(report.entries, 3);
}

/// A file named `.arc` that isn't one: found by its name only, and it fails to open.
#[test]
fn a_file_named_arc_that_isnt_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("notes.arc");
    fs::write(&file, b"just some text, not an archive").unwrap();
    let det = detect_path(&file, &Default::default()).unwrap();
    assert_ne!(
        det.layers.first().map(|l| l.confidence),
        Some(Confidence::Certain)
    );
    let err = open(&file, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert!(
        matches!(err.kind, ErrorKind::Corrupt | ErrorKind::UnsupportedFormat),
        "{err}"
    );
}
