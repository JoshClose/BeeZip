//! ZOO (docs/M6.md §4): unarc-rs's samples, and archives built here byte by byte, through
//! `open`, `ops::extract` and `ops::test`. (BeeZip's reader also matched zoo 2.10's own
//! archives of every method, made in Docker; those aren't committed.)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use beezip_core::{
    Confidence, EntryKind, ErrorKind, FormatId, FsOptions, OpenOptions, Selection, SimpleCtx,
    SkipReason, detect_path, open, ops,
};

fn unarc(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty/unarc")
        .join(name)
}

/// What every unarc-rs sample holds: the Apache License, as unarc-rs's tests say.
fn license() -> Vec<u8> {
    fs::read(unarc("LICENSE-APACHE")).unwrap()
}

fn read_entry(path: &Path, id: usize) -> beezip_core::Result<Vec<u8>> {
    let mut cx = SimpleCtx::new();
    let mut opened = open(path, &OpenOptions::default(), &mut cx)?;
    let mut out = Vec::new();
    opened
        .reader
        .open_entry(id, &mut cx)?
        .read_to_end(&mut out)
        .map_err(|e| beezip_core::Error::from_io(&e))?;
    Ok(out)
}

#[test]
fn unarc_samples_read_in_every_method() {
    for (name, method, path) in [
        ("zoo/store.zoo", "Store", "../license"),
        ("zoo/default.zoo", "LZW", "license"),
        ("zoo/high_per.zoo", "LH5", "../license"),
    ] {
        let file = unarc(name);
        let det = detect_path(&file, &Default::default()).unwrap();
        assert_eq!(det.format(), Some(FormatId::Zoo), "{name}");
        assert_eq!(det.layers[0].confidence, Confidence::Certain, "{name}");
        let mut cx = SimpleCtx::new();
        let mut opened = open(&file, &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 1, "{name}");
        let e = &entries[0];
        // Two of them keep the folder `..` they were added from.
        assert_eq!(e.path, path, "{name}");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.method.as_deref(), Some(method), "{name}");
        assert_eq!(e.size, Some(11_357));
        assert!(e.modified.is_some());
        assert_eq!(read_entry(&file, 0).unwrap(), license(), "{name}");
        let report = ops::test(&file, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
        assert!(report.ok(), "{name}: {report:?}");
        assert_eq!(report.bytes, 11_357);
    }
}

#[test]
fn extracting_refuses_the_samples_climbing_out() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let r = ops::extract(
        &unarc("zoo/default.zoo"),
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(r.files, 1);
    assert_eq!(fs::read(dest.join("license")).unwrap(), license());

    let dest = dir.path().join("out2");
    let r = ops::extract(
        &unarc("zoo/high_per.zoo"),
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(r.files, 0);
    assert_eq!(r.skipped[0].reason, SkipReason::Traversal);
    assert!(!dir.path().join("license").exists());
}

#[test]
fn a_wrong_crc_is_damage() {
    let file = unarc("broken/wrongcrc16.zoo");
    let mut cx = SimpleCtx::new();
    let report = ops::test(&file, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(report.errors_total, 1);
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    assert!(report.errors[0].message.contains("CRC-16"), "{report:?}");
    let err = read_entry(&file, 0).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt);
}

const TAG: u32 = 0xFDC4_A7DC;

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

/// A ZOO of stored type-2 entries: `(folder, long name, data)`.
fn zoo(files: &[(&[u8], &[u8], &[u8])]) -> Vec<u8> {
    let mut out = b"ZOO 2.10 Archive.\x1a\0\0".to_vec();
    out.extend(TAG.to_le_bytes());
    out.extend(42u32.to_le_bytes());
    out.extend(42u32.wrapping_neg().to_le_bytes());
    out.extend([2, 0, 1, 0, 0, 0, 0, 0, 0, 3]);
    for (dir, name, data) in files {
        let mut var = vec![name.len() as u8 + 1, dir.len() as u8 + 1];
        var.extend(*name);
        var.push(0);
        var.extend(*dir);
        var.push(0);
        // Unix, rw-r--r--, no generations.
        var.extend([0, 0, 0xA4, 0x01, 0x40, 0, 0, 0]);
        let offset = out.len() + 56 + var.len();
        out.extend(TAG.to_le_bytes());
        out.extend([2, 0]);
        out.extend(((offset + data.len()) as u32).to_le_bytes());
        out.extend((offset as u32).to_le_bytes());
        // 2026-01-01 00:00, with no time zone.
        out.extend((((2026u16 - 1980) << 9) | (1 << 5) | 1).to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(crc16(data).to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend(b"SHORT.TXT\0\0\0\0");
        out.extend((var.len() as u16).to_le_bytes());
        out.push(127);
        out.extend([0, 0]);
        out.extend(&var);
        out.extend(*data);
    }
    out.extend(TAG.to_le_bytes());
    out.extend([2, 0]);
    out.extend([0; 60]);
    out
}

/// A ZOO built here, under a name that doesn't say ZOO: found by its header, listed with its
/// folders and long names, extracted.
#[test]
fn a_zoo_built_here_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("backup.bin");
    fs::write(
        &file,
        zoo(&[
            (b"docs/deep", b"Notes for later.txt", b"notes"),
            (b"src", b"main.c", b"int main(void) { return 0; }\n"),
            (b"\x8Erger", b"empty", b""),
        ]),
    )
    .unwrap();
    let det = detect_path(&file, &Default::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::Zoo));
    let mut cx = SimpleCtx::new();
    let mut opened = open(&file, &OpenOptions::default(), &mut cx).unwrap();
    let paths: Vec<String> = opened
        .reader
        .entries(&mut cx)
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(
        paths,
        ["docs/deep/Notes for later.txt", "src/main.c", "Ärger/empty"]
    );
    let dest = dir.path().join("out");
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
    assert_eq!(
        fs::read(dest.join("docs/deep/Notes for later.txt")).unwrap(),
        b"notes"
    );
    assert_eq!(fs::read(dest.join("Ärger/empty")).unwrap(), b"");
    // Only some of it.
    let dest = dir.path().join("some");
    let r = ops::extract(
        &file,
        &dest,
        &Selection::new(&["src".to_owned()], &[], &[]).unwrap(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(r.files, 1);
    assert!(dest.join("src/main.c").exists());
}

#[test]
fn a_cut_or_garbled_zoo_fails_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let whole = zoo(&[(b"d", b"a.txt", b"some data here")]);
    for (name, bytes) in [
        ("cut.zoo", whole[..whole.len() - 70].to_vec()),
        ("header.zoo", whole[..20].to_vec()),
        ("empty.zoo", Vec::new()),
    ] {
        let file = dir.path().join(name);
        fs::write(&file, &bytes).unwrap();
        let err = open(&file, &OpenOptions::default(), &mut SimpleCtx::new())
            .err()
            .unwrap_or_else(|| panic!("{name} opened"));
        assert!(
            matches!(err.kind, ErrorKind::Corrupt | ErrorKind::UnsupportedFormat),
            "{name}: {err}"
        );
    }
}
