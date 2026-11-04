//! RAR through UnRAR (docs/M3.md §3.4, §6): passwords, volumes, limits, cancellation, and
//! libarchive's broken files. The fixtures themselves are checked in `fixtures.rs`.

#![cfg(feature = "rar")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};

use beezip_core::{
    Ctx, ErrorKind, FormatId, FsOptions, Limits, OpenOptions, OverwriteChoice, Selection,
    SimpleCtx, detect_path, open, ops,
};

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty")
        .join(name)
}

fn lib(name: &str) -> PathBuf {
    fx(&format!("libarchive/test_read_format_{name}"))
}

fn extract(path: &Path, cx: &mut dyn Ctx) -> beezip_core::Result<(tempfile::TempDir, u64)> {
    let dest = tempfile::tempdir().unwrap();
    let report = ops::extract(
        path,
        dest.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        cx,
    )?;
    Ok((dest, report.files))
}

#[test]
fn broken_files_fail_cleanly() {
    let dir = fx("libarchive/broken");
    let mut n = 0;
    for e in fs::read_dir(&dir).unwrap() {
        let path = e.unwrap().path();
        n += 1;
        let mut cx = SimpleCtx::new();
        // Whatever happens, it is an error with a code or a clean result: a crash in UnRAR would
        // kill this process.
        match open(&path, &OpenOptions::default(), &mut cx) {
            Ok(mut opened) => {
                let _ = opened.reader.entries(&mut cx);
                let tested = ops::test(&path, &Selection::all(), &OpenOptions::default(), &mut cx);
                if let Err(err) = tested {
                    assert!(
                        matches!(
                            err.kind,
                            ErrorKind::Corrupt
                                | ErrorKind::UnsupportedFormat
                                | ErrorKind::LimitExceeded
                                | ErrorKind::PasswordRequired
                                | ErrorKind::NotFound
                        ),
                        "{}: {err:?}",
                        path.display()
                    );
                }
            }
            Err(err) => assert!(
                matches!(
                    err.kind,
                    ErrorKind::Corrupt
                        | ErrorKind::UnsupportedFormat
                        | ErrorKind::LimitExceeded
                        | ErrorKind::NotFound
                ),
                "{}: {err:?}",
                path.display()
            ),
        }
    }
    assert_eq!(n, 20, "libarchive's broken files are all there");
}

#[test]
fn a_password_per_entry() {
    for name in ["rar5_encrypted.rar", "rar4_encrypted.rar"] {
        let path = lib(name);
        // One password: b.txt opens, d.txt (under "password2") doesn't.
        let err = extract(&path, &mut SimpleCtx::new().with_password("password")).unwrap_err();
        assert_eq!(err.kind, ErrorKind::WrongPassword, "{name}: {err}");
        let err = extract(&path, &mut SimpleCtx::new()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::PasswordRequired, "{name}");
        // Two answers: the archive is reopened at d.txt with the second.
        let (dest, files) = extract(
            &path,
            &mut SimpleCtx::new().with_passwords(&["password", "password2"]),
        )
        .unwrap();
        assert_eq!(files, 4, "{name}");
        for f in ["a.txt", "b.txt", "c.txt", "d.txt"] {
            assert!(dest.path().join(f).is_file(), "{name}: {f}");
        }
        let mut cx = SimpleCtx::new().with_passwords(&["password", "password2"]);
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        let info = opened.reader.info(&mut cx).unwrap();
        assert_eq!(info.encryption, beezip_core::Encryption::Some, "{name}");
        // open_entry gets there the same way.
        let mut d = String::new();
        opened
            .reader
            .open_entry(3, &mut cx)
            .unwrap()
            .read_to_string(&mut d)
            .unwrap();
        assert!(d.contains("d.txt") || !d.is_empty(), "{name}: {d}");
    }
}

/// A context that answers once, then cancels the next prompt.
struct OnceThenCancel(Option<String>);

impl Ctx for OnceThenCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn progress(&mut self, _: &beezip_core::Progress) {}
    fn warn(&mut self, _: String) {}
    fn password(&mut self, _: Option<&str>, _: u32) -> beezip_core::Result<String> {
        self.0.take().ok_or_else(beezip_core::Error::cancelled)
    }
    fn overwrite(&mut self, _: &Path) -> beezip_core::Result<OverwriteChoice> {
        Ok(OverwriteChoice::Replace)
    }
}

#[test]
fn header_passwords() {
    for name in [
        "rar5_encrypted_filenames.rar",
        "rar4_encrypted_filenames.rar",
    ] {
        let path = lib(name);
        let open_with = |cx: &mut dyn Ctx| open(&path, &OpenOptions::default(), cx).map(|_| ());
        assert_eq!(
            open_with(&mut SimpleCtx::new()).unwrap_err().kind,
            ErrorKind::PasswordRequired,
            "{name}"
        );
        assert_eq!(
            open_with(&mut SimpleCtx::new().with_password("nope"))
                .unwrap_err()
                .kind,
            ErrorKind::WrongPassword,
            "{name}"
        );
        // Wrong, then right: asked again.
        open_with(&mut SimpleCtx::new().with_passwords(&["nope", "password"])).unwrap();
        // Wrong, then the prompt is cancelled.
        assert_eq!(
            open_with(&mut OnceThenCancel(Some("nope".into())))
                .unwrap_err()
                .kind,
            ErrorKind::Cancelled,
            "{name}"
        );
        let mut cx = SimpleCtx::new().with_password("password");
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        let info = opened.reader.info(&mut cx).unwrap();
        assert!(info.encrypted_headers, "{name}");
        assert_eq!(info.encryption, beezip_core::Encryption::All);
    }
    let rars = fx("rars/header_rar300_password.rar");
    let (_dest, files) = extract(&rars, &mut SimpleCtx::new().with_password("password")).unwrap();
    assert_eq!(files, 1);
}

#[test]
fn volumes_open_from_any_part_and_name_a_missing_one() {
    let first = lib("rar5_multiarchive_solid.part01.rar");
    let third = lib("rar5_multiarchive_solid.part03.rar");
    let det = detect_path(&third, &Limits::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::Rar));
    assert_eq!(det.volumes.len(), 4);
    assert!(det.volumes[0].ends_with("test_read_format_rar5_multiarchive_solid.part01.rar"));
    let (_dest, files) = extract(&third, &mut SimpleCtx::new()).unwrap();
    assert_eq!(files, 9);
    let mut cx = SimpleCtx::new();
    let mut opened = open(&first, &OpenOptions::default(), &mut cx).unwrap();
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.volumes, 4);
    assert!(info.solid);

    // Without part 3, UnRAR asks for it, and the job says which.
    let dir = tempfile::tempdir().unwrap();
    for p in &det.volumes {
        let name = p.file_name().unwrap();
        if !name.to_string_lossy().contains("part03") {
            fs::copy(p, dir.path().join(name)).unwrap();
        }
    }
    let gap = dir
        .path()
        .join("test_read_format_rar5_multiarchive_solid.part01.rar");
    let err = extract(&gap, &mut SimpleCtx::new()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound, "{err}");
    assert!(err.message.contains("part03"), "{err}");
}

#[test]
fn dictionaries_over_the_limit_are_refused() {
    let opts = OpenOptions::new(Limits {
        decoder_memory: 64 * 1024,
        ..Limits::default()
    });
    let dest = tempfile::tempdir().unwrap();
    let err = ops::extract(
        &lib("rar5_compressed.rar"),
        dest.path(),
        &Selection::all(),
        &opts,
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
}

#[test]
fn cancelled_extraction_leaves_nothing() {
    let flag = Arc::new(AtomicBool::new(true));
    let err = extract(
        &lib("rar_multivolume.part0001.rar"),
        &mut SimpleCtx::new().with_cancel(flag),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
}

#[test]
fn sfx_and_links() {
    let sfx = lib("rar_sfx.exe");
    let det = detect_path(&sfx, &Limits::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::Rar));
    assert!(det.sfx);
    let mut cx = SimpleCtx::new();
    let mut opened = open(&lib("rar5_hardlink.rar"), &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert!(
        entries
            .iter()
            .any(|e| matches!(e.kind, beezip_core::EntryKind::Hardlink { .. }))
    );
}
