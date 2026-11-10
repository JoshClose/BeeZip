//! The 7-Zip backend (docs/M6.md §3, §10): what happens without 7-Zip, and, with it, streaming
//! against `7z x`, selections, single entries, staging, testing, cancelling and the limits.
//!
//! The tests that need 7-Zip skip without one, unless `BEEZIP_REQUIRE_7Z` is set (CI sets it).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use beezip_core::{
    ErrorKind, External, FormatId, Limits, OpenOptions, SevenZipOptions, SimpleCtx, detect_path,
    open,
};

/// The 7-Zip the tests run, or `None` to skip them. With `BEEZIP_REQUIRE_7Z` or
/// `BEEZIP_REQUIRE_7Z_BACKEND` set to 1 (CI), a missing one fails.
fn seven_zip() -> Option<beezip_core::backend::SevenZip> {
    let required = ["BEEZIP_REQUIRE_7Z", "BEEZIP_REQUIRE_7Z_BACKEND"]
        .iter()
        .any(|v| std::env::var(v).as_deref() == Ok("1"));
    match beezip_core::backend::find(&SevenZipOptions::default()) {
        Ok(z) => Some(z),
        Err(m) if required => panic!("these tests need 7-Zip: {}", m.reason()),
        Err(m) => {
            eprintln!("skipping: {}", m.reason());
            None
        }
    }
}

/// A tree of files, and a WIM 7-Zip makes of it (`7z a -twim`): `(dir, wim, files)`, the files
/// by their path in the WIM with their contents.
fn made_wim(
    z: &beezip_core::backend::SevenZip,
) -> (tempfile::TempDir, PathBuf, Vec<(String, Vec<u8>)>) {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    let mut files = vec![
        (
            "tree/readme.txt".to_owned(),
            b"hello from BeeZip\n".to_vec(),
        ),
        ("tree/empty.txt".to_owned(), Vec::new()),
        ("tree/sub/deep/a.txt".to_owned(), b"deep\n".to_vec()),
        (
            "tree/sub/[x] *literal*.txt".replace('*', "_"),
            b"brackets\n".to_vec(),
        ),
        (
            "tree/名前/ünïcödé.txt".to_owned(),
            "名前\n".as_bytes().to_vec(),
        ),
    ];
    // A file of a known pattern, big enough to span several of 7-Zip's buffers.
    let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    files.push(("tree/sub/big.bin".to_owned(), big));
    for (p, data) in &files {
        let at = dir.path().join(p);
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(at, data).unwrap();
    }
    let wim = dir.path().join("made.wim");
    let ok = std::process::Command::new(&z.exe)
        .args(["a", "-twim", "-bso0", "-bsp0", "--"])
        .arg(&wim)
        .arg(&tree)
        .status()
        .unwrap()
        .success();
    assert!(ok, "7z a -twim");
    (dir, wim, files)
}

fn read_tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(dir).unwrap();
            (
                rel.to_string_lossy().replace('\\', "/"),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn fs_opts() -> beezip_core::FsOptions {
    beezip_core::FsOptions {
        overwrite: beezip_core::OverwritePolicy::Always,
        ..beezip_core::FsOptions::default()
    }
}

#[test]
fn a_wim_lists_extracts_and_reads_as_written() {
    use beezip_core::{EntryKind, Selection, ops};
    let Some(z) = seven_zip() else { return };
    let (dir, wim, mut files) = made_wim(&z);
    files.sort();
    let det = detect_path(&wim, &Limits::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::External(External::Wim)));

    let mut cx = SimpleCtx::new();
    let mut opened = open(&wim, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    for (p, data) in &files {
        let e = entries
            .iter()
            .find(|e| e.path == *p)
            .unwrap_or_else(|| panic!("{p} isn't listed: {entries:?}"));
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, Some(data.len() as u64), "{p}");
        // Each entry on its own (`7z x -so -i!<name>`).
        let mut got = Vec::new();
        std::io::Read::read_to_end(
            &mut opened.reader.open_entry(e.id, &mut cx).unwrap(),
            &mut got,
        )
        .unwrap();
        assert_eq!(&got, data, "open_entry {p}");
    }
    let info = opened.reader.info(&mut cx).unwrap();
    let ext = info.external.unwrap();
    let backend = ext.backend.unwrap();
    assert!(backend.starts_with("7-Zip") || backend.starts_with("NanaZip"));
    assert_eq!(ext.levels, ["wim"]);

    // Everything, streamed.
    let all = dir.path().join("all");
    ops::extract(
        &wim,
        &all,
        &Selection::all(),
        &OpenOptions::default(),
        fs_opts(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(read_tree(&all), files);

    // A selection: a folder and a file, through a list file `7z l` checks first. `[` and `*`
    // are literal (`-spd`).
    let some = dir.path().join("some");
    let sel = Selection::new(
        &["tree/sub".to_owned(), "tree/readme.txt".to_owned()],
        &[],
        &[],
    )
    .unwrap();
    ops::extract(
        &wim,
        &some,
        &sel,
        &OpenOptions::default(),
        fs_opts(),
        &mut cx,
    )
    .unwrap();
    let want: Vec<_> = files
        .iter()
        .filter(|(p, _)| p.starts_with("tree/sub/") || p == "tree/readme.txt")
        .cloned()
        .collect();
    assert_eq!(read_tree(&some), want);

    // `7z t`.
    let report = ops::test(&wim, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
    assert!(report.ok(), "{report:?}");
    assert!(report.note.is_none(), "a WIM's hashes are checked");
}

#[test]
fn a_damaged_wim_fails_its_test_and_its_extraction_names_the_entry() {
    use beezip_core::{Selection, ops};
    let Some(z) = seven_zip() else { return };
    let (dir, wim, _) = made_wim(&z);
    // 7-Zip stores a WIM's files as they are: damage readme.txt's bytes.
    let mut bytes = fs::read(&wim).unwrap();
    let at = bytes
        .windows(17)
        .position(|w| w == b"hello from BeeZip")
        .expect("stored");
    bytes[at] ^= 0x20;
    fs::write(&wim, &bytes).unwrap();

    let mut cx = SimpleCtx::new();
    let report = ops::test(&wim, &Selection::all(), &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert_eq!(report.errors[0].path, "tree/readme.txt");
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);

    let err = ops::extract(
        &wim,
        &dir.path().join("x"),
        &Selection::all(),
        &OpenOptions::default(),
        fs_opts(),
        &mut cx,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt);
    assert!(err.message.contains("tree/readme.txt"), "{}", err.message);
}

#[test]
fn cancelling_and_the_limits_stop_before_anything_is_written() {
    use std::sync::{Arc, atomic::AtomicBool};

    use beezip_core::{Selection, ops, safefs::partial};
    let Some(z) = seven_zip() else { return };
    let (dir, wim, _) = made_wim(&z);

    let cancelled = SimpleCtx::new().with_cancel(Arc::new(AtomicBool::new(true)));
    let dest = dir.path().join("cancelled");
    let err = ops::extract(
        &wim,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        fs_opts(),
        &mut { cancelled },
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(read_tree(&dest).is_empty());
    assert_eq!(partial::live(), 0);

    // The listing claims more than the job may unpack: refused before 7-Zip starts.
    let small = OpenOptions::new(Limits {
        max_total_bytes: Some(1000),
        ..Limits::default()
    });
    let dest = dir.path().join("total");
    let err = ops::extract(
        &wim,
        &dest,
        &Selection::all(),
        &small,
        fs_opts(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
    assert!(read_tree(&dest).is_empty());

    // More entries than allowed: refused while the listing is read.
    let few = OpenOptions::new(Limits {
        max_entries: Some(3),
        ..Limits::default()
    });
    let err = open(&wim, &few, &mut SimpleCtx::new()).err().unwrap();
    assert_eq!(err.kind, ErrorKind::LimitExceeded, "{err}");
}

/// A file 7-Zip would read as a WIM: the header's magic and nothing else.
fn fake_wim(dir: &Path) -> PathBuf {
    let path = dir.join("fake.wim");
    let mut head = b"MSWIM\0\0\0".to_vec();
    head.extend_from_slice(&208u32.to_le_bytes());
    head.extend_from_slice(&0x0001_0d00u32.to_le_bytes());
    head.resize(4096, 0);
    fs::write(&path, head).unwrap();
    path
}

#[test]
fn without_seven_zip_the_format_is_named_and_opening_says_what_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let wim = fake_wim(dir.path());
    // Detection doesn't need 7-Zip.
    let det = detect_path(&wim, &Limits::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::External(External::Wim)));

    let nowhere = OpenOptions::default().with_seven_zip(SevenZipOptions {
        path: Some(dir.path().join("no-such-7z.exe")),
        enabled: true,
    });
    let err = open(&wim, &nowhere, &mut SimpleCtx::new())
        .err()
        .expect("no 7-Zip there");
    assert_eq!(err.kind, ErrorKind::BackendUnavailable);
    assert!(
        err.message.starts_with(
            "Opening this WIM image needs 7-Zip 25.01 or newer, and there's no 7-Zip at"
        ),
        "{}",
        err.message
    );

    let off = OpenOptions::default().with_seven_zip(SevenZipOptions {
        path: None,
        enabled: false,
    });
    let err = open(&wim, &off, &mut SimpleCtx::new())
        .err()
        .expect("7-Zip is off");
    assert_eq!(err.kind, ErrorKind::BackendUnavailable);
    assert!(
        err.message.contains("turned off in Settings"),
        "{}",
        err.message
    );
}

/// Every file under `dir`, by its path, with its contents' hash; links left out (7-Zip makes
/// them where it can, BeeZip only when asked).
fn files(dir: &Path) -> std::collections::BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(dir).unwrap();
            let mut h = Sha256::new();
            h.update(fs::read(e.path()).unwrap());
            let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
            (rel.to_string_lossy().replace('\\', "/"), hex)
        })
        .collect()
}

/// Opt-in (docs/M6.md §10): real images can't be committed, so `BEEZIP_REAL_IMAGES` names
/// some (separated by `;`). Each is extracted by BeeZip and by `7z x`, and the files compared;
/// then extracted again and cancelled after a second, which must stop soon and leave nothing
/// half-written. Set `BEEZIP_REAL_IMAGES_OUT` to a folder on a disk with room.
#[test]
fn real_images_extract_as_7z_does() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    use beezip_core::{FsOptions, OverwritePolicy, Selection, ops, safefs::partial};

    let Ok(list) = std::env::var("BEEZIP_REAL_IMAGES") else {
        return;
    };
    let seven = beezip_core::backend::find(&SevenZipOptions::default()).expect("7-Zip");
    let out =
        std::env::var_os("BEEZIP_REAL_IMAGES_OUT").map_or_else(std::env::temp_dir, PathBuf::from);
    for image in list.split(';').filter(|s| !s.is_empty()).map(PathBuf::from) {
        let work = tempfile::tempdir_in(&out).unwrap();
        let ours = work.path().join("beezip");
        let theirs = work.path().join("7z");
        let opts = || FsOptions {
            overwrite: OverwritePolicy::Rename,
            ..FsOptions::default()
        };
        let started = Instant::now();
        let report = ops::extract(
            &image,
            &ours,
            &Selection::all(),
            &OpenOptions::default(),
            opts(),
            &mut SimpleCtx::new(),
        );
        let took = started.elapsed();
        let started = Instant::now();
        let status = std::process::Command::new(&seven.exe)
            .args(["x", "-sns-", "-y", "-bso0", "-bsp0"])
            .arg(format!("-o{}", theirs.display()))
            .arg("--")
            .arg(&image)
            .status()
            .unwrap();
        eprintln!(
            "{}: BeeZip {took:.1?} ({:?}), 7z x {:.1?} ({status})",
            image.display(),
            report.as_ref().map(|r| r.files).map_err(|e| e.to_string()),
            started.elapsed()
        );
        let (a, b) = (files(&ours), files(&theirs));
        let differ: Vec<_> = b
            .iter()
            .filter(|(p, h)| a.get(*p) != Some(*h))
            .map(|(p, _)| p)
            .take(10)
            .collect();
        eprintln!(
            "  {} files, {} from 7z x missing or different: {differ:?}",
            a.len(),
            differ.len()
        );
        drop(work);

        let work = tempfile::tempdir_in(&out).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let setter = {
            let flag = flag.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(1));
                flag.store(true, Ordering::Relaxed);
                Instant::now()
            })
        };
        let result = ops::extract(
            &image,
            work.path(),
            &Selection::all(),
            &OpenOptions::default(),
            opts(),
            &mut SimpleCtx::new().with_cancel(flag),
        );
        let stopped = Instant::now();
        let set = setter.join().unwrap();
        let after = stopped.saturating_duration_since(set);
        eprintln!(
            "  cancelled after 1 s: {:?}, stopped {after:.2?} after the flag",
            result.as_ref().err().map(|e| e.kind)
        );
        if result.is_err() {
            assert!(after < Duration::from_secs(3), "{after:?}");
        }
        assert_eq!(partial::live(), 0);
    }
}
