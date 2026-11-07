//! ISO 9660, Joliet, Rock Ridge and UDF (docs/M5.md §5.9) beyond the fixtures: BeeZip's own
//! images read back (by BeeZip and 7-Zip), a convert that spools its entries, links and modes,
//! the writer's warnings, and cancelling while the image is written.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use beezip_core::{
    Ctx, EntryKind, ErrorKind, OpenOptions, OverwriteChoice, Progress, Result, Selection,
    SimpleCtx, WriteSpec,
    edit::ConvertOptions,
    format::{
        ArchiveWriter, NewEntry, NewKind,
        iso::{IsoWriteOptions, IsoWriter},
    },
    open, ops,
};

fn spec() -> WriteSpec {
    WriteSpec::Iso(IsoWriteOptions::default())
}

fn seven_zip() -> Option<PathBuf> {
    let p = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
    if p.is_file() {
        return Some(p);
    }
    assert!(
        std::env::var("BEEZIP_REQUIRE_7Z").as_deref() != Ok("1"),
        "7-Zip is required (BEEZIP_REQUIRE_7Z=1) but wasn't found"
    );
    None
}

/// `7z t` passes, where 7-Zip is installed.
fn seven_t(image: &Path) {
    let Some(exe) = seven_zip() else {
        return;
    };
    let out = Command::new(exe).arg("t").arg(image).output().unwrap();
    assert!(
        out.status.success(),
        "7z t {}: {}",
        image.display(),
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Files and folders under `root`, `/`-separated, with each file's bytes.
fn tree(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let e = e.unwrap();
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let data = e.file_type().is_file().then(|| fs::read(e.path()).unwrap());
        out.push((rel, data));
    }
    out
}

/// A tree with what ISO 9660 makes hard: names Joliet must cut or can't hold, folders deep
/// enough for Rock Ridge to relocate, an empty file and one of several sectors.
fn awkward(root: &Path) {
    let long = "a-name-of-two-hundred-characters-".repeat(7);
    let long = &long[..200];
    let deep = (1..=10)
        .map(|i| format!("level{i:02}"))
        .collect::<Vec<_>>()
        .join("/");
    let mut bytes = vec![0u8; 300_000];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i * 7 % 251) as u8;
    }
    for (path, data) in [
        ("top/hello.txt".to_owned(), b"Hello, BeeZip!\n".to_vec()),
        ("top/empty.bin".to_owned(), Vec::new()),
        (
            "top/Ünïcødé 名前 😀.txt".to_owned(),
            b"non-ASCII\n".to_vec(),
        ),
        (format!("top/{long}"), b"a long name\n".to_vec()),
        (
            format!("top/{deep}/deep.txt"),
            b"ten levels down\n".to_vec(),
        ),
        ("top/data/random.bin".to_owned(), bytes),
    ] {
        let p = root.join(&path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }
}

#[test]
fn written_images_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    awkward(&src);
    let iso = dir.path().join("out").join("my disc.iso");
    fs::create_dir_all(iso.parent().unwrap()).unwrap();
    let mut cx = SimpleCtx::new();
    let report = ops::create(
        &iso,
        &[src.join("top")],
        &spec(),
        &Default::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(report.files, 6);
    assert_eq!(report.bytes_in, 300_000 + 15 + 10 + 12 + 16);
    // Joliet cuts the 200-character name; Rock Ridge relocates the deepest folders.
    let warned = cx.warnings.join("\n");
    assert!(warned.contains("64 characters"), "{warned}");
    assert!(warned.contains("relocated"), "{warned}");
    // Nothing but the image is left beside it.
    assert_eq!(fs::read_dir(iso.parent().unwrap()).unwrap().count(), 1);

    let mut opened = open(&iso, &OpenOptions::default(), &mut cx).unwrap();
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.methods, ["Rock Ridge"]);
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let want = tree(&src);
    let got: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
    for (path, data) in &want {
        let e = entries
            .iter()
            .find(|e| e.path == *path)
            .unwrap_or_else(|| panic!("{path} isn't listed: {got:?}"));
        match data {
            Some(d) => {
                assert_eq!(e.kind, EntryKind::File, "{path}");
                assert_eq!(e.size, Some(d.len() as u64), "{path}");
                let mut read = Vec::new();
                opened
                    .reader
                    .open_entry(e.id, &mut cx)
                    .unwrap()
                    .read_to_end(&mut read)
                    .unwrap();
                assert_eq!(&read, d, "{path}");
            }
            None => assert_eq!(e.kind, EntryKind::Dir, "{path}"),
        }
    }
    assert_eq!(entries.len(), want.len(), "{got:?}");
    drop(opened);

    let dest = dir.path().join("x");
    ops::extract(
        &iso,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        Default::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(tree(&dest), want);
    seven_t(&iso);
}

#[test]
fn a_convert_spools_its_entries() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty");
    let zip = fixtures.join("7z-deflate.zip");
    let dir = tempfile::tempdir().unwrap();
    let iso = dir.path().join("converted.iso");
    let mut cx = SimpleCtx::new();
    let report = ops::convert(
        &zip,
        &iso,
        beezip_core::ArchiveKind::Iso,
        &spec(),
        &ConvertOptions::default(),
        &OpenOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert!(report.files > 0);
    // The spooled entries went with the writer.
    let left: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["converted.iso"]);

    let read_all = |path: &Path| -> Vec<(String, Vec<u8>)> {
        let mut cx = SimpleCtx::new();
        let mut opened = open(path, &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        let mut out = Vec::new();
        for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
            let mut data = Vec::new();
            opened
                .reader
                .open_entry(e.id, &mut cx)
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            out.push((beezip_core::format::normalize(&e.path), data));
        }
        out.sort();
        out
    };
    assert_eq!(read_all(&iso), read_all(&zip));
    seven_t(&iso);
}

#[test]
fn links_modes_and_times_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let iso = dir.path().join("links.iso");
    let when = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
    let entry = |path: &str, kind: NewKind, size: u64, mode: u32| NewEntry {
        path: path.into(),
        kind,
        size,
        modified: Some(when),
        unix_mode: Some(mode),
        dos_attrs: None,
        source: None,
    };
    let entries = [
        entry("bin", NewKind::Dir, 0, 0o700),
        entry("bin/run.sh", NewKind::File, 10, 0o755),
        entry(
            "bin/link",
            NewKind::Symlink {
                target: "run.sh".into(),
            },
            0,
            0o777,
        ),
        entry(
            "up",
            NewKind::Symlink {
                target: "../outside/./x".into(),
            },
            0,
            0o777,
        ),
    ];
    {
        let out = fs::File::create(&iso).unwrap();
        let mut w: Box<dyn ArchiveWriter> =
            Box::new(IsoWriter::new(Box::new(out), IsoWriteOptions::default(), &iso).unwrap());
        let mut cx = SimpleCtx::new();
        w.expect(&entries).unwrap();
        for e in &entries {
            let data: &[u8] = if e.kind == NewKind::File {
                b"#!/bin/sh\n"
            } else {
                b""
            };
            w.add(e, &mut &data[..], &mut cx).unwrap();
        }
        w.finish(&mut cx).unwrap();
    }
    let mut cx = SimpleCtx::new();
    let mut opened = open(&iso, &OpenOptions::default(), &mut cx).unwrap();
    let listed = opened.reader.entries(&mut cx).unwrap().to_vec();
    let by = |p: &str| listed.iter().find(|e| e.path == p).unwrap().clone();
    assert_eq!(by("bin").unix_mode, Some(0o040_700));
    assert_eq!(by("bin/run.sh").unix_mode, Some(0o100_755));
    assert_eq!(by("bin/run.sh").modified, Some(when));
    assert_eq!(
        by("bin/link").kind,
        EntryKind::Symlink {
            target: "run.sh".into()
        }
    );
    assert_eq!(
        by("up").kind,
        EntryKind::Symlink {
            target: "../outside/./x".into()
        }
    );
    let mut data = Vec::new();
    let id = by("bin/run.sh").id;
    opened
        .reader
        .open_entry(id, &mut cx)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"#!/bin/sh\n");
}

/// Cancels once the image starts being written.
struct CancelWhileWriting {
    inner: SimpleCtx,
    cancel: Arc<AtomicBool>,
}

impl Ctx for CancelWhileWriting {
    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn progress(&mut self, p: &Progress) {
        // The writer's own reports have the image's size as their total.
        if p.bytes_total.is_some_and(|t| t > 1_000_000) && p.bytes_done > 0 {
            self.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn warn(&mut self, message: String) {
        self.inner.warn(message);
    }

    fn password(&mut self, entry: Option<&str>, attempt: u32) -> Result<String> {
        self.inner.password(entry, attempt)
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        self.inner.overwrite(existing)
    }
}

#[test]
fn cancelling_while_writing_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let block = vec![7u8; 1 << 20];
    for i in 0..8 {
        fs::write(src.join(format!("f{i}.bin")), &block).unwrap();
    }
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let iso = out.join("big.iso");
    let mut cx = CancelWhileWriting {
        inner: SimpleCtx::new(),
        cancel: Arc::new(AtomicBool::new(false)),
    };
    let err = ops::create(&iso, &[src], &spec(), &Default::default(), &mut cx).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled, "{err}");
    assert!(cx.cancel.load(Ordering::Relaxed));
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
}

#[test]
fn a_file_that_changes_size_fails_the_image() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let file = src.join("grows.txt");
    fs::write(&file, b"short").unwrap();
    let iso = dir.path().join("grows.iso");
    let out = fs::File::create(&iso).unwrap();
    let mut w: Box<dyn ArchiveWriter> =
        Box::new(IsoWriter::new(Box::new(out), IsoWriteOptions::default(), &iso).unwrap());
    let mut cx = SimpleCtx::new();
    let e = NewEntry {
        path: "grows.txt".into(),
        kind: NewKind::File,
        size: 5,
        modified: Some(SystemTime::now()),
        unix_mode: None,
        dos_attrs: None,
        source: Some(file.clone()),
    };
    w.add(&e, &mut std::io::empty(), &mut cx).unwrap();
    fs::write(&file, b"much longer now").unwrap();
    let err = w.finish(&mut cx).unwrap_err();
    assert!(
        matches!(err.kind, ErrorKind::Corrupt | ErrorKind::Io),
        "{err}"
    );
}

/// Rock Ridge names are bytes: an image whose names were written in Shift-JIS (hadris takes them
/// as given; no Joliet tree) reads right in CP932 and wrong as UTF-8 (docs/M5.md §6).
#[test]
fn rock_ridge_names_take_the_chosen_encoding() {
    use beezip_core::{NameDecoding, NameEncoding};
    use hadris_fs::{Content, Node, Tree};
    use hadris_io::StdIo;
    use hadris_iso::{IsoLevel, IsoOptions};
    use hadris_storage::{BlockSize, sync::StreamDevice};

    let dir = tempfile::tempdir().unwrap();
    let iso = dir.path().join("sjis.iso");
    let mut tree = Tree::new();
    // 名前.txt in Shift-JIS.
    tree.insert(
        b"\x96\xbc\x91\x4f.txt",
        Node::file(Content::bytes(b"x".to_vec())),
    )
    .unwrap();
    let opts = IsoOptions::new().with_level(IsoLevel::L3).with_rock_ridge();
    let dev = StreamDevice::new_growable(
        StdIo::new(fs::File::create(&iso).unwrap()),
        BlockSize::new(2048).unwrap(),
    )
    .unwrap();
    hadris_iso::sync::write(dev, &tree, &opts).unwrap();

    let names = |encoding| -> Vec<String> {
        let opts = OpenOptions::default().with_names(NameDecoding {
            encoding,
            ..NameDecoding::default()
        });
        let mut cx = SimpleCtx::new();
        let mut opened = open(&iso, &opts, &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap();
        entries.iter().map(|e| e.path.clone()).collect()
    };
    assert_eq!(
        names(NameEncoding::from_name("cp932").unwrap()),
        ["名前.txt"]
    );
    assert_ne!(names(NameEncoding::Utf8), ["名前.txt"]);
}
