//! DMG (docs/M5.md §5.11, §10):
//!
//! - BeeZip's own images (an HFS+ volume in UDZO) read back through `beezip_core::open`: a tree
//!   with text, noise, an empty file, Unicode names and set times; folders, links, repeated and
//!   case-differing paths, and files whose size wasn't known, written through the writer
//!   directly; the empty image; one behind gzip.
//! - Images without HFS+ list their partitions, named as 7-Zip names them; encrypted ones are
//!   refused.
//! - Windows: BeeZip's images pass `7z t`, and `7z x` gives every file's bytes. With
//!   `BEEZIP_REQUIRE_7Z=1` (CI), a missing 7-Zip fails instead of skipping.
//!
//! The fixtures made by hdiutil (`make-dmg.yml`) are checked by the manifest tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use beezip_core::{
    ArchiveKind, ConvertOptions, CreateOptions, EntryKind, ErrorKind, FormatId, FsOptions,
    NewEntry, NewKind, OpenOptions, Selection, SimpleCtx, WriteSpec,
    format::{dmg::DmgWriteOptions, udif},
    open, ops,
};
use filetime::FileTime;

fn spec() -> WriteSpec {
    WriteSpec::Dmg(DmgWriteOptions::default())
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

/// Every file under `dir` by its `/` path.
fn files_under(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e
                .path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, fs::read(e.path()).unwrap())
        })
        .collect()
}

/// A small tree: text, noise, an empty file, Unicode names, a folder in a folder, set times.
fn tree(root: &Path) -> (PathBuf, BTreeMap<String, Vec<u8>>) {
    let src = root.join("Disk Tree");
    fs::create_dir_all(src.join("sub/deeper")).unwrap();
    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "readme.txt",
            b"BeeZip writes Apple disk images.\n".repeat(200),
        ),
        ("empty.txt", Vec::new()),
        (
            "café ünïcödé 日本.txt",
            "non-ASCII names\n".as_bytes().to_vec(),
        ),
        ("sub/noise.bin", noise(3 << 20, 7)),
        ("sub/deeper/zeros.bin", vec![0u8; 2 << 20]),
        (
            "sub/deeper/blocks.txt",
            b"64 KiB blocks of text ".repeat(9000),
        ),
    ];
    let mut want = BTreeMap::new();
    for (i, (p, data)) in files.iter().enumerate() {
        let path = src.join(p);
        fs::write(&path, data).unwrap();
        filetime::set_file_mtime(
            &path,
            FileTime::from_system_time(at(1_700_000_000 + i as u64)),
        )
        .unwrap();
        want.insert(format!("Disk Tree/{p}"), data.clone());
    }
    for (d, t) in [
        ("sub/deeper", 1_600_000_000),
        ("sub", 1_600_000_100),
        ("", 1_600_000_200),
    ] {
        filetime::set_file_mtime(src.join(d), FileTime::from_system_time(at(t))).unwrap();
    }
    (src, want)
}

fn reader(path: &Path) -> beezip_core::Opened {
    let opened = open(path, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
    assert_eq!(
        opened.detection.format(),
        Some(FormatId::Dmg),
        "{}",
        path.display()
    );
    opened
}

/// Every entry's path, kind and data, read with `open_entry`.
fn read_back(path: &Path) -> Vec<(String, EntryKind, Vec<u8>)> {
    let mut opened = reader(path);
    let mut cx = SimpleCtx::new();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    entries
        .iter()
        .map(|e| {
            let mut data = Vec::new();
            opened
                .reader
                .open_entry(e.id, &mut cx)
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            if let Some(size) = e.size
                && e.kind == EntryKind::File
            {
                assert_eq!(data.len() as u64, size, "{}", e.path);
            }
            (e.path.clone(), e.kind.clone(), data)
        })
        .collect()
}

#[test]
fn a_tree_round_trips() {
    let root = tempfile::tempdir().unwrap();
    let (src, want) = tree(root.path());
    let dmg = root.path().join("Tree Image.dmg");
    let report = ops::create(
        &dmg,
        &[src],
        &spec(),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(report.files, 6);
    assert_eq!(report.dirs, 3);

    let mut opened = reader(&dmg);
    let mut cx = SimpleCtx::new();
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.format, FormatId::Dmg);
    assert!(info.methods.contains(&"zlib"), "{:?}", info.methods);
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let by_path: BTreeMap<&str, &beezip_core::Entry> =
        entries.iter().map(|e| (e.path.as_str(), e)).collect();
    for (path, data) in &want {
        let e = by_path
            .get(path.as_str())
            .unwrap_or_else(|| panic!("{path}: {entries:#?}"));
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, Some(data.len() as u64), "{path}");
        assert_eq!(e.unix_mode, Some(0o100_644), "{path}");
    }
    let d = by_path["Disk Tree/sub"];
    assert_eq!(d.kind, EntryKind::Dir);
    assert_eq!(d.modified, Some(at(1_600_000_100)));
    assert_eq!(d.unix_mode, Some(0o040_755));
    assert_eq!(
        by_path["Disk Tree/readme.txt"].modified,
        Some(at(1_700_000_000))
    );
    drop(opened);

    let dest = root.path().join("out");
    let r = ops::extract(
        &dmg,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    assert_eq!(files_under(&dest), want);
    let mtime = |p: &str| fs::metadata(dest.join(p)).unwrap().modified().unwrap();
    assert_eq!(mtime("Disk Tree/sub/deeper"), at(1_600_000_000));
    assert_eq!(mtime("Disk Tree"), at(1_600_000_200));
    assert_eq!(mtime("Disk Tree/sub/noise.bin"), at(1_700_000_003));

    // The same tree gives the same image.
    let again = root.path().join("again/Tree Image.dmg");
    fs::create_dir_all(again.parent().unwrap()).unwrap();
    let (src, _) = tree(&root.path().join("again"));
    ops::create(
        &again,
        &[src],
        &spec(),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(fs::read(&again).unwrap() == fs::read(&dmg).unwrap());
    // Nothing is left beside the output.
    let left: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("beezip"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

fn entry(path: &str, kind: NewKind, size: u64) -> NewEntry {
    NewEntry {
        path: path.into(),
        kind,
        size,
        modified: Some(at(1_750_000_000)),
        unix_mode: None,
        dos_attrs: None,
        source: None,
    }
}

fn file(path: &str, size: u64) -> NewEntry {
    entry(path, NewKind::File, size)
}

/// Writes `entries` through the writer itself, `expect` first, as `ops::create` does.
fn write(path: &Path, entries: &[(NewEntry, Vec<u8>)]) -> beezip_core::Result<SimpleCtx> {
    let out = fs::File::create(path).unwrap();
    let mut w = ops::create_writer(&spec(), Box::new(out), path)?;
    let expected: Vec<NewEntry> = entries.iter().map(|(e, _)| e.clone()).collect();
    w.expect(&expected)?;
    let mut cx = SimpleCtx::new();
    for (e, data) in entries {
        w.add(e, &mut &data[..], &mut cx)?;
    }
    w.finish(&mut cx)?;
    Ok(cx)
}

#[test]
fn links_folders_and_repeats() {
    let root = tempfile::tempdir().unwrap();
    let dmg = root.path().join("x.dmg");
    let link = |path: &str, target: &str| {
        entry(
            path,
            NewKind::Symlink {
                target: target.into(),
            },
            0,
        )
    };
    let mut exe = file("bin/tool", 5);
    exe.unix_mode = Some(0o100_755);
    let mut late_dir = entry("deep/a", NewKind::Dir, 0);
    late_dir.unix_mode = Some(0o700);
    late_dir.modified = Some(at(1_600_000_000));
    let cx = write(
        &dmg,
        &[
            (file("deep/a/b/c.txt", 3), b"abc".to_vec()),
            // A folder after what's in it: made already, so its mode and time are set.
            (late_dir, Vec::new()),
            (exe, b"#!/x\n".to_vec()),
            (link("bin/link", "tool"), Vec::new()),
            (link("up", "../outside"), Vec::new()),
            (file("dup.txt", 5), b"first".to_vec()),
            (file("dup.txt", 6), b"second".to_vec()),
            (file("Case.txt", 5), b"upper".to_vec()),
            (file("case.txt", 5), b"lower".to_vec()),
        ],
    )
    .unwrap();
    assert!(
        cx.warnings.iter().any(|w| w.contains("dup.txt")),
        "{:?}",
        cx.warnings
    );
    let back = read_back(&dmg);
    let get = |p: &str| {
        back.iter()
            .find(|(path, _, _)| path == p)
            .unwrap_or_else(|| panic!("{p}: {back:#?}"))
    };
    assert_eq!(get("deep/a/b/c.txt").2, b"abc");
    assert_eq!(get("dup.txt").2, b"second");
    assert_eq!(back.iter().filter(|(p, _, _)| p == "dup.txt").count(), 1);
    // Two names that differ only in case: the volume is case-sensitive (HFSX).
    assert_eq!(get("Case.txt").2, b"upper");
    assert_eq!(get("case.txt").2, b"lower");
    assert_eq!(
        get("bin/link").1,
        EntryKind::Symlink {
            target: "tool".into()
        }
    );
    assert_eq!(
        get("up").1,
        EntryKind::Symlink {
            target: "../outside".into()
        }
    );
    let mut opened = reader(&dmg);
    let entries = opened.reader.entries(&mut SimpleCtx::new()).unwrap();
    let mode = |p: &str| entries.iter().find(|e| e.path == p).unwrap().unix_mode;
    assert_eq!(mode("bin/tool"), Some(0o100_755));
    assert_eq!(mode("bin/link"), Some(0o120_755));
    assert_eq!(mode("deep/a"), Some(0o040_700));
    assert_eq!(mode("deep/a/b"), Some(0o040_755));
    let a = entries.iter().find(|e| e.path == "deep/a").unwrap();
    assert_eq!(a.modified, Some(at(1_600_000_000)));
}

#[test]
fn sizes_that_were_wrong_or_unknown() {
    let root = tempfile::tempdir().unwrap();
    let dmg = root.path().join("x.dmg");
    // Announced as empty, as a bare stream's entry is: spooled, and written at its real size.
    let data = noise(300_000, 3);
    write(&dmg, &[(file("stream", 0), data.clone())]).unwrap();
    assert_eq!(read_back(&dmg), [("stream".into(), EntryKind::File, data)]);
    // More data than announced is refused rather than cut short.
    let err = write(&dmg, &[(file("long", 3), b"abcdef".to_vec())]).unwrap_err();
    assert!(err.message.contains("more data"), "{err}");
    // Less is refused too.
    let err = write(&dmg, &[(file("short", 10), b"abc".to_vec())]).unwrap_err();
    assert!(err.message.contains("short"), "{err}");
    // An unannounced file bigger than the volume's room.
    let err = write(&dmg, &[(file("big", 0), vec![1u8; 3 << 20])]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation, "{err}");
    assert!(err.message.contains("doesn't fit"), "{err}");
    let left: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("beezip"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn a_gzip_stream_converts_to_a_dmg() {
    let root = tempfile::tempdir().unwrap();
    let data = b"a stream whose size isn't known up front\n".repeat(5000);
    let gz = root.path().join("notes.txt.gz");
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&data).unwrap();
    fs::write(&gz, z.finish().unwrap()).unwrap();
    let dmg = root.path().join("notes.dmg");
    ops::convert(
        &gz,
        &dmg,
        ArchiveKind::Dmg,
        &spec(),
        &ConvertOptions::default(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let back = read_back(&dmg);
    assert_eq!(back.len(), 1, "{back:?}");
    assert_eq!(back[0].2, data);
}

#[test]
fn an_empty_image() {
    let root = tempfile::tempdir().unwrap();
    let empty = root.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let dmg = root.path().join("e.dmg");
    ops::create(
        &dmg,
        &[empty],
        &spec(),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(
        read_back(&dmg),
        [("empty".into(), EntryKind::Dir, Vec::new())]
    );
    // And one with no entries at all.
    write(&dmg, &[]).unwrap();
    assert!(read_back(&dmg).is_empty());
}

#[test]
fn a_gzipped_image_opens() {
    let root = tempfile::tempdir().unwrap();
    let (src, want) = tree(root.path());
    let dmg = root.path().join("t.dmg");
    ops::create(
        &dmg,
        &[src],
        &spec(),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let gz = root.path().join("t.dmg.gz");
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    z.write_all(&fs::read(&dmg).unwrap()).unwrap();
    fs::write(&gz, z.finish().unwrap()).unwrap();
    let dest = root.path().join("out");
    ops::extract(
        &gz,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(files_under(&dest), want);
}

/// An image whose one partition isn't HFS+ or APFS: its sectors, under 7-Zip's name for it.
#[test]
fn partitions_are_listed_without_a_volume() {
    let root = tempfile::tempdir().unwrap();
    let dmg = root.path().join("raw.dmg");
    let sectors = noise(512 * 300, 9);
    let mut out = Vec::new();
    udif::write_udzo(
        &mut &sectors[..],
        sectors.len() as u64,
        "disk image (Apple_HFS : 4)",
        &mut out,
        &mut SimpleCtx::new(),
    )
    .unwrap();
    fs::write(&dmg, out).unwrap();
    let mut cx = SimpleCtx::new();
    let mut opened = open(&dmg, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "0.hfs");
    assert_eq!(entries[0].size, Some(sectors.len() as u64));
    assert_eq!(entries[0].crc32, Some(crc32fast::hash(&sectors)));
    let mut data = Vec::new();
    opened
        .reader
        .open_entry(0, &mut cx)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert!(data == sectors);
}

#[test]
fn encrypted_images_are_refused() {
    let root = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("v2.dmg", [b"encrcdsa".as_slice(), &[0u8; 4096]].concat()),
        ("v1.dmg", [&[0u8; 4096][..], b"cdsaencr"].concat()),
    ] {
        let p = root.path().join(name);
        fs::write(&p, bytes).unwrap();
        let err = open(&p, &OpenOptions::default(), &mut SimpleCtx::new())
            .err()
            .unwrap();
        assert_eq!(err.kind, ErrorKind::UnsupportedFormat, "{name}: {err}");
        assert!(err.message.contains("encrypted"), "{err}");
    }
}

#[cfg(windows)]
mod windows {
    use std::process::Command;

    use super::*;

    fn seven_zip() -> Option<PathBuf> {
        let installed = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
        if installed.is_file() {
            return Some(installed);
        }
        assert!(
            std::env::var("BEEZIP_REQUIRE_7Z").as_deref() != Ok("1"),
            "7-Zip is required (BEEZIP_REQUIRE_7Z=1) but wasn't found"
        );
        eprintln!("skipping: 7-Zip not found (set BEEZIP_REQUIRE_7Z=1 to require it)");
        None
    }

    fn run(exe: &Path, args: &[&str], cwd: &Path) -> String {
        let out = Command::new(exe)
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "{} {args:?} failed:\n{text}",
            exe.display()
        );
        text
    }

    #[test]
    fn beezip_images_pass_7z() {
        let Some(seven) = seven_zip() else {
            return;
        };
        let root = tempfile::tempdir().unwrap();
        let (src, want) = tree(root.path());
        let dmg = root.path().join("x.dmg");
        ops::create(
            &dmg,
            &[src],
            &spec(),
            &CreateOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        let tested = run(&seven, &["t", "x.dmg"], root.path());
        assert!(tested.contains("Everything is Ok"), "{tested}");
        run(&seven, &["x", "x.dmg", "-o7z-out", "-y"], root.path());
        // 7-Zip may show the volume's name as the top folder, and HFS+'s own files beside it.
        // It lists names as HFS+ stores them, decomposed, where BeeZip composes them again.
        let got: BTreeMap<String, Vec<u8>> = files_under(&root.path().join("7z-out"))
            .into_iter()
            .filter_map(|(p, d)| {
                let p = p.strip_prefix("x/").unwrap_or(&p).to_owned();
                p.starts_with("Disk Tree/").then_some((p, d))
            })
            .collect();
        let decomposed = |p: &str| {
            p.replace('é', "e\u{301}")
                .replace('ü', "u\u{308}")
                .replace('ï', "i\u{308}")
                .replace('ö', "o\u{308}")
        };
        let want: BTreeMap<String, Vec<u8>> =
            want.into_iter().map(|(p, d)| (decomposed(&p), d)).collect();
        assert_eq!(
            got.keys().collect::<Vec<_>>(),
            want.keys().collect::<Vec<_>>()
        );
        for (p, d) in &want {
            assert!(got[p] == *d, "7-Zip's {p} differs");
        }
    }
}
