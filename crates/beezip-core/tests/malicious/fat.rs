//! The malicious FAT cases (docs/M7.md §10), made by the test from 7-Zip's `fat12.img`: file
//! chains that loop or hold a bad cluster, a folder inside itself, and folder chains that loop
//! or break. Each is refused cleanly or read within limits, at once, and nothing is written
//! outside the destination.

use std::time::{Duration, Instant};

use beezip_core::External;
use tempfile::TempDir;

use super::*;

/// `fat12.img`'s layout: sectors of 512 bytes in clusters of 4, one reserved sector, two FATs of
/// a sector each, then a root folder of 512 entries.
const FATS: [usize; 2] = [512, 1024];
const ROOT: usize = 1536;
const ROOT_LEN: usize = 512 * 32;
const DATA: usize = ROOT + ROOT_LEN;
const CLUSTER: usize = 2048;
/// A bad cluster's FAT12 entry.
const BAD: u16 = 0xFF7;

fn fat12() -> Vec<u8> {
    let img = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/thirdparty/7zip/fat12.img"),
    )
    .unwrap();
    // The layout above, as its boot sector gives it.
    assert_eq!(img[11..23], [0, 2, 4, 1, 0, 2, 0, 2, 0, 2, 0xF8, 1]);
    img
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

/// Cluster `c`'s entry in both FATs.
fn set(img: &mut [u8], c: usize, v: u16) {
    for fat in FATS {
        let at = fat + c + c / 2;
        let old = le16(img, at);
        let new = if c.is_multiple_of(2) {
            (old & 0xF000) | v
        } else {
            (old & 0x000F) | (v << 4)
        };
        img[at..at + 2].copy_from_slice(&new.to_le_bytes());
    }
}

/// Cluster `c`'s entry.
fn get(img: &[u8], c: usize) -> usize {
    let v = le16(img, FATS[0] + c + c / 2);
    usize::from(if c.is_multiple_of(2) {
        v & 0xFFF
    } else {
        v >> 4
    })
}

/// Where cluster `c` starts.
fn at(c: usize) -> usize {
    DATA + (c - 2) * CLUSTER
}

/// Where the 8.3 slot `short` is in the `len` bytes of folder from `from`.
fn slot(img: &[u8], from: usize, len: usize, short: &[u8; 11]) -> usize {
    (from..from + len)
        .step_by(32)
        .find(|&s| img[s..s + 11] == *short)
        .unwrap_or_else(|| panic!("no {:?}", String::from_utf8_lossy(short)))
}

/// The first cluster of the entry whose slot is at `slot`.
fn first(img: &[u8], slot: usize) -> usize {
    usize::from(le16(img, slot + 26))
}

/// `random.bin`'s slot and its chain of 32 clusters.
fn random(img: &[u8]) -> (usize, Vec<usize>) {
    let s = slot(img, ROOT, ROOT_LEN, b"RANDOM  BIN");
    let mut chain = vec![first(img, s)];
    loop {
        let next = get(img, chain[chain.len() - 1]);
        if next >= 0xFF8 {
            break;
        }
        chain.push(next);
    }
    assert_eq!(chain.len(), 32);
    (s, chain)
}

/// `sub`'s first cluster.
fn sub(img: &[u8]) -> usize {
    first(img, slot(img, ROOT, ROOT_LEN, b"SUB        "))
}

/// `img` as a FAT image on disk, in a folder of its own.
fn hostile(img: &[u8]) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hostile.img");
    fs::write(&path, img).unwrap();
    assert_eq!(
        detect_path(&path, &Limits::default()).unwrap().format(),
        Some(FormatId::External(External::Fat))
    );
    (dir, path)
}

/// Extracts `path` into `<tmp>/parent/dest`, checking that nothing else appears in `parent`.
fn extract_image(path: &Path) -> (beezip_core::Result<ExtractReport>, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("parent");
    let dest = parent.join("dest");
    fs::create_dir_all(&dest).unwrap();
    fs::write(parent.join("sentinel"), b"").unwrap();
    let before = listing(&parent);
    let result = ops::extract(
        path,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    );
    let outside: Vec<String> = listing(&parent)
        .into_iter()
        .filter(|p| !before.contains(p) && !p.starts_with("dest/"))
        .collect();
    assert!(outside.is_empty(), "written outside: {outside:?}");
    (result, listing(&dest))
}

/// The paths `path` lists, with the warnings.
fn list(path: &Path) -> (Vec<String>, Vec<String>) {
    let mut cx = SimpleCtx::new();
    let mut opened = open(path, &OpenOptions::default(), &mut cx).unwrap();
    let paths = opened
        .reader
        .entries(&mut cx)
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    (paths, cx.warnings)
}

fn has(paths: &[String], p: &str) -> bool {
    paths.iter().any(|q| q == p)
}

/// `random.bin`'s chain looping back inside its size, past its chain, and under a size of
/// 4 GiB; and holding a cluster marked bad. Each is `Corrupt` at once, by extracting and by
/// testing; `random.bin` is never written, and what comes before it extracts.
#[test]
fn fat_file_chains_that_loop_or_break_are_corrupt() {
    type Change = fn(&mut [u8], usize, &[usize]);
    let cases: [(&str, Change); 4] = [
        ("a loop inside its size", |img, _, ch| {
            set(img, ch[20], ch[3] as u16);
        }),
        ("a loop past its chain", |img, s, ch| {
            set(img, ch[31], ch[0] as u16);
            img[s + 28..s + 32].copy_from_slice(&(100 * CLUSTER as u32).to_le_bytes());
        }),
        ("a loop under 4 GiB", |img, s, ch| {
            set(img, ch[31], ch[0] as u16);
            img[s + 28..s + 32].copy_from_slice(&u32::MAX.to_le_bytes());
        }),
        ("a bad cluster", |img, _, ch| set(img, ch[9], BAD)),
    ];
    for (what, change) in cases {
        let mut img = fat12();
        let (s, chain) = random(&img);
        change(&mut img, s, &chain);
        let (_dir, path) = hostile(&img);
        let (r, inside) = extract_image(&path);
        let e = r.unwrap_err();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{what}: {e}");
        assert!(!has(&inside, "random.bin"), "{what}");
        assert!(has(&inside, "mtime.txt"), "{what}: {inside:?}");
        // Testing writes nothing, so its time is the reader's.
        let t = Instant::now();
        let report = ops::test(
            &path,
            &Selection::all(),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        assert!(t.elapsed() < Duration::from_secs(2), "{what}");
        let failed: Vec<(&str, ErrorKind)> = report
            .errors
            .iter()
            .map(|e| (e.path.as_str(), e.kind))
            .collect();
        assert_eq!(failed, [("random.bin", ErrorKind::Corrupt)], "{what}");
    }
}

/// `sub/nested` pointing back at `sub`: listed once, with a warning, and the rest extracts.
#[test]
fn a_fat_folder_inside_itself_is_listed_once() {
    let mut img = fat12();
    let sub = sub(&img);
    let nested = slot(&img, at(sub), CLUSTER, b"NESTED     ");
    img[nested + 26..nested + 28].copy_from_slice(&(sub as u16).to_le_bytes());
    let (_dir, path) = hostile(&img);
    let (paths, warnings) = list(&path);
    assert!(has(&paths, "sub/nested"), "{paths:?}");
    assert!(!paths.iter().any(|p| p.starts_with("sub/nested/")));
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("already listed"), "{warnings:?}");
    let (r, inside) = extract_image(&path);
    assert!(r.unwrap().skipped.is_empty());
    assert!(has(&inside, "sub/nested"), "{inside:?}");
    assert!(has(&inside, "readme.txt"), "{inside:?}");
}

/// `sub`'s one cluster, with deleted slots where its end marker was, linked to itself, and to a
/// cluster past the volume: listed as far as it goes, with a warning, and extracted.
#[test]
fn fat_folder_chains_that_loop_or_break_end() {
    for (what, link, says) in [
        ("loops", None, "runs into cluster"),
        ("breaks", Some(0xFF0), "is broken"),
    ] {
        let mut img = fat12();
        let sub = sub(&img);
        let end = (at(sub)..at(sub) + CLUSTER)
            .step_by(32)
            .find(|&s| img[s] == 0)
            .unwrap();
        for s in (end..at(sub) + CLUSTER).step_by(32) {
            img[s] = 0xE5;
        }
        set(&mut img, sub, link.unwrap_or(sub as u16));
        let (_dir, path) = hostile(&img);
        let (paths, warnings) = list(&path);
        assert!(has(&paths, "sub/nested/deep.txt"), "{what}: {paths:?}");
        assert_eq!(warnings.len(), 1, "{what}: {warnings:?}");
        assert!(warnings[0].contains(says), "{what}: {warnings:?}");
        let (r, inside) = extract_image(&path);
        assert!(r.unwrap().skipped.is_empty(), "{what}");
        assert!(has(&inside, "sub/nested/deep.txt"), "{what}");
    }
}
