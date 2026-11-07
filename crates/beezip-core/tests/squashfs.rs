//! squashfs (docs/M5.md §5.10): the reader on images built here byte by byte, and the writer.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use beezip_core::{
    CreateOptions, EntryKind, FsOptions, OpenOptions, Selection, SimpleCtx, WriteSpec,
    format::squashfs::{SquashfsMethod, SquashfsWriteOptions},
    open, ops,
};

fn spec(method: SquashfsMethod) -> WriteSpec {
    WriteSpec::Squashfs(SquashfsWriteOptions {
        method,
        level: method.resolve_level(None).unwrap(),
    })
}

/// A small tree: text, a file of several blocks with an incompressible stretch, an empty file,
/// one of zeros (holes), a non-ASCII name, nested folders.
fn tree(root: &Path) -> PathBuf {
    let t = root.join("tree");
    fs::create_dir_all(t.join("docs/deep/er")).unwrap();
    fs::create_dir_all(t.join("ünïcödé")).unwrap();
    fs::write(t.join("hello.txt"), b"Hello, BeeZip!\n").unwrap();
    let mut big = Vec::new();
    for i in 0..30_000u32 {
        big.extend_from_slice(format!("line {i}\n").as_bytes());
    }
    let mut x = 0x2545_f491_u32;
    for _ in 0..140_000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        big.push(x as u8);
    }
    fs::write(t.join("docs/big.bin"), &big).unwrap();
    fs::write(t.join("docs/empty.txt"), b"").unwrap();
    fs::write(t.join("docs/deep/er/zeros.bin"), vec![0u8; 300_000]).unwrap();
    fs::write(t.join("ünïcödé/名前.txt"), "non-ASCII names\n").unwrap();
    let when = filetime::FileTime::from_unix_time(1_767_225_600, 0);
    for e in walkdir::WalkDir::new(&t).contents_first(true) {
        filetime::set_file_mtime(e.unwrap().path(), when).unwrap();
    }
    t
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The files under `dir`: their paths, sizes and SHA-256s.
fn files(dir: &Path) -> Vec<(String, usize, String)> {
    let mut out: Vec<(String, usize, String)> = walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(dir).unwrap();
            let data = fs::read(e.path()).unwrap();
            (
                rel.to_string_lossy().replace('\\', "/"),
                data.len(),
                sha256(&data),
            )
        })
        .collect();
    out.sort();
    out
}

/// Where images go for a look from outside, when `BEEZIP_SQUASHFS_OUT` names a folder.
fn keep(image: &Path) {
    if let Ok(dir) = std::env::var("BEEZIP_SQUASHFS_OUT") {
        fs::create_dir_all(&dir).unwrap();
        fs::copy(image, Path::new(&dir).join(image.file_name().unwrap())).unwrap();
    }
}

#[test]
fn every_method_writes_an_image_that_reads_back() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    for method in SquashfsMethod::ALL {
        let image = root.path().join(format!("w-{}.squashfs", method.name()));
        let report = ops::create(
            &image,
            std::slice::from_ref(&input),
            &spec(method),
            &CreateOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap_or_else(|e| panic!("{method:?}: {e}"));
        assert_eq!(report.files, 5, "{method:?}");
        keep(&image);

        let mut cx = SimpleCtx::new();
        let mut opened = open(&image, &OpenOptions::default(), &mut cx).unwrap();
        let info = opened.reader.info(&mut cx).unwrap();
        assert_eq!(info.methods, [method.name()]);
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "tree",
                "tree/docs",
                "tree/docs/big.bin",
                "tree/docs/deep",
                "tree/docs/deep/er",
                "tree/docs/deep/er/zeros.bin",
                "tree/docs/empty.txt",
                "tree/hello.txt",
                "tree/ünïcödé",
                "tree/ünïcödé/名前.txt",
            ],
            "{method:?}"
        );
        let t = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        assert!(entries.iter().all(|e| e.modified == Some(t)), "{method:?}");
        let hello = entries.iter().find(|e| e.path == "tree/hello.txt").unwrap();
        assert_eq!(hello.kind, EntryKind::File);
        assert_eq!(hello.size, Some(15));
        let mut data = String::new();
        opened
            .reader
            .open_entry(hello.id, &mut cx)
            .unwrap()
            .read_to_string(&mut data)
            .unwrap();
        assert_eq!(data, "Hello, BeeZip!\n");

        let dest = root.path().join(format!("x-{}", method.name()));
        ops::extract(
            &image,
            &dest,
            &Selection::all(),
            &OpenOptions::default(),
            FsOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        assert_eq!(files(&dest.join("tree")), files(&input), "{method:?}");
    }
}
