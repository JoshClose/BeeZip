//! squashfs (docs/M5.md §5.10): the writer through `ops`, checked by BeeZip's reader (the
//! interop with unsquashfs and 7-Zip is CI's), and the reader on mksquashfs's fixtures and on
//! images built here byte by byte, for what neither mksquashfs nor backhand writes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use beezip_core::{
    ArchiveKind, CodecId, ConvertOptions, CreateOptions, Ctx, EntryKind, ErrorKind, FsOptions,
    OpenOptions, OverwriteChoice, Progress, Selection, SimpleCtx, WriteSpec,
    format::{
        ArchiveReader, NewEntry, NewKind,
        squashfs::{SquashfsMethod, SquashfsReader, SquashfsWriteOptions},
        zip::ZipWriteOptions,
    },
    open, ops,
    source::Source,
};

fn spec(method: SquashfsMethod) -> WriteSpec {
    WriteSpec::Squashfs(SquashfsWriteOptions {
        method,
        level: method.resolve_level(None).unwrap(),
    })
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty/squashfs")
        .join(name)
}

/// 2026-01-01T00:00:00Z.
const MTIME: u64 = 1_767_225_600;

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
    let when = filetime::FileTime::from_unix_time(MTIME as i64, 0);
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

fn extract_all(image: &Path, dest: &Path) -> beezip_core::ExtractReport {
    ops::extract(
        image,
        dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap()
}

/// Nothing but `keep` is left in `dir`: no partial output, no spool.
fn only(dir: &Path, keep: &[&str]) {
    let mut left: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, keep, "in {}", dir.display());
}

// ---- Writing. ----

#[test]
fn every_method_writes_an_image_that_reads_back() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    for method in SquashfsMethod::ALL {
        let image = root.path().join(format!("w-{}.squashfs", method.name()));
        let mut cx = SimpleCtx::new();
        let report = ops::create(
            &image,
            std::slice::from_ref(&input),
            &spec(method),
            &CreateOptions::default(),
            &mut cx,
        )
        .unwrap_or_else(|e| panic!("{method:?}: {e}"));
        assert_eq!(report.files, 5, "{method:?}");
        let last = cx.last_progress.unwrap();
        assert_eq!(last.entries_done, last.entries_total.unwrap(), "{method:?}");
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
        let t = UNIX_EPOCH + Duration::from_secs(MTIME);
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
        extract_all(&image, &dest);
        assert_eq!(files(&dest.join("tree")), files(&input), "{method:?}");
    }
}

/// What follows the superblock: the compressor's options, where the flag says they're there.
fn options(image: &Path) -> Option<Vec<u8>> {
    let b = fs::read(image).unwrap();
    let flags = u16::from_le_bytes([b[24], b[25]]);
    (flags & 0x0400 != 0).then(|| {
        let header = u16::from_le_bytes([b[96], b[97]]);
        assert_eq!(header & 0x8000, 0x8000, "options are stored uncompressed");
        b[98..98 + usize::from(header & 0x7FFF)].to_vec()
    })
}

/// The options are the ones mksquashfs 4.6.1 writes for the same settings (checked by hand,
/// with `-Xcompression-level`): none at its defaults, gzip's 8 bytes, zstd's 4, lz4's always.
#[test]
fn compressor_options_are_mksquashfs_s() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("a.txt");
    fs::write(&input, b"options").unwrap();
    let le = |n: u32| n.to_le_bytes().to_vec();
    let gzip = |l: u32| [le(l), vec![15, 0, 0, 0]].concat();
    for (method, level, want) in [
        (SquashfsMethod::Gzip, Some(9), None),
        (SquashfsMethod::Gzip, Some(1), Some(gzip(1))),
        (SquashfsMethod::Gzip, Some(6), Some(gzip(6))),
        (SquashfsMethod::Xz, Some(6), None),
        (SquashfsMethod::Xz, Some(0), None),
        (SquashfsMethod::Zstd, Some(15), None),
        (SquashfsMethod::Zstd, Some(19), Some(le(19))),
        (SquashfsMethod::Zstd, Some(1), Some(le(1))),
        (SquashfsMethod::Lz4, None, Some([le(1), le(0)].concat())),
        (SquashfsMethod::Lzo, None, None),
    ] {
        let image = root
            .path()
            .join(format!("{}-{level:?}.squashfs", method.name()));
        let spec = WriteSpec::Squashfs(SquashfsWriteOptions { method, level });
        ops::create(
            &image,
            std::slice::from_ref(&input),
            &spec,
            &CreateOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        assert_eq!(options(&image), want, "{method:?} {level:?}");
        let dest = root.path().join(format!("x-{}-{level:?}", method.name()));
        extract_all(&image, &dest);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"options");
    }
}

/// Entries decoded from another archive have no file: their data is spooled beside the output,
/// and the spool goes when the image is done.
#[test]
fn converting_spools_and_cleans_up() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let zip = root.path().join("a.zip");
    ops::create(
        &zip,
        std::slice::from_ref(&input),
        &WriteSpec::Zip(ZipWriteOptions::default()),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let out = root.path().join("out");
    fs::create_dir(&out).unwrap();
    let image = out.join("a.squashfs");
    let spec = spec(SquashfsMethod::Zstd);
    let report = ops::convert(
        &zip,
        &image,
        ArchiveKind::Squashfs,
        &spec,
        &ConvertOptions::default(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(report.files, 5);
    only(&out, &["a.squashfs"]);
    let dest = root.path().join("x");
    extract_all(&image, &dest);
    assert_eq!(files(&dest.join("tree")), files(&input));
}

/// backhand writes the superblock last, seeking back to the start: a split image is written
/// across its parts all the same, and reads back from them joined.
#[test]
fn a_split_image_reads_back() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let image = root.path().join("split.squashfs");
    let report = ops::create(
        &image,
        std::slice::from_ref(&input),
        &spec(SquashfsMethod::Lz4),
        &CreateOptions {
            volume_size: Some(64 * 1024),
            ..CreateOptions::default()
        },
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(report.volumes.len() > 2, "{:?}", report.volumes);
    let dest = root.path().join("x");
    extract_all(&beezip_core::volume::part_path(&image, 1), &dest);
    assert_eq!(files(&dest.join("tree")), files(&input));
}

fn entry(path: &str, kind: NewKind) -> NewEntry {
    NewEntry {
        path: path.into(),
        kind,
        size: 0,
        modified: Some(UNIX_EPOCH + Duration::from_secs(MTIME)),
        unix_mode: None,
        dos_attrs: None,
        source: None,
    }
}

/// Writes `entries` (with their data, spooled) straight through the writer.
fn write_entries(image: &Path, entries: &[(NewEntry, &[u8])], cx: &mut dyn Ctx) {
    let file = fs::File::create(image).unwrap();
    let mut w = ops::create_writer(&spec(SquashfsMethod::Gzip), Box::new(file), image).unwrap();
    let news: Vec<NewEntry> = entries.iter().map(|(e, _)| e.clone()).collect();
    w.expect(&news).unwrap();
    for (e, mut data) in entries.iter().cloned() {
        w.add(&e, &mut data, cx).unwrap();
    }
    w.finish(cx).unwrap();
    keep(image);
}

/// Symlinks (a target of 255 bytes is the longest backhand writes; 301 bytes is left out),
/// folders nobody gave, an entry given twice, and paths squashfs can't hold.
#[test]
fn links_missing_folders_and_odd_paths() {
    let root = tempfile::tempdir().unwrap();
    let image = root.path().join("links.squashfs");
    let long = format!("{}t", "x/".repeat(127));
    let too_long = format!("{}t", "x/".repeat(150));
    let file = |p: &str, data: &'static [u8]| {
        (
            NewEntry {
                size: data.len() as u64,
                ..entry(p, NewKind::File)
            },
            data,
        )
    };
    let link = |p: &str, t: &str| {
        (
            entry(
                p,
                NewKind::Symlink {
                    target: t.to_owned(),
                },
            ),
            &b""[..],
        )
    };
    let mut cx = SimpleCtx::new();
    write_entries(
        &image,
        &[
            file("deep/er/a.txt", b"first"),
            link("deep/link", "er/a.txt"),
            link("long", &long),
            link("too-long", &too_long),
            file("deep/er/a.txt", b"second"),
            (entry("deep", NewKind::Dir), b""),
            file("../escape.txt", b"no"),
            file("./b.txt", b"b"),
        ],
        &mut cx,
    );
    assert_eq!(long.len(), 255);
    assert_eq!(cx.warnings.len(), 3, "{:?}", cx.warnings);
    assert!(cx.warnings[0].contains("too-long"), "{:?}", cx.warnings);
    assert!(cx.warnings[1].contains("given twice"), "{:?}", cx.warnings);
    assert!(cx.warnings[2].contains("escape.txt"), "{:?}", cx.warnings);

    let mut opened = open(&image, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let listed: Vec<(&str, &EntryKind)> =
        entries.iter().map(|e| (e.path.as_str(), &e.kind)).collect();
    let sym = |t: &str| EntryKind::Symlink {
        target: t.to_owned(),
    };
    assert_eq!(
        listed,
        [
            ("b.txt", &EntryKind::File),
            ("deep", &EntryKind::Dir),
            ("deep/er", &EntryKind::Dir),
            ("deep/er/a.txt", &EntryKind::File),
            ("deep/link", &sym("er/a.txt")),
            ("long", &sym(&long)),
        ]
    );
    let modes: Vec<Option<u32>> = entries.iter().map(|e| e.unix_mode).collect();
    assert_eq!(
        modes,
        [
            Some(0o100_644),
            Some(0o040_755),
            Some(0o040_755),
            Some(0o100_644),
            Some(0o120_777),
            Some(0o120_777),
        ]
    );
    let mut data = Vec::new();
    opened
        .reader
        .open_entry(3, &mut cx)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"second");
}

#[test]
fn an_empty_image_is_fine() {
    let root = tempfile::tempdir().unwrap();
    let image = root.path().join("empty.squashfs");
    write_entries(&image, &[], &mut SimpleCtx::new());
    let mut cx = SimpleCtx::new();
    let mut opened = open(&image, &OpenOptions::default(), &mut cx).unwrap();
    assert!(opened.reader.entries(&mut cx).unwrap().is_empty());
}

/// A file planned at one length and another when the image is written is `Corrupt`, longer or
/// shorter, and nothing is left behind.
#[test]
fn a_file_that_changes_size_is_corrupt() {
    for grow in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("in");
        fs::create_dir(&input).unwrap();
        let f = input.join("f.bin");
        fs::write(&f, vec![7u8; 10_000]).unwrap();
        let out = root.path().join("out");
        fs::create_dir(&out).unwrap();
        let image = out.join("a.squashfs");
        let partial = beezip_core::safefs::Partial::create(&out, ".a.squashfs").unwrap();
        let mut w = ops::create_writer(
            &spec(SquashfsMethod::Gzip),
            Box::new(partial.try_clone().unwrap()),
            &image,
        )
        .unwrap();
        let mut cx = SimpleCtx::new();
        let e = NewEntry {
            size: 10_000,
            source: Some(f.clone()),
            ..entry("f.bin", NewKind::File)
        };
        w.add(&e, &mut std::io::empty(), &mut cx).unwrap();
        fs::write(&f, vec![7u8; if grow { 10_001 } else { 9_999 }]).unwrap();
        let err = w.finish(&mut cx).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
        assert!(err.message.contains("changed size"), "{err}");
        drop(partial);
        only(&out, &[]);
    }
}

/// Cancels once it has been told of `after` steps of progress.
struct CancelAfter {
    after: u64,
    calls: u64,
}

impl Ctx for CancelAfter {
    fn is_cancelled(&self) -> bool {
        self.calls >= self.after
    }

    fn progress(&mut self, _: &Progress) {
        self.calls += 1;
    }

    fn warn(&mut self, _: String) {}

    fn password(&mut self, _: Option<&str>, _: u32) -> beezip_core::Result<String> {
        Err(beezip_core::Error::new(ErrorKind::PasswordRequired, "none"))
    }

    fn overwrite(&mut self, _: &Path) -> beezip_core::Result<OverwriteChoice> {
        Ok(OverwriteChoice::Replace)
    }
}

/// Cancelled at any point while the image is written, a create stops with `Cancelled` and
/// leaves neither the image nor the spool.
#[test]
fn cancelling_leaves_nothing() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    // How many steps a whole create reports, to cancel at each stage of it.
    let mut count = CancelAfter {
        after: u64::MAX,
        calls: 0,
    };
    let image = root.path().join("count.squashfs");
    ops::create(
        &image,
        std::slice::from_ref(&input),
        &spec(SquashfsMethod::Gzip),
        &CreateOptions::default(),
        &mut count,
    )
    .unwrap();
    assert!(count.calls > 10, "{}", count.calls);
    for after in [0, 1, 3, count.calls / 2, count.calls - 3] {
        let out = root.path().join(format!("out{after}"));
        fs::create_dir(&out).unwrap();
        let err = ops::create(
            &out.join("a.squashfs"),
            std::slice::from_ref(&input),
            &spec(SquashfsMethod::Gzip),
            &CreateOptions::default(),
            &mut CancelAfter { after, calls: 0 },
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled, "after {after}: {err}");
        only(&out, &[]);
    }
    // A convert, which spools.
    let zip = root.path().join("a.zip");
    ops::create(
        &zip,
        std::slice::from_ref(&input),
        &WriteSpec::Zip(ZipWriteOptions::default()),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let out = root.path().join("convert");
    fs::create_dir(&out).unwrap();
    let err = ops::convert(
        &zip,
        &out.join("a.squashfs"),
        ArchiveKind::Squashfs,
        &spec(SquashfsMethod::Gzip),
        &ConvertOptions::default(),
        &OpenOptions::default(),
        &mut CancelAfter {
            after: 20,
            calls: 0,
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled, "{err}");
    only(&out, &[]);
}

// ---- Reading mksquashfs's images (the manifest has their entries; these are the corners). ----

#[test]
fn fixtures_name_their_compressor() {
    for (file, method) in [
        ("gzip.squashfs", "gzip"),
        ("lzma.squashfs", "lzma"),
        ("xz-bcj.squashfs", "xz"),
        ("lz4hc.squashfs", "lz4"),
        ("lzo.squashfs", "lzo"),
        ("zstd.squashfs", "zstd"),
    ] {
        let mut cx = SimpleCtx::new();
        let mut opened = open(&fixture(file), &OpenOptions::default(), &mut cx).unwrap();
        assert_eq!(opened.reader.info(&mut cx).unwrap().methods, [method]);
    }
}

/// The hard link is a `Hardlink` to the first name listed, with the same data; the device and
/// the FIFO are `Other`, with their file types in the mode.
#[test]
fn links_devices_and_modes() {
    let mut cx = SimpleCtx::new();
    let mut opened = open(&fixture("gzip.squashfs"), &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let find = |p: &str| entries.iter().find(|e| e.path == p).unwrap();
    assert_eq!(find("docs/hard-hello").kind, EntryKind::File);
    let hello = find("hello.txt");
    assert_eq!(
        hello.kind,
        EntryKind::Hardlink {
            target: "docs/hard-hello".into()
        }
    );
    let mut data = Vec::new();
    opened
        .reader
        .open_entry(hello.id, &mut cx)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"Hello, BeeZip!\n");
    assert_eq!(find("devs/null").kind, EntryKind::Other);
    assert_eq!(find("devs/null").unix_mode, Some(0o020_666));
    assert_eq!(find("devs/fifo").unix_mode, Some(0o010_644));
    assert_eq!(find("docs").unix_mode, Some(0o040_755));
    assert_eq!(find("docs/link-to-hello").unix_mode, Some(0o120_777));
    assert_eq!(find("docs/sparse.bin").size, Some(12_292));
    // A folder comes before its contents.
    for e in &entries {
        if let Some((parent, _)) = e.path.rsplit_once('/') {
            assert!(find(parent).id < e.id, "{}", e.path);
        }
    }
}

/// An image inside a codec is spooled, then read as any other.
#[test]
fn an_image_inside_gzip_reads() {
    let root = tempfile::tempdir().unwrap();
    let gz = root.path().join("a.squashfs.gz");
    let mut enc = flate2::write::GzEncoder::new(
        fs::File::create(&gz).unwrap(),
        flate2::Compression::default(),
    );
    enc.write_all(&fs::read(fixture("zstd.squashfs")).unwrap())
        .unwrap();
    enc.finish().unwrap();
    let mut cx = SimpleCtx::new();
    let source = Source::new(&gz, vec![CodecId::Gzip], &OpenOptions::default()).unwrap();
    let mut r = SquashfsReader::open(source, &mut cx).unwrap();
    let entries = r.entries(&mut cx).unwrap().to_vec();
    let id = entries
        .iter()
        .position(|e| e.path == "docs/blocks.bin")
        .unwrap();
    let mut data = Vec::new();
    r.open_entry(id, &mut cx)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data.len(), 13_788);
    assert_eq!(r.info(&mut cx).unwrap().codecs, [CodecId::Gzip]);
}

#[test]
fn a_cut_image_is_corrupt() {
    let root = tempfile::tempdir().unwrap();
    let bytes = fs::read(fixture("gzip.squashfs")).unwrap();
    let used = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    for cut in [0, 50, 96, used / 2, used - 1] {
        let path = root.path().join(format!("cut{cut}.squashfs"));
        fs::write(&path, &bytes[..cut]).unwrap();
        let source = Source::new(&path, Vec::new(), &OpenOptions::default()).unwrap();
        let err = SquashfsReader::open(source, &mut SimpleCtx::new())
            .err()
            .unwrap();
        assert_eq!(err.kind, ErrorKind::Corrupt, "cut at {cut}: {err}");
    }
}

/// Mutated images open and read, or fail with an error: never a panic or a large allocation
/// (the fuzz target goes further).
#[test]
fn mutated_images_fail_cleanly() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("m.squashfs");
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed
    };
    for file in ["gzip.squashfs", "zstd.squashfs", "uncompressed.squashfs"] {
        let good = fs::read(fixture(file)).unwrap();
        for _ in 0..400 {
            let mut bytes = good.clone();
            for _ in 0..1 + next() % 4 {
                let at = (next() % bytes.len() as u64) as usize;
                bytes[at] = next() as u8;
            }
            fs::write(&path, &bytes).unwrap();
            let _ = ops::test(
                &path,
                &Selection::all(),
                &OpenOptions::default(),
                &mut SimpleCtx::new(),
            );
        }
    }
}

// ---- Images built here, stored uncompressed, for what the tools don't write. ----

mod build {
    //! squashfs 4.0 images by hand: every block stored uncompressed, one directory header per
    //! entry, 4 KiB data blocks, no fragments.

    /// Node 0 is the root.
    pub enum Node {
        /// Entries: name and node.
        Dir(Vec<(Vec<u8>, usize)>),
        /// Data in 4 KiB blocks, and the size the inode claims (the data's when `None`).
        File(Vec<u8>, Option<u64>),
        Symlink(Vec<u8>),
        Fifo,
    }

    const BS: usize = 4096;
    const META: usize = 8192;

    fn inode_len(n: &Node) -> usize {
        16 + match n {
            Node::Dir(_) => 16,
            Node::File(d, _) => 16 + 4 * d.len().div_ceil(BS),
            Node::Symlink(t) => 8 + t.len(),
            Node::Fifo => 4,
        }
    }

    /// A table's bytes as uncompressed metadata blocks, and the reference of a position in it.
    fn blocks(table: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in table.chunks(META) {
            out.extend_from_slice(&(0x8000 | chunk.len() as u16).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    fn reference(pos: usize) -> (u32, u16) {
        (((pos / META) * (META + 2)) as u32, (pos % META) as u16)
    }

    pub fn image(nodes: &[Node]) -> Vec<u8> {
        let mut out = vec![0u8; 96];
        // Data first, then where each inode and listing goes.
        let mut starts = Vec::new();
        for n in nodes {
            starts.push(out.len());
            if let Node::File(d, _) = n {
                out.extend_from_slice(d);
            }
        }
        let mut ipos = Vec::new();
        let mut at = 0;
        for n in nodes {
            ipos.push(at);
            at += inode_len(n);
        }
        let mut dpos = vec![0; nodes.len()];
        let mut dlen = vec![0; nodes.len()];
        let mut at = 0;
        for (i, n) in nodes.iter().enumerate() {
            if let Node::Dir(entries) = n {
                dpos[i] = at;
                dlen[i] = entries
                    .iter()
                    .map(|(name, _)| 20 + name.len())
                    .sum::<usize>();
                at += dlen[i];
            }
        }
        let mut inodes = Vec::new();
        let mut dirs = Vec::new();
        for (i, n) in nodes.iter().enumerate() {
            let kind: u16 = match n {
                Node::Dir(_) => 1,
                Node::File(..) => 2,
                Node::Symlink(_) => 3,
                Node::Fifo => 6,
            };
            inodes.extend_from_slice(&kind.to_le_bytes());
            inodes.extend_from_slice(&0o755u16.to_le_bytes());
            inodes.extend_from_slice(&[0; 8]); // uid, gid, mtime
            inodes.extend_from_slice(&(i as u32 + 1).to_le_bytes());
            match n {
                Node::Dir(entries) => {
                    let (block, offset) = reference(dpos[i]);
                    inodes.extend_from_slice(&block.to_le_bytes());
                    inodes.extend_from_slice(&2u32.to_le_bytes());
                    inodes.extend_from_slice(&((dlen[i] + 3) as u16).to_le_bytes());
                    inodes.extend_from_slice(&offset.to_le_bytes());
                    inodes.extend_from_slice(&1u32.to_le_bytes());
                    for (name, child) in entries {
                        let (block, offset) = reference(ipos[*child]);
                        let kind: u16 = match nodes[*child] {
                            Node::Dir(_) => 1,
                            Node::File(..) => 2,
                            Node::Symlink(_) => 3,
                            Node::Fifo => 6,
                        };
                        dirs.extend_from_slice(&0u32.to_le_bytes());
                        dirs.extend_from_slice(&block.to_le_bytes());
                        dirs.extend_from_slice(&(*child as u32 + 1).to_le_bytes());
                        dirs.extend_from_slice(&offset.to_le_bytes());
                        dirs.extend_from_slice(&0u16.to_le_bytes());
                        dirs.extend_from_slice(&kind.to_le_bytes());
                        dirs.extend_from_slice(&(name.len() as u16 - 1).to_le_bytes());
                        dirs.extend_from_slice(name);
                    }
                }
                Node::File(d, size) => {
                    inodes.extend_from_slice(&(starts[i] as u32).to_le_bytes());
                    inodes.extend_from_slice(&u32::MAX.to_le_bytes());
                    inodes.extend_from_slice(&0u32.to_le_bytes());
                    let len = size.unwrap_or(d.len() as u64);
                    inodes.extend_from_slice(&(len as u32).to_le_bytes());
                    for chunk in d.chunks(BS) {
                        inodes.extend_from_slice(&(chunk.len() as u32 | 1 << 24).to_le_bytes());
                    }
                }
                Node::Symlink(t) => {
                    inodes.extend_from_slice(&1u32.to_le_bytes());
                    inodes.extend_from_slice(&(t.len() as u32).to_le_bytes());
                    inodes.extend_from_slice(t);
                }
                Node::Fifo => inodes.extend_from_slice(&1u32.to_le_bytes()),
            }
        }
        let inode_table = out.len();
        out.extend(blocks(&inodes));
        let dir_table = out.len();
        out.extend(blocks(&dirs));
        let ids = out.len();
        out.extend(blocks(&0u32.to_le_bytes()));
        let id_table = out.len();
        out.extend_from_slice(&(ids as u64).to_le_bytes());
        let (block, offset) = reference(ipos[0]);
        let root = (u64::from(block) << 16) | u64::from(offset);
        let mut sb = Vec::new();
        sb.extend_from_slice(b"hsqs");
        sb.extend_from_slice(&(nodes.len() as u32).to_le_bytes());
        sb.extend_from_slice(&0u32.to_le_bytes()); // time
        sb.extend_from_slice(&(BS as u32).to_le_bytes());
        sb.extend_from_slice(&0u32.to_le_bytes()); // fragments
        sb.extend_from_slice(&1u16.to_le_bytes()); // gzip
        sb.extend_from_slice(&12u16.to_le_bytes());
        sb.extend_from_slice(&0x001Bu16.to_le_bytes()); // stored uncompressed, no fragments
        sb.extend_from_slice(&1u16.to_le_bytes()); // ids
        sb.extend_from_slice(&4u16.to_le_bytes());
        sb.extend_from_slice(&0u16.to_le_bytes());
        for v in [
            root,
            out.len() as u64,
            id_table as u64,
            u64::MAX,
            inode_table as u64,
            dir_table as u64,
            u64::MAX,
            u64::MAX,
        ] {
            sb.extend_from_slice(&v.to_le_bytes());
        }
        out[..96].copy_from_slice(&sb);
        out
    }
}

use build::Node;

fn read_built(nodes: &[Node]) -> (beezip_core::Result<Vec<beezip_core::Entry>>, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("built.squashfs");
    fs::write(&path, build::image(nodes)).unwrap();
    let mut cx = SimpleCtx::new();
    let r = open(&path, &OpenOptions::default(), &mut cx).and_then(|mut o| {
        let entries = o.reader.entries(&mut cx)?.to_vec();
        // Every file read to its end.
        for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
            let mut r = o.reader.open_entry(e.id, &mut cx)?;
            std::io::copy(&mut r, &mut std::io::sink())
                .map_err(|e| beezip_core::io::read_error(&e))?;
        }
        Ok(entries)
    });
    (r, cx.warnings)
}

#[test]
fn the_builder_makes_images_that_read() {
    let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    let (r, _) = read_built(&[
        Node::Dir(vec![
            (b"a".to_vec(), 1),
            (b"f.bin".to_vec(), 2),
            (b"fifo".to_vec(), 3),
        ]),
        Node::Dir(vec![(b"link".to_vec(), 4)]),
        Node::File(data, None),
        Node::Fifo,
        Node::Symlink(b"../f.bin".to_vec()),
    ]);
    let entries = r.unwrap();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["a", "a/link", "f.bin", "fifo"]);
    assert_eq!(entries[2].size, Some(10_000));
}

/// A folder that lists its parent: listed once, the loop skipped with a warning.
#[test]
fn a_folder_cycle_is_skipped() {
    let (r, warnings) = read_built(&[
        Node::Dir(vec![(b"a".to_vec(), 1)]),
        Node::Dir(vec![(b"up".to_vec(), 0), (b"me".to_vec(), 1)]),
    ]);
    let entries = r.unwrap();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["a"]);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
}

#[test]
fn deep_nesting_is_corrupt() {
    let depth = 1100;
    let mut nodes: Vec<Node> = (0..depth)
        .map(|i| Node::Dir(vec![(b"d".to_vec(), i + 1)]))
        .collect();
    nodes.push(Node::Dir(Vec::new()));
    let (r, _) = read_built(&nodes);
    let err = r.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
    assert!(err.message.contains("nested"), "{err}");
}

/// A file whose inode claims more than its blocks hold is `Corrupt` when it's read; one whose
/// block list couldn't fit in the inode table, when the image opens.
#[test]
fn files_that_lie_about_their_size_are_corrupt() {
    let (r, _) = read_built(&[
        Node::Dir(vec![(b"f".to_vec(), 1)]),
        Node::File(vec![1u8; 4000], Some(5000)),
    ]);
    let err = r.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
    let (r, _) = read_built(&[
        Node::Dir(vec![(b"f".to_vec(), 1)]),
        Node::File(vec![1u8; 10], Some(u64::from(u32::MAX))),
    ]);
    let err = r.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
    assert!(
        err.message.contains("more than the inode table can hold"),
        "{err}"
    );
}
