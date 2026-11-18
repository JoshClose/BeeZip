//! `.bhive` round trips (docs/M13.md §8): trees of files (empty, tiny, cell-sized and one more
//! or less, several cells, duplicates, shifted copies) at every level, written on one thread
//! and on several to the same bytes, extracted on one thread and on several, and tested.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use beezip_core::{
    ArchiveReader, CreateOptions, EntryKind, ErrorKind, FormatId, FsOptions, Limits, OpenOptions,
    Selection, SimpleCtx, WriteSpec, detect_path,
    format::bhive::{BhiveReader, BhiveWriteOptions, Level, layout::Coder},
    open, ops,
    source::Source,
};
use filetime::FileTime;
use proptest::prelude::*;

/// Bytes with no pattern.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.extend_from_slice(&s.to_le_bytes());
    }
    v.truncate(len);
    v
}

/// Bytes that compress: words.
fn words(len: usize, seed: u64) -> Vec<u8> {
    let list = [
        "bee", "zip", "hive", "honey", "comb", "wax", "pollen", "queen",
    ];
    let mut out = Vec::with_capacity(len + 8);
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(list[(x % 8) as usize].as_bytes());
        out.push(if x.is_multiple_of(5) { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

fn spec(level: Level, threads: u32, cell_size: Option<u32>) -> WriteSpec {
    WriteSpec::Bhive(BhiveWriteOptions {
        level,
        threads,
        memory: None,
        cell_size,
    })
}

fn at(secs: u64, nanos: u32) -> SystemTime {
    UNIX_EPOCH + Duration::new(secs, nanos)
}

/// Writes `files` (path, bytes) under `dir`, each with a time of its own.
fn write_tree(dir: &Path, files: &[(String, Vec<u8>)]) {
    for (i, (path, data)) in files.iter().enumerate() {
        let p = dir.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        let t = at(
            1_600_000_000 + i as u64 * 61,
            (i as u32 * 1_234_567) % 1_000_000_000 / 100 * 100,
        );
        filetime::set_file_mtime(&p, FileTime::from_system_time(t)).unwrap();
    }
}

/// Every file under `dir`: its path, bytes and modification time.
fn read_tree(dir: &Path) -> BTreeMap<String, (Vec<u8>, SystemTime)> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(dir) {
        let e = e.unwrap();
        if e.file_type().is_file() {
            let rel = e.path().strip_prefix(dir).unwrap();
            let rel = rel.to_string_lossy().replace('\\', "/");
            let m = e.metadata().unwrap().modified().unwrap();
            out.insert(rel, (fs::read(e.path()).unwrap(), m));
        }
    }
    out
}

fn create(archive: &Path, input: &Path, spec: &WriteSpec) {
    ops::create(
        archive,
        &[input.to_path_buf()],
        spec,
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
}

fn threads(n: u32) -> OpenOptions {
    OpenOptions {
        threads: n,
        min_parallel_files: 1,
        ..OpenOptions::default()
    }
}

fn extract(archive: &Path, dest: &Path, opts: &OpenOptions) -> beezip_core::ExtractReport {
    ops::extract(
        archive,
        dest,
        &Selection::all(),
        opts,
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap()
}

fn reader(archive: &Path, opts: &OpenOptions) -> BhiveReader {
    let source = Source::new(archive, Vec::new(), opts).unwrap();
    BhiveReader::open(source, &mut SimpleCtx::new()).unwrap()
}

/// Creates an archive of `files` with `spec`, then checks it every way: detected, listed,
/// tested, extracted on one thread and on four to the same tree, each file read by itself.
fn round_trip(files: &[(String, Vec<u8>)], spec: &WriteSpec) -> PathBuf {
    let root = tempfile::tempdir().unwrap().keep();
    let input = root.join("in");
    fs::create_dir(&input).unwrap();
    write_tree(&input, files);
    let archive = root.join("out.bhive");
    create(&archive, &input, spec);

    let det = detect_path(&archive, &Limits::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::Bhive));
    assert!(det.extension_agrees);

    let want = read_tree(&input);
    for (n, opts) in [(1, threads(1)), (4, threads(4))] {
        let dest = root.join(format!("x{n}"));
        let report = extract(&archive, &dest, &opts);
        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert_eq!(report.files, files.len() as u64, "{n} threads");
        let got = read_tree(&dest.join("in"));
        assert_eq!(got.len(), want.len());
        for (path, (data, modified)) in &want {
            let (d, m) = &got[path];
            assert!(d == data, "{path} differs on {n} threads");
            assert_eq!(m, modified, "{path}'s time on {n} threads");
        }
        let test = ops::test(&archive, &Selection::all(), &opts, &mut SimpleCtx::new()).unwrap();
        assert!(test.ok(), "{:?}", test.errors);
        assert_eq!(
            test.bytes,
            files.iter().map(|f| f.1.len() as u64).sum::<u64>()
        );
    }

    // Each file by itself, through the reader.
    let mut r = reader(&archive, &OpenOptions::default());
    let mut cx = SimpleCtx::new();
    let entries = r.entries(&mut cx).unwrap().to_vec();
    for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
        let mut data = Vec::new();
        r.open_entry(e.id, &mut cx)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        let path = e.path.strip_prefix("in/").unwrap();
        assert!(data == want[path].0, "{path} differs through open_entry");
        assert_eq!(e.size, Some(data.len() as u64));
    }
    root
}

fn file(path: &str, data: Vec<u8>) -> (String, Vec<u8>) {
    (path.to_owned(), data)
}

/// A tree with every shape the plan names, around a cell of `cell` bytes.
fn shapes(cell: usize) -> Vec<(String, Vec<u8>)> {
    let big = words(cell * 3 + 777, 1);
    let mut shifted = big[..cell].to_vec();
    shifted.extend_from_slice(b"an insertion that moves every byte after it");
    shifted.extend_from_slice(&big[cell..]);
    vec![
        file("empty", Vec::new()),
        file("tiny.txt", b"bee".to_vec()),
        file("a/words.txt", words(cell / 3, 2)),
        file("a/exact.bin", noise(cell, 3)),
        file("a/less.bin", noise(cell - 1, 4)),
        file("a/more.bin", noise(cell + 1, 5)),
        file("a/b/big.txt", big.clone()),
        file("a/b/copy of big.txt", big),
        file("a/b/shifted.txt", shifted),
        file("c/zeros", vec![0; cell * 2]),
        file("c/tiny copy.txt", b"bee".to_vec()),
        file("c/noise.bin", noise(cell / 2 + 100, 6)),
        file("c/noise again.bin", noise(cell / 2 + 100, 6)),
        file("d/empty too", Vec::new()),
    ]
}

#[test]
fn every_level_round_trips_every_shape() {
    for level in Level::ALL {
        for cell in [64 << 10, 5000] {
            let root = round_trip(&shapes(cell), &spec(level, 4, Some(cell as u32)));
            let r = reader(&root.join("out.bhive"), &OpenOptions::default());
            assert_eq!(r.level(), Some(level));
            assert!(r.cells().iter().all(|c| c.raw as usize <= cell));
            assert!(r.cells().len() > 8, "{level:?}: {} cells", r.cells().len());
            let coders: Vec<Coder> = r.cells().iter().map(|c| c.coder).collect();
            match level {
                Level::None => assert!(coders.iter().all(|c| *c == Coder::Stored)),
                Level::Fast | Level::Balanced => assert!(coders.contains(&Coder::Zstd)),
                Level::High | Level::Max => assert!(coders.contains(&Coder::Lzma2)),
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}

/// The level's own cells, with a file bigger than one.
#[test]
fn the_default_level_round_trips_a_file_bigger_than_a_cell() {
    let mut files = shapes(100_000);
    files.push(file("big/nine.bin", words(9 << 20, 9)));
    files.push(file("big/noise.bin", noise(3 << 20, 10)));
    let root = round_trip(&files, &spec(Level::Balanced, 0, None));
    let r = reader(&root.join("out.bhive"), &OpenOptions::default());
    assert!(r.cells().len() >= 2);
    fs::remove_dir_all(root).unwrap();
}

/// One thread and several write the same bytes: every decision is the planner's, in order.
#[test]
fn the_archive_is_the_same_however_many_threads_write_it() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    fs::create_dir(&input).unwrap();
    write_tree(&input, &shapes(40_000));
    for level in Level::ALL {
        let mut made = Vec::new();
        for threads in [1, 2, 7] {
            let archive = root
                .path()
                .join(format!("{}-{threads}.bhive", level.name()));
            create(&archive, &input, &spec(level, threads, Some(40_000)));
            made.push(fs::read(&archive).unwrap());
        }
        assert!(made[0] == made[1] && made[1] == made[2], "{level:?}");
    }
}

/// Repeated content is stored once from Fast up, and not at None.
#[test]
fn repeated_content_is_stored_once() {
    let content = noise(600_000, 21);
    let files: Vec<_> = (0..5)
        .map(|i| file(&format!("copy{i}.bin"), content.clone()))
        .collect();
    let size = |level| {
        let root = round_trip(&files, &spec(level, 2, None));
        let len = fs::metadata(root.join("out.bhive")).unwrap().len();
        fs::remove_dir_all(root).unwrap();
        len
    };
    let none = size(Level::None);
    let fast = size(Level::Fast);
    assert!(none > 3_000_000, "{none}");
    assert!(fast < 700_000, "{fast}");
}

/// Folders, an empty one too, and their times; a symbolic link where the system makes one.
#[test]
fn folders_and_links_round_trip() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    fs::create_dir_all(input.join("a/empty")).unwrap();
    fs::write(input.join("a/f.txt"), b"hello").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("a/f.txt", input.join("link")).unwrap();
    let t = at(1_500_000_000, 0);
    for p in ["a/empty", "a", ""] {
        filetime::set_file_mtime(input.join(p), FileTime::from_system_time(t)).unwrap();
    }
    let archive = root.path().join("out.bhive");
    create(&archive, &input, &spec(Level::Balanced, 1, None));

    let mut r = reader(&archive, &OpenOptions::default());
    let mut cx = SimpleCtx::new();
    let entries = r.entries(&mut cx).unwrap().to_vec();
    let dirs: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind == EntryKind::Dir)
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(dirs, ["in", "in/a", "in/a/empty"]);
    assert!(entries.iter().all(|e| e.modified.is_some()));
    #[cfg(unix)]
    assert!(entries.iter().any(|e| matches!(&e.kind,
        EntryKind::Symlink { target } if target == "a/f.txt")));

    let dest = root.path().join("x");
    ops::extract(
        &archive,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions {
            links: true,
            ..FsOptions::default()
        },
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(dest.join("in/a/empty").is_dir());
    let m = fs::metadata(dest.join("in/a/empty"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(m, t);
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(dest.join("in/link")).unwrap(),
        Path::new("a/f.txt")
    );
}

/// A file's creation time is stored, and given back where the system lets one be set.
#[test]
#[cfg(any(windows, target_os = "macos"))]
fn creation_times_round_trip() {
    #[cfg(target_os = "macos")]
    use std::os::darwin::fs::FileTimesExt;
    #[cfg(windows)]
    use std::os::windows::fs::FileTimesExt;
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    fs::create_dir(&input).unwrap();
    let (created, modified) = (at(1_400_000_000, 0), at(1_500_000_000, 0));
    for name in ["small.txt", "big.bin"] {
        let p = input.join(name);
        fs::write(&p, noise(if name == "big.bin" { 5 << 20 } else { 10 }, 1)).unwrap();
        let times = fs::FileTimes::new()
            .set_created(created)
            .set_modified(modified);
        fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_times(times)
            .unwrap();
    }
    let archive = root.path().join("out.bhive");
    create(&archive, &input, &spec(Level::Fast, 2, None));
    let mut r = reader(&archive, &OpenOptions::default());
    let entries = r.entries(&mut SimpleCtx::new()).unwrap().to_vec();
    assert_eq!(entries[1].created, Some(created));
    for (n, opts) in [(1, threads(1)), (4, threads(4))] {
        let dest = root.path().join(format!("x{n}"));
        extract(&archive, &dest, &opts);
        for name in ["small.txt", "big.bin"] {
            let m = fs::metadata(dest.join("in").join(name)).unwrap();
            assert_eq!(m.created().unwrap(), created, "{name} on {n} threads");
            assert_eq!(m.modified().unwrap(), modified, "{name} on {n} threads");
        }
    }
}

/// An archive of nothing is a header, an index and a footer.
#[test]
fn an_empty_archive() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("empty.bhive");
    ops::create(
        &archive,
        &[],
        &spec(Level::Balanced, 1, None),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(fs::metadata(&archive).unwrap().len() < 100);
    let mut opened = open(&archive, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
    assert!(
        opened
            .reader
            .entries(&mut SimpleCtx::new())
            .unwrap()
            .is_empty()
    );
    let test = ops::test(
        &archive,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(test.ok());
}

/// A cancelled create leaves no archive and no partial file.
#[test]
fn a_cancelled_create_leaves_nothing() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    fs::create_dir(&input).unwrap();
    write_tree(&input, &shapes(50_000));
    let archive = root.path().join("out.bhive");
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let e = ops::create(
        &archive,
        &[input],
        &spec(Level::High, 4, Some(50_000)),
        &CreateOptions::default(),
        &mut SimpleCtx::new().with_cancel(flag),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Cancelled);
    let left: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["in"]);
}

fn shape() -> impl Strategy<Value = Vec<u8>> {
    let cell = 6000usize;
    prop_oneof![
        Just(Vec::new()),
        proptest::collection::vec(any::<u8>(), 1..64),
        (0u64..8, 1usize..3 * cell).prop_map(|(seed, len)| words(len, seed)),
        (0u64..8, 1usize..3 * cell).prop_map(|(seed, len)| noise(len, seed)),
        (
            0u64..4,
            prop_oneof![Just(cell - 1), Just(cell), Just(cell + 1), Just(4 * cell)]
        )
            .prop_map(|(seed, len)| noise(len, seed)),
        // A copy of some words with a piece cut out: a shifted copy.
        (0u64..8, 0usize..2 * cell, 1usize..cell).prop_map(move |(seed, from, len)| {
            let mut w = words(3 * cell, seed);
            w.drain(from..from + len);
            w
        }),
    ]
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn trees_round_trip(
        shapes in proptest::collection::vec(shape(), 0..24),
        level in 0i64..5,
        threads in 1u32..5,
    ) {
        let files: Vec<_> = shapes
            .into_iter()
            .enumerate()
            .map(|(i, data)| file(&format!("d{}/f{i}", i % 3), data))
            .collect();
        let level = Level::from_number(level).unwrap();
        let root = round_trip(&files, &spec(level, threads, Some(6000)));
        fs::remove_dir_all(root).unwrap();
    }
}

/// Not a test: packs the folder named by `BEEZIP_BHIVE_MEASURE` at every level and prints sizes
/// and times, for comparing a change with docs/M13.md §4. Run it alone, in a release build:
/// `cargo test --release -p beezip-core --test bhive -- --ignored measure --nocapture`.
#[test]
#[ignore = "a measurement, run by hand"]
fn measure() {
    let Ok(dir) = std::env::var("BEEZIP_BHIVE_MEASURE") else {
        return;
    };
    let threads: u32 = std::env::var("BEEZIP_BHIVE_THREADS")
        .ok()
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
    let input = PathBuf::from(dir);
    let root = tempfile::tempdir().unwrap();
    let total: u64 = walkdir::WalkDir::new(&input)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().map_or(0, |m| m.len()))
        .sum();
    let mib = total as f64 / f64::from(1 << 20);
    println!(
        "{}: {mib:.0} MiB, {threads} threads (0: all)",
        input.display()
    );
    println!("level\tbytes\t%\tcreate s\tMiB/s\ttest s\tMiB/s\textract s\tcells\tindex+records %");
    let only = std::env::var("BEEZIP_BHIVE_LEVELS").unwrap_or_default();
    for level in Level::ALL {
        if !only.is_empty() && !only.split(',').any(|l| l == level.name()) {
            continue;
        }
        let archive = root.path().join(format!("{}.bhive", level.name()));
        let t = std::time::Instant::now();
        create(&archive, &input, &spec(level, threads, None));
        let made = t.elapsed().as_secs_f64();
        let len = fs::metadata(&archive).unwrap().len();
        let opts = OpenOptions {
            threads,
            ..OpenOptions::default()
        };
        let t = std::time::Instant::now();
        let report = ops::test(&archive, &Selection::all(), &opts, &mut SimpleCtx::new()).unwrap();
        let tested = t.elapsed().as_secs_f64();
        assert!(report.ok(), "{:?}", report.errors);
        let dest = root.path().join(format!("x-{}", level.name()));
        let t = std::time::Instant::now();
        extract(&archive, &dest, &opts);
        let extracted = t.elapsed().as_secs_f64();
        let r = reader(&archive, &opts);
        let cells = r.cells().len();
        // What isn't a cell's data: the index block, and the records with their journals.
        let stored: u64 = r.cells().iter().map(|c| u64::from(c.stored)).sum();
        println!(
            "{}\t{len}\t{:.2}\t{made:.2}\t{:.0}\t{tested:.2}\t{:.0}\t{extracted:.2}\t{cells}\t{:.2}",
            level.name(),
            100.0 * len as f64 / total as f64,
            mib / made,
            mib / tested,
            100.0 * (len - stored) as f64 / len as f64,
        );
        // A scanner may still hold a file it is looking at.
        let _ = fs::remove_dir_all(&dest);
    }
}

// The fixtures of `tests/fixtures/bhive/` (docs/M13.md §8), from `cargo xtask gen-fixtures`: one
// for each level and each feature of the format, and what each must read back as.

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture_dir() -> PathBuf {
    repo().join("tests/fixtures/bhive")
}

fn manifest() -> Vec<serde_json::Value> {
    let text = fs::read_to_string(fixture_dir().join("manifest.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["fixtures"].as_array().unwrap().clone()
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A manifest time, `[seconds, nanoseconds]` or null, as this system keeps it.
fn time_of(v: &serde_json::Value) -> Option<SystemTime> {
    let secs = v.get(0)?.as_i64()?;
    let nanos = v.get(1)?.as_u64()?;
    beezip_core::time::from_unix(secs, nanos as u32)
}

/// The files of an extracted tree: path and contents' hash.
fn hashes(dir: &Path) -> BTreeMap<String, String> {
    read_tree(dir)
        .into_iter()
        .map(|(path, (data, _))| (path, sha256(&data)))
        .collect()
}

/// The files a fixture's record expects, the same way.
fn expected_files(fx: &serde_json::Value) -> BTreeMap<String, String> {
    fx["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "file")
        .map(|e| {
            (
                e["path"].as_str().unwrap().to_owned(),
                e["sha256"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn every_fixture_reads_as_its_record_says() {
    let all = manifest();
    assert_eq!(all.len(), 16, "the manifest lists every fixture");
    for fx in &all {
        let name = fx["file"].as_str().unwrap();
        let path = fixture_dir().join(name);
        let recover = fx["recover"] == true;
        let det = detect_path(&path, &Limits::default()).unwrap();
        assert_eq!(det.format(), Some(FormatId::Bhive), "{name}");

        for n in [1, 4] {
            let opts = OpenOptions {
                recover,
                ..threads(n)
            };
            if recover {
                let e = open(&path, &threads(n), &mut SimpleCtx::new())
                    .err()
                    .unwrap();
                assert_eq!(e.kind, ErrorKind::Corrupt, "{name}");
            }
            let mut r = reader(&path, &opts);
            assert_eq!(r.recovered().is_some(), recover, "{name}");
            let mut cx = SimpleCtx::new();
            let entries = r.entries(&mut cx).unwrap().to_vec();
            let want = fx["entries"].as_array().unwrap();
            assert_eq!(entries.len(), want.len(), "{name}");
            for (e, w) in entries.iter().zip(want) {
                let what = format!("{name}: {}", e.path);
                assert_eq!(e.path, w["path"].as_str().unwrap(), "{name}");
                let kind = match &e.kind {
                    EntryKind::File => "file",
                    EntryKind::Dir => "folder",
                    EntryKind::Symlink { target } => {
                        assert_eq!(target, w["target"].as_str().unwrap(), "{what}");
                        "link"
                    }
                    other => panic!("{what}: {other:?}"),
                };
                assert_eq!(kind, w["kind"].as_str().unwrap(), "{what}");
                assert_eq!(e.modified, time_of(&w["modified"]), "{what}");
                assert_eq!(e.created, time_of(&w["created"]), "{what}");
                assert_eq!(e.unix_mode.map(u64::from), w["mode"].as_u64(), "{what}");
                assert_eq!(
                    e.dos_attrs.map(u64::from),
                    w["attributes"].as_u64(),
                    "{what}"
                );
                if e.kind == EntryKind::File {
                    assert_eq!(e.size, w["size"].as_u64(), "{what}");
                    let mut data = Vec::new();
                    r.open_entry(e.id, &mut cx)
                        .unwrap()
                        .read_to_end(&mut data)
                        .unwrap();
                    assert_eq!(sha256(&data), w["sha256"].as_str().unwrap(), "{what}");
                }
            }
            if let Some(level) = fx["level"].as_str() {
                assert_eq!(r.level().map(Level::name), Some(level), "{name}");
            }
            if let Some(coders) = fx["coders"].as_array() {
                let methods = r.info(&mut cx).unwrap().methods;
                let methods: Vec<&str> = methods.iter().map(|m| m.as_ref()).collect();
                let coders: Vec<&str> = coders.iter().filter_map(|c| c.as_str()).collect();
                assert_eq!(methods, coders, "{name}");
            }

            // The whole archive, tested and extracted.
            let test = ops::test(&path, &Selection::all(), &opts, &mut cx).unwrap();
            assert_eq!(test.ok(), !recover, "{name}: {:?}", test.errors);
            let dest = tempfile::tempdir().unwrap();
            let report = ops::extract(
                &path,
                dest.path(),
                &Selection::all(),
                &opts,
                FsOptions::default(),
                &mut cx,
            )
            .unwrap();
            // Links aren't made unless asked for; nothing else is left out.
            assert!(
                report
                    .skipped
                    .iter()
                    .all(|s| s.reason == beezip_core::SkipReason::LinksDisabled),
                "{name}: {:?}",
                report.skipped
            );
            assert_eq!(
                hashes(dest.path()),
                expected_files(fx),
                "{name} on {n} threads"
            );
            // Times that every file system keeps: whole seconds, in this century.
            for w in want.iter().filter(|w| w["kind"] == "file") {
                let secs = w["modified"].get(0).and_then(serde_json::Value::as_i64);
                if let Some(secs) = secs.filter(|s| (946_684_800..4_102_444_800).contains(s)) {
                    let m = fs::metadata(dest.path().join(w["path"].as_str().unwrap())).unwrap();
                    let got = m.modified().unwrap().duration_since(UNIX_EPOCH).unwrap();
                    assert_eq!(got.as_secs() as i64, secs, "{name}: {}", w["path"]);
                }
            }
        }
    }
}

/// What the level fixtures hold in their cells: the coders of each level, and extents that
/// reach back into earlier cells.
#[test]
fn the_fixtures_exercise_what_they_are_for() {
    let cells = |name: &str| {
        reader(&fixture_dir().join(name), &OpenOptions::default())
            .cells()
            .to_vec()
    };
    for (name, coder) in [
        ("none.bhive", Coder::Stored),
        ("fast.bhive", Coder::Zstd),
        ("balanced.bhive", Coder::Zstd),
        ("high.bhive", Coder::Lzma2),
        ("max.bhive", Coder::Lzma2),
    ] {
        let c = cells(name);
        assert_eq!(c.len(), 1, "{name}");
        assert_eq!(c[0].coder, coder, "{name}");
    }
    assert!(cells("cells.bhive").len() > 20);
    let probe = cells("probe.bhive");
    assert!(probe.iter().any(|c| c.coder == Coder::Stored && c.raw > 0));
    assert!(probe.iter().any(|c| c.coder == Coder::Lzma2));
    let max = cells("max-cells.bhive");
    assert!(max.iter().filter(|c| c.coder == Coder::Lzma2).count() > 5);
    // The last record of an archive of folders carries a journal and no bytes.
    let folders = cells("folders.bhive");
    assert_eq!(folders.len(), 1);
    assert_eq!((folders[0].raw, folders[0].stored), (0, 0));
    assert!(cells("empty.bhive").is_empty());
    // Repeated content is stored once from Fast up: the tree holds its words three times.
    let fast = fs::metadata(fixture_dir().join("fast.bhive"))
        .unwrap()
        .len();
    let none = fs::metadata(fixture_dir().join("none.bhive"))
        .unwrap()
        .len();
    assert!(none > 280_000 && fast < 20_000, "{none} {fast}");
}

/// The bytes docs/bhive.md lists for its examples are the fixtures' bytes.
#[test]
fn the_specifications_examples_are_the_fixtures() {
    let spec = fs::read_to_string(repo().join("docs/bhive.md")).unwrap();
    for name in ["spec-empty.bhive", "spec-small.bhive"] {
        let marker = format!("<!-- bytes of {name} -->");
        let at = spec
            .find(&marker)
            .unwrap_or_else(|| panic!("no listing of {name}"));
        let block = spec[at..].split("```").nth(1).unwrap();
        let mut bytes = Vec::new();
        for line in block.lines().map(str::trim_end) {
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            // An offset, two spaces, the bytes, and after two more spaces what they are.
            let mut parts = line.splitn(3, "  ");
            let offset = usize::from_str_radix(parts.next().unwrap(), 16).unwrap();
            assert_eq!(offset, bytes.len(), "{name}: `{line}`");
            for b in parts.next().unwrap().split_whitespace() {
                assert_eq!(b.len(), 2, "{name}: `{line}`");
                bytes.push(u8::from_str_radix(b, 16).unwrap());
            }
        }
        let file = fs::read(fixture_dir().join(name)).unwrap();
        assert!(bytes == file, "{name}: the listing isn't the file");
    }
}

/// A Python that has Zstandard in its standard library (3.14), if this machine has one.
/// `BEEZIP_REQUIRE_PYTHON=1` (CI) makes its absence a failure.
fn python() -> Option<String> {
    for exe in ["python3", "python", "python3.14"] {
        let ok = std::process::Command::new(exe)
            .args(["-I", "-c", "import compression.zstd"])
            .output()
            .is_ok_and(|o| o.status.success());
        if ok {
            return Some(exe.to_owned());
        }
    }
    if std::env::var("BEEZIP_REQUIRE_PYTHON").as_deref() == Ok("1") {
        panic!("the reference reader needs Python 3.14 or later on PATH");
    }
    eprintln!("skipped: no Python 3.14 on PATH for docs/bhive_reader.py");
    None
}

/// docs/bhive_reader.py, a reader written from the specification alone, lists, tests and
/// extracts every fixture as its record says (docs/M13.md decision 12).
#[test]
fn the_python_reader_agrees() {
    use std::ffi::OsStr;
    let Some(python) = python() else {
        return;
    };
    let script = repo().join("docs/bhive_reader.py");
    let run = |args: &[&OsStr]| {
        std::process::Command::new(&python)
            .arg("-I")
            .arg(&script)
            .args(args)
            .output()
            .unwrap()
    };
    let stamp = |v: &serde_json::Value| match (v.get(0), v.get(1)) {
        (Some(s), Some(n)) => format!("{}.{:09}", s.as_i64().unwrap(), n.as_u64().unwrap()),
        _ => "-".to_owned(),
    };
    for fx in &manifest() {
        let name = fx["file"].as_str().unwrap();
        let path = fixture_dir().join(name);
        let recover = fx["recover"] == true;
        let with = |command: &'static str, more: &[&OsStr]| {
            let mut args: Vec<&OsStr> = vec![command.as_ref(), path.as_os_str()];
            args.extend_from_slice(more);
            if recover {
                args.push("--recover".as_ref());
            }
            run(&args)
        };
        // An incomplete archive is said to be one, by the exit code.
        let code = i32::from(recover);

        let out = with("list", &[]);
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(code), "{name}: {err}");
        let want: Vec<String> = fx["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let number = |v: &serde_json::Value, hex: bool| match v.as_u64() {
                    Some(n) if hex => format!("{n:x}"),
                    Some(n) => format!("{n:o}"),
                    None => "-".to_owned(),
                };
                let mut fields = vec![
                    e["kind"].as_str().unwrap().to_owned(),
                    e["size"].as_u64().unwrap_or(0).to_string(),
                    stamp(&e["modified"]),
                    stamp(&e["created"]),
                    number(&e["mode"], false),
                    number(&e["attributes"], true),
                    e["path"].as_str().unwrap().to_owned(),
                ];
                if let Some(t) = e["target"].as_str() {
                    fields.push(t.to_owned());
                }
                fields.join("\t")
            })
            .collect();
        let listed = String::from_utf8(out.stdout).unwrap();
        let listed: Vec<&str> = listed.lines().collect();
        assert_eq!(listed, want, "{name}");

        let out = with("test", &[]);
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(code), "{name}: {err}");

        // Windows may not let this user make a link: such a fixture is listed and tested here,
        // and extracted by BeeZip above.
        let links = fx["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "link");
        if links && cfg!(windows) {
            continue;
        }
        let dest = tempfile::tempdir().unwrap();
        let out = with("extract", &[dest.path().as_os_str()]);
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(code), "{name}: {err}");
        assert_eq!(hashes(dest.path()), expected_files(fx), "{name}");
    }

    // And it refuses what breaks the format's rules, as BeeZip does.
    let malicious = repo().join("tests/fixtures/malicious");
    for name in [
        "bhive-extent-past-cell.bhive",
        "bhive-extent-no-cell.bhive",
        "bhive-cells-overlap.bhive",
        "bhive-entries-2-60.bhive",
        "bhive-cells-2-60.bhive",
        "bhive-cell-over-256m.bhive",
        "bhive-index-more.bhive",
        "bhive-footer-outside.bhive",
        "bhive-footer-in-cell.bhive",
        "bhive-version-2.bhive",
        "bhive-feature.bhive",
        "bhive-cut-index.bhive",
        "bhive-raw-more.bhive",
        "bhive-raw-less.bhive",
    ] {
        let file = malicious.join(name);
        let out = run(&["test".as_ref(), file.as_os_str()]);
        assert_eq!(out.status.code(), Some(1), "{name}");
    }
}

// A stand-in for the two fuzz targets that runs with `cargo test` (as `mutations.rs` is for the
// others): the fixtures and the malicious files, and bit-flipped, truncated and spliced copies
// of them, through the reader; and the index and journals of each, mutated behind their
// checksums, through the parsers.

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed | 1;
    move || {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn mutate(data: &[u8], other: &[u8], next: &mut impl FnMut() -> u64) -> Vec<u8> {
    let mut d = data.to_vec();
    let n = |next: &mut dyn FnMut() -> u64, max: usize| (next() % max.max(1) as u64) as usize;
    match next() % 5 {
        0 => {
            for _ in 0..1 + n(next, 8) {
                if !d.is_empty() {
                    let i = n(next, d.len());
                    d[i] ^= 1 << (next() % 8);
                }
            }
        }
        1 => d.truncate(n(next, d.len() + 1)),
        2 => {
            let at = n(next, d.len() + 1);
            let from = n(next, other.len() + 1);
            let len = n(next, 64).min(other.len() - from);
            d.splice(at..at, other[from..from + len].iter().copied());
        }
        3 => {
            // A number made large: what a length or a count is most often.
            if !d.is_empty() {
                let i = n(next, d.len());
                let v = [0u8, 0xFF, 0x7F, 0x80][n(next, 4)];
                for b in d.iter_mut().skip(i).take(1 + n(next, 9)) {
                    *b = v;
                }
            }
        }
        _ => {
            if d.len() > 1 {
                let (a, b) = (n(next, d.len()), n(next, d.len()));
                d.swap(a, b);
            }
        }
    }
    d
}

/// Tight limits, as the fuzzers have: a bomb among the mutations can't stall the run.
fn tight() -> Limits {
    Limits {
        max_ratio: Some(200),
        ratio_grace: 1 << 20,
        max_total_bytes: Some(32 << 20),
        max_entries: Some(10_000),
        max_layers: 4,
        decoder_memory: 64 << 20,
    }
}

/// What the `bhive` fuzz target does with an input.
fn exercise(path: &Path) {
    for (recover, n) in [(false, 1), (true, 1), (false, 3)] {
        let opts = OpenOptions {
            recover,
            threads: n,
            min_parallel_files: 1,
            ..OpenOptions::new(tight())
        };
        let mut cx = SimpleCtx::new();
        let Ok(source) = Source::new(path, Vec::new(), &opts) else {
            return;
        };
        let Ok(mut r) = BhiveReader::open(source, &mut cx) else {
            continue;
        };
        let count = r.entries(&mut cx).map(<[_]>::len).unwrap_or(0);
        let _ = r.info(&mut cx);
        let _ = r.extract(
            &Selection::all(),
            &mut beezip_core::NullSink::default(),
            &mut cx,
        );
        for id in 0..count.min(8) {
            if let Ok(mut e) = r.open_entry(id, &mut cx) {
                let _ = std::io::copy(&mut e.by_ref().take(1 << 20), &mut std::io::sink());
            }
        }
        let _ = r.test(&mut cx);
    }
}

/// What the `bhive-index` fuzz target does with an input: whatever the parser accepts keeps
/// the rules the reader relies on.
fn parse(raw: &[u8], index_offset: u64) {
    use beezip_core::format::bhive::layout::{self, Items};
    let Ok(index) = layout::parse_index(raw, index_offset, Some(10_000)) else {
        return;
    };
    let mut end = 16u64;
    for cell in &index.cells {
        assert!(cell.offset >= end + 48 && cell.end() <= index_offset);
        assert!(cell.raw <= layout::MAX_CELL);
        end = cell.end();
    }
    let mut items = Vec::new();
    for item in &index.items.items {
        let extents = index.items.extents_of(item);
        let size: u64 = extents.iter().map(|x| u64::from(x.len)).sum();
        assert_eq!(size, item.size);
        for x in extents {
            let cell = &index.cells[x.cell as usize];
            assert!(x.len > 0 && u64::from(x.offset) + u64::from(x.len) <= u64::from(cell.raw));
        }
        layout::put_item(
            &mut items,
            &layout::ItemRef {
                kind: item.kind,
                path: &item.path,
                modified: item.modified,
                created: item.created,
                mode: item.mode,
                attrs: item.attrs,
                extents,
                target: &item.target,
            },
        );
    }
    let count = index.items.items.len();
    let again = layout::encode_index(&index.cells, count as u64, &items, index.level);
    assert_eq!(
        layout::parse_index(&again, index_offset, None).unwrap(),
        index
    );
    let _ = layout::parse_journal(&items, count as u32, &index.cells, &mut Items::default());
    let _ = layout::parse_journal(raw, 3, &index.cells, &mut Items::default());
}

#[test]
fn fixtures_and_their_mutations_never_panic() {
    let per = std::env::var("BEEZIP_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48usize);
    let mut files: Vec<PathBuf> = [fixture_dir(), repo().join("tests/fixtures/malicious")]
        .iter()
        .flat_map(|d| fs::read_dir(d).unwrap())
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bhive"))
        // The bombs decode megabytes for every copy; the limits are theirs to test.
        .filter(|p| fs::metadata(p).unwrap().len() < 100_000)
        .collect();
    files.sort();
    assert!(files.len() > 30, "the fixtures are missing");
    let corpus: Vec<Vec<u8>> = files.iter().map(|p| fs::read(p).unwrap()).collect();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bhive");
    let mut next = rng(0x00BE_E21F);
    for (i, data) in corpus.iter().enumerate() {
        let other = &corpus[(i + 1) % corpus.len()];
        fs::write(&path, data).unwrap();
        exercise(&path);
        for _ in 0..per {
            fs::write(&path, mutate(data, other, &mut next)).unwrap();
            exercise(&path);
        }

        // Behind its checksum: the archive's own index, mutated.
        if let Some((raw, offset)) = index_of(data) {
            parse(&raw, offset);
            for _ in 0..per * 4 {
                parse(&mutate(&raw, other, &mut next), offset);
            }
        }
    }
}

/// An archive's index as it is before it is stored, and where its index block starts.
fn index_of(data: &[u8]) -> Option<(Vec<u8>, u64)> {
    use beezip_core::format::bhive::layout::{self, IndexHead};
    let footer = data.get(data.len().checked_sub(16)?..)?;
    let offset = layout::parse_footer(footer)?;
    let at = usize::try_from(offset).ok()?;
    let head = IndexHead::parse(data.get(at..at.checked_add(32)?)?).ok()?;
    let stored = data.get(at + 32..data.len() - 16)?;
    let raw = if head.zstd {
        let len = usize::try_from(head.raw).ok()?.min(16 << 20);
        zstd::bulk::decompress(stored, len).ok()?
    } else {
        stored.to_vec()
    };
    Some((raw, offset))
}
