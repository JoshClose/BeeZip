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
        inherit: false,
        ..BhiveWriteOptions::default()
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
    extract_as(archive, dest, opts, None)
}

fn extract_as(
    archive: &Path,
    dest: &Path,
    opts: &OpenOptions,
    answer: Option<&str>,
) -> beezip_core::ExtractReport {
    ops::extract(
        archive,
        dest,
        &Selection::all(),
        opts,
        FsOptions::default(),
        &mut ctx(answer),
    )
    .unwrap()
}

fn reader(archive: &Path, opts: &OpenOptions) -> BhiveReader {
    reader_as(archive, opts, None)
}

fn reader_as(archive: &Path, opts: &OpenOptions, answer: Option<&str>) -> BhiveReader {
    let source = Source::new(archive, Vec::new(), opts).unwrap();
    BhiveReader::open(source, &mut ctx(answer)).unwrap()
}

/// Creates an archive of `files` with `spec`, then checks it every way: detected, listed,
/// tested, extracted on one thread and on four to the same tree, each file read by itself.
fn round_trip(files: &[(String, Vec<u8>)], spec: &WriteSpec) -> PathBuf {
    round_trip_as(files, spec, None)
}

/// A context that answers with `answer`, the password or recovery key of an encrypted archive.
fn ctx(answer: Option<&str>) -> SimpleCtx {
    match answer {
        Some(a) => SimpleCtx::new().with_password(a),
        None => SimpleCtx::new(),
    }
}

/// [`round_trip`] for an archive that opens with `answer`.
fn round_trip_as(files: &[(String, Vec<u8>)], spec: &WriteSpec, answer: Option<&str>) -> PathBuf {
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
        let report = extract_as(&archive, &dest, &opts, answer);
        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert_eq!(report.files, files.len() as u64, "{n} threads");
        let got = read_tree(&dest.join("in"));
        assert_eq!(got.len(), want.len());
        for (path, (data, modified)) in &want {
            let (d, m) = &got[path];
            assert!(d == data, "{path} differs on {n} threads");
            assert_eq!(m, modified, "{path}'s time on {n} threads");
        }
        let test = ops::test(&archive, &Selection::all(), &opts, &mut ctx(answer)).unwrap();
        assert!(test.ok(), "{:?}", test.errors);
        assert_eq!(
            test.bytes,
            files.iter().map(|f| f.1.len() as u64).sum::<u64>()
        );
    }

    // Each file by itself, through the reader.
    let mut r = reader_as(&archive, &OpenOptions::default(), answer);
    let mut cx = ctx(answer);
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
    let sealed_dir = repo().join("tests/fixtures/bhive-m14");
    for (name, dir) in [
        ("spec-empty.bhive", fixture_dir()),
        ("spec-small.bhive", fixture_dir()),
        ("spec-sealed.bhive", sealed_dir.clone()),
    ] {
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
        let file = fs::read(dir.join(name)).unwrap();
        assert!(bytes == file, "{name}: the listing isn't the file");
    }
    // The encrypted example is spec-small.bhive's contents behind the password `honey`.
    let sealed = sealed_dir.join("spec-sealed.bhive");
    let small = fixture_dir().join("spec-small.bhive");
    let mut a = reader_as(&sealed, &OpenOptions::default(), Some("honey"));
    let mut b = reader(&small, &OpenOptions::default());
    let mut cx = SimpleCtx::new();
    let names = |r: &mut BhiveReader, cx: &mut SimpleCtx| -> Vec<(String, Option<u64>)> {
        let e = r.entries(cx).unwrap();
        e.iter().map(|e| (e.path.clone(), e.size)).collect()
    };
    assert_eq!(names(&mut a, &mut cx), names(&mut b, &mut cx));
    assert_eq!(contents_as(&sealed, Some("honey")), contents(&small));
    let d = a.unlocked().unwrap().descriptions().unwrap();
    assert_eq!(d[0].label.as_deref(), Some("Password"));
    let e = BhiveReader::open(
        Source::new(&sealed, Vec::new(), &OpenOptions::default()).unwrap(),
        &mut SimpleCtx::new().with_password("Honey"),
    )
    .err()
    .unwrap();
    assert_eq!(e.kind, ErrorKind::WrongPassword);
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
    // Every section as it was, the level's included, in the order it was in.
    let sections: Vec<(u64, &[u8])> = index
        .sections
        .iter()
        .map(|s| (s.id, s.body.as_slice()))
        .collect();
    let again = layout::encode_index_with(&index.cells, None, count as u64, &items, &sections);
    // Where the entries lie may move: a reader takes longer varints than a writer makes.
    let mut parsed = layout::parse_index(&again, index_offset, None).unwrap();
    parsed.entry_bytes = index.entry_bytes.clone();
    assert_eq!(parsed, index);
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

// Editing (docs/M13.md §5, decision 14): an edit writes a new archive, copying the cells it
// keeps as they are stored and storing again what is left of a cell that lost most of its bytes.

fn edit_spec(cell_size: u32) -> WriteSpec {
    spec(Level::Balanced, 2, Some(cell_size))
}

fn edit(archive: &Path, op: &beezip_core::EditOp, cell_size: u32) -> beezip_core::EditReport {
    ops::edit(
        archive,
        op,
        &mut |_| Ok(edit_spec(cell_size)),
        &beezip_core::EditOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap()
}

fn remove(paths: &[&str]) -> beezip_core::EditOp {
    let paths: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
    beezip_core::EditOp::Remove(Selection::new(&paths, &[], &[]).unwrap())
}

fn rename(from: &str, to: &str) -> beezip_core::EditOp {
    beezip_core::EditOp::Rename {
        from: from.into(),
        to: to.into(),
    }
}

/// Every file of an archive, by path.
fn contents(archive: &Path) -> BTreeMap<String, Vec<u8>> {
    contents_as(archive, None)
}

fn contents_as(archive: &Path, answer: Option<&str>) -> BTreeMap<String, Vec<u8>> {
    let mut r = reader_as(archive, &OpenOptions::default(), answer);
    let mut cx = ctx(answer);
    let entries = r.entries(&mut cx).unwrap().to_vec();
    let mut out = BTreeMap::new();
    for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
        let mut data = Vec::new();
        r.open_entry(e.id, &mut cx)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        out.insert(e.path.clone(), data);
    }
    out
}

/// Each cell's stored bytes, by its checksum.
fn stored_cells(archive: &Path) -> BTreeMap<u64, Vec<u8>> {
    let bytes = fs::read(archive).unwrap();
    reader(archive, &OpenOptions::default())
        .cells()
        .iter()
        .map(|c| {
            let at = c.offset as usize;
            (c.checksum, bytes[at..at + c.stored as usize].to_vec())
        })
        .collect()
}

/// A tree of ten files of 3,000 bytes in cells of 8 KiB: two to a cell and a bit.
fn ten(root: &Path) -> (PathBuf, BTreeMap<String, Vec<u8>>) {
    let input = root.join("in");
    fs::create_dir(&input).unwrap();
    let files: Vec<_> = (0..10)
        .map(|i| file(&format!("f{i}.bin"), noise(3000, 40 + i)))
        .collect();
    write_tree(&input, &files);
    let archive = root.join("ten.bhive");
    create(&archive, &input, &edit_spec(8 << 10));
    let want = files
        .into_iter()
        .map(|(path, data)| (format!("in/{path}"), data))
        .collect();
    (archive, want)
}

/// A rename decodes nothing: every cell goes into the new archive as it was stored.
#[test]
fn a_rename_copies_every_cell_byte_for_byte() {
    let root = tempfile::tempdir().unwrap();
    let (archive, mut want) = ten(root.path());
    let before = stored_cells(&archive);
    assert!(before.len() >= 4, "{}", before.len());

    let r = edit(&archive, &rename("in/f3.bin", "in/renamed.bin"), 8 << 10);
    assert_eq!((r.renamed, r.recompressed), (1, 0));
    assert_eq!(r.copied, r.entries);
    assert_eq!(stored_cells(&archive), before);
    let data = want.remove("in/f3.bin").unwrap();
    want.insert("in/renamed.bin".into(), data);
    assert_eq!(contents(&archive), want);
    let test = ops::test(
        &archive,
        &Selection::all(),
        &threads(4),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(test.ok(), "{:?}", test.errors);
}

/// An edit that names no level keeps the archive's own: the cells it stores again and the level
/// the index gives are the archive's, not the writer's default.
#[test]
fn an_edit_keeps_the_archives_level() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    fs::create_dir(&input).unwrap();
    let files: Vec<_> = (0..6)
        .map(|i| {
            // About 2,000 bytes of text each, so four share a cell and LZMA2 is worth its time.
            let lines: String = (0..125)
                .map(|j| {
                    format!(
                        "file {i} line {j}
"
                    )
                })
                .collect();
            file(&format!("f{i}.txt"), lines.into_bytes())
        })
        .collect();
    write_tree(&input, &files);
    let archive = root.path().join("high.bhive");
    create(&archive, &input, &spec(Level::High, 2, Some(8 << 10)));
    let level = |archive: &Path| reader(archive, &OpenOptions::default()).level();
    assert_eq!(level(&archive), Some(Level::High));

    let keeping = |inherit: bool| {
        move |_: beezip_core::ArchiveKind| {
            Ok(WriteSpec::Bhive(BhiveWriteOptions {
                level: Level::Fast,
                threads: 2,
                memory: None,
                cell_size: Some(8 << 10),
                inherit,
                ..BhiveWriteOptions::default()
            }))
        }
    };
    // Half of a cell goes, so what is left of it is stored again: at High, as LZMA2.
    let r = ops::edit(
        &archive,
        &remove(&["in/f0.txt", "in/f1.txt", "in/f2.txt"]),
        &mut keeping(true),
        &beezip_core::EditOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(r.removed, 3);
    assert_eq!(level(&archive), Some(Level::High));
    let mut cx = SimpleCtx::new();
    let mut opened = reader(&archive, &OpenOptions::default());
    let methods = opened.info(&mut cx).unwrap().methods;
    assert_eq!(methods, ["LZMA2"], "{methods:?}");
    drop(opened);

    // A level that was chosen is the archive's from then on.
    ops::edit(
        &archive,
        &rename("in/f5.txt", "in/g5.txt"),
        &mut keeping(false),
        &beezip_core::EditOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(level(&archive), Some(Level::Fast));
}

/// A cell that keeps at least half its bytes is copied with the dead ones; one that keeps less
/// is decoded and what is left stored again; one that keeps nothing is dropped.
#[test]
fn a_remove_copies_drops_or_stores_again() {
    let root = tempfile::tempdir().unwrap();
    let (archive, mut want) = ten(root.path());
    let before = stored_cells(&archive);
    let size = fs::metadata(&archive).unwrap().len();
    // Cells hold f0 f1 | f2 f3 | f4 f5 | f6 f7 | f8 f9. Losing one of two files, a cell still
    // has half; losing both, nothing.
    let r = edit(
        &archive,
        &remove(&["in/f1.bin", "in/f4.bin", "in/f5.bin"]),
        8 << 10,
    );
    assert_eq!(r.removed, 3);
    for gone in ["in/f1.bin", "in/f4.bin", "in/f5.bin"] {
        want.remove(gone);
    }
    assert_eq!(contents(&archive), want);
    let after = stored_cells(&archive);
    assert_eq!(after.len(), before.len() - 1, "the emptied cell is gone");
    assert!(
        after
            .iter()
            .all(|(sum, data)| before.get(sum) == Some(data))
    );
    assert_eq!(r.recompressed, 0);
    let smaller = fs::metadata(&archive).unwrap().len();
    assert!(smaller < size - 5000, "{smaller} of {size}");

    // A big file and a small one in one cell: without the big one, the small one's bytes are
    // a sliver of the cell, and are stored again.
    let input = root.path().join("two");
    fs::create_dir(&input).unwrap();
    write_tree(
        &input,
        &[
            file("a big.bin", noise(6000, 1)),
            file("b small.txt", words(700, 2)),
            file("c other.bin", noise(5000, 3)),
        ],
    );
    let archive = root.path().join("two.bhive");
    create(&archive, &input, &edit_spec(8 << 10));
    let before = stored_cells(&archive);
    let r = edit(&archive, &remove(&["two/a big.bin"]), 8 << 10);
    assert_eq!((r.removed, r.recompressed), (1, 1), "{r:?}");
    let after = stored_cells(&archive);
    assert!(after.len() == before.len() && after != before);
    let got = contents(&archive);
    assert_eq!(got.len(), 2);
    assert_eq!(got["two/b small.txt"], words(700, 2));
    assert_eq!(got["two/c other.bin"], noise(5000, 3));
    assert!(fs::metadata(&archive).unwrap().len() < 6500);
}

/// A copy's bytes are the first file's: removing the first keeps them for the copy.
#[test]
fn removing_a_file_keeps_the_bytes_its_copies_use() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    fs::create_dir(&input).unwrap();
    let shared = noise(5000, 9);
    write_tree(
        &input,
        &[
            file("a first.bin", shared.clone()),
            file("b copy.bin", shared.clone()),
            file("c other.txt", words(4000, 1)),
        ],
    );
    let archive = root.path().join("out.bhive");
    create(&archive, &input, &edit_spec(8 << 10));
    let size = fs::metadata(&archive).unwrap().len();
    assert!(size < 9000, "the copy is stored once: {size}");
    edit(&archive, &remove(&["in/a first.bin"]), 8 << 10);
    let got = contents(&archive);
    assert_eq!(got.len(), 2);
    assert_eq!(got["in/b copy.bin"], shared);
}

/// Added files go into new cells after the copied ones; the old cells are untouched.
#[test]
fn an_add_appends_cells() {
    let root = tempfile::tempdir().unwrap();
    let (archive, mut want) = ten(root.path());
    let before = stored_cells(&archive);
    let extra = root.path().join("extra.bin");
    fs::write(&extra, noise(20_000, 77)).unwrap();
    let r = edit(
        &archive,
        &beezip_core::EditOp::Add(beezip_core::AddOptions {
            inputs: vec![extra],
            dir: "in".into(),
            ..beezip_core::AddOptions::default()
        }),
        8 << 10,
    );
    assert_eq!((r.added, r.recompressed), (1, 0));
    want.insert("in/extra.bin".into(), noise(20_000, 77));
    assert_eq!(contents(&archive), want);
    let after = stored_cells(&archive);
    assert!(after.len() > before.len());
    assert!(
        before
            .iter()
            .all(|(sum, data)| after.get(sum) == Some(data))
    );
}

/// An edit keeps every time as the archive has it, those a system's own clock can't hold too.
#[test]
fn an_edit_keeps_times_exactly() {
    use beezip_core::format::bhive::layout;
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("times.bhive");
    fs::copy(fixture_dir().join("times.bhive"), &archive).unwrap();
    let items = |path: &Path| {
        let (raw, offset) = index_of(&fs::read(path).unwrap()).unwrap();
        layout::parse_index(&raw, offset, None).unwrap().items.items
    };
    let before = items(&archive);
    edit(
        &archive,
        &rename("no time.txt", "still no time.txt"),
        4 << 20,
    );
    let after = items(&archive);
    assert_eq!(after.len(), before.len());
    for (a, b) in after.iter().zip(&before) {
        assert_eq!((a.modified, a.created), (b.modified, b.created));
        assert_eq!((a.mode, a.attrs, a.size), (b.mode, b.attrs, b.size));
    }
    assert_eq!(after[4].path, b"still no time.txt");
    assert_eq!(after[1].modified, Some((-28_500_000_000, 0)));
    assert_eq!(after[3].modified, Some((1_767_225_600, 1)));
}

/// After edits the records still list every entry, in order, each in a record no earlier than
/// its bytes: cut anywhere, the edited archive recovers a first part of its entries, whole.
#[test]
fn an_edited_archive_still_recovers() {
    let root = tempfile::tempdir().unwrap();
    let (archive, _) = ten(root.path());
    edit(
        &archive,
        &remove(&["in/f1.bin", "in/f4.bin", "in/f5.bin"]),
        8 << 10,
    );
    edit(&archive, &rename("in/f8.bin", "in/a.bin"), 8 << 10);
    let extra = root.path().join("extra.bin");
    fs::write(&extra, noise(9000, 5)).unwrap();
    edit(
        &archive,
        &beezip_core::EditOp::Add(beezip_core::AddOptions {
            inputs: vec![extra],
            ..beezip_core::AddOptions::default()
        }),
        8 << 10,
    );
    let whole = contents(&archive);
    let all: Vec<String> = reader(&archive, &OpenOptions::default())
        .entries(&mut SimpleCtx::new())
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    let bytes = fs::read(&archive).unwrap();
    let ends: Vec<u64> = reader(&archive, &OpenOptions::default())
        .cells()
        .iter()
        .map(|c| c.offset + u64::from(c.stored))
        .collect();
    let cut = root.path().join("cut.bhive");
    let recover = OpenOptions {
        recover: true,
        ..OpenOptions::default()
    };
    let mut most = 0;
    for &end in &ends {
        fs::write(&cut, &bytes[..end as usize]).unwrap();
        let mut r = reader(&cut, &recover);
        let mut cx = SimpleCtx::new();
        let entries = r.entries(&mut cx).unwrap().to_vec();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, all[..paths.len()], "cut at {end}");
        for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
            let mut data = Vec::new();
            r.open_entry(e.id, &mut cx)
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            assert!(data == whole[&e.path], "{} cut at {end}", e.path);
        }
        most = most.max(paths.len());
    }
    assert_eq!(
        most,
        all.len(),
        "the last cell's record lists the last entries"
    );
    // And the Python reader reads the edited archive.
    if let Some(python) = python() {
        let out = std::process::Command::new(python)
            .arg("-I")
            .arg(repo().join("docs/bhive_reader.py"))
            .arg("test")
            .arg(&archive)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// An archive listed from its records isn't edited: what is left is to be extracted.
#[test]
fn a_recovered_archive_is_not_edited() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("cut.bhive");
    fs::copy(fixture_dir().join("cut.bhive"), &archive).unwrap();
    let e = ops::edit(
        &archive,
        &rename("one.txt", "1.txt"),
        &mut |_| Ok(edit_spec(4 << 20)),
        &beezip_core::EditOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    let opts = beezip_core::EditOptions {
        open: OpenOptions {
            recover: true,
            ..OpenOptions::default()
        },
        ..beezip_core::EditOptions::default()
    };
    let e = ops::edit(
        &archive,
        &rename("one.txt", "1.txt"),
        &mut |_| Ok(edit_spec(4 << 20)),
        &opts,
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    assert!(e.message.contains("incomplete"), "{e}");
}

fn convert(source: &Path, output: &Path, kind: beezip_core::ArchiveKind, spec: &WriteSpec) {
    let r = ops::convert(
        source,
        output,
        kind,
        spec,
        &beezip_core::ConvertOptions::default(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
}

/// Converting to another level decodes every file and packs it again; converting a zip makes a
/// `.bhive` of it.
#[test]
fn converting_changes_the_level_and_the_format() {
    use beezip_core::ArchiveKind;
    let root = tempfile::tempdir().unwrap();
    let (archive, want) = ten(root.path());
    let high = root.path().join("high.bhive");
    convert(
        &archive,
        &high,
        ArchiveKind::Bhive,
        &spec(Level::High, 2, Some(8 << 10)),
    );
    assert_eq!(contents(&high), want);
    assert_eq!(
        reader(&high, &OpenOptions::default()).level(),
        Some(Level::High)
    );

    let zip = root.path().join("out.zip");
    convert(
        &high,
        &zip,
        ArchiveKind::Zip,
        &WriteSpec::Zip(Default::default()),
    );
    let back = root.path().join("back.bhive");
    convert(&zip, &back, ArchiveKind::Bhive, &spec(Level::Fast, 3, None));
    assert_eq!(contents(&back), want);
}

// Encrypted archives (docs/bhive.md §12, docs/M14.md §9): round trips at every level and with
// every way in PR A builds, edits that keep the key and the slots, a new key, protecting a plain
// archive, and files changed in every part, each refused as the specification says.

use beezip_core::format::bhive::crypt::{
    Labelled, Protection, Recipient, Strength,
    envelope::{KeyBlock, Unlocked},
    recovery,
};
use zeroize::Zeroizing;

const HONEY: &str = "honey";
const DIGITS: &str = "000011-000022-000033-000044-000055-000066-000077-000088";

/// A password at a cost a test can afford; BeeZip writes Standard or Strong.
fn small(password: &str) -> Labelled {
    Labelled {
        recipient: Recipient::Password {
            password: Zeroizing::new(password.to_owned()),
            strength: Strength::Cost {
                memory_kib: 256,
                passes: 1,
                lanes: 2,
            },
        },
        label: Some("Password".into()),
    }
}

fn recovery_key(digits: &str) -> Labelled {
    Labelled {
        recipient: Recipient::RecoveryKey(recovery::parse(digits).unwrap()),
        label: Some("Recovery key".into()),
    }
}

fn sealed(level: Level, cell_size: Option<u32>, ways: Vec<Labelled>) -> WriteSpec {
    WriteSpec::Bhive(BhiveWriteOptions {
        level,
        threads: 2,
        cell_size,
        protection: Some(Protection::New(ways)),
        ..BhiveWriteOptions::default()
    })
}

/// The key block of an encrypted archive, as it is in the file.
fn key_block(archive: &Path) -> KeyBlock {
    let bytes = fs::read(archive).unwrap();
    let header: [u8; 16] = bytes[..16].try_into().unwrap();
    KeyBlock::read(&header, &mut &bytes[16..]).unwrap()
}

/// The slots' bytes, as the key block holds them.
fn slots(archive: &Path) -> Vec<Vec<u8>> {
    let k = key_block(archive);
    k.slots
        .iter()
        .map(|(_, r)| k.bytes[r.clone()].to_vec())
        .collect()
}

fn unlocked(archive: &Path, answer: &str) -> std::sync::Arc<Unlocked> {
    reader_as(archive, &OpenOptions::default(), Some(answer))
        .unlocked()
        .unwrap()
        .clone()
}

/// Each cell's bytes as they are in the file (sealed), and its table row less its offset.
fn sealed_cells(archive: &Path, answer: &str) -> Vec<(Vec<u8>, (u32, u32, Coder, u64))> {
    let bytes = fs::read(archive).unwrap();
    reader_as(archive, &OpenOptions::default(), Some(answer))
        .cells()
        .iter()
        .map(|c| {
            let at = c.offset as usize;
            let len = beezip_core::format::bhive::layout::sealed_len(u64::from(c.stored)) as usize;
            (
                bytes[at..at + len].to_vec(),
                (c.stored, c.raw, c.coder, c.checksum),
            )
        })
        .collect()
}

fn open_err(archive: &Path, answer: Option<&str>, recover: bool) -> Option<beezip_core::Error> {
    let opts = OpenOptions {
        recover,
        ..OpenOptions::default()
    };
    let source = Source::new(archive, Vec::new(), &opts).ok()?;
    BhiveReader::open(source, &mut ctx(answer)).err()
}

#[test]
fn every_level_round_trips_encrypted() {
    for level in Level::ALL {
        let files = shapes(64 << 10);
        let spec = sealed(
            level,
            Some(64 << 10),
            vec![small(HONEY), recovery_key(DIGITS)],
        );
        let root = round_trip_as(&files, &spec, Some(HONEY));
        let archive = root.join("out.bhive");
        // The recovery key opens it as well, and the names are sealed with the rest.
        assert_eq!(unlocked(&archive, DIGITS).opened_by(), 1);
        let bytes = fs::read(&archive).unwrap();
        assert!(
            !bytes.windows(4).any(|w| w == b"tiny"),
            "{level:?}: a name in the clear"
        );
        let mut r = reader_as(&archive, &OpenOptions::default(), Some(HONEY));
        let info = r.info(&mut SimpleCtx::new()).unwrap();
        assert_eq!(info.encryption, beezip_core::Encryption::All);
        assert!(info.encrypted_headers);
        assert_eq!(
            open_err(&archive, None, false).unwrap().kind,
            ErrorKind::PasswordRequired
        );
        assert_eq!(
            open_err(&archive, Some("bees"), false).unwrap().kind,
            ErrorKind::WrongPassword
        );
        fs::remove_dir_all(root).unwrap();
    }
}

/// Stored cells of more than 1 MiB are sealed in several segments.
#[test]
fn cells_over_several_segments_round_trip() {
    let files = vec![
        file("big.bin", noise(2_500_000, 1)),
        file("exact.bin", noise(2 << 20, 2)),
        file("small.txt", words(5000, 3)),
    ];
    for level in [Level::None, Level::Fast] {
        let spec = sealed(level, Some(3 << 20), vec![small(HONEY)]);
        let root = round_trip_as(&files, &spec, Some(HONEY));
        let r = reader_as(
            &root.join("out.bhive"),
            &OpenOptions::default(),
            Some(HONEY),
        );
        assert!(r.cells().iter().any(|c| c.stored > 2 << 20), "{level:?}");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn an_empty_encrypted_archive() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("empty.bhive");
    let opts = match sealed(Level::Fast, None, vec![small(HONEY)]) {
        WriteSpec::Bhive(o) => o,
        _ => unreachable!(),
    };
    let out = fs::File::create(&archive).unwrap();
    let w = beezip_core::format::bhive::BhiveWriter::new(Box::new(out), &opts).unwrap();
    beezip_core::ArchiveWriter::finish(Box::new(w), &mut SimpleCtx::new()).unwrap();
    let mut r = reader_as(&archive, &OpenOptions::default(), Some(HONEY));
    assert!(r.entries(&mut SimpleCtx::new()).unwrap().is_empty());
    assert!(r.cells().is_empty());
    assert!(r.test(&mut SimpleCtx::new()).unwrap().unwrap().ok());
}

#[test]
fn repeated_content_is_stored_once_encrypted() {
    let data = noise(300_000, 9);
    let files = vec![file("a.bin", data.clone()), file("b.bin", data)];
    let root = round_trip_as(
        &files,
        &sealed(Level::Fast, None, vec![small(HONEY)]),
        Some(HONEY),
    );
    let size = fs::metadata(root.join("out.bhive")).unwrap().len();
    assert!(size < 320_000, "{size}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn either_of_two_passwords_opens_it() {
    let files = vec![file("a.txt", words(3000, 1))];
    let spec = sealed(Level::Balanced, None, vec![small("one"), small("two")]);
    let root = round_trip_as(&files, &spec, Some("two"));
    let archive = root.join("out.bhive");
    assert_eq!(unlocked(&archive, "two").opened_by(), 1);
    assert_eq!(unlocked(&archive, "one").opened_by(), 0);
    assert_eq!(
        open_err(&archive, Some("three"), false).unwrap().kind,
        ErrorKind::WrongPassword
    );
    fs::remove_dir_all(root).unwrap();
}

/// Ten files of 3,000 bytes, encrypted, in cells of 8 KiB.
fn ten_sealed(root: &Path) -> (PathBuf, BTreeMap<String, Vec<u8>>) {
    let input = root.join("in");
    fs::create_dir(&input).unwrap();
    let files: Vec<_> = (0..10)
        .map(|i| file(&format!("f{i}.bin"), noise(3000, 40 + i)))
        .collect();
    write_tree(&input, &files);
    let archive = root.join("ten.bhive");
    let spec = sealed(
        Level::Balanced,
        Some(8 << 10),
        vec![small(HONEY), recovery_key(DIGITS)],
    );
    create(&archive, &input, &spec);
    let want = files
        .into_iter()
        .map(|(path, data)| (format!("in/{path}"), data))
        .collect();
    (archive, want)
}

fn edit_sealed(archive: &Path, op: &beezip_core::EditOp) -> beezip_core::EditReport {
    ops::edit(
        archive,
        op,
        &mut |_| Ok(edit_spec(8 << 10)),
        &beezip_core::EditOptions::default(),
        &mut ctx(Some(HONEY)),
    )
    .unwrap()
}

/// An edit keeps the file key, the key id and every slot byte for byte, with a new archive id,
/// and copies the cells it keeps sealed as they are (docs/M14.md decision 7).
#[test]
fn edits_keep_the_key_and_the_slots() {
    let root = tempfile::tempdir().unwrap();
    let (archive, mut want) = ten_sealed(root.path());
    let before = slots(&archive);
    let key = key_block(&archive);
    let cells = sealed_cells(&archive, HONEY);

    edit_sealed(&archive, &rename("in/f3.bin", "in/three.bin"));
    let moved = want.remove("in/f3.bin").unwrap();
    want.insert("in/three.bin".into(), moved);
    assert_eq!(contents_as(&archive, Some(HONEY)), want);
    assert_eq!(slots(&archive), before);
    let after = key_block(&archive);
    assert_eq!(after.key_id, key.key_id);
    assert_ne!(after.archive_id, key.archive_id);
    // Every cell, sealed bytes and all.
    assert_eq!(sealed_cells(&archive, HONEY), cells);

    edit_sealed(&archive, &remove(&["in/f0.bin", "in/f1.bin"]));
    want.remove("in/f0.bin");
    want.remove("in/f1.bin");
    assert_eq!(contents_as(&archive, Some(DIGITS)), want);
    assert_eq!(slots(&archive), before);

    let extra = root.path().join("more");
    fs::create_dir(&extra).unwrap();
    fs::write(extra.join("new.txt"), b"added later").unwrap();
    let add = beezip_core::EditOp::Add(beezip_core::AddOptions {
        inputs: vec![extra.join("new.txt")],
        ..beezip_core::AddOptions::default()
    });
    edit_sealed(&archive, &add);
    want.insert("new.txt".into(), b"added later".to_vec());
    assert_eq!(contents_as(&archive, Some(HONEY)), want);
    assert_eq!(slots(&archive), before);
    assert_eq!(key_block(&archive).key_id, key.key_id);
    let test = ops::test(
        &archive,
        &Selection::all(),
        &OpenOptions::default(),
        &mut ctx(Some(HONEY)),
    )
    .unwrap();
    assert!(test.ok(), "{:?}", test.errors);
}

fn convert_as(
    source: &Path,
    output: &Path,
    spec: &WriteSpec,
    answer: Option<&str>,
    decrypt: bool,
) -> beezip_core::Result<beezip_core::ConvertReport> {
    ops::convert(
        source,
        output,
        beezip_core::ArchiveKind::Bhive,
        spec,
        &beezip_core::ConvertOptions {
            raw: true,
            decrypt,
            ..beezip_core::ConvertOptions::default()
        },
        &OpenOptions::default(),
        &mut ctx(answer),
    )
}

fn rows(cells: &[(Vec<u8>, (u32, u32, Coder, u64))]) -> Vec<(u32, u32, Coder, u64)> {
    cells.iter().map(|c| c.1).collect()
}

/// A new key: a new file key and key id, every slot rebuilt with fresh randomness, and every
/// cell's stored bytes sealed again as they are, never packed again (docs/M14.md §3).
#[test]
fn a_new_key_changes_every_slot_and_seals_every_cell_again() {
    let root = tempfile::tempdir().unwrap();
    let (archive, want) = ten_sealed(root.path());
    let fresh = root.path().join("fresh.bhive");
    let spec = sealed(
        Level::Balanced,
        Some(8 << 10),
        vec![small(HONEY), recovery_key(DIGITS)],
    );
    let report = convert_as(&archive, &fresh, &spec, Some(HONEY), false).unwrap();
    assert_eq!(report.recompressed, 0);
    assert_eq!(contents_as(&fresh, Some(DIGITS)), want);
    let (old, new) = (key_block(&archive), key_block(&fresh));
    assert_ne!(old.key_id, new.key_id);
    for (a, b) in slots(&archive).iter().zip(slots(&fresh)) {
        assert_ne!(a[4..], b[4..]);
    }
    let (a, b) = (sealed_cells(&archive, HONEY), sealed_cells(&fresh, HONEY));
    assert_eq!(rows(&a), rows(&b));
    assert!(a.iter().zip(&b).all(|(x, y)| x.0 != y.0));
}

/// Protecting a plain archive seals each cell's stored bytes as they are.
#[test]
fn protecting_an_archive_seals_its_cells_as_they_are() {
    let root = tempfile::tempdir().unwrap();
    let (plain, want) = ten(root.path());
    let protected = root.path().join("protected.bhive");
    let spec = sealed(Level::Balanced, Some(8 << 10), vec![small(HONEY)]);
    let report = convert_as(&plain, &protected, &spec, None, false).unwrap();
    assert_eq!(report.recompressed, 0);
    assert_eq!(contents_as(&protected, Some(HONEY)), want);
    let p = reader(&plain, &OpenOptions::default());
    let q = reader_as(&protected, &OpenOptions::default(), Some(HONEY));
    let row = |c: &beezip_core::format::bhive::layout::Cell| (c.stored, c.raw, c.coder, c.checksum);
    assert_eq!(
        p.cells().iter().map(row).collect::<Vec<_>>(),
        q.cells().iter().map(row).collect::<Vec<_>>()
    );

    // And taken out again, with `decrypt`, into the clear.
    let clear = root.path().join("clear.bhive");
    let plain_spec = spec_of(Level::Balanced);
    convert_as(&protected, &clear, &plain_spec, Some(HONEY), true).unwrap();
    assert_eq!(contents(&clear), want);
    assert!(reader(&clear, &OpenOptions::default()).unlocked().is_none());
    // Without it, a conversion into a .bhive keeps the key; into a zip it is refused.
    let kept = root.path().join("kept.bhive");
    convert_as(&protected, &kept, &plain_spec, Some(HONEY), false).unwrap();
    assert_eq!(key_block(&kept).key_id, key_block(&protected).key_id);
    let zip = root.path().join("out.zip");
    let e = ops::convert(
        &protected,
        &zip,
        beezip_core::ArchiveKind::Zip,
        &WriteSpec::Zip(beezip_core::format::zip::ZipWriteOptions::default()),
        &beezip_core::ConvertOptions::default(),
        &OpenOptions::default(),
        &mut ctx(Some(HONEY)),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidArgs);
}

fn spec_of(level: Level) -> WriteSpec {
    spec(level, 2, Some(8 << 10))
}

/// Ways in added and removed under the same key: the kept slots stay byte for byte, and the
/// cells are copied sealed as they are.
#[test]
fn changing_the_ways_in_keeps_the_key() {
    let root = tempfile::tempdir().unwrap();
    let (archive, want) = ten_sealed(root.path());
    let other = "000110-000220-000330-000440-000550-000660-000770-000880";
    let from = unlocked(&archive, HONEY);
    let spec = WriteSpec::Bhive(BhiveWriteOptions {
        level: Level::Balanced,
        cell_size: Some(8 << 10),
        protection: Some(Protection::Change {
            from,
            remove: vec![1],
            add: vec![recovery_key(other)],
        }),
        ..BhiveWriteOptions::default()
    });
    let changed = root.path().join("changed.bhive");
    convert_as(&archive, &changed, &spec, Some(HONEY), false).unwrap();
    assert_eq!(contents_as(&changed, Some(other)), want);
    assert_eq!(
        open_err(&changed, Some(DIGITS), false).unwrap().kind,
        ErrorKind::WrongPassword
    );
    assert_eq!(slots(&changed)[0], slots(&archive)[0]);
    assert_eq!(key_block(&changed).key_id, key_block(&archive).key_id);
    assert_eq!(sealed_cells(&changed, HONEY), sealed_cells(&archive, HONEY));
    let d = unlocked(&changed, HONEY).descriptions().unwrap();
    assert_eq!(d.len(), 2);
    assert_eq!(d[0].label.as_deref(), Some("Password"));
}

/// Cut anywhere, an encrypted archive is refused cleanly; opened to recover, what its records
/// still list comes back, each record opened with its nonce and offset.
#[test]
fn a_cut_encrypted_archive_is_refused_or_recovered() {
    let root = tempfile::tempdir().unwrap();
    let (archive, want) = ten_sealed(root.path());
    let bytes = fs::read(&archive).unwrap();
    let cut = root.path().join("cut.bhive");
    let r = reader_as(&archive, &OpenOptions::default(), Some(DIGITS));
    let last = *r.cells().last().unwrap();
    let mut step = 0;
    for len in (0..bytes.len()).step_by(97).chain([bytes.len() - 1]) {
        fs::write(&cut, &bytes[..len]).unwrap();
        assert!(open_err(&cut, Some(DIGITS), false).is_some(), "{len}");
        step += 1;
        // Recovered: the cells wholly before the cut, and what their records list.
        let opts = OpenOptions {
            recover: true,
            ..OpenOptions::default()
        };
        let Ok(source) = Source::new(&cut, Vec::new(), &opts) else {
            continue;
        };
        let mut cx = ctx(Some(DIGITS));
        let Ok(mut r) = BhiveReader::open(source, &mut cx) else {
            continue;
        };
        let entries = r.entries(&mut cx).unwrap().to_vec();
        let files: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .collect();
        for e in &files {
            let mut data = Vec::new();
            r.open_entry(e.id, &mut cx)
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            assert!(data == want[&e.path], "{len}: {}", e.path);
        }
        if len as u64
            >= last.offset + beezip_core::format::bhive::layout::sealed_len(u64::from(last.stored))
        {
            assert_eq!(files.len(), want.len(), "{len}");
        }
    }
    assert!(step > 50);
}

/// Cells swapped, duplicated, moved in from another archive under the same key, and segments
/// reordered: each fails its check when it is read, and only its files are lost.
#[test]
fn sealed_cells_that_moved_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let (archive, _) = ten_sealed(root.path());
    let bytes = fs::read(&archive).unwrap();
    let r = reader_as(&archive, &OpenOptions::default(), Some(HONEY));
    let cells = r.cells().to_vec();
    let len = |c: &beezip_core::format::bhive::layout::Cell| {
        beezip_core::format::bhive::layout::sealed_len(u64::from(c.stored)) as usize
    };
    let (a, b) = (cells[0], cells[1]);
    assert_eq!(len(&a), len(&b));
    let at = |c: &beezip_core::format::bhive::layout::Cell| c.offset as usize;
    let failing = |data: &[u8]| -> usize {
        let p = root.path().join("bad.bhive");
        fs::write(&p, data).unwrap();
        let t = ops::test(
            &p,
            &Selection::all(),
            &OpenOptions::default(),
            &mut ctx(Some(HONEY)),
        )
        .unwrap();
        t.errors.len()
    };
    assert_eq!(failing(&bytes), 0);
    // Swapped.
    let mut swapped = bytes.clone();
    swapped[at(&a)..at(&a) + len(&a)].copy_from_slice(&bytes[at(&b)..at(&b) + len(&b)]);
    swapped[at(&b)..at(&b) + len(&b)].copy_from_slice(&bytes[at(&a)..at(&a) + len(&a)]);
    assert!(failing(&swapped) >= 2);
    // Duplicated.
    let mut twice = bytes.clone();
    twice[at(&b)..at(&b) + len(&b)].copy_from_slice(&bytes[at(&a)..at(&a) + len(&a)]);
    assert!(failing(&twice) >= 1);
    // From an archive under the same file key: an edit's, whose new cell has a new id.
    let sibling = root.path().join("sibling.bhive");
    fs::copy(&archive, &sibling).unwrap();
    let more = root.path().join("more");
    fs::create_dir(&more).unwrap();
    write_tree(
        &more,
        &[
            file("m0.bin", noise(3000, 90)),
            file("m1.bin", noise(3000, 91)),
        ],
    );
    let add = beezip_core::EditOp::Add(beezip_core::AddOptions {
        inputs: vec![more.clone()],
        ..beezip_core::AddOptions::default()
    });
    edit_sealed(&sibling, &add);
    let sib = fs::read(&sibling).unwrap();
    let theirs = *reader_as(&sibling, &OpenOptions::default(), Some(HONEY))
        .cells()
        .last()
        .unwrap();
    assert_eq!(len(&theirs), len(&a));
    let mut moved = bytes.clone();
    moved[at(&a)..at(&a) + len(&a)].copy_from_slice(&sib[at(&theirs)..at(&theirs) + len(&theirs)]);
    assert!(failing(&moved) >= 1);
}

/// A cell of two equal segments with the segments swapped, and the sealed index or a record
/// changed.
#[test]
fn reordered_segments_and_changed_frames_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    fs::create_dir(&input).unwrap();
    write_tree(
        &input,
        &[
            file("two.bin", noise(2 << 20, 5)),
            file("b.txt", words(100, 6)),
        ],
    );
    let archive = root.path().join("two.bhive");
    create(
        &archive,
        &input,
        &sealed(Level::None, Some(2 << 20), vec![recovery_key(DIGITS)]),
    );
    let bytes = fs::read(&archive).unwrap();
    let r = reader_as(&archive, &OpenOptions::default(), Some(DIGITS));
    let c = *r.cells().iter().find(|c| c.stored == 2 << 20).unwrap();
    let (at, seg) = (c.offset as usize, (1 << 20) + 16);
    let mut swapped = bytes.clone();
    swapped[at..at + seg].copy_from_slice(&bytes[at + seg..at + 2 * seg]);
    swapped[at + seg..at + 2 * seg].copy_from_slice(&bytes[at..at + seg]);
    let p = root.path().join("bad.bhive");
    fs::write(&p, &swapped).unwrap();
    let t = ops::test(
        &p,
        &Selection::all(),
        &OpenOptions::default(),
        &mut ctx(Some(DIGITS)),
    )
    .unwrap();
    assert!(!t.errors.is_empty());

    // The sealed index changed: refused, and recovered from the records.
    let footer = bytes.len() - 16;
    let index_at = u64::from_le_bytes(bytes[footer..footer + 8].try_into().unwrap()) as usize;
    let mut index = bytes.clone();
    index[index_at + 60] ^= 1;
    fs::write(&p, &index).unwrap();
    assert_eq!(
        open_err(&p, Some(DIGITS), false).unwrap().kind,
        ErrorKind::Corrupt
    );
    assert!(open_err(&p, Some(DIGITS), true).is_none());
    assert_eq!(
        contents_as_recovered(&p),
        contents_as(&archive, Some(DIGITS))
    );

    // A record changed: the index doesn't need it, and recovery stops before it.
    let first = r.cells()[0];
    assert!(first.offset < c.offset);
    let mut record = bytes.clone();
    record[c.offset as usize - 40] ^= 1;
    fs::write(&p, &record).unwrap();
    assert!(open_err(&p, Some(DIGITS), false).is_none());
    record[index_at + 60] ^= 1;
    fs::write(&p, &record).unwrap();
    assert_eq!(contents_as_recovered(&p).len(), 1);
}

fn contents_as_recovered(archive: &Path) -> BTreeMap<String, Vec<u8>> {
    let opts = OpenOptions {
        recover: true,
        ..OpenOptions::default()
    };
    let mut r = reader_as(archive, &opts, Some(DIGITS));
    let mut cx = ctx(Some(DIGITS));
    let entries = r.entries(&mut cx).unwrap().to_vec();
    let mut out = BTreeMap::new();
    for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
        let mut data = Vec::new();
        r.open_entry(e.id, &mut cx)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        out.insert(e.path.clone(), data);
    }
    out
}
