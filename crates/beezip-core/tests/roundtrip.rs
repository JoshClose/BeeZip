//! Archive round trips (docs/M1.md §6). A random tree (names with spaces and non-ASCII, depth up
//! to 4, empty files and directories, mixed compressibility, set mtimes) is written in every
//! writable combination, extracted, and compared: same bytes, same mtimes to the second.
//! `PROPTEST_CASES` raises the case count (default 32 per combination).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use beezip_core::{
    CodecId, CreateOptions, EncodeOpts, FsOptions, OpenOptions, Selection, SimpleCtx, WriteSpec,
    format::{
        cab::{CabMethod, CabWriteOptions},
        dmg::DmgWriteOptions,
        sevenz::{SevenZMethod, SevenZWriteOptions},
        squashfs::{SquashfsMethod, SquashfsWriteOptions},
        zip::{ZipEncryption, ZipMethod, ZipWriteOptions},
    },
    ops,
    time::to_dos,
};
use filetime::FileTime;
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Node {
    File {
        name: String,
        data: Vec<u8>,
        mtime: u64,
    },
    Dir {
        name: String,
        children: Vec<Node>,
        mtime: u64,
    },
}

impl Node {
    fn name(&self) -> &str {
        match self {
            Node::File { name, .. } | Node::Dir { name, .. } => name,
        }
    }
}

const DEVICES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

fn name() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9éü日本_-][a-zA-Z0-9éü日本 ._-]{0,10}[a-zA-Z0-9éü日本_-]|[a-z0-9]".prop_filter(
        "a Windows device name",
        |n| {
            let base = n.split('.').next().unwrap_or(n).to_lowercase();
            !DEVICES.contains(&base.as_str())
        },
    )
}

/// Whole seconds from 1980-01-02 to 2099-12-31, the range zip's DOS times can hold.
fn mtime() -> impl Strategy<Value = u64> {
    315_619_200u64..4_102_358_400
}

fn data() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        proptest::collection::vec(any::<u8>(), 1..2048),
        (1usize..65_536, proptest::collection::vec(any::<u8>(), 1..8)).prop_map(|(len, unit)| unit
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()),
    ]
}

/// Children with names unique ignoring case, as Windows needs.
fn dedupe(nodes: Vec<Node>) -> Vec<Node> {
    let mut seen = HashSet::new();
    nodes
        .into_iter()
        .filter(|n| seen.insert(n.name().to_lowercase()))
        .collect()
}

fn tree() -> impl Strategy<Value = Vec<Node>> {
    let leaf =
        (name(), data(), mtime()).prop_map(|(name, data, mtime)| Node::File { name, data, mtime });
    let node = leaf.prop_recursive(3, 24, 5, |inner| {
        prop_oneof![
            2 => (name(), data(), mtime()).prop_map(|(name, data, mtime)| Node::File { name, data, mtime }),
            1 => (name(), proptest::collection::vec(inner, 0..5), mtime()).prop_map(
                |(name, children, mtime)| Node::Dir { name, children: dedupe(children), mtime }
            ),
        ]
    });
    proptest::collection::vec(node, 0..6).prop_map(dedupe)
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Writes the tree; directory times are set after their contents.
fn write(dir: &Path, nodes: &[Node]) {
    for n in nodes {
        match n {
            Node::File { name, data, mtime } => {
                let p = dir.join(name);
                fs::write(&p, data).unwrap();
                filetime::set_file_mtime(&p, FileTime::from_system_time(at(*mtime))).unwrap();
            }
            Node::Dir {
                name,
                children,
                mtime,
            } => {
                let p = dir.join(name);
                fs::create_dir(&p).unwrap();
                write(&p, children);
                filetime::set_file_mtime(&p, FileTime::from_system_time(at(*mtime))).unwrap();
            }
        }
    }
}

fn secs(p: &Path) -> u64 {
    fs::metadata(p)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn compare(dir: &Path, nodes: &[Node]) -> Result<(), TestCaseError> {
    let on_disk: HashSet<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let expected: HashSet<String> = nodes.iter().map(|n| n.name().to_owned()).collect();
    prop_assert_eq!(&on_disk, &expected, "in {}", dir.display());
    for n in nodes {
        match n {
            Node::File { name, data, mtime } => {
                let p = dir.join(name);
                prop_assert!(fs::read(&p).unwrap() == *data, "{} differs", p.display());
                prop_assert_eq!(secs(&p), *mtime, "mtime of {}", p.display());
            }
            Node::Dir {
                name,
                children,
                mtime,
            } => {
                let p = dir.join(name);
                compare(&p, children)?;
                prop_assert_eq!(secs(&p), *mtime, "mtime of {}", p.display());
            }
        }
    }
    Ok(())
}

fn round_trip(
    ext: &str,
    spec: &WriteSpec,
    password: Option<&str>,
    tree: &[Node],
) -> Result<(), TestCaseError> {
    round_trip_with(ext, spec, password, None, tree)
}

/// `volume`: split the archive into volumes of that size, and extract from the first part.
fn round_trip_with(
    ext: &str,
    spec: &WriteSpec,
    password: Option<&str>,
    volume: Option<u64>,
    tree: &[Node],
) -> Result<(), TestCaseError> {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in put");
    fs::create_dir(&input).unwrap();
    write(&input, tree);
    filetime::set_file_mtime(&input, FileTime::from_system_time(at(1_700_000_000))).unwrap();

    let archive = root.path().join(format!("out.{ext}"));
    let mut cx = SimpleCtx::new();
    ops::create(
        &archive,
        std::slice::from_ref(&input),
        spec,
        &CreateOptions {
            volume_size: volume,
            ..CreateOptions::default()
        },
        &mut cx,
    )
    .map_err(|e| TestCaseError::fail(format!("create: {e}")))?;
    let archive = match volume {
        Some(_) => beezip_core::volume::part_path(&archive, 1),
        None => archive,
    };

    let dest = root.path().join("x");
    let mut cx = match password {
        Some(pw) => SimpleCtx::new().with_password(pw),
        None => SimpleCtx::new(),
    };
    let report = ops::extract(
        &archive,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut cx,
    )
    .map_err(|e| TestCaseError::fail(format!("extract: {e}")))?;
    prop_assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    prop_assert!(report.renamed.is_empty(), "{:?}", report.renamed);
    let out = dest.join("in put");
    compare(&out, tree)?;
    prop_assert_eq!(secs(&out), 1_700_000_000);
    no_partials(root.path())?;

    // A zip again on four workers: the same tree and the same report (docs/M6.md §10).
    if ext == "zip" {
        let dest = root.path().join("x4");
        let mut cx = match password {
            Some(pw) => SimpleCtx::new().with_password(pw),
            None => SimpleCtx::new(),
        };
        let par = ops::extract(
            &archive,
            &dest,
            &Selection::all(),
            &parallel(),
            FsOptions::default(),
            &mut cx,
        )
        .map_err(|e| TestCaseError::fail(format!("parallel extract: {e}")))?;
        prop_assert_eq!(&par, &report);
        let out = dest.join("in put");
        compare(&out, tree)?;
        prop_assert_eq!(secs(&out), 1_700_000_000);
        no_partials(root.path())?;
    }
    Ok(())
}

/// Four workers, from the first file (docs/M6.md §6.3).
fn parallel() -> OpenOptions {
    OpenOptions {
        threads: 4,
        min_parallel_files: 1,
        ..OpenOptions::default()
    }
}

fn no_partials(dir: &Path) -> Result<(), TestCaseError> {
    for e in walkdir::WalkDir::new(dir) {
        let e = e.unwrap();
        prop_assert!(
            !e.file_name().to_string_lossy().ends_with(".beezip-partial"),
            "left behind: {}",
            e.path().display()
        );
    }
    Ok(())
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32)
}

fn zip(method: ZipMethod, password: Option<(&str, ZipEncryption)>) -> WriteSpec {
    WriteSpec::Zip(ZipWriteOptions {
        method,
        level: None,
        password: password.map(|(p, _)| p.to_owned()),
        encryption: password.map(|(_, e)| e).unwrap_or_default(),
        // Workers for every round trip: one thread's bytes are checked against them below.
        threads: 4,
    })
}

fn tar(codec: Option<CodecId>) -> WriteSpec {
    WriteSpec::Tar {
        codec,
        opts: EncodeOpts {
            threads: 1,
            ..EncodeOpts::default()
        },
    }
}

macro_rules! combos {
    ($($name:ident: $ext:expr, $spec:expr, $pw:expr;)*) => {$(
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(cases()))]
            #[test]
            fn $name(tree in tree()) {
                round_trip($ext, &$spec, $pw, &tree)?;
            }
        }
    )*};
}

const PW: &str = "pässwörd 1";

combos! {
    zip_store: "zip", zip(ZipMethod::Store, None), None;
    zip_deflate: "zip", zip(ZipMethod::Deflate, None), None;
    zip_bzip2: "zip", zip(ZipMethod::Bzip2, None), None;
    zip_zstd: "zip", zip(ZipMethod::Zstd, None), None;
    zip_xz: "zip", zip(ZipMethod::Xz, None), None;
    zip_ppmd: "zip", zip(ZipMethod::Ppmd, None), None;
    zip_store_aes: "zip", zip(ZipMethod::Store, Some((PW, ZipEncryption::Aes256))), Some(PW);
    zip_deflate_aes: "zip", zip(ZipMethod::Deflate, Some((PW, ZipEncryption::Aes256))), Some(PW);
    zip_bzip2_aes: "zip", zip(ZipMethod::Bzip2, Some((PW, ZipEncryption::Aes256))), Some(PW);
    zip_zstd_aes: "zip", zip(ZipMethod::Zstd, Some((PW, ZipEncryption::Aes256))), Some(PW);
    zip_xz_aes: "zip", zip(ZipMethod::Xz, Some((PW, ZipEncryption::Aes256))), Some(PW);
    zip_ppmd_aes: "zip", zip(ZipMethod::Ppmd, Some((PW, ZipEncryption::Aes256))), Some(PW);
    zip_store_zipcrypto: "zip", zip(ZipMethod::Store, Some((PW, ZipEncryption::ZipCrypto))), Some(PW);
    zip_deflate_zipcrypto: "zip", zip(ZipMethod::Deflate, Some((PW, ZipEncryption::ZipCrypto))), Some(PW);
    zip_bzip2_zipcrypto: "zip", zip(ZipMethod::Bzip2, Some((PW, ZipEncryption::ZipCrypto))), Some(PW);
    zip_zstd_zipcrypto: "zip", zip(ZipMethod::Zstd, Some((PW, ZipEncryption::ZipCrypto))), Some(PW);
    zip_xz_zipcrypto: "zip", zip(ZipMethod::Xz, Some((PW, ZipEncryption::ZipCrypto))), Some(PW);
    zip_ppmd_zipcrypto: "zip", zip(ZipMethod::Ppmd, Some((PW, ZipEncryption::ZipCrypto))), Some(PW);
    tar_plain: "tar", tar(None), None;
    tar_gz: "tar.gz", tar(Some(CodecId::Gzip)), None;
    tar_bz2: "tar.bz2", tar(Some(CodecId::Bzip2)), None;
    tar_xz: "tar.xz", tar(Some(CodecId::Xz)), None;
    tar_lzma: "tar.lzma", tar(Some(CodecId::Lzma)), None;
    tar_lz: "tar.lz", tar(Some(CodecId::Lzip)), None;
    tar_zst: "tar.zst", tar(Some(CodecId::Zstd)), None;
    tar_lz4: "tar.lz4", tar(Some(CodecId::Lz4)), None;
    tar_br: "tar.br", tar(Some(CodecId::Brotli)), None;
    tar_sz: "tar.sz", tar(Some(CodecId::Snappy)), None;
    tar_z: "tar.Z", tar(Some(CodecId::Compress)), None;
    tar_lzo: "tar.lzo", tar(Some(CodecId::Lzop)), None;
    cpio_plain: "cpio", cpio(None), None;
    cpio_gz: "cpio.gz", cpio(Some(CodecId::Gzip)), None;
    cpio_bz2: "cpio.bz2", cpio(Some(CodecId::Bzip2)), None;
    cpio_xz: "cpio.xz", cpio(Some(CodecId::Xz)), None;
    cpio_lzma: "cpio.lzma", cpio(Some(CodecId::Lzma)), None;
    cpio_lz: "cpio.lz", cpio(Some(CodecId::Lzip)), None;
    cpio_zst: "cpio.zst", cpio(Some(CodecId::Zstd)), None;
    cpio_lz4: "cpio.lz4", cpio(Some(CodecId::Lz4)), None;
    cpio_br: "cpio.br", cpio(Some(CodecId::Brotli)), None;
    cpio_sz: "cpio.sz", cpio(Some(CodecId::Snappy)), None;
    cpio_z: "cpio.Z", cpio(Some(CodecId::Compress)), None;
    cpio_lzo: "cpio.lzo", cpio(Some(CodecId::Lzop)), None;
    iso: "iso", WriteSpec::Iso(Default::default()), None;
    squashfs_gzip: "squashfs", squashfs(SquashfsMethod::Gzip), None;
    squashfs_xz: "squashfs", squashfs(SquashfsMethod::Xz), None;
    squashfs_zstd: "squashfs", squashfs(SquashfsMethod::Zstd), None;
    squashfs_lz4: "squashfs", squashfs(SquashfsMethod::Lz4), None;
    squashfs_lzo: "squashfs", squashfs(SquashfsMethod::Lzo), None;
}

/// squashfs holds folders, files and their times in seconds, so the whole tree comes back.
fn squashfs(method: SquashfsMethod) -> WriteSpec {
    WriteSpec::Squashfs(SquashfsWriteOptions {
        method,
        level: method.resolve_level(None).unwrap(),
    })
}

fn cpio(codec: Option<CodecId>) -> WriteSpec {
    WriteSpec::Cpio {
        codec,
        opts: EncodeOpts {
            threads: 1,
            ..EncodeOpts::default()
        },
    }
}

/// The files of `tree` under `dir`, by path, with their data and mtimes.
fn flat(dir: &str, tree: &[Node], out: &mut Vec<(String, Vec<u8>, u64)>) {
    for n in tree {
        match n {
            Node::File { name, data, mtime } => {
                out.push((format!("{dir}/{name}"), data.clone(), *mtime))
            }
            Node::Dir { name, children, .. } => flat(&format!("{dir}/{name}"), children, out),
        }
    }
}

/// How a format stores times.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Times {
    /// Unix seconds: they come back exactly.
    Unix,
    /// Local DOS times (CAB): the same DOS fields come back. They have 2-second steps, and a
    /// local time in the hour repeated when summer time ends names two instants.
    Dos,
}

/// A format that holds files only (ar, CAB): every file comes back with its bytes and its time;
/// folders come from paths.
fn files_round_trip(
    ext: &str,
    spec: &WriteSpec,
    times: Times,
    tree: &[Node],
) -> Result<(), TestCaseError> {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in put");
    fs::create_dir(&input).unwrap();
    write(&input, tree);
    let archive = root.path().join(format!("out.{ext}"));
    ops::create(
        &archive,
        std::slice::from_ref(&input),
        spec,
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .map_err(|e| TestCaseError::fail(format!("create: {e}")))?;
    let dest = root.path().join("x");
    let report = ops::extract(
        &archive,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .map_err(|e| TestCaseError::fail(format!("extract: {e}")))?;
    prop_assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    let mut files = Vec::new();
    flat("in put", tree, &mut files);
    for (path, data, mtime) in files {
        let p = dest.join(&path);
        prop_assert!(
            fs::read(&p).unwrap_or_default() == data,
            "{} differs",
            p.display()
        );
        let got = secs(&p);
        let same = match times {
            Times::Unix => got == mtime,
            Times::Dos => to_dos(at(got)) == to_dos(at(mtime)),
        };
        prop_assert!(same, "mtime of {}: {got} for {mtime}", p.display());
    }
    no_partials(root.path())?;
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn ar(tree in tree()) {
        files_round_trip("ar", &WriteSpec::Ar, Times::Unix, &tree)?;
    }

    #[test]
    fn cab_store(tree in tree()) {
        let spec = WriteSpec::Cab(CabWriteOptions { method: CabMethod::Store });
        files_round_trip("cab", &spec, Times::Dos, &tree)?;
    }

    #[test]
    fn cab_mszip(tree in tree()) {
        let spec = WriteSpec::Cab(CabWriteOptions { method: CabMethod::Mszip });
        files_round_trip("cab", &spec, Times::Dos, &tree)?;
    }
}

/// 7z has 38 combinations, so 8 cases each unless `PROPTEST_CASES` says otherwise.
fn cases_7z() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8)
}

fn sevenz(method: SevenZMethod, solid: bool, password: Option<&str>, headers: bool) -> WriteSpec {
    WriteSpec::SevenZ(SevenZWriteOptions {
        method,
        level: None,
        threads: 1,
        password: password.map(str::to_owned),
        encrypt_headers: headers,
        solid,
    })
}

macro_rules! sevenz_combos {
    ($($name:ident: $method:expr;)*) => {$(
        mod $name {
            use super::*;
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(cases_7z()))]
                #[test]
                fn solid(tree in tree()) {
                    round_trip("7z", &sevenz($method, true, None, false), None, &tree)?;
                }
                #[test]
                fn not_solid(tree in tree()) {
                    round_trip("7z", &sevenz($method, false, None, false), None, &tree)?;
                }
                #[test]
                fn aes(tree in tree()) {
                    round_trip("7z", &sevenz($method, true, Some(PW), false), Some(PW), &tree)?;
                }
                #[test]
                fn aes_not_solid(tree in tree()) {
                    round_trip("7z", &sevenz($method, false, Some(PW), false), Some(PW), &tree)?;
                }
                #[test]
                fn aes_headers(tree in tree()) {
                    round_trip("7z", &sevenz($method, true, Some(PW), true), Some(PW), &tree)?;
                }
                #[test]
                fn aes_headers_not_solid(tree in tree()) {
                    round_trip("7z", &sevenz($method, false, Some(PW), true), Some(PW), &tree)?;
                }
            }
        }
    )*};
}

sevenz_combos! {
    sz_lzma2: SevenZMethod::Lzma2;
    sz_lzma: SevenZMethod::Lzma;
    sz_ppmd: SevenZMethod::Ppmd;
    sz_bzip2: SevenZMethod::Bzip2;
    sz_deflate: SevenZMethod::Deflate;
    sz_copy: SevenZMethod::Copy;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases_7z()))]
    #[test]
    fn sz_lzma2_multithreaded(tree in tree()) {
        let spec = WriteSpec::SevenZ(SevenZWriteOptions {
            threads: 4,
            ..SevenZWriteOptions::default()
        });
        round_trip("7z", &spec, None, &tree)?;
    }

    #[test]
    fn sz_lzma2_volumes(tree in tree()) {
        let spec = sevenz(SevenZMethod::Lzma2, true, Some(PW), true);
        round_trip_with("7z", &spec, Some(PW), Some(1024), &tree)?;
    }
}

/// HFS+ holds times up to 2040-02-06 06:28:15 UTC: a tree for a DMG keeps to them.
fn hfs_times(nodes: Vec<Node>) -> Vec<Node> {
    const HFS_LAST: u64 = u32::MAX as u64 - 2_082_844_800;
    nodes
        .into_iter()
        .map(|n| match n {
            Node::File { name, data, mtime } => Node::File {
                name,
                data,
                mtime: mtime.min(HFS_LAST),
            },
            Node::Dir {
                name,
                children,
                mtime,
            } => Node::Dir {
                name,
                children: hfs_times(children),
                mtime: mtime.min(HFS_LAST),
            },
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    /// An HFS+ volume in UDZO: names (composed again from HFS+'s decomposed ones), bytes and
    /// times come back.
    #[test]
    fn dmg(tree in tree().prop_map(hfs_times)) {
        round_trip("dmg", &WriteSpec::Dmg(DmgWriteOptions::default()), None, &tree)?;
    }
}

/// Every writable kind is covered above.
#[test]
fn every_kind_is_tested() {
    assert_eq!(beezip_core::ArchiveKind::all().count(), 31);
}

#[test]
fn sevenz_keeps_100ns_mtimes() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("t");
    fs::create_dir(&input).unwrap();
    let file = input.join("f.txt");
    fs::write(&file, b"precise").unwrap();
    let t = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_700);
    filetime::set_file_mtime(&file, FileTime::from_system_time(t)).unwrap();
    let archive = root.path().join("t.7z");
    ops::create(
        &archive,
        std::slice::from_ref(&input),
        &WriteSpec::SevenZ(SevenZWriteOptions::default()),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let dest = root.path().join("x");
    ops::extract(
        &archive,
        &dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let got = fs::metadata(dest.join("t/f.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(got, t);
}

/// A solid block goes on past an entry whose CRC is wrong, since its decoder is sound: only that
/// entry fails. (A block whose decoder fails stops there: `regress.rs`.)
#[test]
fn sevenz_crc_mismatch_fails_only_its_entry() {
    let root = tempfile::tempdir().unwrap();
    let files: Vec<PathBuf> = [("a.txt", b'A'), ("b.txt", b'B'), ("c.txt", b'C')]
        .into_iter()
        .map(|(name, byte)| {
            let path = root.path().join(name);
            fs::write(&path, vec![byte; 5000]).unwrap();
            path
        })
        .collect();
    let archive = root.path().join("t.7z");
    let spec = sevenz(SevenZMethod::Copy, true, None, false);
    let mut cx = SimpleCtx::new();
    ops::create(&archive, &files, &spec, &CreateOptions::default(), &mut cx).unwrap();
    let mut bytes = fs::read(&archive).unwrap();
    let at = bytes.windows(100).position(|w| w == [b'A'; 100]).unwrap();
    bytes[at + 50] = b'Z';
    fs::write(&archive, bytes).unwrap();

    let mut opened = beezip_core::open(&archive, &OpenOptions::default(), &mut cx).unwrap();
    let mut sink = beezip_core::TestSink::default();
    opened
        .reader
        .extract(&Selection::all(), &mut sink, &mut cx)
        .unwrap();
    assert_eq!(sink.report.entries, 3);
    let errors: Vec<_> = sink
        .report
        .errors
        .iter()
        .map(|e| (e.path.as_str(), e.message.as_str()))
        .collect();
    assert_eq!(errors, [("a.txt", "7z: CRC mismatch")]);
}

#[test]
fn sevenz_passwords() {
    use beezip_core::ErrorKind;
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("f.txt");
    fs::write(&input, b"secret ".repeat(1000)).unwrap();
    for headers in [false, true] {
        let archive = root.path().join(format!("h{headers}.7z"));
        ops::create(
            &archive,
            std::slice::from_ref(&input),
            &sevenz(SevenZMethod::Lzma2, true, Some("right"), headers),
            &CreateOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        let run = |cx: &mut SimpleCtx| {
            ops::extract(
                &archive,
                &root.path().join("x"),
                &Selection::all(),
                &OpenOptions::default(),
                FsOptions {
                    overwrite: beezip_core::OverwritePolicy::Always,
                    ..FsOptions::default()
                },
                cx,
            )
        };
        let err = run(&mut SimpleCtx::new()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::PasswordRequired, "headers {headers}");
        let err = run(&mut SimpleCtx::new().with_password("wrong")).unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::WrongPassword,
            "headers {headers}: {err}"
        );
        assert!(err.message.contains("wrong password"), "{err}");
        run(&mut SimpleCtx::new().with_password("right")).unwrap();
        assert_eq!(
            fs::read(root.path().join("x/f.txt")).unwrap(),
            b"secret ".repeat(1000)
        );
        // Without the password, an encrypted header hides the names; otherwise they list.
        let listed = beezip_core::open(&archive, &OpenOptions::default(), &mut SimpleCtx::new());
        assert_eq!(listed.is_err(), headers);
        // The test sink stops on a wrong password instead of recording damage.
        let tested = ops::test(
            &archive,
            &Selection::all(),
            &OpenOptions::default(),
            &mut SimpleCtx::new().with_password("wrong"),
        );
        assert_eq!(tested.unwrap_err().kind, ErrorKind::WrongPassword);
    }
}

#[test]
fn a_wrong_password_is_wrong_password() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("f.txt");
    fs::write(&input, b"secret".repeat(100)).unwrap();
    for enc in [ZipEncryption::Aes256, ZipEncryption::ZipCrypto] {
        let archive = root.path().join(format!("{enc:?}.zip"));
        let spec = zip(ZipMethod::Deflate, Some(("right", enc)));
        ops::create(
            &archive,
            std::slice::from_ref(&input),
            &spec,
            &CreateOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        let run = |cx: &mut SimpleCtx| {
            ops::extract(
                &archive,
                &root.path().join("x"),
                &Selection::all(),
                &OpenOptions::default(),
                FsOptions::default(),
                cx,
            )
        };
        let err = run(&mut SimpleCtx::new()).unwrap_err();
        assert_eq!(
            err.kind,
            beezip_core::ErrorKind::PasswordRequired,
            "{enc:?}"
        );
        let err = run(&mut SimpleCtx::new().with_password("wrong")).unwrap_err();
        assert!(
            matches!(err.kind, beezip_core::ErrorKind::WrongPassword),
            "{enc:?}: {err:?}"
        );
    }
}

/// About 1 wrong password in 256 passes ZipCrypto's one-byte check, and the garbage it decrypts
/// to then fails in the decompressor: that's a wrong password too. (`a_wrong_password_…` above
/// failed this way 1 run in 256, the header being random.)
#[test]
fn a_wrong_password_past_zipcryptos_check_is_still_wrong() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("f.txt");
    fs::write(&input, b"secret ".repeat(1000)).unwrap();
    let archive = root.path().join("z.zip");
    let spec = zip(
        ZipMethod::Deflate,
        Some(("right", ZipEncryption::ZipCrypto)),
    );
    ops::create(
        &archive,
        std::slice::from_ref(&input),
        &spec,
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let mut past_the_check = 0;
    for i in 0..3000 {
        let mut cx = SimpleCtx::new().with_password(format!("wrong{i}"));
        let mut opened = beezip_core::open(&archive, &OpenOptions::default(), &mut cx).unwrap();
        let mut data = Vec::new();
        let err = match opened.reader.open_entry(0, &mut cx) {
            Err(e) => e,
            Ok(mut r) => {
                past_the_check += 1;
                r.read_to_end(&mut data)
                    .map_err(|e| beezip_core::io::read_error(&e))
                    .unwrap_err()
            }
        };
        assert_eq!(
            err.kind,
            beezip_core::ErrorKind::WrongPassword,
            "wrong{i}: {err}"
        );
    }
    assert!(past_the_check > 0, "no password got past the check");
}

#[test]
fn create_never_adds_its_own_output_and_respects_excludes() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("d");
    fs::create_dir_all(dir.join("build")).unwrap();
    fs::write(dir.join("a.txt"), b"a").unwrap();
    fs::write(dir.join("build/out.o"), b"o").unwrap();
    fs::write(dir.join("skip.log"), b"l").unwrap();
    let archive = dir.join("self.zip");
    fs::write(&archive, b"old").unwrap();
    let opts = CreateOptions {
        exclude: vec!["build".into(), "*.log".into()],
        overwrite: true,
        ..CreateOptions::default()
    };
    let plan = ops::plan(std::slice::from_ref(&dir), &archive, &opts).unwrap();
    let names: Vec<&str> = plan.iter().map(|p| p.entry.path.as_str()).collect();
    assert_eq!(names, ["d", "d/a.txt"]);
    ops::create(
        &archive,
        std::slice::from_ref(&dir),
        &zip(ZipMethod::Deflate, None),
        &opts,
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let err = ops::create(
        &archive,
        &[dir],
        &zip(ZipMethod::Deflate, None),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, beezip_core::ErrorKind::Conflict);
}

#[test]
fn cancelled_create_leaves_nothing() {
    use std::sync::{Arc, atomic::AtomicBool};
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("big.bin");
    fs::write(&input, vec![7u8; 4 << 20]).unwrap();
    let archive = root.path().join("out.tar.zst");
    let flag = Arc::new(AtomicBool::new(true));
    let err = ops::create(
        &archive,
        &[input],
        &tar(Some(CodecId::Zstd)),
        &CreateOptions::default(),
        &mut SimpleCtx::new().with_cancel(flag),
    )
    .unwrap_err();
    assert_eq!(err.kind, beezip_core::ErrorKind::Cancelled);
    let left: Vec<PathBuf> = fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(left.len(), 1, "{left:?}");
}
