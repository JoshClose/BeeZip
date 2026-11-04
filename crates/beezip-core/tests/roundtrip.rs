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
        sevenz::{SevenZMethod, SevenZWriteOptions},
        zip::{ZipEncryption, ZipMethod, ZipWriteOptions},
    },
    ops,
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
    Ok(())
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

/// Every writable kind is covered above.
#[test]
fn every_kind_is_tested() {
    assert_eq!(beezip_core::ArchiveKind::all().count(), 12);
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
