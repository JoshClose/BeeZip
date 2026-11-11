//! CAB (docs/M5.md §5.5, §10):
//!
//! - Windows: cabinets made by `makecab` (MSZIP and LZX:21, a subfolder, an empty file, a name
//!   in the ANSI code page, several folders and blocks, and sets of several cabinets) read back
//!   through `beezip_core::open`, byte for byte; BeeZip's own cabinets expand with `expand.exe`
//!   and pass `7z t` and `7z x`. With `BEEZIP_REQUIRE_7Z=1` (CI), a missing 7-Zip fails instead
//!   of skipping.
//! - Everywhere: random trees written as CAB with both methods and read back, with their DOS
//!   times. `PROPTEST_CASES` raises the case count (default 32 per method).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use beezip_core::{
    CreateOptions, FsOptions, OpenOptions, Selection, SimpleCtx, WriteSpec,
    format::cab::{CabMethod, CabWriteOptions},
    open, ops,
    time::to_dos,
};
use filetime::FileTime;
use proptest::prelude::*;

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

fn create(output: &Path, inputs: &[PathBuf], method: CabMethod) {
    ops::create(
        output,
        inputs,
        &WriteSpec::Cab(CabWriteOptions { method }),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
}

fn extract(archive: &Path, dest: &Path) {
    let report = ops::extract(
        archive,
        dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

/// The archive's entries, `(path, size)`, in order.
fn listing(archive: &Path) -> Vec<(String, u64)> {
    let mut opened = open(archive, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
    assert_eq!(
        opened.detection.format(),
        Some(beezip_core::FormatId::Cab),
        "{}",
        archive.display()
    );
    opened
        .reader
        .entries(&mut SimpleCtx::new())
        .unwrap()
        .iter()
        .map(|e| (e.path.clone(), e.size.unwrap()))
        .collect()
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

#[cfg(windows)]
mod windows {
    use std::{io::Read, process::Command};

    use super::*;

    const MAKECAB: &str = r"C:\Windows\System32\makecab.exe";
    const EXPAND: &str = r"C:\Windows\System32\expand.exe";

    fn tool(path: &str) -> Option<PathBuf> {
        let p = PathBuf::from(path);
        if p.is_file() {
            Some(p)
        } else {
            eprintln!("skipping: {path} not found");
            None
        }
    }

    fn seven_zip() -> Option<PathBuf> {
        let installed = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
        let found = if installed.is_file() {
            Some(installed)
        } else {
            Command::new("7z")
                .arg("i")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|_| PathBuf::from("7z"))
        };
        if found.is_none() {
            assert!(
                std::env::var("BEEZIP_REQUIRE_7Z").as_deref() != Ok("1"),
                "7-Zip is required (BEEZIP_REQUIRE_7Z=1) but wasn't found"
            );
            eprintln!("skipping: 7-Zip not found (set BEEZIP_REQUIRE_7Z=1 to require it)");
        }
        found
    }

    fn run(exe: &Path, args: &[&str], cwd: &Path) {
        let out = Command::new(exe)
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{} {args:?} failed:\n{}{}",
            exe.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Whether the ANSI code page is Windows-1252, which makecab reads its directives in and
    /// stores names in: the non-ASCII name is only tested then.
    fn ansi_is_1252() -> bool {
        Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage",
                "/v",
                "ACP",
            ])
            .output()
            .is_ok_and(|o| {
                String::from_utf8_lossy(&o.stdout).split_whitespace().last() == Some("1252")
            })
    }

    /// Runs makecab on `directives` in `dir`; the cabinets go to `dir/out`. The directive file
    /// is written in Latin-1, which is Windows-1252 for the letters used here.
    fn makecab(exe: &Path, dir: &Path, directives: &str) {
        let bytes: Vec<u8> = directives
            .chars()
            .map(|c| u8::try_from(u32::from(c)).expect("a Latin-1 directive"))
            .collect();
        fs::write(dir.join("x.ddf"), bytes).unwrap();
        run(exe, &["/F", "x.ddf"], dir);
    }

    fn header(name: &str, method: &str) -> String {
        let memory = if method == "LZX" {
            ".Set CompressionMemory=21\n"
        } else {
            ""
        };
        format!(
            ".OPTION EXPLICIT\n.Set CabinetNameTemplate={name}\n.Set DiskDirectoryTemplate=out\n\
             .Set Cabinet=on\n.Set Compress=on\n.Set CompressionType={method}\n{memory}\
             .Set RptFileName=nul\n.Set InfFileName=nul\n"
        )
    }

    /// The source files, and the entries the cabinet should have: `(cabinet path, data)`.
    fn sources(dir: &Path) -> (String, Vec<(String, Vec<u8>)>) {
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        let big: Vec<u8> = (0..2_000_000u32)
            .map(|i| (i % 253) as u8 ^ (i / 7_000) as u8)
            .collect();
        let mut files: Vec<(&str, &str, Vec<u8>)> = vec![
            ("a.txt", "a.txt", b"hello cab\n".repeat(1000)),
            ("empty.txt", "empty.txt", Vec::new()),
        ];
        if ansi_is_1252() {
            files.push(("ünïcödé.txt", "ünïcödé.txt", b"non-ASCII\n".to_vec()));
        }
        files.push(("sub/b.bin", "sub\\b.bin", noise(300_000, 5)));
        files.push(("big.bin", "big.bin", big));
        files.push(("c.txt", "c.txt", b"after the big one\n".to_vec()));
        let mut ddf = String::new();
        for (path, _, data) in &files {
            fs::write(src.join(path), data).unwrap();
        }
        for (path, stored, _) in &files {
            let (dest_dir, name) = stored.rsplit_once('\\').unwrap_or(("", stored));
            if *path == "big.bin" {
                // A folder of its own, with the file after it.
                ddf.push_str(".New Folder\n");
            }
            ddf.push_str(&format!(".Set DestinationDir={dest_dir}\n"));
            ddf.push_str(&format!(
                "\"src\\{}\" \"{name}\"\n",
                path.replace('/', "\\")
            ));
        }
        let entries = files
            .into_iter()
            .map(|(path, _, data)| (path.to_owned(), data))
            .collect();
        (ddf, entries)
    }

    fn check_read_back(cab: &Path, entries: &[(String, Vec<u8>)], method: &str, dest: &Path) {
        let listed = listing(cab);
        let want: Vec<(String, u64)> = entries
            .iter()
            .map(|(p, d)| (p.clone(), d.len() as u64))
            .collect();
        assert_eq!(listed, want, "{}", cab.display());
        extract(cab, dest);
        let got = files_under(dest);
        let want: BTreeMap<String, Vec<u8>> = entries.iter().cloned().collect();
        assert_eq!(
            got.keys().collect::<Vec<_>>(),
            want.keys().collect::<Vec<_>>()
        );
        for (p, d) in &want {
            assert!(got[p] == *d, "{p} differs in {}", cab.display());
        }
        let mut opened = open(cab, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
        let info = opened.reader.info(&mut SimpleCtx::new()).unwrap();
        assert_eq!(info.methods, [method]);
        // Each entry on its own, last first.
        for id in (0..entries.len()).rev() {
            let mut data = Vec::new();
            opened
                .reader
                .open_entry(id, &mut SimpleCtx::new())
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            assert!(data == entries[id].1, "entry {id} of {}", cab.display());
        }
    }

    #[test]
    fn makecab_cabinets_read_back() {
        let Some(exe) = tool(MAKECAB) else { return };
        for method in ["MSZIP", "LZX"] {
            let dir = tempfile::tempdir().unwrap();
            let (files, entries) = sources(dir.path());
            makecab(&exe, dir.path(), &(header("x.cab", method) + &files));
            let cab = dir.path().join("out").join("x.cab");
            check_read_back(&cab, &entries, method, &dir.path().join("x"));
            let mut opened = open(&cab, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
            let info = opened.reader.info(&mut SimpleCtx::new()).unwrap();
            assert_eq!(info.volumes, 1);
            assert!(info.solid);
        }
    }

    #[test]
    fn makecab_sets_read_whole_from_any_cabinet() {
        let Some(exe) = tool(MAKECAB) else { return };
        for method in ["MSZIP", "LZX"] {
            let dir = tempfile::tempdir().unwrap();
            let src = dir.path().join("src");
            fs::create_dir(&src).unwrap();
            let entries: Vec<(String, Vec<u8>)> = vec![
                ("one.bin".into(), noise(150_000, 1)),
                ("small.txt".into(), b"between the big ones\n".repeat(30)),
                ("two.bin".into(), noise(120_000, 2)),
                ("three.bin".into(), noise(50_000, 3)),
            ];
            let mut ddf = header("set*.cab", method);
            ddf.push_str(".Set MaxDiskSize=102400\n");
            for (name, data) in &entries {
                fs::write(src.join(name), data).unwrap();
                ddf.push_str(&format!("\"src\\{name}\" \"{name}\"\n"));
            }
            makecab(&exe, dir.path(), &ddf);
            let out = dir.path().join("out");
            let cabs: Vec<PathBuf> = (1..)
                .map(|i| out.join(format!("set{i}.cab")))
                .take_while(|p| p.is_file())
                .collect();
            assert!(cabs.len() >= 3, "{method}: {cabs:?}");
            for (i, cab) in cabs.iter().enumerate() {
                let dest = dir.path().join(format!("x{i}"));
                check_read_back(cab, &entries, method, &dest);
                let mut opened = open(cab, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
                let info = opened.reader.info(&mut SimpleCtx::new()).unwrap();
                assert_eq!(info.volumes, cabs.len());
            }
        }
    }

    /// makecab's LZX cabinet, damaged at random: errors, never a panic or an abort.
    #[test]
    fn damaged_makecab_cabinets_fail_cleanly() {
        let Some(exe) = tool(MAKECAB) else { return };
        for method in ["MSZIP", "LZX"] {
            let dir = tempfile::tempdir().unwrap();
            let src = dir.path().join("src");
            fs::create_dir(&src).unwrap();
            let text: Vec<u8> = (0..120_000u32)
                .flat_map(|i| format!("line {} of {}\n", i % 977, i / 3).into_bytes())
                .take(120_000)
                .collect();
            fs::write(src.join("t.txt"), &text).unwrap();
            fs::write(src.join("n.bin"), noise(20_000, 4)).unwrap();
            let ddf =
                header("m.cab", method) + "\"src\\t.txt\" \"t.txt\"\n\"src\\n.bin\" \"n.bin\"\n";
            makecab(&exe, dir.path(), &ddf);
            let bytes = fs::read(dir.path().join("out").join("m.cab")).unwrap();
            let m = dir.path().join("mut.cab");
            let mut x = 0x9E37_79B9u32;
            for i in 0..300 {
                let mut b = bytes.clone();
                for _ in 0..1 + i % 4 {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    let at = 100 + (x as usize) % (b.len() - 100);
                    b[at] ^= (x >> 8) as u8 | 1;
                }
                fs::write(&m, &b).unwrap();
                let source =
                    beezip_core::source::Source::new(&m, Vec::new(), &OpenOptions::default())
                        .unwrap();
                let Ok(mut r) =
                    beezip_core::format::cab::CabReader::open(source, &mut SimpleCtx::new())
                else {
                    continue;
                };
                use beezip_core::ArchiveReader;
                let mut sink = beezip_core::NullSink::default();
                let _ = r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new());
            }
        }
    }

    /// 2 000 files in one LZX folder, which the `cab` crate took 289 s to extract (docs/M5.md
    /// §16): timed, so `cargo test --release -- --ignored two_thousand`.
    #[test]
    #[ignore = "a timing"]
    fn two_thousand_files_in_one_folder() {
        let Some(exe) = tool(MAKECAB) else { return };
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        let mut ddf = header("big.cab", "LZX");
        for i in 0..2000 {
            let name = format!("f{i:04}.txt");
            let data = format!("file {i}: {}\n", "lorem ipsum ".repeat(i % 50)).repeat(20);
            fs::write(src.join(&name), data).unwrap();
            ddf.push_str(&format!("\"src\\{name}\" \"{name}\"\n"));
        }
        makecab(&exe, dir.path(), &ddf);
        let cab = dir.path().join("out").join("big.cab");
        let started = std::time::Instant::now();
        let report = ops::test(
            &cab,
            &Selection::all(),
            &OpenOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        let tested = started.elapsed();
        assert!(report.ok(), "{:?}", report.errors);
        assert_eq!(report.entries, 2000);
        let started = std::time::Instant::now();
        extract(&cab, &dir.path().join("x"));
        let took = started.elapsed();
        eprintln!("2 000 files tested in {tested:?}, extracted in {took:?}");
        assert_eq!(files_under(&dir.path().join("x")).len(), 2000);
        assert_eq!(files_under(&dir.path().join("x")), files_under(&src));
    }

    /// A tree with text, binary, empty, nested and non-ASCII files, and one of several blocks.
    fn tree(root: &Path) -> PathBuf {
        let t = root.join("tree");
        let files: [(&str, Vec<u8>); 7] = [
            ("hello.txt", b"Hello, BeeZip!\n".to_vec()),
            (
                "docs/readme.md",
                b"BeeZip reads and writes archives. ".repeat(200),
            ),
            ("data/blob.bin", noise(200_000, 9)),
            ("empty.txt", Vec::new()),
            ("ünïcödé/名前.txt", "non-ASCII names\n".as_bytes().to_vec()),
            ("deep/a/b/c/d.txt", b"deep\n".to_vec()),
            (
                "big.bin",
                (0..1_000_000u32).map(|i| (i % 241) as u8).collect(),
            ),
        ];
        for (path, data) in files {
            let p = t.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        }
        t
    }

    #[test]
    fn beezip_cabinets_expand_and_pass_7z() {
        let seven = seven_zip();
        let expand = tool(EXPAND);
        for method in CabMethod::ALL {
            let root = tempfile::tempdir().unwrap();
            let t = tree(root.path());
            let want = files_under(root.path());
            let cab = root.path().join("x.cab");
            create(&cab, std::slice::from_ref(&t), method);
            if let Some(expand) = &expand {
                let out = root.path().join("expanded");
                fs::create_dir(&out).unwrap();
                run(expand, &["x.cab", "-F:*", "expanded"], root.path());
                assert_eq!(files_under(&out), want, "expand, {method:?}");
            }
            if let Some(seven) = &seven {
                run(seven, &["t", "x.cab"], root.path());
                run(seven, &["x", "x.cab", "-o7z-out", "-y"], root.path());
                assert_eq!(
                    files_under(&root.path().join("7z-out")),
                    want,
                    "7z, {method:?}"
                );
            }
            // And BeeZip's own reader.
            let out = root.path().join("beezip-out");
            extract(&cab, &out);
            assert_eq!(files_under(&out), want);
        }
    }

    /// An empty cabinet (an empty folder) passes too.
    #[test]
    fn an_empty_beezip_cabinet_passes_7z_and_expand() {
        let root = tempfile::tempdir().unwrap();
        let empty = root.path().join("nothing");
        fs::create_dir(&empty).unwrap();
        let cab = root.path().join("e.cab");
        create(&cab, std::slice::from_ref(&empty), CabMethod::Mszip);
        assert!(listing(&cab).is_empty());
        if let Some(seven) = seven_zip() {
            run(&seven, &["t", "e.cab"], root.path());
        }
        if let Some(expand) = tool(EXPAND) {
            let out = root.path().join("expanded");
            fs::create_dir(&out).unwrap();
            run(&expand, &["e.cab", "-F:*", "expanded"], root.path());
            assert!(files_under(&out).is_empty());
        }
    }
}

/// A small tree of files to put in a cabinet, and the files as extraction should give them.
fn small_tree(root: &Path) -> (PathBuf, BTreeMap<String, Vec<u8>>) {
    let t = root.join("t");
    fs::create_dir_all(t.join("sub")).unwrap();
    fs::write(t.join("a.txt"), b"some text\n".repeat(500)).unwrap();
    fs::write(t.join("sub").join("n.bin"), noise(100_000, 3)).unwrap();
    fs::write(t.join("empty"), b"").unwrap();
    let want = files_under(root);
    (t, want)
}

/// A cabinet inside gzip is spooled, and reads like any other.
#[test]
fn a_gzipped_cabinet_opens() {
    let root = tempfile::tempdir().unwrap();
    let (t, want) = small_tree(root.path());
    let cab = root.path().join("x.cab");
    create(&cab, std::slice::from_ref(&t), CabMethod::Mszip);
    let gz = root.path().join("x.cab.gz");
    let mut enc = flate2::write::GzEncoder::new(
        fs::File::create(&gz).unwrap(),
        flate2::Compression::default(),
    );
    std::io::copy(&mut fs::File::open(&cab).unwrap(), &mut enc).unwrap();
    enc.finish().unwrap();
    assert_eq!(listing(&gz).len(), want.len());
    let dest = root.path().join("x");
    extract(&gz, &dest);
    assert_eq!(files_under(&dest), want);
}

/// A cabinet at the overlay of an executable, where CAB SFX modules put theirs.
#[test]
fn a_cabinet_inside_an_executable_opens() {
    let root = tempfile::tempdir().unwrap();
    let (t, want) = small_tree(root.path());
    let cab = root.path().join("x.cab");
    create(&cab, std::slice::from_ref(&t), CabMethod::Mszip);
    // The least PE image: one section, ending at 0x400, where the overlay starts.
    let mut exe = vec![0u8; 0x400];
    exe[..2].copy_from_slice(b"MZ");
    exe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    exe[0x80..0x84].copy_from_slice(b"PE\0\0");
    exe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    let section = 0x80 + 24;
    exe[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    exe[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    exe.extend_from_slice(&fs::read(&cab).unwrap());
    let sfx = root.path().join("setup.exe");
    fs::write(&sfx, exe).unwrap();
    let mut opened = open(&sfx, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
    assert!(opened.detection.sfx);
    assert_eq!(opened.detection.offset, 0x400);
    let info = opened.reader.info(&mut SimpleCtx::new()).unwrap();
    assert!(info.sfx);
    assert_eq!(listing(&sfx).len(), want.len());
    let dest = root.path().join("x");
    extract(&sfx, &dest);
    assert_eq!(files_under(&dest), want);
}

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

/// Whole seconds from 1980-01-02 to 2099-12-31, the range DOS times hold.
fn mtime() -> impl Strategy<Value = u64> {
    315_619_200u64..4_102_358_400
}

fn data() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        proptest::collection::vec(any::<u8>(), 1..2048),
        (
            1usize..100_000,
            proptest::collection::vec(any::<u8>(), 1..8)
        )
            .prop_map(|(len, unit)| unit.iter().copied().cycle().take(len).collect()),
        (1usize..80_000, any::<u32>()).prop_map(|(len, seed)| noise(len, seed)),
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
            1 => (name(), proptest::collection::vec(inner, 0..5)).prop_map(
                |(name, children)| Node::Dir { name, children: dedupe(children) }
            ),
        ]
    });
    proptest::collection::vec(node, 0..6).prop_map(dedupe)
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Writes the tree, and returns its files by `/` path with their data and times.
fn write(dir: &Path, prefix: &str, nodes: &[Node], out: &mut BTreeMap<String, (Vec<u8>, u64)>) {
    for n in nodes {
        let path = format!("{prefix}{}", n.name());
        match n {
            Node::File { name, data, mtime } => {
                let p = dir.join(name);
                fs::write(&p, data).unwrap();
                filetime::set_file_mtime(&p, FileTime::from_system_time(at(*mtime))).unwrap();
                out.insert(path, (data.clone(), *mtime));
            }
            Node::Dir { name, children } => {
                let p = dir.join(name);
                fs::create_dir(&p).unwrap();
                write(&p, &format!("{path}/"), children, out);
            }
        }
    }
}

fn round_trip(method: CabMethod, nodes: &[Node]) -> Result<(), TestCaseError> {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in put");
    fs::create_dir(&input).unwrap();
    let mut want = BTreeMap::new();
    write(&input, "in put/", nodes, &mut want);
    let cab = root.path().join("out.cab");
    create(&cab, std::slice::from_ref(&input), method);
    let dest = root.path().join("x");
    extract(&cab, &dest);
    let got = files_under(&dest);
    prop_assert_eq!(
        got.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>()
    );
    for (path, (data, mtime)) in &want {
        prop_assert!(got[path] == *data, "{} differs", path);
        let t = fs::metadata(dest.join(path)).unwrap().modified().unwrap();
        // CAB keeps DOS times: local, to 2 seconds.
        prop_assert_eq!(to_dos(t), to_dos(at(*mtime)), "the time of {}", path);
    }
    let listed: BTreeMap<String, u64> = listing(&cab).into_iter().collect();
    let sizes: BTreeMap<String, u64> = want
        .iter()
        .map(|(p, (d, _))| (p.clone(), d.len() as u64))
        .collect();
    prop_assert_eq!(listed, sizes);
    Ok(())
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn cab_store_round_trip(tree in tree()) {
        round_trip(CabMethod::Store, &tree)?;
    }

    #[test]
    fn cab_mszip_round_trip(tree in tree()) {
        round_trip(CabMethod::Mszip, &tree)?;
    }
}

/// A stored cabinet of one folder whose files `a.txt`, `b.txt` and `c.txt` are all its 20 bytes,
/// as an installer's identical files are (LLVM's `clang.exe` and `clang++.exe`), and `d.txt` the
/// last 10 of them.
fn shared_cabinet(path: &Path) -> &'static [u8] {
    const DATA: &[u8] = b"hello, shared bytes\n";
    let names = [
        ("a.txt", 0u32, 20u32),
        ("b.txt", 0, 20),
        ("c.txt", 0, 20),
        ("d.txt", 10, 10),
    ];
    let files_len: usize = names.iter().map(|(n, _, _)| 16 + n.len() + 1).sum();
    let data_at = 36 + 8 + files_len;
    let total = data_at + 8 + DATA.len();
    let mut c = Vec::new();
    c.extend_from_slice(b"MSCF");
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&(total as u32).to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&44u32.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&[3, 1]);
    c.extend_from_slice(&1u16.to_le_bytes());
    c.extend_from_slice(&(names.len() as u16).to_le_bytes());
    c.extend_from_slice(&[0, 0, 0x34, 0x12, 0, 0]);
    // The folder: its one data block, stored.
    c.extend_from_slice(&(data_at as u32).to_le_bytes());
    c.extend_from_slice(&1u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    for (name, offset, size) in names {
        c.extend_from_slice(&size.to_le_bytes());
        c.extend_from_slice(&offset.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        // 2024-05-06 07:08:10
        c.extend_from_slice(&0x58A6u16.to_le_bytes());
        c.extend_from_slice(&0x3905u16.to_le_bytes());
        c.extend_from_slice(&0x20u16.to_le_bytes());
        c.extend_from_slice(name.as_bytes());
        c.push(0);
    }
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&(DATA.len() as u16).to_le_bytes());
    c.extend_from_slice(&(DATA.len() as u16).to_le_bytes());
    c.extend_from_slice(DATA);
    assert_eq!(c.len(), total);
    fs::write(path, &c).unwrap();
    DATA
}

/// What a reader hands a sink: each file's data, or `same_as` an earlier one.
#[derive(Default)]
struct Recorder {
    data: Vec<String>,
    same: Vec<(String, String)>,
}

impl beezip_core::EntrySink for Recorder {
    fn entry(
        &mut self,
        entry: &beezip_core::Entry,
        data: &mut dyn std::io::Read,
        _: &mut dyn beezip_core::Ctx,
    ) -> beezip_core::Result<()> {
        std::io::copy(data, &mut std::io::sink()).unwrap();
        self.data.push(entry.path.clone());
        Ok(())
    }

    fn same_as(
        &mut self,
        entry: &beezip_core::Entry,
        earlier: &beezip_core::Entry,
        _: bool,
        _: &mut dyn beezip_core::Ctx,
    ) -> beezip_core::Result<bool> {
        self.same.push((entry.path.clone(), earlier.path.clone()));
        Ok(true)
    }
}

/// Files whose folder, offset and size are another's are offered to the sink as the same bytes
/// (docs/M8.md §6.2): extracting copies the file written, testing passes them unread, and a
/// sink that can't take them (`d.txt`, part of the data) gets the data as before.
#[test]
fn files_that_share_their_data_are_served_once() {
    let dir = tempfile::tempdir().unwrap();
    let cab = dir.path().join("shared.cab");
    let data = shared_cabinet(&cab);

    let mut cx = SimpleCtx::new();
    let mut opened = open(&cab, &OpenOptions::default(), &mut cx).unwrap();
    let mut rec = Recorder::default();
    opened
        .reader
        .extract(&Selection::all(), &mut rec, &mut cx)
        .unwrap();
    assert_eq!(rec.data, ["a.txt", "d.txt"]);
    assert_eq!(
        rec.same,
        [
            ("b.txt".to_owned(), "a.txt".to_owned()),
            ("c.txt".to_owned(), "a.txt".to_owned())
        ]
    );

    let out = dir.path().join("out");
    extract(&cab, &out);
    let got = files_under(&out);
    for name in ["a.txt", "b.txt", "c.txt"] {
        assert_eq!(got[name], data, "{name}");
    }
    assert_eq!(got["d.txt"], &data[10..]);

    let report = ops::test(
        &cab,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.entries, 4);
}

/// A copy is only made from a file this job wrote: with a.txt left out, b.txt is decoded and
/// c.txt copied from it.
#[test]
fn a_shared_file_whose_first_is_left_out_is_decoded() {
    let dir = tempfile::tempdir().unwrap();
    let cab = dir.path().join("shared.cab");
    let data = shared_cabinet(&cab);
    let out = dir.path().join("out");
    let sel = Selection::new(&["b.txt".into(), "c.txt".into()], &[], &[]).unwrap();
    ops::extract(
        &cab,
        &out,
        &sel,
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let got = files_under(&out);
    assert_eq!(got.len(), 2);
    assert_eq!(got["b.txt"], data);
    assert_eq!(got["c.txt"], data);
}

/// Small files are written on other threads while the folder decodes (docs/M8.md §6.3): every
/// file comes out whole, with its time, the same as on one thread, and a file of the same name
/// later in the cabinet still replaces the earlier one.
#[test]
fn small_files_are_written_on_other_threads() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    let mut inputs = Vec::new();
    for d in 0..4 {
        let folder = src.join(format!("d{d}"));
        fs::create_dir_all(&folder).unwrap();
        for i in 0..150 {
            let p = folder.join(format!("f{i:03}.bin"));
            fs::write(&p, noise(100 + i * 37 + d * 11, (d * 1000 + i) as u32)).unwrap();
            filetime::set_file_mtime(&p, FileTime::from_unix_time(1_700_000_000 + i as i64, 0))
                .unwrap();
        }
        inputs.push(folder);
    }
    let big = src.join("big.bin");
    fs::write(&big, noise(6 << 20, 7)).unwrap();
    inputs.push(big);
    let cab = dir.path().join("many.cab");
    create(&cab, &inputs, CabMethod::Mszip);

    let threaded = dir.path().join("threaded");
    let report = ops::extract(
        &cab,
        &threaded,
        &Selection::all(),
        &OpenOptions::default().with_threads(4),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(report.files, 601);
    let one = dir.path().join("one");
    extract(&cab, &one);
    assert_eq!(files_under(&threaded), files_under(&one));
    let t = fs::metadata(threaded.join("d2/f018.bin"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(t, UNIX_EPOCH + Duration::from_secs(1_700_000_018));
}
