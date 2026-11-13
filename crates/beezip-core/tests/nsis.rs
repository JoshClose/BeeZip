//! BeeZip's own NSIS reader (docs/M10.md) on `tests/fixtures/thirdparty/nsis/`, made by
//! `tests/fixtures/make-nsis.sh` with makensis 3.09 (whose files `fixtures.rs` checks through
//! their records), and on installers written by core's writer. Then real installers against
//! 7-Zip, opt-in.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "oracle/seven_zip.rs"]
mod seven_zip;

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};

use beezip_core::{
    ArchiveReader, Ctx, Entry, EntryKind, EntrySink, ErrorKind, External, FormatId, Limits,
    OpenOptions, Selection, SimpleCtx, detect_path, format::nsis, source::Source,
};
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The installer at `path`, through BeeZip's own reader (never 7-Zip).
fn native(path: &Path) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let source = Source::new(path, Vec::new(), &OpenOptions::default())?;
    nsis::open(source, &mut SimpleCtx::new())
}

/// Each file's bytes, or why it failed.
#[derive(Default)]
struct Collect(BTreeMap<String, Result<Vec<u8>, ErrorKind>>);

impl EntrySink for Collect {
    fn entry(
        &mut self,
        e: &Entry,
        data: &mut dyn Read,
        _: &mut dyn Ctx,
    ) -> beezip_core::Result<()> {
        if e.kind == EntryKind::File {
            let mut v = Vec::new();
            let r = data
                .read_to_end(&mut v)
                .map(|_| v)
                .map_err(|e| beezip_core::io::read_error(&e).kind);
            self.0.insert(e.path.clone(), r);
        }
        Ok(())
    }
}

fn extract(r: &mut dyn ArchiveReader) -> BTreeMap<String, Result<Vec<u8>, ErrorKind>> {
    let mut sink = Collect::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    sink.0
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty/nsis")
}

fn fixture_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".exe"))
        .collect();
    names.sort();
    assert_eq!(names.len(), 7);
    names
}

/// Info's NSIS properties, by name.
fn props(r: &mut dyn ArchiveReader) -> BTreeMap<String, String> {
    r.info(&mut SimpleCtx::new())
        .unwrap()
        .external
        .unwrap()
        .properties
        .into_iter()
        .map(|p| (p.name, p.value))
        .collect()
}

#[test]
fn info_says_how_each_fixture_was_made() {
    for (file, want) in [
        (
            "u-zlib.exe",
            &[("Version", "NSIS 3, Unicode"), ("Method", "Deflate")][..],
        ),
        ("u-bzip2-solid.exe", &[("Method", "BZip2")][..]),
        (
            "u-lzma-solid.exe",
            &[("Method", "LZMA, 8 MiB dictionary")][..],
        ),
        ("a-bzip2.exe", &[("Version", "NSIS 3, ANSI")][..]),
        (
            "a-zlib-solid.exe",
            &[("Version", "NSIS 3, ANSI"), ("Method", "Deflate")][..],
        ),
        ("x64-lzma.exe", &[("Target", "64-bit")][..]),
        ("u-nocrc.exe", &[("Checksum", "none")][..]),
    ] {
        let mut r = native(&fixtures().join(file)).unwrap();
        let got = props(&mut *r);
        for (name, value) in want {
            assert_eq!(
                got.get(*name).map(String::as_str),
                Some(*value),
                "{file}: {name}"
            );
        }
        assert_eq!(got["Kind"], "installer", "{file}");
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert!(report.ok(), "{file}: {:?}", report.errors);
        assert_eq!(
            report.note.is_some(),
            file == "u-nocrc.exe",
            "{file}: {:?}",
            report.note
        );
    }
}

/// Each fixture's uninstaller, rebuilt as `WriteUninstaller` writes it, is an NSIS uninstaller
/// BeeZip opens.
#[test]
fn each_uninstaller_is_an_uninstaller() {
    let dir = tempfile::tempdir().unwrap();
    for file in fixture_names() {
        let mut r = native(&fixtures().join(&file)).unwrap();
        let id = r
            .entries(&mut SimpleCtx::new())
            .unwrap()
            .iter()
            .position(|e| e.path == "uninstall.exe")
            .unwrap();
        let mut data = Vec::new();
        r.open_entry(id, &mut SimpleCtx::new())
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        let p = dir.path().join(format!("un-{file}"));
        std::fs::write(&p, &data).unwrap();
        assert_eq!(
            detect_path(&p, &Limits::default()).unwrap().format(),
            Some(FormatId::External(External::Nsis)),
            "{file}"
        );
        let mut un = native(&p).unwrap();
        assert_eq!(props(&mut *un)["Kind"], "uninstaller", "{file}");
        let report = un.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert!(report.ok(), "{file}: {:?}", report.errors);
    }
}

#[test]
fn a_cut_fixture_gives_the_files_before_the_cut() {
    for file in ["u-lzma-solid.exe", "u-zlib.exe"] {
        let whole = std::fs::read(fixtures().join(file)).unwrap();
        let mut r = native(&fixtures().join(file)).unwrap();
        let listed = r.entries(&mut SimpleCtx::new()).unwrap().len();
        let want = extract(&mut *r);
        let dir = tempfile::tempdir().unwrap();
        let cut = dir.path().join("cut.exe");
        // The data starts after the stub; cut a little way into it, and just before its end.
        let data = whole
            .windows(16)
            .position(|w| w == b"\xEF\xBE\xAD\xDENullsoftInst")
            .unwrap()
            - 4;
        for keep in [data + (whole.len() - data) / 2, whole.len() - 3000] {
            std::fs::write(&cut, &whole[..keep]).unwrap();
            let mut r = native(&cut).unwrap_or_else(|e| panic!("{file} {keep}: {e}"));
            assert_eq!(
                r.entries(&mut SimpleCtx::new()).unwrap().len(),
                listed,
                "{file} {keep}"
            );
            let got = extract(&mut *r);
            let (mut good, mut bad) = (0, 0);
            for (p, data) in &got {
                match data {
                    Ok(d) => {
                        assert_eq!(want.get(p), Some(&Ok(d.clone())), "{file} {keep}: {p}");
                        good += 1;
                    }
                    Err(k) => {
                        assert_eq!(*k, ErrorKind::Corrupt, "{file} {keep}: {p}");
                        bad += 1;
                    }
                }
            }
            assert!(
                good > 0 && bad > 0,
                "{file} {keep}: {good} read, {bad} failed"
            );
            let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
            assert!(
                report.errors.iter().any(|e| e.path.is_empty()),
                "{file} {keep}"
            );
        }
    }
}

/// The fuzz target's body over bit-flipped, overwritten and cut copies of the fixtures, the
/// corpus and installers with their header stored (so changes reach the header's parser), half
/// of the changes in the first 4 KiB from the first header: none may panic or hang.
/// `BEEZIP_MUTATIONS` sets the copies per installer (default 100).
#[test]
fn mutated_installers_never_panic() {
    use beezip_core::format::nsis::write::{Layout, Method, Op, Strings, nsis};
    let mut seeds: Vec<Vec<u8>> = fixture_names()
        .iter()
        .map(|n| std::fs::read(fixtures().join(n)).unwrap())
        .collect();
    let malicious = fixtures().join("../../malicious");
    for e in std::fs::read_dir(&malicious).unwrap() {
        let p = e.unwrap().path();
        let n = p.file_name().unwrap().to_string_lossy().into_owned();
        if n.starts_with("nsis-") || n == "traversal.nsis.exe" {
            seeds.push(std::fs::read(p).unwrap());
        }
    }
    let ops = [
        Op::SetOutPath(b"$INSTDIR\\sub"),
        Op::File(b"a.txt", b"some text, some text, some text"),
        Op::File(b"$PLUGINSDIR\\b.dll", &[7; 3000]),
        Op::EmptyFile(b"$INSTDIR\\empty.txt"),
        Op::WriteUninstaller {
            name: b"$INSTDIR\\uninstall.exe",
            alt: Some(b"$INSTDIR\\uninstall.exe"),
            data: b"uninstaller",
            patches: vec![(600, b"ICON".to_vec())],
        },
    ];
    for strings in [
        Strings::Nsis2Ansi,
        Strings::Nsis3Unicode,
        Strings::ParkUnicode,
    ] {
        for method in [
            Method::Deflate,
            Method::Nsis2Deflate,
            Method::Lzma { filter: Some(true) },
        ] {
            seeds.push(nsis(
                &ops,
                &Layout {
                    strings,
                    method,
                    solid: false,
                    header_compressed: false,
                    stub: 1024,
                    ..Layout::default()
                },
            ));
        }
    }
    let per = std::env::var("BEEZIP_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100usize);
    let limits = Limits {
        max_ratio: Some(200),
        ratio_grace: 1 << 20,
        max_total_bytes: Some(32 << 20),
        max_entries: Some(10_000),
        max_layers: 4,
        decoder_memory: 64 << 20,
    };
    let opts = OpenOptions::new(limits);
    let mut x = 0x00F5_15A5_u64;
    let mut next = move || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.exe");
    for seed in &seeds {
        let first = seed
            .windows(16)
            .position(|w| w == b"\xEF\xBE\xAD\xDENullsoftInst")
            .map_or(0, |p| p.saturating_sub(4));
        for _ in 0..per {
            let mut d = seed.clone();
            let len = d.len().max(1) as u64;
            // Half the changes from the first header on, where the header is.
            let (from, span) = if next() % 2 == 0 {
                (first as u64, (len - first as u64).clamp(1, 4096))
            } else {
                (0, len)
            };
            match next() % 3 {
                0 => {
                    for _ in 0..1 + next() % 8 {
                        let i = (from + next() % span) as usize;
                        if let Some(b) = d.get_mut(i) {
                            *b ^= 1 << (next() % 8);
                        }
                    }
                }
                1 => {
                    let i = (from + next() % span) as usize;
                    let v = [0u8, 0xFF, 0x7F, 0x80][(next() % 4) as usize];
                    for b in d.iter_mut().skip(i).take(1 + (next() % 4) as usize) {
                        *b = v;
                    }
                }
                _ => d.truncate((next() % len) as usize),
            }
            std::fs::write(&input, &d).unwrap();
            let Ok(source) = Source::new(&input, Vec::new(), &opts) else {
                continue;
            };
            let mut cx = SimpleCtx::new();
            let Ok(mut r) = nsis::open(source, &mut cx) else {
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
}

/// 7-Zip's name for a file on Windows: what it writes in place of what a name can't hold.
fn seven_zip_name(path: &str) -> String {
    if !cfg!(windows) {
        return path.to_owned();
    }
    path.chars()
        .map(|c| {
            if "<>:\"|?*".contains(c) || (c as u32) < 32 {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// The paths 7-Zip names in its errors (`ERROR: Data Error : path`).
fn seven_zip_errors(out: &str) -> BTreeSet<String> {
    out.lines()
        .filter_map(|l| l.strip_prefix("ERROR: "))
        .filter_map(|l| l.split(" : ").nth(1))
        .map(|p| p.replace('\\', "/"))
        .collect()
}

/// Opt-in: `BEEZIP_NSIS_SAMPLES` names folders of NSIS installers (`.exe`), separated as PATH
/// is. Each one detection takes for an installer is read natively, and every file must read
/// unless its installer fails its CRC; each file the installed 7-Zip extracts without an error
/// must be the same bytes (docs/M10.md §8). Counted apart: files only BeeZip writes, under the
/// names it gives them, and files that differ in an installer 7-Zip reports failures in (it
/// reads Ubuntu 16.04's makensis 2.50 zlib stream in NSIS 2's form, wrongly, and writes MuMu's
/// stored-header records empty, "Not implemented").
#[test]
fn real_installers_read_as_7zip_extracts_them() {
    let Some(folders) = std::env::var_os("BEEZIP_NSIS_SAMPLES") else {
        return;
    };
    let seven = seven_zip::find().expect("BEEZIP_NSIS_SAMPLES needs 7-Zip");
    let mut paths: Vec<PathBuf> = std::env::split_paths(&folders)
        .flat_map(|f| std::fs::read_dir(f).unwrap())
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")))
        .collect();
    paths.sort();
    let mut bad = Vec::new();
    let (mut same, mut only_ours, mut failed_ours, mut theirs_wrong) = (0, 0, 0, 0);
    let mut installers = 0;
    for path in &paths {
        let det = detect_path(path, &Limits::default()).unwrap();
        if det.format() != Some(FormatId::External(External::Nsis)) {
            continue;
        }
        let mut r = match native(path) {
            Ok(r) => r,
            Err(e) => {
                bad.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        installers += 1;
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        let crc_failed = report.errors.iter().any(|e| e.path.is_empty());
        let got = extract(&mut *r);
        let out = tempfile::tempdir().unwrap();
        let run = std::process::Command::new(&seven.exe)
            .args(["x", "-y", "-bso1", "-bse1", "-bsp0"])
            .arg(format!("-o{}", out.path().display()))
            .arg(path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&run.stdout);
        let failed = seven_zip_errors(&text);
        let seven_failed = text.contains("ERROR: ");
        for (p, data) in &got {
            let Ok(data) = data else {
                failed_ours += 1;
                if !crc_failed {
                    bad.push(format!("{}: {p}: {data:?}", path.display()));
                }
                continue;
            };
            let name = seven_zip_name(p);
            let theirs = out.path().join(&name);
            if failed.contains(&name) || !theirs.is_file() {
                only_ours += 1;
                continue;
            }
            if sha256(&std::fs::read(&theirs).unwrap()) == sha256(data) {
                same += 1;
            } else if seven_failed {
                theirs_wrong += 1;
            } else {
                bad.push(format!("{}: {p} differs from 7-Zip's", path.display()));
            }
        }
    }
    eprintln!(
        "{installers} installers of {} files: {same} files as {} extracts them, {only_ours} it \
         doesn't write or names otherwise, {theirs_wrong} where it reports failures, \
         {failed_ours} failed in damaged installers; {} problems",
        paths.len(),
        seven.name,
        bad.len()
    );
    assert!(bad.is_empty(), "{bad:#?}");
}
