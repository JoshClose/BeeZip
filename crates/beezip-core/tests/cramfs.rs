//! BeeZip's own CramFS reader (docs/M10.md) on `tests/fixtures/thirdparty/cramfs/`, made by
//! `tests/fixtures/make-cramfs.sh` with mkfs.cramfs (whose files `fixtures.rs` checks through
//! their records): what Info says of each, 7-Zip's own variant handed to 7-Zip, and cut images.
//! Then real images against 7-Zip, opt-in.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};

use beezip_core::{
    ArchiveReader, Ctx, Entry, EntryKind, EntrySink, ErrorKind, OpenOptions, Selection,
    SevenZipOptions, SimpleCtx, format::cramfs, open, source::Source,
};
use sha2::{Digest, Sha256};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty/cramfs")
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The image at `path`, through BeeZip's own reader (never 7-Zip).
fn native(path: &Path) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let source = Source::new(path, Vec::new(), &OpenOptions::default())?;
    cramfs::open(source, &mut SimpleCtx::new())
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

/// Info's CramFS properties, by name.
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
            "le.img",
            &[
                ("Name", "BeeZipCramfs"),
                ("Edition", "7"),
                ("Byte order", "little-endian"),
                ("Block size", "4 KiB"),
                ("Flags", "sorted folders"),
            ][..],
        ),
        ("be.img", &[("Byte order", "big-endian")][..]),
        ("holes.img", &[("Flags", "sorted folders, holes")][..]),
        ("pad.img", &[("Boot block", "512 bytes")][..]),
        ("b16k.img", &[("Block size", "16 KiB")][..]),
        (
            "ext-ptrs.img",
            &[("Flags", "sorted folders, extended block pointers")][..],
        ),
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
        assert_eq!(got["Checksum"], "CRC-32 of the image", "{file}");
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert!(report.ok(), "{file}: {:?}", report.errors);
        assert_eq!(report.note, None, "{file}");
    }
}

#[test]
fn sevenzips_own_variant_goes_to_7zip() {
    let path = fixtures().join("sevenzip-lzma.img");
    let err = native(&path).err().unwrap();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation, "{err}");
    assert!(err.message.contains("flags Linux doesn't know"), "{err}");

    // Without 7-Zip, the error says what BeeZip couldn't read.
    let off = OpenOptions::default().with_seven_zip(SevenZipOptions {
        path: None,
        enabled: false,
    });
    let err = open(&path, &off, &mut SimpleCtx::new()).err().unwrap();
    assert_eq!(err.kind, ErrorKind::BackendUnavailable);
    assert!(
        err.message
            .starts_with("BeeZip can't read this one itself (its superblock sets flags"),
        "{}",
        err.message
    );

    // With it, 7-Zip reads it, and Info says why.
    if beezip_core::backend::find(&SevenZipOptions::default()).is_err() {
        return;
    }
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let info = opened.reader.info(&mut cx).unwrap();
    let x = info.external.unwrap();
    assert!(x.backend.is_some());
    assert!(
        x.notes
            .iter()
            .any(|n| n.contains("BeeZip can't read this one itself")),
        "{:?}",
        x.notes
    );
    let files = extract(&mut *opened.reader);
    assert_eq!(files["small.txt"], Ok(b"small\n".to_vec()));
}

#[test]
fn a_cut_fixture_gives_the_files_before_the_cut() {
    let whole = std::fs::read(fixtures().join("b16k.img")).unwrap();
    let mut r = native(&fixtures().join("b16k.img")).unwrap();
    let listed = r.entries(&mut SimpleCtx::new()).unwrap().len();
    let want = extract(&mut *r);
    let dir = tempfile::tempdir().unwrap();
    let cut = dir.path().join("cut.img");
    // Inside the folders: nothing lists.
    std::fs::write(&cut, &whole[..200]).unwrap();
    assert_eq!(native(&cut).err().unwrap().kind, ErrorKind::Corrupt);
    for keep in [whole.len() / 2, whole.len() * 3 / 4, whole.len() - 5000] {
        std::fs::write(&cut, &whole[..keep]).unwrap();
        let mut r = native(&cut).unwrap_or_else(|e| panic!("{keep}: {e}"));
        assert_eq!(
            r.entries(&mut SimpleCtx::new()).unwrap().len(),
            listed,
            "{keep}: listed whole"
        );
        // A link past the cut is listed as a file of its blocks, which fails.
        let got = extract(&mut *r);
        let (mut good, mut bad) = (0, 0);
        for (p, data) in &got {
            match data {
                Ok(d) => {
                    assert_eq!(want.get(p), Some(&Ok(d.clone())), "{keep}: {p}");
                    good += 1;
                }
                Err(k) => {
                    assert_eq!(*k, ErrorKind::Corrupt, "{keep}: {p}");
                    bad += 1;
                }
            }
        }
        assert!(good > 0 && bad > 0, "{keep}: {good} read, {bad} failed");
        // The CRC can't be checked, and each file past the cut fails.
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert_eq!(report.errors_total, bad + 1, "{keep}: {:?}", report.errors);
        assert!(report.errors[0].message.contains("cut short"), "{keep}");
    }
}

/// 7-Zip's name for a file on Windows: a CramFS name's bytes in the OEM code page (437 on a US
/// system).
fn seven_zip_name(raw: &[u8]) -> String {
    if cfg!(windows) {
        raw.iter()
            .map(|&b| {
                let c = beezip_core::NameDecoding {
                    encoding: beezip_core::NameEncoding::Cp437,
                    ..beezip_core::NameDecoding::default()
                }
                .decode(&[b], false, beezip_core::SystemPage::Oem);
                if c == "/" { "\\".to_owned() } else { c }
            })
            .collect::<String>()
            .replace('\\', "/")
    } else {
        String::from_utf8_lossy(raw).into_owned()
    }
}

/// The paths 7-Zip names in its errors (`ERROR: Data Error : path`).
fn seven_zip_errors(out: &str) -> BTreeSet<String> {
    out.lines()
        .filter_map(|l| l.strip_prefix("ERROR: "))
        .filter_map(|l| l.split(" : ").nth(1))
        .map(|p| p.replace('\\', "/"))
        .collect()
}

/// Opt-in: `BEEZIP_CRAMFS_SAMPLES` names a folder of CramFS images (`.img`, `.cramfs`). Each is
/// read natively, and every file must read; each file the installed 7-Zip extracts without an
/// error must be the same bytes (docs/M10.md §8). Images 7-Zip can't open, and its files that
/// fail, are counted.
#[test]
fn real_images_read_as_7zip_extracts_them() {
    let Some(folder) = std::env::var_os("BEEZIP_CRAMFS_SAMPLES") else {
        return;
    };
    let seven = beezip_core::backend::find(&SevenZipOptions::default())
        .expect("BEEZIP_CRAMFS_SAMPLES needs 7-Zip");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("img") || e.eq_ignore_ascii_case("cramfs"))
        })
        .collect();
    paths.sort();
    let mut bad = Vec::new();
    let (mut same, mut only_ours, mut unopened) = (0, 0, 0);
    for path in &paths {
        let mut r = match native(path) {
            Ok(r) => r,
            Err(e) => {
                bad.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let entries = r.entries(&mut SimpleCtx::new()).unwrap().to_vec();
        let raw: BTreeMap<String, Vec<u8>> = entries
            .iter()
            .map(|e| (e.path.clone(), e.raw_path.clone()))
            .collect();
        let got = extract(&mut *r);
        let out = tempfile::tempdir().unwrap();
        let run = std::process::Command::new(&seven.exe)
            .args(["x", "-y", "-bso1", "-bse1", "-bsp0"])
            .arg(format!("-o{}", out.path().display()))
            .arg(path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&run.stdout);
        if text.contains("Cannot open the file as archive") {
            unopened += 1;
        }
        let failed = seven_zip_errors(&text);
        // Names that differ only in case are one file on Windows.
        let mut folded: BTreeMap<String, usize> = BTreeMap::new();
        for p in got.keys() {
            *folded.entry(p.to_lowercase()).or_default() += 1;
        }
        for (p, data) in &got {
            let Ok(data) = data else {
                bad.push(format!("{}: {p}: {data:?}", path.display()));
                continue;
            };
            let name = seven_zip_name(&raw[p]);
            let theirs = out.path().join(&name);
            if failed.contains(&name)
                || !theirs.is_file()
                || (cfg!(windows) && folded[&p.to_lowercase()] > 1)
            {
                only_ours += 1;
                continue;
            }
            if sha256(&std::fs::read(&theirs).unwrap()) != sha256(data) {
                bad.push(format!("{}: {p} differs from 7-Zip's", path.display()));
            } else {
                same += 1;
            }
        }
    }
    eprintln!(
        "{} images ({unopened} 7-Zip can't open): {same} files as {} extracts them, {only_ours} \
         it doesn't; {} problems",
        paths.len(),
        seven.name,
        bad.len()
    );
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The fuzz target's body over bit-flipped, overwritten and cut copies of every image here,
/// half of the changes in the superblock and folders: none may panic or hang. `BEEZIP_MUTATIONS`
/// sets the copies per image (default 150).
#[test]
fn mutated_images_never_panic() {
    let mut seeds = Vec::new();
    for e in std::fs::read_dir(fixtures()).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|e| e == "img") {
            seeds.push(std::fs::read(p).unwrap());
        }
    }
    let malicious = fixtures().join("../../malicious");
    for e in std::fs::read_dir(&malicious).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|e| e == "cramfs") {
            seeds.push(std::fs::read(p).unwrap());
        }
    }
    assert!(seeds.len() >= 15, "{} seeds", seeds.len());
    let per = std::env::var("BEEZIP_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150usize);
    let limits = beezip_core::Limits {
        max_ratio: Some(200),
        ratio_grace: 1 << 20,
        max_total_bytes: Some(32 << 20),
        max_entries: Some(10_000),
        max_layers: 4,
        decoder_memory: 64 << 20,
    };
    let opts = OpenOptions::new(limits);
    let mut x = 0x00CA_AF55_u64;
    let mut next = move || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.cramfs");
    for seed in &seeds {
        for _ in 0..per {
            let mut d = seed.clone();
            let len = d.len().max(1) as u64;
            // Half the changes where the superblock and folders are.
            let span = if next() % 2 == 0 { len.min(4096) } else { len };
            match next() % 3 {
                0 => {
                    for _ in 0..1 + next() % 8 {
                        let i = (next() % span) as usize;
                        if let Some(b) = d.get_mut(i) {
                            *b ^= 1 << (next() % 8);
                        }
                    }
                }
                1 => {
                    let i = (next() % span) as usize;
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
            let Ok(mut r) = cramfs::open(source, &mut cx) else {
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
