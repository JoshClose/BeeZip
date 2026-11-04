//! A deterministic stand-in for the fuzzers that runs with `cargo test`: the bodies of the seven
//! `fuzz/` targets, run over every fixture and over bit-flipped, truncated and spliced copies of
//! each. The fuzzers (Linux, nightly) explore far more; this catches regressions on every
//! platform before they get there. `BEEZIP_MUTATIONS` sets the copies per fixture (default 48).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use beezip_core::{
    ArchiveReader, CodecId, Limits, NullSink, OpenOptions, Selection, SimpleCtx, detect_bytes,
    format::{rar::RarReader, sevenz::SevenZReader, tar::TarReader, zip::ZipReader},
    safefs::sanitize::sanitize,
    source::Source,
};

fn limits() -> Limits {
    Limits {
        max_ratio: Some(200),
        ratio_grace: 1 << 20,
        max_total_bytes: Some(32 << 20),
        max_entries: Some(10_000),
        max_layers: 4,
        decoder_memory: 64 << 20,
    }
}

fn corpus() -> Vec<Vec<u8>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    files.sort();
    files.iter().map(|p| std::fs::read(p).unwrap()).collect()
}

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
    match next() % 4 {
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
            let len = n(next, 512).min(other.len() - from);
            d.splice(at..at, other[from..from + len].iter().copied());
        }
        _ => {
            if !d.is_empty() {
                let i = n(next, d.len());
                let v = [0u8, 0xFF, 0x7F, 0x80][n(next, 4)];
                d[i] = v;
                if i + 1 < d.len() {
                    d[i + 1] = v;
                }
            }
        }
    }
    d
}

fn read_some(r: &mut dyn Read) {
    let _ = std::io::copy(&mut r.take(1 << 20), &mut std::io::sink());
}

fn readers(data: &[u8], dir: &Path) {
    let opts = OpenOptions::new(limits());
    let path = dir.join("input");
    std::fs::write(&path, data).unwrap();
    let mut cx = SimpleCtx::new().with_password("fuzz");

    if let Ok(source) = Source::new(&path, Vec::new(), &opts)
        && let Ok(mut r) = ZipReader::open(source, false, &mut cx)
    {
        let n = r.entries(&mut cx).map(<[_]>::len).unwrap_or(0);
        let _ = r.info(&mut cx);
        let _ = r.extract(&Selection::all(), &mut NullSink::default(), &mut cx);
        for id in 0..n.min(8) {
            if let Ok(mut e) = r.open_entry(id, &mut cx) {
                read_some(&mut e);
            }
        }
    }

    if let Ok(source) = Source::new(&path, Vec::new(), &opts)
        && let Ok(mut r) = SevenZReader::open(source, false, &mut cx)
    {
        exercise(&mut r, &mut cx);
    }

    // UnRAR runs in this process: a crash in it fails the test run instead of passing silently.
    if let Ok(source) = Source::new(&path, Vec::new(), &opts)
        && let Ok(mut r) = RarReader::open(source, false, &mut cx)
    {
        exercise(r.as_mut(), &mut cx);
    }

    if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
        let mut r = TarReader::new(source);
        let n = r.entries(&mut cx).map(<[_]>::len).unwrap_or(0);
        let _ = r.info(&mut cx);
        let _ = r.extract(&Selection::all(), &mut NullSink::default(), &mut cx);
        for id in 0..n.min(8) {
            if let Ok(mut e) = r.open_entry(id, &mut cx) {
                read_some(&mut e);
            }
        }
    }
}

/// What every reader body does: list, describe, extract to nothing, and read a few entries.
fn exercise(r: &mut dyn ArchiveReader, cx: &mut SimpleCtx) {
    let n = r.entries(cx).map(<[_]>::len).unwrap_or(0);
    let _ = r.info(cx);
    let _ = r.extract(&Selection::all(), &mut NullSink::default(), cx);
    for id in 0..n.min(8) {
        if let Ok(mut e) = r.open_entry(id, cx) {
            read_some(&mut e);
        }
    }
}

fn codecs_and_detect(data: &[u8]) {
    let limits = limits();
    let det = detect_bytes(data, Some("x.tar.gz"), &limits);
    assert!(det.codecs().len() <= limits.max_layers);
    let _ = detect_bytes(data, None, &limits);
    for codec in CodecId::ALL {
        if let Ok(mut dec) = codec.codec().decoder(Box::new(data), &limits) {
            read_some(&mut dec);
        }
    }
}

fn paths(data: &[u8]) {
    let input = String::from_utf8_lossy(data);
    if let Ok(safe) = sanitize(&input) {
        let again = sanitize(&safe.joined()).unwrap();
        assert_eq!(again.components, safe.components, "{input:?}");
        assert!(!again.renamed, "{input:?}");
    }
}

#[test]
fn fixtures_and_their_mutations_never_panic() {
    let corpus = corpus();
    assert!(corpus.len() > 30, "the fixtures are missing");
    let per = std::env::var("BEEZIP_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48usize);
    let dir = tempfile::tempdir().unwrap();
    let mut next = rng(0x00BE_E21F);
    for (i, data) in corpus.iter().enumerate() {
        let other = &corpus[(i + 1) % corpus.len()];
        let mut inputs = vec![data.clone()];
        inputs.extend((0..per).map(|_| mutate(data, other, &mut next)));
        for input in &inputs {
            readers(input, dir.path());
            codecs_and_detect(input);
            paths(&input[..input.len().min(512)]);
        }
    }
}

#[test]
fn hostile_paths_sanitise_to_fixed_points() {
    let samples = [
        "..\\..\\x",
        "C:\\..\\x",
        "\\\\?\\UNC\\a\\b\\..\\c",
        "a/ ./b",
        "con .txt",
        "COM¹",
        "x:y:z",
        "\u{0}\u{1f}\u{7f}",
        "trailing. . .",
        "//././//a",
        "C:",
        "C:a",
        "ﬀ/ǅ/ı",
        "\\\\?\\ab\u{FFFD}x",
        "//./é/UNC",
    ];
    for s in samples {
        paths(s.as_bytes());
    }
}
