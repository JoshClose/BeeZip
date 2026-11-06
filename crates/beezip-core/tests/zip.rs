//! The zip reader: the local-header scan and its spans (docs/M5.md §4), and the time a million
//! entries take to open (#54).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use beezip_core::{
    Limits, OpenOptions, SimpleCtx,
    format::{ArchiveReader, zip::ZipReader},
    source::Source,
};

fn fixture(dir: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(dir)
        .join(name)
}

fn zip_reader(path: &Path) -> ZipReader {
    let source = Source::new(path, Vec::new(), &OpenOptions::default()).unwrap();
    ZipReader::open(source, false, &mut SimpleCtx::new()).unwrap()
}

/// The offset of the central directory, from the end record (none of these is Zip64).
fn central_directory(path: &Path) -> u64 {
    let bytes = std::fs::read(path).unwrap();
    let at = (0..bytes.len() - 21)
        .rev()
        .find(|&i| bytes[i..i + 4] == *b"PK\x05\x06")
        .unwrap();
    u64::from(u32::from_le_bytes(
        bytes[at + 16..at + 20].try_into().unwrap(),
    ))
}

/// Every entry's span ends where the next begins, and the last where the central directory
/// does: the scan found each local header, its data, and its data descriptor.
#[test]
fn spans_cover_the_entries_exactly() {
    let zips = [
        "7z-deflate.zip",
        "7z-copy.zip",
        "7z-bzip2.zip",
        "7z-lzma.zip",
        "7z-ppmd.zip",
        "7z-deflate64.zip",
        "7z-aes256.zip",
        "7z-zipcrypto.zip",
        "7z-cp932.zip",
        // Data descriptors, with the signature.
        "bsdtar.zip",
        "dotnet.zip",
        "dotnet-cp932.zip",
    ];
    for name in zips {
        let path = fixture("thirdparty", name);
        let mut reader = zip_reader(&path);
        let count = reader.entries(&mut SimpleCtx::new()).unwrap().len();
        let mut spans: Vec<_> = (0..count).map(|i| reader.span(i).unwrap()).collect();
        spans.sort_by_key(|s| s.header);
        assert_eq!(spans[0].header, 0, "{name}");
        for w in spans.windows(2) {
            assert_eq!(w[0].end, w[1].header, "{name}: {w:?}");
        }
        let last = spans.last().unwrap();
        assert_eq!(last.end, central_directory(&path), "{name}");
        for (i, s) in spans.iter().enumerate() {
            assert!(
                s.header < s.data && s.data <= s.data_end && s.data_end <= s.end,
                "{name} {i}"
            );
        }
    }
}

/// A zip with data descriptors: the spans include them.
#[test]
fn spans_include_data_descriptors() {
    let path = fixture("thirdparty", "bsdtar.zip");
    let mut reader = zip_reader(&path);
    let entries = reader.entries(&mut SimpleCtx::new()).unwrap().to_vec();
    let with_tail = entries
        .iter()
        .filter(|e| {
            let s = reader.span(e.id).unwrap();
            s.end > s.data_end
        })
        .count();
    assert!(with_tail > 0, "bsdtar.zip has data descriptors");
}

/// `cargo test -p beezip-core --release --test zip -- --ignored bigzip`, after
/// `cargo xtask bigzip`: a million entries open in under a second (docs/M5.md §4, #54).
#[test]
#[ignore = "needs target/bigzip.zip from `cargo xtask bigzip`; run in release"]
fn bigzip_opens_in_under_a_second() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/bigzip.zip");
    assert!(path.is_file(), "run `cargo xtask bigzip` first");
    let opts = OpenOptions::new(Limits {
        max_entries: None,
        ..Limits::default()
    });
    let mut best = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        let mut cx = SimpleCtx::new();
        let mut opened = beezip_core::open(&path, &opts, &mut cx).unwrap();
        let n = opened.reader.entries(&mut cx).unwrap().len();
        let secs = t.elapsed().as_secs_f64();
        assert_eq!(n, 1_001_000);
        println!("opened {n} entries in {secs:.3} s");
        best = best.min(secs);
    }
    if !cfg!(debug_assertions) {
        assert!(best < 1.0, "the best of three took {best:.3} s");
    }
}
