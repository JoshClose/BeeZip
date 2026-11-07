//! Codec round trips (docs/M1.md §6): empty, tiny, incompressible and highly repetitive inputs
//! up to 1 MiB, at each codec's lowest and highest level and through the multithreaded writers.
//! `PROPTEST_CASES` raises the case count (default 12 per test).

#![allow(clippy::unwrap_used, clippy::expect_used)] // test helpers, not just #[test] fns

use std::io::{Read, Write};

use beezip_core::{
    CodecId, EncodeOpts, Limits,
    detect::{Confidence, Probe},
};
use proptest::prelude::*;

/// Input shapes, generated from a seed so a 1 MiB input costs one strategy value.
#[derive(Debug, Clone)]
enum Shape {
    Empty,
    Tiny(Vec<u8>),
    Random { len: usize, seed: u64 },
    Repetitive { len: usize, unit: Vec<u8> },
    Text { len: usize, seed: u64 },
}

const MAX: usize = 1024 * 1024;

fn shape() -> impl Strategy<Value = Shape> {
    prop_oneof![
        1 => Just(Shape::Empty),
        2 => proptest::collection::vec(any::<u8>(), 1..64).prop_map(Shape::Tiny),
        2 => (1..MAX, any::<u64>()).prop_map(|(len, seed)| Shape::Random { len, seed }),
        2 => (1..MAX, proptest::collection::vec(any::<u8>(), 1..32))
            .prop_map(|(len, unit)| Shape::Repetitive { len, unit }),
        2 => (1..MAX / 4, any::<u64>()).prop_map(|(len, seed)| Shape::Text { len, seed }),
    ]
}

/// xorshift64*, enough for test data.
fn rng(mut s: u64) -> impl FnMut() -> u64 {
    s |= 1;
    move || {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn bytes(shape: &Shape) -> Vec<u8> {
    match shape {
        Shape::Empty => Vec::new(),
        Shape::Tiny(b) => b.clone(),
        Shape::Random { len, seed } => {
            let mut next = rng(*seed);
            (0..*len).map(|_| (next() >> 24) as u8).collect()
        }
        Shape::Repetitive { len, unit } => unit.iter().copied().cycle().take(*len).collect(),
        Shape::Text { len, seed } => {
            const WORDS: [&str; 8] = ["bee", "zip ", "hive\n", "honey ", "é", "wax ", "the ", "a "];
            let mut next = rng(*seed);
            let mut out = Vec::with_capacity(*len);
            while out.len() < *len {
                out.extend_from_slice(WORDS[(next() % 8) as usize].as_bytes());
            }
            out.truncate(*len);
            out
        }
    }
}

fn encode(codec: CodecId, data: &[u8], opts: &EncodeOpts) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = codec.codec().encoder(Box::new(&mut out), opts).unwrap();
    // Uneven writes, as a tar writer would make them.
    for chunk in data.chunks(100_003) {
        enc.write_all(chunk).unwrap();
    }
    enc.finish().unwrap();
    out
}

fn decode(codec: CodecId, data: &[u8]) -> Vec<u8> {
    let mut dec = codec
        .codec()
        .decoder(Box::new(data), &Limits::default())
        .unwrap();
    let mut out = Vec::new();
    dec.read_to_end(&mut out).unwrap();
    out
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12)
}

fn round_trip(codec: CodecId, data: &[u8], opts: &EncodeOpts) -> Result<(), TestCaseError> {
    let packed = encode(codec, data, opts);
    let back = decode(codec, &packed);
    prop_assert_eq!(back.len(), data.len());
    prop_assert!(back == data, "{} round trip changed the data", codec);
    Ok(())
}

/// Options for a level, with the input size as a hint (as stream.compress gives it).
fn at(level: Option<i32>, len: usize) -> EncodeOpts {
    EncodeOpts {
        level,
        threads: 1,
        size_hint: Some(len as u64),
        size_exact: true,
        ..EncodeOpts::default()
    }
}

/// Multithreaded, with small blocks so a 1 MiB input really splits.
fn mt(level: i32) -> EncodeOpts {
    EncodeOpts {
        level: Some(level),
        threads: 4,
        size_hint: Some(256 * 1024),
        block_size: Some(256 * 1024),
        ..EncodeOpts::default()
    }
}

macro_rules! levels_test {
    ($name:ident, $codec:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(cases()))]
            #[test]
            fn $name(shape in shape()) {
                let codec: CodecId = $codec;
                let data = bytes(&shape);
                match codec.codec().levels() {
                    Some(l) => {
                        round_trip(codec, &data, &at(Some(l.min), data.len()))?;
                        round_trip(codec, &data, &at(Some(l.max), data.len()))?;
                    }
                    None => round_trip(codec, &data, &at(None, data.len()))?,
                }
            }
        }
    };
}

levels_test!(gzip, CodecId::Gzip);
levels_test!(zlib, CodecId::Zlib);
levels_test!(deflate, CodecId::Deflate);
levels_test!(bzip2, CodecId::Bzip2);
levels_test!(xz, CodecId::Xz);
levels_test!(lzma, CodecId::Lzma);
levels_test!(lzip, CodecId::Lzip);
levels_test!(zstd, CodecId::Zstd);
levels_test!(lz4, CodecId::Lz4);
levels_test!(brotli, CodecId::Brotli);
levels_test!(snappy, CodecId::Snappy);
levels_test!(compress, CodecId::Compress);
levels_test!(lzop, CodecId::Lzop);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]
    #[test]
    fn multithreaded_writers(shape in shape()) {
        let data = bytes(&shape);
        for codec in [CodecId::Xz, CodecId::Lzip, CodecId::Zstd] {
            let l = codec.codec().levels().unwrap();
            assert!(codec.codec().threads());
            round_trip(codec, &data, &mt(l.min))?;
            round_trip(codec, &data, &mt(l.max))?;
        }
    }
}

#[test]
fn multithreaded_xz_writes_several_blocks() {
    let data = bytes(&Shape::Random {
        len: 900_000,
        seed: 7,
    });
    let single = encode(CodecId::Xz, &data, &at(Some(0), data.len()));
    let multi = encode(CodecId::Xz, &data, &mt(0));
    assert_ne!(single, multi, "the MT writer should split into blocks");
    assert_eq!(decode(CodecId::Xz, &multi), data);
}

/// `cat a.gz b.gz` and friends decode to both parts.
#[test]
fn concatenated_streams_decode_whole() {
    let a = b"first part, ".repeat(100);
    let b = b"second part".repeat(50);
    for codec in [
        CodecId::Gzip,
        CodecId::Bzip2,
        CodecId::Xz,
        CodecId::Lzip,
        CodecId::Zstd,
        CodecId::Lz4,
        CodecId::Lzop,
    ] {
        let mut joined = encode(codec, &a, &EncodeOpts::default());
        joined.extend(encode(codec, &b, &EncodeOpts::default()));
        let mut want = a.clone();
        want.extend_from_slice(&b);
        assert_eq!(decode(codec, &joined), want, "{codec}");
    }
}

/// Every codec's output is recognised as that codec: by magic, or by magic plus extension for
/// the formats without a strong one. Raw deflate is never detected.
#[test]
fn outputs_sniff_as_their_codec() {
    let data = b"some data that compresses: aaaaaaaaaaaaaaaaaaaaaaaa".repeat(20);
    for codec in CodecId::ALL {
        let packed = encode(codec, &data, &EncodeOpts::default());
        let ext = codec.codec().extensions().first().copied();
        let name = ext.map(|e| format!("file{e}"));
        let probe = Probe {
            head: &packed,
            len: Some(packed.len() as u64),
            name: name.as_deref(),
            ..Probe::default()
        };
        let got = codec.codec().sniff(&probe);
        if codec == CodecId::Deflate {
            assert_eq!(got, None);
        } else {
            assert!(got >= Some(Confidence::Likely), "{codec}: {got:?}");
        }
        // Without its name, a codec without magic doesn't claim the data.
        let anon = Probe {
            head: &packed,
            ..Probe::default()
        };
        if matches!(codec, CodecId::Zlib | CodecId::Lzma | CodecId::Brotli) {
            assert_eq!(codec.codec().sniff(&anon), None, "{codec}");
        }
    }
}

#[test]
fn truncated_streams_fail_as_corrupt() {
    let data = bytes(&Shape::Random {
        len: 50_000,
        seed: 3,
    });
    for codec in CodecId::ALL {
        let packed = encode(codec, &data, &EncodeOpts::default());
        let cut = &packed[..packed.len() / 2];
        if codec == CodecId::Compress {
            // `.Z` has no end marker, length or checksum: a cut stream reads as a shorter one.
            let short = decode(codec, cut);
            assert!(!short.is_empty() && data.starts_with(&short), "{codec}");
            continue;
        }
        let result = codec
            .codec()
            .decoder(Box::new(cut), &Limits::default())
            .and_then(|mut d| {
                let mut out = Vec::new();
                d.read_to_end(&mut out)
                    .map_err(|e| beezip_core::io::read_error(&e))
            });
        let err = result.expect_err(codec.name());
        assert_eq!(err.kind, beezip_core::ErrorKind::Corrupt, "{codec}: {err}");
    }
}

#[test]
fn decoder_memory_limit_is_enforced() {
    let data = bytes(&Shape::Random {
        len: 3_000_000,
        seed: 9,
    });
    let small = Limits {
        decoder_memory: 1024 * 1024,
        ..Limits::default()
    };
    for codec in [CodecId::Xz, CodecId::Lzma, CodecId::Lzip, CodecId::Zstd] {
        // Level-6 dictionaries (8 MiB) and zstd's 19+ windows exceed 1 MiB.
        let level = if codec == CodecId::Zstd { 19 } else { 6 };
        let packed = encode(codec, &data, &EncodeOpts::with_level(level));
        let result = codec
            .codec()
            .decoder(Box::new(&packed[..]), &small)
            .and_then(|mut d| {
                let mut out = Vec::new();
                d.read_to_end(&mut out)
                    .map_err(|e| beezip_core::io::read_error(&e))
            });
        let err = result.expect_err(codec.name());
        assert_eq!(
            err.kind,
            beezip_core::ErrorKind::LimitExceeded,
            "{codec}: {err:?}"
        );
    }
}
