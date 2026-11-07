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
        for codec in [
            CodecId::Gzip,
            CodecId::Zlib,
            CodecId::Deflate,
            CodecId::Xz,
            CodecId::Lzip,
            CodecId::Zstd,
        ] {
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

/// Parallel deflate (docs/M6.md §6.1, §10): gzip, zlib and raw deflate on more than one thread.
mod parallel_deflate {
    use std::time::{Duration, SystemTime};

    use flate2::{
        Compression, GzBuilder,
        read::{DeflateDecoder, MultiGzDecoder, ZlibDecoder},
        write::{DeflateEncoder, ZlibEncoder},
    };

    use super::*;

    const BLOCK: usize = 128 * 1024;
    const CODECS: [CodecId; 3] = [CodecId::Gzip, CodecId::Zlib, CodecId::Deflate];
    const NAME: &str = "notes é.txt";
    const MTIME: u64 = 1_700_000_000;

    fn opts(level: u32, threads: u32) -> EncodeOpts {
        EncodeOpts {
            level: Some(level as i32),
            threads,
            gzip_name: Some(NAME.into()),
            gzip_mtime: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(MTIME)),
            ..EncodeOpts::default()
        }
    }

    /// Text, then random bytes: compressible blocks and incompressible ones.
    fn mixed(len: usize) -> Vec<u8> {
        let mut data = bytes(&Shape::Text {
            len: len / 2,
            seed: 11,
        });
        data.extend(bytes(&Shape::Random {
            len: len - len / 2,
            seed: 12,
        }));
        data
    }

    /// Through flate2's decoder, and through BeeZip's own.
    fn decode_both(codec: CodecId, packed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut flate2 = Vec::new();
        match codec {
            CodecId::Gzip => MultiGzDecoder::new(packed).read_to_end(&mut flate2),
            CodecId::Zlib => ZlibDecoder::new(packed).read_to_end(&mut flate2),
            _ => DeflateDecoder::new(packed).read_to_end(&mut flate2),
        }
        .unwrap();
        let mut ours = Vec::new();
        codec
            .decoder(Box::new(packed), &Limits::default())
            .unwrap()
            .read_to_end(&mut ours)
            .unwrap();
        (flate2, ours)
    }

    /// What flate2 alone writes at `level`, as the codecs did before M6, with [`opts`]'s
    /// gzip name and mtime.
    fn flate2(codec: CodecId, data: &[u8], level: u32) -> Vec<u8> {
        let level = Compression::new(level);
        match codec {
            CodecId::Gzip => {
                let latin1: Vec<u8> = NAME.chars().map(|c| c as u8).collect();
                let mut e = GzBuilder::new()
                    .filename(latin1)
                    .mtime(MTIME as u32)
                    .write(Vec::new(), level);
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            CodecId::Zlib => {
                let mut e = ZlibEncoder::new(Vec::new(), level);
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            _ => {
                let mut e = DeflateEncoder::new(Vec::new(), level);
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
        }
    }

    /// Writes of `piece` bytes each.
    fn encode_in(codec: CodecId, data: &[u8], opts: &EncodeOpts, piece: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut enc = codec.codec().encoder(Box::new(&mut out), opts).unwrap();
        for chunk in data.chunks(piece.max(1)) {
            enc.write_all(chunk).unwrap();
        }
        enc.finish().unwrap();
        out
    }

    #[test]
    fn the_bytes_depend_only_on_the_level() {
        let data = mixed(5 * BLOCK + 777);
        for codec in CODECS {
            for level in 0..=9 {
                let two = encode_in(codec, &data, &opts(level, 2), data.len());
                for threads in [4, 32] {
                    let more = encode_in(codec, &data, &opts(level, threads), data.len());
                    assert!(more == two, "{codec} level {level}: {threads} threads");
                }
                let (a, b) = decode_both(codec, &two);
                assert!(a == data && b == data, "{codec} level {level}");
            }
        }
    }

    #[test]
    fn round_trips_at_the_block_edges() {
        let text = mixed(12 * BLOCK);
        let random = bytes(&Shape::Random {
            len: 3_000_000,
            seed: 5,
        });
        let cases: [(&str, &[u8]); 7] = [
            ("empty", &[]),
            ("one byte", b"x"),
            ("one block", &text[..BLOCK]),
            ("one block and a byte", &text[..BLOCK + 1]),
            ("two blocks", &text[..2 * BLOCK]),
            ("many blocks", &text),
            ("3 MB of random", &random),
        ];
        for codec in CODECS {
            for (name, data) in cases {
                for level in [0, 1, 6, 9] {
                    let packed = encode_in(codec, data, &opts(level, 4), data.len());
                    let (a, b) = decode_both(codec, &packed);
                    assert!(a == data, "{codec} {name} level {level}: flate2");
                    assert!(b == data, "{codec} {name} level {level}: BeeZip");
                }
            }
        }
    }

    /// The gzip header keeps BeeZip's name and mtime as flate2's `GzBuilder` wrote them, and
    /// the trailer has the same CRC and size; zlib's header and Adler-32 match too.
    #[test]
    fn headers_and_trailers_are_flate2s() {
        let data = mixed(3 * BLOCK + 5);
        let head = 10 + NAME.chars().count() + 1;
        for level in 0..=9 {
            let ours = encode_in(CodecId::Gzip, &data, &opts(level, 4), data.len());
            let theirs = flate2(CodecId::Gzip, &data, level);
            assert_eq!(ours[..head], theirs[..head], "gzip level {level}");
            assert_eq!(ours[ours.len() - 8..], theirs[theirs.len() - 8..]);
            let ours = encode_in(CodecId::Zlib, &data, &opts(level, 4), data.len());
            let theirs = flate2(CodecId::Zlib, &data, level);
            assert_eq!(ours[..2], theirs[..2], "zlib level {level}");
            assert_eq!(ours[ours.len() - 4..], theirs[theirs.len() - 4..]);
        }
        // Without a name or a time: no FNAME and MTIME 0, as before.
        let bare = EncodeOpts {
            threads: 4,
            ..EncodeOpts::default()
        };
        let ours = encode_in(CodecId::Gzip, b"abc", &bare, 3);
        let mut theirs = GzBuilder::new().write(Vec::new(), Compression::new(6));
        theirs.write_all(b"abc").unwrap();
        assert_eq!(ours[..10], theirs.finish().unwrap()[..10]);
    }

    /// One thread is flate2's encoder, so it writes what BeeZip wrote before.
    #[test]
    fn one_thread_writes_todays_bytes() {
        let data = mixed(3 * BLOCK + 5);
        for codec in CODECS {
            for level in [0, 1, 6, 9] {
                let ours = encode_in(codec, &data, &opts(level, 1), data.len());
                let theirs = flate2(codec, &data, level);
                assert!(ours == theirs, "{codec} level {level}");
            }
        }
    }

    /// Blocks are cut by offset, so the sizes of the writes don't matter.
    #[test]
    fn odd_sized_writes_give_the_same_bytes() {
        let data = mixed(2 * BLOCK + 1234);
        for codec in CODECS {
            let whole = encode_in(codec, &data, &opts(6, 4), data.len());
            for piece in [1, 7, 1024 * 1024] {
                let pieces = encode_in(codec, &data, &opts(6, 4), piece);
                assert!(pieces == whole, "{codec}: writes of {piece}");
            }
        }
    }
}
