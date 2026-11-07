//! squashfs's compressors on the workspace's codecs (docs/M5.md §5.10): decoding for the
//! reader, encoding for the writer's backhand `CompressionAction`. Every block is one
//! self-contained stream: a zlib stream (gzip), a legacy `.lzma` stream with its 13-byte header,
//! an LZO1X block, an `.xz` stream (BCJ filters, when mksquashfs used them, are inside it), a raw
//! LZ4 block, or a zstd frame.

use std::io::{self, Read, Write};

use flate2::{Decompress, FlushDecompress, Status};

use super::SquashfsMethod;
use crate::{Error, Limits, Result, limits::MIB};

/// The most memory an xz or lzma block's decoder may take. A squashfs block is at most 1 MiB and
/// mksquashfs's dictionary is at most the block size, so this is far more than an image needs,
/// and a crafted block can't make the decoder allocate the job's whole `decoder_memory`.
const LZMA_MEMORY: u64 = 64 * MIB;
/// The largest zstd window a block may use (16 MiB), for the same reason.
const ZSTD_WINDOW_LOG: u32 = 24;

/// A compressor id from the superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Compressor {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Lz4,
    Zstd,
}

impl Compressor {
    pub(super) fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            1 => Self::Gzip,
            2 => Self::Lzma,
            3 => Self::Lzo,
            4 => Self::Xz,
            5 => Self::Lz4,
            6 => Self::Zstd,
            _ => return None,
        })
    }

    /// mksquashfs's name for it (`-comp`), which is also the image's method.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Lzma => "lzma",
            Self::Lzo => "lzo",
            Self::Xz => "xz",
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
        }
    }
}

fn bad(name: &str, e: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("squashfs: a {name} block doesn't decode: {e}"))
}

fn too_big(max: usize) -> Error {
    Error::corrupt(format!(
        "squashfs: a block decodes to more than {max} bytes"
    ))
}

/// Decodes blocks, reusing the decoders that can be reused (zlib's and zstd's state).
pub(super) struct Decoder {
    compressor: Compressor,
    inflate: Option<Box<Decompress>>,
    zstd: Option<zstd::bulk::Decompressor<'static>>,
    lzma_kib: u32,
}

impl Decoder {
    pub(super) fn new(compressor: Compressor, limits: &Limits) -> Result<Self> {
        let lzma = limits.decoder_memory.min(LZMA_MEMORY);
        let zstd = match compressor {
            Compressor::Zstd => {
                let mut d = zstd::bulk::Decompressor::new().map_err(|e| Error::from_io(&e))?;
                d.window_log_max(limits.zstd_window_log_max().min(ZSTD_WINDOW_LOG))
                    .map_err(|e| Error::from_io(&e))?;
                Some(d)
            }
            _ => None,
        };
        Ok(Self {
            compressor,
            inflate: (compressor == Compressor::Gzip).then(|| Box::new(Decompress::new(true))),
            zstd,
            lzma_kib: u32::try_from(lzma / 1024).unwrap_or(u32::MAX),
        })
    }

    pub(super) fn compressor(&self) -> Compressor {
        self.compressor
    }

    /// Decodes `packed` into `out`, replacing what was there. More than `max` bytes is
    /// `Corrupt`, found before more than `max` (plus one, for the streaming decoders) is held.
    pub(super) fn decode(&mut self, packed: &[u8], out: &mut Vec<u8>, max: usize) -> Result<()> {
        let name = self.compressor.name();
        out.clear();
        match self.compressor {
            Compressor::Gzip => {
                let inflate = self
                    .inflate
                    .get_or_insert_with(|| Box::new(Decompress::new(true)));
                inflate.reset(true);
                out.resize(max + 1, 0);
                let status = inflate
                    .decompress(packed, out, FlushDecompress::Finish)
                    .map_err(|e| bad(name, e))?;
                let n = usize::try_from(inflate.total_out()).unwrap_or(usize::MAX);
                if n > max {
                    return Err(too_big(max));
                }
                if status != Status::StreamEnd {
                    return Err(bad(name, "the stream ends early"));
                }
                out.truncate(n);
            }
            Compressor::Xz => {
                let r = lzma_rust2::XzReader::new_mem_limit(packed, false, self.lzma_kib);
                read_bounded(r, out, max)
                    .map_err(|e| e.map_or_else(|| too_big(max), |e| bad(name, e)))?;
            }
            Compressor::Lzma => {
                let r = lzma_rust2::LzmaReader::new_mem_limit(packed, self.lzma_kib, None)
                    .map_err(|e| bad(name, e))?;
                read_bounded(r, out, max)
                    .map_err(|e| e.map_or_else(|| too_big(max), |e| bad(name, e)))?;
            }
            Compressor::Lzo => {
                out.resize(max, 0);
                match lzokay::decompress::decompress(packed, out) {
                    Ok(n) => out.truncate(n),
                    Err(lzokay::Error::OutputOverrun) => return Err(too_big(max)),
                    Err(e) => return Err(bad(name, e)),
                }
            }
            Compressor::Lz4 => {
                out.resize(max, 0);
                let n = lz4_flex::block::decompress_into(packed, out).map_err(|e| bad(name, e))?;
                out.truncate(n);
            }
            Compressor::Zstd => {
                out.resize(max, 0);
                let d = match &mut self.zstd {
                    Some(d) => d,
                    None => return Err(bad(name, "no decoder")),
                };
                let n = d
                    .decompress_to_buffer(packed, out.as_mut_slice())
                    .map_err(|e| bad(name, e))?;
                out.truncate(n);
            }
        }
        Ok(())
    }
}

/// Reads `r` to its end into `out`, at most `max` bytes: `Err(None)` if there are more.
fn read_bounded(r: impl Read, out: &mut Vec<u8>, max: usize) -> Result<(), Option<io::Error>> {
    let mut r = r.take(max as u64 + 1);
    r.read_to_end(out).map_err(Some)?;
    if out.len() > max { Err(None) } else { Ok(()) }
}

/// Encodes one block (data, a fragment block or metadata) as `method` at `level`, as mksquashfs
/// would: zlib at the level with a 32 KiB window, xz with a dictionary of the block size and a
/// CRC32 check (the kernel's decoder allows no more than the block size), a raw LZ4 block, LZO1X,
/// a zstd frame.
pub(super) fn encode(
    method: SquashfsMethod,
    level: Option<i32>,
    block_size: u32,
    bytes: &[u8],
) -> io::Result<Vec<u8>> {
    let level = level.and_then(|l| u32::try_from(l).ok());
    Ok(match method {
        SquashfsMethod::Gzip => {
            let level = flate2::Compression::new(level.unwrap_or(9));
            let mut e = flate2::write::ZlibEncoder::new(Vec::with_capacity(bytes.len() / 2), level);
            e.write_all(bytes)?;
            e.finish()?
        }
        SquashfsMethod::Xz => {
            let mut o = lzma_rust2::XzOptions::with_preset(level.unwrap_or(6));
            o.lzma_options.dict_size = block_size.max(4096);
            o.set_check_sum_type(lzma_rust2::CheckType::Crc32);
            let mut w = lzma_rust2::XzWriter::new(Vec::with_capacity(bytes.len() / 2), o)?;
            w.write_all(bytes)?;
            w.finish()?
        }
        // lzokay compresses empty input to a block every decoder rejects (the upstream list):
        // backhand only asks for that when it closes an empty fragment block, which nothing
        // reads, and stores it uncompressed since it's longer than its input. Encode it as
        // nothing either way.
        SquashfsMethod::Lzo if bytes.is_empty() => Vec::new(),
        SquashfsMethod::Lzo => LZO.with(|dict| {
            let mut dict = dict.borrow_mut();
            lzokay::compress::compress_with_dict(bytes, &mut dict)
                .map_err(|e| io::Error::other(format!("lzo: {e}")))
        })?,
        SquashfsMethod::Lz4 => lz4_flex::block::compress(bytes),
        SquashfsMethod::Zstd => {
            let level = level.map_or(15, |l| i32::try_from(l).unwrap_or(15));
            ZSTD.with(|z| -> io::Result<Vec<u8>> {
                let mut z = z.borrow_mut();
                let c = match &mut *z {
                    Some((l, c)) if *l == level => c,
                    slot => &mut slot.insert((level, zstd::bulk::Compressor::new(level)?)).1,
                };
                c.compress(bytes)
            })?
        }
    })
}

thread_local! {
    /// lzokay's match tables (about 600 KiB), kept between blocks.
    static LZO: std::cell::RefCell<Box<lzokay::compress::Dict>> =
        std::cell::RefCell::new(lzokay::compress::Dict::new());
    /// A zstd context and its level, kept between blocks.
    static ZSTD: std::cell::RefCell<Option<(i32, zstd::bulk::Compressor<'static>)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_round_trips_and_is_bounded() {
        let data: Vec<u8> = (0..20_000u32)
            .map(|i| (i % 251) as u8 ^ (i / 97) as u8)
            .collect();
        for (method, comp) in [
            (SquashfsMethod::Gzip, Compressor::Gzip),
            (SquashfsMethod::Xz, Compressor::Xz),
            (SquashfsMethod::Lzo, Compressor::Lzo),
            (SquashfsMethod::Lz4, Compressor::Lz4),
            (SquashfsMethod::Zstd, Compressor::Zstd),
        ] {
            let packed =
                encode(method, method.levels().map(|l| l.default), 131_072, &data).unwrap();
            let mut d = Decoder::new(comp, &Limits::default()).unwrap();
            let mut out = Vec::new();
            d.decode(&packed, &mut out, data.len()).unwrap();
            assert_eq!(out, data, "{method:?}");
            // One byte less room is refused, not truncated.
            let err = d.decode(&packed, &mut out, data.len() - 1).unwrap_err();
            assert_eq!(err.kind, crate::ErrorKind::Corrupt, "{method:?}: {err}");
            // Damage is Corrupt, never a panic.
            let err = d
                .decode(&packed[..packed.len() / 2], &mut out, data.len())
                .unwrap_err();
            assert_eq!(err.kind, crate::ErrorKind::Corrupt, "{method:?}: {err}");
        }
    }

    #[test]
    fn empty_lzo_input_encodes_to_nothing() {
        assert!(
            encode(SquashfsMethod::Lzo, None, 131_072, &[])
                .unwrap()
                .is_empty()
        );
    }
}
