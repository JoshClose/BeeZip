use std::io::{Read, Write};

use zstd::stream::{read::Decoder, write::Encoder};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher};
use crate::{
    Error, Limits, Result,
    detect::{Confidence, Probe},
};

pub struct Zstd;

pub const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Skippable frames (`0x184D2A5?` little-endian), which zstd and LZ4 share.
pub fn skippable(head: &[u8]) -> bool {
    matches!(head, [b, 0x2A, 0x4D, 0x18, ..] if b & 0xF0 == 0x50)
}

/// The head after any leading skippable frames, or `None` if it runs out first.
pub fn skip_skippable(mut head: &[u8]) -> Option<&[u8]> {
    for _ in 0..16 {
        if !skippable(head) {
            return Some(head);
        }
        let size = u32::from_le_bytes(head.get(4..8)?.try_into().ok()?);
        head = head.get(8 + usize::try_from(size).ok()?..)?;
    }
    None
}

impl Codec for Zstd {
    fn id(&self) -> CodecId {
        CodecId::Zstd
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".zst", ".tzst", ".zstd"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let starts_skippable = skippable(probe.head);
        let Some(head) = skip_skippable(probe.head) else {
            // A skippable frame longer than the head: say so only if nothing else would claim it.
            return starts_skippable.then_some(Confidence::Guess);
        };
        if !head.starts_with(&MAGIC) {
            return None;
        }
        // Frame header descriptor: bit 3 is reserved and must be zero.
        match head.get(4) {
            Some(fhd) if fhd & 0x08 == 0 => Some(Confidence::Certain),
            _ => Some(Confidence::Likely),
        }
    }

    fn levels(&self) -> Option<Levels> {
        Some(Levels {
            min: 1,
            max: 22,
            default: 3,
        })
    }

    fn threads(&self) -> bool {
        true
    }

    /// Windows larger than `decoder_memory` allows (at most 2³⁰) are refused.
    fn decoder<'a>(&self, r: Box<dyn Read + 'a>, limits: &Limits) -> Result<Box<dyn Read + 'a>> {
        let mut dec = Decoder::new(r).map_err(|e| Error::from_io(&e))?;
        dec.window_log_max(limits.zstd_window_log_max())
            .map_err(|e| Error::from_io(&e))?;
        Ok(Box::new(WindowLimit(dec)))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        let err = |e: std::io::Error| Error::invalid_args(format!("zstd encoder: {e}"));
        let mut enc = Encoder::new(w, level).map_err(err)?;
        enc.include_checksum(true).map_err(err)?;
        let threads = opts.resolve_threads();
        if threads > 1 {
            enc.multithread(threads).map_err(err)?;
        }
        if opts.size_exact {
            enc.set_pledged_src_size(opts.size_hint).map_err(err)?;
        }
        Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
    }
}

/// Turns zstd's "window too large" into `LimitExceeded`; zstd reports it like any other
/// decoding error.
struct WindowLimit<R>(R);

impl<R: Read> Read for WindowLimit<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf).map_err(|e| {
            if e.to_string().contains("too much memory") {
                Error::limit(format!(
                    "zstd frame needs a larger window than `decoder_memory` allows ({e})"
                ))
                .into_io()
            } else {
                e
            }
        })
    }
}
