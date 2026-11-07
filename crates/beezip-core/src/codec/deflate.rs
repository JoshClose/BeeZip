use std::io::{Read, Write};

use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, deflate_par::ParDeflate, finisher};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
};

/// Raw deflate has no magic and no extension, so it is never detected; `--codec deflate` only.
pub struct Deflate;

impl Codec for Deflate {
    fn id(&self) -> CodecId {
        CodecId::Deflate
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    fn sniff(&self, _: &Probe<'_>) -> Option<Confidence> {
        None
    }

    fn levels(&self) -> Option<Levels> {
        Some(Levels {
            min: 0,
            max: 9,
            default: 6,
        })
    }

    fn decoder<'a>(
        &self,
        r: Box<dyn Read + Send + 'a>,
        _: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        Ok(Box::new(DeflateDecoder::new(r)))
    }

    fn threads(&self) -> bool {
        true
    }

    /// One thread is flate2's encoder; more is [`ParDeflate`], as for gzip.
    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?.unsigned_abs();
        let threads = opts.resolve_threads();
        if threads > 1 {
            let enc = ParDeflate::new(w, level, threads);
            return Ok(finisher(enc, |e| {
                e.finish().and_then(|(mut w, _)| w.flush())
            }));
        }
        let enc = DeflateEncoder::new(w, Compression::new(level));
        Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
    }
}
