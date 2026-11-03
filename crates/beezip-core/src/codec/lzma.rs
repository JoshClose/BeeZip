use std::io::{Read, Write};

use lzma_rust2::{LzmaOptions, LzmaReader, LzmaWriter};

use super::{
    Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher, fit_dict, has_ext, open_error,
};
use crate::{
    Error, Limits, Result,
    detect::{Confidence, Probe},
};

/// LZMA-alone (`.lzma`), as written by `xz --format=lzma` and LZMA SDK tools.
pub struct Lzma;

impl Codec for Lzma {
    fn id(&self) -> CodecId {
        CodecId::Lzma
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".lzma"]
    }

    /// No magic: a 13-byte header of properties, dictionary size and uncompressed size. It is
    /// only plausible, never proof, so it counts together with the extension.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        (header_plausible(probe.head) && has_ext(probe, self.extensions()))
            .then_some(Confidence::Likely)
    }

    fn levels(&self) -> Option<Levels> {
        Some(Levels {
            min: 0,
            max: 9,
            default: 6,
        })
    }

    /// The header's dictionary size is checked against `decoder_memory` before decoding.
    fn decoder<'a>(&self, r: Box<dyn Read + 'a>, limits: &Limits) -> Result<Box<dyn Read + 'a>> {
        let reader = LzmaReader::new_mem_limit(r, limits.decoder_memory_kib(), None)
            .map_err(|e| open_error(self.id(), &e))?;
        Ok(Box::new(reader))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        let mut options = LzmaOptions::with_preset(level.unsigned_abs());
        options.dict_size = fit_dict(options.dict_size, opts.size_hint);
        // Unknown size in the header, so the stream ends with an end marker.
        let enc = LzmaWriter::new_use_header(w, &options, None)
            .map_err(|e| Error::invalid_args(format!("lzma encoder: {e}")))?;
        Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
    }
}

/// Properties byte below 9·5·5, a dictionary size of the form 2ⁿ or 3·2ⁿ, and an uncompressed
/// size that is either unknown (all ones) or below 2⁵⁶.
pub fn header_plausible(head: &[u8]) -> bool {
    let Some(h) = head.get(..13) else {
        return false;
    };
    let props = h[0];
    let dict = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
    let size = u64::from_le_bytes([h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12]]);
    let dict_ok = dict >= 4096 && {
        let low = dict >> dict.trailing_zeros();
        low == 1 || low == 3
    };
    props < 225 && dict_ok && (size == u64::MAX || size < 1 << 56)
}
