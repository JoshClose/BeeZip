use std::io::{Read, Write};

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher, has_ext};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
};

pub struct Zlib;

impl Codec for Zlib {
    fn id(&self) -> CodecId {
        CodecId::Zlib
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".zz", ".zlib"]
    }

    /// Two header bytes are too weak alone (1 in 31 random pairs pass the check), so a valid
    /// header only counts together with a zlib extension.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let [cmf, flg, ..] = *probe.head else {
            return None;
        };
        let check = (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0;
        let valid = cmf & 0x0F == 8 && cmf >> 4 <= 7 && check;
        (valid && has_ext(probe, self.extensions())).then_some(Confidence::Likely)
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
        Ok(Box::new(ZlibDecoder::new(r)))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        let enc = ZlibEncoder::new(w, Compression::new(level.unsigned_abs()));
        Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
    }
}
