use std::io::{Read, Write};

use snap::{read::FrameDecoder, write::FrameEncoder};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
};

/// The Snappy framing format. It has no levels.
pub struct Snappy;

/// The stream identifier chunk: type 0xFF, length 6, "sNaPpY".
const MAGIC: [u8; 10] = [0xFF, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y'];

impl Codec for Snappy {
    fn id(&self) -> CodecId {
        CodecId::Snappy
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".sz"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        probe
            .head
            .starts_with(&MAGIC)
            .then_some(Confidence::Certain)
    }

    fn levels(&self) -> Option<Levels> {
        None
    }

    fn decoder<'a>(&self, r: Box<dyn Read + 'a>, _: &Limits) -> Result<Box<dyn Read + 'a>> {
        Ok(Box::new(FrameDecoder::new(r)))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        opts.resolve_level(self.id(), self.levels())?;
        let enc = FrameEncoder::new(w);
        Ok(finisher(enc, |e| {
            e.into_inner()
                .map_err(snap::write::IntoInnerError::into_error)
                .and_then(|mut w| w.flush())
        }))
    }
}
