use std::io::{Read, Write};

use bzip2::{Compression, read::MultiBzDecoder, write::BzEncoder};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
};

pub struct Bzip2;

/// After the 4-byte header comes the first block's magic (BCD π) or, for empty input, the
/// end-of-stream magic (BCD √π).
const BLOCK_MAGIC: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
const EOS_MAGIC: [u8; 6] = [0x17, 0x72, 0x45, 0x38, 0x50, 0x90];

impl Codec for Bzip2 {
    fn id(&self) -> CodecId {
        CodecId::Bzip2
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".bz2", ".tbz", ".tbz2"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let head = probe.head;
        if head.len() < 4 || &head[..3] != b"BZh" || !(b'1'..=b'9').contains(&head[3]) {
            return None;
        }
        match head.get(4..10) {
            Some(m) if m == BLOCK_MAGIC || m == EOS_MAGIC => Some(Confidence::Certain),
            _ => Some(Confidence::Likely),
        }
    }

    fn levels(&self) -> Option<Levels> {
        Some(Levels {
            min: 1,
            max: 9,
            default: 9,
        })
    }

    fn decoder<'a>(
        &self,
        r: Box<dyn Read + Send + 'a>,
        _: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        Ok(Box::new(MultiBzDecoder::new(r)))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        let enc = BzEncoder::new(w, Compression::new(level.unsigned_abs()));
        Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
    }
}
