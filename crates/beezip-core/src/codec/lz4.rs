use std::io::{self, Read, Write};

use lz4_flex::frame::{FrameDecoder, FrameEncoder, FrameInfo};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher, zstd::skip_skippable};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
    io::{Counter, CountingReader},
};

/// The LZ4 frame format (`lz4` CLI). It has no levels.
pub struct Lz4;

const MAGIC: [u8; 4] = [0x04, 0x22, 0x4D, 0x18];
const LEGACY_MAGIC: [u8; 4] = [0x02, 0x21, 0x4C, 0x18];

impl Codec for Lz4 {
    fn id(&self) -> CodecId {
        CodecId::Lz4
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".lz4"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let head = skip_skippable(probe.head)?;
        if head.starts_with(&LEGACY_MAGIC) {
            return Some(Confidence::Likely);
        }
        if !head.starts_with(&MAGIC) {
            return None;
        }
        // FLG: version 01 and reserved bit 1 clear; BD: reserved bits clear.
        match (head.get(4), head.get(5)) {
            (Some(flg), Some(bd)) if flg >> 6 == 1 && flg & 0x02 == 0 && bd & 0x8F == 0 => {
                Some(Confidence::Certain)
            }
            _ => Some(Confidence::Likely),
        }
    }

    fn levels(&self) -> Option<Levels> {
        None
    }

    fn decoder<'a>(
        &self,
        r: Box<dyn Read + Send + 'a>,
        _: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        let counter = Counter::new();
        Ok(Box::new(Frames {
            dec: FrameDecoder::new(CountingReader::new(r, counter.clone())),
            counter,
            done: false,
        }))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        opts.resolve_level(self.id(), self.levels())?;
        let info = FrameInfo::new().content_checksum(true);
        let enc = FrameEncoder::with_frame_info(info, w);
        Ok(finisher(enc, |e| {
            e.finish()
                .map_err(io::Error::other)
                .and_then(|mut w| w.flush())
        }))
    }
}

/// Decodes concatenated frames, as the `lz4` CLI does. `FrameDecoder` returns `Ok(0)` at the
/// end of each frame and only starts the next on the following call; a call that returns
/// nothing *and* consumes no input is the real end.
struct Frames<'a> {
    dec: FrameDecoder<CountingReader<Box<dyn Read + Send + 'a>>>,
    counter: Counter,
    done: bool,
}

impl Read for Frames<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            let before = self.counter.get();
            let n = self.dec.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            if self.counter.get() == before {
                self.done = true;
                return Ok(0);
            }
        }
    }
}
