use std::io::{Read, Write};

use brotli::{
    BrotliDecompressStream, BrotliResult, BrotliState, CompressorWriter, Decompressor, HeapAlloc,
    HuffmanCode,
};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher, has_ext};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
    io::LatchWriter,
};

pub struct Brotli;

/// Window log for new streams: 4 MiB, the CLI's default.
const LGWIN: u32 = 22;
const BUF: usize = 64 * 1024;

impl Codec for Brotli {
    fn id(&self) -> CodecId {
        CodecId::Brotli
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".br"]
    }

    /// Brotli has no magic: the extension, confirmed by decoding the head without an error.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        (has_ext(probe, self.extensions())
            && trial_decode(probe.head, probe.len == Some(probe.head.len() as u64)))
        .then_some(Confidence::Likely)
    }

    fn levels(&self) -> Option<Levels> {
        // The CLI defaults to 11, which runs at about 1 MB/s.
        Some(Levels {
            min: 0,
            max: 11,
            default: 9,
        })
    }

    fn decoder<'a>(&self, r: Box<dyn Read + 'a>, _: &Limits) -> Result<Box<dyn Read + 'a>> {
        Ok(Box::new(Decompressor::new(r, BUF)))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        // `into_inner` finishes the stream but swallows write errors, so the latch keeps them.
        let enc = CompressorWriter::new(LatchWriter::new(w), BUF, level.unsigned_abs(), LGWIN);
        Ok(finisher(enc, |e| {
            let (mut w, err) = e.into_inner().into_parts();
            match err {
                Some(err) => Err(err),
                None => w.flush(),
            }
        }))
    }
}

/// Decodes `head` (up to 1 MiB of output) and says whether it is plausibly brotli: no error
/// before the input runs out, and when `head` is the whole file (`complete`), a stream that
/// ends exactly at its end.
fn trial_decode(head: &[u8], complete: bool) -> bool {
    if head.is_empty() {
        return false;
    }
    let mut state = BrotliState::new(
        HeapAlloc::<u8>::new(0),
        HeapAlloc::<u32>::new(0),
        HeapAlloc::<HuffmanCode>::new(HuffmanCode::default()),
    );
    let mut out = vec![0u8; BUF];
    let (mut avail_in, mut in_off) = (head.len(), 0usize);
    let mut total = 0usize;
    for _ in 0..16 {
        let (mut avail_out, mut out_off) = (out.len(), 0usize);
        match BrotliDecompressStream(
            &mut avail_in,
            &mut in_off,
            head,
            &mut avail_out,
            &mut out_off,
            &mut out,
            &mut total,
            &mut state,
        ) {
            BrotliResult::ResultFailure => return false,
            // A whole file must end exactly where the stream does.
            BrotliResult::ResultSuccess => return !complete || in_off == head.len(),
            BrotliResult::NeedsMoreInput => return !complete,
            BrotliResult::NeedsMoreOutput => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trial_decode_tells_brotli_from_noise() {
        let mut out = Vec::new();
        let mut enc = Brotli
            .encoder(Box::new(&mut out), &EncodeOpts::default())
            .unwrap();
        enc.write_all(b"hello hello hello").unwrap();
        enc.finish().unwrap();
        assert!(trial_decode(&out, true));
        let cut = &out[..out.len() - 1];
        assert!(trial_decode(cut, false));
        assert!(!trial_decode(cut, true));
        let noise = b"PK\x03\x04 this is not brotli at all, not one bit";
        assert!(!trial_decode(noise, true));
    }
}
