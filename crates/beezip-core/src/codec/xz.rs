use std::io::{Read, Write};

use lzma_rust2::{XzOptions, XzReader, XzWriter, XzWriterMt};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher, fit_dict, mt_block_size};
use crate::{
    Error, Limits, Result,
    detect::{Confidence, Probe},
};

pub struct Xz;

const MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

impl Codec for Xz {
    fn id(&self) -> CodecId {
        CodecId::Xz
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".xz", ".txz"]
    }

    /// The magic, then the stream flags and their CRC32.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let head = probe.head;
        if !head.starts_with(&MAGIC) {
            return None;
        }
        match (head.get(6..8), head.get(8..12)) {
            (Some(flags), Some(crc)) if crc32fast::hash(flags).to_le_bytes() == crc => {
                Some(Confidence::Certain)
            }
            _ => Some(Confidence::Likely),
        }
    }

    fn levels(&self) -> Option<Levels> {
        Some(Levels {
            min: 0,
            max: 9,
            default: 6,
        })
    }

    fn threads(&self) -> bool {
        true
    }

    /// Single-threaded: lzma-rust2 0.23's `XzReaderMt` takes no memory limit (docs/M1.md §11).
    fn decoder<'a>(&self, r: Box<dyn Read + 'a>, limits: &Limits) -> Result<Box<dyn Read + 'a>> {
        Ok(Box::new(XzReader::new_mem_limit(
            r,
            true,
            limits.decoder_memory_kib(),
        )))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        let mut options = XzOptions::with_preset(level.unsigned_abs());
        let dict = fit_dict(options.lzma_options.dict_size, opts.size_hint);
        options.lzma_options.dict_size = dict;
        let threads = opts.resolve_threads();
        let err = |e: std::io::Error| Error::invalid_args(format!("xz encoder: {e}"));
        if threads > 1 {
            options.set_block_size(mt_block_size(opts, dict));
            let enc = XzWriterMt::new(w, options, threads).map_err(err)?;
            Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
        } else {
            let enc = XzWriter::new(w, options).map_err(err)?;
            Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
        }
    }
}
