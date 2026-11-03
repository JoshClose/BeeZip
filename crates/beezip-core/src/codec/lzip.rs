use std::io::{Cursor, Read, Write};

use lzma_rust2::{LzipOptions, LzipReader, LzipWriter, LzipWriterMt};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher, fit_dict, mt_block_size};
use crate::{
    Error, Limits, Result,
    detect::{Confidence, Probe},
    io::read_prefix,
};

pub struct Lzip;

impl Codec for Lzip {
    fn id(&self) -> CodecId {
        CodecId::Lzip
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".lz", ".tlz"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        if !probe.head.starts_with(b"LZIP") {
            return None;
        }
        match probe.head.get(4..6) {
            Some(&[1, coded]) if dict_size(coded).is_some() => Some(Confidence::Certain),
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

    /// lzma-rust2's `LzipReader` takes no memory limit, so the first member's dictionary size
    /// is checked here. Lzip caps dictionaries at 512 MiB.
    fn decoder<'a>(
        &self,
        mut r: Box<dyn Read + 'a>,
        limits: &Limits,
    ) -> Result<Box<dyn Read + 'a>> {
        let header = read_prefix(&mut r, 6);
        if let Some(&[b'L', b'Z', b'I', b'P', _, coded]) = header.get(..6)
            && let Some(dict) = dict_size(coded)
            && u64::from(dict) > limits.decoder_memory
        {
            return Err(Error::limit(format!(
                "lzip stream needs a {} MiB dictionary (limit `decoder_memory`)",
                dict >> 20
            )));
        }
        Ok(Box::new(LzipReader::new(Cursor::new(header).chain(r))))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        let mut options = LzipOptions::with_preset(level.unsigned_abs());
        let dict = fit_dict(options.lzma_options.dict_size, opts.size_hint);
        options.lzma_options.dict_size = dict;
        let threads = opts.resolve_threads();
        if threads > 1 {
            options.set_member_size(mt_block_size(opts, dict));
            let enc = LzipWriterMt::new(w, options, threads)
                .map_err(|e| Error::invalid_args(format!("lzip encoder: {e}")))?;
            Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
        } else {
            let enc = LzipWriter::new(w, options);
            Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
        }
    }
}

/// The dictionary size coded in byte 5 of an lzip header, if it is in lzip's 4 KiB–512 MiB.
fn dict_size(coded: u8) -> Option<u32> {
    let base = 1u32.checked_shl(u32::from(coded & 0x1F))?;
    let size = base - (base / 16) * u32::from(coded >> 5);
    (4096..=1 << 29).contains(&size).then_some(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_dictionary_sizes() {
        assert_eq!(dict_size(12), Some(4096));
        assert_eq!(dict_size(23), Some(8 << 20));
        assert_eq!(dict_size(0x20 | 24), Some((16 << 20) - (1 << 20)));
        assert_eq!(dict_size(30), None);
        assert_eq!(dict_size(11), None);
    }
}
