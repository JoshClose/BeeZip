use std::io::{Read, Write};

use flate2::{Compression, GzBuilder, read::MultiGzDecoder};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
    time::to_unix,
};

pub struct Gzip;

impl Codec for Gzip {
    fn id(&self) -> CodecId {
        CodecId::Gzip
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".gz", ".tgz"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        match probe.head {
            // ID1 ID2 CM=deflate, then FLG with the reserved bits clear.
            [0x1F, 0x8B, 0x08, flg, ..] if flg & 0xE0 == 0 => Some(Confidence::Certain),
            [0x1F, 0x8B, 0x08, ..] => Some(Confidence::Likely),
            _ => None,
        }
    }

    fn levels(&self) -> Option<Levels> {
        Some(Levels {
            min: 0,
            max: 9,
            default: 6,
        })
    }

    fn decoder<'a>(&self, r: Box<dyn Read + 'a>, _: &Limits) -> Result<Box<dyn Read + 'a>> {
        // Multi-member: `cat a.gz b.gz` decodes to both.
        Ok(Box::new(MultiGzDecoder::new(r)))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?;
        let mut builder = GzBuilder::new();
        if let Some(name) = &opts.gzip_name {
            // FNAME is ISO 8859-1 and NUL-terminated; names outside Latin-1 are left out.
            if let Some(latin1) = latin1(name) {
                builder = builder.filename(latin1);
            }
        }
        if let Some(t) = opts.gzip_mtime {
            builder = builder.mtime(u32::try_from(to_unix(t)).unwrap_or(0));
        }
        let enc = builder.write(w, Compression::new(level.unsigned_abs()));
        Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
    }
}

fn latin1(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .map(|c| u8::try_from(u32::from(c)).ok().filter(|&b| b != 0))
        .collect()
}

/// The FNAME field of a gzip header, if the head has one.
pub fn header_name(head: &[u8]) -> Option<String> {
    const FEXTRA: u8 = 4;
    const FNAME: u8 = 8;
    let [0x1F, 0x8B, 0x08, flg, ..] = *head else {
        return None;
    };
    if flg & FNAME == 0 {
        return None;
    }
    let mut at = 10;
    if flg & FEXTRA != 0 {
        let xlen = usize::from(u16::from_le_bytes([*head.get(10)?, *head.get(11)?]));
        at = 12 + xlen;
    }
    let rest = head.get(at..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    // ISO 8859-1: each byte is its own code point.
    let name: String = rest[..end].iter().map(|&b| char::from(b)).collect();
    (!name.is_empty()).then_some(name)
}

/// The ISIZE trailer: the uncompressed size mod 2³², so only a hint.
pub fn trailer_size(tail: &[u8]) -> Option<u32> {
    let n = tail.len();
    (n >= 4).then(|| u32::from_le_bytes([tail[n - 4], tail[n - 3], tail[n - 2], tail[n - 1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_header_name() {
        let mut out = Vec::new();
        let opts = EncodeOpts {
            gzip_name: Some("notes é.txt".into()),
            ..EncodeOpts::default()
        };
        let mut enc = Gzip.encoder(Box::new(&mut out), &opts).unwrap();
        enc.write_all(b"hello").unwrap();
        enc.finish().unwrap();
        assert_eq!(header_name(&out).as_deref(), Some("notes é.txt"));
        assert_eq!(trailer_size(&out), Some(5));
    }
}
