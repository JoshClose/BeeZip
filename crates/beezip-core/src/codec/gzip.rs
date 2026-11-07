use std::io::{Read, Write};

use flate2::{Compression, GzBuilder, read::MultiGzDecoder};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, deflate_par::ParDeflate, finisher};
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

    fn decoder<'a>(
        &self,
        r: Box<dyn Read + Send + 'a>,
        _: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        // Multi-member: `cat a.gz b.gz` decodes to both.
        Ok(Box::new(MultiGzDecoder::new(r)))
    }

    fn threads(&self) -> bool {
        true
    }

    /// One thread is flate2's encoder; more is [`ParDeflate`], whose bytes differ from it but
    /// not between thread counts.
    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        let level = opts.resolve_level(self.id(), self.levels())?.unsigned_abs();
        // FNAME is ISO 8859-1 and NUL-terminated; names outside Latin-1 are left out.
        let name = opts.gzip_name.as_deref().and_then(latin1);
        let mtime = opts
            .gzip_mtime
            .map_or(0, |t| u32::try_from(to_unix(t)).unwrap_or(0));
        let threads = opts.resolve_threads();
        if threads > 1 {
            let head = header(name.as_deref(), mtime, level);
            let enc = ParDeflate::gzip(w, level, threads, head);
            return Ok(finisher(enc, |e| {
                e.finish_gzip().and_then(|mut w| w.flush())
            }));
        }
        let mut builder = GzBuilder::new().mtime(mtime);
        if let Some(name) = name {
            builder = builder.filename(name);
        }
        let enc = builder.write(w, Compression::new(level));
        Ok(finisher(enc, |e| e.finish().and_then(|mut w| w.flush())))
    }
}

fn latin1(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .map(|c| u8::try_from(u32::from(c)).ok().filter(|&b| b != 0))
        .collect()
}

/// The header flate2's `GzBuilder` writes: FNAME if there's a name, MTIME, XFL from the level
/// as flate2 sets it, and OS 255 (unknown).
fn header(name: Option<&[u8]>, mtime: u32, level: u32) -> Vec<u8> {
    const FNAME: u8 = 8;
    let xfl = match level {
        9 => 2,
        0 | 1 => 4,
        _ => 0,
    };
    let mut h = vec![0x1F, 0x8B, 0x08, 0];
    h.extend_from_slice(&mtime.to_le_bytes());
    h.extend_from_slice(&[xfl, 255]);
    if let Some(name) = name {
        h[3] = FNAME;
        h.extend_from_slice(name);
        h.push(0);
    }
    h
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
