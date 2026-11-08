//! pbzx (docs/M6.md §5): Apple's chunked xz, the payload of newer macOS packages.
//!
//! `pbzx`, a big-endian u64 (the chunk size, 16 MiB; old readers loop while its bit 24 is set),
//! then chunks to the end of the stream: a u64 decoded size, a u64 stored length, and that many
//! bytes, which are the chunk itself when the two are equal, else one xz stream that must
//! decode to exactly the decoded size, followed by nothing but stream padding. Each chunk's
//! sizes are at most [`MAX_CHUNK`]; the xz decoding is lzma-rust2's, as BeeZip's xz codec's,
//! within the job's decoder memory.

use std::io::{self, Read};

use lzma_rust2::XzReader;

use crate::Error;

pub(crate) const MAGIC: &[u8; 4] = b"pbzx";
/// The largest chunk accepted, decoded or stored (Apple's are 16 MiB).
pub(crate) const MAX_CHUNK: u64 = 64 << 20;

fn bad(msg: impl Into<String>) -> io::Error {
    Error::corrupt(format!("pbzx: {}", msg.into())).into_io()
}

/// A pbzx stream, decoded.
pub(crate) struct Pbzx<R: Read> {
    /// The stream between chunks.
    r: Option<R>,
    cur: Option<Chunk<R>>,
    mem_kib: u32,
}

enum Chunk<R: Read> {
    Stored(io::Take<R>),
    Xz {
        dec: Box<XzReader<io::Take<R>>>,
        left: u64,
    },
}

impl<R: Read> Pbzx<R> {
    /// Reads the header. `mem_kib` bounds each xz stream's dictionary.
    pub(crate) fn new(mut r: R, mem_kib: u32) -> io::Result<Self> {
        let mut h = [0u8; 12];
        r.read_exact(&mut h)
            .map_err(|_| bad("the header is cut short"))?;
        if h[..4] != *MAGIC {
            return Err(bad("no pbzx header"));
        }
        Ok(Self {
            r: Some(r),
            cur: None,
            mem_kib,
        })
    }

    /// The next chunk, or `None` at the end of the stream.
    fn next_chunk(&self, mut r: R) -> io::Result<Option<Chunk<R>>> {
        let mut h = [0u8; 16];
        let mut got = 0;
        while got < h.len() {
            match r.read(&mut h[got..]) {
                Ok(0) if got == 0 => return Ok(None),
                Ok(0) => return Err(bad("a chunk's header is cut short")),
                Ok(k) => got += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let mut be = [0u8; 8];
        be.copy_from_slice(&h[..8]);
        let size = u64::from_be_bytes(be);
        be.copy_from_slice(&h[8..]);
        let len = u64::from_be_bytes(be);
        if size > MAX_CHUNK || len > MAX_CHUNK {
            return Err(bad(format!(
                "a chunk of {size} bytes ({len} stored), where BeeZip reads at most {} MiB",
                MAX_CHUNK >> 20
            )));
        }
        Ok(Some(if size == len {
            Chunk::Stored(r.take(len))
        } else {
            Chunk::Xz {
                dec: Box::new(XzReader::new_mem_limit(r.take(len), false, self.mem_kib)),
                left: size,
            }
        }))
    }

    /// Ends a chunk: an xz chunk must have decoded to its size, and only zeros (stream padding)
    /// may follow its stream.
    fn end_chunk(c: Chunk<R>) -> io::Result<R> {
        let mut t = match c {
            Chunk::Stored(t) => t,
            Chunk::Xz { left, .. } if left != 0 => {
                return Err(bad("a chunk decodes to less than its size"));
            }
            Chunk::Xz { dec, .. } => dec.into_inner(),
        };
        let mut buf = [0u8; 8192];
        loop {
            match t.read(&mut buf) {
                Ok(0) => break,
                Ok(n) if buf[..n].iter().all(|&b| b == 0) => {}
                Ok(_) => return Err(bad("data after a chunk's xz stream")),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if t.limit() != 0 {
            return Err(bad("a chunk is cut short"));
        }
        Ok(t.into_inner())
    }
}

impl<R: Read> Read for Pbzx<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(c) = &mut self.cur {
                let k = match c {
                    Chunk::Stored(t) => {
                        let k = t.read(buf)?;
                        if k == 0 && t.limit() != 0 {
                            return Err(bad("a chunk is cut short"));
                        }
                        k
                    }
                    Chunk::Xz { dec, left } => {
                        let room = usize::try_from(*left + 1)
                            .unwrap_or(usize::MAX)
                            .min(buf.len());
                        let k = dec.read(&mut buf[..room])?;
                        if k as u64 > *left {
                            return Err(bad("a chunk decodes to more than its size"));
                        }
                        *left -= k as u64;
                        k
                    }
                };
                if k > 0 {
                    return Ok(k);
                }
                if let Some(c) = self.cur.take() {
                    self.r = Some(Self::end_chunk(c)?);
                }
            }
            let Some(r) = self.r.take() else {
                return Ok(0);
            };
            match self.next_chunk(r)? {
                Some(c) => self.cur = Some(c),
                None => return Ok(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn xz(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w =
            lzma_rust2::XzWriter::new(&mut out, lzma_rust2::XzOptions::with_preset(6)).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap();
        out
    }

    /// A pbzx of `chunks`, each stored or xz'd.
    pub(crate) fn pbzx(chunks: &[(&[u8], bool)]) -> Vec<u8> {
        let mut out = b"pbzx".to_vec();
        out.extend_from_slice(&(1u64 << 24).to_be_bytes());
        for (data, packed) in chunks {
            let body = if *packed { xz(data) } else { data.to_vec() };
            out.extend_from_slice(&(data.len() as u64).to_be_bytes());
            out.extend_from_slice(&(body.len() as u64).to_be_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    fn decode(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Pbzx::new(bytes, 1 << 20)?.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn stored_and_xz_chunks_decode() {
        let a = vec![b'a'; 5000];
        let b: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        let bytes = pbzx(&[(&a, true), (b"plain", false), (&b, true)]);
        let mut want = a.clone();
        want.extend_from_slice(b"plain");
        want.extend_from_slice(&b);
        assert_eq!(decode(&bytes).unwrap(), want);
        assert_eq!(decode(&pbzx(&[])).unwrap(), b"");
    }

    #[test]
    fn damage_is_corrupt() {
        let a = vec![b'a'; 5000];
        let good = pbzx(&[(&a, true)]);
        // Cut anywhere: header, chunk header, stream.
        for cut in [3, 13, 20, good.len() - 1] {
            assert!(decode(&good[..cut]).is_err(), "cut at {cut}");
        }
        // A size that doesn't match what the stream decodes to.
        let mut short = good.clone();
        short[19] = 0x10;
        assert!(decode(&short).is_err());
        // A chunk claiming more than 64 MiB.
        let mut huge = good.clone();
        huge[12..20].copy_from_slice(&(1u64 << 40).to_be_bytes());
        let e = decode(&huge).unwrap_err();
        assert!(e.to_string().contains("at most"), "{e}");
        // Junk after the stream inside the chunk.
        let mut junk = pbzx(&[(&a, true)]);
        let len = u64::from_be_bytes(junk[20..28].try_into().unwrap()) + 4;
        junk[20..28].copy_from_slice(&len.to_be_bytes());
        junk.extend_from_slice(b"junk");
        assert!(decode(&junk).is_err());
        // Zeros after it are stream padding.
        let mut pad = pbzx(&[(&a, true)]);
        pad[20..28].copy_from_slice(&(len).to_be_bytes());
        pad.extend_from_slice(&[0; 4]);
        assert_eq!(decode(&pad).unwrap(), a);
    }
}
