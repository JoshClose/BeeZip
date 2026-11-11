//! Files Windows compressed with WOF (`compact /exe:`, CompactOS, Edge's installer), read through
//! their `WofCompressedData` stream (docs/M8.md §4). The layout was established from
//! Windows-written NTFS, byte for byte, never from GPL code:
//!
//! - **The reparse point** (tag 0x80000017) holds WOF's version (1) and provider (2: the file
//!   provider; 1, WIMBoot, keeps the data in a WIM elsewhere), then the file provider's version
//!   (1) and its algorithm ([`Algorithm`]).
//! - **The stream** is a table of the starts of chunks 1 to n−1 (chunk 0's is left out), relative
//!   to the table's end, 4 bytes each, or 8 when the file is 4 GiB or more; then the chunks. The
//!   last chunk ends at the stream's end. Each chunk decodes alone: XPRESS with its own table,
//!   LZX with a fresh state ([`Lzx::new_wim`]). One that didn't shrink is stored as is, the last
//!   one included.
//! - **The unnamed `$DATA`** is sparse, with the file's size and no clusters.
//!
//! [`WofReader`] reads the table a piece at a time (no allocation the size of the table) and
//! decodes one chunk at a time, so a seek decodes only the chunk it lands in. Every chunk's
//! bounds are checked before it's read: in the stream, after the one before, and no larger than
//! what it decodes to.

use std::io::{self, Read, Seek, SeekFrom};

use crate::{
    Error,
    format::{lzx::Lzx, xpress},
};

/// A WOF file provider's algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Xpress4k,
    Lzx,
    Xpress8k,
    Xpress16k,
}

impl Algorithm {
    /// The file provider's algorithm number.
    pub fn from_id(id: u32) -> Option<Self> {
        Some(match id {
            0 => Self::Xpress4k,
            1 => Self::Lzx,
            2 => Self::Xpress8k,
            3 => Self::Xpress16k,
            _ => return None,
        })
    }

    /// Its chunks' size.
    pub fn chunk(self) -> usize {
        match self {
            Self::Xpress4k => 4096,
            Self::Lzx => 32_768,
            Self::Xpress8k => 8192,
            Self::Xpress16k => 16_384,
        }
    }

    /// Its name, as Info shows it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Xpress4k => "XPRESS4K",
            Self::Lzx => "LZX",
            Self::Xpress8k => "XPRESS8K",
            Self::Xpress16k => "XPRESS16K",
        }
    }
}

/// The width of a chunk table's entries for a file of `size` bytes.
fn entry_size(size: u64) -> u64 {
    if size > u64::from(u32::MAX) { 8 } else { 4 }
}

/// Decodes one chunk at a time.
#[derive(Default)]
struct ChunkDecoder {
    xpress: xpress::Decoder,
    lzx_out: Vec<u8>,
}

impl ChunkDecoder {
    /// `comp` into exactly `out`; a chunk as long as its output is stored.
    fn decode(&mut self, algo: Algorithm, comp: &[u8], out: &mut [u8]) -> Result<(), &'static str> {
        if comp.len() == out.len() {
            out.copy_from_slice(comp);
            return Ok(());
        }
        match algo {
            Algorithm::Lzx => {
                let mut lzx = Lzx::new_wim(15)?;
                self.lzx_out.clear();
                lzx.decode_frame(comp, out.len(), &mut self.lzx_out)?;
                if self.lzx_out.len() != out.len() {
                    return Err("an LZX chunk of the wrong size");
                }
                out.copy_from_slice(&self.lzx_out);
                Ok(())
            }
            _ => self.xpress.decode(comp, out),
        }
    }
}

/// A WOF file's data, decoded from its `WofCompressedData` stream `inner` (see the module's
/// notes). What's damaged is `Corrupt`, naming the file.
pub struct WofReader<R> {
    inner: R,
    path: String,
    algo: Algorithm,
    /// The file's size: its unnamed `$DATA`'s.
    size: u64,
    stream_len: u64,
    chunks: u64,
    entry: u64,
    /// The table's length: where chunk 0 starts.
    table: u64,
    /// The chunk decoded last, and which.
    buf: Vec<u8>,
    held: Option<u64>,
    comp: Vec<u8>,
    pos: u64,
    dec: ChunkDecoder,
}

impl<R: Read + Seek> WofReader<R> {
    /// The file `path` of `size` bytes compressed with `algo` into the stream `inner`.
    pub fn new(mut inner: R, path: &str, algo: Algorithm, size: u64) -> crate::Result<Self> {
        let stream_len = inner
            .seek(SeekFrom::End(0))
            .map_err(|e| crate::io::read_error(&e))?;
        let chunk = algo.chunk() as u64;
        let chunks = size.div_ceil(chunk);
        let entry = entry_size(size);
        let table = chunks.saturating_sub(1).saturating_mul(entry);
        // Every chunk takes at least a byte.
        if table.saturating_add(chunks) > stream_len {
            return Err(Error::corrupt(format!(
                "ntfs: `{path}` is compressed by Windows into {chunks} chunks, which can't fit its \
                 stream of {stream_len} bytes"
            )));
        }
        Ok(Self {
            inner,
            path: path.to_owned(),
            algo,
            size,
            stream_len,
            chunks,
            entry,
            table,
            buf: vec![0; algo.chunk()],
            held: None,
            comp: Vec::with_capacity(algo.chunk()),
            pos: 0,
            dec: ChunkDecoder::default(),
        })
    }

    fn bad(&self, why: String) -> io::Error {
        Error::corrupt(format!(
            "ntfs: `{}`'s data compressed by Windows ({}) is damaged: {why}",
            self.path,
            self.algo.name()
        ))
        .into_io()
    }

    /// Where chunk `i` starts in the stream; chunk `chunks` "starts" at its end.
    fn start(&mut self, i: u64) -> io::Result<u64> {
        if i == 0 {
            return Ok(self.table);
        }
        if i >= self.chunks {
            return Ok(self.stream_len);
        }
        let mut e = [0u8; 8];
        self.inner.seek(SeekFrom::Start((i - 1) * self.entry))?;
        self.inner.read_exact(&mut e[..self.entry as usize])?;
        Ok(self.table.saturating_add(u64::from_le_bytes(e)))
    }

    /// Decodes chunk `i` into `buf`, unless it's there already.
    fn load(&mut self, i: u64) -> io::Result<()> {
        if self.held == Some(i) {
            return Ok(());
        }
        self.held = None;
        let (a, b) = (self.start(i)?, self.start(i + 1)?);
        let chunk = self.algo.chunk() as u64;
        let want = (self.size - i * chunk).min(chunk) as usize;
        if a >= b || b > self.stream_len || b - a > want as u64 {
            return Err(self.bad(format!(
                "chunk {i} lies at {a}..{b} of {} bytes, for {want} bytes",
                self.stream_len
            )));
        }
        self.comp.resize((b - a) as usize, 0);
        self.inner.seek(SeekFrom::Start(a))?;
        self.inner.read_exact(&mut self.comp)?;
        if let Err(e) = self
            .dec
            .decode(self.algo, &self.comp, &mut self.buf[..want])
        {
            return Err(self.bad(format!("chunk {i}: {e}")));
        }
        self.held = Some(i);
        Ok(())
    }
}

impl<R: Read + Seek> Read for WofReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || out.is_empty() {
            return Ok(0);
        }
        let chunk = self.algo.chunk() as u64;
        let i = self.pos / chunk;
        self.load(i)?;
        let within = (self.pos - i * chunk) as usize;
        let have = ((self.size - i * chunk).min(chunk) as usize) - within;
        let n = have.min(out.len());
        out[..n].copy_from_slice(&self.buf[within..within + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for WofReader<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = p.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a seek before the file's start",
            )
        })?;
        Ok(self.pos)
    }
}

/// A stream as WOF writes one: each chunk compressed alone by `compress`, stored when it doesn't
/// shrink, behind the table. For tests and fixtures.
#[cfg(test)]
pub fn build(algo: Algorithm, data: &[u8], compress: &mut dyn FnMut(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let entry = entry_size(data.len() as u64) as usize;
    let mut body = Vec::new();
    let mut starts = Vec::new();
    for c in data.chunks(algo.chunk()) {
        starts.push(body.len() as u64);
        let z = compress(c);
        body.extend_from_slice(if z.len() < c.len() { &z } else { c });
    }
    let mut out = Vec::new();
    for s in starts.iter().skip(1) {
        out.extend_from_slice(&s.to_le_bytes()[..entry]);
    }
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn data() -> Vec<u8> {
        (0..100_000u32)
            .map(|i| (i % 251) as u8 ^ (i / 1000) as u8)
            .collect()
    }

    /// Stored chunks only (what doesn't shrink): the table, the bounds and the seeks.
    #[test]
    fn reads_and_seeks_a_stream_of_stored_chunks() {
        let data = data();
        for algo in [
            Algorithm::Xpress4k,
            Algorithm::Xpress8k,
            Algorithm::Xpress16k,
            Algorithm::Lzx,
        ] {
            let s = build(algo, &data, &mut |c| c.to_vec());
            let mut r = WofReader::new(Cursor::new(s), "f", algo, data.len() as u64).unwrap();
            let mut all = Vec::new();
            r.read_to_end(&mut all).unwrap();
            assert!(all == data, "{algo:?}");
            for at in [0u64, 4095, 4096, 50_000, 99_999] {
                r.seek(SeekFrom::Start(at)).unwrap();
                let mut b = [0u8; 3];
                let n = r.read(&mut b).unwrap();
                assert_eq!(&b[..n], &data[at as usize..at as usize + n]);
            }
        }
    }

    #[test]
    fn damaged_streams_are_corrupt() {
        let data = data();
        let algo = Algorithm::Xpress4k;
        let good = build(algo, &data, &mut |c| c.to_vec());
        let read = |s: Vec<u8>| -> crate::Result<Vec<u8>> {
            let mut r = WofReader::new(Cursor::new(s), "f", algo, data.len() as u64)?;
            let mut v = Vec::new();
            r.read_to_end(&mut v)
                .map_err(|e| crate::io::read_error(&e))?;
            Ok(v)
        };
        // Cut short; a chunk start that goes back; one past the end.
        let mut cut = good.clone();
        cut.truncate(good.len() / 2);
        let mut back = good.clone();
        back[4..8].copy_from_slice(&0u32.to_le_bytes());
        let mut past = good.clone();
        past[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        for (what, s) in [("cut", cut), ("back", back), ("past", past)] {
            let e = read(s).unwrap_err();
            assert_eq!(e.kind, crate::ErrorKind::Corrupt, "{what}: {e}");
        }
        // A chunk that isn't XPRESS at all.
        let mut junk = build(algo, &data, &mut |c| vec![0xFF; c.len() / 2]);
        junk.truncate(junk.len());
        assert_eq!(read(junk).unwrap_err().kind, crate::ErrorKind::Corrupt);
        assert_eq!(read(good).unwrap(), data);
    }

    #[test]
    fn files_of_4_gib_or_more_have_8_byte_entries() {
        assert_eq!(entry_size(u64::from(u32::MAX)), 4);
        assert_eq!(entry_size(1 << 32), 8);
    }
}
