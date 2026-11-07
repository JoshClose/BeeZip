//! lzop (`.lzo`, docs/M5.md §5.8): BeeZip's own container, with LZO1X blocks from `lzokay`
//! (2.0.1, pure Rust). Written from libarchive's lzop filters (BSD-2) and files real lzop wrote.
//! All integers are big-endian.
//!
//! ```text
//! header  magic 89 4C 5A 4F 00 0D 0A 1A 0A
//!         version u16, lib_version u16, [version_needed u16]      [..] when version >= 0x0940
//!         method u8 (1 LZO1X-1, 2 LZO1X-1(15), 3 LZO1X-999), [level u8]
//!         flags u32, [filter u32 if F_H_FILTER], mode u32, mtime_low u32, [mtime_high u32]
//!         name_len u8, name, checksum u32 (Adler-32, or CRC-32 with F_H_CRC32, of version..name)
//!         [extra field if F_H_EXTRA_FIELD: len u32, data, checksum u32]
//! block   dst_len u32 (0 ends the member), src_len u32 (<= dst_len; equal means stored)
//!         [adler32(dst) if F_ADLER32_D] [crc32(dst) if F_CRC32_D]
//!         [adler32(src) if F_ADLER32_C] [crc32(src) if F_CRC32_C]   only when src_len < dst_len
//!         data
//! ```
//!
//! - **Reading:** members may be concatenated; data after the last one that isn't another
//!   member is ignored, as libarchive ignores it. Every checksum is checked. A block is at most
//!   64 MiB (libarchive's limit; lzop writes 256 KiB), and at most `decoder_memory`.
//! - **Writing:** lzop 1.04's layout in 256 KiB blocks with Adler-32s of both sides. lzokay's
//!   output is LZO1X-999's kind, so the header says method 3, level 9. A block that doesn't
//!   shrink is stored.
//! - **Threads:** lzokay compresses at about 10 MB/s, as LZO1X-999 does, so blocks are
//!   compressed side by side, two per worker at a time, and written in order (docs/M6.md §7).
//!   Each block stands alone, so the bytes are the same at any thread count.
//! - **lzokay's empty block:** lzokay compresses empty input to 4 bytes that every decoder
//!   rejects, so BeeZip writes no block for empty input (docs/M5.md §5.8; the upstream list).

use std::io::{self, Read, Write};

use super::{Codec, CodecId, EncodeOpts, FinishWrite, Levels, finisher};
use crate::{
    Limits, Result,
    detect::{Confidence, Probe},
    time::to_unix,
};

pub struct Lzop;

pub const MAGIC: [u8; 9] = [0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A];
const F_ADLER32_D: u32 = 0x0001;
const F_ADLER32_C: u32 = 0x0002;
const F_H_EXTRA_FIELD: u32 = 0x0040;
const F_CRC32_D: u32 = 0x0100;
const F_CRC32_C: u32 = 0x0200;
const F_MULTIPART: u32 = 0x0400;
const F_H_FILTER: u32 = 0x0800;
const F_H_CRC32: u32 = 0x1000;
const F_OS_UNIX: u32 = 0x0300_0000;
/// lzop's own block size.
const BLOCK_SIZE: usize = 256 * 1024;
/// libarchive's limit on a block's size.
const MAX_BLOCK: u64 = 64 * 1024 * 1024;

impl Codec for Lzop {
    fn id(&self) -> CodecId {
        CodecId::Lzop
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".lzo", ".tzo"]
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

    fn decoder<'a>(
        &self,
        r: Box<dyn Read + Send + 'a>,
        limits: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        Ok(Box::new(Reader::new(
            r,
            MAX_BLOCK.min(limits.decoder_memory),
        )))
    }

    fn encoder<'a>(
        &self,
        w: Box<dyn Write + 'a>,
        opts: &EncodeOpts,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        opts.resolve_level(self.id(), self.levels())?;
        let name = opts.gzip_name.as_deref().unwrap_or_default();
        let mtime = opts.gzip_mtime.map(to_unix).unwrap_or(0).max(0);
        let mut w = Writer::new(w, name.as_bytes(), mtime.unsigned_abs())
            .map_err(|e| crate::io::write_error(&e))?;
        w.threads = usize::try_from(opts.resolve_threads()).unwrap_or(1).max(1);
        Ok(finisher(w, Writer::finish))
    }

    fn threads(&self) -> bool {
        true
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("lzop: {}", msg.into()))
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 bytes is the most that can be summed before `b` could overflow.
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    b << 16 | a
}

/// A header's fields, after the magic.
#[derive(Debug, Clone, Default)]
struct Header {
    flags: u32,
    name: Vec<u8>,
}

/// Reads bytes into `seen` too, for the header checksum.
struct Tee<'a, R: ?Sized> {
    r: &'a mut R,
    seen: Vec<u8>,
}

impl<R: Read + ?Sized> Tee<'_, R> {
    fn bytes<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut b = [0u8; N];
        self.r
            .read_exact(&mut b)
            .map_err(|_| bad("the header is cut short"))?;
        self.seen.extend_from_slice(&b);
        Ok(b)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.bytes::<1>()?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.bytes()?))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.bytes()?))
    }
}

fn read_u32<R: Read + ?Sized>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)
        .map_err(|_| bad("the file is cut short"))?;
    Ok(u32::from_be_bytes(b))
}

/// The header after the magic, its checksum checked.
fn read_header<R: Read + ?Sized>(r: &mut R) -> io::Result<Header> {
    let mut t = Tee {
        r,
        seen: Vec::new(),
    };
    let version = t.u16()?;
    let _lib_version = t.u16()?;
    let new = version >= 0x0940;
    if new {
        let _needed = t.u16()?;
    }
    let method = t.u8()?;
    if !(1..=3).contains(&method) {
        return Err(bad(format!("method {method} isn't LZO1X")));
    }
    if new {
        let level = t.u8()?;
        if level > 9 {
            return Err(bad(format!("level {level}")));
        }
    }
    let flags = t.u32()?;
    if flags & (F_H_FILTER | F_MULTIPART) != 0 {
        return Err(bad(format!("unsupported flags {flags:#x}")));
    }
    let _mode = t.u32()?;
    let _mtime_low = t.u32()?;
    if new {
        let _mtime_high = t.u32()?;
    }
    let len = t.u8()?;
    let mut name = Vec::with_capacity(usize::from(len));
    for _ in 0..len {
        name.push(t.u8()?);
    }
    let seen = std::mem::take(&mut t.seen);
    let want = read_u32(t.r)?;
    let got = if flags & F_H_CRC32 != 0 {
        crc32fast::hash(&seen)
    } else {
        adler32(&seen)
    };
    if want != got {
        return Err(bad("the header's checksum doesn't match"));
    }
    if flags & F_H_EXTRA_FIELD != 0 {
        let len = read_u32(t.r)?;
        // The data and its checksum.
        let skip = u64::from(len) + 4;
        let n = io::copy(&mut t.r.take(skip), &mut io::sink())?;
        if n != skip {
            return Err(bad("the header's extra field is cut short"));
        }
    }
    Ok(Header { flags, name })
}

/// The file name in the header at the start of `head`, for the stream view's entry name.
pub fn header_name(head: &[u8]) -> Option<String> {
    let mut r = head.strip_prefix(&MAGIC)?;
    let h = read_header(&mut r).ok()?;
    let name = String::from_utf8_lossy(&h.name).into_owned();
    (!name.is_empty()).then_some(name)
}

/// A streaming reader: one block in memory at a time.
struct Reader<R> {
    inner: R,
    max_block: u64,
    header: Option<Header>,
    block: Vec<u8>,
    pos: usize,
    done: bool,
    members: usize,
}

impl<R: Read> Reader<R> {
    fn new(inner: R, max_block: u64) -> Self {
        Self {
            inner,
            max_block,
            header: None,
            block: Vec::new(),
            pos: 0,
            done: false,
            members: 0,
        }
    }

    /// Starts the next member: `false` at the end of the input, or at data after a member that
    /// isn't another one.
    fn member(&mut self) -> io::Result<bool> {
        let mut m = [0u8; 9];
        let mut n = 0;
        while n < m.len() {
            match self.inner.read(&mut m[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        match n {
            9 if m == MAGIC => {}
            _ if self.members > 0 => return Ok(false),
            _ => return Err(bad("not an lzop file")),
        }
        self.header = Some(read_header(&mut self.inner)?);
        self.members += 1;
        Ok(true)
    }

    /// Fills `block` with the next block: `false` at the end of the member.
    fn next_block(&mut self) -> io::Result<bool> {
        let flags = self.header.as_ref().map_or(0, |h| h.flags);
        let dst_len = read_u32(&mut self.inner)?;
        if dst_len == 0 {
            return Ok(false);
        }
        let src_len = read_u32(&mut self.inner)?;
        if u64::from(dst_len) > self.max_block {
            return Err(bad(format!(
                "a block of {dst_len} bytes is over the limit of {}",
                self.max_block
            )));
        }
        // LZO1X expands at most about 255:1 (each length byte adds 255), so a block can't claim
        // more, and nothing is allocated for a claim that couldn't be true.
        if src_len > dst_len || src_len == 0 || u64::from(dst_len) > u64::from(src_len) * 256 + 4096
        {
            return Err(bad(format!("a block of {src_len} bytes for {dst_len}")));
        }
        let stored = src_len == dst_len;
        let mut sums = Vec::new();
        for (flag, crc, on_data) in [
            (F_ADLER32_D, false, true),
            (F_CRC32_D, true, true),
            (F_ADLER32_C, false, false),
            (F_CRC32_C, true, false),
        ] {
            if flags & flag != 0 && (on_data || !stored) {
                sums.push((crc, on_data, read_u32(&mut self.inner)?));
            }
        }
        let mut src = Vec::new();
        let got = (&mut self.inner)
            .take(u64::from(src_len))
            .read_to_end(&mut src)?;
        if got != src_len as usize {
            return Err(bad("a block is cut short"));
        }
        let check = |data: &[u8], on_data: bool| -> io::Result<()> {
            for &(crc, d, want) in &sums {
                let sum = if crc {
                    crc32fast::hash(data)
                } else {
                    adler32(data)
                };
                if d == on_data && want != sum {
                    return Err(bad(if d {
                        "a block's data checksum doesn't match"
                    } else {
                        "a block's compressed checksum doesn't match"
                    }));
                }
            }
            Ok(())
        };
        check(&src, false)?;
        self.block = if stored {
            src
        } else {
            let mut out = vec![0; dst_len as usize];
            let n = lzokay::decompress::decompress(&src, &mut out)
                .map_err(|e| bad(format!("a block doesn't decode ({e:?})")))?;
            if n != out.len() {
                return Err(bad("a block decodes short"));
            }
            out
        };
        check(&self.block, true)?;
        self.pos = 0;
        Ok(true)
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos == self.block.len() {
            if self.done {
                return Ok(0);
            }
            if self.header.is_none() && !self.member()? {
                self.done = true;
                return Ok(0);
            }
            if !self.next_block()? {
                // The next member, if there is one.
                self.header = None;
                self.block.clear();
                self.pos = 0;
            }
        }
        let n = buf.len().min(self.block.len() - self.pos);
        buf[..n].copy_from_slice(&self.block[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A streaming writer.
struct Writer<W: Write> {
    out: W,
    buf: Vec<u8>,
    /// Workers; with more than one, full blocks wait in `batch` until each has two.
    threads: usize,
    batch: Vec<Vec<u8>>,
}

impl<W: Write> Writer<W> {
    fn new(mut out: W, name: &[u8], mtime: u64) -> io::Result<Self> {
        let flags = F_OS_UNIX | F_ADLER32_D | F_ADLER32_C;
        let mut h = Vec::new();
        h.extend_from_slice(&0x1040u16.to_be_bytes()); // lzop 1.04's format version
        h.extend_from_slice(&0x20a0u16.to_be_bytes()); // LZO 2.10
        h.extend_from_slice(&0x0940u16.to_be_bytes()); // needed to extract
        h.push(3); // LZO1X-999
        h.push(9);
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&0o100_644u32.to_be_bytes());
        h.extend_from_slice(&(mtime as u32).to_be_bytes());
        h.extend_from_slice(&((mtime >> 32) as u32).to_be_bytes());
        let name = &name[..name.len().min(255)];
        h.push(name.len() as u8);
        h.extend_from_slice(name);
        let sum = adler32(&h);
        out.write_all(&MAGIC)?;
        out.write_all(&h)?;
        out.write_all(&sum.to_be_bytes())?;
        Ok(Self {
            out,
            buf: Vec::with_capacity(BLOCK_SIZE),
            threads: 1,
            batch: Vec::new(),
        })
    }

    fn block(&mut self) -> io::Result<()> {
        // No block for no data: lzokay's empty block is one no decoder reads.
        if self.buf.is_empty() {
            return Ok(());
        }
        if self.threads == 1 {
            let packed = pack(&self.buf)?;
            self.buf.clear();
            return self.out.write_all(&packed);
        }
        let full = std::mem::replace(&mut self.buf, Vec::with_capacity(BLOCK_SIZE));
        self.batch.push(full);
        if self.batch.len() >= 2 * self.threads {
            self.write_batch()?;
        }
        Ok(())
    }

    /// Compresses the waiting blocks on the workers, and writes them in order.
    fn write_batch(&mut self) -> io::Result<()> {
        let batch = std::mem::take(&mut self.batch);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let packed: Vec<std::sync::Mutex<Option<io::Result<Vec<u8>>>>> =
            batch.iter().map(|_| std::sync::Mutex::new(None)).collect();
        std::thread::scope(|s| {
            for _ in 0..self.threads.min(batch.len()) {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(block) = batch.get(i) else { break };
                        let done = pack(block);
                        *packed[i]
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(done);
                    }
                });
            }
        });
        for p in packed {
            let p = p
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .unwrap_or_else(|| Err(io::Error::other("lzop: a block wasn't compressed")))?;
            self.out.write_all(&p)?;
        }
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        self.block()?;
        self.write_batch()?;
        self.out.write_all(&0u32.to_be_bytes())?;
        self.out.flush()
    }
}

/// One block as lzop writes it: its sizes, its checksums, then its data, compressed if that
/// makes it smaller.
fn pack(block: &[u8]) -> io::Result<Vec<u8>> {
    let c = lzokay::compress::compress(block)
        .map_err(|e| io::Error::other(format!("lzokay: {e:?}")))?;
    let stored = c.len() >= block.len();
    let data: &[u8] = if stored { block } else { &c };
    let mut out = Vec::with_capacity(16 + data.len());
    out.extend_from_slice(&(block.len() as u32).to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&adler32(block).to_be_bytes());
    if !stored {
        out.extend_from_slice(&adler32(&c).to_be_bytes());
    }
    out.extend_from_slice(data);
    Ok(out)
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(BLOCK_SIZE - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == BLOCK_SIZE {
            self.block()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(data: &[u8], name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out, name.as_bytes(), 1_700_000_000).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap();
        out
    }

    fn decode(data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Reader::new(data, MAX_BLOCK).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn threads_give_the_same_bytes() {
        let data: Vec<u8> = (0..3_000_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8 & 0x3F)
            .collect();
        let one = encode(&data, "x");
        for threads in [2, 4, 32] {
            let mut out = Vec::new();
            let mut w = Writer::new(&mut out, b"x", 1_700_000_000).unwrap();
            w.threads = threads;
            for piece in data.chunks(100_000) {
                w.write_all(piece).unwrap();
            }
            w.finish().unwrap();
            assert!(out == one, "{threads} threads");
        }
        assert_eq!(decode(&one).unwrap(), data);
    }

    #[test]
    fn adler32_matches_zlib() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        let big = vec![0xFFu8; 100_000];
        // zlib's adler32 of 100 000 0xFF bytes.
        assert_eq!(adler32(&big), 0x149A_302C);
    }

    #[test]
    fn round_trips() {
        let mut data = Vec::new();
        for i in 0..700_000u32 {
            data.push(if i % 3 == 0 { (i % 251) as u8 } else { b'a' });
        }
        let z = encode(&data, "a.bin");
        assert_eq!(decode(&z).unwrap(), data);
        // The most compressible data stays within the expansion bound.
        let zeros = vec![0u8; 3 << 20];
        assert_eq!(decode(&encode(&zeros, "z")).unwrap(), zeros);
        assert_eq!(header_name(&z).as_deref(), Some("a.bin"));
        // Concatenated members read as one stream, and junk after them is ignored.
        let mut two = z.clone();
        two.extend_from_slice(&encode(b"more", ""));
        two.extend_from_slice(b"junk");
        let mut want = data.clone();
        want.extend_from_slice(b"more");
        assert_eq!(decode(&two).unwrap(), want);
    }

    #[test]
    fn empty_input_has_no_block() {
        let z = encode(b"", "e");
        // The magic, 25 bytes of fields, the name and the checksum, and the end marker: no block.
        assert_eq!(z.len(), 9 + 25 + 1 + 4 + 4);
        assert_eq!(decode(&z).unwrap(), b"");
    }

    #[test]
    fn checksums_and_sizes_are_checked() {
        let z = encode(&vec![7u8; 5000], "");
        let block = 9 + 25 + 4;
        let mut bad_data = z.clone();
        bad_data[block + 8] ^= 1; // the data's Adler-32
        assert!(decode(&bad_data).is_err());
        let mut bad_header = z.clone();
        bad_header[20] ^= 1;
        assert!(decode(&bad_header).is_err());
        let mut huge = z.clone();
        huge[block..block + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(
            Reader::new(&huge[..], MAX_BLOCK)
                .read_to_end(&mut Vec::new())
                .is_err()
        );
        assert!(decode(&z[..z.len() - 6]).is_err(), "cut short");
        assert!(decode(b"not lzop").is_err());
    }
}
