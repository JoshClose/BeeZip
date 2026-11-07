//! Apple-compressed files (decmpfs, docs/M5.md §5.11), decoded by BeeZip: fstool 0.5.2 reads
//! their header in the wrong byte order and fails them.
//!
//! - **The header** is the `com.apple.decmpfs` attribute: `fpmc`, then the type and the size the
//!   file has uncompressed (little-endian), then for the inline types the data itself.
//! - **Inline types:** 1 (stored), 3 (zlib), 7 (LZVN) and 11 (LZFSE). Apple stores a file inline
//!   only when it fits in the attribute, so an attribute over [`MAX_ATTR`] is refused, and an
//!   inline file is decoded whole, up to [`MAX_INLINE`].
//! - **Resource-fork types:** 4 (zlib), 8 (LZVN) and 12 (LZFSE), in 64 KiB blocks. Type 4 wraps
//!   its block table in a resource (the data's offset in the first four bytes, then the
//!   resource's length, then a little-endian count and `(offset, length)` pairs from the
//!   count); types 8 and 12 start the fork with `blocks + 1` little-endian offsets. Blocks are
//!   read one at a time, every offset and length checked against the fork first.
//! - **A block stored uncompressed** starts with a marker instead: a byte whose low nibble is
//!   `F` for zlib, `0x06` (LZVN's end of stream) for LZVN, `0xFF` for LZFSE.
//! - Other types are `UnsupportedOperation` for that file.

use std::io::{self, Cursor, Read};

use super::lzvn;
use crate::{Error, Result};

/// The attribute's name.
pub const XATTR: &str = "com.apple.decmpfs";
/// The header's magic, `cmpf` little-endian.
const MAGIC: &[u8; 4] = b"fpmc";
const HEADER: usize = 16;
/// The size each block of a resource fork decodes to (the last one less).
const BLOCK: u64 = 64 * 1024;
/// The largest attribute read: HFS+ and APFS hold under 4 KiB inline.
pub const MAX_ATTR: usize = 64 * 1024;
/// The most an inline file may decode to.
const MAX_INLINE: u64 = 64 << 20;
/// The most a block may be stored in: a whole block, its marker, and slack.
const MAX_BLOCK: u64 = 2 * BLOCK + 64;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("dmg: {message}"))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// The header: the compression type and the size uncompressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: u32,
    pub size: u64,
}

impl Header {
    pub fn parse(x: &[u8]) -> Result<Self> {
        if x.len() < HEADER || !x.starts_with(MAGIC) {
            return Err(bad("a compressed file's attribute has no decmpfs header"));
        }
        if x.len() > MAX_ATTR {
            return Err(bad(format!(
                "a compressed file's attribute is {} bytes",
                x.len()
            )));
        }
        let size = x[8..16]
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| bad("a short decmpfs header"))?;
        Ok(Self {
            kind: le32(x, 4),
            size,
        })
    }

    /// Whether the data is in the resource fork.
    pub fn in_fork(&self) -> bool {
        matches!(self.kind, 4 | 8 | 12)
    }

    /// The codec, for `Entry::method`; `None` for a type BeeZip can't read.
    pub fn method(&self) -> Option<&'static str> {
        Some(match self.kind {
            1 => "decmpfs stored",
            3 | 4 => "decmpfs zlib",
            7 | 8 => "decmpfs LZVN",
            11 | 12 => "decmpfs LZFSE",
            _ => return None,
        })
    }
}

/// A file's resource fork, read at offsets.
pub trait Fork {
    fn len(&self) -> u64;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

#[derive(Clone, Copy)]
enum Codec {
    Zlib,
    Lzvn,
    Lzfse,
}

/// Decodes one block (or a whole inline file) to exactly `want` bytes.
fn decode(codec: Codec, packed: &[u8], want: usize) -> Result<Vec<u8>> {
    let stored = match (codec, packed.first()) {
        (Codec::Zlib, Some(b)) => b & 0x0F == 0x0F,
        (Codec::Lzvn, Some(&b)) => b == 0x06,
        (Codec::Lzfse, Some(&b)) => b == 0xFF,
        (_, None) => want == 0,
    };
    let out = if stored {
        packed.get(1..).unwrap_or_default().to_vec()
    } else {
        match codec {
            Codec::Zlib => {
                let mut out = Vec::with_capacity(want);
                flate2::read::ZlibDecoder::new(packed)
                    .take(want as u64 + 1)
                    .read_to_end(&mut out)
                    .map_err(|e| bad(format!("a zlib block is damaged: {e}")))?;
                out
            }
            Codec::Lzvn => {
                lzvn::decode(packed, want).map_err(|e| bad(format!("an LZVN block: {e}")))?
            }
            Codec::Lzfse => {
                let mut out = Vec::with_capacity(want);
                let mut sink = Bounded {
                    out: &mut out,
                    max: want,
                };
                lzfse_rust::LzfseRingDecoder::default()
                    .decode(&mut &packed[..], &mut sink)
                    .map_err(|e| bad(format!("an LZFSE block is damaged: {e}")))?;
                out
            }
        }
    };
    if out.len() != want {
        return Err(bad(format!(
            "a compressed block decodes to {} bytes instead of {want}",
            out.len()
        )));
    }
    Ok(out)
}

struct Bounded<'a> {
    out: &'a mut Vec<u8>,
    max: usize,
}

impl io::Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.out.len() + buf.len() > self.max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "it decodes to more than the file's size",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn unsupported(kind: u32, path: &str) -> Error {
    Error::unsupported(format!(
        "`{path}` is an Apple-compressed file of type {kind}, which BeeZip can't read"
    ))
}

/// The data of the file whose `com.apple.decmpfs` attribute is `x`, with its resource fork when
/// it has one. `path` names it in errors.
pub fn open<'a>(
    x: &[u8],
    fork: Option<Box<dyn Fork + 'a>>,
    path: &str,
) -> Result<Box<dyn Read + 'a>> {
    let h = Header::parse(x)?;
    let codec = match h.kind {
        1 => None,
        3 | 4 => Some(Codec::Zlib),
        7 | 8 => Some(Codec::Lzvn),
        11 | 12 => Some(Codec::Lzfse),
        kind => return Err(unsupported(kind, path)),
    };
    if !h.in_fork() {
        let tail = &x[HEADER..];
        let data = match codec {
            None => tail
                .get(..usize::try_from(h.size).unwrap_or(usize::MAX))
                .unwrap_or(tail)
                .to_vec(),
            Some(c) => {
                if h.size > MAX_INLINE {
                    return Err(bad(format!(
                        "`{path}` claims {} bytes from {} in its attribute",
                        h.size,
                        tail.len()
                    )));
                }
                decode(c, tail, h.size as usize)?
            }
        };
        return Ok(Box::new(Cursor::new(data)));
    }
    let Some(codec) = codec else {
        return Err(unsupported(h.kind, path));
    };
    let Some(fork) = fork else {
        return Err(Error::unsupported(format!(
            "`{path}` is an Apple-compressed file kept in a resource fork, which BeeZip can't \
             read from this volume"
        )));
    };
    Ok(Box::new(Blocks::new(fork, codec, h, path)?))
}

/// Where a resource fork's block table is.
enum Table {
    /// Type 4: `(offset, length)` pairs after a count, offsets from `base`.
    Pairs { base: u64 },
    /// Types 8 and 12: `blocks + 1` offsets from the start of the fork.
    Offsets,
}

/// A resource fork's blocks, decoded one at a time.
struct Blocks<'a> {
    fork: Box<dyn Fork + 'a>,
    codec: Codec,
    table: Table,
    size: u64,
    blocks: u64,
    next: u64,
    buf: Vec<u8>,
    at: usize,
    path: String,
}

impl<'a> Blocks<'a> {
    fn new(mut fork: Box<dyn Fork + 'a>, codec: Codec, h: Header, path: &str) -> Result<Self> {
        let blocks = h.size.div_ceil(BLOCK);
        let len = fork.len();
        let too_small = || {
            bad(format!(
                "`{path}`'s resource fork is too small for {blocks} blocks ({len} bytes)"
            ))
        };
        let table = if matches!(codec, Codec::Zlib) {
            let mut head = [0u8; 4];
            if len < 4 {
                return Err(too_small());
            }
            fork.read_at(0, &mut head)?;
            let base = u64::from(u32::from_be_bytes(head)) + 4;
            let mut count = [0u8; 4];
            if base.checked_add(4).is_none_or(|end| end > len) {
                return Err(too_small());
            }
            fork.read_at(base, &mut count)?;
            let count = u64::from(u32::from_le_bytes(count));
            if count != blocks {
                return Err(bad(format!(
                    "`{path}` has {count} blocks for {} bytes",
                    h.size
                )));
            }
            if base + 4 + blocks * 8 > len {
                return Err(too_small());
            }
            Table::Pairs { base }
        } else {
            if (blocks + 1) * 4 > len {
                return Err(too_small());
            }
            Table::Offsets
        };
        Ok(Self {
            fork,
            codec,
            table,
            size: h.size,
            blocks,
            next: 0,
            buf: Vec::new(),
            at: 0,
            path: path.to_owned(),
        })
    }

    /// Block `i`'s place in the fork.
    fn range(&mut self, i: u64) -> Result<(u64, u64)> {
        let (start, len) = match self.table {
            Table::Pairs { base } => {
                let mut e = [0u8; 8];
                self.fork.read_at(base + 4 + i * 8, &mut e)?;
                let off = u64::from(le32(&e, 0));
                (base + off, u64::from(le32(&e, 4)))
            }
            Table::Offsets => {
                let mut e = [0u8; 8];
                self.fork.read_at(i * 4, &mut e)?;
                let (a, b) = (u64::from(le32(&e, 0)), u64::from(le32(&e, 4)));
                if b < a {
                    return Err(bad(format!(
                        "`{}`'s block {i} ends before it starts",
                        self.path
                    )));
                }
                (a, b - a)
            }
        };
        if len > MAX_BLOCK
            || start
                .checked_add(len)
                .is_none_or(|end| end > self.fork.len())
        {
            return Err(bad(format!(
                "`{}`'s block {i} ({len} bytes at {start}) is past its resource fork",
                self.path
            )));
        }
        Ok((start, len))
    }

    fn fill(&mut self) -> Result<()> {
        let i = self.next;
        let (start, len) = self.range(i)?;
        let mut packed = vec![0u8; len as usize];
        self.fork.read_at(start, &mut packed)?;
        let want = (self.size - i * BLOCK).min(BLOCK) as usize;
        self.buf =
            decode(self.codec, &packed, want).map_err(|e| e.context(format!("`{}`", self.path)))?;
        self.at = 0;
        self.next += 1;
        Ok(())
    }
}

impl Read for Blocks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.buf.len() {
            if self.next == self.blocks {
                return Ok(0);
            }
            self.fill().map_err(Error::into_io)?;
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn header(kind: u32, size: u64) -> Vec<u8> {
        let mut x = MAGIC.to_vec();
        x.extend_from_slice(&kind.to_le_bytes());
        x.extend_from_slice(&size.to_le_bytes());
        x
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    fn lzfse(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        lzfse_rust::encode_bytes(data, &mut out).unwrap();
        out
    }

    /// An LZVN stream: lzfse_rust's LZVN block for a small input, else stored.
    fn lzvn(data: &[u8]) -> Vec<u8> {
        let enc = lzfse(data);
        if enc.starts_with(b"bvxn") {
            let n = u32::from_le_bytes(enc[8..12].try_into().unwrap()) as usize;
            enc[12..12 + n].to_vec()
        } else {
            let mut s = vec![0x06];
            s.extend_from_slice(data);
            s
        }
    }

    struct Mem(Vec<u8>);

    impl Fork for Mem {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let at = offset as usize;
            let src = self
                .0
                .get(at..at + buf.len())
                .ok_or_else(|| bad("past the fork"))?;
            buf.copy_from_slice(src);
            Ok(())
        }
    }

    fn read(x: &[u8], fork: Option<Vec<u8>>) -> Result<Vec<u8>> {
        let fork = fork.map(|f| Box::new(Mem(f)) as Box<dyn Fork>);
        let mut r = open(x, fork, "f")?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).map_err(Error::from)?;
        Ok(out)
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| b"decmpfs blocks of text "[i % 23] ^ (i / 4099) as u8)
            .collect()
    }

    #[test]
    fn inline_types() {
        let data = text(3000);
        let n = data.len() as u64;
        for (kind, payload) in [
            (1, data.clone()),
            (3, zlib(&data)),
            (3, [&[0xFF][..], &data].concat()),
            (7, lzvn(&data)),
            (7, [&[0x06][..], &data].concat()),
            (11, lzfse(&data)),
            (11, [&[0xFF][..], &data].concat()),
        ] {
            let mut x = header(kind, n);
            x.extend_from_slice(&payload);
            assert_eq!(read(&x, None).unwrap(), data, "type {kind}");
            // The wrong size.
            let mut x = header(kind, n + 1);
            x.extend_from_slice(&payload);
            if kind != 1 {
                assert!(read(&x, None).is_err(), "type {kind}");
            }
        }
        assert_eq!(read(&header(3, 0), None).unwrap(), b"");
    }

    /// A type-4 fork: the resource header, the resource's length, the count and the pairs, then
    /// the blocks.
    fn fork4(blocks: &[Vec<u8>]) -> Vec<u8> {
        let data_off = 256u32;
        let mut f = vec![0u8; data_off as usize];
        f[..4].copy_from_slice(&data_off.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes()); // the resource's length, unused
        let base = f.len();
        f.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        let mut off = 4 + blocks.len() * 8;
        for b in blocks {
            f.extend_from_slice(&(off as u32).to_le_bytes());
            f.extend_from_slice(&(b.len() as u32).to_le_bytes());
            off += b.len();
        }
        for b in blocks {
            f.extend_from_slice(b);
        }
        assert_eq!(f.len(), base + off);
        f
    }

    /// A type-8 or 12 fork: `blocks + 1` offsets, then the blocks.
    fn fork8(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut off = (blocks.len() + 1) * 4;
        let mut f = Vec::new();
        for b in blocks {
            f.extend_from_slice(&(off as u32).to_le_bytes());
            off += b.len();
        }
        f.extend_from_slice(&(off as u32).to_le_bytes());
        for b in blocks {
            f.extend_from_slice(b);
        }
        f
    }

    #[test]
    fn resource_fork_types() {
        let data = text(150_000);
        let pieces: Vec<&[u8]> = data.chunks(BLOCK as usize).collect();
        let n = data.len() as u64;
        let z: Vec<Vec<u8>> = pieces.iter().map(|p| zlib(p)).collect();
        let f: Vec<Vec<u8>> = pieces.iter().map(|p| lzfse(p)).collect();
        // LZVN: the first block stored, the rest as lzfse_rust's LZVN where it makes one.
        let v: Vec<Vec<u8>> = pieces.iter().map(|p| [&[0x06][..], p].concat()).collect();
        for (kind, fork) in [(4, fork4(&z)), (12, fork8(&f)), (8, fork8(&v))] {
            assert_eq!(
                read(&header(kind, n), Some(fork.clone())).unwrap(),
                data,
                "type {kind}"
            );
            // Without the fork, or with it cut short.
            assert_eq!(
                read(&header(kind, n), None).unwrap_err().kind,
                crate::ErrorKind::UnsupportedOperation
            );
            assert!(read(&header(kind, n), Some(fork[..fork.len() - 10].to_vec())).is_err());
            // A size that needs more blocks than the table has.
            assert!(
                read(&header(kind, n + BLOCK), Some(fork)).is_err(),
                "type {kind}"
            );
        }
        // A short LZVN block made by lzfse_rust.
        let small = text(2000);
        let v = fork8(&[lzvn(&small)]);
        assert_eq!(read(&header(8, 2000), Some(v)).unwrap(), small);
    }

    #[test]
    fn crafted_tables_are_refused() {
        // A block claiming 4 GiB, and one ending before it starts.
        let mut f = fork8(&[vec![0x06; 10]]);
        f[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            read(&header(8, 9), Some(f))
                .unwrap_err()
                .message
                .contains("past")
        );
        let mut f = fork8(&[vec![0x06; 10]]);
        f[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(read(&header(8, 9), Some(f)).is_err());
        // A size of 2^60 bytes needs a table far bigger than the fork.
        let f = fork8(&[vec![0x06; 10]]);
        assert!(
            read(&header(12, 1 << 60), Some(f))
                .unwrap_err()
                .message
                .contains("too small")
        );
        // A type-4 count that doesn't match the size.
        let f = fork4(&[zlib(b"abc")]);
        assert!(read(&header(4, 3 * BLOCK), Some(f)).is_err());
        // An inline file claiming more than an attribute can hold.
        let mut x = header(3, MAX_INLINE + 1);
        x.extend_from_slice(&zlib(b"x"));
        assert!(read(&x, None).is_err());
        // Unknown types, a missing magic, an oversized attribute.
        assert_eq!(
            read(&header(5, 1), None).unwrap_err().kind,
            crate::ErrorKind::UnsupportedOperation
        );
        assert!(read(b"cmpf\x03\0\0\0\0\0\0\0\0\0\0\0", None).is_err());
        let mut x = header(1, 10);
        x.resize(MAX_ATTR + 1, 0);
        assert!(read(&x, None).is_err());
    }
}
