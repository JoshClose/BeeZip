//! The 7z header checks BeeZip makes before sevenz-rust2 reads anything (docs/M3.md §3.3).
//!
//! sevenz-rust2 decodes a compressed ("encoded") header with no memory limit, growing its
//! buffer as data decodes, so a 1 KiB header declaring gigabytes of zeros would fill memory.
//! This reads the 32-byte start header and the encoded header's streams info (its coders and
//! unpack sizes) and refuses anything over `decoder_memory`. It also says whether the header is
//! encrypted. Anything it can't parse is left to sevenz-rust2, which reports it as damage.

use std::io::{Read, Seek, SeekFrom};

use crate::{Error, Result};

pub const SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_ENCODED_HEADER: u8 = 0x17;

pub const ID_COPY: &[u8] = &[0x00];
pub const ID_LZMA: &[u8] = &[0x03, 0x01, 0x01];
pub const ID_LZMA2: &[u8] = &[0x21];
pub const ID_PPMD: &[u8] = &[0x03, 0x04, 0x01];
pub const ID_AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

/// One coder of a block, as the header declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoderInfo {
    pub id: Vec<u8>,
    pub props: Vec<u8>,
}

/// What the start header and the next header's first bytes say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderInfo {
    /// The header is compressed (an encoded header).
    pub encoded: bool,
    /// The encoded header's block has an AES coder: names are encrypted.
    pub encrypted: bool,
    /// The encoded header's coders.
    pub coders: Vec<CoderInfo>,
    /// The largest unpack size the encoded header's block declares.
    pub unpack_size: u64,
}

/// The memory a coder needs to decode, from its properties: the LZMA and LZMA2 dictionary
/// sizes and PPMd's model size. Other coders need little.
pub fn coder_memory(id: &[u8], props: &[u8]) -> u64 {
    match id {
        ID_LZMA if props.len() >= 5 => {
            u64::from(u32::from_le_bytes([props[1], props[2], props[3], props[4]]))
        }
        ID_LZMA2 if !props.is_empty() => lzma2_dict(props[0]),
        ID_PPMD if props.len() >= 5 => {
            u64::from(u32::from_le_bytes([props[1], props[2], props[3], props[4]]))
        }
        _ => 0,
    }
}

/// LZMA2's one-byte dictionary size: 40 is 4 GiB - 1, anything higher is invalid (and read
/// as the largest, so it fails the memory check).
pub fn lzma2_dict(b: u8) -> u64 {
    if b >= 40 {
        return u64::from(u32::MAX);
    }
    (2 | u64::from(b & 1)) << (u32::from(b) / 2 + 11)
}

/// Reads the start header and, for an encoded header, its streams info; refuses a header over
/// `decoder_memory` with `LimitExceeded`. `None` when the input doesn't parse; sevenz-rust2
/// will then say what is wrong.
pub fn check<R: Read + Seek>(r: &mut R, decoder_memory: u64) -> Result<Option<HeaderInfo>> {
    let Some(info) = read(r) else {
        return Ok(None);
    };
    if info.unpack_size > decoder_memory {
        return Err(Error::limit(format!(
            "the 7z header unpacks to {} bytes, over the {decoder_memory}-byte limit \
             (`decoder_memory`)",
            info.unpack_size
        )));
    }
    for c in &info.coders {
        let need = coder_memory(&c.id, &c.props);
        if need > decoder_memory {
            return Err(Error::limit(format!(
                "the 7z header needs {need} bytes to decode, over the {decoder_memory}-byte \
                 limit (`decoder_memory`)"
            )));
        }
    }
    Ok(Some(info))
}

fn read<R: Read + Seek>(r: &mut R) -> Option<HeaderInfo> {
    let len = r.seek(SeekFrom::End(0)).ok()?;
    r.seek(SeekFrom::Start(0)).ok()?;
    let mut start = [0u8; 32];
    r.read_exact(&mut start).ok()?;
    if start[..6] != SIGNATURE {
        return None;
    }
    let offset = u64::from_le_bytes(start[12..20].try_into().ok()?);
    let size = u64::from_le_bytes(start[20..28].try_into().ok()?);
    let at = 32u64.checked_add(offset)?;
    if size == 0 || at >= len {
        return Some(HeaderInfo::default());
    }
    // An encoded header is just streams info; 64 KiB is far more than one needs.
    let want = size.min(len - at).min(64 * 1024);
    r.seek(SeekFrom::Start(at)).ok()?;
    let mut buf = vec![0u8; usize::try_from(want).ok()?];
    r.read_exact(&mut buf).ok()?;
    let mut p = Parser { buf: &buf, at: 0 };
    match p.byte()? {
        K_HEADER => Some(HeaderInfo::default()),
        K_ENCODED_HEADER => p.streams_info(),
        _ => None,
    }
}

struct Parser<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    /// 7z's variable-length number: the leading one bits of the first byte count the bytes
    /// that follow.
    fn number(&mut self) -> Option<u64> {
        let first = self.byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = u64::from(first & mask.wrapping_sub(1));
                return Some(value | (high << (8 * i)));
            }
            value |= u64::from(self.byte()?) << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }

    /// A count that can't exceed what is left of the buffer, since every item takes a byte.
    fn count(&mut self) -> Option<usize> {
        let n = usize::try_from(self.number()?).ok()?;
        (n <= self.buf.len() - self.at).then_some(n)
    }

    fn skip_digests(&mut self, n: usize) -> Option<()> {
        let all = self.byte()?;
        let defined = if all != 0 {
            n
        } else {
            let bits = self.bytes(n.div_ceil(8))?;
            (0..n)
                .filter(|i| bits[i / 8] & (0x80 >> (i % 8)) != 0)
                .count()
        };
        self.bytes(defined.checked_mul(4)?)?;
        Some(())
    }

    fn streams_info(&mut self) -> Option<HeaderInfo> {
        let mut info = HeaderInfo {
            encoded: true,
            ..HeaderInfo::default()
        };
        loop {
            match self.byte()? {
                // The sizes and CRCs of the files in a block say nothing about memory.
                K_END | K_SUBSTREAMS_INFO => return Some(info),
                K_PACK_INFO => {
                    self.number()?;
                    let n = self.count()?;
                    loop {
                        match self.byte()? {
                            K_END => break,
                            K_SIZE => {
                                for _ in 0..n {
                                    self.number()?;
                                }
                            }
                            K_CRC => self.skip_digests(n)?,
                            _ => return None,
                        }
                    }
                }
                K_UNPACK_INFO => {
                    if self.byte()? != K_FOLDER {
                        return None;
                    }
                    let folders = self.count()?;
                    if self.byte()? != 0 {
                        return None; // external
                    }
                    let mut outs = Vec::with_capacity(folders);
                    for _ in 0..folders {
                        outs.push(self.folder(&mut info)?);
                    }
                    loop {
                        match self.byte()? {
                            K_END => break,
                            K_CODERS_UNPACK_SIZE => {
                                for &n in &outs {
                                    for _ in 0..n {
                                        info.unpack_size = info.unpack_size.max(self.number()?);
                                    }
                                }
                            }
                            K_CRC => self.skip_digests(folders)?,
                            _ => return None,
                        }
                    }
                }
                _ => return None,
            }
        }
    }

    /// One folder (block): its coders, bind pairs and packed streams. Returns its number of
    /// output streams.
    fn folder(&mut self, info: &mut HeaderInfo) -> Option<usize> {
        let coders = self.count()?;
        let (mut ins, mut outs) = (0usize, 0usize);
        for _ in 0..coders {
            let main = self.byte()?;
            if main & 0x80 != 0 {
                return None;
            }
            let id = self.bytes(usize::from(main & 0x0F))?.to_vec();
            let (i, o) = if main & 0x10 != 0 {
                (self.count()?, self.count()?)
            } else {
                (1, 1)
            };
            ins = ins.checked_add(i)?;
            outs = outs.checked_add(o)?;
            let props = if main & 0x20 != 0 {
                let n = self.count()?;
                self.bytes(n)?.to_vec()
            } else {
                Vec::new()
            };
            if id == ID_AES {
                info.encrypted = true;
            }
            info.coders.push(CoderInfo { id, props });
        }
        let pairs = outs.checked_sub(1)?;
        for _ in 0..pairs {
            self.number()?;
            self.number()?;
        }
        let packed = ins.checked_sub(pairs)?;
        if packed > 1 {
            for _ in 0..packed {
                self.number()?;
            }
        }
        Some(outs)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// A start header pointing at `next`, which follows it directly.
    fn archive(next: &[u8]) -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        v.extend_from_slice(&[0, 4]);
        let mut sh = Vec::new();
        sh.extend_from_slice(&0u64.to_le_bytes());
        sh.extend_from_slice(&(next.len() as u64).to_le_bytes());
        sh.extend_from_slice(&crc32fast::hash(next).to_le_bytes());
        v.extend_from_slice(&crc32fast::hash(&sh).to_le_bytes());
        v.extend_from_slice(&sh);
        v.extend_from_slice(next);
        v
    }

    /// An encoded header with one LZMA coder (dictionary `dict`) unpacking to `size`, the
    /// number written as 7z writes 8-byte values (0xFF and eight bytes).
    fn encoded(dict: u32, size: u64) -> Vec<u8> {
        let mut h = vec![
            K_ENCODED_HEADER,
            K_PACK_INFO,
            0x00,
            0x01,
            K_SIZE,
            0x10,
            K_END,
        ];
        h.extend_from_slice(&[K_UNPACK_INFO, K_FOLDER, 0x01, 0x00]);
        h.extend_from_slice(&[0x01, 0x23, 0x03, 0x01, 0x01, 0x05, 0x5D]);
        h.extend_from_slice(&dict.to_le_bytes());
        h.push(K_CODERS_UNPACK_SIZE);
        h.push(0xFF);
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&[K_END, K_END]);
        h
    }

    /// The encoded header sevenz-rust2 0.24.2 wrote for an AES + LZMA2 archive: it keeps the
    /// block CRC in substreams info, after the unpack info.
    #[test]
    fn reads_sevenz_rust2s_encrypted_header() {
        let next = [
            0x17, 0x06, 0xc1, 0xe0, 0x06, 0x01, 0x09, 0x82, 0xf0, 0x0a, 0x01, 0x99, 0xbd, 0x03,
            0x05, 0x00, 0x07, 0x0b, 0x01, 0x00, 0x02, 0x24, 0x06, 0xf1, 0x07, 0x01, 0x22, 0xc8,
            0xff, 0x0a, 0xeb, 0xcd, 0xd0, 0x1d, 0x0b, 0xde, 0xd7, 0xe6, 0x41, 0xbd, 0x41, 0x4c,
            0xfd, 0x75, 0xa5, 0x5c, 0x74, 0x8a, 0x3b, 0x9e, 0x65, 0x52, 0xf7, 0xa4, 0x68, 0x91,
            0x1d, 0xae, 0x33, 0x7a, 0xad, 0x23, 0x03, 0x01, 0x01, 0x05, 0x5d, 0x00, 0x00, 0x80,
            0x00, 0x01, 0x00, 0x0c, 0x82, 0xe5, 0x87, 0xd8, 0x00, 0x08, 0x0a, 0x01, 0x2d, 0x8e,
            0x74, 0xb6, 0x00, 0x00,
        ];
        let info = check(&mut Cursor::new(archive(&next)), 1 << 30)
            .unwrap()
            .unwrap();
        assert!(info.encoded && info.encrypted);
        assert_eq!(info.coders.len(), 2);
        assert_eq!(info.unpack_size, 0x7d8);
    }

    #[test]
    fn numbers() {
        let mut p = Parser {
            buf: &[0x7F, 0x80, 0x80, 0xC1, 0x02, 0x03],
            at: 0,
        };
        assert_eq!(p.number(), Some(0x7F));
        assert_eq!(p.number(), Some(0x80));
        assert_eq!(p.number(), Some(0x0302 | (0x01 << 16)));
    }

    #[test]
    fn lzma2_dictionaries() {
        assert_eq!(lzma2_dict(0), 4096);
        assert_eq!(lzma2_dict(1), 6144);
        assert_eq!(lzma2_dict(18), 2 << 20);
        assert_eq!(lzma2_dict(40), u64::from(u32::MAX));
    }

    #[test]
    fn refuses_huge_headers() {
        let ok = archive(&encoded(1 << 16, 4096));
        let info = check(&mut Cursor::new(ok), 1 << 30).unwrap().unwrap();
        assert!(info.encoded && !info.encrypted);
        assert_eq!(info.unpack_size, 4096);

        let bomb = archive(&encoded(1 << 16, 8 << 30));
        let err = check(&mut Cursor::new(bomb), 1 << 30).unwrap_err();
        assert_eq!(err.kind, crate::ErrorKind::LimitExceeded);

        let dict = archive(&encoded(u32::MAX, 4096));
        assert!(check(&mut Cursor::new(dict), 1 << 30).is_err());

        let plain = archive(&[K_HEADER, K_END]);
        assert_eq!(
            check(&mut Cursor::new(plain), 1 << 30).unwrap(),
            Some(HeaderInfo::default())
        );
        assert_eq!(
            check(&mut Cursor::new(b"not 7z".to_vec()), 1 << 30).unwrap(),
            None
        );
    }
}
