//! ACE's headers: the main header, file headers, recovery records and headers of unknown types,
//! each led by its CRC-16 and size. Every field is read only once the header's bytes are known
//! to hold it.

use crate::{Error, Result};

pub const MAGIC: &[u8; 7] = b"**ACE**";

pub const TYPE_MAIN: u8 = 0;
pub const TYPE_FILE32: u8 = 1;
pub const TYPE_RECOVERY32: u8 = 2;
pub const TYPE_FILE64: u8 = 3;
pub const TYPE_RECOVERY64A: u8 = 4;
pub const TYPE_RECOVERY64B: u8 = 5;

/// The header is followed by `addsize` bytes of data (files and recovery records).
pub const FLAG_ADDSIZE: u16 = 1 << 0;
pub const FLAG_COMMENT: u16 = 1 << 1;
/// File and recovery headers: the sizes are 64-bit.
pub const FLAG_64BIT: u16 = 1 << 2;
/// File headers: an NT security descriptor follows the name.
pub const FLAG_NTSECURITY: u16 = 1 << 10;
/// Main header: the archive is one part of a set.
pub const FLAG_MULTIVOLUME: u16 = 1 << 11;
/// Main header: an advertisement string follows the fixed fields.
pub const FLAG_ADVERT: u16 = 1 << 12;
/// File headers: the entry began in the part before.
pub const FLAG_CONTPREV: u16 = 1 << 12;
/// Main header: the archive has a recovery record.
pub const FLAG_RECOVERY: u16 = 1 << 13;
/// File headers: the entry goes on in the next part.
pub const FLAG_CONTNEXT: u16 = 1 << 13;
/// Main header: locked against changes.
pub const FLAG_LOCKED: u16 = 1 << 14;
/// File headers: the data is encrypted.
pub const FLAG_PASSWORD: u16 = 1 << 14;
pub const FLAG_SOLID: u16 = 1 << 15;

pub const COMP_STORED: u8 = 0;
/// ACE 1.0's LZ77.
pub const COMP_LZ77: u8 = 1;
/// ACE 2.0's: LZ77 with its EXE, DELTA, SOUND and PIC modes.
pub const COMP_BLOCKED: u8 = 2;

/// The DOS attribute of a folder.
pub const ATTR_DIRECTORY: u32 = 0x10;

/// ACE's CRC-32: CRC-32 without the final inversion.
pub fn crc32(data: &[u8]) -> u32 {
    !crc32fast::hash(data)
}

/// ACE's CRC-16: the low half of its CRC-32.
pub fn crc16(data: &[u8]) -> u16 {
    crc32(data) as u16
}

pub fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("ace: {message}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainHeader {
    pub flags: u16,
    /// The version needed to extract, and the one that made it, times ten.
    pub extract_version: u8,
    pub creator_version: u8,
    pub host: u8,
    /// The part's number in its set, from 0.
    pub volume: u8,
    /// A DOS date (high half) and time (low half).
    pub datetime: u32,
    /// The archive comment, still compressed.
    pub comment: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub flags: u16,
    /// The bytes of data after the header, in this part.
    pub packed: u64,
    pub size: u64,
    pub datetime: u32,
    pub attribs: u32,
    /// ACE's CRC-32 of the data. A split entry's last part holds the whole entry's.
    pub crc: u32,
    pub method: u8,
    pub quality: u8,
    /// The low four bits are the dictionary's size: `1 << (bits + 10)`.
    pub params: u16,
    pub name: Vec<u8>,
}

impl FileHeader {
    pub fn flag(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    pub fn dict_size(&self) -> usize {
        1 << (usize::from(self.params & 0x0F) + 10)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Main(MainHeader),
    File(FileHeader),
    /// A recovery record or a header of a type ACE 2.0 doesn't have: skipped, with the data
    /// after it.
    Other {
        addsize: u64,
    },
}

/// Reads the header's fields in order, failing when it runs out.
struct Fields<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or_else(|| bad("a header is cut short"))?;
        let field = &self.buf[self.at..end];
        self.at = end;
        Ok(field)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(b);
        Ok(u64::from_le_bytes(v))
    }

    /// A field led by its 16-bit length.
    fn sized(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}

/// Parses a header's bytes: what follows its CRC-16 and size, the CRC already checked.
pub fn parse(buf: &[u8]) -> Result<Header> {
    let mut f = Fields { buf, at: 0 };
    let kind = f.u8()?;
    let flags = f.u16()?;
    match kind {
        TYPE_MAIN => {
            if flags & FLAG_ADDSIZE != 0 {
                return Err(bad("the main header claims data after it"));
            }
            if f.take(7)? != MAGIC {
                return Err(bad("the main header has no `**ACE**`"));
            }
            let extract_version = f.u8()?;
            let creator_version = f.u8()?;
            let host = f.u8()?;
            let volume = f.u8()?;
            let datetime = f.u32()?;
            f.take(8)?;
            if flags & FLAG_ADVERT != 0 {
                let n = f.u8()?;
                f.take(usize::from(n))?;
            }
            let comment = if flags & FLAG_COMMENT != 0 {
                Some(f.sized()?.to_vec())
            } else {
                None
            };
            Ok(Header::Main(MainHeader {
                flags,
                extract_version,
                creator_version,
                host,
                volume,
                datetime,
                comment,
            }))
        }
        TYPE_FILE32 | TYPE_FILE64 => {
            if flags & FLAG_ADDSIZE == 0 {
                return Err(bad("a file header without a data size"));
            }
            let wide = flags & FLAG_64BIT != 0;
            if wide != (kind == TYPE_FILE64) {
                return Err(bad("a file header's sizes don't match its type"));
            }
            let (packed, size) = if wide {
                (f.u64()?, f.u64()?)
            } else {
                (u64::from(f.u32()?), u64::from(f.u32()?))
            };
            let datetime = f.u32()?;
            let attribs = f.u32()?;
            let crc = f.u32()?;
            let method = f.u8()?;
            let quality = f.u8()?;
            let params = f.u16()?;
            f.u16()?;
            let name = f.sized()?.to_vec();
            // The comment and the NT security descriptor are skipped, but must be there.
            if flags & FLAG_COMMENT != 0 {
                f.sized()?;
            }
            if flags & FLAG_NTSECURITY != 0 {
                f.sized()?;
            }
            Ok(Header::File(FileHeader {
                flags,
                packed,
                size,
                datetime,
                attribs,
                crc,
                method,
                quality,
                params,
                name,
            }))
        }
        TYPE_RECOVERY32 | TYPE_RECOVERY64A | TYPE_RECOVERY64B => {
            if flags & FLAG_ADDSIZE == 0 {
                return Err(bad("a recovery record without a data size"));
            }
            let wide = flags & FLAG_64BIT != 0;
            if wide == (kind == TYPE_RECOVERY32) {
                return Err(bad("a recovery record's sizes don't match its type"));
            }
            let addsize = if wide { f.u64()? } else { u64::from(f.u32()?) };
            Ok(Header::Other { addsize })
        }
        _ => {
            let addsize = match (flags & FLAG_ADDSIZE != 0, flags & FLAG_64BIT != 0) {
                (false, _) => 0,
                (true, true) => f.u64()?,
                (true, false) => u64::from(f.u32()?),
            };
            Ok(Header::Other { addsize })
        }
    }
}

/// A main header at the start of `head`, by its CRC-16: `**ACE**` at byte 7 alone is only
/// likely, and so is a header longer than `head`.
pub fn main_header_at(head: &[u8]) -> Option<bool> {
    if head.get(7..14)? != MAGIC {
        return None;
    }
    let crc = u16::from_le_bytes([head[0], head[1]]);
    let len = usize::from(u16::from_le_bytes([head[2], head[3]]));
    let Some(body) = head.get(4..4 + len) else {
        return Some(false);
    };
    Some(crc16(body) == crc && matches!(parse(body), Ok(Header::Main(_))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crcs_match_acefile() {
        // acefile's doctests: ace_crc32(b"123456789") and ace_crc16.
        assert_eq!(crc32(b"123456789"), 873_187_033);
        assert_eq!(crc16(b"123456789"), 50_905);
    }

    fn main_body(flags: u16) -> Vec<u8> {
        let mut h = vec![TYPE_MAIN];
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&[20, 20, 2, 0]);
        h.extend_from_slice(&0x5B89_8B8Au32.to_le_bytes());
        h.extend_from_slice(&[0; 8]);
        h
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = crc16(body).to_le_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn main_headers_are_found_by_their_crc() {
        let head = framed(&main_body(FLAG_SOLID));
        assert_eq!(main_header_at(&head), Some(true));
        let mut bad_crc = head.clone();
        bad_crc[0] ^= 1;
        assert_eq!(main_header_at(&bad_crc), Some(false));
        assert_eq!(main_header_at(&head[..20]), Some(false), "cut short");
        assert_eq!(main_header_at(b"not an ace archive"), None);
        assert_eq!(main_header_at(b""), None);
    }

    #[test]
    fn every_field_is_bounded() {
        // A file header cut at every length fails cleanly.
        let mut body = vec![TYPE_FILE32];
        body.extend_from_slice(&(FLAG_ADDSIZE | FLAG_COMMENT | FLAG_NTSECURITY).to_le_bytes());
        body.extend_from_slice(&[0; 26]);
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(b"a.b");
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(0);
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&[0, 0]);
        assert!(matches!(parse(&body), Ok(Header::File(h)) if h.name == b"a.b"));
        for n in 0..body.len() {
            assert!(parse(&body[..n]).is_err(), "{n}");
        }
        let mut main = main_body(FLAG_ADVERT | FLAG_COMMENT);
        main.extend_from_slice(&[2, b'h', b'i', 2, 0, 1, 2]);
        assert!(matches!(parse(&main), Ok(Header::Main(h)) if h.comment == Some(vec![1, 2])));
        for n in 0..main.len() {
            assert!(parse(&main[..n]).is_err(), "{n}");
        }
    }

    #[test]
    fn sizes_must_match_the_type() {
        let mut body = vec![TYPE_FILE64];
        body.extend_from_slice(&FLAG_ADDSIZE.to_le_bytes());
        body.extend_from_slice(&[0; 40]);
        assert!(parse(&body).is_err());
        body[0] = TYPE_RECOVERY64A;
        assert!(parse(&body).is_err());
        body[1] |= FLAG_64BIT as u8;
        assert_eq!(parse(&body), Ok(Header::Other { addsize: 0 }));
    }
}
