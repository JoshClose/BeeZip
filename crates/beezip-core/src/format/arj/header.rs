//! ARJ's headers (ARJ 3.10's TECHNOTE.TXT). Every one is a basic header (`60 EA`, a 16-bit size
//! of at most 2 600 bytes, the bytes, their CRC-32), then extended headers (a 16-bit size, the
//! bytes, their CRC-32) up to one of size 0. A basic header holds its fixed fields (their length
//! is its first byte), then a name and a comment, each ending in a NUL.
//!
//! unarc-rs read the fields one after another with unchecked macros, and the name right after the
//! fields it knew: crafted 9–58-byte files with valid CRCs panicked it (docs/M6.md §16). Here the
//! fixed part is checked against the header's size before any field is read, and the name starts
//! where the first byte says.

use std::io::{self, Read};

use crate::{Error, Result};

/// The two bytes every header starts with.
pub const ID: [u8; 2] = [0x60, 0xEA];
/// The largest basic header ARJ writes or reads (`HEADERSIZE_MAX`).
pub const MAX_BASIC: usize = 2600;
/// The fixed fields every header has, through the last chapter (`STD_HDR_SIZE`).
pub const FIXED: usize = 30;
/// The fixed fields with a local header's extended file position, which a piece of a file split
/// between volumes needs.
const WITH_EXT_POS: usize = 34;

/// Flags: a local header's data is garbled (a main header's: some entry's is).
pub const GARBLED: u8 = 0x01;
/// The file goes on in the next part (a main header's: the next part exists).
pub const VOLUME: u8 = 0x04;
/// This piece of a file goes on from the previous part, at the extended file position.
pub const EXT_FILE: u8 = 0x08;

/// File types.
pub const BINARY: u8 = 0;
pub const TEXT: u8 = 1;
pub const MAIN: u8 = 2;
pub const DIR: u8 = 3;

const OS_UNIX: u8 = 2;
const OS_NEXT: u8 = 8;

/// Hosts whose times are Unix times, as ARJ 3.10's `is_unix` tells them; the rest store DOS
/// times.
pub fn unix_host(os: u8) -> bool {
    os == OS_UNIX || os == OS_NEXT
}

/// The main header at the start of each part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Main {
    pub flags: u8,
    /// The encryption version: 0 and 1 are garble, 2 and up GOST.
    pub encryption: u8,
    pub comment: Vec<u8>,
}

/// The header before an entry's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    pub host_os: u8,
    pub flags: u8,
    pub method: u8,
    pub file_type: u8,
    /// Garble's password modifier.
    pub modifier: u8,
    pub time: u32,
    pub packed: u32,
    pub size: u32,
    pub crc: u32,
    /// DOS attributes, or for a Unix host ARJ's own type bits (0x1000 a file, 0x2000 a folder)
    /// over the permissions.
    pub mode: u16,
    /// Where this piece starts in the whole file, for one split between volumes; 0 when absent.
    pub ext_pos: u32,
    pub name: Vec<u8>,
}

fn corrupt(what: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("arj: {what}"))
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The length of the fixed fields, checked: at least [`FIXED`], at most the header.
fn fixed_len(b: &[u8]) -> Result<usize> {
    let first = b.first().map_or(0, |&f| usize::from(f));
    if first < FIXED || first > b.len() {
        return Err(corrupt(format!(
            "a header's fixed part is {first} bytes in {}",
            b.len()
        )));
    }
    Ok(first)
}

/// The name and the comment after the fixed fields. The name must end in a NUL; the comment
/// ends at one or at the header's end.
fn strings(b: &[u8], first: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    let rest = b.get(first..).unwrap_or_default();
    let end = rest
        .iter()
        .position(|&c| c == 0)
        .ok_or_else(|| corrupt("a name in a header doesn't end"))?;
    let comment = rest[end + 1..]
        .split(|&c| c == 0)
        .next()
        .unwrap_or_default();
    Ok((rest[..end].to_vec(), comment.to_vec()))
}

impl Main {
    pub fn parse(b: &[u8]) -> Result<Self> {
        let first = fixed_len(b)?;
        if b[6] != MAIN {
            return Err(corrupt("the archive doesn't start with a main header"));
        }
        let (_, comment) = strings(b, first)?;
        Ok(Self {
            flags: b[4],
            encryption: b[28],
            comment,
        })
    }
}

impl Local {
    pub fn parse(b: &[u8]) -> Result<Self> {
        let first = fixed_len(b)?;
        let (name, _) = strings(b, first)?;
        Ok(Self {
            host_os: b[3],
            flags: b[4],
            method: b[5],
            file_type: b[6],
            modifier: b[7],
            time: u32_at(b, 8),
            packed: u32_at(b, 12),
            size: u32_at(b, 16),
            crc: u32_at(b, 20),
            mode: u16_at(b, 26),
            ext_pos: if first >= WITH_EXT_POS {
                u32_at(b, 30)
            } else {
                0
            },
            name,
        })
    }
}

/// `read_exact`, with the end of the input as "cut short".
fn fill(r: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            corrupt("the archive is cut short")
        } else {
            crate::io::read_error(&e).context("arj")
        }
    })
}

/// Reads up to `buf.len()` bytes, fewer only at the end of the input.
fn fill_some(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(crate::io::read_error(&e).context("arj")),
        }
    }
    Ok(n)
}

/// Reads a basic header, checking its CRC, and the extended headers after it, checking theirs.
/// `None` at the end of a part: a header of size 0, or the end of the input where a header
/// would start.
pub fn read(r: &mut dyn Read) -> Result<Option<Vec<u8>>> {
    let mut start = [0u8; 4];
    match fill_some(r, &mut start)? {
        0 => return Ok(None),
        4 => {}
        _ => return Err(corrupt("the archive is cut short")),
    }
    if start[..2] != ID {
        return Err(corrupt("no header where one should be"));
    }
    let size = usize::from(u16::from_le_bytes([start[2], start[3]]));
    if size == 0 {
        return Ok(None);
    }
    if size > MAX_BASIC {
        return Err(corrupt(format!(
            "a header of {size} bytes (ARJ's are at most {MAX_BASIC})"
        )));
    }
    let mut b = vec![0u8; size + 4];
    fill(r, &mut b)?;
    let stored = u32::from_le_bytes([b[size], b[size + 1], b[size + 2], b[size + 3]]);
    b.truncate(size);
    if crc32fast::hash(&b) != stored {
        return Err(corrupt("a header doesn't match its CRC-32"));
    }
    skip_extended(r)?;
    Ok(Some(b))
}

/// Reads the extended headers, checking each one's CRC without keeping it: BeeZip uses none.
fn skip_extended(r: &mut dyn Read) -> Result<()> {
    let mut buf = [0u8; 512];
    loop {
        let mut size = [0u8; 2];
        fill(r, &mut size)?;
        let mut left = usize::from(u16::from_le_bytes(size));
        if left == 0 {
            return Ok(());
        }
        let mut crc = crc32fast::Hasher::new();
        while left > 0 {
            let n = left.min(buf.len());
            fill(r, &mut buf[..n])?;
            crc.update(&buf[..n]);
            left -= n;
        }
        let mut stored = [0u8; 4];
        fill(r, &mut stored)?;
        if crc.finalize() != u32::from_le_bytes(stored) {
            return Err(corrupt("an extended header doesn't match its CRC-32"));
        }
    }
}

/// A main header at the start of `head`: the id, a size within ARJ's limit, the CRC-32, a fixed
/// part that fits, and the main header's file type. Detection's check.
pub fn main_at(head: &[u8]) -> bool {
    if !head.starts_with(&ID) || head.len() < 4 {
        return false;
    }
    let size = usize::from(u16::from_le_bytes([head[2], head[3]]));
    if size == 0 || size > MAX_BASIC {
        return false;
    }
    let (Some(b), Some(stored)) = (head.get(4..4 + size), head.get(4 + size..8 + size)) else {
        return false;
    };
    crc32fast::hash(b) == u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]])
        && Main::parse(b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A basic header around `fields` (the first byte is set to their length) and `strings`.
    fn basic(fields: &[u8], strings: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 0];
        b.push(u8::try_from(fields.len() + 1).unwrap());
        b.extend_from_slice(fields);
        b.extend_from_slice(strings);
        let mut out = ID.to_vec();
        out.extend_from_slice(&u16::try_from(b.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&b);
        out.extend_from_slice(&crc32fast::hash(&b).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn main_fields() -> Vec<u8> {
        let mut f = vec![0u8; FIXED - 1];
        f[5] = MAIN;
        f
    }

    #[test]
    fn reads_a_main_header() {
        let mut f = main_fields();
        f[3] = VOLUME;
        f[27] = 1;
        let h = basic(&f, b"x.arj\0a comment\0");
        assert!(main_at(&h));
        let b = read(&mut &h[..]).unwrap().unwrap();
        let m = Main::parse(&b).unwrap();
        assert_eq!(m.flags, VOLUME);
        assert_eq!(m.encryption, 1);
        assert_eq!(m.comment, b"a comment");
    }

    #[test]
    fn the_name_starts_where_the_first_byte_says() {
        // 33 bytes of fixed fields, as no ARJ writes, then the name.
        let mut f = vec![0u8; 33];
        f[11..15].copy_from_slice(&7u32.to_le_bytes());
        let h = basic(&f, b"name\0");
        let b = read(&mut &h[..]).unwrap().unwrap();
        let l = Local::parse(&b).unwrap();
        assert_eq!(l.name, b"name");
        assert_eq!(l.packed, 7);
        assert_eq!(l.ext_pos, 0, "34 bytes are needed for the position");
    }

    #[test]
    fn bad_headers_are_corrupt() {
        // Each with a valid CRC.
        let cases: [(&str, Vec<u8>); 4] = [
            ("fixed part too short", basic(&[0u8; 20], b"a\0")),
            ("no NUL after the name", basic(&main_fields(), b"name")),
            ("not a main header", basic(&[0u8; FIXED - 1], b"a\0\0")),
            ("fixed part longer than the header", {
                let mut h = basic(&main_fields(), b"");
                h[4] = 200;
                let size = usize::from(u16::from_le_bytes([h[2], h[3]]));
                let crc = crc32fast::hash(&h[4..4 + size]);
                h[4 + size..8 + size].copy_from_slice(&crc.to_le_bytes());
                h
            }),
        ];
        for (what, h) in cases {
            assert!(!main_at(&h), "{what}");
            let parsed = read(&mut &h[..]).and_then(|b| Main::parse(&b.unwrap_or_default()));
            assert_eq!(
                parsed.unwrap_err().kind,
                crate::ErrorKind::Corrupt,
                "{what}"
            );
        }
    }

    #[test]
    fn sizes_and_crcs_are_checked() {
        let mut h = basic(&main_fields(), b"a\0\0");
        h[6] ^= 1;
        assert!(!main_at(&h));
        assert!(read(&mut &h[..]).unwrap_err().message.contains("CRC"));
        let big = [0x60, 0xEA, 0x29, 0x0A];
        assert!(!main_at(&big));
        assert!(read(&mut &big[..]).unwrap_err().message.contains("2600"));
        assert_eq!(read(&mut &[0x60, 0xEA, 0, 0][..]).unwrap(), None);
        assert_eq!(read(&mut &[][..]).unwrap(), None);
        assert!(read(&mut &[0x60][..]).is_err());
        assert!(read(&mut &b"MZ\x90\0"[..]).is_err());
    }

    #[test]
    fn extended_headers_are_checked_and_skipped() {
        let mut h = basic(&main_fields(), b"a\0\0");
        h.truncate(h.len() - 2);
        let ext = b"Uextra";
        h.extend_from_slice(&6u16.to_le_bytes());
        h.extend_from_slice(ext);
        h.extend_from_slice(&crc32fast::hash(ext).to_le_bytes());
        h.extend_from_slice(&[0, 0, 0xAA]);
        let mut r = &h[..];
        assert!(read(&mut r).unwrap().is_some());
        assert_eq!(r, [0xAA]);
        let at = h.len() - 4;
        h[at - 1] ^= 1;
        assert!(read(&mut &h[..]).unwrap_err().message.contains("extended"));
    }
}
