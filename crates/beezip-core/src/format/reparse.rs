//! Reparse points, as NTFS (docs/M7.md §6) and WIM images (docs/M8.md §5.2) keep them: a tag,
//! then data whose layout the tag gives. NTFS stores the whole `$REPARSE_POINT` value (the tag,
//! the data's length, then the data: [`decode_value`]); a WIM keeps the tag in its directory
//! entry and the data alone in a blob ([`decode`]).
//!
//! - Symlinks, junctions and WSL symlinks become links to their targets as stored, `\` made `/`
//!   (a junction's `\??\C:\…` stays recognisable, as `/??/C:/…`); `FsSink` judges them like any
//!   other link.
//! - WSL's FIFOs, devices and sockets are special files.
//! - Files Windows compressed (WOF) or deduplicated keep their data elsewhere: the reader says
//!   what they are, and whether it can decode them.
//!
//! Nothing here may panic, whatever the bytes.

use super::volume::wof::Algorithm;

/// What a reparse point makes of its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reparse {
    /// A symlink, junction or WSL symlink, with its target as stored, `\` made `/`.
    Link(String),
    /// WSL's FIFOs, devices and sockets.
    Special,
    /// Compressed by Windows (WOF), with the method's name and, for the file provider's
    /// algorithms BeeZip decodes, the algorithm.
    Wof(&'static str, Option<Algorithm>),
    /// Deduplicated by Windows Server: the data is in a chunk store elsewhere.
    Dedup,
    /// A link whose target can't be read.
    Bad,
    /// A tag BeeZip leaves alone: the file reads as stored.
    Other,
}

pub const TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const TAG_SYMLINK: u32 = 0xA000_000C;
pub const TAG_DEDUP: u32 = 0x8000_0013;
pub const TAG_WOF: u32 = 0x8000_0017;
pub const TAG_LX_SYMLINK: u32 = 0xA000_001D;
pub const TAG_AF_UNIX: u32 = 0x8000_0023;
pub const TAG_LX_FIFO: u32 = 0x8000_0024;
pub const TAG_LX_CHR: u32 = 0x8000_0025;
pub const TAG_LX_BLK: u32 = 0x8000_0026;

/// A symlink's flag: its target is relative to the link's folder.
pub const SYMLINK_FLAG_RELATIVE: u32 = 1;

/// The most data a reparse point holds, as Windows bounds it
/// (`MAXIMUM_REPARSE_DATA_BUFFER_SIZE`).
pub const MAX_DATA: u64 = 16 * 1024;

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// UTF-16LE, an unpaired surrogate read as U+FFFD; an odd last byte is dropped.
pub fn utf16(b: &[u8]) -> String {
    char::decode_utf16(b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)))
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// A link target as stored: UTF-16 or UTF-8, `\` made `/`. Empty or holding NUL is no target.
pub fn target(t: String) -> Reparse {
    if t.is_empty() || t.contains('\0') {
        Reparse::Bad
    } else {
        Reparse::Link(t.replace('\\', "/"))
    }
}

/// An NTFS `$REPARSE_POINT` value: its tag, the length of its data, then the data.
pub fn decode_value(v: &[u8]) -> Reparse {
    let len = usize::from(le16(v, 4));
    let data = v.get(8..).map_or(&[][..], |d| &d[..len.min(d.len())]);
    decode(le32(v, 0), data)
}

/// A reparse point of tag `tag` whose data (after the 8-byte header of the reparse buffer) is
/// `data`.
pub fn decode(tag: u32, data: &[u8]) -> Reparse {
    // Substitute and print names, as offsets and lengths into the path buffer at `buf`.
    let names = |buf: usize| -> Option<String> {
        let path = data.get(buf..)?;
        let name = |off: usize, n: usize| -> Option<String> {
            path.get(usize::from(le16(data, off))..)?
                .get(..usize::from(le16(data, n)))
                .map(utf16)
        };
        let subst = name(0, 2).unwrap_or_default();
        Some(if subst.is_empty() { name(4, 6)? } else { subst })
    };
    match tag {
        TAG_SYMLINK if data.len() >= 12 => names(12).map_or(Reparse::Bad, target),
        TAG_MOUNT_POINT if data.len() >= 8 => names(8).map_or(Reparse::Bad, target),
        // A version (2), then the target in UTF-8.
        TAG_LX_SYMLINK if data.len() > 4 => {
            target(String::from_utf8_lossy(&data[4..]).into_owned())
        }
        TAG_SYMLINK | TAG_MOUNT_POINT | TAG_LX_SYMLINK => Reparse::Bad,
        TAG_AF_UNIX | TAG_LX_FIFO | TAG_LX_CHR | TAG_LX_BLK => Reparse::Special,
        // WOF's version and provider; the file provider's version and algorithm.
        TAG_WOF => {
            let name = match (le32(data, 4), le32(data, 12)) {
                (1, _) => "WIM",
                (2, 0) => "XPRESS4K",
                (2, 1) => "LZX",
                (2, 2) => "XPRESS8K",
                (2, 3) => "XPRESS16K",
                _ => "WOF",
            };
            // WOF version 1, the file provider (2), its version 1: an algorithm BeeZip decodes.
            let algo = (data.len() >= 16
                && le32(data, 0) == 1
                && le32(data, 4) == 2
                && le32(data, 8) == 1)
                .then(|| Algorithm::from_id(le32(data, 12)))
                .flatten();
            Reparse::Wof(name, algo)
        }
        TAG_DEDUP => Reparse::Dedup,
        _ => Reparse::Other,
    }
}

/// Whether a symlink's data says its target is relative (`SYMLINK_FLAG_RELATIVE`).
pub fn symlink_is_relative(tag: u32, data: &[u8]) -> bool {
    tag == TAG_SYMLINK && le32(data, 8) & SYMLINK_FLAG_RELATIVE != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reparse_points() {
        fn names(subst: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
            let s: Vec<u8> = subst.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let p: Vec<u8> = print.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let mut d = Vec::new();
            for n in [0, s.len(), s.len(), p.len()] {
                d.extend_from_slice(&(n as u16).to_le_bytes());
            }
            if let Some(f) = flags {
                d.extend_from_slice(&f.to_le_bytes());
            }
            d.extend_from_slice(&s);
            d.extend_from_slice(&p);
            d
        }
        fn value(tag: u32, data: &[u8]) -> Vec<u8> {
            let mut v = tag.to_le_bytes().to_vec();
            v.extend_from_slice(&(data.len() as u16).to_le_bytes());
            v.extend_from_slice(&[0, 0]);
            v.extend_from_slice(data);
            v
        }
        let link = |t: &str| Reparse::Link(t.into());
        let cases = [
            (
                value(TAG_SYMLINK, &names(r"a\b.txt", r"a\b.txt", Some(1))),
                link("a/b.txt"),
            ),
            (
                value(TAG_SYMLINK, &names(r"\??\C:\x", r"C:\x", Some(0))),
                link("/??/C:/x"),
            ),
            // No substitute name: the print name.
            (value(TAG_SYMLINK, &names("", "p", Some(1))), link("p")),
            (
                value(TAG_MOUNT_POINT, &names(r"\??\C:\Users", r"C:\Users", None)),
                link("/??/C:/Users"),
            ),
            (value(TAG_LX_SYMLINK, b"\x02\0\0\0../up"), link("../up")),
            (value(TAG_LX_SYMLINK, b"\x02\0\0\0a\0b"), Reparse::Bad),
            (value(TAG_SYMLINK, &names("", "", Some(0))), Reparse::Bad),
            (value(TAG_LX_FIFO, b""), Reparse::Special),
            (
                value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0]),
                Reparse::Wof("XPRESS16K", Some(Algorithm::Xpress16k)),
            ),
            (
                value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]),
                Reparse::Wof("LZX", Some(Algorithm::Lzx)),
            ),
            // Another provider version, or an algorithm BeeZip doesn't know: named, not decoded.
            (
                value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]),
                Reparse::Wof("LZX", None),
            ),
            (
                value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0]),
                Reparse::Wof("WOF", None),
            ),
            (
                value(TAG_WOF, &[1, 0, 0, 0, 1, 0, 0, 0]),
                Reparse::Wof("WIM", None),
            ),
            (value(TAG_DEDUP, b""), Reparse::Dedup),
            (value(0x9000_001A, b"cloud"), Reparse::Other),
        ];
        for (v, want) in &cases {
            assert_eq!(decode_value(v), *want);
            // The same data without NTFS's header, as a WIM keeps it.
            assert_eq!(decode(le32(v, 0), &v[8..]), *want);
            // Cut anywhere, or with lengths past the value: no panic.
            for n in 0..v.len() {
                let _ = decode_value(&v[..n]);
                let mut w = v[..n].to_vec();
                w.extend_from_slice(&[0xFF; 16]);
                let _ = decode_value(&w);
                let _ = decode(TAG_SYMLINK, &w);
                let _ = decode(TAG_MOUNT_POINT, &w);
            }
        }
        // An offset past the buffer.
        let mut v = value(TAG_SYMLINK, &names("abc", "abc", Some(0)));
        v[8..10].copy_from_slice(&0xFFF0u16.to_le_bytes());
        assert_eq!(decode_value(&v), link("abc"));
        v[12..14].copy_from_slice(&0xFFF0u16.to_le_bytes());
        assert_eq!(decode_value(&v), Reparse::Bad);
        // The relative flag.
        let rel = names("a", "a", Some(1));
        assert!(symlink_is_relative(TAG_SYMLINK, &rel));
        assert!(!symlink_is_relative(TAG_SYMLINK, &names("a", "a", Some(0))));
        assert!(!symlink_is_relative(TAG_MOUNT_POINT, &rel));
    }

    #[test]
    fn utf16_reads_unpaired_surrogates_as_replacements() {
        assert_eq!(utf16(&[0x61, 0, 0x00, 0xD8, 0x62, 0]), "a\u{FFFD}b");
        assert_eq!(utf16(&[0x61, 0, 0x62]), "a");
    }
}
