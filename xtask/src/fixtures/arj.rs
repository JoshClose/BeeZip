//! The malicious ARJ cases (docs/M6.md §10): names that climb out of the destination, and a
//! header whose sizes run past the end of the file.

use super::{DOS_DATE, DOS_TIME};

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        (
            "traversal.arj",
            archive(&[
                File::stored(b"../evil.txt", b"escaped"),
                File::stored(b"..\\evil2.txt", b"escaped"),
                File::stored(b"/tmp/beezip-abs.txt", b"abs"),
                File::stored(b"safe.txt", b"safe"),
            ])?,
        ),
        (
            // 4 GiB packed and unpacked, claimed by a file of 160 bytes.
            "past-end.arj",
            archive(&[
                File {
                    claim: Some((u32::MAX, u32::MAX)),
                    ..File::stored(b"huge.bin", b"tiny")
                },
                File::stored(b"after.txt", b"never reached"),
            ])?,
        ),
    ])
}

/// MS-DOS, so the times are DOS times.
const HOST_DOS: u8 = 0;

struct File<'a> {
    name: &'a [u8],
    data: &'a [u8],
    /// Packed and original sizes to claim instead of the data's.
    claim: Option<(u32, u32)>,
}

impl<'a> File<'a> {
    fn stored(name: &'a [u8], data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            claim: None,
        }
    }
}

/// A basic header around `b`, with its CRC-32 and no extended headers.
fn basic(b: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0x60, 0xEA];
    out.extend_from_slice(&u16::try_from(b.len())?.to_le_bytes());
    out.extend_from_slice(b);
    out.extend_from_slice(&crc32fast::hash(b).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    Ok(out)
}

fn archive(files: &[File<'_>]) -> anyhow::Result<Vec<u8>> {
    let time = (u32::from(DOS_DATE) << 16) | u32::from(DOS_TIME);
    // Main header: 34 bytes of fields, the archive's name, an empty comment.
    let mut m = vec![34u8, 11, 1, HOST_DOS, 0, 0, 2, 0];
    m.extend_from_slice(&time.to_le_bytes());
    m.extend_from_slice(&time.to_le_bytes());
    m.extend_from_slice(&[0; 18]);
    m.extend_from_slice(b"MALICIOUS.ARJ\0\0");
    let mut out = basic(&m)?;
    for f in files {
        let size = u32::try_from(f.data.len())?;
        let (packed, original) = f.claim.unwrap_or((size, size));
        // Local header: 30 bytes of fields, stored, a binary file, archive attribute.
        let mut h = vec![30u8, 11, 1, HOST_DOS, 0, 0, 0, 0];
        h.extend_from_slice(&time.to_le_bytes());
        h.extend_from_slice(&packed.to_le_bytes());
        h.extend_from_slice(&original.to_le_bytes());
        h.extend_from_slice(&crc32fast::hash(f.data).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&0x20u16.to_le_bytes());
        h.extend_from_slice(&[0, 0]);
        h.extend_from_slice(f.name);
        h.extend_from_slice(&[0, 0]);
        out.extend(basic(&h)?);
        out.extend_from_slice(f.data);
    }
    out.extend_from_slice(&[0x60, 0xEA, 0, 0]);
    Ok(out)
}
