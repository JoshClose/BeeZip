//! The malicious ZOO cases (docs/M6.md §10).

use super::{DOS_DATE, DOS_TIME, crc16, len32};

const TAG: u32 = 0xFDC4_A7DC;
/// A type-2 directory entry's fixed part.
const DIRENT: usize = 56;

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        // `..` as a folder, `..\` in a long name, an absolute folder, and a safe file.
        (
            "traversal.zoo",
            zoo(&[
                (b"..", b"evil.txt", b"escaped"),
                (b"", b"..\\evil2.txt", b"escaped"),
                (b"/etc", b"beezip-abs.txt", b"abs"),
                (b"", b"safe.txt", b"safe"),
            ]),
        ),
        ("cycle.zoo", cycle()),
    ])
}

/// A ZOO 2.x archive of stored type-2 entries, `(folder, long name, data)`, each one's data
/// after it, and the empty entry that ends the chain.
fn zoo(files: &[(&[u8], &[u8], &[u8])]) -> Vec<u8> {
    let mut out = b"ZOO 2.10 Archive.\x1a\0\0".to_vec();
    out.extend(TAG.to_le_bytes());
    out.extend(42u32.to_le_bytes());
    out.extend(42u32.wrapping_neg().to_le_bytes());
    out.extend([2, 0, 1, 0, 0, 0, 0, 0, 0, 3]);
    for (dir, name, data) in files {
        let with_nul = |b: &[u8]| {
            let mut v = b.to_vec();
            if !v.is_empty() {
                v.push(0);
            }
            v
        };
        let (name, dir) = (with_nul(name), with_nul(dir));
        let mut var = vec![
            u8::try_from(name.len()).unwrap_or(u8::MAX),
            u8::try_from(dir.len()).unwrap_or(u8::MAX),
        ];
        var.extend(&name);
        var.extend(&dir);
        // Unix, rw-r--r--, no generations.
        var.extend([0, 0, 0xA4, 0x01, 0x40, 0, 0, 0]);
        let offset = len32(&out) + len32(&var) + len32(&[0u8; DIRENT]);
        out.extend(TAG.to_le_bytes());
        out.extend([2, 0]);
        out.extend((offset + len32(data)).to_le_bytes());
        out.extend(offset.to_le_bytes());
        out.extend(DOS_DATE.to_le_bytes());
        out.extend(DOS_TIME.to_le_bytes());
        out.extend(crc16(data).to_le_bytes());
        out.extend(len32(data).to_le_bytes());
        out.extend(len32(data).to_le_bytes());
        out.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend(b"ZOO.TXT\0\0\0\0\0\0");
        out.extend(u16::try_from(var.len()).unwrap_or(u16::MAX).to_le_bytes());
        // No time zone.
        out.push(127);
        out.extend([0, 0]);
        out.extend(&var);
        out.extend(*data);
    }
    out.extend(TAG.to_le_bytes());
    out.extend([2, 0]);
    out.extend([0; DIRENT - 6 + 10]);
    out
}

/// Two entries whose directory chain loops: the second's `next` is the first.
fn cycle() -> Vec<u8> {
    let mut v = zoo(&[(b"", b"a.txt", b"one"), (b"", b"b.txt", b"two")]);
    // The second entry follows the first's 56 + 16 bytes of header and 3 of data.
    let second = 42 + DIRENT + 2 + 6 + 8 + 3;
    v[second + 6..second + 10].copy_from_slice(&42u32.to_le_bytes());
    v
}
