//! The malicious ARC cases (docs/M6.md §10).

use super::{DOS_DATE, DOS_TIME, crc16, len32};

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        // Names hold 12 bytes: `../`, `..\`, an absolute path, and a safe file.
        (
            "traversal.arc",
            arc(&[
                (b"../evil.txt", b"escaped"),
                (b"..\\evil2.txt", b"escaped"),
                (b"/etc/abs.txt", b"abs"),
                (b"safe.txt", b"safe"),
            ]),
        ),
    ])
}

/// An ARC of stored (method 2) entries and its end marker.
fn arc(files: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in files {
        out.extend([0x1A, 2]);
        let mut field = [0u8; 13];
        let n = name.len().min(12);
        field[..n].copy_from_slice(&name[..n]);
        out.extend(field);
        out.extend(len32(data).to_le_bytes());
        out.extend(DOS_DATE.to_le_bytes());
        out.extend(DOS_TIME.to_le_bytes());
        out.extend(crc16(data).to_le_bytes());
        out.extend(len32(data).to_le_bytes());
        out.extend(*data);
    }
    out.extend([0x1A, 0]);
    out
}
