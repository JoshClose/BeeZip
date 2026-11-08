//! The malicious ACE cases (docs/M6.md §10).

use anyhow::Context;

use super::{DOS_DATE, DOS_TIME};

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![(
        "traversal.ace",
        ace(&[
            ("../evil.txt", b"escaped"),
            ("..\\evil.txt", b"escaped"),
            ("\\etc\\beezip-abs.txt", b"absolute"),
            ("safe.txt", b"safe"),
        ])?,
    )])
}

/// ACE's CRC-32: CRC-32 without the final inversion. Its CRC-16 is the low half.
fn crc(data: &[u8]) -> u32 {
    !crc32fast::hash(data)
}

/// A header: its CRC-16 and size, then `body`.
fn framed(body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let len = u16::try_from(body.len()).context("an ACE header over 64 KiB")?;
    let mut out = (crc(body) as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// An ACE archive of stored files: a main header, then each file's header and data.
fn ace(files: &[(&str, &[u8])]) -> anyhow::Result<Vec<u8>> {
    let datetime = (u32::from(DOS_DATE) << 16) | u32::from(DOS_TIME);
    let mut main = vec![0u8]; // the main header
    main.extend_from_slice(&0u16.to_le_bytes());
    main.extend_from_slice(b"**ACE**");
    main.extend_from_slice(&[20, 20, 2, 0]); // versions 2.0, Win32, part 0
    main.extend_from_slice(&datetime.to_le_bytes());
    main.extend_from_slice(&[0; 8]);
    let mut out = framed(&main)?;
    for (name, data) in files {
        let size = u32::try_from(data.len()).context("an ACE entry over 4 GiB")?;
        let name_len = u16::try_from(name.len()).context("an ACE name over 64 KiB")?;
        let mut h = vec![1u8]; // a 32-bit file header
        h.extend_from_slice(&1u16.to_le_bytes()); // ADDSIZE: data follows
        h.extend_from_slice(&size.to_le_bytes()); // packed
        h.extend_from_slice(&size.to_le_bytes()); // original
        h.extend_from_slice(&datetime.to_le_bytes());
        h.extend_from_slice(&0x20u32.to_le_bytes()); // archive attribute
        h.extend_from_slice(&crc(data).to_le_bytes());
        h.extend_from_slice(&[0, 0]); // stored
        h.extend_from_slice(&0x000Au16.to_le_bytes()); // a 1 MiB dictionary
        h.extend_from_slice(&[0, 0]);
        h.extend_from_slice(&name_len.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        out.extend(framed(&h)?);
        out.extend_from_slice(data);
    }
    Ok(out)
}
