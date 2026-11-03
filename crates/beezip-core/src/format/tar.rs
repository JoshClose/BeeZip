//! TAR, through the `tar` crate (0.4.46). This is the only file that names `tar::`.

use super::{ArchiveFormat, FormatCaps, FormatId};
use crate::detect::{Confidence, Probe};

pub struct Tar;

impl ArchiveFormat for Tar {
    fn id(&self) -> FormatId {
        FormatId::Tar
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".tar"]
    }

    /// `ustar` at offset 257 with a valid header checksum is certain; the magic alone, or a
    /// valid checksum on a v7 header without it, is likely.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let header = probe.head.get(..512)?;
        let magic = header[257..262] == *b"ustar";
        let checksum = checksum_ok(header);
        match (magic, checksum) {
            (true, true) => Some(Confidence::Certain),
            (true, false) => Some(Confidence::Likely),
            (false, true) if v7_plausible(header) => Some(Confidence::Likely),
            _ => None,
        }
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}

/// The header checksum: the byte sum with the checksum field read as spaces. Some old tars
/// summed signed bytes, so both sums are accepted.
fn checksum_ok(header: &[u8]) -> bool {
    let Some(stored) = octal(&header[148..156]) else {
        return false;
    };
    let field = 148..156;
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in header.iter().enumerate() {
        let b = if field.contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b.cast_signed());
    }
    // An all-zero block sums to 256 (the spaces); that is an end marker, not a header.
    unsigned != 256 && (stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed))
}

/// A v7 header has a name and octal mode, size and mtime fields.
fn v7_plausible(header: &[u8]) -> bool {
    header[0] != 0
        && octal(&header[100..108]).is_some()
        && octal(&header[124..136]).is_some()
        && octal(&header[136..148]).is_some()
}

/// An octal field: optional leading spaces, digits, then NUL or space padding.
fn octal(field: &[u8]) -> Option<u64> {
    let s = field
        .iter()
        .skip_while(|&&b| b == b' ')
        .take_while(|&&b| b != 0 && b != b' ')
        .copied()
        .collect::<Vec<_>>();
    if s.is_empty() || !s.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return None;
    }
    s.iter().try_fold(0u64, |acc, &d| {
        acc.checked_mul(8)?.checked_add(u64::from(d - b'0'))
    })
}
