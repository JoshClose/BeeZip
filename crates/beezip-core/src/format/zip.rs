//! ZIP, through the `zip` crate (=9.2.2). This is the only file that names `zip::`.

use super::{ArchiveFormat, FormatCaps, FormatId};
use crate::detect::{Confidence, Probe};

pub struct Zip;

const LOCAL: &[u8; 4] = b"PK\x03\x04";
const EOCD: &[u8; 4] = b"PK\x05\x06";
const SPANNED: &[u8; 4] = b"PK\x07\x08";

impl ArchiveFormat for Zip {
    fn id(&self) -> FormatId {
        FormatId::Zip
    }

    fn extensions(&self) -> &'static [&'static str] {
        // Formats that are zips underneath open as zips.
        &[
            ".zip", ".jar", ".war", ".apk", ".aab", ".ipa", ".xpi", ".vsix", ".nupkg", ".whl",
            ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".appx", ".msix",
        ]
    }

    /// `PK\3\4` with an end-of-central-directory record in the tail, an empty archive (just
    /// the EOCD), or an executable with an EOCD in its tail (a zip SFX).
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let head = probe.head;
        let eocd = eocd_in(probe.tail).is_some();
        if head.starts_with(LOCAL) || (head.starts_with(SPANNED) && head[4..].starts_with(LOCAL)) {
            // Inside a codec there is no tail to check, so it stays likely.
            return Some(if eocd {
                Confidence::Certain
            } else {
                Confidence::Likely
            });
        }
        if head.starts_with(EOCD) && eocd_in(head).is_some() {
            return Some(Confidence::Certain);
        }
        is_sfx(probe).then_some(Confidence::Certain)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            encrypt: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}

/// An executable (`MZ`) whose tail holds a zip end-of-central-directory record.
pub fn is_sfx(probe: &Probe<'_>) -> bool {
    probe.head.starts_with(b"MZ") && eocd_in(probe.tail).is_some()
}

/// The offset of the last EOCD record in `buf` whose comment fits in what follows it.
fn eocd_in(buf: &[u8]) -> Option<usize> {
    if buf.len() < 22 {
        return None;
    }
    (0..=buf.len() - 22).rev().find(|&i| {
        &buf[i..i + 4] == EOCD && {
            let comment = usize::from(u16::from_le_bytes([buf[i + 20], buf[i + 21]]));
            i + 22 + comment <= buf.len()
        }
    })
}
