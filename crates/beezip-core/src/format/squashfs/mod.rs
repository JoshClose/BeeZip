//! squashfs (docs/M5.md §5.10): BeeZip's own reader, and backhand's writer with BeeZip's codecs.

mod codec;
mod read;
mod write;

pub use read::SquashfsReader;
pub use write::SquashfsWriter;

use super::{ArchiveFormat, FormatCaps, FormatId};
use crate::detect::{Confidence, Probe};

pub struct Squashfs;

/// `hsqs`: a little-endian superblock.
pub const MAGIC: &[u8; 4] = b"hsqs";
/// `sqsh`: a big-endian one, which BeeZip refuses.
pub const MAGIC_BE: &[u8; 4] = b"sqsh";

impl ArchiveFormat for Squashfs {
    fn id(&self) -> FormatId {
        FormatId::Squashfs
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".squashfs", ".sqfs", ".snap"]
    }

    /// The magic with version 4.0 is certain. A big-endian image, or another version, is likely,
    /// so it opens to be refused with a reason.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let h = probe.head;
        if h.starts_with(MAGIC_BE) {
            return Some(Confidence::Likely);
        }
        if !h.starts_with(MAGIC) {
            return None;
        }
        let version = h.get(28..32).map(|v| {
            (
                u16::from_le_bytes([v[0], v[1]]),
                u16::from_le_bytes([v[2], v[3]]),
            )
        });
        match version {
            Some((4, 0)) => Some(Confidence::Certain),
            _ => Some(Confidence::Likely),
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

/// The compressors BeeZip writes squashfs with (`method`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SquashfsMethod {
    /// mksquashfs's default, read by every kernel and by 7-Zip.
    #[default]
    Gzip,
    Xz,
    Zstd,
    /// 7-Zip 26.00 can't read lz4 squashfs.
    Lz4,
    Lzo,
}

impl SquashfsMethod {
    pub const ALL: [SquashfsMethod; 5] = [Self::Gzip, Self::Xz, Self::Zstd, Self::Lz4, Self::Lzo];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
            Self::Lzo => "lzo",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }

    /// The levels it takes: gzip's and zstd's as mksquashfs gives them (`-Xcompression-level`),
    /// xz's presets. lz4 and lzo have none here.
    pub const fn levels(self) -> Option<crate::Levels> {
        let (min, max, default) = match self {
            Self::Gzip => (1, 9, 9),
            Self::Xz => (0, 9, 6),
            Self::Zstd => (1, 22, 15),
            Self::Lz4 | Self::Lzo => return None,
        };
        Some(crate::Levels { min, max, default })
    }

    /// `level` checked against [`SquashfsMethod::levels`]: the level to use, or `None` for a
    /// method without levels. Out of range, or given to lz4 or lzo, is `InvalidArgs`.
    pub fn resolve_level(self, level: Option<i32>) -> crate::Result<Option<i32>> {
        match (self.levels(), level) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(crate::Error::invalid_args(format!(
                "squashfs {} has no levels",
                self.name()
            ))),
            (Some(l), None) => Ok(Some(l.default)),
            (Some(l), Some(n)) if (l.min..=l.max).contains(&n) => Ok(Some(n)),
            (Some(l), Some(n)) => Err(crate::Error::invalid_args(format!(
                "level {n} is out of range for squashfs {} ({}–{})",
                self.name(),
                l.min,
                l.max
            ))),
        }
    }
}

/// How to write a squashfs image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SquashfsWriteOptions {
    pub method: SquashfsMethod,
    /// The compressor's level, where it has one; `None` for its default.
    pub level: Option<i32>,
}
