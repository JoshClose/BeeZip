//! A bare compressed file (`notes.txt.gz`) seen as an archive with one entry.

use super::{ArchiveFormat, FormatCaps, FormatId};
use crate::detect::{Confidence, Probe};

pub struct Stream;

impl ArchiveFormat for Stream {
    fn id(&self) -> FormatId {
        FormatId::Stream
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    /// Never sniffed: it is what's left when a codec's output isn't an archive.
    fn sniff(&self, _: &Probe<'_>) -> Option<Confidence> {
        None
    }

    /// Created through `stream.compress`, not `archive.create`.
    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}
