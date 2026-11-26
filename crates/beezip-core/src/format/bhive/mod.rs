//! `.bhive`, BeeZip's own archive format (docs/M13.md). docs/bhive.md is its specification, and
//! `layout.rs` is that specification as code.
//!
//! - **Cells:** the files' bytes are packed in the order given into cells of a few MiB, each
//!   compressed alone (stored, zstd or LZMA2) and checked by an XXH3-64. Any file comes out by
//!   decoding the cells it has bytes in, and every core works in both directions.
//! - **Extents:** a file is a list of runs, each in one cell. A chunk of content that was
//!   stored before becomes an extent into the cell that holds it (`chunk.rs`, `write.rs`).
//! - **The index** comes last, with a footer that points to it; a record before each cell
//!   repeats enough to list and extract the cells before a cut (`read.rs`).

#[doc(hidden)]
pub mod build;
mod chunk;
mod coder;
pub mod crypt;
pub mod layout;
mod mem;
mod par;
mod read;
pub mod sign;
#[cfg(test)]
mod tests;
mod write;

pub use coder::Level;
pub use read::BhiveReader;
pub use write::{BhiveWriteOptions, BhiveWriter};

use super::{ArchiveFormat, FormatCaps, FormatId};
use crate::detect::{Confidence, Probe};

pub struct Bhive;

impl ArchiveFormat for Bhive {
    fn id(&self) -> FormatId {
        FormatId::Bhive
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".bhive"]
    }

    /// The magic, and a version that is one: the eight bytes are BeeZip's alone, with a high
    /// bit and a line ending that no text has.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        if !probe.head.starts_with(&layout::MAGIC) {
            return None;
        }
        match probe.head.get(8..10) {
            Some(v) if v != [0, 0] => Some(Confidence::Certain),
            _ => Some(Confidence::Likely),
        }
    }

    /// Everything, encryption included (docs/bhive.md §12): an encrypted `.bhive` seals its
    /// names too. An edit copies the cells it keeps as they are.
    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            append: true,
            delete: true,
            rename: true,
            encrypt: true,
            encrypt_headers: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}
