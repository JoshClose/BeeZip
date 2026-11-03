//! Format detection (docs/M1.md §3.3).

/// How sure a sniffer is. `Guess` is an extension match only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Guess,
    /// Magic bytes only.
    Likely,
    /// Magic bytes plus a structural check, such as the tar header checksum.
    Certain,
}

/// What sniffers look at.
#[derive(Debug, Clone, Copy, Default)]
pub struct Probe<'a> {
    /// The first bytes, up to [`HEAD_LEN`].
    pub head: &'a [u8],
    /// The last bytes, up to [`TAIL_LEN`], when they were read (for zip and SFX).
    pub tail: &'a [u8],
    /// The total length, if known.
    pub len: Option<u64>,
    /// The file name, lowercased, for extension checks.
    pub name: Option<&'a str>,
}

/// How much of the start of a file sniffers see.
pub const HEAD_LEN: usize = 64 * 1024;
/// How much of the end: a zip end-of-central-directory record with the longest comment.
pub const TAIL_LEN: usize = 64 * 1024 + 22;
