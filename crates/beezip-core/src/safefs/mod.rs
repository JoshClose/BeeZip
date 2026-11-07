//! SafeFs: the only code that writes extracted files (docs/M1.md §3.5).

pub mod disk;
pub mod motw;
pub mod partial;
pub mod sanitize;
mod sink;

pub use partial::Partial;
pub(crate) use sink::FileJob;
pub use sink::FsSink;

use crate::{Limits, io::Counter, limits::Budget};

/// What to do when an extracted file already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverwritePolicy {
    /// Ask through `Ctx::overwrite`; Replace all and Skip all hold for the rest of the job.
    #[default]
    Ask,
    Always,
    Never,
    /// Write `name (1).ext` instead.
    Rename,
    /// Replace only if the entry is newer than the file.
    Newer,
}

#[derive(Debug, Clone, Default)]
pub struct FsOptions {
    pub overwrite: OverwritePolicy,
    /// Create symlinks (only ones that resolve inside the destination). Off by default.
    pub links: bool,
    /// Leading path components to drop, as with `tar --strip-components`.
    pub strip_components: usize,
    /// A `Zone.Identifier` stream to write to every extracted file (see [`motw`]).
    pub zone: Option<Vec<u8>>,
    pub limits: Limits,
    /// The counter on the archive's compressed input. Hardlinks are extracted as copies,
    /// which produce data without consuming input, so their bytes are held to `max_ratio`
    /// against it.
    pub input: Counter,
    /// The job's `max_total_bytes` budget, shared with the reader, for the same reason.
    pub budget: Budget,
}

/// Why an entry wasn't extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// A `..` component.
    Traversal,
    /// A parent directory leads outside the destination through a symlink or junction.
    OutsideDest,
    /// A link entry, and links are off.
    LinksDisabled,
    /// A symlink or hardlink whose target is outside the destination.
    LinkOutside,
    /// A hardlink to a file that wasn't extracted.
    LinkTargetMissing,
    /// The path is empty once made safe.
    InvalidPath,
    /// A device, FIFO or other special file.
    Unsupported,
    /// Policy `never`, or Skip at the prompt.
    Exists,
    /// Policy `newer`, and the existing file is as new.
    NotNewer,
    /// A directory is in the way of a file, or a file in the way of a directory.
    Blocked,
    /// Creating a symlink failed (on Windows it needs Developer Mode or admin).
    LinkFailed,
}

impl SkipReason {
    /// Refused entries make the extraction fail with `Unsafe` once the rest is done.
    pub const fn is_unsafe(self) -> bool {
        matches!(
            self,
            Self::Traversal | Self::OutsideDest | Self::LinksDisabled | Self::LinkOutside
        )
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Traversal => "traversal",
            Self::OutsideDest => "outside-dest",
            Self::LinksDisabled => "links-disabled",
            Self::LinkOutside => "link-outside",
            Self::LinkTargetMissing => "link-target-missing",
            Self::InvalidPath => "invalid-path",
            Self::Unsupported => "unsupported",
            Self::Exists => "exists",
            Self::NotNewer => "not-newer",
            Self::Blocked => "blocked",
            Self::LinkFailed => "link-failed",
        }
    }

    pub const fn describe(self) -> &'static str {
        match self {
            Self::Traversal => "the path climbs out with `..`",
            Self::OutsideDest => "a parent directory leads outside the destination",
            Self::LinksDisabled => "links are off",
            Self::LinkOutside => "the link points outside the destination",
            Self::LinkTargetMissing => "the hard link's target wasn't extracted",
            Self::InvalidPath => "the path is empty once made safe",
            Self::Unsupported => "devices and other special files aren't extracted",
            Self::Exists => "the file exists",
            Self::NotNewer => "the existing file is as new",
            Self::Blocked => "something of another kind is in the way",
            Self::LinkFailed => "the symlink couldn't be created",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub path: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    /// As stored in the archive.
    pub from: String,
    /// Relative to the destination, `/`-separated.
    pub to: String,
}

/// Each list in a report holds at most this many items; the totals count all of them.
pub const REPORT_CAP: usize = 1000;

/// What an extraction did. Lists are capped at [`REPORT_CAP`] items, with totals alongside.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractReport {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes: u64,
    pub skipped: Vec<Skipped>,
    pub skipped_total: u64,
    pub renamed: Vec<Renamed>,
    pub renamed_total: u64,
    /// Skipped entries whose reason [`SkipReason::is_unsafe`].
    pub unsafe_total: u64,
}

impl ExtractReport {
    pub fn is_unsafe(&self) -> bool {
        self.unsafe_total > 0
    }

    fn skip(&mut self, path: &str, reason: SkipReason) {
        self.skipped_total += 1;
        if reason.is_unsafe() {
            self.unsafe_total += 1;
        }
        if self.skipped.len() < REPORT_CAP {
            self.skipped.push(Skipped {
                path: path.to_owned(),
                reason,
            });
        }
    }

    fn rename(&mut self, from: &str, to: String) {
        self.renamed_total += 1;
        if self.renamed.len() < REPORT_CAP {
            self.renamed.push(Renamed {
                from: from.to_owned(),
                to,
            });
        }
    }
}
