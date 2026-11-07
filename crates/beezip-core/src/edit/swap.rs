//! The safe rewrite (docs/M5.md §3.1): nothing writes into an archive. An edit writes a new
//! one beside it, through a `Partial`, and swaps it in with one rename, after checking that
//! nobody else changed the archive meanwhile.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use crate::{
    Ctx, Error, ErrorKind, Result,
    safefs::{Partial, motw},
};

/// How long a swap waits for another program to let go of the archive.
pub const SWAP_WAIT: Duration = Duration::from_secs(2);

/// Hidden, system and not indexed: the attributes a new archive gets from the old one.
#[cfg(windows)]
const KEPT_ATTRIBUTES: u32 = 0x2 | 0x4 | 0x2000;

/// What an archive file looked like: if any of it changes before the swap, someone else wrote
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub created: Option<SystemTime>,
}

impl Stamp {
    pub fn of(path: &Path) -> Result<Self> {
        let meta =
            fs::metadata(path).map_err(|e| Error::io(format!("reading {}", path.display()), &e))?;
        Ok(Self {
            size: meta.len(),
            modified: meta.modified().ok(),
            created: meta.created().ok(),
        })
    }
}

/// The archive an edit writes, as it was when the edit began.
#[derive(Debug, Clone)]
pub struct Target {
    /// The canonical path: an archive reached through a symlink is edited at its target, and
    /// the link stays.
    pub path: PathBuf,
    /// The file's name, for messages.
    pub name: String,
    pub stamp: Stamp,
    /// The attributes kept (Windows), set when the new file is created.
    attributes: u32,
    /// The Mark of the Web, carried over.
    zone: Option<Vec<u8>>,
}

impl Target {
    /// Checks that `given` can be edited in place: it exists, is a file, and isn't read-only
    /// (a rename can't replace a read-only file, docs/M5.md §16).
    pub fn check(given: &Path) -> Result<Self> {
        let path = fs::canonicalize(given)
            .map_err(|e| Error::io(format!("opening {}", given.display()), &e))?;
        let name = given
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| given.display().to_string());
        let meta = fs::metadata(&path)
            .map_err(|e| Error::io(format!("opening {}", given.display()), &e))?;
        if !meta.is_file() {
            return Err(Error::invalid_args(format!("{name} isn't a file")));
        }
        if meta.permissions().readonly() {
            return Err(Error::new(
                ErrorKind::Io,
                format!("{name} is read-only; nothing was changed"),
            ));
        }
        #[cfg(windows)]
        let attributes = {
            use std::os::windows::fs::MetadataExt;
            meta.file_attributes() & KEPT_ATTRIBUTES
        };
        #[cfg(not(windows))]
        let attributes = 0;
        Ok(Self {
            stamp: Stamp::of(&path)?,
            zone: motw::read_zone(&path),
            path,
            name,
            attributes,
        })
    }

    /// The new archive's partial file, in the archive's folder so the swap is a rename on one
    /// volume, with the archive's attributes.
    pub fn partial(&self) -> Result<Partial> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Partial::create_with(dir, &format!(".{name}"), self.attributes)
    }

    /// Swaps `partial` in: the creation time and the Mark of the Web first, then the stamp
    /// check, then the rename, retried for [`SWAP_WAIT`] while another program holds the
    /// archive. Cancellation is checked before, not during. On failure the partial file is
    /// deleted and the archive is untouched.
    pub fn swap(&self, partial: Partial, cx: &mut dyn Ctx) -> Result<()> {
        cx.check()?;
        if let Some(created) = self.stamp.created {
            partial.set_created(created)?;
        }
        if let Some(zone) = &self.zone {
            motw::write_zone(partial.path(), zone)
                .map_err(|e| Error::io(format!("writing {}", partial.path().display()), &e))?;
        }
        if Stamp::of(&self.path).ok().as_ref() != Some(&self.stamp) {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "{} changed while BeeZip was editing it; nothing was changed",
                    self.name
                ),
            ));
        }
        partial
            .persist_retrying(&self.path, SWAP_WAIT)
            .map_err(|(e, held)| {
                if held {
                    Error::new(
                        ErrorKind::Io,
                        format!(
                            "{} is open in another program; nothing was changed",
                            self.name
                        ),
                    )
                } else {
                    Error::io(format!("replacing {}", self.name), &e)
                }
            })
    }
}
