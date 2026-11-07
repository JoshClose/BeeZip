//! Partial files: everything BeeZip writes goes to `<name>.<random>.beezip-partial` first and is
//! renamed into place only when complete (docs/M3.md §3.7).
//!
//! Every partial file is recorded in one process-wide registry. A [`Partial`] that is dropped
//! deletes its file, which covers cancellation, errors and panics. The registry covers the one
//! case `Drop` can't: a front end that has to exit at once (the CLI's second Ctrl+C) calls
//! [`abandon_all`], which deletes every recorded file before the process ends, even ones that
//! are still open and being written.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
};

use crate::{Error, Result};

/// The suffix every partial file has.
pub const SUFFIX: &str = ".beezip-partial";

struct Registry {
    next: u64,
    live: BTreeMap<u64, PathBuf>,
    /// Set by [`abandon_all`]: no new partial file may be made, and none may be persisted.
    abandoned: bool,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    next: 0,
    live: BTreeMap::new(),
    abandoned: false,
});

fn registry() -> MutexGuard<'static, Registry> {
    // A panic while the lock was held can't leave the map inconsistent: every update is a
    // single insert or remove.
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A file being written. [`Partial::persist`] renames it into place; dropping it deletes it.
#[derive(Debug)]
pub struct Partial {
    file: Option<File>,
    path: PathBuf,
    id: u64,
    persisted: bool,
}

impl Partial {
    /// Creates `<name>.<random>.beezip-partial` in `dir` and records it. `name` is cut to 64
    /// characters. Fails with `Cancelled` once [`abandon_all`] has run.
    pub fn create(dir: &Path, name: &str) -> Result<Self> {
        Self::create_with(dir, name, 0)
    }

    /// [`Partial::create`], with Windows file attributes set as it is created (hidden, system,
    /// not indexed: an edited archive keeps its own, docs/M5.md §3.1). Ignored off Windows.
    pub fn create_with(dir: &Path, name: &str, attributes: u32) -> Result<Self> {
        let short: String = name.chars().take(64).collect();
        let mut reg = registry();
        if reg.abandoned {
            return Err(Error::cancelled());
        }
        // tempfile only picks the name: the file is opened with std, whose default share mode
        // includes FILE_SHARE_DELETE on Windows, so `abandon_all` can delete it while it is
        // still open here. Unlike tempfile's own files, it doesn't get FILE_ATTRIBUTE_TEMPORARY,
        // which a rename would carry over to the result. Cleanup is ours, and `keep` is avoided:
        // it calls SetFileAttributesW without std's long-path handling.
        let (file, temp_path) = tempfile::Builder::new()
            .prefix(&format!("{short}."))
            .suffix(SUFFIX)
            .rand_bytes(6)
            .disable_cleanup(true)
            .make_in(dir, |path| {
                let mut o = OpenOptions::new();
                o.read(true).write(true).create_new(true);
                #[cfg(windows)]
                if attributes != 0 {
                    use std::os::windows::fs::OpenOptionsExt;
                    o.attributes(attributes);
                }
                #[cfg(not(windows))]
                let _ = attributes;
                o.open(path)
            })
            .map_err(|e| Error::io(format!("creating a file in {}", dir.display()), &e))?
            .into_parts();
        let path = temp_path.to_path_buf();
        drop(temp_path);
        let id = reg.next;
        reg.next += 1;
        reg.live.insert(id, path.clone());
        Ok(Self {
            file: Some(file),
            path,
            id,
            persisted: false,
        })
    }

    /// Creates one in the system's temp directory, for spooling.
    pub fn create_temp(name: &str) -> Result<Self> {
        Self::create(&std::env::temp_dir(), name)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The open handle. Panics after [`Partial::close`] until [`Partial::open`]; only the
    /// volume writer closes handles, and it always goes through `open`.
    pub fn file(&self) -> &File {
        self.file
            .as_ref()
            .unwrap_or_else(|| unreachable!("a closed partial file"))
    }

    pub fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .unwrap_or_else(|| unreachable!("a closed partial file"))
    }

    /// Closes the handle; the file stays, and stays recorded. A long volume set keeps only one
    /// part open at a time.
    pub fn close(&mut self) {
        drop(self.file.take());
    }

    /// The handle, reopened for reading and writing if [`Partial::close`] closed it.
    pub fn open(&mut self) -> Result<&mut File> {
        if self.file.is_none() {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)
                .map_err(|e| Error::io(format!("opening {}", self.path.display()), &e))?;
            self.file = Some(f);
        }
        Ok(self.file_mut())
    }

    /// Another handle to the same file.
    pub fn try_clone(&self) -> Result<File> {
        self.file()
            .try_clone()
            .map_err(|e| Error::io(format!("opening {}", self.path.display()), &e))
    }

    /// A new handle, reading from the start.
    pub fn reopen(&self) -> Result<File> {
        File::open(&self.path)
            .map_err(|e| Error::io(format!("opening {}", self.path.display()), &e))
    }

    /// Sets the file's creation time (Windows; elsewhere nothing happens).
    pub fn set_created(&self, created: std::time::SystemTime) -> Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileTimesExt;
            let times = fs::FileTimes::new().set_created(created);
            self.file()
                .set_times(times)
                .map_err(|e| Error::io(format!("writing {}", self.path.display()), &e))?;
        }
        #[cfg(not(windows))]
        let _ = created;
        Ok(())
    }

    /// Closes the file and renames it to `to`, replacing what is there. It holds the registry's
    /// lock while it renames, so it either lands before [`abandon_all`] or fails with
    /// `Cancelled` after it. std's rename is used rather than tempfile's `persist`, which calls
    /// `MoveFileExW` without std's long-path handling.
    pub fn persist(self, to: &Path) -> Result<()> {
        self.persist_retrying(to, std::time::Duration::ZERO)
            .map_err(|(e, _)| Error::io(format!("writing {}", to.display()), &e))
    }

    /// [`Partial::persist`], trying again for up to `wait` while the rename is refused because
    /// another program holds `to` open without letting it be deleted (`ERROR_ACCESS_DENIED`,
    /// `ERROR_SHARING_VIOLATION`): virus scanners and indexers let go quickly. The error that
    /// comes back says whether that was why it failed. The partial file is deleted on failure.
    pub fn persist_retrying(
        mut self,
        to: &Path,
        wait: std::time::Duration,
    ) -> std::result::Result<(), (std::io::Error, bool)> {
        drop(self.file.take());
        let deadline = std::time::Instant::now() + wait;
        loop {
            {
                let mut reg = registry();
                if reg.abandoned {
                    return Err((Error::cancelled().into_io(), false));
                }
                match fs::rename(&self.path, to) {
                    Ok(()) => {
                        reg.live.remove(&self.id);
                        self.persisted = true;
                        return Ok(());
                    }
                    Err(e) if !held_open(&e) => return Err((e, false)),
                    Err(e) if std::time::Instant::now() >= deadline => return Err((e, true)),
                    Err(_) => {}
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if self.persisted {
            return;
        }
        drop(self.file.take());
        let recorded = registry().live.remove(&self.id).is_some();
        // After `abandon_all` the file is already gone.
        if recorded {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A rename refused because another handle holds the target without `FILE_SHARE_DELETE`.
fn held_open(e: &std::io::Error) -> bool {
    // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
    cfg!(windows) && matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// Deletes every partial file this process has open and refuses new ones, for a front end
/// that is about to exit without running destructors. Returns how many it deleted. The jobs
/// writing them see later writes succeed, and their renames fail with `Cancelled`.
pub fn abandon_all() -> usize {
    let mut reg = registry();
    reg.abandoned = true;
    let live = std::mem::take(&mut reg.live);
    live.values().filter(|p| fs::remove_file(p).is_ok()).count()
}

/// How many partial files are recorded now.
pub fn live() -> usize {
    registry().live.len()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn persist_renames_and_drop_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = Partial::create(dir.path(), "a.txt").unwrap();
        let name = p.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("a.txt.") && name.ends_with(SUFFIX),
            "{name}"
        );
        p.file_mut().write_all(b"done").unwrap();
        let target = dir.path().join("a.txt");
        p.persist(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"done");

        let mut p = Partial::create(dir.path(), "b.txt").unwrap();
        p.file_mut().write_all(b"half").unwrap();
        let path = p.path().to_path_buf();
        let mut again = String::new();
        p.reopen().unwrap().read_to_string(&mut again).unwrap();
        assert_eq!(again, "half");
        drop(p);
        assert!(!path.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn results_are_not_marked_temporary() {
        use std::os::windows::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let p = Partial::create(dir.path(), "c").unwrap();
        let target = dir.path().join("c");
        p.persist(&target).unwrap();
        let attrs = fs::metadata(&target).unwrap().file_attributes();
        assert_eq!(
            attrs & 0x100,
            0,
            "FILE_ATTRIBUTE_TEMPORARY is set: {attrs:#x}"
        );
    }
}
