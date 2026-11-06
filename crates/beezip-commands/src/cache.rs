//! The archive cache (docs/M3.md §4.2): open readers with their indexes, and what
//! `archive.list` built over them, so the desktop pages through a million-entry zip, or
//! previews one entry after another, without parsing the archive again.
//!
//! - **Lending:** a job takes its archive out and puts it back when it succeeds, so a reader
//!   is never shared. A second job on the same archive meanwhile opens its own.
//! - **The key** is the canonical path, the limits and name encoding it was opened under, and
//!   each volume's size and mtime; a volume that changed makes the next lookup a miss.
//! - **Passwords:** a reader that was given one remembers it, so it isn't put back.
//! - **Size:** at most [`MAX_ARCHIVES`] archives and [`MAX_ENTRIES`] entries and listing rows
//!   in all; the least recently used goes first.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
    time::SystemTime,
};

use beezip_core::{Limits, NameDecoding, Opened, limits::Budget};

use crate::commands::listing::Memo;

pub const MAX_ARCHIVES: usize = 4;
pub const MAX_ENTRIES: usize = 4_000_000;

/// An open archive, as a command works with it.
pub struct OpenArchive {
    pub opened: Opened,
    /// The tree and listings `archive.list` built.
    pub memo: Memo,
    /// The budget the reader's guards share, reset for each job.
    budget: Budget,
    /// The number of entries, once a command has read the index.
    pub entries: Option<usize>,
}

impl OpenArchive {
    pub fn new(opened: Opened, budget: Budget) -> Self {
        Self {
            opened,
            memo: Memo::default(),
            budget,
            entries: None,
        }
    }

    fn size(&self) -> Option<usize> {
        Some(self.entries? + self.memo.rows())
    }
}

/// One volume as it was when the archive was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
}

impl Stamp {
    fn of(path: &Path) -> Option<Self> {
        let meta = fs::metadata(path).ok()?;
        Some(Self {
            path: path.to_path_buf(),
            size: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

/// What a cached archive is found by.
#[derive(Debug, Clone)]
pub struct Key {
    /// The canonical path it was opened by; any of its volumes finds it too.
    path: PathBuf,
    limits: Limits,
    /// How its names were read (docs/M5.md §6).
    names: NameDecoding,
    stamps: Vec<Stamp>,
}

impl Key {
    /// `path` is canonical; `volumes` are the parts detection found (empty for one file).
    pub fn new(
        path: PathBuf,
        limits: Limits,
        names: NameDecoding,
        volumes: &[PathBuf],
    ) -> Option<Self> {
        let stamps = if volumes.is_empty() {
            vec![Stamp::of(&path)?]
        } else {
            volumes
                .iter()
                .map(|v| Stamp::of(&fs::canonicalize(v).ok()?))
                .collect::<Option<Vec<_>>>()?
        };
        Some(Self {
            path,
            limits,
            names,
            stamps,
        })
    }

    fn finds(&self, path: &Path, limits: &Limits, names: &NameDecoding) -> bool {
        (self.path == path || self.stamps.iter().any(|s| s.path == path))
            && self.limits == *limits
            && self.names == *names
    }

    fn same(&self, other: &Key) -> bool {
        self.limits == other.limits && self.names == other.names && self.stamps == other.stamps
    }

    fn fresh(&self) -> bool {
        self.stamps
            .iter()
            .all(|s| Stamp::of(&s.path).as_ref() == Some(s))
    }
}

struct Slot {
    key: Key,
    archive: OpenArchive,
    size: usize,
    used: u64,
}

#[derive(Default)]
struct State {
    slots: Vec<Slot>,
    clock: u64,
    hits: u64,
    misses: u64,
}

/// What the cache holds, for tests and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub archives: usize,
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
}

#[derive(Default)]
pub struct ArchiveCache {
    state: Mutex<State>,
}

impl ArchiveCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the archive `path` (canonical) opens, if it is here and unchanged, with its budget
    /// and counters reset for the new job.
    pub fn lend(
        &self,
        path: &Path,
        limits: &Limits,
        names: &NameDecoding,
    ) -> Option<(OpenArchive, Key)> {
        let slot = {
            let mut state = self.state();
            let Some(i) = state
                .slots
                .iter()
                .position(|s| s.key.finds(path, limits, names))
            else {
                state.misses += 1;
                return None;
            };
            state.slots.swap_remove(i)
        };
        // Checked, and a stale reader closed, outside the lock.
        let fresh = slot.key.fresh();
        if fresh {
            self.state().hits += 1;
        } else {
            self.state().misses += 1;
            return None;
        }
        let archive = slot.archive;
        archive.budget.reset();
        archive.opened.input.set(0);
        Some((archive, slot.key))
    }

    /// Puts an archive back after a job that succeeded without a password.
    pub fn give_back(&self, key: Key, archive: OpenArchive) {
        let Some(size) = archive.size() else { return };
        if size > MAX_ENTRIES {
            return;
        }
        let mut evicted = Vec::new();
        let mut state = self.state();
        state.clock += 1;
        let used = state.clock;
        // Another job's copy of the same archive, back first, is replaced.
        if let Some(i) = state.slots.iter().position(|s| s.key.same(&key)) {
            evicted.push(state.slots.swap_remove(i));
        }
        state.slots.push(Slot {
            key,
            archive,
            size,
            used,
        });
        loop {
            let total: usize = state.slots.iter().map(|s| s.size).sum();
            if state.slots.len() <= MAX_ARCHIVES && total <= MAX_ENTRIES {
                break;
            }
            let Some(oldest) = state
                .slots
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.used)
                .map(|(i, _)| i)
            else {
                break;
            };
            evicted.push(state.slots.swap_remove(oldest));
        }
        drop(state);
        // The readers close here, outside the lock.
        drop(evicted);
    }

    pub fn stats(&self) -> CacheStats {
        let state = self.state();
        CacheStats {
            archives: state.slots.len(),
            entries: state.slots.iter().map(|s| s.size).sum(),
            hits: state.hits,
            misses: state.misses,
        }
    }

    /// Empties it, closing every reader.
    pub fn clear(&self) {
        let slots = std::mem::take(&mut self.state().slots);
        drop(slots);
    }
}
