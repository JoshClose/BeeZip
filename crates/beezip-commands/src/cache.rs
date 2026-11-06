//! The archive cache (docs/M3.md §4.2): open readers with their indexes, and what
//! `archive.list` built over them, so the desktop pages through a million-entry zip, or
//! previews one entry after another, without parsing the archive again.
//!
//! - **Lending:** a job takes its archive out and puts it back when it succeeds, so a reader
//!   is never shared. A second job on the same archive meanwhile waits for it, for at most
//!   twice as long as opening it took (and 5 s), then opens its own. The jobs that borrow
//!   (`archive.list`, `archive.info`, `entry.read`) are short, and the desktop runs two at once
//!   on every folder it opens (the table's listing and the tree's): without waiting, the second
//!   opened a million-entry zip again, a second's stall (docs/M5.md §16).
//! - **The key** is the canonical path, the limits and name encoding it was opened under, and
//!   each volume's size and mtime; a volume that changed makes the next lookup a miss.
//! - **Passwords:** a reader that was given one remembers it, so it isn't put back.
//! - **Size:** at most [`MAX_ARCHIVES`] archives and [`MAX_ENTRIES`] entries and listing rows
//!   in all; the least recently used goes first.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Condvar, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant, SystemTime},
};

use beezip_core::{Limits, NameDecoding, Opened, limits::Budget};

use crate::commands::listing::Memo;

pub const MAX_ARCHIVES: usize = 4;
pub const MAX_ENTRIES: usize = 4_000_000;
/// The longest a job waits for another to give its archive back.
pub const MAX_WAIT: Duration = Duration::from_secs(5);

/// An open archive, as a command works with it.
pub struct OpenArchive {
    pub opened: Opened,
    /// The tree and listings `archive.list` built.
    pub memo: Memo,
    /// The budget the reader's guards share, reset for each job.
    budget: Budget,
    /// The number of entries, once a command has read the index.
    pub entries: Option<usize>,
    /// How long another job waits for it while it's lent: twice what opening it took.
    wait: Duration,
}

impl OpenArchive {
    /// `opening` is how long opening it took.
    pub fn new(opened: Opened, budget: Budget, opening: Duration) -> Self {
        Self {
            opened,
            memo: Memo::default(),
            budget,
            entries: None,
            wait: opening.saturating_mul(2).min(MAX_WAIT),
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
    /// Archives lent to a job now, and how long another may wait for each.
    lent: Vec<(Key, Duration)>,
    clock: u64,
    hits: u64,
    misses: u64,
}

impl State {
    fn release(&mut self, key: &Key) {
        if let Some(i) = self
            .lent
            .iter()
            .position(|(k, _)| k.path == key.path && k.same(key))
        {
            self.lent.swap_remove(i);
        }
    }
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
    /// Signalled when a lent archive comes back, or won't.
    returned: Condvar,
}

impl ArchiveCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the archive `path` (canonical) opens, if it is here and unchanged, with its budget
    /// and counters reset for the new job. If another job has it, waits for it a while. The
    /// key that comes back goes back through [`ArchiveCache::give_back`] or
    /// [`ArchiveCache::release`].
    pub fn lend(
        &self,
        path: &Path,
        limits: &Limits,
        names: &NameDecoding,
    ) -> Option<(OpenArchive, Key)> {
        let slot = {
            let mut state = self.state();
            let mut deadline = None;
            loop {
                if let Some(i) = state
                    .slots
                    .iter()
                    .position(|s| s.key.finds(path, limits, names))
                {
                    let slot = state.slots.swap_remove(i);
                    state.lent.push((slot.key.clone(), slot.archive.wait));
                    break slot;
                }
                let Some(wait) = state
                    .lent
                    .iter()
                    .find(|(k, _)| k.finds(path, limits, names))
                    .map(|(_, w)| *w)
                else {
                    state.misses += 1;
                    return None;
                };
                let deadline = *deadline.get_or_insert_with(|| Instant::now() + wait);
                let now = Instant::now();
                if now >= deadline {
                    state.misses += 1;
                    return None;
                }
                state = self
                    .returned
                    .wait_timeout(state, deadline - now)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
        };
        // Checked, and a stale reader closed, outside the lock.
        let fresh = slot.key.fresh();
        if fresh {
            self.state().hits += 1;
        } else {
            self.release(&slot.key);
            self.state().misses += 1;
            return None;
        }
        let archive = slot.archive;
        archive.budget.reset();
        archive.opened.input.set(0);
        Some((archive, slot.key))
    }

    /// A lent archive that won't come back (its job failed, or used a password): a job waiting
    /// for it opens its own.
    pub fn release(&self, key: &Key) {
        self.state().release(key);
        self.returned.notify_all();
    }

    /// Puts an archive back after a job that succeeded without a password.
    pub fn give_back(&self, key: Key, archive: OpenArchive) {
        let Some(size) = archive.size() else {
            self.release(&key);
            return;
        };
        if size > MAX_ENTRIES {
            self.release(&key);
            return;
        }
        let mut evicted = Vec::new();
        let mut state = self.state();
        state.release(&key);
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
        self.returned.notify_all();
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{sync::Arc, thread};

    use beezip_core::{OpenOptions, SimpleCtx, open};

    use super::*;

    fn fixture() -> PathBuf {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/thirdparty/7z-deflate.zip");
        fs::canonicalize(p).unwrap()
    }

    /// A cache holding the fixture, as if its first job took `opening` to open it.
    fn cache_with(opening: Duration) -> (Arc<ArchiveCache>, PathBuf) {
        let path = fixture();
        let opts = OpenOptions::default();
        let opened = open(&path, &opts, &mut SimpleCtx::new()).unwrap();
        let mut archive = OpenArchive::new(opened, opts.budget, opening);
        archive.entries = Some(1);
        let key = Key::new(
            path.clone(),
            Limits::default(),
            NameDecoding::default(),
            &[],
        )
        .unwrap();
        let cache = Arc::new(ArchiveCache::new());
        cache.give_back(key, archive);
        (cache, path)
    }

    fn lend(cache: &ArchiveCache, path: &Path) -> Option<(OpenArchive, Key)> {
        cache.lend(path, &Limits::default(), &NameDecoding::default())
    }

    #[test]
    fn a_second_job_waits_for_the_first_to_give_it_back() {
        let (cache, path) = cache_with(Duration::from_secs(10));
        let (archive, key) = lend(&cache, &path).unwrap();
        let waiter = {
            let (cache, path) = (Arc::clone(&cache), path.clone());
            thread::spawn(move || {
                let t = Instant::now();
                let got = lend(&cache, &path).map(|(a, k)| cache.give_back(k, a));
                (got.is_some(), t.elapsed())
            })
        };
        thread::sleep(Duration::from_millis(150));
        cache.give_back(key, archive);
        let (got, waited) = waiter.join().unwrap();
        assert!(got, "the second job got the first's reader");
        assert!(
            waited >= Duration::from_millis(100) && waited < MAX_WAIT,
            "{waited:?}"
        );
        assert_eq!(cache.stats().hits, 2);
    }

    #[test]
    fn a_release_or_a_quick_open_ends_the_wait() {
        let (cache, path) = cache_with(Duration::from_secs(10));
        let (_archive, key) = lend(&cache, &path).unwrap();
        let waiter = {
            let (cache, path) = (Arc::clone(&cache), path.clone());
            thread::spawn(move || {
                let t = Instant::now();
                (lend(&cache, &path).is_some(), t.elapsed())
            })
        };
        thread::sleep(Duration::from_millis(100));
        // The first job failed: its reader won't come back.
        cache.release(&key);
        let (got, waited) = waiter.join().unwrap();
        assert!(!got);
        assert!(waited < Duration::from_secs(2), "{waited:?}");

        // An archive that opened in a millisecond is opened again rather than waited for long.
        let (cache, path) = cache_with(Duration::from_millis(1));
        let _held = lend(&cache, &path).unwrap();
        let t = Instant::now();
        assert!(lend(&cache, &path).is_none());
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
    }
}
