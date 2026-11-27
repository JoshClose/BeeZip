//! Encrypted `.bhive` archives kept unlocked (docs/M14.md §8): what opened each one's slot, so
//! that the desktop's next job on the same archive opens it again without a prompt, a device or
//! another Argon2 run.
//!
//! - **Only for jobs that ask:** a job keeps and takes these when its policy says
//!   ([`crate::Policy::keep_unlocked`]): the desktop sets it for the main window's tabs and
//!   their drags. The CLI, MCP and Explorer's job windows never do, and nothing is kept for them.
//! - **What is kept** is the secret that opened a slot (core's `SlotSecret`: a password's
//!   Argon2 output, a key's or device's secret), filed under the slot's `kept_id`: its key id
//!   and its bytes, so a slot rebuilt for a new key never matches. With it, the archive's
//!   paths it opened at: an entry is taken only for one of them, and goes when the last tab
//!   showing it closes ([`Unlocks::forget`]).
//! - **Size:** at most [`MAX_KEPT`] entries; the least recently used goes first. Every secret
//!   is wiped when its entry goes, and none is ever written anywhere.

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
};

use beezip_core::format::bhive::crypt::SlotSecret;

/// The most slots kept unlocked at once.
pub const MAX_KEPT: usize = 64;

/// Where an archive is: as the job named it, made absolute, and as the file system resolves it,
/// when it can.
#[derive(Debug, Clone)]
pub(crate) struct Place {
    given: PathBuf,
    canonical: Option<PathBuf>,
}

impl Place {
    pub(crate) fn new(path: &Path) -> Self {
        let given = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let canonical = std::fs::canonicalize(&given).ok();
        Self { given, canonical }
    }

    fn is(&self, other: &Self) -> bool {
        self.given == other.given || (self.canonical.is_some() && self.canonical == other.canonical)
    }
}

/// One slot kept unlocked.
struct Kept {
    /// The slot's `kept_id`.
    id: [u8; 32],
    /// Boxed, so that moving the entry about never leaves a copy of the secret behind.
    secret: Box<SlotSecret>,
    /// Where it opened the archive.
    places: Vec<Place>,
}

/// The slots kept unlocked, one set per engine: the desktop's tabs and drags share its engine.
#[derive(Default)]
pub struct Unlocks {
    /// Least recently used first.
    kept: Mutex<Vec<Kept>>,
}

impl Unlocks {
    pub fn new() -> Self {
        Self::default()
    }

    fn kept(&self) -> MutexGuard<'_, Vec<Kept>> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The secret kept for the slot `id` of the archive at `at`, if it was kept there.
    pub(crate) fn get(&self, id: &[u8; 32], at: &Place) -> Option<SlotSecret> {
        let mut kept = self.kept();
        let i = kept
            .iter()
            .position(|k| &k.id == id && k.places.iter().any(|p| p.is(at)))?;
        let k = kept.remove(i);
        let secret = SlotSecret::clone(&k.secret);
        kept.push(k);
        Some(secret)
    }

    /// Keeps `secret` for the slot `id` of the archive at `at`. A slot kept already is kept for
    /// `at` too; past [`MAX_KEPT`], the least recently used slot goes.
    pub(crate) fn keep(&self, id: [u8; 32], secret: &SlotSecret, at: Place) {
        let mut kept = self.kept();
        if let Some(i) = kept.iter().position(|k| k.id == id) {
            let mut k = kept.remove(i);
            if !k.places.iter().any(|p| p.is(&at)) {
                k.places.push(at);
            }
            kept.push(k);
            return;
        }
        while kept.len() >= MAX_KEPT {
            kept.remove(0);
        }
        kept.push(Kept {
            id,
            secret: Box::new(secret.clone()),
            places: vec![at],
        });
    }

    /// Locks the archive at `path` again: what was kept for it there is forgotten, and a slot
    /// kept for no other path is wiped. The desktop calls it when the archive's tab closes.
    /// Returns how many slots were wiped.
    pub fn forget(&self, path: &Path) -> usize {
        let at = Place::new(path);
        let mut kept = self.kept();
        let before = kept.len();
        for k in kept.iter_mut() {
            k.places.retain(|p| !p.is(&at));
        }
        kept.retain(|k| !k.places.is_empty());
        before - kept.len()
    }

    /// Forgets every slot kept.
    pub fn clear(&self) {
        self.kept().clear();
    }

    /// How many slots are kept unlocked.
    pub fn len(&self) -> usize {
        self.kept().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use zeroize::Zeroizing;

    use super::*;

    fn secret(n: u8) -> SlotSecret {
        SlotSecret::Extracted(Zeroizing::new([n; 32]))
    }

    fn bytes(s: &SlotSecret) -> Vec<u8> {
        match s {
            SlotSecret::Shared(b) => b.to_vec(),
            SlotSecret::Extracted(b) => b.to_vec(),
        }
    }

    #[test]
    fn a_slot_is_kept_only_where_it_opened() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.bhive");
        let b = dir.path().join("b.bhive");
        std::fs::write(&a, "a").unwrap();
        std::fs::write(&b, "b").unwrap();
        let u = Unlocks::new();
        u.keep([1; 32], &secret(7), Place::new(&a));
        assert_eq!(bytes(&u.get(&[1; 32], &Place::new(&a)).unwrap()), [7; 32]);
        // The same file named another way.
        let other = dir.path().join(".").join("a.bhive");
        assert!(u.get(&[1; 32], &Place::new(&other)).is_some());
        // A copy elsewhere, or another slot, isn't.
        assert!(u.get(&[1; 32], &Place::new(&b)).is_none());
        assert!(u.get(&[2; 32], &Place::new(&a)).is_none());
        // Opened at b too: kept for both, once.
        u.keep([1; 32], &secret(7), Place::new(&b));
        assert_eq!(u.len(), 1);
        assert!(u.get(&[1; 32], &Place::new(&b)).is_some());
        // a's tab closes: b still has it; then b's.
        assert_eq!(u.forget(&a), 0);
        assert!(u.get(&[1; 32], &Place::new(&a)).is_none());
        assert!(u.get(&[1; 32], &Place::new(&b)).is_some());
        assert_eq!(u.forget(&b), 1);
        assert!(u.is_empty());
    }

    #[test]
    fn forgetting_a_path_wipes_every_slot_kept_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.bhive");
        let b = dir.path().join("b.bhive");
        let u = Unlocks::new();
        u.keep([1; 32], &secret(1), Place::new(&a));
        u.keep([2; 32], &secret(2), Place::new(&a));
        u.keep([3; 32], &secret(3), Place::new(&b));
        // The file has gone since: its path still names it.
        assert_eq!(u.forget(&a), 2);
        assert_eq!(u.len(), 1);
        assert!(u.get(&[3; 32], &Place::new(&b)).is_some());
        assert_eq!(u.forget(&a), 0);
        u.clear();
        assert!(u.is_empty());
    }

    #[test]
    fn at_most_max_kept_and_the_least_recently_used_goes_first() {
        let dir = tempfile::tempdir().unwrap();
        let a = Place::new(&dir.path().join("a.bhive"));
        let u = Unlocks::new();
        let id = |n: usize| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(n as u64).to_le_bytes());
            id
        };
        for n in 0..MAX_KEPT {
            u.keep(id(n), &secret(n as u8), a.clone());
        }
        assert_eq!(u.len(), MAX_KEPT);
        // Slot 0 is used again, so slot 1 is the oldest now.
        assert!(u.get(&id(0), &a).is_some());
        u.keep(id(MAX_KEPT), &secret(0), a.clone());
        assert_eq!(u.len(), MAX_KEPT);
        assert!(u.get(&id(1), &a).is_none(), "the least recently used went");
        assert!(u.get(&id(0), &a).is_some());
        assert!(u.get(&id(MAX_KEPT), &a).is_some());
        for n in 0..3 * MAX_KEPT {
            u.keep(id(1000 + n), &secret(1), a.clone());
        }
        assert_eq!(u.len(), MAX_KEPT);
    }
}
