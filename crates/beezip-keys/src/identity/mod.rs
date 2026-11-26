//! Your own keys and your contacts (docs/M14.md §6, decision 14). PR C builds it; your signing
//! key is [`signing`] (PR H).
//!
//! - **Keys** are age's X25519 and X-Wing identities, and BeeZip signing keys, each under a
//!   name. A private key is sealed by the system: DPAPI-NG for this Windows account, the login
//!   Keychain as a generic password, or a file readable only by you on Linux. Each exports as
//!   its text (`AGE-SECRET-KEY-PQ-1…`, `BZSIG-SECRET-KEY-1…`), with a warning.
//! - **Contacts** are other people's public keys and certificates, by name.

pub mod signing;

use std::path::PathBuf;

use beezip_core::{
    Result,
    format::bhive::crypt::{KeySource, SlotSecret, SlotView},
};

use crate::not_built;

/// What a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// Opens archives: an `age1…` key.
    X25519,
    /// Opens archives, post-quantum: an `age1pq1…` key. The default (decision 9).
    XWing,
    /// Signs archives: a `bzsig1…` key.
    Signing,
}

/// A key or contact as `keys.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub name: String,
    pub kind: KeyKind,
    /// The public key as text, to share.
    pub public: String,
    /// 16 characters in groups of four (docs/bhive.md §13.5).
    pub fingerprint: String,
    /// Yours (with a private key), or a contact's.
    pub own: bool,
    /// Seconds since 1970.
    pub created: i64,
}

/// Where your keys and contacts are kept.
#[derive(Debug, Clone)]
pub struct Store {
    /// BeeZip's settings folder; keys go in `keys/` under it.
    pub dir: PathBuf,
}

impl Store {
    /// The store under BeeZip's settings folder.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn list(&self) -> Result<Vec<KeyEntry>> {
        Err(not_built("your keys"))
    }

    /// A new key of `kind` under `name`.
    pub fn create(&self, name: &str, kind: KeyKind) -> Result<KeyEntry> {
        let _ = (name, kind);
        Err(not_built("making keys"))
    }

    /// A key from its text: a private key becomes yours, a public key a contact.
    pub fn import(&self, name: &str, text: &str) -> Result<KeyEntry> {
        let _ = (name, text);
        Err(not_built("importing keys"))
    }

    /// The key's text: the public key, or with `secret` the private key.
    pub fn export(&self, name: &str, secret: bool) -> Result<zeroize::Zeroizing<String>> {
        let _ = (name, secret);
        Err(not_built("exporting keys"))
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let _ = name;
        Err(not_built("deleting keys"))
    }

    /// Your keys that open archives, as a key source: tried silently, before anything is
    /// asked (docs/M14.md §8).
    pub fn source(&self) -> Result<Box<dyn KeySource + Send>> {
        Ok(Box::new(OwnKeys))
    }
}

/// Your keys as a key source.
struct OwnKeys;

impl KeySource for OwnKeys {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        let _ = slot;
        false
    }

    fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>> {
        let _ = (slot, device);
        Ok(None)
    }
}
