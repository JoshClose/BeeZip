//! Your own keys and your contacts (docs/M14.md §6, decision 14); your signing key is
//! [`signing`] (PR H).
//!
//! - **Keys** are age's X25519 and X-Wing identities, and BeeZip signing keys, each under a
//!   name. A private key is sealed by the system ([`seal`]): DPAPI-NG for this Windows account,
//!   the login Keychain as a generic password, or a file readable only by you on Linux. Each
//!   exports as its text (`AGE-SECRET-KEY-PQ-1…`, `BZSIG-SECRET-KEY-1…`), with a warning.
//! - **Contacts** are other people's public keys, by name.
//!
//! The store is a folder, `keys` under BeeZip's settings folder: `keys.json` lists every key
//! and contact with its public key, and each private key is kept beside it (or in the
//! Keychain) under the record's id.

#[cfg(windows)]
mod dpapi;
mod seal;
pub mod signing;

use std::path::{Path, PathBuf};

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::crypt::{
        KeySource, SlotKind, SlotSecret, SlotView,
        bech32::{self, KeyText},
        mldsa, x25519, xwing,
    },
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::not_built;

/// What a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyKind {
    /// Opens archives: an `age1…` key.
    X25519,
    /// Opens archives, post-quantum: an `age1pq1…` key. The default (decision 9).
    #[serde(rename = "xwing")]
    XWing,
    /// Signs archives: a `bzsig1…` key.
    Signing,
}

impl KeyKind {
    /// The kind of a key string.
    pub const fn of(key: &KeyText) -> Self {
        match key {
            KeyText::X25519Public(_) | KeyText::X25519Secret(_) => Self::X25519,
            KeyText::XWingPublic(_) | KeyText::XWingSecret(_) => Self::XWing,
            KeyText::SigningPublic(_) | KeyText::SigningSecret(_) => Self::Signing,
        }
    }

    /// The slot kind its keys open; `None` for a signing key.
    pub const fn slot(self) -> Option<SlotKind> {
        match self {
            Self::X25519 => Some(SlotKind::X25519),
            Self::XWing => Some(SlotKind::XWing),
            Self::Signing => None,
        }
    }
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

/// `keys.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    version: u32,
    keys: Vec<Record>,
}

const VERSION: u32 = 1;
/// The longest name, in characters.
const NAME_MAX: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    name: String,
    kind: KeyKind,
    public: String,
    own: bool,
    created: i64,
    /// What its private key is kept as ([`seal`]); empty for a contact.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
}

impl Record {
    fn entry(&self) -> KeyEntry {
        let fingerprint = bech32::parse_key(&self.public)
            .ok()
            .and_then(|k| k.public_bytes().map(bech32::fingerprint))
            .unwrap_or_default();
        KeyEntry {
            name: self.name.clone(),
            kind: self.kind,
            public: self.public.clone(),
            fingerprint,
            own: self.own,
            created: self.created,
        }
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidArgs, message)
}

fn same_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Writes `bytes` to `path` through a temporary file beside it, so a reader never sees half.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.into()
    })
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

    fn keys_dir(&self) -> PathBuf {
        self.dir.join("keys")
    }

    fn index_path(&self) -> PathBuf {
        self.keys_dir().join("keys.json")
    }

    fn load(&self) -> Result<Index> {
        let path = self.index_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Index {
                    version: VERSION,
                    keys: Vec::new(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        let index: Index = serde_json::from_str(&text)
            .map_err(|e| Error::corrupt(format!("{} isn't a list of keys: {e}", path.display())))?;
        if index.version > VERSION {
            return Err(Error::new(
                ErrorKind::UnsupportedFormat,
                format!(
                    "{} was written by a newer BeeZip (version {})",
                    path.display(),
                    index.version
                ),
            ));
        }
        Ok(index)
    }

    fn save(&self, index: &Index) -> Result<()> {
        std::fs::create_dir_all(self.keys_dir())?;
        let mut text = serde_json::to_string_pretty(index)
            .map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
        text.push('\n');
        write_atomic(&self.index_path(), text.as_bytes())
    }

    fn find<'a>(index: &'a Index, name: &str) -> Result<&'a Record> {
        index
            .keys
            .iter()
            .find(|r| r.name == name)
            .or_else(|| index.keys.iter().find(|r| same_name(&r.name, name)))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NotFound,
                    format!("no key or contact is called `{name}`"),
                )
            })
    }

    /// Your keys first, then your contacts, each in the order they were added.
    pub fn list(&self) -> Result<Vec<KeyEntry>> {
        let index = self.load()?;
        let (mut own, contacts): (Vec<_>, Vec<_>) = index.keys.iter().partition(|r| r.own);
        own.extend(contacts);
        Ok(own.into_iter().map(Record::entry).collect())
    }

    /// A new key of `kind` under `name`.
    pub fn create(&self, name: &str, kind: KeyKind) -> Result<KeyEntry> {
        let key = match kind {
            KeyKind::X25519 => KeyText::X25519Secret(x25519::generate()?),
            KeyKind::XWing => KeyText::XWingSecret(xwing::generate()?),
            KeyKind::Signing => KeyText::SigningSecret(mldsa::HybridKey::generate()?.seeds),
        };
        self.add(name, &key)
    }

    /// A key from its text: a private key becomes yours, a public key a contact. The text may
    /// be an age identity file, comments and all, with one key in it.
    pub fn import(&self, name: &str, text: &str) -> Result<KeyEntry> {
        if text.contains("-----BEGIN") {
            return Err(not_built("certificates as contacts"));
        }
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let key = match lines.as_slice() {
            [one] => bech32::parse_key(one)?,
            [] => return Err(invalid("there is no key in it")),
            more => {
                return Err(invalid(format!(
                    "it holds {} keys; import them one at a time, each with its own name",
                    more.len()
                )));
            }
        };
        self.add(name, &key)
    }

    fn add(&self, name: &str, key: &KeyText) -> Result<KeyEntry> {
        let name = name.trim();
        if name.is_empty() {
            return Err(invalid("a key needs a name"));
        }
        if name.chars().count() > NAME_MAX {
            return Err(invalid(format!(
                "a key's name is at most {NAME_MAX} characters"
            )));
        }
        if name.chars().any(char::is_control) {
            return Err(invalid("a key's name can't hold control characters"));
        }
        let mut index = self.load()?;
        index.version = VERSION;
        if let Some(r) = index.keys.iter().find(|r| same_name(&r.name, name)) {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!("a key or contact is already called `{}`", r.name),
            ));
        }
        let public = key.public()?;
        let public_text = bech32::key_text(&public);
        if let Some(r) = index.keys.iter().find(|r| r.public == public_text) {
            let whose = if r.own {
                "one of your keys"
            } else {
                "a contact"
            };
            return Err(Error::new(
                ErrorKind::Conflict,
                format!("this key is already here, as {whose}: `{}`", r.name),
            ));
        }
        let own = key.is_secret();
        let id = if own {
            // The fingerprint, which no other key here has: the public key is unique.
            let id = bech32::fingerprint(public.public_bytes().unwrap_or_default())
                .replace('-', "")
                .to_lowercase();
            std::fs::create_dir_all(self.keys_dir())?;
            let text = Zeroizing::new(bech32::key_text(key));
            seal::put(&self.keys_dir(), &id, text.as_bytes())?;
            id
        } else {
            String::new()
        };
        let record = Record {
            name: name.to_owned(),
            kind: KeyKind::of(key),
            public: public_text,
            own,
            created: now(),
            id,
        };
        index.keys.push(record.clone());
        if let Err(e) = self.save(&index) {
            if own {
                let _ = seal::remove(&self.keys_dir(), &record.id);
            }
            return Err(e);
        }
        Ok(record.entry())
    }

    /// The key's text: the public key, or with `secret` the private key.
    pub fn export(&self, name: &str, secret: bool) -> Result<Zeroizing<String>> {
        let index = self.load()?;
        let record = Self::find(&index, name)?;
        if !secret {
            return Ok(Zeroizing::new(record.public.clone()));
        }
        Ok(Zeroizing::new(bech32::key_text(&self.secret_of(record)?)))
    }

    /// Your private key `name`, as its key string's bytes: for signing (PR H) and opening.
    pub fn private(&self, name: &str) -> Result<KeyText> {
        let index = self.load()?;
        self.secret_of(Self::find(&index, name)?)
    }

    fn secret_of(&self, record: &Record) -> Result<KeyText> {
        if !record.own {
            return Err(invalid(format!(
                "`{}` is a contact's key: only its public key is here",
                record.name
            )));
        }
        let bytes = seal::get(&self.keys_dir(), &record.id)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::corrupt(format!("the key `{}` is damaged", record.name)))?;
        let key = bech32::parse_key(text)
            .map_err(|e| Error::corrupt(format!("the key `{}` is damaged: {e}", record.name)))?;
        if !key.is_secret() || KeyKind::of(&key) != record.kind {
            return Err(Error::corrupt(format!(
                "the key `{}` is damaged",
                record.name
            )));
        }
        Ok(key)
    }

    /// The key or contact whose public key is `public` (its bytes): to tell a signer, or a
    /// slot description's recipient, by the name you gave it.
    pub fn find_public(&self, public: &[u8]) -> Result<Option<KeyEntry>> {
        Ok(self
            .load()?
            .keys
            .iter()
            .find(|r| {
                bech32::parse_key(&r.public)
                    .ok()
                    .is_some_and(|k| k.public_bytes() == Some(public))
            })
            .map(Record::entry))
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let mut index = self.load()?;
        let record = Self::find(&index, name)?.clone();
        index.keys.retain(|r| r.name != record.name);
        self.save(&index)?;
        if record.own {
            seal::remove(&self.keys_dir(), &record.id)?;
        }
        Ok(())
    }

    /// Your keys that open archives, as a key source: tried silently, before anything is
    /// asked (docs/M14.md §8). They are unsealed the first time a slot is tried.
    pub fn source(&self) -> Result<Box<dyn KeySource + Send>> {
        Ok(Box::new(OwnKeys {
            store: self.clone(),
            identities: None,
            matched: Vec::new(),
        }))
    }
}

/// One of your keys that opens archives.
struct Identity {
    kind: SlotKind,
    secret: Zeroizing<[u8; 32]>,
}

/// Your keys as a key source.
struct OwnKeys {
    store: Store,
    /// Unsealed on first use; a key that can't be (another account's) is left out.
    identities: Option<Vec<Identity>>,
    /// The slots found so far, by commitment, with the identity that opens each.
    matched: Vec<([u8; 32], usize)>,
}

impl OwnKeys {
    fn identities(&mut self) -> &[Identity] {
        self.identities.get_or_insert_with(|| {
            let Ok(index) = self.store.load() else {
                return Vec::new();
            };
            index
                .keys
                .iter()
                .filter(|r| r.own && r.kind != KeyKind::Signing)
                .filter_map(|r| match self.store.secret_of(r).ok()? {
                    KeyText::X25519Secret(secret) => Some(Identity {
                        kind: SlotKind::X25519,
                        secret,
                    }),
                    KeyText::XWingSecret(secret) => Some(Identity {
                        kind: SlotKind::XWing,
                        secret,
                    }),
                    _ => None,
                })
                .collect()
        })
    }

    fn open(slot: &SlotView<'_>, identity: &Identity) -> Option<SlotSecret> {
        let opened = match slot.kind {
            SlotKind::X25519 => x25519::open(slot, &identity.secret),
            SlotKind::XWing => xwing::open(slot, &identity.secret),
            _ => return None,
        };
        opened.ok().flatten()
    }

    fn find(&mut self, slot: &SlotView<'_>) -> Option<SlotSecret> {
        if !matches!(slot.kind, SlotKind::X25519 | SlotKind::XWing) {
            return None;
        }
        if let Some(&(_, i)) = self.matched.iter().find(|(c, _)| c == slot.commitment) {
            let identity = &self.identities()[i];
            return Self::open(slot, identity);
        }
        let kind = slot.kind;
        let found = self
            .identities()
            .iter()
            .enumerate()
            .filter(|(_, id)| id.kind == kind)
            .find_map(|(i, id)| Self::open(slot, id).map(|s| (i, s)));
        let (i, secret) = found?;
        self.matched.push((*slot.commitment, i));
        Some(secret)
    }
}

impl KeySource for OwnKeys {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        self.find(slot).is_some()
    }

    fn secret(&mut self, slot: &SlotView<'_>, _device: bool) -> Result<Option<SlotSecret>> {
        Ok(self.find(slot))
    }
}

#[cfg(test)]
mod tests;
