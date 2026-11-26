//! Bech32 (BIP 173) without the 90-character limit, for age's key strings and BeeZip's
//! `bzsig1…` (bhive.md §13.5): post-quantum keys run to thousands of characters. PR C builds
//! it.

use crate::Result;

use super::not_built;

/// `hrp` lowercase gives a lowercase string, uppercase an uppercase one.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let _ = (hrp, data);
    String::new()
}

/// The human-readable part (lowercase) and the data. A mixed-case string is refused.
pub fn decode(text: &str) -> Result<(String, Vec<u8>)> {
    let _ = text;
    Err(not_built("Bech32"))
}

/// A key as text: what it is and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyText {
    /// `age1…`
    X25519Public([u8; 32]),
    /// `AGE-SECRET-KEY-1…`
    X25519Secret(zeroize::Zeroizing<[u8; 32]>),
    /// `age1pq1…`
    XWingPublic(Box<[u8; 1216]>),
    /// `AGE-SECRET-KEY-PQ-1…`
    XWingSecret(zeroize::Zeroizing<[u8; 32]>),
    /// `bzsig1…`: an Ed25519 and an ML-DSA-65 public key (bhive.md §13.5).
    SigningPublic(Box<[u8; 1984]>),
    /// `BZSIG-SECRET-KEY-1…`: the two seeds.
    SigningSecret(zeroize::Zeroizing<[u8; 64]>),
}

/// Reads any of [`KeyText`]'s forms; anything else is `InvalidArgs` with what it looked like.
pub fn parse_key(text: &str) -> Result<KeyText> {
    let _ = text;
    Err(not_built("key strings"))
}

/// The text of a key.
pub fn key_text(key: &KeyText) -> String {
    let _ = key;
    String::new()
}
