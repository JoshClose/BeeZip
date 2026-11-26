//! Slot kind 5, an RSA certificate or key (bhive.md §12.5): RSAES-OAEP with SHA-256 and an
//! empty label, 2,048 bits or more. The pure-Rust half: writing to a public key, and opening
//! with a key file. Keys in CNG and the Keychain are reached by `beezip-keys`. PR D builds it.

use super::{MadeSlot, SlotSecret, SlotView, not_built};
use crate::Result;

/// The smallest modulus, in bytes.
pub const MIN_MODULUS: usize = 256;
pub const MAX_MODULUS: usize = 1024;

/// A slot for the RSA key in `spki` (DER SubjectPublicKeyInfo): a random `S`, OAEP-encrypted,
/// and the slot's tag.
pub fn make(spki: &[u8]) -> Result<MadeSlot> {
    let _ = spki;
    Err(not_built("RSA slots"))
}

/// The ciphertext a key's owner decrypts (CNG's `NCryptDecrypt`, or [`secret`]).
pub fn ciphertext<'a>(slot: &SlotView<'a>) -> Option<&'a [u8]> {
    let _ = slot;
    None
}

/// The secret with a private key from a file (PKCS #8 DER, already decrypted).
pub fn secret(slot: &SlotView<'_>, pkcs8: &[u8]) -> Result<SlotSecret> {
    let _ = (slot, pkcs8);
    Err(not_built("RSA slots"))
}

pub fn check(public: &[u8]) -> Result<()> {
    let _ = public;
    Err(not_built("RSA slots"))
}
