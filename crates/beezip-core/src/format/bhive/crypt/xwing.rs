//! Slot kind 4, an X-Wing public key (ML-KEM-768 with X25519), age's `age1pq1…`
//! (bhive.md §12.5, docs/M14.md decision 8). Built here from `ml-kem` and `x25519-dalek` with
//! the draft's combiner. PR C builds it.

use super::{MadeSlot, SlotSecret, SlotView, not_built};
use crate::Result;

/// The public part: the X-Wing ciphertext.
pub const PUBLIC_LEN: usize = 1120;
pub const PUBLIC_KEY_LEN: usize = 1216;

pub fn make(recipient: &[u8; PUBLIC_KEY_LEN]) -> Result<MadeSlot> {
    let _ = recipient;
    Err(not_built("X-Wing slots"))
}

/// The secret with `identity`, a 32-byte X-Wing private key (its seed).
pub fn secret(slot: &SlotView<'_>, identity: &[u8; 32]) -> Result<SlotSecret> {
    let _ = (slot, identity);
    Err(not_built("X-Wing slots"))
}

/// The public key of a 32-byte X-Wing private key.
pub fn public_of(identity: &[u8; 32]) -> Result<Box<[u8; PUBLIC_KEY_LEN]>> {
    let _ = identity;
    Err(not_built("X-Wing keys"))
}

/// A new X-Wing private key.
pub fn generate() -> Result<zeroize::Zeroizing<[u8; 32]>> {
    Err(not_built("X-Wing keys"))
}

pub fn check(public: &[u8]) -> Result<()> {
    let _ = public;
    Err(not_built("X-Wing slots"))
}
