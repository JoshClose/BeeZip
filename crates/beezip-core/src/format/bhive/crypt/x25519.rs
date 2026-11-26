//! Slot kind 3, an X25519 public key, age's `age1…` (bhive.md §12.5). PR C builds it.

use super::{MadeSlot, SlotSecret, SlotView, not_built};
use crate::Result;

/// The public part: the ephemeral share.
pub const PUBLIC_LEN: usize = 32;

/// A slot for `recipient`, with a fresh ephemeral secret.
pub fn make(recipient: &[u8; 32]) -> Result<MadeSlot> {
    let _ = recipient;
    Err(not_built("X25519 slots"))
}

/// The secret with `identity`, an X25519 private key; `None` is never returned for a slot of
/// this kind, since anonymous slots are told apart by their commitment.
pub fn secret(slot: &SlotView<'_>, identity: &[u8; 32]) -> Result<SlotSecret> {
    let _ = (slot, identity);
    Err(not_built("X25519 slots"))
}

/// `identity`'s public key, which the context adds (bhive.md §12.4).
pub fn public_of(identity: &[u8; 32]) -> [u8; 32] {
    let _ = identity;
    [0; 32]
}

pub fn check(public: &[u8]) -> Result<()> {
    let _ = public;
    Err(not_built("X25519 slots"))
}
