//! Slot kind 1, a password (bhive.md §12.5): Argon2id of the password in NFC. PR A builds it.

use zeroize::Zeroizing;

use super::{MadeSlot, SlotSecret, SlotView, Strength, not_built};
use crate::Result;

/// The public part's length: version, reserved, memory, passes, lanes, salt.
pub const PUBLIC_LEN: usize = 48;
/// Readers refuse more (bhive.md §12.5).
pub const MAX_MEMORY_KIB: u32 = 4 << 20;
pub const MAX_PASSES: u32 = 16;
pub const MAX_LANES: u32 = 16;

/// A new slot's public part (a fresh salt, the strength's cost) and Argon2id's output.
pub fn make(password: &Zeroizing<String>, strength: Strength) -> Result<MadeSlot> {
    let _ = (password, strength);
    Err(not_built("password slots"))
}

/// Argon2id of `password` with the slot's salt and cost.
pub fn secret(slot: &SlotView<'_>, password: &str) -> Result<SlotSecret> {
    let _ = (slot, password);
    Err(not_built("password slots"))
}

/// The bytes of memory Argon2 needs for this slot, to ask before spending more than half the
/// machine's (docs/M14.md §5).
pub fn memory(public: &[u8]) -> Option<u64> {
    let _ = public;
    None
}

/// Length and limits.
pub fn check(public: &[u8]) -> Result<()> {
    let _ = public;
    Err(not_built("password slots"))
}
