//! Slot kind 2, a recovery key (bhive.md §12.5): 16 random bytes shown as 48 digits, as
//! BitLocker's. PR A builds it.

use zeroize::Zeroizing;

use super::{MadeSlot, SlotSecret, SlotView, not_built};
use crate::Result;

/// The public part: a salt.
pub const PUBLIC_LEN: usize = 32;

/// A new recovery key.
pub fn generate() -> Result<Zeroizing<[u8; 16]>> {
    Err(not_built("recovery keys"))
}

/// The key as people see it: 8 groups of 6 digits joined by hyphens.
pub fn format(key: &[u8; 16]) -> Zeroizing<String> {
    let _ = key;
    Zeroizing::new(String::new())
}

/// The key from what someone typed: any separators, 48 digits, each group a multiple of 11.
pub fn parse(text: &str) -> Result<Zeroizing<[u8; 16]>> {
    let _ = text;
    Err(not_built("recovery keys"))
}

pub fn make(key: &Zeroizing<[u8; 16]>) -> Result<MadeSlot> {
    let _ = key;
    Err(not_built("recovery-key slots"))
}

pub fn secret(slot: &SlotView<'_>, typed: &str) -> Result<SlotSecret> {
    let _ = (slot, typed);
    Err(not_built("recovery-key slots"))
}

pub fn check(public: &[u8]) -> Result<()> {
    let _ = public;
    Err(not_built("recovery-key slots"))
}
