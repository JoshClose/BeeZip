//! Slot kinds 6 and 7, an EC certificate or key on P-256 or P-384 (bhive.md §12.5): ECDH with
//! a fresh ephemeral key, `PRK = HMAC(context, Z)`, which CNG computes itself with
//! `BCRYPT_KDF_HMAC`. The pure-Rust half. PR D builds it.

use super::{Curve, MadeSlot, SlotSecret, SlotView, not_built};
use crate::Result;

impl Curve {
    /// An uncompressed point's length: `04 ‖ x ‖ y`.
    pub const fn point_len(self) -> usize {
        match self {
            Self::P256 => 65,
            Self::P384 => 97,
        }
    }
}

/// A slot for the EC key in `spki`.
pub fn make(curve: Curve, spki: &[u8]) -> Result<MadeSlot> {
    let _ = (curve, spki);
    Err(not_built("EC slots"))
}

/// The slot's ephemeral public key, which a key's owner agrees with (CNG, or [`secret`]).
pub fn ephemeral<'a>(slot: &SlotView<'a>) -> Option<&'a [u8]> {
    let _ = slot;
    None
}

/// The secret with a private key from a file (PKCS #8 DER, already decrypted).
pub fn secret(slot: &SlotView<'_>, curve: Curve, pkcs8: &[u8]) -> Result<SlotSecret> {
    let _ = (slot, curve, pkcs8);
    Err(not_built("EC slots"))
}

pub fn check(curve: Curve, public: &[u8]) -> Result<()> {
    let _ = (curve, public);
    Err(not_built("EC slots"))
}
