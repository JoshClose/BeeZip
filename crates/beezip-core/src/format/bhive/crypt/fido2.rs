//! Slot kind 8, a FIDO2 authenticator's hmac-secret: a security key, or Windows Hello
//! (bhive.md §12.5). The slot's bytes; webauthn.dll is reached by `beezip-keys`. PR E builds
//! it.

use zeroize::Zeroizing;

use super::{MadeSlot, SlotView, not_built};
use crate::Result;

/// What a kind-8 slot says, for the authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Slot<'a> {
    pub credential_id: &'a [u8],
    pub rp_id: &'a str,
    pub salt: &'a [u8; 32],
    /// The salt is a WebAuthn PRF input (flag bit 0).
    pub prf: bool,
    /// User verification is required (flag bit 1).
    pub uv: bool,
}

pub fn parse<'a>(slot: &SlotView<'a>) -> Result<Fido2Slot<'a>> {
    let _ = slot;
    Err(not_built("security-key slots"))
}

pub fn make(
    credential_id: &[u8],
    rp_id: &str,
    salt: &[u8; 32],
    prf: bool,
    secret: &Zeroizing<[u8; 32]>,
) -> Result<MadeSlot> {
    let _ = (credential_id, rp_id, salt, prf, secret);
    Err(not_built("security-key slots"))
}

pub fn check(public: &[u8]) -> Result<()> {
    let _ = public;
    Err(not_built("security-key slots"))
}
