//! Windows: security keys and Windows Hello through webauthn.dll (docs/M14.md §4, slot kind 8).
//! PR E builds it.
//!
//! From the spike: webauthn.dll's API is version 9 here, and `windows` 0.62.2's bindings stop
//! at 7, so the newer structures are declared here. Registration and every unlock show the
//! Windows Security dialog; BeeZip always asks for user verification. hmac-secret is asked for
//! raw (`WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`) or as PRF, as the slot's flag says.

use beezip_core::{
    Result,
    format::bhive::crypt::{KeySource, Recipient},
};

use crate::not_built;

/// Whether this machine can make a security-key slot, and Windows Hello one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Support {
    pub security_keys: bool,
    pub hello: bool,
}

pub fn support() -> Support {
    Support {
        security_keys: false,
        hello: false,
    }
}

/// Registers a credential (or uses `credential`), asks it for the hmac-secret of a fresh
/// salt, and returns the recipient core makes the slot from. Shows Windows' dialog, parented to
/// `window` when there is one.
pub fn recipient(
    hello: bool,
    credential: Option<&[u8]>,
    window: Option<isize>,
) -> Result<Recipient> {
    let _ = (hello, credential, window);
    Err(not_built("security keys"))
}

/// A key source for kind-8 slots: offers every one, and asks the authenticator only when the
/// user chose it.
pub fn source(window: Option<isize>) -> Result<Box<dyn KeySource + Send>> {
    let _ = window;
    Err(not_built("security keys"))
}
