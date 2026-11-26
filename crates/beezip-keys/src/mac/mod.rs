//! macOS: Keychain identities and `.p12` files through Security.framework (docs/M14.md §6).
//! PR D builds it.

use beezip_core::{Result, format::bhive::crypt::KeySource};

use crate::not_built;

/// A key source over the login Keychain's identities.
pub fn source() -> Result<Box<dyn KeySource + Send>> {
    Err(not_built("Keychain identities"))
}
