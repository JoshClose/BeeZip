//! Your BeeZip signing key as a [`Signer`] (docs/M14.md §11, decision 24): a hybrid of
//! ML-DSA-65 and Ed25519 (core's `crypt::mldsa`), kept in the [`super::Store`] as the other
//! keys are. PR H builds it.

use std::sync::Arc;

use beezip_core::{
    Result,
    format::bhive::sign::{MESSAGE_LEN, Signer},
};

use super::Store;
use crate::not_built;

/// The signer for your key `name`.
pub fn signer(store: &Store, name: &str) -> Result<Arc<dyn Signer>> {
    let _ = (store, name);
    Err(not_built("signing with your key"))
}

/// Your signing keys' public halves, to tell your own signatures (`trust`).
pub fn own_signers(store: &Store) -> Result<Vec<Vec<u8>>> {
    let _ = store;
    Err(not_built("your signing keys"))
}

#[allow(dead_code, reason = "PR H builds the signer")]
const _: usize = MESSAGE_LEN;
