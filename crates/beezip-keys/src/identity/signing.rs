//! Your BeeZip signing key as a [`Signer`] (docs/M14.md §11, decision 24): a hybrid of
//! ML-DSA-65 and Ed25519 (core's `crypt::mldsa`), kept in the [`super::Store`] as the other
//! keys are, and written as `bzsig1…` and `BZSIG-SECRET-KEY-1…` (docs/bhive.md §13.5).

use std::sync::Arc;

use beezip_core::{
    Error, Result,
    format::bhive::{
        crypt::{
            bech32::{KeyText, parse_key},
            mldsa::{HybridKey, HybridSigner},
        },
        sign::Signer,
    },
};

use super::{KeyKind, Store};

/// The signer for a signing key's text, `BZSIG-SECRET-KEY-1…`.
pub fn signer_of(text: &str) -> Result<Arc<dyn Signer>> {
    match parse_key(text.trim())? {
        KeyText::SigningSecret(seeds) => Ok(Arc::new(HybridSigner::new(HybridKey { seeds })?)),
        _ => Err(Error::invalid_args(
            "that isn't a BeeZip signing key's secret (BZSIG-SECRET-KEY-1…)",
        )),
    }
}

/// The signer for your key `name`.
pub fn signer(store: &Store, name: &str) -> Result<Arc<dyn Signer>> {
    let entry = store
        .list()?
        .into_iter()
        .find(|e| e.name == name && e.own)
        .ok_or_else(|| Error::invalid_args(format!("you have no key called {name}")))?;
    if entry.kind != KeyKind::Signing {
        return Err(Error::invalid_args(format!(
            "{name} opens archives; it can't sign them. Make a signing key for that"
        )));
    }
    signer_of(&store.export(name, true)?)
}

/// The signer bytes of a signing key's public text, `bzsig1…`.
pub fn public_of(text: &str) -> Result<Vec<u8>> {
    match parse_key(text.trim())? {
        KeyText::SigningPublic(public) => Ok(public.to_vec()),
        _ => Err(Error::invalid_args(
            "that isn't a BeeZip signing key (bzsig1…)",
        )),
    }
}

/// Your signing keys' public halves, to tell your own signatures (`trust`).
pub fn own_signers(store: &Store) -> Result<Vec<Vec<u8>>> {
    store
        .list()?
        .into_iter()
        .filter(|e| e.own && e.kind == KeyKind::Signing)
        .map(|e| public_of(&e.public))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Until PR C's store is in, every way to a stored key says so (docs/M14.md §10).
    #[test]
    fn a_store_that_isnt_built_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf());
        for e in [
            signer(&store, "me").err(),
            own_signers(&store).err(),
            signer_of("BZSIG-SECRET-KEY-1").err(),
            public_of("bzsig1").err(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!e.message.is_empty());
        }
    }
}
