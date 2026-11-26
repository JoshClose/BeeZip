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
    use beezip_core::format::bhive::{crypt::mldsa, sign::MESSAGE_LEN};

    use super::*;

    /// The value of what is built. Until PR C's key text and store are in (docs/M14.md §10),
    /// what they would do ends in `not_built`, and the test checks only what it can; any other
    /// error fails it.
    fn built<T>(r: Result<T>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(e) if e.message.contains("not built yet") => None,
            Err(e) => panic!("{e}"),
        }
    }

    fn example() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/bhive-m14/vectors.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["signed_example"].clone()
    }

    fn hex(ex: &serde_json::Value, k: &str) -> Vec<u8> {
        let s = ex[k].as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The specification's example key (docs/bhive.md §13.5), as its two texts.
    #[test]
    fn the_specifications_example_key() {
        let ex = example();
        let public = [hex(&ex, "ed25519_public"), hex(&ex, "mldsa_public")].concat();
        assert_eq!(public.len(), 1984);
        let signer_text = ex["signer_text"].as_str().unwrap();
        let secret_text = ex["secret_text"].as_str().unwrap();
        assert!(signer_text.starts_with("bzsig1"));
        assert!(secret_text.starts_with("BZSIG-SECRET-KEY-1"));

        if let Some(got) = built(public_of(signer_text)) {
            assert_eq!(got, public);
        }
        if let Some(s) = built(signer_of(secret_text)) {
            assert_eq!(s.algorithm().id(), 1);
            assert_eq!(s.signer_bytes(), public);
            let message: [u8; MESSAGE_LEN] = hex(&ex, "message").try_into().unwrap();
            let signature = s.sign(&message).unwrap();
            // Ed25519 is deterministic; ML-DSA here is randomized, so it is only checked.
            assert_eq!(signature[..64], hex(&ex, "ed25519_signature"));
            assert!(mldsa::verify(&public, &message, &signature).unwrap());
        }
        // Each text where the other is wanted, and no key at all, are refused.
        for e in [
            public_of(secret_text).err(),
            signer_of(signer_text).err(),
            public_of("bzsig1").err(),
            signer_of("BZSIG-SECRET-KEY-1").err(),
        ] {
            assert!(e.is_some_and(|e| !e.message.is_empty()));
        }
    }

    /// A signing key made in a store of its own signs, and is one of your signers; a key that
    /// opens archives isn't.
    #[test]
    fn a_stored_signing_key_signs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf());
        assert!(signer(&store, "me").is_err());
        let Some(entry) = built(store.create("me", KeyKind::Signing)) else {
            assert!(built(own_signers(&store)).is_none_or(|o| o.is_empty()));
            return;
        };
        assert!(entry.own && entry.kind == KeyKind::Signing);
        let s = signer(&store, "me").unwrap();
        assert_eq!(public_of(&entry.public).unwrap(), s.signer_bytes());
        assert_eq!(own_signers(&store).unwrap(), vec![s.signer_bytes()]);
        let message = [7; MESSAGE_LEN];
        let signature = s.sign(&message).unwrap();
        assert!(mldsa::verify(&s.signer_bytes(), &message, &signature).unwrap());

        // Its secret's text, imported elsewhere, is the same key.
        let secret = store.export("me", true).unwrap();
        assert_eq!(signer_of(&secret).unwrap().signer_bytes(), s.signer_bytes());

        store.create("opens", KeyKind::XWing).unwrap();
        let e = signer(&store, "opens").err().unwrap();
        assert!(e.message.contains("can't sign"), "{e}");
        assert_eq!(own_signers(&store).unwrap().len(), 1);
    }
}
