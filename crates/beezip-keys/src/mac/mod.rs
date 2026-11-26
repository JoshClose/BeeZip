//! macOS: Keychain identities through Security.framework (docs/M14.md §6, §11): certificate
//! slots opened with an identity's key (RSA-OAEP, ECDH), signing with it (RSA-PSS, ECDSA), and
//! the system's trust evaluation for signers.
//!
//! The Keychain may ask the user before an app uses a private key, so an identity's key is
//! only used for a way in the user chose (a slot's `device`), or to sign. Finding which slot
//! is whose needs only the certificates, and never asks.

use std::sync::Arc;

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::{
        crypt::{
            Curve, KeySource, SlotKind, SlotSecret, SlotView,
            cert::{self, Certificate, KeyAlgorithm},
            ecdh, rsa,
        },
        sign::{Algorithm, MESSAGE_LEN, Signer},
    },
};
use security_framework::{
    identity::SecIdentity,
    item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult},
    key::{Algorithm as SecAlgorithm, SecKey},
    os::macos::import_export::{ImportOptions, SecItems},
};
use zeroize::Zeroizing;

fn keychain_error(what: &str, e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, format!("{what}: {e}"))
}

/// The identities (a certificate and its private key) in the user's keychains, with their
/// certificates parsed. Those that don't parse are left out.
fn identities() -> Vec<(SecIdentity, Certificate)> {
    let found = ItemSearchOptions::new()
        .class(ItemClass::identity())
        .load_refs(true)
        .limit(Limit::All)
        .search()
        .unwrap_or_default();
    found
        .into_iter()
        .filter_map(|r| match r {
            SearchResult::Ref(Reference::Identity(id)) => {
                let der = id.certificate().ok()?.to_der();
                let certificate = cert::parse(&der).ok()?;
                Some((id, certificate))
            }
            _ => None,
        })
        .collect()
}

/// The Keychain's identities, as a key source.
pub struct KeychainSource {
    identities: Vec<(SecIdentity, Certificate)>,
}

fn fits(certificate: &Certificate, slot: &SlotView<'_>) -> bool {
    let kind = matches!(
        (slot.kind, certificate.algorithm),
        (SlotKind::Rsa, KeyAlgorithm::Rsa { .. })
            | (SlotKind::EcP256, KeyAlgorithm::Ec(Curve::P256))
            | (SlotKind::EcP384, KeyAlgorithm::Ec(Curve::P384))
    );
    kind && cert::tag_matches(slot, &certificate.spki)
}

/// A public key as Security.framework has it, from its SubjectPublicKeyInfo, in memory only
/// (no keychain).
fn public_key(spki: &[u8]) -> Result<SecKey> {
    let pem = cert::pem("PUBLIC KEY", spki)?;
    let mut items = SecItems::default();
    ImportOptions::new()
        .filename("key.pem")
        .items(&mut items)
        .import(pem.as_bytes())
        .map_err(|e| keychain_error("importing a public key", e))?;
    items.keys.into_iter().next().ok_or_else(|| {
        Error::new(
            ErrorKind::Io,
            "a public key that Security.framework didn't take",
        )
    })
}

fn open(key: &SecKey, certificate: &Certificate, slot: &SlotView<'_>) -> Result<SlotSecret> {
    match certificate.algorithm {
        KeyAlgorithm::Rsa { .. } => {
            let ct = rsa::ciphertext(slot).ok_or_else(|| Error::corrupt("a damaged RSA slot"))?;
            let plain = key
                .decrypt_data(SecAlgorithm::RSAEncryptionOAEPSHA256, ct)
                .map_err(|e| keychain_error("RSA-OAEP with the Keychain's key", e))?;
            rsa::from_plaintext(Zeroizing::new(plain))
        }
        KeyAlgorithm::Ec(curve) => {
            let point = ecdh::ephemeral(slot).ok_or_else(|| Error::corrupt("a damaged EC slot"))?;
            let peer = public_key(&ecdh::spki_of_point(curve, point)?)?;
            // "Standard" is the shared point's x-coordinate, as bhive.md §12.5 takes it.
            let z = key
                .key_exchange(
                    SecAlgorithm::ECDHKeyExchangeStandard,
                    &peer,
                    curve.point_len() / 2,
                    None,
                )
                .map_err(|e| keychain_error("ECDH with the Keychain's key", e))?;
            let z = Zeroizing::new(z);
            let recipient = ecdh::point_of_spki(curve, &certificate.spki)?;
            Ok(ecdh::extract(slot, &recipient, &z))
        }
        KeyAlgorithm::Other => Err(Error::corrupt("not a certificate slot")),
    }
}

impl KeySource for KeychainSource {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        self.identities.iter().any(|(_, c)| fits(c, slot))
    }

    fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>> {
        if !device {
            // Using the key may show the Keychain's prompt: only for a way in the user chose.
            return Ok(None);
        }
        let Some((id, certificate)) = self.identities.iter().find(|(_, c)| fits(c, slot)) else {
            return Ok(None);
        };
        let key = id
            .private_key()
            .map_err(|e| keychain_error("the identity's private key", e))?;
        open(&key, certificate, slot).map(Some)
    }
}

/// A key source over the Keychain's identities.
pub fn source() -> Result<Box<dyn KeySource + Send>> {
    Ok(Box::new(KeychainSource {
        identities: identities(),
    }))
}

/// A signer for the Keychain identity whose certificate has this SHA-1 thumbprint. Signing may
/// show the Keychain's prompt.
pub fn signer(thumbprint: &[u8; 20]) -> Result<Arc<dyn Signer>> {
    let (id, certificate) = identities()
        .into_iter()
        .find(|(_, c)| &c.thumbprint == thumbprint)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                "no identity in the Keychain has that certificate",
            )
        })?;
    let algorithm = crate::files::may_sign(&certificate)?;
    let key = id
        .private_key()
        .map_err(|e| keychain_error("the identity's private key", e))?;
    Ok(Arc::new(KeychainSigner {
        key,
        algorithm,
        signer: cert::chain_bytes(&[certificate.der.clone()])?,
    }))
}

struct KeychainSigner {
    key: SecKey,
    algorithm: Algorithm,
    signer: Vec<u8>,
}

impl Signer for KeychainSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn signer_bytes(&self) -> Vec<u8> {
        self.signer.clone()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        let hash = cert::digest(self.algorithm, message)?;
        let sec = match self.algorithm {
            Algorithm::RsaPss => SecAlgorithm::RSASignatureDigestPSSSHA256,
            Algorithm::RsaPkcs1 => SecAlgorithm::RSASignatureDigestPKCS1v15SHA256,
            Algorithm::EcdsaP256 => SecAlgorithm::ECDSASignatureDigestX962SHA256,
            Algorithm::EcdsaP384 => SecAlgorithm::ECDSASignatureDigestX962SHA384,
            Algorithm::MlDsa65Ed25519 => {
                return Err(Error::new(
                    ErrorKind::InvalidArgs,
                    "not a certificate's algorithm",
                ));
            }
        };
        let sig = self
            .key
            .create_signature(sec, &hash)
            .map_err(|e| keychain_error("signing with the Keychain's key", e))?;
        // Security.framework gives ECDSA as DER; a signature holds `r ‖ s` (bhive.md §13.4).
        match self.algorithm {
            Algorithm::EcdsaP256 | Algorithm::EcdsaP384 => cert::ecdsa_fixed(self.algorithm, &sig),
            _ => Ok(sig),
        }
    }
}

/// What the system's trust evaluation makes of a signer's certificates, the signer's first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluation {
    Trusted,
    Expired,
    Revoked,
    Untrusted,
}

/// SecTrust with the basic X.509 policy over `certificates`.
pub fn evaluate(certificates: &[Vec<u8>]) -> Result<Evaluation> {
    use security_framework::{certificate::SecCertificate, policy::SecPolicy, trust::SecTrust};
    let certs = certificates
        .iter()
        .map(|der| SecCertificate::from_der(der).map_err(|e| keychain_error("a certificate", e)))
        .collect::<Result<Vec<_>>>()?;
    let trust = SecTrust::create_with_certificates(&certs, &[SecPolicy::create_x509()])
        .map_err(|e| keychain_error("SecTrust", e))?;
    Ok(match trust.evaluate_with_error() {
        Ok(()) => Evaluation::Trusted,
        // errSecCertificateExpired, errSecCertificateRevoked.
        Err(e) if e.code() == -67818 => Evaluation::Expired,
        Err(e) if e.code() == -67820 => Evaluation::Revoked,
        Err(_) => Evaluation::Untrusted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::{data, hex, vectors, view};

    /// The Keychain is only read: a source over it offers nothing for a slot made for a test
    /// key, and never uses a key without the user's choice.
    #[test]
    fn the_keychain_is_read_without_asking() {
        let v = vectors();
        let key_id = [2; beezip_core::format::bhive::crypt::KEY_ID_LEN];
        let slot = hex(&v["slots"]["rsa"]["slot"]);
        let mut source = source().unwrap();
        assert!(!source.offers(&view(&slot, &key_id)));
        assert!(
            source
                .secret(&view(&slot, &key_id), false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_self_signed_certificate_is_untrusted() {
        let der = cert::parse(&std::fs::read(data("rsa.crt")).unwrap())
            .unwrap()
            .der;
        assert_ne!(evaluate(&[der]).unwrap(), Evaluation::Trusted);
    }

    #[test]
    fn public_keys_import_in_memory() {
        let spki = cert::parse(&std::fs::read(data("p256.crt")).unwrap())
            .unwrap()
            .spki;
        assert!(public_key(&spki).is_ok());
    }
}
