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
            ecdh, rsa, sig,
        },
        sign::{Algorithm, MAX_CERTIFICATES, MESSAGE_LEN, Signer},
    },
};
use security_framework::{
    certificate::SecCertificate,
    identity::SecIdentity,
    item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult},
    key::{Algorithm as SecAlgorithm, SecKey},
    os::macos::import_export::{ImportOptions, SecItems},
    policy::SecPolicy,
    trust::{SecTrust, TrustOptions},
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
                let certificate = cert::parse_der(&der).ok()?;
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
        signer: sig::signer_bytes(&chain_of(&certificate.der))?,
    }))
}

/// The chain the Keychain has for a certificate, its own first, without its root (which a
/// reader must have anyway), as the signature carries it (docs/M14.md §11). Built offline,
/// from the keychains alone; a chain that stops short of a root keeps its last intermediate.
fn chain_of(der: &[u8]) -> Vec<Vec<u8>> {
    let built = || -> Option<Vec<Vec<u8>>> {
        let leaf = SecCertificate::from_der(der).ok()?;
        let mut trust =
            SecTrust::create_with_certificates(&[leaf], &[SecPolicy::create_x509()]).ok()?;
        trust.set_network_fetch_allowed(false).ok()?;
        // Whether or not it is trusted, evaluating builds the chain.
        let _ = trust.evaluate_with_error();
        #[allow(
            deprecated,
            reason = "chain() needs security-framework's macos-12 feature"
        )]
        let count = trust.certificate_count();
        #[allow(
            deprecated,
            reason = "chain() needs security-framework's macos-12 feature"
        )]
        let ders = (0..count)
            .map(|i| trust.certificate_at_index(i).map(|c| c.to_der()))
            .collect::<Option<Vec<_>>>()?;
        Some(ders)
    };
    let mut ders = built()
        .filter(|d| d.first().map(Vec::as_slice) == Some(der))
        .unwrap_or_else(|| vec![der.to_vec()]);
    if ders.len() > 1 && ders.last().is_some_and(|d| cert::self_issued(d)) {
        ders.pop();
    }
    ders.truncate(MAX_CERTIFICATES);
    ders
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

const ERR_SEC_CERTIFICATE_EXPIRED: isize = -67818;
const ERR_SEC_CERTIFICATE_REVOKED: isize = -67820;

/// SecTrust with the basic X.509 policy over `certificates`, the signer's first. `Expired` and
/// `Revoked` only for a chain macOS otherwise trusts: the certificates came with the archive,
/// and its maker chose their names and dates. Offline first, as on Windows: their URLs are the
/// maker's too. Only a chain macOS trusts offline is evaluated again with the network allowed,
/// for its revocation (decision 25).
pub fn evaluate(certificates: &[Vec<u8>]) -> Result<Evaluation> {
    let certs = certificates
        .iter()
        .map(|der| SecCertificate::from_der(der).map_err(|e| keychain_error("a certificate", e)))
        .collect::<Result<Vec<_>>>()?;
    let make = |network: bool, options: Option<TrustOptions>| -> Result<SecTrust> {
        let mut trust = SecTrust::create_with_certificates(&certs, &[SecPolicy::create_x509()])
            .map_err(|e| keychain_error("SecTrust", e))?;
        trust
            .set_network_fetch_allowed(network)
            .map_err(|e| keychain_error("SecTrust", e))?;
        if let Some(options) = options {
            trust
                .set_options(options)
                .map_err(|e| keychain_error("SecTrust", e))?;
        }
        Ok(trust)
    };
    let offline = make(false, None)?;
    match offline.evaluate_with_error() {
        Ok(()) => {}
        // Trusted but for its dates?
        Err(e) if e.code() == ERR_SEC_CERTIFICATE_EXPIRED => {
            let undated = make(
                false,
                Some(TrustOptions::ALLOW_EXPIRED | TrustOptions::ALLOW_EXPIRED_ROOT),
            )?;
            return Ok(if undated.evaluate_with_error().is_ok() {
                Evaluation::Expired
            } else {
                Evaluation::Untrusted
            });
        }
        // Revoked by an issuer whose root the system trusts?
        Err(e) if e.code() == ERR_SEC_CERTIFICATE_REVOKED => {
            return Ok(if ends_at_a_system_root(&offline) {
                Evaluation::Revoked
            } else {
                Evaluation::Untrusted
            });
        }
        Err(_) => return Ok(Evaluation::Untrusted),
    }
    // Trusted offline: now its revocation, which may ask the issuer. A check that can't be
    // made leaves it trusted, as Windows' does.
    Ok(match make(true, None)?.evaluate_with_error() {
        Err(e) if e.code() == ERR_SEC_CERTIFICATE_REVOKED => Evaluation::Revoked,
        _ => Evaluation::Trusted,
    })
}

/// Whether an evaluated chain's last certificate is one of the system's roots.
fn ends_at_a_system_root(trust: &SecTrust) -> bool {
    #[allow(
        deprecated,
        reason = "chain() needs security-framework's macos-12 feature"
    )]
    let count = trust.certificate_count();
    #[allow(
        deprecated,
        reason = "chain() needs security-framework's macos-12 feature"
    )]
    let last = if count > 0 {
        trust.certificate_at_index(count - 1)
    } else {
        None
    };
    let (Some(last), Ok(roots)) = (last, SecTrust::copy_anchor_certificates()) else {
        return false;
    };
    let last = last.to_der();
    roots.iter().any(|r| r.to_der() == last)
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

    /// A self-signed certificate is untrusted, expired or not: its maker chose its dates.
    #[test]
    fn a_self_signed_certificate_is_untrusted_whatever_its_dates() {
        for file in ["rsa.crt", "rsa-expired.crt"] {
            let der = cert::parse(&std::fs::read(data(file)).unwrap())
                .unwrap()
                .der;
            assert_eq!(evaluate(&[der]).unwrap(), Evaluation::Untrusted, "{file}");
        }
    }

    /// A chain built for a certificate the Keychain has no issuer for is the certificate alone.
    #[test]
    fn a_signers_chain_is_its_certificate_without_a_root() {
        let pem = std::fs::read(data("chain.pem")).unwrap();
        let leaf = cert::parse(&pem).unwrap().der;
        assert_eq!(chain_of(&leaf), vec![leaf.clone()]);
        let root = cert::parse_all(&pem).unwrap()[1].der.clone();
        assert!(cert::self_issued(&root));
        assert!(!cert::self_issued(&leaf));
    }

    #[test]
    fn public_keys_import_in_memory() {
        let spki = cert::parse(&std::fs::read(data("p256.crt")).unwrap())
            .unwrap()
            .spki;
        assert!(public_key(&spki).is_ok());
    }
}
