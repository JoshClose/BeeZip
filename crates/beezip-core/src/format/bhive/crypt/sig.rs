//! Checking the certificate algorithms' signatures, 2 to 5 (bhive.md §13.4): RSA-PSS, RSA
//! PKCS #1 v1.5, ECDSA P-256 and P-384, through `ring`. Signing with a certificate belongs to
//! `beezip-keys` (CNG, Keychain) or a key file (PR D).
//!
//! A key that isn't the algorithm's, or is outside §13.4's limits, is an error here: the
//! signature couldn't be checked. A signature that doesn't verify is `Ok(false)`.

use der::{
    Decode, Encode,
    asn1::{AnyRef, ObjectIdentifier},
};
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, RSA_PKCS1_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA256, UnparsedPublicKey, VerificationAlgorithm,
};
use spki::SubjectPublicKeyInfoRef;

use crate::{
    Error, ErrorKind, Result,
    format::bhive::{
        crypt::cert,
        layout::{Bytes, put_uvarint},
        sign::{Algorithm, MAX_CERTIFICATES},
    },
};

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

fn refused(what: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Corrupt, format!("bhive: {what}"))
}

/// The certificates of a signer field: DER, the signer's first. 1 to 8 of them, and nothing
/// after.
pub fn certificates(signer: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut b = Bytes::new(signer);
    let count = b.uvarint()?;
    if count == 0 || count > MAX_CERTIFICATES as u64 {
        return Err(refused(format!(
            "a signer of {count} certificates, not 1 to {MAX_CERTIFICATES}"
        )));
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let len = usize::try_from(b.uvarint()?).map_err(|_| refused("a certificate too long"))?;
        out.push(b.take(len)?.to_vec());
    }
    if b.left() != 0 {
        return Err(refused("bytes after a signer's certificates"));
    }
    Ok(out)
}

/// A signer field for these certificates, the signer's first.
pub fn signer_bytes(certificates: &[Vec<u8>]) -> Result<Vec<u8>> {
    if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
        return Err(Error::invalid_args(format!(
            "a signature carries 1 to {MAX_CERTIFICATES} certificates, not {}",
            certificates.len()
        )));
    }
    let mut out = Vec::new();
    put_uvarint(&mut out, certificates.len() as u64);
    for c in certificates {
        put_uvarint(&mut out, c.len() as u64);
        out.extend_from_slice(c);
    }
    Ok(out)
}

/// The SubjectPublicKeyInfo of a certificate in DER.
pub fn spki_of(certificate: &[u8]) -> Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(certificate)
        .map_err(|e| refused(format!("a signer's certificate doesn't parse ({e})")))?;
    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| refused(format!("a signer's public key ({e})")))
}

/// What `ring` checks `algorithm`'s signatures with, and the key it takes, from `spki`; or why
/// the key can't be the algorithm's (bhive.md §13.4).
fn key_for(algorithm: u8, spki: &[u8]) -> Result<(&'static dyn VerificationAlgorithm, Vec<u8>)> {
    let algorithm = Algorithm::from_id(algorithm)
        .ok_or_else(|| refused(format!("signature algorithm {algorithm} is unknown")))?;
    let info = SubjectPublicKeyInfoRef::from_der(spki)
        .map_err(|e| refused(format!("a signer's public key doesn't parse ({e})")))?;
    let key = info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| refused("a signer's public key isn't whole bytes"))?;
    let oid = info.algorithm.oid;
    let curve = || {
        info.algorithm
            .parameters
            .and_then(|p: AnyRef<'_>| p.decode_as::<ObjectIdentifier>().ok())
    };
    match algorithm {
        Algorithm::MlDsa65Ed25519 => Err(refused(
            "a BeeZip signing key's signature has no certificate",
        )),
        Algorithm::RsaPss | Algorithm::RsaPkcs1 => {
            if oid != RSA_ENCRYPTION {
                return Err(refused(format!(
                    "the signer's key isn't RSA ({oid}), as algorithm {} needs",
                    algorithm.id()
                )));
            }
            // §13.4's limits, as a writer's certificate is held to them.
            cert::check_rsa(spki)
                .map_err(|why| refused(format!("the signer's certificate: {why}")))?;
            let ring: &'static dyn VerificationAlgorithm = match algorithm {
                Algorithm::RsaPss => &RSA_PSS_2048_8192_SHA256,
                _ => &RSA_PKCS1_2048_8192_SHA256,
            };
            Ok((ring, key.to_vec()))
        }
        Algorithm::EcdsaP256 | Algorithm::EcdsaP384 => {
            let (want, ring, point): (_, &'static dyn VerificationAlgorithm, _) = match algorithm {
                Algorithm::EcdsaP256 => (P256, &ECDSA_P256_SHA256_FIXED, 65),
                _ => (P384, &ECDSA_P384_SHA384_FIXED, 97),
            };
            if oid != EC_PUBLIC_KEY || curve() != Some(want) {
                return Err(refused(format!(
                    "the signer's key isn't on the curve algorithm {} needs",
                    algorithm.id()
                )));
            }
            // `ring` takes the uncompressed point only.
            if key.len() != point || key[0] != 4 {
                return Err(refused("the signer's EC key isn't an uncompressed point"));
            }
            Ok((ring, key.to_vec()))
        }
    }
}

/// Whether `signature` of `message` checks under the SubjectPublicKeyInfo `spki`, for
/// `algorithm` 2 to 5. A key that isn't the algorithm's, or is outside the limits, is an error:
/// the signature couldn't be checked.
pub fn verify(algorithm: u8, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let (ring, key) = key_for(algorithm, spki)?;
    Ok(UnparsedPublicKey::new(ring, key)
        .verify(message, signature)
        .is_ok())
}
