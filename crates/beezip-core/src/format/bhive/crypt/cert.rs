//! Certificates and public keys from files and stores: what kind of slot or signature a key
//! can make, and what to show (docs/M14.md §4, §11). PR D builds it.

use super::{Curve, SlotKind, not_built};
use crate::Result;

/// A public key's algorithm, from its SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa { bits: u32 },
    Ec(Curve),
    Other,
}

/// A certificate, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub spki: Vec<u8>,
    pub algorithm: KeyAlgorithm,
    pub subject: String,
    pub issuer: String,
    /// Seconds since 1970.
    pub not_before: i64,
    pub not_after: i64,
    /// What its key usage allows; `None` when the certificate doesn't say.
    pub key_encipherment: Option<bool>,
    pub key_agreement: Option<bool>,
    pub digital_signature: Option<bool>,
    /// SHA-1 of the DER, as Windows shows it.
    pub thumbprint: [u8; 20],
}

impl Certificate {
    /// The slot it can be encrypted to, or why not (docs/M14.md §4: ECDSA-only keys, RSA under
    /// 2,048 bits, a key usage that forbids it).
    pub fn slot_kind(&self) -> std::result::Result<SlotKind, String> {
        Err("certificates are not built yet (docs/M14.md)".into())
    }
}

/// A certificate from DER or PEM.
pub fn parse(bytes: &[u8]) -> Result<Certificate> {
    let _ = bytes;
    Err(not_built("certificates"))
}

/// A key's algorithm from its SubjectPublicKeyInfo.
pub fn spki_algorithm(spki: &[u8]) -> Result<KeyAlgorithm> {
    let _ = spki;
    Err(not_built("public keys"))
}
