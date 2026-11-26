//! Checking the certificate algorithms' signatures, 2 to 5 (bhive.md §13.4): RSA-PSS, RSA
//! PKCS #1 v1.5, ECDSA P-256 and P-384, through `ring`. Signing with a certificate belongs to
//! `beezip-keys` (CNG, Keychain) or a key file (PR D). PR H builds this.

use super::not_built;
use crate::Result;

/// The certificates of a signer field: DER, the signer's first.
pub fn certificates(signer: &[u8]) -> Result<Vec<Vec<u8>>> {
    let _ = signer;
    Err(not_built("certificate signers"))
}

/// A signer field for these certificates.
pub fn signer_bytes(certificates: &[Vec<u8>]) -> Result<Vec<u8>> {
    let _ = certificates;
    Err(not_built("certificate signers"))
}

/// Whether `signature` of `message` checks under the SubjectPublicKeyInfo `spki`, for
/// `algorithm` 2 to 5.
pub fn verify(algorithm: u8, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let _ = (algorithm, spki, message, signature);
    Err(not_built("checking certificate signatures"))
}
