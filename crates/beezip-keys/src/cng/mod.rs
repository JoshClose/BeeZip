//! Windows: certificate stores, CNG keys in software, on smart cards and in the TPM, "This PC",
//! and chain checks (docs/M14.md §6, §14; the Windows spike in target/m14-spikes/winkeys).
//! PR D builds it.
//!
//! What the spike found, which this must respect: CNG's `BCRYPT_KDF_HKDF` is broken and can
//! crash the process, so EC slots use `BCRYPT_KDF_HMAC` with the slot's context as
//! `KDF_HMAC_KEY`; `BCRYPT_KDF_RAW_SECRET` is little-endian; ECDSA keys can't do ECDH; TPM
//! RSA-OAEP needs an empty label; the TPM provider refuses `NCRYPT_SILENT_FLAG` on delete; its
//! provider-handle property is borrowed, not owned.

use std::sync::Arc;

use beezip_core::{
    Result,
    format::bhive::{
        crypt::{KeySource, cert::Certificate},
        sign::Signer,
    },
};

use crate::not_built;

/// A certificate in one of the user's stores, as `certificates.list` shows it.
#[derive(Debug, Clone)]
pub struct StoreCertificate {
    pub certificate: Certificate,
    /// `My` (Personal) or `AddressBook` (Other People).
    pub store: String,
    /// Where its private key is, when this machine has it.
    pub key: Option<KeyHome>,
    /// Windows trusts its chain.
    pub trusted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyHome {
    Software,
    SmartCard,
    Tpm,
}

/// The certificates of Personal and Other People that can encrypt or sign.
pub fn certificates() -> Result<Vec<StoreCertificate>> {
    Err(not_built("Windows' certificate stores"))
}

/// A key source over the Personal store's keys and "This PC" keys.
pub fn source() -> Result<Box<dyn KeySource + Send>> {
    Err(not_built("Windows' certificate keys"))
}

/// A new "This PC" key in the TPM (ECDH P-256), optionally with a PIN: its name and
/// SubjectPublicKeyInfo.
pub fn create_this_pc(pin: Option<&str>) -> Result<(String, Vec<u8>)> {
    let _ = pin;
    Err(not_built("This PC keys"))
}

/// A signer for the certificate with this SHA-1 thumbprint, whose key is on this machine.
pub fn signer(thumbprint: &[u8; 20]) -> Result<Arc<dyn Signer>> {
    let _ = thumbprint;
    Err(not_built("signing with certificates"))
}
