//! Key files and certificate files, on every system (docs/M14.md §6): PEM and PKCS #8 private
//! keys, plain or under a password; `.cer`, `.crt`, `.der`, `.pem` certificates; age identity
//! files. PR D builds it (age identity files with PR C's parsing).

use std::{path::Path, sync::Arc};

use beezip_core::{
    Result,
    format::bhive::{
        crypt::{KeySource, cert::Certificate},
        sign::Signer,
    },
};

use crate::not_built;

/// A key source over private-key files given for one job (`--identity`).
pub fn source(paths: &[&Path], password: Option<&str>) -> Result<Box<dyn KeySource + Send>> {
    let _ = (paths, password);
    Err(not_built("key files"))
}

/// A certificate, or a public key, from a file: to encrypt to, or to add as a contact.
pub fn certificate(path: &Path) -> Result<Certificate> {
    let _ = path;
    Err(not_built("certificate files"))
}

/// A signer for a certificate whose private key is in a file.
pub fn signer(certificate: &Path, key: &Path, password: Option<&str>) -> Result<Arc<dyn Signer>> {
    let _ = (certificate, key, password);
    Err(not_built("signing with key files"))
}
