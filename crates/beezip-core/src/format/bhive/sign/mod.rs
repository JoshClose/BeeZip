//! Signatures on a `.bhive` (bhive.md §13, docs/M14.md §11): the cells' digests (index
//! section 2), the manifest, the signature section (3), and checking them. Encrypted or not.
//! PR H builds it; certificates sign through `beezip-keys` (PR D), which implements
//! [`Signer`] for them.

use std::sync::Arc;

use super::layout::{Cell, Index};
use crate::{
    Result,
    format::bhive::crypt::{label, not_built},
};

/// The message every algorithm signs is this long (bhive.md §13.3).
pub const MESSAGE_LEN: usize = 113;
/// What a reader checks at most (bhive.md §13.3, §13.4).
pub const MAX_SIGNATURES: usize = 16;
pub const MAX_CERTIFICATES: usize = 8;
pub const MAX_SECTION_LEN: usize = 1 << 20;
pub const RSA_BITS: std::ops::RangeInclusive<u32> = 2048..=8192;
/// An RSA exponent is odd and from 3 to 2^32 − 1.
pub const RSA_EXPONENT: std::ops::RangeInclusive<u64> = 3..=0xFFFF_FFFF;

/// A signature algorithm (bhive.md §13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Your BeeZip signing key: ML-DSA-65 and Ed25519.
    MlDsa65Ed25519 = 1,
    RsaPss = 2,
    RsaPkcs1 = 3,
    EcdsaP256 = 4,
    EcdsaP384 = 5,
}

impl Algorithm {
    pub const ALL: [Self; 5] = [
        Self::MlDsa65Ed25519,
        Self::RsaPss,
        Self::RsaPkcs1,
        Self::EcdsaP256,
        Self::EcdsaP384,
    ];

    pub const fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.id() == id)
    }

    /// Whether a quantum computer can't forge it.
    pub const fn post_quantum(self) -> bool {
        matches!(self, Self::MlDsa65Ed25519)
    }
}

/// Makes one signature: your BeeZip key (`crypt::mldsa`, PR H), or a certificate's key in
/// CNG, the Keychain or a file (`beezip-keys`, PR D).
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> Algorithm;
    /// The signer field: the public key, or the certificates (bhive.md §13.4).
    fn signer_bytes(&self) -> Vec<u8>;
    /// The signature of the 113-byte message. A smart card or TPM key may show Windows' PIN
    /// dialog here.
    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>>;
}

/// What a writer signs with.
#[derive(Clone, Default)]
pub struct Signing {
    pub signers: Vec<Arc<dyn Signer>>,
    /// The signing time each signature claims, as seconds since 1970; `None` is now.
    pub time: Option<i64>,
}

impl std::fmt::Debug for Signing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algorithms: Vec<_> = self.signers.iter().map(|s| s.algorithm()).collect();
        f.debug_struct("Signing")
            .field("signers", &algorithms)
            .field("time", &self.time)
            .finish()
    }
}

impl Signing {
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
    out
}

/// SHA-256 of a cell's stored bytes, before sealing (bhive.md §13.2). The writer calls it for
/// every cell when it signs; the reader checks each cell against section 2 before decoding.
pub fn cell_digest(stored: &[u8]) -> Result<[u8; 32]> {
    Ok(sha256(stored))
}

/// Whether a writer can sign with `signing`: every signer's algorithm is built. Called before
/// anything is written, so a create that can't sign fails at once.
pub fn ready(signing: &Signing) -> Result<()> {
    let _ = signing;
    Err(not_built("signing"))
}

/// The manifest of an index (bhive.md §13.1), from the file's header, the index's raw bytes
/// and their parse.
pub fn manifest(header: &[u8; 16], raw: &[u8], index: &Index) -> Result<[u8; 32]> {
    let _ = (header, raw, index);
    Err(not_built("the manifest"))
}

/// The manifest from a writer's parts: the header's version and features (bit 0 is cleared
/// here), its cells, its entries' items as encoded, and its sections with even ids, in order.
pub fn manifest_of(
    version: u16,
    features: u32,
    cells: &[Cell],
    entry_count: u64,
    entries: &[u8],
    even_sections: &[(u64, &[u8])],
) -> Result<[u8; 32]> {
    let _ = (
        version,
        features,
        cells,
        entry_count,
        entries,
        even_sections,
    );
    Err(not_built("the manifest"))
}

/// The 113-byte message for `algorithm` (bhive.md §13.3): the label, the algorithm, the
/// manifest, and the SHA-256 of the signer bytes and of the signed attributes.
pub fn message(
    algorithm: u8,
    manifest: &[u8; 32],
    signer: &[u8],
    signed_attributes: &[u8],
) -> [u8; MESSAGE_LEN] {
    let mut m = [0; MESSAGE_LEN];
    let (l, rest) = m.split_at_mut(label::SIGNATURE.len());
    l.copy_from_slice(label::SIGNATURE);
    rest[0] = algorithm;
    rest[1..33].copy_from_slice(manifest);
    rest[33..65].copy_from_slice(&sha256(signer));
    rest[65..97].copy_from_slice(&sha256(signed_attributes));
    m
}

/// Section 3's body: each signer's signature of the manifest, at `signing.time`.
pub fn section(signing: &Signing, manifest: &[u8; 32]) -> Result<Vec<u8>> {
    let _ = (signing, manifest);
    Err(not_built("signing"))
}

/// What became of one signature when the archive was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// It verifies, and section 2 is whole. Whether to trust the signer is the caller's
    /// question (docs/M14.md §11).
    Valid,
    /// It doesn't verify: the archive changed after it was signed, or the signature is
    /// damaged.
    Invalid,
    /// An algorithm this BeeZip doesn't know.
    UnknownAlgorithm(u8),
    /// It couldn't be checked, and why: section 2 or 3 is malformed, a critical (odd) signed
    /// attribute is unknown, a key is outside the limits or doesn't match the algorithm.
    NotChecked(String),
}

/// One signature, as section 3 holds it, and its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    pub algorithm: u8,
    /// The signer field: a public key, or certificates.
    pub signer: Vec<u8>,
    /// Signed attribute 1, as the signer claims it.
    pub time: Option<i64>,
    pub status: Status,
}

/// The signatures of an archive, checked against its index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub signatures: Vec<SignatureInfo>,
    /// Section 2, when the index has it: one digest per cell, in table order.
    pub digests: Option<Vec<[u8; 32]>>,
}

/// Reads sections 2 and 3 from `index` and checks every signature against the manifest of
/// `header` and `raw`. Never fails the archive: a signature that can't be checked says so in
/// its status. A recovered archive has no index, and is unsigned.
pub fn check(header: &[u8; 16], raw: &[u8], index: &Index) -> Report {
    let _ = (header, raw);
    let has = |id| index.sections.iter().any(|s| s.id == id);
    if !has(super::layout::SECTION_SIGNATURES) && !has(super::layout::SECTION_DIGESTS) {
        return Report::default();
    }
    Report {
        signatures: vec![SignatureInfo {
            algorithm: 0,
            signer: Vec::new(),
            time: None,
            status: Status::NotChecked(not_built("checking signatures").message),
        }],
        digests: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tests/fixtures/bhive-m14/vectors.json, `signed_example`.
    #[test]
    fn the_message_is_the_specifications() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let ex = &v["signed_example"];
        let hex = |k: &str| -> Vec<u8> {
            let s = ex[k].as_str().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let manifest: [u8; 32] = hex("manifest").try_into().unwrap();
        let signer = [hex("ed25519_public"), hex("mldsa_public")].concat();
        let m = message(1, &manifest, &signer, &hex("signed_attributes"));
        assert_eq!(m.to_vec(), hex("message"));
        assert_eq!(
            cell_digest(b"honeycomb\n").unwrap().to_vec(),
            hex("cell_digest")
        );
    }

    #[test]
    fn algorithms_round_trip() {
        for a in Algorithm::ALL {
            assert_eq!(Algorithm::from_id(a.id()), Some(a));
        }
        assert_eq!(Algorithm::from_id(0), None);
        assert_eq!(Algorithm::from_id(6), None);
    }
}
