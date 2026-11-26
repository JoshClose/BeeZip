//! Your BeeZip signing key: ML-DSA-65 with Ed25519, both of which must verify (bhive.md §13.4,
//! algorithm 1; docs/M14.md decision 24). ML-DSA through `ml-dsa`, Ed25519 through `ring`.
//! PR H builds it.

use zeroize::Zeroizing;

use super::not_built;
use crate::Result;

/// The signer bytes: the Ed25519 public key, then the ML-DSA-65 one.
pub const PUBLIC_LEN: usize = 32 + 1952;
/// Ed25519's 64 bytes, then ML-DSA-65's 3,309.
pub const SIGNATURE_LEN: usize = 64 + 3309;

/// A signing key: the Ed25519 seed, then the ML-DSA-65 seed.
#[derive(Clone)]
pub struct HybridKey {
    pub seeds: Zeroizing<[u8; 64]>,
}

impl std::fmt::Debug for HybridKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridKey(***)")
    }
}

impl HybridKey {
    pub fn generate() -> Result<Self> {
        Err(not_built("signing keys"))
    }

    pub fn public(&self) -> Result<Box<[u8; PUBLIC_LEN]>> {
        Err(not_built("signing keys"))
    }

    /// Both signatures of the 113-byte message; ML-DSA with fresh randomness.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let _ = message;
        Err(not_built("signing"))
    }
}

/// Whether both halves of `signature` verify `message` under `public`.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let _ = (public, message, signature);
    Err(not_built("checking signatures"))
}
