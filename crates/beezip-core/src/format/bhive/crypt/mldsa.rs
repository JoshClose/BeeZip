//! Your BeeZip signing key: ML-DSA-65 with Ed25519, both of which must verify (bhive.md §13.4,
//! algorithm 1; docs/M14.md decision 24). ML-DSA through `ml-dsa`, Ed25519 through `ring`.

use ml_dsa::{B32, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Signature, VerifyingKey};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use zeroize::Zeroizing;

use super::label;
use crate::{
    Error, ErrorKind, Result,
    format::bhive::sign::{Algorithm, MESSAGE_LEN, Signer},
};

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

fn random(out: &mut [u8]) -> Result<()> {
    SystemRandom::new()
        .fill(out)
        .map_err(|_| Error::new(ErrorKind::Io, "bhive: the system's random generator failed"))
}

impl HybridKey {
    pub fn generate() -> Result<Self> {
        let mut seeds = Zeroizing::new([0; 64]);
        random(&mut seeds[..])?;
        Ok(Self { seeds })
    }

    fn ed25519(&self) -> Result<Ed25519KeyPair> {
        Ed25519KeyPair::from_seed_unchecked(&self.seeds[..32])
            .map_err(|e| Error::new(ErrorKind::Corrupt, format!("bhive: an Ed25519 seed: {e}")))
    }

    fn mldsa_seed(&self) -> Zeroizing<B32> {
        let mut seed = Zeroizing::new(B32::default());
        seed.copy_from_slice(&self.seeds[32..]);
        seed
    }

    pub fn public(&self) -> Result<Box<[u8; PUBLIC_LEN]>> {
        let mut out = Box::new([0; PUBLIC_LEN]);
        out[..32].copy_from_slice(self.ed25519()?.public_key().as_ref());
        let key = ml_dsa::SigningKey::<MlDsa65>::from_seed(&self.mldsa_seed());
        let public: &VerifyingKey<MlDsa65> = key.as_ref();
        out[32..].copy_from_slice(public.encode().as_slice());
        Ok(out)
    }

    /// Both signatures of the 113-byte message; ML-DSA with fresh randomness.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut rnd = Zeroizing::new(B32::default());
        random(rnd.as_mut_slice())?;
        self.sign_with(message, &rnd)
    }

    /// FIPS 204's ML-DSA.Sign (Algorithm 2) with `rnd` as its randomness: all zeros is its
    /// deterministic variant, which the specification's example uses.
    pub(crate) fn sign_with(&self, message: &[u8], rnd: &B32) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(self.ed25519()?.sign(message).as_ref());
        let key = ExpandedSigningKey::<MlDsa65>::from_seed(&self.mldsa_seed());
        // M′ is 0, the context's length, the context, then the message (FIPS 204 §5.2).
        let context = label::MLDSA_CONTEXT;
        let head = [0, context.len() as u8];
        let signature = key.sign_internal(&[&head, context, message], rnd);
        out.extend_from_slice(signature.encode().as_slice());
        debug_assert_eq!(out.len(), SIGNATURE_LEN);
        Ok(out)
    }
}

/// Whether both halves of `signature` verify `message` under `public`. A public key or a
/// signature of the wrong length doesn't.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    if public.len() != PUBLIC_LEN || signature.len() != SIGNATURE_LEN {
        return Ok(false);
    }
    let (ed_public, ml_public) = public.split_at(32);
    let (ed_signature, ml_signature) = signature.split_at(64);
    let ed = UnparsedPublicKey::new(&ED25519, ed_public)
        .verify(message, ed_signature)
        .is_ok();
    let Ok(encoded) = EncodedVerifyingKey::<MlDsa65>::try_from(ml_public) else {
        return Ok(false);
    };
    let ml = match Signature::<MlDsa65>::try_from(ml_signature) {
        Ok(s) => VerifyingKey::<MlDsa65>::decode(&encoded).verify_with_context(
            message,
            label::MLDSA_CONTEXT,
            &s,
        ),
        Err(_) => false,
    };
    Ok(ed && ml)
}

/// Your signing key as a [`Signer`], with its public half worked out once.
pub struct HybridSigner {
    key: HybridKey,
    public: Box<[u8; PUBLIC_LEN]>,
}

impl HybridSigner {
    pub fn new(key: HybridKey) -> Result<Self> {
        let public = key.public()?;
        Ok(Self { key, public })
    }
}

impl std::fmt::Debug for HybridSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridSigner(***)")
    }
}

impl Signer for HybridSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::MlDsa65Ed25519
    }

    fn signer_bytes(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        self.key.sign(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, data)
            .as_ref()
            .to_vec()
    }

    fn key(ed: &[u8], ml: &[u8]) -> HybridKey {
        let mut seeds = Zeroizing::new([0; 64]);
        seeds[..32].copy_from_slice(ed);
        seeds[32..].copy_from_slice(ml);
        HybridKey { seeds }
    }

    /// RFC 8032 §7.1, tests 1 to 3 and SHA(abc): `ring` makes and checks them.
    #[test]
    fn ed25519_is_rfc_8032() {
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
            (
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
        ];
        for (seed, public, message, signature) in cases {
            let pair = Ed25519KeyPair::from_seed_unchecked(&hex(seed)).unwrap();
            assert_eq!(pair.public_key().as_ref(), hex(public), "{seed}");
            assert_eq!(pair.sign(&hex(message)).as_ref(), hex(signature), "{seed}");
            assert!(
                UnparsedPublicKey::new(&ED25519, hex(public))
                    .verify(&hex(message), &hex(signature))
                    .is_ok()
            );
        }
    }

    /// The IETF LAMPS example key that `ml-dsa` ships (its tests/examples/ML-DSA-65-seed.priv
    /// and ML-DSA-65.pub, from github.com/lamps-wg/dilithium-certificates): the seed 00 01 …
    /// 1f gives this public key, by its SHA-256.
    #[test]
    fn mldsa_65_keys_are_the_lamps_examples() {
        let seed: Vec<u8> = (0..32).collect();
        let public = key(&[0; 32], &seed).public().unwrap();
        assert_eq!(public[32..48], hex("48683d91978e31eb3dddb8b0473482d2"));
        assert_eq!(
            sha256(&public[32..]),
            hex("d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9")
        );
    }

    /// The specification's example (vectors.json, `signed_example`): the keys from their
    /// seeds, ML-DSA's deterministic signature byte for byte, Ed25519's, and both checking.
    #[test]
    fn the_specifications_example_signs_and_checks() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let ex = &v["signed_example"];
        let get = |k: &str| hex(ex[k].as_str().unwrap());
        let k = key(&get("ed25519_seed"), &get("mldsa_seed"));
        let public = k.public().unwrap();
        assert_eq!(public[..32], get("ed25519_public")[..]);
        assert_eq!(public[32..], get("mldsa_public")[..]);
        let message = get("message");
        let signature = k.sign_with(&message, &B32::default()).unwrap();
        assert_eq!(signature[..64], get("ed25519_signature")[..]);
        assert_eq!(signature[64..], get("mldsa_signature")[..]);
        assert!(verify(&public[..], &message, &signature).unwrap());

        // Randomized signing gives another signature each time, and each one checks.
        let a = k.sign(&message).unwrap();
        let b = k.sign(&message).unwrap();
        assert_ne!(a[64..], b[64..]);
        assert_eq!(a[..64], b[..64], "Ed25519 is deterministic");
        assert!(verify(&public[..], &message, &a).unwrap());
        assert!(verify(&public[..], &message, &b).unwrap());
    }

    /// ML-DSA.Sign with zero randomness is `ml-dsa`'s own deterministic signing, so M′ is put
    /// together as FIPS 204 says.
    #[test]
    fn randomness_goes_where_fips_204_puts_it() {
        let k = HybridKey::generate().unwrap();
        let message = [7u8; MESSAGE_LEN];
        let ours = k.sign_with(&message, &B32::default()).unwrap();
        let theirs = ExpandedSigningKey::<MlDsa65>::from_seed(&k.mldsa_seed())
            .sign_deterministic(&message, label::MLDSA_CONTEXT)
            .unwrap();
        assert_eq!(ours[64..], theirs.encode()[..]);
    }

    #[test]
    fn both_halves_must_verify() {
        let k = HybridKey::generate().unwrap();
        let other = HybridKey::generate().unwrap();
        let public = k.public().unwrap();
        let theirs = other.public().unwrap();
        let message = [1u8; MESSAGE_LEN];
        let good = k.sign(&message).unwrap();
        assert!(verify(&public[..], &message, &good).unwrap());

        // Each half alone, with the other half from another key.
        let mut mixed = public.to_vec();
        mixed[32..].copy_from_slice(&theirs[32..]);
        assert!(!verify(&mixed, &message, &good).unwrap());
        let mut mixed = public.to_vec();
        mixed[..32].copy_from_slice(&theirs[..32]);
        assert!(!verify(&mixed, &message, &good).unwrap());

        // A changed byte in either signature, or in the message.
        for at in [0, 63, 64, 1000, SIGNATURE_LEN - 1] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            assert!(!verify(&public[..], &message, &bad).unwrap(), "byte {at}");
        }
        let mut changed = message;
        changed[50] ^= 1;
        assert!(!verify(&public[..], &changed, &good).unwrap());

        // Wrong lengths, and another context.
        assert!(!verify(&public[..31], &message, &good).unwrap());
        assert!(!verify(&public[..], &message, &good[..SIGNATURE_LEN - 1]).unwrap());
        let ml = ExpandedSigningKey::<MlDsa65>::from_seed(&k.mldsa_seed())
            .sign_deterministic(&message, b"other")
            .unwrap();
        let mut other_context = good.clone();
        other_context[64..].copy_from_slice(&ml.encode());
        assert!(!verify(&public[..], &message, &other_context).unwrap());
    }

    #[test]
    fn the_signer_signs_with_its_key() {
        let k = HybridKey::generate().unwrap();
        let s = HybridSigner::new(k.clone()).unwrap();
        assert_eq!(s.algorithm(), Algorithm::MlDsa65Ed25519);
        assert_eq!(s.signer_bytes(), k.public().unwrap().to_vec());
        let message = [9u8; MESSAGE_LEN];
        let sig = s.sign(&message).unwrap();
        assert!(verify(&s.signer_bytes(), &message, &sig).unwrap());
        assert_eq!(format!("{k:?} {s:?}"), "HybridKey(***) HybridSigner(***)");
    }
}
