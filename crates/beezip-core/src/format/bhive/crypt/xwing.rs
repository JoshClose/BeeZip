//! Slot kind 4, an X-Wing public key (ML-KEM-768 with X25519), age's `age1pq1…`
//! (bhive.md §12.5, docs/M14.md decision 8). Built here from `ml-kem` and `x25519-dalek` with
//! the combiner of draft-connolly-cfrg-xwing-kem-10, and checked against its Appendix C.
//!
//! A private key is 32 bytes, from which SHAKE256 makes ML-KEM-768's seed and an X25519 key
//! (the draft's `expandDecapsulationKey`). A public key is ML-KEM's 1,184 bytes and X25519's 32.

use ml_kem::{
    B32, Decapsulate, KeyExport, Seed,
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
};
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::{MadeSlot, SlotKind, SlotSecret, SlotView, x25519};
use crate::{Error, ErrorKind, Result};

/// The public part: the X-Wing ciphertext.
pub const PUBLIC_LEN: usize = 1120;
pub const PUBLIC_KEY_LEN: usize = 1216;
const MLKEM_PUBLIC_LEN: usize = 1184;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;
/// The draft's `XWingLabel`, `\.//^\`.
const LABEL: &[u8; 6] = b"\\.//^\\";

/// A private key's halves (the draft's `expandDecapsulationKey`).
struct Expanded {
    mlkem: DecapsulationKey,
    x25519: StaticSecret,
    x25519_public: [u8; 32],
}

fn expand(identity: &[u8; 32]) -> Expanded {
    let mut xof = Shake256::default();
    xof.update(identity);
    let mut wide = Zeroizing::new([0u8; 96]);
    xof.finalize_xof().read(&mut wide[..]);
    let mut seed = Zeroizing::new([0u8; 64]);
    seed.copy_from_slice(&wide[..64]);
    let mlkem = DecapsulationKey::from_seed(Seed::from(*seed));
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&wide[64..]);
    let x25519 = StaticSecret::from(*sk);
    let x25519_public = PublicKey::from(&x25519).to_bytes();
    Expanded {
        mlkem,
        x25519,
        x25519_public,
    }
}

/// `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` (the draft's `Combiner`).
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, LABEL);
    let mut out = Zeroizing::new([0u8; 32]);
    h.finalize_into((&mut *out).into());
    Zeroizing::new(out.to_vec())
}

fn mlkem_public(public: &[u8; PUBLIC_KEY_LEN]) -> Result<EncapsulationKey> {
    let bytes = public[..MLKEM_PUBLIC_LEN]
        .try_into()
        .expect("1,184 bytes are ML-KEM-768's public key");
    EncapsulationKey::new(&bytes).map_err(|_| {
        Error::new(
            ErrorKind::InvalidArgs,
            "this age1pq1 key isn't a post-quantum key: its ML-KEM-768 half is invalid",
        )
    })
}

/// The draft's `EncapsulateDerand`: the ciphertext and the shared secret.
fn encapsulate(
    public: &[u8; PUBLIC_KEY_LEN],
    eseed: &[u8; 64],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let ek = mlkem_public(public)?;
    let pk_x: [u8; 32] = public[MLKEM_PUBLIC_LEN..].try_into().expect("32 bytes");
    let mut ek_x = Zeroizing::new([0u8; 32]);
    ek_x.copy_from_slice(&eseed[32..]);
    let ek_x = StaticSecret::from(*ek_x);
    let ct_x = PublicKey::from(&ek_x).to_bytes();
    let ss_x = ek_x.diffie_hellman(&PublicKey::from(pk_x));
    let m = B32::try_from(&eseed[..32]).expect("32 bytes");
    let (ct_m, ss_m) = ek.encapsulate_deterministic(&m);
    let ss = combiner(&ss_m, ss_x.as_bytes(), &ct_x, &pk_x);
    let mut ct = Vec::with_capacity(PUBLIC_LEN);
    ct.extend_from_slice(&ct_m);
    ct.extend_from_slice(&ct_x);
    Ok((ct, ss))
}

/// The draft's `Decapsulate`.
fn decapsulate(identity: &[u8; 32], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    check(ct)?;
    let x = expand(identity);
    let ct_m = Ciphertext::try_from(&ct[..MLKEM_CIPHERTEXT_LEN]).expect("1,088 bytes");
    let ct_x: [u8; 32] = ct[MLKEM_CIPHERTEXT_LEN..].try_into().expect("32 bytes");
    let ss_m = x.mlkem.decapsulate(&ct_m);
    let ss_x = x.x25519.diffie_hellman(&PublicKey::from(ct_x));
    Ok(combiner(&ss_m, ss_x.as_bytes(), &ct_x, &x.x25519_public))
}

pub fn make(recipient: &[u8; PUBLIC_KEY_LEN]) -> Result<MadeSlot> {
    let eseed = Zeroizing::new(super::prim::random::<64>()?);
    make_with(recipient, &eseed)
}

/// [`make`] with the encapsulation's randomness given, for the vectors.
pub(crate) fn make_with(recipient: &[u8; PUBLIC_KEY_LEN], eseed: &[u8; 64]) -> Result<MadeSlot> {
    let (public, s) = encapsulate(recipient, eseed)?;
    Ok(MadeSlot {
        public,
        secret: SlotSecret::Shared(s),
        recipient_key: Vec::new(),
    })
}

/// The secret with `identity`, a 32-byte X-Wing private key (its seed). ML-KEM rejects a
/// ciphertext that isn't its key's implicitly, so a slot that isn't this identity's gives a
/// secret whose commitment doesn't match ([`open`]).
pub fn secret(slot: &SlotView<'_>, identity: &[u8; 32]) -> Result<SlotSecret> {
    if slot.kind != SlotKind::XWing {
        return Err(Error::new(
            ErrorKind::InvalidArgs,
            "an X-Wing key opens only X-Wing slots",
        ));
    }
    decapsulate(identity, slot.public).map(SlotSecret::Shared)
}

/// The secret, when `identity` is this slot's: its commitment matches. `None` otherwise.
pub fn open(slot: &SlotView<'_>, identity: &[u8; 32]) -> Result<Option<SlotSecret>> {
    let secret = secret(slot, identity)?;
    Ok(x25519::commits(slot, &secret).then_some(secret))
}

/// The public key of a 32-byte X-Wing private key.
pub fn public_of(identity: &[u8; 32]) -> Result<Box<[u8; PUBLIC_KEY_LEN]>> {
    let x = expand(identity);
    let mut out = Box::new([0u8; PUBLIC_KEY_LEN]);
    out[..MLKEM_PUBLIC_LEN].copy_from_slice(&x.mlkem.encapsulation_key().to_bytes());
    out[MLKEM_PUBLIC_LEN..].copy_from_slice(&x.x25519_public);
    Ok(out)
}

/// A new X-Wing private key.
pub fn generate() -> Result<zeroize::Zeroizing<[u8; 32]>> {
    x25519::generate()
}

/// A public key's ML-KEM half is a valid ML-KEM-768 key (FIPS 203's modulus check).
pub fn check_public_key(public: &[u8; PUBLIC_KEY_LEN]) -> Result<()> {
    mlkem_public(public).map(drop)
}

pub fn check(public: &[u8]) -> Result<()> {
    if public.len() != PUBLIC_LEN {
        return Err(Error::corrupt(format!(
            "bhive: an X-Wing slot's public part is {} bytes, not {PUBLIC_LEN}",
            public.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::SlotKind;
    use super::super::bech32::tests::hex;
    use super::super::x25519::tests::{slot_vector, view, wrapped};
    use super::*;

    /// draft-connolly-cfrg-xwing-kem-10, Appendix C (tests/fixtures/keys/xwing-draft-10.json).
    #[test]
    fn the_drafts_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/keys/xwing-draft-10.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let vectors = v["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 3);
        for t in vectors {
            let sk: [u8; 32] = hex(&t["sk"]).try_into().unwrap();
            assert_eq!(hex(&t["seed"]), sk, "the seed is the private key");
            let pk = public_of(&sk).unwrap();
            assert_eq!(pk.to_vec(), hex(&t["pk"]));
            let eseed: [u8; 64] = hex(&t["eseed"]).try_into().unwrap();
            let (ct, ss) = encapsulate(&pk, &eseed).unwrap();
            assert_eq!(ct, hex(&t["ct"]));
            assert_eq!(ss.to_vec(), hex(&t["ss"]));
            assert_eq!(decapsulate(&sk, &ct).unwrap().to_vec(), hex(&t["ss"]));
        }
    }

    #[test]
    fn the_specifications_xwing_slot() {
        let (vec, key_id, slot) = slot_vector("xwing");
        let identity: [u8; 32] = hex(&vec["recipient_seed"]).try_into().unwrap();
        let recipient: [u8; PUBLIC_KEY_LEN] = hex(&vec["recipient_public"]).try_into().unwrap();
        let eseed: [u8; 64] = hex(&vec["encapsulation_seed"]).try_into().unwrap();
        assert_eq!(*public_of(&identity).unwrap(), recipient);

        let view = view(&key_id, &slot);
        let made = make_with(&recipient, &eseed).unwrap();
        assert_eq!(made.public, view.public);
        assert!(made.recipient_key.is_empty());
        let SlotSecret::Shared(s) = &made.secret else {
            panic!("a shared secret")
        };
        assert_eq!(s.to_vec(), hex(&vec["secret"]));
        assert_eq!(view.commitment.to_vec(), hex(&vec["commitment"]));
        assert!(x25519::commits(&view, &made.secret));

        let SlotSecret::Shared(read) = secret(&view, &identity).unwrap() else {
            panic!("a shared secret")
        };
        assert_eq!(read.to_vec(), hex(&vec["secret"]));
        assert!(open(&view, &identity).unwrap().is_some());
        assert!(open(&view, &[3; 32]).unwrap().is_none());
    }

    #[test]
    fn a_fresh_slot_opens_with_its_identity_only() {
        let identity = generate().unwrap();
        let public = public_of(&identity).unwrap();
        let made = make(&public).unwrap();
        assert_ne!(made.public, make(&public).unwrap().public);
        let (key_id, slot) = wrapped(SlotKind::XWing, &made);
        let v = view(&key_id, &slot);
        assert!(open(&v, &identity).unwrap().is_some());
        assert!(open(&v, &generate().unwrap()).unwrap().is_none());
    }

    #[test]
    fn bad_inputs_are_refused() {
        assert!(check(&[0; PUBLIC_LEN - 1]).is_err());
        assert!(check(&[0; PUBLIC_LEN]).is_ok());
        assert!(check_public_key(&[0xff; PUBLIC_KEY_LEN]).is_err());
        assert!(make(&Box::new([0xff; PUBLIC_KEY_LEN])).is_err());
        let public = public_of(&[1; 32]).unwrap();
        assert!(check_public_key(&public).is_ok());
    }
}
