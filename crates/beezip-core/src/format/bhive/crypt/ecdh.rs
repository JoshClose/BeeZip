//! Slot kinds 6 and 7, an EC certificate or key on P-256 or P-384 (bhive.md §12.5): ECDH with
//! a fresh ephemeral key, and `S` the shared point's x-coordinate, big-endian. A reader gives
//! the envelope `PRK = HMAC(context, S)` ([`SlotSecret::Extracted`]), since the context holds
//! the recipient's public key: CNG computes the same inside the key's provider with
//! `BCRYPT_KDF_HMAC` and the context as `KDF_HMAC_KEY`, so a TPM's or smart card's secret
//! never leaves it. The pure-Rust half.

use p256::elliptic_curve::sec1::ToSec1Point;
use pkcs8::DecodePrivateKey;
use spki::DecodePublicKey;
use zeroize::Zeroizing;

use super::{Curve, MadeSlot, SlotKind, SlotSecret, SlotView, cert};
use crate::{Error, ErrorKind, Result};

impl Curve {
    /// An uncompressed point's length: `04 ‖ x ‖ y`.
    pub const fn point_len(self) -> usize {
        match self {
            Self::P256 => 65,
            Self::P384 => 97,
        }
    }

    /// The slot kind of this curve.
    pub const fn slot_kind(self) -> SlotKind {
        match self {
            Self::P256 => SlotKind::EcP256,
            Self::P384 => SlotKind::EcP384,
        }
    }

    pub const fn from_slot_kind(kind: SlotKind) -> Option<Self> {
        match kind {
            SlotKind::EcP256 => Some(Self::P256),
            SlotKind::EcP384 => Some(Self::P384),
            _ => None,
        }
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidArgs, message)
}

/// The curve's operations, the same for both.
macro_rules! curve {
    ($m:ident, $c:ident) => {
        mod $m {
            use super::*;

            /// The uncompressed point of a SubjectPublicKeyInfo.
            pub fn point_of_spki(spki: &[u8]) -> Result<Vec<u8>> {
                let key = ::$c::PublicKey::from_public_key_der(spki)
                    .map_err(|e| invalid(format!("an EC public key doesn't parse: {e}")))?;
                Ok(key.to_sec1_point(false).as_bytes().to_vec())
            }

            /// A fresh key pair's public point, and its shared secret with `point`.
            pub fn ephemeral(point: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
                let peer = ::$c::PublicKey::from_sec1_bytes(point)
                    .map_err(|_| invalid("an EC public key that isn't on its curve"))?;
                let e = <::$c::SecretKey as rsa::Generate>::generate();
                let share = e.public_key().to_sec1_point(false).as_bytes().to_vec();
                let z = e.diffie_hellman(&peer);
                Ok((share, Zeroizing::new(z.raw_secret_bytes().to_vec())))
            }

            /// The shared secret of a private key (PKCS #8) with `point`, and the key's own
            /// uncompressed point.
            pub fn agree(pkcs8: &[u8], point: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
                let key = ::$c::SecretKey::from_pkcs8_der(pkcs8)
                    .map_err(|e| invalid(format!("an EC private key: {e}")))?;
                let peer = ::$c::PublicKey::from_sec1_bytes(point)
                    .map_err(|_| Error::corrupt("an EC slot's point isn't on its curve"))?;
                let z = key.diffie_hellman(&peer);
                let own = key.public_key().to_sec1_point(false).as_bytes().to_vec();
                Ok((own, Zeroizing::new(z.raw_secret_bytes().to_vec())))
            }

            pub fn on_curve(point: &[u8]) -> bool {
                ::$c::PublicKey::from_sec1_bytes(point).is_ok()
            }
        }
    };
}

curve!(ops256, p256);
curve!(ops384, p384);

/// The uncompressed public point of an EC SubjectPublicKeyInfo on `curve`: what the context
/// adds for kinds 6 and 7 (bhive.md §12.4).
pub fn point_of_spki(curve: Curve, spki: &[u8]) -> Result<Vec<u8>> {
    match curve {
        Curve::P256 => ops256::point_of_spki(spki),
        Curve::P384 => ops384::point_of_spki(spki),
    }
}

/// A slot for the EC key in `spki`.
pub fn make(curve: Curve, spki: &[u8]) -> Result<MadeSlot> {
    if cert::spki_algorithm(spki)? != cert::KeyAlgorithm::Ec(curve) {
        return Err(invalid(format!("the key isn't an EC key on {curve:?}")));
    }
    let recipient = point_of_spki(curve, spki)?;
    let (share, z) = match curve {
        Curve::P256 => ops256::ephemeral(&recipient)?,
        Curve::P384 => ops384::ephemeral(&recipient)?,
    };
    let kind = curve.slot_kind();
    let mut public = Vec::with_capacity(4 + share.len());
    public.extend_from_slice(&cert::tag(kind, spki, &share));
    public.extend_from_slice(&share);
    Ok(MadeSlot {
        public,
        secret: SlotSecret::Shared(z),
        recipient_key: recipient,
    })
}

/// The slot's ephemeral public key, which a key's owner agrees with (CNG, or [`secret`]).
pub fn ephemeral<'a>(slot: &SlotView<'a>) -> Option<&'a [u8]> {
    let curve = Curve::from_slot_kind(slot.kind)?;
    check(curve, slot.public).ok()?;
    slot.public.get(4..)
}

/// `PRK = HMAC-SHA256(context, Z)` for a slot whose recipient key is `recipient` (an
/// uncompressed point) and whose shared secret is `z` (bhive.md §12.4 step 2).
pub fn extract(slot: &SlotView<'_>, recipient: &[u8], z: &[u8]) -> SlotSecret {
    let context = slot.context(recipient);
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &context);
    let mut prk = Zeroizing::new([0; 32]);
    prk.copy_from_slice(ring::hmac::sign(&key, z).as_ref());
    SlotSecret::Extracted(prk)
}

/// The secret with a private key from a file (PKCS #8 DER, already decrypted): `PRK`, with the
/// key's own public point in the context.
pub fn secret(slot: &SlotView<'_>, curve: Curve, pkcs8: &[u8]) -> Result<SlotSecret> {
    if Curve::from_slot_kind(slot.kind) != Some(curve) {
        return Err(invalid(format!("not a slot for an EC key on {curve:?}")));
    }
    let point = ephemeral(slot).ok_or_else(|| Error::corrupt("a damaged EC slot"))?;
    let (own, z) = match curve {
        Curve::P256 => ops256::agree(pkcs8, point)?,
        Curve::P384 => ops384::agree(pkcs8, point)?,
    };
    Ok(extract(slot, &own, &z))
}

pub fn check(curve: Curve, public: &[u8]) -> Result<()> {
    if public.len() != 4 + curve.point_len() {
        return Err(Error::corrupt(format!(
            "an EC slot on {curve:?} with a public part of {} bytes",
            public.len()
        )));
    }
    let point = &public[4..];
    let on_curve = point[0] == 4
        && match curve {
            Curve::P256 => ops256::on_curve(point),
            Curve::P384 => ops384::on_curve(point),
        };
    if !on_curve {
        return Err(Error::corrupt(
            "an EC slot's point isn't an uncompressed point on its curve",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{KEY_ID_LEN, SLOT_TAIL_LEN, cert::tests::*};
    use super::*;

    fn view<'a>(slot: &'a [u8], key_id: &'a [u8; KEY_ID_LEN]) -> SlotView<'a> {
        let framed = &slot[..slot.len() - SLOT_TAIL_LEN];
        SlotView {
            index: 0,
            kind: SlotKind::from_id(slot[0]).unwrap(),
            key_id,
            framed,
            public: &framed[4..],
        }
    }

    fn extracted(s: SlotSecret) -> Vec<u8> {
        match s {
            SlotSecret::Extracted(p) => p.to_vec(),
            SlotSecret::Shared(_) => panic!("an EC reader gives PRK"),
        }
    }

    #[test]
    fn the_vectors_open_with_their_keys() {
        let v = vectors();
        let key_id: [u8; KEY_ID_LEN] = hex(&v["slots"]["key_id"]).try_into().unwrap();
        for (name, curve) in [("p256", Curve::P256), ("p384", Curve::P384)] {
            let vec = &v["slots"][name];
            let slot = hex(&vec["slot"]);
            let view = view(&slot, &key_id);
            check(curve, view.public).unwrap();
            let spki = hex(&vec["spki"]);
            assert_eq!(
                point_of_spki(curve, &spki).unwrap(),
                hex(&vec["recipient_public"])
            );
            assert!(cert::tag_matches(&view, &spki), "{name}");
            let prk = extracted(secret(&view, curve, &hex(&vec["pkcs8"])).unwrap());
            assert_eq!(prk, hex(&vec["prk"]), "{name}");
            let own = hex(&vec["recipient_public"]);
            assert_eq!(
                extracted(extract(&view, &own, &hex(&vec["secret"]))),
                hex(&vec["prk"])
            );
        }
    }

    #[test]
    fn a_made_slot_opens_with_the_key() {
        let v = vectors();
        for (name, curve) in [("p256", Curve::P256), ("p384", Curve::P384)] {
            let spki = hex(&v["slots"][name]["spki"]);
            let made = make(curve, &spki).unwrap();
            check(curve, &made.public).unwrap();
            assert_eq!(
                made.recipient_key,
                hex(&v["slots"][name]["recipient_public"])
            );
            let mut slot = vec![curve.slot_kind().id(), 0];
            slot.extend_from_slice(&((made.public.len() + SLOT_TAIL_LEN) as u16).to_le_bytes());
            slot.extend_from_slice(&made.public);
            slot.extend_from_slice(&[0; SLOT_TAIL_LEN]);
            let key_id = [9; KEY_ID_LEN];
            let view = view(&slot, &key_id);
            let SlotSecret::Shared(z) = made.secret else {
                panic!("a writer has S");
            };
            let want = extracted(extract(&view, &made.recipient_key, &z));
            let got = extracted(secret(&view, curve, &hex(&v["slots"][name]["pkcs8"])).unwrap());
            assert_eq!(got, want, "{name}");
            assert!(make(curve, &hex(&v["slots"]["rsa"]["spki"])).is_err());
        }
        let p384 = hex(&v["slots"]["p384"]["spki"]);
        assert!(make(Curve::P256, &p384).is_err());
    }

    #[test]
    fn points_off_the_curve_are_refused() {
        let v = vectors();
        let slot = hex(&v["slots"]["p256"]["slot"]);
        let public = &slot[4..slot.len() - SLOT_TAIL_LEN];
        check(Curve::P256, public).unwrap();
        assert!(check(Curve::P384, public).is_err());
        let mut bad = public.to_vec();
        bad[40] ^= 1;
        assert!(check(Curve::P256, &bad).is_err());
        let mut compressed = public.to_vec();
        compressed[4] = 2;
        assert!(check(Curve::P256, &compressed).is_err());
        assert!(check(Curve::P256, &public[..60]).is_err());
    }
}
