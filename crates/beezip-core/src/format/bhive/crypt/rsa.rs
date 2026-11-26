//! Slot kind 5, an RSA certificate or key (bhive.md §12.5): RSAES-OAEP with SHA-256, MGF1 with
//! SHA-256 and an empty label, 2,048 to 8,192 bits. The pure-Rust half: writing to a public
//! key, and opening with a key file. Keys in CNG and the Keychain are reached by `beezip-keys`,
//! which decrypts [`ciphertext`] itself; an empty label is what TPMs require.

use pkcs8::DecodePrivateKey;
use spki::DecodePublicKey;
use zeroize::Zeroizing;

use super::{MadeSlot, SlotKind, SlotSecret, SlotView, cert};
use crate::{Error, ErrorKind, Result};

/// The smallest modulus, in bytes.
pub const MIN_MODULUS: usize = 256;
pub const MAX_MODULUS: usize = 1024;
/// `S`'s length: 32 random bytes.
pub const SECRET_LEN: usize = 32;

fn oaep() -> rsa::Oaep<rsa::sha2::Sha256> {
    rsa::Oaep::<rsa::sha2::Sha256>::new()
}

/// A slot for the RSA key in `spki` (DER SubjectPublicKeyInfo): a random `S`, OAEP-encrypted,
/// and the slot's tag.
pub fn make(spki: &[u8]) -> Result<MadeSlot> {
    cert::check_rsa(spki).map_err(|e| Error::new(ErrorKind::InvalidArgs, e))?;
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| Error::new(ErrorKind::InvalidArgs, format!("an RSA key: {e}")))?;
    let mut s = Zeroizing::new(vec![0; SECRET_LEN]);
    getrandom::fill(&mut s).map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
    let ct = key
        .encrypt(&mut getrandom::SysRng, oaep(), &s)
        .map_err(|e| Error::new(ErrorKind::InvalidArgs, format!("RSA-OAEP: {e}")))?;
    let len = u16::try_from(ct.len())
        .ok()
        .filter(|n| (MIN_MODULUS..=MAX_MODULUS).contains(&usize::from(*n)))
        .ok_or_else(|| Error::new(ErrorKind::InvalidArgs, "an RSA key of the wrong size"))?;
    let mut public = Vec::with_capacity(6 + ct.len());
    public.extend_from_slice(&cert::tag(SlotKind::Rsa, spki, &ct));
    public.extend_from_slice(&len.to_le_bytes());
    public.extend_from_slice(&ct);
    Ok(MadeSlot {
        public,
        secret: SlotSecret::Shared(s),
        recipient_key: Vec::new(),
    })
}

/// The ciphertext a key's owner decrypts (CNG's `NCryptDecrypt`, or [`secret`]).
pub fn ciphertext<'a>(slot: &SlotView<'a>) -> Option<&'a [u8]> {
    if slot.kind != SlotKind::Rsa || check(slot.public).is_err() {
        return None;
    }
    slot.public.get(6..)
}

/// `S` from the decrypted ciphertext: exactly 32 bytes.
pub fn from_plaintext(plain: Zeroizing<Vec<u8>>) -> Result<SlotSecret> {
    if plain.len() != SECRET_LEN {
        return Err(Error::corrupt("an RSA slot's secret has the wrong length"));
    }
    Ok(SlotSecret::Shared(plain))
}

/// The secret with a private key from a file (PKCS #8 DER, already decrypted).
pub fn secret(slot: &SlotView<'_>, pkcs8: &[u8]) -> Result<SlotSecret> {
    let ct = ciphertext(slot).ok_or_else(|| Error::corrupt("a damaged RSA slot"))?;
    let key = rsa::PrivateKey::from_pkcs8_der(pkcs8)
        .map_err(|e| Error::new(ErrorKind::InvalidArgs, format!("an RSA private key: {e}")))?;
    let plain = key
        .decrypt(oaep(), ct)
        .map_err(|_| Error::new(ErrorKind::KeyRequired, "this RSA key doesn't open the slot"))?;
    from_plaintext(Zeroizing::new(plain))
}

/// A slot's public part: its tag, the ciphertext's length and 256 to 1,024 bytes of
/// ciphertext, exactly. That is all of it ([`super::check_framing`] holds the one copy); the
/// ciphertext itself is for the key to judge.
pub fn check(public: &[u8]) -> Result<()> {
    super::check_framing(SlotKind::Rsa, public)
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
            commitment: slot[framed.len()..framed.len() + 32].try_into().unwrap(),
        }
    }

    fn shared(s: SlotSecret) -> Vec<u8> {
        match s {
            SlotSecret::Shared(s) => s.to_vec(),
            SlotSecret::Extracted(_) => panic!("an RSA secret is shared"),
        }
    }

    #[test]
    fn the_vector_opens_with_its_key() {
        let v = vectors();
        let vec = &v["slots"]["rsa"];
        let slot = hex(&vec["slot"]);
        let key_id: [u8; KEY_ID_LEN] = hex(&v["slots"]["key_id"]).try_into().unwrap();
        let view = view(&slot, &key_id);
        check(view.public).unwrap();
        assert_eq!(ciphertext(&view).unwrap().len(), 256);
        let s = shared(secret(&view, &hex(&vec["pkcs8"])).unwrap());
        assert_eq!(s, hex(&vec["secret"]));
        assert!(cert::tag_matches(&view, &hex(&vec["spki"])));
        assert!(!cert::tag_matches(&view, &hex(&v["slots"]["p256"]["spki"])));
    }

    #[test]
    fn a_made_slot_opens_with_the_key() {
        let v = vectors();
        let spki = hex(&v["slots"]["rsa"]["spki"]);
        let made = make(&spki).unwrap();
        check(&made.public).unwrap();
        assert!(made.recipient_key.is_empty());
        let mut slot = vec![5, 0];
        slot.extend_from_slice(&((made.public.len() + SLOT_TAIL_LEN) as u16).to_le_bytes());
        slot.extend_from_slice(&made.public);
        slot.extend_from_slice(&[0; SLOT_TAIL_LEN]);
        let key_id = [3; KEY_ID_LEN];
        let view = view(&slot, &key_id);
        assert!(cert::tag_matches(&view, &spki));
        let opened = shared(secret(&view, &hex(&v["slots"]["rsa"]["pkcs8"])).unwrap());
        assert_eq!(opened, shared(made.secret));
        // Another slot for the same key is new: a fresh S and ciphertext, so a fresh tag.
        assert_ne!(make(&spki).unwrap().public, made.public);
    }

    #[test]
    fn damaged_and_unfit_slots_are_refused() {
        assert!(check(&[0; 5]).is_err());
        let mut p = vec![0; 4];
        p.extend_from_slice(&255u16.to_le_bytes());
        p.extend_from_slice(&[0; 255]);
        assert!(check(&p).is_err());
        let mut p = vec![0; 4];
        p.extend_from_slice(&256u16.to_le_bytes());
        p.extend_from_slice(&[0; 257]);
        assert!(check(&p).is_err());
        p.pop();
        check(&p).unwrap();
        assert!(make(&hex(&vectors()["slots"]["p256"]["spki"])).is_err());
        assert!(from_plaintext(Zeroizing::new(vec![0; 31])).is_err());
    }
}
