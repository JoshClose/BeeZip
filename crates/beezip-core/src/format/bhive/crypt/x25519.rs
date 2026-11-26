//! Slot kind 3, an X25519 public key, age's `age1…` (bhive.md §12.5).
//!
//! Also what kinds 3 and 4 share: the slot's PRK (bhive.md §12.4 step 2), and checking a
//! commitment, so a key source can tell which of its keys an anonymous slot is for without
//! the reader trying each.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::{MadeSlot, SlotKind, SlotSecret, SlotView, label};
use crate::{Error, ErrorKind, Result};

/// The public part: the ephemeral share.
pub const PUBLIC_LEN: usize = 32;

/// A slot for `recipient`, with a fresh ephemeral secret.
pub fn make(recipient: &[u8; 32]) -> Result<MadeSlot> {
    let mut e = Zeroizing::new([0u8; 32]);
    random(&mut e[..])?;
    make_with(recipient, &e)
}

/// [`make`] with the ephemeral secret given, for the specification's vectors.
pub(crate) fn make_with(recipient: &[u8; 32], ephemeral: &[u8; 32]) -> Result<MadeSlot> {
    let e = StaticSecret::from(*ephemeral);
    let share = PublicKey::from(&e);
    let s = e.diffie_hellman(&PublicKey::from(*recipient));
    if !s.was_contributory() {
        return Err(Error::new(
            ErrorKind::InvalidArgs,
            "this age1 key isn't a usable X25519 key: it gives an all-zero secret",
        ));
    }
    Ok(MadeSlot {
        public: share.as_bytes().to_vec(),
        secret: SlotSecret::Shared(Zeroizing::new(s.as_bytes().to_vec())),
        recipient_key: recipient.to_vec(),
    })
}

/// The secret with `identity`, an X25519 private key, as its PRK: the context holds the
/// identity's public key, which only the key's holder knows to be this slot's. Whether the
/// identity is the slot's shows in the commitment ([`open`]).
pub fn secret(slot: &SlotView<'_>, identity: &[u8; 32]) -> Result<SlotSecret> {
    if slot.kind != SlotKind::X25519 {
        return Err(Error::new(
            ErrorKind::InvalidArgs,
            "an X25519 key opens only X25519 slots",
        ));
    }
    check(slot.public)?;
    let share: [u8; 32] = slot.public.try_into().expect("checked");
    let me = StaticSecret::from(*identity);
    let s = me.diffie_hellman(&PublicKey::from(share));
    if !s.was_contributory() {
        return Err(Error::corrupt(
            "bhive: an X25519 slot's share gives an all-zero secret",
        ));
    }
    let context = slot.context(PublicKey::from(&me).as_bytes());
    Ok(SlotSecret::Extracted(prk(&context, s.as_bytes())))
}

/// The secret, when `identity` is this slot's: its commitment matches. `None` otherwise.
pub fn open(slot: &SlotView<'_>, identity: &[u8; 32]) -> Result<Option<SlotSecret>> {
    let secret = secret(slot, identity)?;
    Ok(commits(slot, &secret).then_some(secret))
}

/// `identity`'s public key, which the context adds (bhive.md §12.4).
pub fn public_of(identity: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*identity)).to_bytes()
}

/// A new X25519 private key.
pub fn generate() -> Result<Zeroizing<[u8; 32]>> {
    let mut k = Zeroizing::new([0u8; 32]);
    random(&mut k[..])?;
    Ok(k)
}

pub fn check(public: &[u8]) -> Result<()> {
    if public.len() != PUBLIC_LEN {
        return Err(Error::corrupt(format!(
            "bhive: an X25519 slot's public part is {} bytes, not {PUBLIC_LEN}",
            public.len()
        )));
    }
    Ok(())
}

/// `PRK = HMAC-SHA256(key = context, message = S)` (bhive.md §12.4 step 2).
pub(crate) fn prk(context: &[u8; 32], s: &[u8]) -> Zeroizing<[u8; 32]> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, context);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(ring::hmac::sign(&key, s).as_ref());
    out
}

/// Whether `secret` gives `slot`'s commitment, compared in constant time: the second half of
/// `HKDF-Expand(PRK, "bhive1 slot", 64)` (bhive.md §12.4 step 3). A shared secret's PRK is
/// taken over the context with no recipient key, which is right for every kind but 3, 6 and 7;
/// those come as a PRK.
pub fn commits(slot: &SlotView<'_>, secret: &SlotSecret) -> bool {
    let prk = match secret {
        SlotSecret::Extracted(prk) => prk.clone(),
        SlotSecret::Shared(s) => prk(&slot.context(&[]), s),
    };
    let (key, msg) = expand_second(&prk);
    ring::hmac::verify(&key, &msg, slot.commitment).is_ok()
}

/// The commitment a writer puts in a slot it frames as `slot.framed`, for `made`
/// (bhive.md §12.4 step 3). `slot.commitment` isn't read.
pub fn commitment(slot: &SlotView<'_>, made: &MadeSlot) -> [u8; 32] {
    let prk = match &made.secret {
        SlotSecret::Extracted(prk) => prk.clone(),
        SlotSecret::Shared(s) => prk(&slot.context(&made.recipient_key), s),
    };
    let (key, msg) = expand_second(&prk);
    let mut out = [0; 32];
    out.copy_from_slice(ring::hmac::sign(&key, &msg).as_ref());
    out
}

/// HKDF-Expand's second block for 64 bytes: its key, and the message `T(1) ‖ info ‖ 02`.
fn expand_second(prk: &[u8; 32]) -> (ring::hmac::Key, Zeroizing<Vec<u8>>) {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, prk);
    let mut first = ring::hmac::Context::with_key(&key);
    first.update(label::SLOT);
    first.update(&[1]);
    let wrap = first.sign();
    let mut msg = Zeroizing::new(Vec::with_capacity(32 + label::SLOT.len() + 1));
    msg.extend_from_slice(wrap.as_ref());
    msg.extend_from_slice(label::SLOT);
    msg.push(2);
    (key, msg)
}

/// Fills `out` from the system's random generator.
pub(crate) fn random(out: &mut [u8]) -> Result<()> {
    getrandom::fill(out).map_err(|e| {
        Error::new(
            ErrorKind::Io,
            format!("the system's random generator failed: {e}"),
        )
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::bech32::tests::{hex, vectors};
    use super::super::{KEY_ID_LEN, SLOT_TAIL_LEN};
    use super::*;

    /// The slot vector's parts: its key id, its bytes.
    pub(crate) fn slot_vector(name: &str) -> (serde_json::Value, [u8; KEY_ID_LEN], Vec<u8>) {
        let v = vectors();
        let key_id = hex(&v["slots"]["key_id"]).try_into().unwrap();
        let vec = v["slots"][name].clone();
        let slot = hex(&vec["slot"]);
        (vec, key_id, slot)
    }

    pub(crate) fn view<'a>(key_id: &'a [u8; KEY_ID_LEN], slot: &'a [u8]) -> SlotView<'a> {
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

    #[test]
    fn the_specifications_x25519_slot() {
        let (vec, key_id, slot) = slot_vector("x25519");
        let recipient: [u8; 32] = hex(&vec["recipient_public"]).try_into().unwrap();
        let identity: [u8; 32] = hex(&vec["recipient_secret"]).try_into().unwrap();
        let ephemeral: [u8; 32] = hex(&vec["ephemeral_secret"]).try_into().unwrap();
        assert_eq!(public_of(&identity), recipient);

        // Writing: the share and S.
        let made = make_with(&recipient, &ephemeral).unwrap();
        let view = view(&key_id, &slot);
        assert_eq!(made.public, view.public);
        assert_eq!(made.recipient_key, recipient);
        let SlotSecret::Shared(s) = &made.secret else {
            panic!("a shared secret")
        };
        assert_eq!(s.to_vec(), hex(&vec["secret"]));
        assert_eq!(
            view.context(&made.recipient_key).to_vec(),
            hex(&vec["context"])
        );

        // Reading: the PRK, and the commitment tells this identity's slot.
        let SlotSecret::Extracted(prk) = secret(&view, &identity).unwrap() else {
            panic!("a PRK")
        };
        assert_eq!(prk.to_vec(), hex(&vec["prk"]));
        assert_eq!(view.commitment.to_vec(), hex(&vec["commitment"]));
        assert_eq!(commitment(&view, &made).to_vec(), hex(&vec["commitment"]));
        assert!(open(&view, &identity).unwrap().is_some());
        assert!(open(&view, &[7; 32]).unwrap().is_none());
    }

    #[test]
    fn a_fresh_slot_opens_with_its_identity_only() {
        let identity = generate().unwrap();
        let made = make(&public_of(&identity)).unwrap();
        let again = make(&public_of(&identity)).unwrap();
        assert_ne!(made.public, again.public, "a fresh ephemeral key each time");
        // A slot as a writer would frame it, with the commitment its secret gives.
        let key_id = [9; KEY_ID_LEN];
        let mut slot = vec![3, 0, 112, 0];
        slot.extend(&made.public);
        let probe = SlotView {
            index: 0,
            kind: SlotKind::X25519,
            key_id: &key_id,
            framed: &slot,
            public: &slot[4..],
            commitment: &[0; 32],
        };
        let commitment = commitment_for(&probe, &made);
        slot.extend(commitment);
        slot.extend([0; 48]);
        let v = view(&key_id, &slot);
        assert!(open(&v, &identity).unwrap().is_some());
        assert!(open(&v, &generate().unwrap()).unwrap().is_none());
    }

    /// The commitment a writer computes for `made` (bhive.md §12.4 step 3).
    pub(crate) fn commitment_for(slot: &SlotView<'_>, made: &MadeSlot) -> [u8; 32] {
        commitment(slot, made)
    }

    #[test]
    fn low_order_points_are_refused() {
        // The all-zero point gives an all-zero secret, for writer and reader alike.
        assert!(make(&[0; 32]).is_err());
        let key_id = [0; KEY_ID_LEN];
        let mut slot = vec![3, 0, 112, 0];
        slot.extend([0; 32 + 80]);
        let v = view(&key_id, &slot);
        assert!(secret(&v, &[1; 32]).is_err());
        assert!(check(&[0; 31]).is_err());
        assert!(check(&[0; 32]).is_ok());
    }
}
