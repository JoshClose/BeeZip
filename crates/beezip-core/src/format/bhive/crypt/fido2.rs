//! Slot kind 8, a FIDO2 authenticator's hmac-secret: a security key, or Windows Hello
//! (bhive.md §12.5). The slot's bytes are here; `beezip-keys` reaches webauthn.dll, which asks
//! the authenticator for `S`.
//!
//! The public part is the flags (`u8`), a reserved byte, the credential id's length (`u16`) and
//! the id, the relying party id's length (`u8`) and the id, and the salt (32), filling the part
//! exactly. Flag bit 0 says the salt is a WebAuthn PRF input, which the authenticator gets as
//! `SHA-256("WebAuthn PRF" ‖ 00 ‖ salt)`; bit 1 says user verification is required, and BeeZip
//! always sets it. For a security key BeeZip leaves bit 0 clear: the salt goes to the key as it
//! is, as libfido2 and other tools that talk to keys do. For Windows Hello it sets bit 0, since
//! PRF is how Windows offers hmac-secret there (and how browsers do). A reader honours either.

use zeroize::Zeroizing;

use super::{MadeSlot, SlotKind, SlotSecret, SlotView};
use crate::{Error, Result};

/// The salt is a WebAuthn PRF input (flag bit 0).
pub const FLAG_PRF: u8 = 0b01;
/// User verification is required (flag bit 1). BeeZip always sets it.
pub const FLAG_UV: u8 = 0b10;
const FLAGS_KNOWN: u8 = FLAG_PRF | FLAG_UV;

/// A credential id is 1 to 1,023 bytes, a relying party id 1 to 253 (bhive.md §12.5).
pub const MAX_CREDENTIAL_ID: usize = 1023;
pub const MAX_RP_ID: usize = 253;
/// The salt's length, and the hmac-secret output's.
pub const SALT_LEN: usize = 32;
/// The public part's fixed fields: flags, reserved, the two lengths, the salt.
const FIXED_LEN: usize = 1 + 1 + 2 + 1 + SALT_LEN;
/// The longest public part: 1,313 bytes.
pub const MAX_PUBLIC_LEN: usize = FIXED_LEN + MAX_CREDENTIAL_ID + MAX_RP_ID;

/// The relying party BeeZip registers its credentials for.
pub const RP_ID: &str = "beezip";

/// What a kind-8 slot says, for the authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Slot<'a> {
    pub credential_id: &'a [u8],
    pub rp_id: &'a str,
    pub salt: &'a [u8; 32],
    /// The salt is a WebAuthn PRF input (flag bit 0).
    pub prf: bool,
    /// User verification is required (flag bit 1).
    pub uv: bool,
}

impl Fido2Slot<'_> {
    /// The salt the authenticator's hmac-secret is computed over: the slot's own, or with flag
    /// bit 0 its PRF hash. A program that talks to the authenticator itself (CTAP) sends this;
    /// webauthn.dll is given the slot's salt and computes it.
    pub fn authenticator_salt(&self) -> [u8; 32] {
        if self.prf {
            prf_salt(self.salt)
        } else {
            *self.salt
        }
    }
}

/// The slot's fields, borrowed from its public part. Its lengths are checked as [`check`] checks
/// them, and then what using it needs: no flag bit this BeeZip doesn't know, and a relying party
/// id in UTF-8. A slot refused here is only unusable: the archive still opens another way.
pub fn parse<'a>(slot: &SlotView<'a>) -> Result<Fido2Slot<'a>> {
    if slot.kind != SlotKind::Fido2 {
        return Err(Error::invalid_args(format!(
            "bhive: slot {} isn't a security-key slot",
            slot.index
        )));
    }
    read(slot.public)
}

/// The public part and `S` of a new slot, for a credential that has already given the
/// hmac-secret of `salt`. User verification is always required (flag bit 1).
pub fn make(
    credential_id: &[u8],
    rp_id: &str,
    salt: &[u8; 32],
    prf: bool,
    secret: &Zeroizing<[u8; 32]>,
) -> Result<MadeSlot> {
    if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID {
        return Err(Error::invalid_args(format!(
            "bhive: a credential id of {} bytes; 1 to {MAX_CREDENTIAL_ID} fit a slot",
            credential_id.len()
        )));
    }
    if rp_id.is_empty() || rp_id.len() > MAX_RP_ID {
        return Err(Error::invalid_args(format!(
            "bhive: a relying party id of {} bytes; 1 to {MAX_RP_ID} fit a slot",
            rp_id.len()
        )));
    }
    let mut public = Vec::with_capacity(FIXED_LEN + credential_id.len() + rp_id.len());
    public.push(FLAG_UV | if prf { FLAG_PRF } else { 0 });
    public.push(0);
    // Both lengths fit: checked above.
    public.extend_from_slice(&(credential_id.len() as u16).to_le_bytes());
    public.extend_from_slice(credential_id);
    public.push(rp_id.len() as u8);
    public.extend_from_slice(rp_id.as_bytes());
    public.extend_from_slice(salt);
    debug_assert!(read(&public).is_ok());
    Ok(MadeSlot {
        public,
        secret: SlotSecret::Shared(Zeroizing::new(secret.to_vec())),
        recipient_key: Vec::new(),
    })
}

/// Checks a kind-8 public part as the key block is read (bhive.md §12.10): its fixed fields and
/// the lengths inside it fill it exactly, and the lengths are in range. Only these refuse the
/// whole archive. A reserved flag bit or a relying party id that isn't UTF-8 makes just this
/// slot unusable, which [`parse`] says, so the archive still opens another way.
pub fn check(public: &[u8]) -> Result<()> {
    fields(public).map(|_| ())
}

/// A public part's fields, their lengths checked.
struct Fields<'a> {
    flags: u8,
    credential_id: &'a [u8],
    rp_id: &'a [u8],
    salt: &'a [u8; SALT_LEN],
}

fn corrupt(what: &str) -> Error {
    Error::corrupt(format!("bhive: a security-key slot's {what}"))
}

fn fields(public: &[u8]) -> Result<Fields<'_>> {
    if public.len() < FIXED_LEN + 2 {
        return Err(corrupt("public part is too short"));
    }
    if public.len() > MAX_PUBLIC_LEN {
        return Err(corrupt("public part is too long"));
    }
    let id_len = usize::from(u16::from_le_bytes([public[2], public[3]]));
    if id_len == 0 || id_len > MAX_CREDENTIAL_ID {
        return Err(corrupt("credential id length is out of range"));
    }
    let (credential_id, rest) = public[4..]
        .split_at_checked(id_len)
        .ok_or_else(|| corrupt("credential id runs past the slot"))?;
    let (&rp_len, rest) = rest
        .split_first()
        .ok_or_else(|| corrupt("relying party id is missing"))?;
    let rp_len = usize::from(rp_len);
    if rp_len == 0 || rp_len > MAX_RP_ID {
        return Err(corrupt("relying party id length is out of range"));
    }
    if rest.len() != rp_len + SALT_LEN {
        return Err(corrupt("fields don't fill its public part exactly"));
    }
    let (rp_id, salt) = rest.split_at(rp_len);
    let salt = salt
        .try_into()
        .map_err(|_| corrupt("salt isn't 32 bytes"))?;
    Ok(Fields {
        flags: public[0],
        credential_id,
        rp_id,
        salt,
    })
}

fn read(public: &[u8]) -> Result<Fido2Slot<'_>> {
    let f = fields(public)?;
    if f.flags & !FLAGS_KNOWN != 0 {
        return Err(Error::unsupported_format(format!(
            "bhive: a security-key slot sets flag bits this BeeZip doesn't know (0x{:02x})",
            f.flags & !FLAGS_KNOWN
        )));
    }
    let rp_id =
        std::str::from_utf8(f.rp_id).map_err(|_| corrupt("relying party id isn't UTF-8"))?;
    Ok(Fido2Slot {
        credential_id: f.credential_id,
        rp_id,
        salt: f.salt,
        prf: f.flags & FLAG_PRF != 0,
        uv: f.flags & FLAG_UV != 0,
    })
}

/// WebAuthn's `prf` extension's salt for an input: `SHA-256("WebAuthn PRF" ‖ 00 ‖ input)`.
pub fn prf_salt(input: &[u8; 32]) -> [u8; 32] {
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(b"WebAuthn PRF\0");
    h.update(input);
    let mut out = [0; 32];
    out.copy_from_slice(h.finish().as_ref());
    out
}

/// What an authenticator's hmac-secret computes for one salt (CTAP 2.1 §12.5):
/// HMAC-SHA256 keyed by the credential's own random secret. For authenticators in tests; a
/// real one keeps its secret inside.
pub fn hmac_secret(cred_random: &[u8; 32], salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, cred_random);
    let mut out = Zeroizing::new([0; 32]);
    out.copy_from_slice(ring::hmac::sign(&key, salt).as_ref());
    out
}

/// 32 random bytes: a new slot's salt, and what `beezip-keys` needs for a credential's user id
/// and a request's challenge.
pub fn new_salt() -> Result<[u8; 32]> {
    let mut salt = [0; 32];
    getrandom::fill(&mut salt).map_err(|e| {
        Error::new(
            crate::ErrorKind::Io,
            format!("the system's random generator failed: {e}"),
        )
    })?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::bhive::crypt::{KEY_ID_LEN, SLOT_TAIL_LEN, label};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// A public part with these fields and lengths, which may lie about them.
    fn public(
        flags: u8,
        id_len: u16,
        id: &[u8],
        rp_len: u8,
        rp: &[u8],
        salt_len: usize,
    ) -> Vec<u8> {
        let mut p = vec![flags, 0];
        p.extend_from_slice(&id_len.to_le_bytes());
        p.extend_from_slice(id);
        p.push(rp_len);
        p.extend_from_slice(rp);
        p.extend(std::iter::repeat_n(0x5a, salt_len));
        p
    }

    fn good(id: &[u8], rp: &[u8]) -> Vec<u8> {
        public(FLAG_UV, id.len() as u16, id, rp.len() as u8, rp, SALT_LEN)
    }

    /// tests/fixtures/bhive-m14/vectors.json, `slots.fido2`: the slot parses into its fields,
    /// `make` writes its public part byte for byte, and its secret opens it as bhive.md §12.4
    /// says (context, PRK, wrap key and commitment, the wrapped file key).
    #[test]
    fn the_vector_parses_makes_and_opens() {
        let v = vectors();
        let slots = &v["slots"];
        let vec = &slots["fido2"];
        let s = |name: &str| hex(vec[name].as_str().unwrap());
        let key_id: [u8; KEY_ID_LEN] = hex(slots["key_id"].as_str().unwrap()).try_into().unwrap();
        let slot = s("slot");
        assert_eq!(slot[0], SlotKind::Fido2.id());
        let body = usize::from(u16::from_le_bytes([slot[2], slot[3]]));
        assert_eq!(slot.len(), 4 + body);
        let framed = &slot[..4 + body - SLOT_TAIL_LEN];
        let view = SlotView {
            index: 3,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed,
            public: &framed[4..],
        };
        check(view.public).unwrap();
        let parsed = parse(&view).unwrap();
        let credential_id = s("credential_id");
        let salt: [u8; 32] = s("salt").try_into().unwrap();
        assert_eq!(parsed.credential_id, credential_id);
        assert_eq!(parsed.rp_id, vec["rp_id"].as_str().unwrap());
        assert_eq!(parsed.rp_id, RP_ID);
        assert_eq!(parsed.salt, &salt);
        assert!(
            !parsed.prf,
            "the vector's salt goes to the authenticator as it is"
        );
        assert!(parsed.uv);
        assert_eq!(parsed.authenticator_salt(), salt);

        let secret: [u8; 32] = s("secret").try_into().unwrap();
        let made = make(&credential_id, RP_ID, &salt, false, &Zeroizing::new(secret)).unwrap();
        assert_eq!(made.public, view.public);
        assert!(made.recipient_key.is_empty());
        let SlotSecret::Shared(shared) = &made.secret else {
            panic!("a security key's secret is its hmac-secret output");
        };
        assert_eq!(shared.as_slice(), secret);

        // bhive.md §12.4, steps 1 to 4.
        let context = view.context(&made.recipient_key);
        assert_eq!(context.to_vec(), s("context"));
        let prk = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &context),
            shared,
        );
        assert_eq!(prk.as_ref(), s("prk"));
        let mut okm = [0; 64];
        hkdf::Hkdf::<sha2::Sha256>::from_prk(prk.as_ref())
            .unwrap()
            .expand(label::SLOT, &mut okm)
            .unwrap();
        assert_eq!(okm[..32], s("wrap_key"));
        assert_eq!(okm[32..], s("commitment"));
        let tail = &slot[framed.len()..];
        assert_eq!(tail[..32], okm[32..]);
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &okm[..32]).unwrap(),
        );
        let mut wrapped = tail[32..].to_vec();
        let file_key = key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key([0; 12]),
                ring::aead::Aad::from(framed),
                &mut wrapped,
            )
            .unwrap();
        assert_eq!(file_key, hex(slots["file_key"].as_str().unwrap()));
    }

    #[test]
    fn made_slots_parse_back_at_every_length_limit() {
        let salt = [7; 32];
        let secret = Zeroizing::new([9; 32]);
        let longest_rp = "r".repeat(MAX_RP_ID);
        for id_len in [1, 16, 48, 255, 256, MAX_CREDENTIAL_ID] {
            for rp in ["b", RP_ID, &longest_rp, "bée"] {
                let id: Vec<u8> = (0..id_len).map(|i| i as u8).collect();
                for prf in [false, true] {
                    let made = make(&id, rp, &salt, prf, &secret).unwrap();
                    assert_eq!(made.public.len(), FIXED_LEN + id_len + rp.len());
                    let s = read(&made.public).unwrap();
                    assert_eq!(s.credential_id, id);
                    assert_eq!(s.rp_id, rp);
                    assert_eq!(s.salt, &salt);
                    assert_eq!(s.prf, prf);
                    assert!(s.uv, "BeeZip always requires user verification");
                    assert_eq!(made.public[0] & !FLAGS_KNOWN, 0);
                    assert_eq!(made.public[1], 0, "the reserved byte");
                }
            }
        }
        assert_eq!(MAX_PUBLIC_LEN, 1313);
        let longest = make(&[1; MAX_CREDENTIAL_ID], &longest_rp, &salt, true, &secret).unwrap();
        assert_eq!(longest.public.len(), MAX_PUBLIC_LEN);
        // A slot's body length is a u16: the longest public part and its tail fit.
        assert!(MAX_PUBLIC_LEN + SLOT_TAIL_LEN <= usize::from(u16::MAX));
    }

    #[test]
    fn make_refuses_what_a_slot_cant_hold() {
        let salt = [0; 32];
        let secret = Zeroizing::new([0; 32]);
        for (id, rp) in [
            (vec![], RP_ID.to_string()),
            (vec![1; MAX_CREDENTIAL_ID + 1], RP_ID.to_string()),
            (vec![1], String::new()),
            (vec![1], "r".repeat(MAX_RP_ID + 1)),
        ] {
            let e = make(&id, &rp, &salt, true, &secret).err().unwrap();
            assert_eq!(e.kind, crate::ErrorKind::InvalidArgs, "{}", e.message);
        }
    }

    #[test]
    fn readers_refuse_malformed_public_parts() {
        let id = [0xc5; 48];
        let ok = good(&id, b"beezip");
        read(&ok).unwrap();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("only the flags", vec![FLAG_UV, 0, 1]),
            ("no id", public(FLAG_UV, 0, &[], 6, b"beezip", SALT_LEN)),
            (
                "an id over 1,023",
                public(FLAG_UV, 1024, &[1; 1024], 1, b"b", SALT_LEN),
            ),
            (
                "an id past the end",
                public(FLAG_UV, 200, &id, 6, b"beezip", SALT_LEN),
            ),
            (
                "no relying party",
                public(FLAG_UV, 48, &id, 0, b"", SALT_LEN),
            ),
            (
                "a relying party over 253",
                public(FLAG_UV, 1, &[1], 254, &[b'r'; 254], SALT_LEN),
            ),
            ("a short salt", public(FLAG_UV, 48, &id, 6, b"beezip", 31)),
            (
                "a byte too many",
                public(FLAG_UV, 48, &id, 6, b"beezip", 33),
            ),
            (
                "a relying party past the end",
                public(FLAG_UV, 48, &id, 40, b"beezip", SALT_LEN),
            ),
            (
                "too long",
                public(FLAG_UV, 1023, &[1; 1023], 253, &[b'r'; 253], SALT_LEN + 1),
            ),
        ];
        for (what, p) in cases {
            let e = check(&p)
                .err()
                .unwrap_or_else(|| panic!("{what} was checked"));
            assert_eq!(e.kind, crate::ErrorKind::Corrupt, "{what}");
            let e = read(&p).err().unwrap_or_else(|| panic!("{what} was read"));
            assert_eq!(e.kind, crate::ErrorKind::Corrupt, "{what}");
        }
        // Well framed but unusable: the key block is read, and only this slot can't be used.
        // A relying party id that isn't UTF-8:
        let p = public(FLAG_UV, 48, &id, 2, &[0xc3, 0x28], SALT_LEN);
        check(&p).unwrap();
        assert_eq!(read(&p).err().unwrap().kind, crate::ErrorKind::Corrupt);
        // Flag bits 2 to 7 are reserved: one set, the slot is for a newer reader.
        for bit in 2..8 {
            let mut p = ok.clone();
            p[0] |= 1 << bit;
            check(&p).unwrap();
            let e = read(&p)
                .err()
                .unwrap_or_else(|| panic!("bit {bit} was read"));
            assert_eq!(e.kind, crate::ErrorKind::UnsupportedFormat, "bit {bit}");
        }
        // The reserved byte is a field: it is ignored.
        let mut p = ok.clone();
        p[1] = 0xff;
        read(&p).unwrap();
        // Flags as other writers may set them: no PRF, no user verification.
        let mut p = ok;
        p[0] = 0;
        let s = read(&p).unwrap();
        assert!(!s.prf && !s.uv);
    }

    #[test]
    fn parse_takes_only_security_key_slots() {
        let key_id = [0; KEY_ID_LEN];
        let p = good(&[1; 8], b"beezip");
        let mut framed = vec![SlotKind::Fido2.id(), 0, 0, 0];
        framed.extend_from_slice(&p);
        let mut view = SlotView {
            index: 0,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
        };
        assert_eq!(parse(&view).unwrap().credential_id, [1; 8]);
        view.kind = SlotKind::Password;
        assert_eq!(
            parse(&view).err().unwrap().kind,
            crate::ErrorKind::InvalidArgs
        );
    }

    /// WebAuthn's PRF hash and CTAP's hmac-secret, against Python's hashlib and hmac.
    #[test]
    fn prf_and_hmac_secret_are_the_specifications() {
        let salt: [u8; 32] =
            hex("e7ce63ea1c9ae6f3cc1af2a6623a81eac9a571d1a824d68d9d3e339fc139f3a1")
                .try_into()
                .unwrap();
        assert_eq!(
            prf_salt(&salt).to_vec(),
            hex("c364a2195f6fc41d1bed3b2ac604df28d9c7a992fc2a548b9819f771ab8a2777")
        );
        let cred_random: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            hmac_secret(&cred_random, &salt).to_vec(),
            hex("781cfc918df034d7655892af258bd3bea57db6086e4babdbf47ed773b8b57b45")
        );
        let s = Fido2Slot {
            credential_id: &[1],
            rp_id: RP_ID,
            salt: &salt,
            prf: true,
            uv: true,
        };
        assert_eq!(s.authenticator_salt(), prf_salt(&salt));
    }

    #[test]
    fn salts_are_new_each_time() {
        let a = new_salt().unwrap();
        let b = new_salt().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }
}
