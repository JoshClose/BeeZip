//! Encrypted `.bhive` (docs/bhive.md §12, docs/M14.md §3–§8).
//!
//! The pieces, and who builds them in M14's wave 1 (docs/M14.md §10):
//! - [`envelope`]: the key block, the slots' wrapping, the header MAC, sealed records, cells and
//!   index (PR A).
//! - one module per slot kind's pure-Rust half: [`password`] and [`recovery`] (PR A),
//!   [`x25519`], [`xwing`] and [`bech32`] (PR C), [`rsa`], [`ecdh`] and [`cert`] (PR D),
//!   [`fido2`] (PR E);
//! - the signature algorithms' halves, [`mldsa`] and [`sig`] (PR H), used by `super::sign`.
//!
//! Keys and devices that live in the system (certificate stores, smart cards, the TPM,
//! security keys, your stored keys) are reached through [`KeySource`], which `beezip-keys`
//! implements and the commands layer hands to core through [`crate::Ctx::key_source`].
//! A slot kind returns [`not_built`] until its PR fills it.

pub mod bech32;
pub mod cert;
pub mod ecdh;
pub mod envelope;
pub mod fido2;
pub mod mldsa;
pub mod password;
pub mod prim;
pub mod recovery;
pub mod rsa;
pub mod sig;
pub mod x25519;
pub mod xwing;

use std::fmt;

use zeroize::Zeroizing;

use crate::{Error, ErrorKind, Result};

/// The suite the key block names: AES-256-GCM, HKDF-SHA256, HMAC-SHA256 (bhive.md §12.1).
pub const SUITE_1: u8 = 1;
/// At most this many slots, and this many bytes of them (bhive.md §12.3).
pub const MAX_SLOTS: usize = 64;
pub const MAX_SLOTS_LEN: usize = 65_536;
/// A slot's commitment and wrapped file key, after its public part (bhive.md §12.4).
pub const SLOT_TAIL_LEN: usize = 32 + 48;
/// The key id's length (bhive.md §12.2).
pub const KEY_ID_LEN: usize = 16;
/// At most this many password slots in a key block: a reader may run Argon2 for each
/// (bhive.md §12.5).
pub const MAX_PASSWORD_SLOTS: usize = 4;
/// Cells and the index are sealed in segments of this much plaintext (bhive.md §12.8).
pub const SEGMENT: usize = 1 << 20;
/// An AES-256-GCM tag.
pub const TAG_LEN: usize = 16;

/// The labels of bhive.md §12 and §13, byte for byte.
pub mod label {
    pub const MAC: &[u8] = b"bhive1 mac";
    pub const RECORD: &[u8] = b"bhive1 record";
    pub const CELL: &[u8] = b"bhive1 cell";
    pub const INDEX: &[u8] = b"bhive1 index";
    pub const SLOT: &[u8] = b"bhive1 slot";
    pub const TAG: &[u8] = b"bhive1 tag";
    pub const MANIFEST: &[u8] = b"bhive1 manifest";
    pub const SIGNATURE: &[u8] = b"bhive1 signature";
    /// ML-DSA-65's context string for signatures (bhive.md §13.4).
    pub const MLDSA_CONTEXT: &[u8] = b"bhive1";
}

/// What M14's parts return until their PR builds them.
pub fn not_built(what: &str) -> Error {
    Error::new(
        ErrorKind::UnsupportedOperation,
        format!("bhive: {what} is not built yet (docs/M14.md)"),
    )
}

/// The file key, `K` in bhive.md §12.2. Wiped when dropped; never printed.
#[derive(Clone)]
pub struct FileKey(pub Zeroizing<[u8; 32]>);

impl fmt::Debug for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileKey(***)")
    }
}

/// A slot's kind (bhive.md §12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotKind {
    Password = 1,
    RecoveryKey = 2,
    X25519 = 3,
    XWing = 4,
    Rsa = 5,
    EcP256 = 6,
    EcP384 = 7,
    Fido2 = 8,
}

impl SlotKind {
    pub const ALL: [Self; 8] = [
        Self::Password,
        Self::RecoveryKey,
        Self::X25519,
        Self::XWing,
        Self::Rsa,
        Self::EcP256,
        Self::EcP384,
        Self::Fido2,
    ];

    pub const fn id(self) -> u8 {
        self as u8
    }

    /// `None` for a kind this BeeZip doesn't know: a reader skips such slots.
    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.id() == id)
    }

    /// Whether a quantum computer can't open this kind (docs/M14.md §1, decision 9).
    pub const fn post_quantum(self) -> bool {
        matches!(
            self,
            Self::Password | Self::RecoveryKey | Self::XWing | Self::Fido2
        )
    }

    /// Whether opening it may need a person: a PIN, a touch, Windows Hello. BeeZip never
    /// touches such a way in unless the user chose it (docs/M14.md §8).
    pub const fn needs_device(self) -> bool {
        matches!(self, Self::Fido2)
    }
}

/// The label of [`SlotView::kept_id`]: BeeZip's own, in memory only, not one of bhive.md's.
const KEPT: &[u8] = b"beezip kept slot";

/// A slot as the key block holds it (bhive.md §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotView<'a> {
    /// Its place in the key block, from 0.
    pub index: usize,
    pub kind: SlotKind,
    /// The key block's key id, which every slot's context includes.
    pub key_id: &'a [u8; KEY_ID_LEN],
    /// The slot's first 4 + p bytes: its head and public part. The context, the wrap key's
    /// associated data and the tags are computed over these.
    pub framed: &'a [u8],
    /// The public part alone.
    pub public: &'a [u8],
    /// The slot's commitment, after its public part. A key source with several keys for an
    /// anonymous slot (kinds 3 and 4) compares it to tell which key is the slot's
    /// (`x25519::commits`).
    pub commitment: &'a [u8; 32],
}

impl SlotView<'_> {
    /// `SHA-256("bhive1 slot" ‖ key id ‖ framed ‖ recipient key)` (bhive.md §12.4 step 1). A
    /// key source whose secret never leaves its device (CNG's `BCRYPT_KDF_HMAC`) keys its HMAC
    /// with this.
    pub fn context(&self, recipient_key: &[u8]) -> [u8; 32] {
        let mut h = ring::digest::Context::new(&ring::digest::SHA256);
        h.update(label::SLOT);
        h.update(self.key_id);
        h.update(self.framed);
        h.update(recipient_key);
        let mut out = [0; 32];
        out.copy_from_slice(h.finish().as_ref());
        out
    }

    /// The tag of a slot of kind 5 to 7, for the certificate or key whose SubjectPublicKeyInfo
    /// is `spki` (bhive.md §12.5, "Tags"). `None` for other kinds.
    pub fn tag_for(&self, spki: &[u8]) -> Option<[u8; 4]> {
        let rest = match self.kind {
            // A tag, the ciphertext's length, the ciphertext.
            SlotKind::Rsa => self.public.get(6..)?,
            // A tag, the ephemeral public key.
            SlotKind::EcP256 | SlotKind::EcP384 => self.public.get(4..)?,
            _ => return None,
        };
        let key = ring::digest::digest(&ring::digest::SHA256, spki);
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.as_ref());
        let mut m = ring::hmac::Context::with_key(&key);
        m.update(label::TAG);
        m.update(&[self.kind.id()]);
        m.update(rest);
        let mut tag = [0; 4];
        tag.copy_from_slice(&m.sign().as_ref()[..4]);
        Some(tag)
    }

    /// What a secret kept for this slot is filed under ([`crate::Ctx::keep_secret`]): SHA-256
    /// over a label, the key id, and the slot's head, public part and commitment. A rebuilt slot
    /// (a new key makes every slot again, with a new key id) never matches what was kept for the
    /// old one; an edit, which keeps the key id and the slots byte for byte under a new archive
    /// id, still does. Never written anywhere.
    pub fn kept_id(&self) -> [u8; 32] {
        let mut h = ring::digest::Context::new(&ring::digest::SHA256);
        h.update(KEPT);
        h.update(self.key_id);
        h.update(self.framed);
        h.update(self.commitment);
        let mut out = [0; 32];
        out.copy_from_slice(h.finish().as_ref());
        out
    }

    /// The tag the slot carries (kinds 5 to 7).
    pub fn tag(&self) -> Option<[u8; 4]> {
        match self.kind {
            SlotKind::Rsa | SlotKind::EcP256 | SlotKind::EcP384 => {
                self.public.get(..4).and_then(|t| t.try_into().ok())
            }
            _ => None,
        }
    }
}

/// What opens a slot: its secret `S`, or, where `S` never leaves a device, the HMAC already
/// computed from it (`PRK`, bhive.md §12.4 step 2). For kinds 3, 6 and 7 a reader gives the
/// PRK: their context holds the recipient's public key, which only the key's holder knows
/// ([`SlotView::context`]). A writer always gives `S` ([`MadeSlot`]). Wiped when dropped, a
/// clone too.
#[derive(Clone)]
pub enum SlotSecret {
    Shared(Zeroizing<Vec<u8>>),
    Extracted(Zeroizing<[u8; 32]>),
}

impl fmt::Debug for SlotSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Shared(_) => "SlotSecret::Shared(***)",
            Self::Extracted(_) => "SlotSecret::Extracted(***)",
        })
    }
}

/// Where a reader gets the secrets of slots that need a key or a device: your stored keys,
/// key files given with `--identity`, certificates, the TPM, security keys. `beezip-keys`
/// implements it (PRs C, D, E); the commands layer passes one through [`crate::Ctx`] (PR F).
pub trait KeySource {
    /// Whether this source has a key or device for `slot`: for anonymous public-key slots it
    /// tries its keys, for tagged ones it compares tags. Never prompts, never touches a device.
    fn offers(&mut self, slot: &SlotView<'_>) -> bool;

    /// The secret for `slot`, or `None` when this source has nothing for it. `device` says the
    /// user chose this way in, so the source may show a PIN dialog or ask for a touch; then an
    /// error says why it didn't open (`KeyRequired` for another device, `Cancelled` for a
    /// closed dialog), and the unlock asks for a way in again. Only `Corrupt` ends it.
    fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>>;
}

/// A way in, as the Unlock prompt lists it (docs/M14.md §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WayInfo {
    pub slot: u32,
    pub kind: SlotKind,
    /// A key or device on this machine fits it ([`KeySource::offers`]).
    pub here: bool,
}

/// What an encrypted archive asks [`crate::Ctx::unlock`] for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockRequest {
    pub ways: Vec<WayInfo>,
    /// The answers that already failed: `0` is the first ask.
    pub attempt: u32,
}

/// An answer to an [`UnlockRequest`].
#[derive(Clone, PartialEq, Eq)]
pub enum UnlockAnswer {
    Password(String),
    /// The 48 digits, with any separators (bhive.md §12.5, kind 2).
    RecoveryKey(String),
    /// Use this slot's key or device, through the [`KeySource`].
    Way(u32),
}

impl fmt::Debug for UnlockAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(***)"),
            Self::RecoveryKey(_) => f.write_str("RecoveryKey(***)"),
            Self::Way(slot) => write!(f, "Way({slot})"),
        }
    }
}

/// How hard a password slot makes guessing (bhive.md §12.5, docs/M14.md decision 5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Strength {
    /// 1 GiB, 2 passes, 4 lanes.
    #[default]
    Standard,
    /// 2 GiB, 3 passes, 4 lanes.
    Strong,
    /// Any cost within the limits (bhive.md §12.5): for tests and fixtures, which can't spend
    /// a gigabyte on every archive. BeeZip writes Standard or Strong.
    #[doc(hidden)]
    Cost {
        memory_kib: u32,
        passes: u32,
        lanes: u32,
    },
}

impl Strength {
    /// Argon2id's memory in KiB, passes and lanes.
    pub const fn cost(self) -> (u32, u32, u32) {
        match self {
            Self::Standard => (1 << 20, 2, 4),
            Self::Strong => (2 << 20, 3, 4),
            Self::Cost {
                memory_kib,
                passes,
                lanes,
            } => (memory_kib, passes, lanes),
        }
    }
}

/// An EC curve of slots 6 and 7, and of ECDSA signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    P256,
    P384,
}

/// A slot to make when writing: who will be able to open the archive.
#[derive(Clone)]
pub enum Recipient {
    Password {
        password: Zeroizing<String>,
        strength: Strength,
    },
    /// The key's 16 bytes; the commands layer makes it and shows it once.
    RecoveryKey(Zeroizing<[u8; 16]>),
    /// An `age1…` key's 32 bytes.
    X25519([u8; 32]),
    /// An `age1pq1…` key's 1,216 bytes.
    XWing(Box<[u8; 1216]>),
    /// A certificate's or key's SubjectPublicKeyInfo, DER, with the certificate if there is
    /// one (for the slot description).
    Rsa {
        spki: Vec<u8>,
        certificate: Option<Vec<u8>>,
    },
    Ec {
        curve: Curve,
        spki: Vec<u8>,
        certificate: Option<Vec<u8>>,
        /// A TPM key: bound to this machine (docs/M14.md decision 11).
        machine_bound: bool,
    },
    /// A security key or Windows Hello, already asked for the hmac-secret of `salt` by the
    /// commands layer (PR E), since making the slot needs `S`.
    Fido2 {
        credential_id: Vec<u8>,
        rp_id: String,
        salt: [u8; 32],
        prf: bool,
        secret: Zeroizing<[u8; 32]>,
        machine_bound: bool,
    },
}

impl Recipient {
    /// A password slot's recipient, for callers that don't hold a `Zeroizing` of their own.
    pub fn password(password: &str, strength: Strength) -> Self {
        Self::Password {
            password: Zeroizing::new(password.to_owned()),
            strength,
        }
    }

    /// A recovery key's recipient, from its 16 bytes.
    pub fn recovery_key(key: &[u8; 16]) -> Self {
        Self::RecoveryKey(Zeroizing::new(*key))
    }

    pub const fn kind(&self) -> SlotKind {
        match self {
            Self::Password { .. } => SlotKind::Password,
            Self::RecoveryKey(_) => SlotKind::RecoveryKey,
            Self::X25519(_) => SlotKind::X25519,
            Self::XWing(_) => SlotKind::XWing,
            Self::Rsa { .. } => SlotKind::Rsa,
            Self::Ec {
                curve: Curve::P256, ..
            } => SlotKind::EcP256,
            Self::Ec {
                curve: Curve::P384, ..
            } => SlotKind::EcP384,
            Self::Fido2 { .. } => SlotKind::Fido2,
        }
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient::{:?}", self.kind())
    }
}

/// A recipient with the label its slot description gets (bhive.md §12.9).
#[derive(Debug, Clone)]
pub struct Labelled {
    pub recipient: Recipient,
    pub label: Option<String>,
}

/// Who can open an archive a writer makes.
#[derive(Debug, Clone)]
pub enum Protection {
    /// A new file key, with a slot for each.
    New(Vec<Labelled>),
    /// An edit: the archive it reads keeps its file key and slots (docs/M14.md decision 7).
    Keep(std::sync::Arc<envelope::Unlocked>),
    /// The archive it reads with ways in removed (by slot, as the key block has them) and
    /// added, under the same file key: its cells are copied sealed as they are, and the slots
    /// it keeps are kept byte for byte (`archive.protect`, docs/M14.md §3).
    Change {
        from: std::sync::Arc<envelope::Unlocked>,
        remove: Vec<usize>,
        add: Vec<Labelled>,
    },
}

/// What section 5 says of a slot (bhive.md §12.9): claims, for people, never checked against the
/// slot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Description {
    pub label: Option<String>,
    /// An X25519 (32 bytes) or X-Wing (1,216) public key.
    pub public_key: Option<Vec<u8>>,
    /// A certificate in DER, or a key's SubjectPublicKeyInfo.
    pub certificate: Option<Vec<u8>>,
    /// Bound to one machine: a TPM key, Windows Hello.
    pub machine_bound: bool,
}

impl Description {
    /// What a writer says of a recipient.
    pub fn of(l: &Labelled) -> Self {
        let (public_key, certificate, machine_bound) = match &l.recipient {
            Recipient::X25519(k) => (Some(k.to_vec()), None, false),
            Recipient::XWing(k) => (Some(k.to_vec()), None, false),
            Recipient::Rsa { spki, certificate } => (
                None,
                Some(certificate.clone().unwrap_or_else(|| spki.clone())),
                false,
            ),
            Recipient::Ec {
                spki,
                certificate,
                machine_bound,
                ..
            } => (
                None,
                Some(certificate.clone().unwrap_or_else(|| spki.clone())),
                *machine_bound,
            ),
            Recipient::Fido2 { machine_bound, .. } => (None, None, *machine_bound),
            Recipient::Password { .. } | Recipient::RecoveryKey(_) => (None, None, false),
        };
        Self {
            label: l.label.clone(),
            public_key,
            certificate,
            machine_bound,
        }
    }

    /// The fields, as one slot's entry of section 5 holds them, without its length.
    pub fn encode(&self) -> Vec<u8> {
        use super::layout::put_uvarint;
        let mut out = Vec::new();
        let mut field = |tag: u64, value: &[u8]| {
            put_uvarint(&mut out, tag);
            put_uvarint(&mut out, value.len() as u64);
            out.extend_from_slice(value);
        };
        if let Some(label) = &self.label {
            field(1, label.as_bytes());
        }
        if let Some(key) = &self.public_key {
            field(2, key);
        }
        if let Some(cert) = &self.certificate {
            field(3, cert);
        }
        if self.machine_bound {
            field(4, &[]);
        }
        out
    }

    /// One slot's fields. Tags it doesn't know are skipped; tags out of order are refused.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut b = super::layout::Bytes::new(body);
        let mut d = Self::default();
        let mut last = None;
        while b.left() > 0 {
            let tag = b.uvarint()?;
            let value = b.bytes()?;
            if last.is_some_and(|last| tag <= last) {
                return Err(super::layout::bad(
                    "a slot description's fields are out of order",
                ));
            }
            last = Some(tag);
            match tag {
                1 => d.label = Some(String::from_utf8_lossy(value).into_owned()),
                2 => d.public_key = Some(value.to_vec()),
                3 => d.certificate = Some(value.to_vec()),
                4 => d.machine_bound = true,
                _ => {}
            }
        }
        Ok(d)
    }
}

/// Section 5's body for these slots' entries, each as [`Description::encode`] gives it.
pub fn encode_descriptions(entries: &[Vec<u8>]) -> Vec<u8> {
    use super::layout::put_uvarint;
    let mut out = Vec::new();
    put_uvarint(&mut out, entries.len() as u64);
    for e in entries {
        put_uvarint(&mut out, e.len() as u64);
        out.extend_from_slice(e);
    }
    out
}

/// Section 5's entries, one per slot, as they are; `None` unless its count is `slots` and it
/// parses (bhive.md §12.9: otherwise a reader ignores it).
pub fn split_descriptions(body: &[u8], slots: usize) -> Option<Vec<Vec<u8>>> {
    let mut b = super::layout::Bytes::new(body);
    let count = b.uvarint().ok()?;
    if count != slots as u64 {
        return None;
    }
    let mut out = Vec::with_capacity(slots);
    for _ in 0..slots {
        out.push(b.bytes().ok()?.to_vec());
    }
    (b.left() == 0).then_some(out)
}

/// A slot's public part and secret, made for a [`Recipient`] by its kind's module.
pub struct MadeSlot {
    pub public: Vec<u8>,
    pub secret: SlotSecret,
    /// What the context adds for kinds 3, 6 and 7 (bhive.md §12.4).
    pub recipient_key: Vec<u8>,
}

/// Makes the public part and secret of a slot for `recipient`: each kind in its own module.
pub fn make_slot(recipient: &Recipient) -> Result<MadeSlot> {
    match recipient {
        Recipient::Password { password, strength } => password::make(password, *strength),
        Recipient::RecoveryKey(key) => recovery::make(key),
        Recipient::X25519(public) => x25519::make(public),
        Recipient::XWing(public) => xwing::make(public),
        Recipient::Rsa { spki, .. } => rsa::make(spki),
        Recipient::Ec { curve, spki, .. } => ecdh::make(*curve, spki),
        Recipient::Fido2 {
            credential_id,
            rp_id,
            salt,
            prf,
            secret,
            ..
        } => fido2::make(credential_id, rp_id, salt, *prf, secret),
    }
}

/// The secret of `slot` from an answer the user typed: a password, or a recovery key. Other
/// kinds come from a [`KeySource`].
pub fn typed_secret(slot: &SlotView<'_>, answer: &UnlockAnswer) -> Result<Option<SlotSecret>> {
    match (slot.kind, answer) {
        (SlotKind::Password, UnlockAnswer::Password(p)) => password::secret(slot, p).map(Some),
        (SlotKind::RecoveryKey, UnlockAnswer::RecoveryKey(k)) => {
            recovery::secret(slot, k).map(Some)
        }
        _ => Ok(None),
    }
}

/// A credential id is at most this long, and a relying party id at most this (bhive.md §12.5).
pub const MAX_CREDENTIAL_ID: usize = 1023;
pub const MAX_RP_ID: usize = 253;

/// Kinds 5 and 8 carry lengths inside their public parts: those lengths and the fixed fields
/// must fill the part exactly (bhive.md §12.5, §12.10). Kind 5: a tag (4), the ciphertext's
/// length (`u16`) and the ciphertext, 256 to 1,024 bytes. Kind 8: flags, reserved, the
/// credential id's length (`u16`) and the id (1 to 1,023 bytes), the relying party's length
/// (`u8`) and its id (1 to 253), and a salt (32).
pub fn check_framing(kind: SlotKind, public: &[u8]) -> Result<()> {
    let u16_at = |at: usize| {
        public
            .get(at..at + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
    };
    match kind {
        SlotKind::Rsa => match u16_at(4) {
            Some(len)
                if (rsa::MIN_MODULUS..=rsa::MAX_MODULUS).contains(&len)
                    && public.len() == 6 + len =>
            {
                Ok(())
            }
            _ => Err(super::layout::bad(format!(
                "an RSA slot's public part of {} bytes doesn't hold a tag and a ciphertext of \
                 256 to 1,024 bytes exactly",
                public.len()
            ))),
        },
        SlotKind::Fido2 => {
            let fits = u16_at(2).is_some_and(|id| {
                let rp_at = 4 + id;
                (1..=MAX_CREDENTIAL_ID).contains(&id)
                    && public.get(rp_at).is_some_and(|&rp| {
                        let rp = usize::from(rp);
                        (1..=MAX_RP_ID).contains(&rp) && public.len() == rp_at + 1 + rp + 32
                    })
            });
            if fits {
                Ok(())
            } else {
                Err(super::layout::bad(format!(
                    "a security-key slot's public part of {} bytes doesn't hold its credential \
                     id (1 to 1,023 bytes), relying party (1 to 253) and salt exactly",
                    public.len()
                )))
            }
        }
        _ => Ok(()),
    }
}

/// Checks a slot's public part against its kind's rules before anything is tried with it
/// (bhive.md §12.10): lengths and how they fill the part, Argon2's limits, a credential id's
/// size.
pub fn check_public(kind: SlotKind, public: &[u8]) -> Result<()> {
    check_framing(kind, public)?;
    match kind {
        SlotKind::Password => password::check(public),
        SlotKind::RecoveryKey => recovery::check(public),
        SlotKind::X25519 => x25519::check(public),
        SlotKind::XWing => xwing::check(public),
        SlotKind::Rsa => rsa::check(public),
        SlotKind::EcP256 => ecdh::check(Curve::P256, public),
        SlotKind::EcP384 => ecdh::check(Curve::P384, public),
        SlotKind::Fido2 => fido2::check(public),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_and_unknown_ones_are_skipped() {
        for k in SlotKind::ALL {
            assert_eq!(SlotKind::from_id(k.id()), Some(k));
        }
        assert_eq!(SlotKind::from_id(0), None);
        assert_eq!(SlotKind::from_id(9), None);
    }

    #[test]
    fn levels_cost_what_the_plan_says() {
        assert_eq!(Strength::Standard.cost(), (1_048_576, 2, 4));
        assert_eq!(Strength::Strong.cost(), (2_097_152, 3, 4));
    }

    /// tests/fixtures/bhive-m14/vectors.json, `slots`: every kind's context, and the tags.
    #[test]
    fn contexts_and_tags_are_the_specifications() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let hex = |s: &serde_json::Value| -> Vec<u8> {
            let s = s.as_str().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let slots = &v["slots"];
        let key_id: [u8; KEY_ID_LEN] = hex(&slots["key_id"]).try_into().unwrap();
        for name in [
            "password",
            "recovery_key",
            "x25519",
            "xwing",
            "rsa",
            "p256",
            "p384",
            "fido2",
        ] {
            let vec = &slots[name];
            let slot = hex(&vec["slot"]);
            let kind = SlotKind::from_id(slot[0]).unwrap();
            let body = usize::from(u16::from_le_bytes([slot[2], slot[3]]));
            assert_eq!(slot.len(), 4 + body, "{name}");
            let framed = &slot[..4 + body - SLOT_TAIL_LEN];
            let view = SlotView {
                index: 0,
                kind,
                key_id: &key_id,
                framed,
                public: &framed[4..],
                commitment: slot[framed.len()..framed.len() + 32].try_into().unwrap(),
            };
            let recipient = match name {
                "x25519" | "p256" | "p384" => hex(&vec["recipient_public"]),
                _ => Vec::new(),
            };
            assert_eq!(
                view.context(&recipient).to_vec(),
                hex(&vec["context"]),
                "{name}"
            );
            if let Some(spki) = vec.get("spki") {
                let tag = view.tag_for(&hex(spki)).unwrap();
                assert_eq!(tag.to_vec(), hex(&vec["tag"]), "{name}");
                assert_eq!(view.tag(), Some(tag), "{name}");
            } else {
                assert_eq!(view.tag_for(b"spki"), None, "{name}");
            }
        }
    }

    /// vectors.json's RSA and security-key slots fill their public parts exactly; a byte less
    /// or more, or a length out of its range, is refused.
    #[test]
    fn kinds_5_and_8_fill_their_public_parts_exactly() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for name in ["rsa", "fido2"] {
            let s = v["slots"][name]["slot"].as_str().unwrap();
            let slot: Vec<u8> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect();
            let kind = SlotKind::from_id(slot[0]).unwrap();
            let public = &slot[4..slot.len() - SLOT_TAIL_LEN];
            assert!(check_framing(kind, public).is_ok(), "{name}");
            let cut = &public[..public.len() - 1];
            assert!(check_framing(kind, cut).is_err(), "{name}");
            let mut longer = public.to_vec();
            longer.push(0);
            assert!(check_framing(kind, &longer).is_err(), "{name}");
            for at in 0..public.len().min(8) {
                assert!(check_framing(kind, &public[..at]).is_err(), "{name} {at}");
            }
        }
        // RSA: a ciphertext of 255 bytes, or of 1,025, is no modulus BeeZip takes.
        for len in [0usize, 255, 1025] {
            let mut p = vec![0u8; 6 + len];
            p[4..6].copy_from_slice(&(len as u16).to_le_bytes());
            assert!(check_framing(SlotKind::Rsa, &p).is_err(), "{len}");
        }
        for len in [256usize, 1024] {
            let mut p = vec![0u8; 6 + len];
            p[4..6].copy_from_slice(&(len as u16).to_le_bytes());
            assert!(check_framing(SlotKind::Rsa, &p).is_ok(), "{len}");
        }
        // FIDO2: the id and the relying party each 1 or more, at most 1,023 and 253.
        let fido = |id: usize, rp: usize| {
            let mut p = vec![2u8, 0];
            p.extend_from_slice(&(id as u16).to_le_bytes());
            p.extend(std::iter::repeat_n(7u8, id));
            p.push(rp as u8);
            p.extend(std::iter::repeat_n(b'r', rp));
            p.extend([0u8; 32]);
            check_framing(SlotKind::Fido2, &p).is_ok()
        };
        assert!(fido(1, 1) && fido(MAX_CREDENTIAL_ID, MAX_RP_ID));
        assert!(!fido(0, 6) && !fido(16, 0) && !fido(MAX_CREDENTIAL_ID + 1, 6));
        assert!(!fido(16, MAX_RP_ID + 1));
        // The other kinds are checked by their own lengths.
        assert!(check_framing(SlotKind::Password, &[]).is_ok());
    }

    /// Tags it doesn't know, 0 among them, are skipped (bhive.md §12.9).
    #[test]
    fn descriptions_skip_unknown_tags() {
        let mut body = vec![0u8, 1, 9];
        body.extend_from_slice(
            &Description {
                label: Some("Password".into()),
                ..Description::default()
            }
            .encode(),
        );
        let d = Description::parse(&body).unwrap();
        assert_eq!(d.label.as_deref(), Some("Password"));
        assert!(Description::parse(&[1, 1, b'a', 1, 1, b'b']).is_err());
        assert!(Description::parse(&[0, 0, 0, 0]).is_err());
    }

    #[test]
    fn secrets_are_never_printed() {
        let a = UnlockAnswer::Password("hunter2".into());
        assert!(!format!("{a:?}").contains("hunter2"));
        let r = Recipient::Password {
            password: Zeroizing::new("hunter2".into()),
            strength: Strength::Standard,
        };
        assert!(!format!("{r:?}").contains("hunter2"));
    }
}
