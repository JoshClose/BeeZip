//! The wire types of encrypted and signed `.bhive` (docs/M14.md §8, §11): ways in, the Unlock
//! prompt's, signatures, keys and certificates. Enums derive `clap::ValueEnum` where a flag
//! takes them, with the same names as serde.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// How hard a password makes guessing (docs/M14.md decision 5).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum StrengthName {
    /// Argon2id with 1 GiB and 2 passes: about 0.3 s on a fast desktop, 0.6 s on a laptop.
    #[default]
    Standard,
    /// 2 GiB and 3 passes: about 0.8 s and 1.7 s. Needs 2 GiB free to open.
    Strong,
}

/// A way into an encrypted `.bhive` (docs/bhive.md §12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum SlotKindName {
    Password,
    RecoveryKey,
    /// An `age1…` key.
    PublicKey,
    /// An `age1pq1…` key: post-quantum.
    PostQuantumKey,
    RsaCertificate,
    /// An EC certificate or key on P-256, "This PC"'s included.
    EcP256,
    EcP384,
    /// A FIDO2 security key, or Windows Hello.
    SecurityKey,
}

/// A way in, as `archive.protection` lists it once the archive is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WayIn {
    /// Its slot, from 0: what `archive.protect` removes.
    pub slot: u32,
    pub kind: SlotKindName,
    /// What the writer called it, from the archive's slot descriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub label: Option<String>,
    /// The public key as text, or the certificate's subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub recipient: Option<String>,
    /// The fingerprint of its public key or certificate, 16 characters in groups of four, for
    /// people to compare with the key's owner before trusting it (New key's confirmation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub fingerprint: Option<String>,
    /// It works only on one machine: a TPM key, Windows Hello.
    pub machine_bound: bool,
    /// A quantum computer couldn't open it.
    pub post_quantum: bool,
}

/// A way in, as the Unlock prompt lists it, before the archive is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct UnlockWay {
    pub slot: u32,
    pub kind: SlotKindName,
    /// A key or device on this machine fits it.
    pub here: bool,
    /// Choosing it needs a PIN that the front end asks for and sends with the reply
    /// (`UnlockReply::Slot`'s `pin`): a This PC key's. Windows' own dialog never asks for it.
    /// A smart card's PIN is still Windows' to ask for.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[ts(as = "Option<bool>", optional)]
    pub needs_pin: bool,
}

impl UnlockWay {
    /// Whether it is a password or a recovery key: something a person types, which a front
    /// end with nobody to ask fails for as `PasswordRequired` rather than `KeyRequired`.
    pub fn is_typed(&self) -> bool {
        matches!(
            self.kind,
            SlotKindName::Password | SlotKindName::RecoveryKey
        )
    }
}

/// An answer to the Unlock prompt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "way", rename_all = "kebab-case")]
pub enum UnlockReply {
    Password {
        password: String,
    },
    /// 48 digits, with any separators.
    RecoveryKey {
        key: String,
    },
    /// Use this slot's key or device: a PIN dialog or a touch may follow. For a way in that
    /// `needs_pin`, `pin` is the PIN the front end asked for.
    Slot {
        slot: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        pin: Option<crate::wire::Secret>,
    },
}

impl std::fmt::Debug for UnlockReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => f.write_str("Password(***)"),
            Self::RecoveryKey { .. } => f.write_str("RecoveryKey(***)"),
            Self::Slot { slot, pin: None } => write!(f, "Slot({slot})"),
            Self::Slot { slot, pin: Some(_) } => write!(f, "Slot({slot}, PIN ***)"),
        }
    }
}

/// A signature's algorithm (docs/bhive.md §13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithmName {
    /// A BeeZip signing key: ML-DSA-65 and Ed25519. Post-quantum.
    MlDsa65Ed25519,
    RsaPss,
    RsaPkcs1,
    EcdsaP256,
    EcdsaP384,
    Unknown,
}

/// Whether a signature checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureStatusName {
    Valid,
    /// It doesn't verify, or a cell differs from its digest: the archive changed after it was
    /// signed.
    Changed,
    UnknownAlgorithm,
    NotChecked,
}

/// Whom a valid signature is from (docs/M14.md §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum TrustName {
    /// Your own signing key.
    Yours,
    Contact,
    /// A certificate whose chain the system trusts.
    Trusted,
    Expired,
    Revoked,
    Unknown,
}

/// A signature, as `archive.info`, `archive.test` and `archive.sign` report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SignatureReport {
    pub algorithm: SignatureAlgorithmName,
    pub status: SignatureStatusName,
    /// Set when the signature is valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub trust: Option<TrustName>,
    /// Who signed, as BeeZip shows it: your key's or a contact's name, a certificate's subject,
    /// or the fingerprint.
    pub signer: String,
    /// 16 characters in groups of four (docs/bhive.md §13.5), of the signer bytes: for a
    /// certificate, of its chain as the signature carries it.
    pub fingerprint: String,
    /// A certificate signer's own certificate's fingerprint, the same whatever chain follows it:
    /// what its owner can read out, and what the contact made from it shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub certificate_fingerprint: Option<String>,
    /// The signer's public key (`bzsig1…`) or certificate (PEM), for "Add to contacts"; absent
    /// for a certificate whose key usage forbids signatures, which no contact makes known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub public: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub issuer: Option<String>,
    /// The time the signer claims, in seconds since 1970.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub claimed_time: Option<i64>,
    pub post_quantum: bool,
    /// Why it couldn't be checked, or what is wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub note: Option<String>,
}

/// What a key of yours is for.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum KeyKindName {
    /// Opens archives; post-quantum (`age1pq1…`). The default.
    #[default]
    PostQuantum,
    /// Opens archives (`age1…`), for age tools that don't know post-quantum keys.
    Classic,
    /// Signs archives (`bzsig1…`).
    Signing,
    /// Someone else's certificate, a contact: added with `keys.import`, never made.
    #[value(skip)]
    Certificate,
}

/// A key or contact, as `keys.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct KeyInfo {
    pub name: String,
    pub kind: KeyKindName,
    /// The public key as text, to share; a certificate's PEM.
    pub public: String,
    pub fingerprint: String,
    /// Yours, with its private key here; or a contact's.
    pub own: bool,
    /// Seconds since 1970.
    pub created: i64,
    /// A certificate's subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub subject: Option<String>,
    /// A certificate's issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub issuer: Option<String>,
    /// When a certificate expires, in seconds since 1970.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub not_after: Option<i64>,
    /// Why an archive can't be encrypted to a certificate, when it can't (an ECDSA-only key,
    /// RSA under 2,048 bits…): it may still be known as a signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub refused: Option<String>,
}

/// Where a certificate's private key is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum KeyHomeName {
    Software,
    SmartCard,
    Tpm,
    File,
}

/// A certificate, as `certificates.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CertificateInfo {
    /// SHA-1, hex, as Windows shows it: what `--to-cert` and `--sign` take.
    pub thumbprint: String,
    pub subject: String,
    pub issuer: String,
    /// Seconds since 1970.
    pub not_after: i64,
    /// `rsa-2048`, `ec-p256`…
    pub algorithm: String,
    /// The store it is in (`personal`, `other-people`), on Windows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub store: Option<String>,
    /// Where its private key is, when this machine has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub key: Option<KeyHomeName>,
    pub can_encrypt: bool,
    pub can_sign: bool,
    /// Why it can't encrypt, when it can't (an ECDSA-only key, RSA under 2,048 bits…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub refused: Option<String>,
    /// The system trusts its chain.
    pub trusted: bool,
}
