//! What the commands share for encrypted and signed `.bhive` (docs/M14.md §8, §11): the ways in
//! an input asks for, the signers it names, `require_signer`, the ways in and signatures an
//! archive reports, and writing a `.bhive` again with its cells as they are stored.
//!
//! Core makes the slots and signatures; `beezip-keys` finds the keys, certificates and devices.
//! This module turns the inputs' strings (a key, a contact's name, a thumbprint, a file) into
//! what they take, and keeps the rules that are about people rather than bytes: a way in bound
//! to one PC needs one that isn't (decision 11), a password beside other people's keys gets a
//! warning (decision 12), and nobody's device is touched, no recovery key made and nothing
//! signed when nobody is there to see it (MCP, decisions 15 and 27).

use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use beezip_core::{
    EntryKind, Keep, WriteSpec,
    edit::{Item, RewriteReport, file_writer, rewrite, swap::Target},
    format::{
        ArchiveReader, FormatId,
        bhive::{
            BhiveReader, BhiveWriteOptions,
            crypt::{
                Curve, Labelled, Recipient, SLOT_TAIL_LEN, SlotKind, Strength,
                bech32::{self, KeyText},
                cert::{self, Certificate, KeyAlgorithm},
                envelope::KeyBlock,
                recovery,
            },
            layout,
            sign::{self, Algorithm, SignatureInfo, Signing, Status},
        },
    },
    source::open,
};
use beezip_keys::identity::{KeyKind, Store};
use zeroize::Zeroizing;

use crate::{
    CmdError, ErrorCode, JobCtx, LogLevel,
    commands::{
        ArchiveProtectionOutput,
        util::{absolute, open_options},
    },
    crypt::{
        SignatureAlgorithmName, SignatureReport, SignatureStatusName, SlotKindName, StrengthName,
        TrustName, WayIn,
    },
    wire::Secret,
};

impl From<SlotKind> for SlotKindName {
    fn from(kind: SlotKind) -> Self {
        match kind {
            SlotKind::Password => Self::Password,
            SlotKind::RecoveryKey => Self::RecoveryKey,
            SlotKind::X25519 => Self::PublicKey,
            SlotKind::XWing => Self::PostQuantumKey,
            SlotKind::Rsa => Self::RsaCertificate,
            SlotKind::EcP256 => Self::EcP256,
            SlotKind::EcP384 => Self::EcP384,
            SlotKind::Fido2 => Self::SecurityKey,
        }
    }
}

impl From<StrengthName> for Strength {
    fn from(s: StrengthName) -> Self {
        match s {
            StrengthName::Standard => Self::Standard,
            StrengthName::Strong => Self::Strong,
        }
    }
}

/// The ways in an input asks a new `.bhive` to have.
#[derive(Debug, Clone, Copy, Default)]
pub struct WaysArgs<'a> {
    pub password: Option<&'a Secret>,
    pub recovery_key: bool,
    pub to: &'a [String],
    pub to_cert: &'a [String],
    pub this_pc: bool,
    pub this_pc_pin: Option<&'a Secret>,
    pub security_key: bool,
    pub windows_hello: bool,
    pub strength: Option<StrengthName>,
    /// The archive keeps other ways in (`archive.protect`), which may leave this PC.
    pub kept: bool,
}

impl WaysArgs<'_> {
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.bhive_only().is_none()
    }

    /// The first option given that only a `.bhive` takes: zip and 7z take a password too.
    pub fn bhive_only(&self) -> Option<&'static str> {
        [
            (self.recovery_key, "recovery_key"),
            (!self.to.is_empty(), "to"),
            (!self.to_cert.is_empty(), "to_cert"),
            (self.this_pc, "this_pc"),
            (self.this_pc_pin.is_some(), "this_pc_pin"),
            (self.security_key, "security_key"),
            (self.windows_hello, "windows_hello"),
            (self.strength.is_some(), "strength"),
        ]
        .into_iter()
        .find_map(|(set, name)| set.then_some(name))
    }
}

/// A way in that needs a device: made last, once everything else has been checked.
#[derive(Debug, Clone)]
pub enum Device {
    /// A new This PC key in the TPM, with its PIN.
    ThisPc(Option<Secret>),
    /// A security key, or with `hello` Windows Hello: a new credential, or the one a slot
    /// already has ("New key").
    Fido2 {
        hello: bool,
        credential: Option<Vec<u8>>,
        label: Option<String>,
    },
}

impl Device {
    /// Whether its way in works only on this PC (decision 11).
    pub fn machine_bound(&self) -> bool {
        matches!(self, Self::ThisPc(_) | Self::Fido2 { hello: true, .. })
    }
}

/// The slots to make, the devices still to ask, and the recovery key that was made for one of
/// them, to show once.
#[derive(Debug, Default)]
pub struct Ways {
    pub recipients: Vec<Labelled>,
    pub recovery_key: Option<Secret>,
    pub devices: Vec<Device>,
    /// The archive keeps a way in that works elsewhere (`archive.protect`), so these may all
    /// be bound to this PC.
    pub kept: bool,
}

impl Ways {
    /// Refuses ways in that would all be bound to this PC, before any device is asked.
    pub fn check(&self) -> Result<(), CmdError> {
        if self.kept {
            return Ok(());
        }
        leaves_the_machine(&self.recipients, &self.devices)
    }

    /// Asks the devices, last: the security keys and Windows Hello first, since a person may
    /// cancel them, then the TPM. Their ways in join the others; the rule of decision 11 is
    /// checked again on what the devices made.
    pub fn make_devices(&mut self, cx: &mut JobCtx) -> Result<(), CmdError> {
        let mut devices = std::mem::take(&mut self.devices);
        devices.sort_by_key(|d| matches!(d, Device::ThisPc(_)));
        for device in devices {
            let option = match &device {
                Device::ThisPc(_) => "this_pc",
                Device::Fido2 { hello: true, .. } => "windows_hello",
                Device::Fido2 { .. } => "security_key",
            };
            attended(cx, option, NO_DEVICES)?;
            if let Device::Fido2 { hello, .. } = &device {
                fido2_supported(*hello)?;
            }
            self.recipients.push(match device {
                Device::ThisPc(pin) => this_pc(pin.as_ref(), cx)?,
                Device::Fido2 {
                    hello,
                    credential,
                    label,
                } => {
                    let mut l = security_key(hello, credential.as_deref())?;
                    if label.is_some() {
                        l.label = label;
                    }
                    l
                }
            });
        }
        self.check()
    }
}

/// Refuses `option` when nobody is there to see what it does (MCP).
fn attended(cx: &JobCtx, option: &str, why: &str) -> Result<(), CmdError> {
    if cx.policy().unattended {
        return Err(CmdError::new(
            ErrorCode::UnsupportedOperation,
            format!("`{option}` isn't offered here: {why} (docs/MCP.md)"),
        ));
    }
    Ok(())
}

const NO_DEVICES: &str = "nobody is there to touch a device or type its PIN";

/// Refuses a security key, or with `hello` Windows Hello, that this machine can't ask for the
/// secret a slot needs (hmac-secret), before Windows shows anything.
fn fido2_supported(hello: bool) -> Result<(), CmdError> {
    let support = beezip_keys::webauthn::support();
    if (hello && support.hello) || (!hello && support.security_keys) {
        return Ok(());
    }
    let why = if !cfg!(windows) {
        "security keys and Windows Hello work through Windows' webauthn.dll; on this system use \
         a password, a recovery key or a key"
            .to_owned()
    } else if hello {
        "Windows Hello isn't set up on this PC, or this Windows can't use it for archives"
            .to_owned()
    } else {
        format!(
            "this Windows can't ask a security key for the secret an archive needs \
             (webauthn.dll's API version is {})",
            support.api_version
        )
    };
    Err(CmdError::new(ErrorCode::UnsupportedOperation, why))
}

/// Makes the recipients `args` asks for, and lists the devices it needs without asking them:
/// the caller checks everything else first, then calls [`Ways::make_devices`], so a key string
/// that doesn't parse or an output in the way leaves no TPM key behind and asks for no touch.
pub fn ways(args: &WaysArgs<'_>, cx: &mut JobCtx) -> Result<Ways, CmdError> {
    if args.strength.is_some() && args.password.is_none() {
        return Err(CmdError::invalid_args(
            "`strength` is for a password; pass `password` too",
        ));
    }
    if args.this_pc_pin.is_some() && !args.this_pc {
        return Err(CmdError::invalid_args(
            "`this_pc_pin` is the PIN of the This PC key; pass `this_pc` too",
        ));
    }
    if args.recovery_key {
        attended(
            cx,
            "recovery_key",
            "a new recovery key would pass through the model's context; make one in the app or \
             the CLI",
        )?;
    }
    if args.this_pc {
        attended(cx, "this_pc", NO_DEVICES)?;
    }
    if args.security_key {
        attended(cx, "security_key", NO_DEVICES)?;
    }
    if args.windows_hello {
        attended(cx, "windows_hello", NO_DEVICES)?;
    }
    // Decision 11: a way in that never leaves this PC needs one that does.
    let leaves = args.kept
        || args.password.is_some()
        || args.recovery_key
        || !args.to.is_empty()
        || !args.to_cert.is_empty()
        || args.security_key;
    if (args.this_pc || args.windows_hello) && !leaves {
        let what = if args.this_pc {
            "This PC can't be the only way in: its key never leaves this PC"
        } else {
            "Windows Hello can't be the only way in: it works only on this PC"
        };
        return Err(CmdError::invalid_args(format!(
            "{what}, so the archive would be lost with it. Add a password, a recovery key or \
             someone's key too."
        )));
    }

    let mut out = Ways {
        kept: args.kept,
        ..Ways::default()
    };
    if let Some(password) = args.password {
        if password.expose().is_empty() {
            return Err(CmdError::invalid_args("the password is empty"));
        }
        out.recipients.push(Labelled {
            recipient: Recipient::Password {
                password: Zeroizing::new(password.expose().to_owned()),
                strength: args.strength.unwrap_or_default().into(),
            },
            label: Some("Password".into()),
        });
    }
    if args.recovery_key {
        let key = recovery::generate()?;
        out.recovery_key = Some(Secret::new(recovery::format(&key).as_str()));
        out.recipients.push(Labelled {
            recipient: Recipient::RecoveryKey(key),
            label: Some("Recovery key".into()),
        });
    }
    let others = !args.to.is_empty() || !args.to_cert.is_empty();
    for text in args.to {
        out.recipients.push(public_key(text, cx)?);
    }
    for text in args.to_cert {
        let c = certificate(text)?;
        if c.not_after < now() {
            cx.log(
                LogLevel::Warn,
                format!(
                    "{}'s certificate has expired; it can still open the archive",
                    c.subject
                ),
            );
        }
        out.recipients.push(certificate_recipient(c)?);
    }
    // "New key" checks this on every way in it keeps (`kept`).
    if args.password.is_some() && others && !args.kept {
        warn_password_beside_keys(cx);
    }
    if args.this_pc {
        out.devices.push(Device::ThisPc(args.this_pc_pin.cloned()));
    }
    if args.security_key {
        out.devices.push(Device::Fido2 {
            hello: false,
            credential: None,
            label: None,
        });
    }
    if args.windows_hello {
        out.devices.push(Device::Fido2 {
            hello: true,
            credential: None,
            label: None,
        });
    }
    Ok(out)
}

/// Decision 12: a password beside other people's keys.
pub fn warn_password_beside_keys(cx: &JobCtx) {
    cx.log(
        LogLevel::Warn,
        "anyone who can open this archive with their key could also make an archive that your \
         password opens; sign it to show that it's yours",
    );
}

/// Seconds since 1970, now.
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// An `age1…` or `age1pq1…` key, or a contact's (or your own key's) name: a contact's
/// certificate is encrypted to as `to_cert` would be, with a warning when it has expired.
pub fn public_key(text: &str, cx: &JobCtx) -> Result<Labelled, CmdError> {
    let text = text.trim();
    if text.to_ascii_lowercase().starts_with("age1") {
        return Ok(Labelled {
            recipient: key_recipient(bech32::parse_key(text)?, text)?,
            label: None,
        });
    }
    let entry = cx
        .key_store()?
        .list()?
        .into_iter()
        .find(|k| {
            k.name == text
                && matches!(
                    k.kind,
                    KeyKind::X25519 | KeyKind::XWing | KeyKind::Certificate
                )
        })
        .ok_or_else(|| {
            CmdError::new(
                ErrorCode::NotFound,
                format!(
                    "`{text}` is neither an `age1…` key nor the name of a key or contact \
                     (`keys.list` shows them)"
                ),
            )
        })?;
    if entry.kind == KeyKind::Certificate {
        let c = entry.certificate.ok_or_else(|| {
            CmdError::new(
                ErrorCode::Corrupt,
                format!("the contact `{}`'s certificate is damaged", entry.name),
            )
        })?;
        let recipient = c.recipient(false).map_err(|why| {
            CmdError::invalid_args(format!(
                "an archive can't be encrypted to {}'s certificate: {why}",
                entry.name
            ))
        })?;
        if c.not_after < now() {
            cx.log(
                LogLevel::Warn,
                format!(
                    "{}'s certificate has expired; it can still open the archive",
                    entry.name
                ),
            );
        }
        return Ok(Labelled {
            recipient,
            label: Some(entry.name),
        });
    }
    Ok(Labelled {
        recipient: key_recipient(bech32::parse_key(&entry.public)?, text)?,
        label: Some(entry.name),
    })
}

fn key_recipient(key: KeyText, text: &str) -> Result<Recipient, CmdError> {
    match key {
        KeyText::X25519Public(k) => Ok(Recipient::X25519(k)),
        KeyText::XWingPublic(k) => Ok(Recipient::XWing(k)),
        KeyText::X25519Secret(_) | KeyText::XWingSecret(_) | KeyText::SigningSecret(_) => {
            Err(CmdError::invalid_args(
                "that's a private key: pass its public key (`age1…`), and keep the private key \
                 to yourself",
            ))
        }
        KeyText::SigningPublic(_) => Err(CmdError::invalid_args(format!(
            "`{}…` is a signing key: it signs archives, it can't open them",
            text.get(..12).unwrap_or(text)
        ))),
    }
}

/// A SHA-1 thumbprint as Windows shows it: 40 hex digits, with any spaces or colons.
pub fn thumbprint(text: &str) -> Option<[u8; 20]> {
    let hex: String = text.chars().filter(|c| !matches!(c, ' ' | ':')).collect();
    if hex.len() != 40 || Path::new(text).exists() {
        return None;
    }
    let mut out = [0; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A certificate by its thumbprint in your stores (Windows), or from a file.
pub fn certificate(text: &str) -> Result<Certificate, CmdError> {
    if let Some(t) = thumbprint(text) {
        return store_certificate(&t);
    }
    Ok(beezip_keys::files::certificate(Path::new(text))?)
}

#[cfg(windows)]
fn store_certificate(thumbprint: &[u8; 20]) -> Result<Certificate, CmdError> {
    beezip_keys::cng::certificates()?
        .into_iter()
        .map(|c| c.certificate)
        .find(|c| c.thumbprint == *thumbprint)
        .ok_or_else(|| {
            CmdError::new(
                ErrorCode::NotFound,
                "no certificate with that thumbprint is in Personal or Other People \
                 (`certificates.list` shows them)",
            )
        })
}

/// The Keychain's certificates, as `certificates.list` lists them on macOS.
#[cfg(target_os = "macos")]
fn store_certificate(thumbprint: &[u8; 20]) -> Result<Certificate, CmdError> {
    beezip_keys::mac::certificates()?
        .into_iter()
        .map(|c| c.certificate)
        .find(|c| c.thumbprint == *thumbprint)
        .ok_or_else(|| {
            CmdError::new(
                ErrorCode::NotFound,
                "no certificate with that thumbprint is in the Keychain (`certificates.list` \
                 shows them)",
            )
        })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn store_certificate(_: &[u8; 20]) -> Result<Certificate, CmdError> {
    Err(CmdError::invalid_args(
        "a thumbprint names a certificate in Windows' stores or the macOS Keychain; pass a \
         certificate file",
    ))
}

/// The slot a certificate makes, or why it can't make one.
pub fn certificate_recipient(c: Certificate) -> Result<Labelled, CmdError> {
    let kind = c.slot_kind().map_err(|why| {
        CmdError::invalid_args(format!(
            "an archive can't be encrypted to {}: {why}",
            c.subject
        ))
    })?;
    let recipient = match kind {
        SlotKind::Rsa => Recipient::Rsa {
            spki: c.spki.clone(),
            certificate: Some(c.der.clone()),
        },
        SlotKind::EcP256 | SlotKind::EcP384 => Recipient::Ec {
            curve: if kind == SlotKind::EcP256 {
                Curve::P256
            } else {
                Curve::P384
            },
            spki: c.spki.clone(),
            certificate: Some(c.der.clone()),
            machine_bound: false,
        },
        other => {
            return Err(CmdError::internal(format!(
                "a certificate made a slot of kind {other:?}"
            )));
        }
    };
    Ok(Labelled {
        recipient,
        label: Some(c.subject),
    })
}

/// A new This PC key, which the job deletes again if it then fails (`JobCtx::made_this_pc`).
#[cfg(windows)]
fn this_pc(pin: Option<&Secret>, cx: &mut JobCtx) -> Result<Labelled, CmdError> {
    let (name, spki) = beezip_keys::cng::create_this_pc(pin.map(Secret::expose))?;
    cx.made_this_pc(name);
    Ok(Labelled {
        recipient: Recipient::Ec {
            curve: Curve::P256,
            spki,
            certificate: None,
            machine_bound: true,
        },
        label: Some("This PC".into()),
    })
}

#[cfg(not(windows))]
fn this_pc(_: Option<&Secret>, _: &mut JobCtx) -> Result<Labelled, CmdError> {
    Err(CmdError::new(
        ErrorCode::UnsupportedOperation,
        "This PC keys are in Windows' TPM; on this system use a password, a recovery key or a \
         key",
    ))
}

/// A security key, or with `hello` Windows Hello: Windows asks for a touch, a PIN or a face.
/// `credential` rebuilds the slot of one already registered ("New key").
#[cfg(windows)]
fn security_key(hello: bool, credential: Option<&[u8]>) -> Result<Labelled, CmdError> {
    let recipient = beezip_keys::webauthn::recipient(hello, credential, None)?;
    Ok(Labelled {
        recipient,
        label: Some(
            if hello {
                "Windows Hello"
            } else {
                "Security key"
            }
            .into(),
        ),
    })
}

#[cfg(not(windows))]
fn security_key(_: bool, _: Option<&[u8]>) -> Result<Labelled, CmdError> {
    Err(CmdError::new(
        ErrorCode::UnsupportedOperation,
        "security keys work through Windows' webauthn.dll; on this system use a password, a \
         recovery key or a key",
    ))
}

/// Whom `sign` names: your signing key by name, a certificate's thumbprint in your stores, a
/// certificate file with its key beside it (`name.key`, or in the same PEM file), or a `.pfx`
/// (opened in memory, on Windows). A key file under a password asks for it.
pub fn signing(names: &[String], cx: &mut JobCtx) -> Result<Option<Signing>, CmdError> {
    if names.is_empty() {
        return Ok(None);
    }
    attended(
        cx,
        "sign",
        "a signature says that you made the archive, so BeeZip signs only when you ask it to \
         yourself",
    )?;
    let mut signers = Vec::with_capacity(names.len());
    for name in names {
        signers.push(signer(name.trim(), cx)?);
    }
    let signing = Signing {
        signers,
        time: None,
    };
    sign::ready(&signing)?;
    Ok(Some(signing))
}

fn signer(text: &str, cx: &mut JobCtx) -> Result<Arc<dyn sign::Signer>, CmdError> {
    if let Some(t) = thumbprint(text) {
        return store_signer(&t);
    }
    let path = Path::new(text);
    if path.is_file() {
        let bytes = std::fs::read(path)
            .map_err(|e| beezip_core::Error::io(format!("reading {}", path.display()), &e))?;
        // A .pfx holds its key, opened in memory (Windows); its password is asked for.
        if beezip_keys::pfx::is_pfx(&bytes) {
            return cx.with_file_password(path, |password| {
                beezip_keys::pfx::signer(&bytes, password).map_err(|e| {
                    beezip_core::Error::new(e.kind, format!("{}: {}", path.display(), e.message))
                })
            });
        }
        let key = key_beside(path);
        return cx.with_file_password(&key, |password| {
            beezip_keys::files::signer(path, &key, password)
        });
    }
    Ok(beezip_keys::identity::signing::signer(
        &cx.key_store()?,
        text,
    )?)
}

/// The private key of a certificate file: `name.key` beside it, else the file itself (a PEM
/// with both).
fn key_beside(certificate: &Path) -> PathBuf {
    let key = certificate.with_extension("key");
    if key.is_file() {
        key
    } else {
        certificate.to_path_buf()
    }
}

#[cfg(windows)]
fn store_signer(thumbprint: &[u8; 20]) -> Result<Arc<dyn sign::Signer>, CmdError> {
    Ok(beezip_keys::cng::signer(thumbprint)?)
}

/// A Keychain identity, which may show the Keychain's prompt when it signs.
#[cfg(target_os = "macos")]
fn store_signer(thumbprint: &[u8; 20]) -> Result<Arc<dyn sign::Signer>, CmdError> {
    Ok(beezip_keys::mac::signer(thumbprint)?)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn store_signer(_: &[u8; 20]) -> Result<Arc<dyn sign::Signer>, CmdError> {
    Err(CmdError::invalid_args(
        "a thumbprint names a certificate in Windows' stores or the macOS Keychain; pass a \
         certificate file and its key",
    ))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
    out
}

/// A signer's fingerprint (docs/bhive.md §13.5), for people to compare; never matched on.
pub fn fingerprint(signer: &[u8]) -> String {
    sign::fingerprint(signer)
}

/// A `uvarint` (docs/bhive.md §2) from the front of `data`.
fn uvarint(data: &mut &[u8]) -> Option<u64> {
    let mut value: u64 = 0;
    for shift in (0..64).step_by(7) {
        let (&b, rest) = data.split_first()?;
        *data = rest;
        value |= u64::from(b & 0x7F).checked_shl(shift)?;
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The certificates of a certificate signer (docs/bhive.md §13.4), the signer's own first.
pub fn signer_certificates(signer: &[u8]) -> Option<Vec<&[u8]>> {
    let mut rest = signer;
    let count = uvarint(&mut rest)?;
    if !(1..=sign::MAX_CERTIFICATES as u64).contains(&count) {
        return None;
    }
    let mut out = Vec::new();
    for _ in 0..count {
        let len = usize::try_from(uvarint(&mut rest)?).ok()?;
        let (der, tail) = (rest.get(..len)?, rest.get(len..)?);
        out.push(der);
        rest = tail;
    }
    rest.is_empty().then_some(out)
}

/// A signer `require_signer` asks for: the SHA-256 of a signing key's bytes, or of the
/// signer's own certificate, the first in its signer bytes, whatever chain follows it (the
/// chain a signer includes may change; docs/bhive.md §13.5). Whole hashes, never fingerprints
/// (docs/M14.md §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    Key([u8; 32]),
    Certificate([u8; 32]),
}

impl Wanted {
    pub fn matches(&self, signature: &SignatureInfo) -> bool {
        if signature.status != Status::Valid {
            return false;
        }
        match (self, Algorithm::from_id(signature.algorithm)) {
            (Self::Key(want), Some(Algorithm::MlDsa65Ed25519)) => {
                sign::signer_id(&signature.signer) == *want
            }
            (Self::Certificate(want), Some(a)) if a != Algorithm::MlDsa65Ed25519 => {
                signer_certificates(&signature.signer)
                    .and_then(|c| c.first().map(|leaf| sha256(leaf) == *want))
                    .unwrap_or(false)
            }
            _ => false,
        }
    }
}

/// What each `require_signer` value names: a `bzsig1…` key, a certificate file, or a contact's
/// (or your own) signing key by name.
pub fn wanted(list: &[String], cx: &JobCtx) -> Result<Vec<(String, Wanted)>, CmdError> {
    list.iter()
        .map(|text| {
            let text = text.trim();
            Ok((text.to_owned(), wanted_one(text, cx)?))
        })
        .collect()
}

fn wanted_one(text: &str, cx: &JobCtx) -> Result<Wanted, CmdError> {
    let signing_key = |key: KeyText| match key {
        KeyText::SigningPublic(k) => Ok(Wanted::Key(sha256(&k[..]))),
        _ => Err(CmdError::invalid_args(format!(
            "`{text}` isn't a signing key (`bzsig1…`)"
        ))),
    };
    if text.to_ascii_lowercase().starts_with("bzsig1") {
        return signing_key(bech32::parse_key(text)?);
    }
    if Path::new(text).is_file() {
        let c = beezip_keys::files::certificate(Path::new(text))?;
        return Ok(Wanted::Certificate(sha256(&c.der)));
    }
    let entry = cx
        .key_store()?
        .list()?
        .into_iter()
        .find(|k| k.name == text && matches!(k.kind, KeyKind::Signing | KeyKind::Certificate))
        .ok_or_else(|| {
            CmdError::new(
                ErrorCode::NotFound,
                format!(
                    "`{text}` is neither a `bzsig1…` key, a certificate file, nor the name of a \
                     signing key or contact (`keys.list` shows them)"
                ),
            )
        })?;
    if let Some(c) = &entry.certificate {
        return Ok(Wanted::Certificate(sha256(&c.der)));
    }
    signing_key(bech32::parse_key(&entry.public)?)
}

/// `Ok` when a valid signature is from each signer `wanted` names; `SignatureRequired`
/// otherwise. `report` is `None` for an archive that can't be signed (not a `.bhive`).
pub fn require(report: Option<&sign::Report>, wanted: &[(String, Wanted)]) -> Result<(), CmdError> {
    let signatures = report.map(|r| r.signatures.as_slice()).unwrap_or_default();
    for (name, want) in wanted {
        if signatures.iter().any(|s| want.matches(s)) {
            continue;
        }
        let why = if signatures.is_empty() {
            "the archive isn't signed".to_owned()
        } else if signatures.iter().any(|s| s.status == Status::Invalid) {
            "it changed after it was signed".to_owned()
        } else {
            format!("none of its {} signatures is from them", signatures.len())
        };
        return Err(CmdError::new(
            ErrorCode::SignatureRequired,
            format!("not signed by `{name}`: {why}"),
        )
        .with_details(serde_json::json!({ "signer": name })));
    }
    Ok(())
}

/// `archive.verify`'s rule, on the signatures as [`reports`] shows them: none may have failed,
/// and one must be valid. With `require_signer` given ([`require`] checked who), any valid one
/// does; without, one must be from someone you trust: yourself, a contact, or a certificate
/// the system trusts. `SignatureRequired` otherwise.
pub fn verified(signatures: &[SignatureReport], signers_given: bool) -> Result<(), CmdError> {
    let fail = |why: String| Err(CmdError::new(ErrorCode::SignatureRequired, why));
    if signatures.is_empty() {
        return fail("the archive isn't signed".into());
    }
    if let Some(changed) = signatures
        .iter()
        .find(|s| s.status == SignatureStatusName::Changed)
    {
        return fail(format!(
            "it changed after it was signed by {} [{}]",
            changed.signer, changed.fingerprint
        ));
    }
    let valid: Vec<&SignatureReport> = signatures
        .iter()
        .filter(|s| s.status == SignatureStatusName::Valid)
        .collect();
    let trusted = |s: &&SignatureReport| {
        matches!(
            s.trust,
            Some(TrustName::Yours | TrustName::Contact | TrustName::Trusted)
        )
    };
    match valid.first() {
        None => fail("none of its signatures could be checked".into()),
        Some(_) if signers_given || valid.iter().any(trusted) => Ok(()),
        Some(s) => fail(format!(
            "it is signed by {} [{}], whom BeeZip doesn't know: add them as a contact, or pass \
             `require_signer` with their key or certificate",
            s.signer, s.fingerprint
        )),
    }
}

/// Warns of each signature that failed: the archive changed after it was signed (decision 26).
/// It still opens; `require_signer` is what refuses it.
pub fn warn_changed(reader: &mut dyn ArchiveReader, cx: &JobCtx) {
    let Some(report) = signatures_of(reader) else {
        return;
    };
    if !report
        .signatures
        .iter()
        .any(|s| s.status == Status::Invalid)
    {
        return;
    }
    for s in reports(report, cx) {
        if s.status == SignatureStatusName::Changed {
            cx.log(
                LogLevel::Warn,
                format!(
                    "this archive CHANGED after it was signed by {} [{}]",
                    s.signer, s.fingerprint
                ),
            );
        }
    }
}

/// The signatures of an open archive, when it is a `.bhive`.
pub fn signatures_of(reader: &mut dyn ArchiveReader) -> Option<&sign::Report> {
    reader
        .as_any_mut()
        .downcast_mut::<BhiveReader>()
        .map(|r| r.signatures())
}

/// How many signatures the `.bhive` file at `path` has, read before a change that drops them
/// (an edit of its contents, a conversion), so BeeZip can say so first (docs/M14.md §11).
/// `None` when it isn't a `.bhive`, or is encrypted: its index can't be read without opening
/// it, which would ask for its key a second time.
pub fn signatures_before_change(path: &Path, cx: &mut JobCtx) -> Option<usize> {
    let mut header = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut header))
        .ok()?;
    let features = layout::check_header(&header).ok()?;
    if features & layout::FEATURE_ENCRYPTED != 0 {
        return None;
    }
    let opts = open_options(None, cx);
    let mut opened = open(path, &opts, cx).ok()?;
    signatures_of(&mut *opened.reader).map(|r| r.signatures.len())
}

/// Warns, before a change, that the archive's signatures won't survive it.
pub fn warn_signatures_dropped(path: &Path, why: &str, cx: &mut JobCtx) {
    if let Some(n) = signatures_before_change(path, cx).filter(|&n| n > 0) {
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let them = if n == 1 {
            "its signature".to_owned()
        } else {
            format!("its {n} signatures")
        };
        cx.log(
            LogLevel::Warn,
            format!("{name} is signed, and {them} {why}"),
        );
    }
}

/// How BeeZip shows each signature: checked by core, its signer named through your keys,
/// contacts and the system's trust (`beezip-keys`).
pub fn reports(report: &sign::Report, cx: &JobCtx) -> Vec<SignatureReport> {
    let store = cx.key_store();
    report
        .signatures
        .iter()
        .map(|s| signature_report(s, store.as_ref()))
        .collect()
}

/// How BeeZip shows a signature. Without your keys' store (`Err`), nobody is trusted.
fn signature_report(s: &SignatureInfo, store: Result<&Store, &CmdError>) -> SignatureReport {
    let algorithm = Algorithm::from_id(s.algorithm);
    let fingerprint = fingerprint(&s.signer);
    let leaf = signer_certificates(&s.signer)
        .and_then(|c| c.first().and_then(|der| cert::parse(der).ok()));
    let (status, mut note) = match &s.status {
        Status::Valid => (SignatureStatusName::Valid, None),
        Status::Invalid => (
            SignatureStatusName::Changed,
            Some("the archive changed after it was signed".to_owned()),
        ),
        Status::UnknownAlgorithm(id) => (
            SignatureStatusName::UnknownAlgorithm,
            Some(format!("algorithm {id} is unknown to this BeeZip")),
        ),
        Status::NotChecked(why) => (SignatureStatusName::NotChecked, Some(why.clone())),
    };
    let public = match algorithm {
        Some(Algorithm::MlDsa65Ed25519) => <[u8; 1984]>::try_from(&s.signer[..])
            .ok()
            .map(|k| bech32::key_text(&KeyText::SigningPublic(Box::new(k)))),
        _ => signer_certificates(&s.signer).and_then(|c| c.first().map(|der| pem(der))),
    };
    let mut signer = leaf
        .as_ref()
        .map_or_else(|| fingerprint.clone(), |c| c.subject.clone());
    let trust = (status == SignatureStatusName::Valid).then(|| {
        match store
            .map_err(Clone::clone)
            .and_then(|store| Ok(beezip_keys::trust::trust(store, s)?))
        {
            Ok(t) => {
                use beezip_keys::trust::Trust as T;
                let (name, trust) = match t {
                    T::Yours(n) => (n, TrustName::Yours),
                    T::Contact(n) => (n, TrustName::Contact),
                    T::Certificate { subject } => (subject, TrustName::Trusted),
                    T::Expired { subject } => (subject, TrustName::Expired),
                    T::Revoked { subject } => (subject, TrustName::Revoked),
                    T::Unknown { who } => (who, TrustName::Unknown),
                };
                signer = name;
                trust
            }
            Err(e) => {
                note = Some(format!("couldn't tell who signed it: {}", e.message));
                TrustName::Unknown
            }
        }
    });
    SignatureReport {
        algorithm: match algorithm {
            Some(Algorithm::MlDsa65Ed25519) => SignatureAlgorithmName::MlDsa65Ed25519,
            Some(Algorithm::RsaPss) => SignatureAlgorithmName::RsaPss,
            Some(Algorithm::RsaPkcs1) => SignatureAlgorithmName::RsaPkcs1,
            Some(Algorithm::EcdsaP256) => SignatureAlgorithmName::EcdsaP256,
            Some(Algorithm::EcdsaP384) => SignatureAlgorithmName::EcdsaP384,
            None => SignatureAlgorithmName::Unknown,
        },
        status,
        trust,
        signer,
        fingerprint,
        public,
        issuer: leaf.map(|c| c.issuer),
        claimed_time: s.time,
        post_quantum: algorithm.is_some_and(Algorithm::post_quantum),
        note,
    }
}

/// A certificate in PEM.
fn pem(der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in text.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// The signature each signer will make, as `archive.sign` reports it once written.
pub fn signed_reports(signing: &Signing, cx: &JobCtx) -> Vec<SignatureReport> {
    let store = cx.key_store();
    let time = signing.time.unwrap_or_else(now);
    signing
        .signers
        .iter()
        .map(|s| {
            signature_report(
                &SignatureInfo {
                    algorithm: s.algorithm().id(),
                    signer: s.signer_bytes(),
                    time: Some(time),
                    status: Status::Valid,
                },
                store.as_ref(),
            )
        })
        .collect()
}

/// What section 5 says of one slot (docs/bhive.md §12.9): claims anyone who has held the file
/// key could have written, shown as such and never used to open the archive.
pub use beezip_core::format::bhive::crypt::Description;

/// One slot of an encrypted `.bhive`'s key block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub index: u32,
    pub kind: SlotKind,
    /// Its public part, from which a security key's credential id is read.
    pub public: Vec<u8>,
    pub description: Description,
}

/// The slots of the `.bhive` at `path` from its key block, in order, with what the open
/// archive's section 5 says of each; `None` when it isn't encrypted. Slots of a kind this
/// BeeZip doesn't know are left out.
pub fn slots(path: &Path, reader: Option<&BhiveReader>) -> Result<Option<Vec<Slot>>, CmdError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| beezip_core::Error::io(format!("opening {}", path.display()), &e))?;
    let mut header = [0u8; 16];
    // A .bhive read through a codec (`a.bhive.zst`) has no key block at the file's start.
    if file.read_exact(&mut header).is_err() {
        return Ok(None);
    }
    let Ok(features) = layout::check_header(&header) else {
        return Ok(None);
    };
    if features & layout::FEATURE_ENCRYPTED == 0 {
        return Ok(None);
    }
    let block = KeyBlock::read(&header, &mut file)?;
    let described = reader.map(descriptions).unwrap_or_default();
    let mut out = Vec::new();
    for (i, (kind, range)) in block.slots.iter().enumerate() {
        let Some(kind) = *kind else { continue };
        let bytes = block.bytes.get(range.clone()).unwrap_or_default();
        // The head (4 bytes), the public part, then the commitment and the wrapped key.
        let public = bytes
            .get(4..bytes.len().saturating_sub(SLOT_TAIL_LEN))
            .unwrap_or_default()
            .to_vec();
        out.push(Slot {
            index: i as u32,
            kind,
            public,
            description: described.get(i).cloned().unwrap_or_default(),
        });
    }
    Ok(Some(out))
}

/// Section 5 of an open archive, one description per slot; none when it has no section 5.
fn descriptions(reader: &BhiveReader) -> Vec<Description> {
    reader
        .unlocked()
        .and_then(|u| u.descriptions())
        .unwrap_or_default()
}

/// A way in as `archive.protection` lists it.
pub fn way_in(slot: &Slot) -> WayIn {
    let d = &slot.description;
    let recipient = match slot.kind {
        SlotKind::X25519 => d
            .public_key
            .as_deref()
            .and_then(|k| k.try_into().ok())
            .map(|k| bech32::key_text(&KeyText::X25519Public(k))),
        SlotKind::XWing => d
            .public_key
            .as_deref()
            .and_then(|k| <[u8; 1216]>::try_from(k).ok())
            .map(|k| bech32::key_text(&KeyText::XWingPublic(Box::new(k)))),
        SlotKind::Rsa | SlotKind::EcP256 | SlotKind::EcP384 => d
            .certificate
            .as_deref()
            .and_then(|der| cert::parse(der).ok())
            .map(|c| c.subject),
        _ => None,
    }
    .filter(|t| !t.is_empty());
    let fingerprint = match slot.kind {
        SlotKind::X25519 | SlotKind::XWing => d.public_key.as_deref(),
        SlotKind::Rsa | SlotKind::EcP256 | SlotKind::EcP384 => d.certificate.as_deref(),
        _ => None,
    }
    .map(bech32::fingerprint);
    WayIn {
        slot: slot.index,
        kind: slot.kind.into(),
        label: d.label.clone(),
        recipient,
        fingerprint,
        machine_bound: d.machine_bound,
        post_quantum: slot.kind.post_quantum(),
    }
}

/// Whether every way in resists a quantum computer.
pub fn post_quantum(ways: &[WayIn]) -> bool {
    !ways.is_empty() && ways.iter().all(|w| w.post_quantum)
}

/// A security key slot's credential id (docs/bhive.md §12.5, kind 8): flags, a reserved byte,
/// the id's length and the id.
pub fn credential_id(public: &[u8]) -> Option<&[u8]> {
    let len = usize::from(u16::from_le_bytes([*public.get(2)?, *public.get(3)?]));
    public.get(4..4 + len)
}

/// The recipient "New key" rebuilds a slot for from its description: a public key, or a
/// certificate or key's SubjectPublicKeyInfo. `None` for the kinds that need a person.
pub fn described_recipient(slot: &Slot) -> Result<Option<Recipient>, CmdError> {
    let d = &slot.description;
    let missing = || {
        CmdError::new(
            ErrorCode::UnsupportedOperation,
            format!(
                "slot {} doesn't say whose it is, so a new key can't rebuild it; remove it, or \
                 keep the key the archive has",
                slot.index
            ),
        )
    };
    Ok(Some(match slot.kind {
        SlotKind::X25519 => Recipient::X25519(
            d.public_key
                .as_deref()
                .and_then(|k| k.try_into().ok())
                .ok_or_else(missing)?,
        ),
        SlotKind::XWing => Recipient::XWing(Box::new(
            d.public_key
                .as_deref()
                .and_then(|k| <[u8; 1216]>::try_from(k).ok())
                .ok_or_else(missing)?,
        )),
        SlotKind::Rsa | SlotKind::EcP256 | SlotKind::EcP384 => {
            let bytes = d.certificate.clone().ok_or_else(missing)?;
            let (spki, certificate) = match cert::parse(&bytes) {
                Ok(c) => (c.spki, Some(bytes)),
                Err(_) => (bytes, None),
            };
            match (slot.kind, cert::spki_algorithm(&spki)?) {
                (SlotKind::Rsa, KeyAlgorithm::Rsa { .. }) => Recipient::Rsa { spki, certificate },
                (SlotKind::EcP256, KeyAlgorithm::Ec(Curve::P256)) => Recipient::Ec {
                    curve: Curve::P256,
                    spki,
                    certificate,
                    machine_bound: d.machine_bound,
                },
                (SlotKind::EcP384, KeyAlgorithm::Ec(Curve::P384)) => Recipient::Ec {
                    curve: Curve::P384,
                    spki,
                    certificate,
                    machine_bound: d.machine_bound,
                },
                _ => {
                    return Err(CmdError::new(
                        ErrorCode::Corrupt,
                        format!(
                            "slot {}'s description is of another kind of key",
                            slot.index
                        ),
                    ));
                }
            }
        }
        SlotKind::Password | SlotKind::RecoveryKey | SlotKind::Fido2 => return Ok(None),
    }))
}

/// Whether "New key" may rebuild `slot` without asking (docs/bhive.md §12.9): the key its
/// description names is one of your keys or contacts, or, for a slot bound to one machine, a
/// This PC key this PC has (`this_pc`, their SubjectPublicKeyInfos). A description is a claim
/// anyone who held the file key could have written, so it counts only where it names a key
/// you have; any other is confirmed by the user.
pub fn known_recipient(slot: &Slot, store: Option<&Store>, this_pc: &[Vec<u8>]) -> bool {
    let d = &slot.description;
    if d.machine_bound {
        let Some(bytes) = d.certificate.as_deref() else {
            return false;
        };
        let spki = cert::parse(bytes).map_or_else(|_| bytes.to_vec(), |c| c.spki);
        return slot.kind == SlotKind::EcP256 && this_pc.contains(&spki);
    }
    let Some(store) = store else {
        return false;
    };
    if matches!(
        slot.kind,
        SlotKind::Rsa | SlotKind::EcP256 | SlotKind::EcP384
    ) {
        // A contact's certificate, compared whole; a key without one is confirmed.
        return d
            .certificate
            .as_deref()
            .is_some_and(|der| store.find_certificate(der).ok().flatten().is_some());
    }
    let Some(key) = d.public_key.as_deref() else {
        return false;
    };
    store.list().unwrap_or_default().iter().any(|k| {
        matches!(
            bech32::parse_key(&k.public),
            Ok(KeyText::X25519Public(p)) if p[..] == *key
        ) || matches!(
            bech32::parse_key(&k.public),
            Ok(KeyText::XWingPublic(p)) if p[..] == *key
        )
    })
}

/// The device a security key or Windows Hello slot is rebuilt with for a new file key: its own
/// credential, one touch, asked last. A slot whose salt is a PRF input (flag bit 0, bhive.md
/// §12.5) is Windows Hello's, as `beezip-keys` makes them.
pub fn security_key_device(slot: &Slot) -> Result<Device, CmdError> {
    let id = credential_id(&slot.public).ok_or_else(|| {
        CmdError::new(
            ErrorCode::Corrupt,
            format!("slot {} has no credential id", slot.index),
        )
    })?;
    Ok(Device::Fido2 {
        hello: slot.public.first().is_some_and(|flags| flags & 1 != 0),
        credential: Some(id.to_vec()),
        label: slot.description.label.clone(),
    })
}

/// A recovery key for a slot rebuilt for a new file key.
pub fn new_recovery_key(cx: &JobCtx) -> Result<(Labelled, Secret), CmdError> {
    attended(
        cx,
        "new_key",
        "a new recovery key would pass through the model's context",
    )?;
    let key = recovery::generate()?;
    let shown = Secret::new(recovery::format(&key).as_str());
    Ok((
        Labelled {
            recipient: Recipient::RecoveryKey(key),
            label: Some("Recovery key".into()),
        },
        shown,
    ))
}

/// A password slot made for `password`.
pub fn password_recipient(password: &str, strength: Strength, label: Option<String>) -> Labelled {
    Labelled {
        recipient: Recipient::Password {
            password: Zeroizing::new(password.to_owned()),
            strength,
        },
        label: label.or_else(|| Some("Password".into())),
    }
}

/// Writes the `.bhive` at `archive` again under the options `opts` gives once it is open
/// (protection, signing), every entry copied as it is stored (no decoding, no recompression,
/// docs/M14.md §3), then swaps it in. One change to an archive at a time, as for edits.
pub fn rewrite_bhive(
    archive: &Path,
    password: Option<&Secret>,
    cx: &mut JobCtx,
    opts: impl FnOnce(&Path, &mut BhiveReader, &mut JobCtx) -> Result<BhiveWriteOptions, CmdError>,
) -> Result<RewriteReport, CmdError> {
    let path = absolute(archive);
    let canonical = std::fs::canonicalize(&path).map_err(|e| {
        CmdError::from(beezip_core::Error::io(
            format!("opening {}", archive.display()),
            &e,
        ))
    })?;
    let _guard = cx.edit_lock(&canonical)?;
    let target = Target::check(&path)?;
    cx.set_password(password);
    let open_opts = open_options(None, cx);
    let mut opened = open(&target.path, &open_opts, cx)?;
    let (format, codecs) = opened.detection.require_archive()?;
    let name = archive.display();
    if format != FormatId::Bhive || !codecs.is_empty() {
        return Err(CmdError::invalid_args(format!(
            "{name} isn't a .bhive: only a .bhive can be encrypted or signed"
        )));
    }
    let reader = opened
        .reader
        .as_any_mut()
        .downcast_mut::<BhiveReader>()
        .ok_or_else(|| CmdError::internal("a .bhive opened with another reader"))?;
    if reader.recovered().is_some() {
        return Err(CmdError::new(
            ErrorCode::UnsupportedOperation,
            format!(
                "{name} is incomplete: it is listed from what is left of it. Extract that, and \
                 create the archive again."
            ),
        ));
    }
    let mut wopts = opts(&target.path, reader, cx)?;
    if let Some(level) = reader.level() {
        wopts.level = level;
    }
    let entries = opened.reader.entries(cx)?.to_vec();
    let items: Vec<Item> = entries
        .iter()
        .filter(|e| e.kind != EntryKind::Other)
        .map(|e| {
            Item::Keep(Keep {
                id: e.id,
                path: e.path.clone(),
            })
        })
        .collect();
    let partial = target.partial()?;
    let writer = file_writer(&WriteSpec::Bhive(wopts), partial.try_clone()?, &target.path)?;
    let report = rewrite(&mut *opened.reader, &items, writer, true, cx);
    drop(opened);
    let result = match report {
        Ok(r) => target.swap(partial, cx).map(|()| r),
        Err(e) => Err(e),
    };
    // The cache forgets the archive once it has changed, or once a change of it failed.
    if let Some(cache) = cx.cache() {
        cache.evict(&canonical);
    }
    Ok(result?)
}

/// The ways in a writer was given, as `archive.protect` reports them afterwards.
pub fn ways_of(recipients: &[Labelled]) -> Vec<WayIn> {
    recipients
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let r = &l.recipient;
            let subject = |c: &Option<Vec<u8>>| {
                c.as_deref()
                    .and_then(|der| cert::parse(der).ok())
                    .map(|c| c.subject)
            };
            let (recipient, machine_bound) = match r {
                Recipient::X25519(k) => (Some(bech32::key_text(&KeyText::X25519Public(*k))), false),
                Recipient::XWing(k) => (
                    Some(bech32::key_text(&KeyText::XWingPublic(k.clone()))),
                    false,
                ),
                Recipient::Rsa { certificate, .. } => (subject(certificate), false),
                Recipient::Ec {
                    certificate,
                    machine_bound,
                    ..
                } => (subject(certificate), *machine_bound),
                Recipient::Fido2 { machine_bound, .. } => (None, *machine_bound),
                Recipient::Password { .. } | Recipient::RecoveryKey(_) => (None, false),
            };
            let fingerprint = match r {
                Recipient::X25519(k) => Some(bech32::fingerprint(&k[..])),
                Recipient::XWing(k) => Some(bech32::fingerprint(&k[..])),
                Recipient::Rsa { spki, certificate }
                | Recipient::Ec {
                    spki, certificate, ..
                } => Some(bech32::fingerprint(certificate.as_deref().unwrap_or(spki))),
                _ => None,
            };
            WayIn {
                slot: i as u32,
                kind: r.kind().into(),
                label: l.label.clone(),
                recipient: recipient.filter(|t| !t.is_empty()),
                fingerprint,
                machine_bound,
                post_quantum: r.kind().post_quantum(),
            }
        })
        .collect()
}

/// Refuses ways in, made and still to make on `devices`, that are all bound to this PC
/// (docs/M14.md decision 11).
pub fn leaves_the_machine(recipients: &[Labelled], devices: &[Device]) -> Result<(), CmdError> {
    let bound = |l: &Labelled| {
        matches!(
            l.recipient,
            Recipient::Ec {
                machine_bound: true,
                ..
            } | Recipient::Fido2 {
                machine_bound: true,
                ..
            }
        )
    };
    if recipients.is_empty() && devices.is_empty() {
        return Err(CmdError::invalid_args(
            "that would leave the archive with no way in",
        ));
    }
    if recipients.iter().all(bound) && devices.iter().all(Device::machine_bound) {
        return Err(CmdError::invalid_args(
            "every way in left would work only on this PC, so the archive would be lost with \
             it. Keep or add a password, a recovery key or someone's key.",
        ));
    }
    Ok(())
}

/// An open archive's protection and signatures, as `archive.info` and `archive.test` report
/// them: `None` for an archive that isn't a `.bhive`, isn't encrypted, or isn't signed.
pub fn security(
    path: &Path,
    reader: &mut dyn ArchiveReader,
    cx: &JobCtx,
) -> Result<
    (
        Option<ArchiveProtectionOutput>,
        Option<Vec<SignatureReport>>,
    ),
    CmdError,
> {
    let Some(bhive) = reader.as_any_mut().downcast_mut::<BhiveReader>() else {
        return Ok((None, None));
    };
    let protection = slots(path, Some(bhive))?.map(|slots| {
        let ways: Vec<WayIn> = slots.iter().map(way_in).collect();
        ArchiveProtectionOutput {
            encrypted: true,
            post_quantum: post_quantum(&ways),
            ways,
        }
    });
    let signatures = Some(reports(bhive.signatures(), cx)).filter(|r| !r.is_empty());
    Ok((protection, signatures))
}

/// The human lines for an archive's protection: its ways in, with the writer's labels marked
/// as what they are.
pub fn protection_text(p: &ArchiveProtectionOutput) -> String {
    let mut s = format!(
        "\n  ways in: {}, {}",
        p.ways.len(),
        if p.post_quantum {
            "safe from quantum computers"
        } else {
            "not safe from quantum computers"
        }
    );
    for w in &p.ways {
        let kind = match w.kind {
            SlotKindName::Password => "password",
            SlotKindName::RecoveryKey => "recovery key",
            SlotKindName::PublicKey => "public key",
            SlotKindName::PostQuantumKey => "post-quantum key",
            SlotKindName::RsaCertificate => "RSA certificate",
            SlotKindName::EcP256 => "EC P-256 key",
            SlotKindName::EcP384 => "EC P-384 key",
            SlotKindName::SecurityKey => "security key",
        };
        s.push_str(&format!("\n    {}: {kind}", w.slot));
        if let Some(label) = &w.label {
            s.push_str(&format!(", \"{label}\""));
        }
        if let Some(r) = &w.recipient {
            let short: String = r.chars().take(40).collect();
            let more = if r.chars().count() > 40 { "…" } else { "" };
            s.push_str(&format!(", {short}{more}"));
        }
        if w.machine_bound {
            s.push_str(", this PC only");
        }
    }
    if p.ways
        .iter()
        .any(|w| w.label.is_some() || w.recipient.is_some())
    {
        s.push_str(
            "\n    (names and keys are what the archive says of itself: anyone who could open \
             it could have changed them)",
        );
    }
    s
}

/// The human lines for an archive's signatures.
pub fn signatures_text(signatures: &[SignatureReport]) -> String {
    let mut s = String::new();
    // Numbered from 1, as `archive.sign`'s `remove` takes them.
    for (n, r) in signatures.iter().enumerate() {
        let line = match (r.status, r.trust) {
            (SignatureStatusName::Valid, Some(TrustName::Yours)) => {
                format!("signed by you ({})", r.signer)
            }
            (SignatureStatusName::Valid, Some(TrustName::Contact | TrustName::Trusted)) => {
                format!("signed by {}", r.signer)
            }
            (SignatureStatusName::Valid, Some(TrustName::Expired)) => {
                format!("signed by {}, whose certificate has expired", r.signer)
            }
            (SignatureStatusName::Valid, Some(TrustName::Revoked)) => {
                format!("signed by {}, whose certificate was revoked", r.signer)
            }
            (SignatureStatusName::Valid, _) => {
                format!("signed by an unknown signer, {}", r.signer)
            }
            (SignatureStatusName::Changed, _) => {
                format!("CHANGED after it was signed by {}", r.signer)
            }
            (SignatureStatusName::UnknownAlgorithm | SignatureStatusName::NotChecked, _) => {
                format!("a signature that couldn't be checked, by {}", r.signer)
            }
        };
        s.push_str(&format!("\n  {}. {line} [{}]", n + 1, r.fingerprint));
        if let Some(note) = &r.note {
            s.push_str(&format!("\n    {note}"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn hex(s: &serde_json::Value) -> Vec<u8> {
        let s = s.as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// docs/bhive.md §13.6: the example signer's fingerprint.
    #[test]
    fn fingerprints_are_the_specifications() {
        let v = vectors();
        let ex = &v["signed_example"];
        let signer = [hex(&ex["ed25519_public"]), hex(&ex["mldsa_public"])].concat();
        assert_eq!(fingerprint(&signer), ex["fingerprint"].as_str().unwrap());
        assert_eq!(fingerprint(b""), fingerprint(b""));
        assert_eq!(fingerprint(b"").len(), 19);
    }

    fn signature(algorithm: u8, signer: Vec<u8>, status: Status) -> SignatureInfo {
        SignatureInfo {
            algorithm,
            signer,
            time: Some(1_767_225_600),
            status,
        }
    }

    fn certificates(ders: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![ders.len() as u8];
        for d in ders {
            out.push(d.len() as u8);
            out.extend_from_slice(d);
        }
        out
    }

    #[test]
    fn signers_match_whole_hashes_only() {
        let key = vec![7u8; 1984];
        let want = Wanted::Key(sha256(&key));
        assert!(want.matches(&signature(1, key.clone(), Status::Valid)));
        // Another key, an invalid signature, a certificate algorithm: no.
        let mut other = key.clone();
        other[1983] ^= 1;
        assert_eq!(fingerprint(&other).len(), 19);
        assert!(!want.matches(&signature(1, other, Status::Valid)));
        assert!(!want.matches(&signature(1, key.clone(), Status::Invalid)));
        assert!(!want.matches(&signature(4, key.clone(), Status::Valid)));

        // A certificate signer is matched by its own certificate, whatever chain follows it.
        let leaf: &[u8] = b"leaf certificate";
        let want = Wanted::Certificate(sha256(leaf));
        let chain = certificates(&[leaf, b"issuer"]);
        assert!(want.matches(&signature(4, chain.clone(), Status::Valid)));
        assert!(want.matches(&signature(2, certificates(&[leaf]), Status::Valid)));
        assert!(!want.matches(&signature(
            4,
            certificates(&[b"issuer", leaf]),
            Status::Valid
        )));
        assert!(!want.matches(&signature(1, chain, Status::Valid)));
        // A malformed signer field matches nothing.
        assert!(!want.matches(&signature(4, vec![1, 200], Status::Valid)));
        assert!(!want.matches(&signature(4, vec![0], Status::Valid)));
    }

    #[test]
    fn require_says_why() {
        let key = vec![1u8; 1984];
        let wanted = vec![("alice".to_owned(), Wanted::Key(sha256(&key)))];
        let e = require(None, &wanted).unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureRequired);
        assert!(e.message.contains("isn't signed"), "{}", e.message);
        let report = sign::Report {
            signatures: vec![signature(1, key.clone(), Status::Invalid)],
            digests: None,
        };
        let e = require(Some(&report), &wanted).unwrap_err();
        assert!(e.message.contains("changed after"), "{}", e.message);
        let report = sign::Report {
            signatures: vec![signature(1, vec![2; 1984], Status::Valid)],
            digests: None,
        };
        let e = require(Some(&report), &wanted).unwrap_err();
        assert!(e.message.contains("none of its 1"), "{}", e.message);
        let report = sign::Report {
            signatures: vec![
                signature(1, vec![2; 1984], Status::Valid),
                signature(1, key, Status::Valid),
            ],
            digests: None,
        };
        require(Some(&report), &wanted).unwrap();
        require(None, &[]).unwrap();
    }

    #[test]
    fn signature_reports() {
        let store = Store::new(std::env::temp_dir().join("beezip-no-such-store"));
        let r = signature_report(&signature(1, vec![3; 1984], Status::Valid), Ok(&store));
        assert_eq!(r.algorithm, SignatureAlgorithmName::MlDsa65Ed25519);
        assert_eq!(r.status, SignatureStatusName::Valid);
        assert!(r.post_quantum);
        assert!(r.trust.is_some());
        assert_eq!(r.fingerprint, fingerprint(&[3; 1984]));
        assert_eq!(r.claimed_time, Some(1_767_225_600));
        let r = signature_report(
            &signature(9, vec![], Status::UnknownAlgorithm(9)),
            Ok(&store),
        );
        assert_eq!(r.algorithm, SignatureAlgorithmName::Unknown);
        assert_eq!(r.status, SignatureStatusName::UnknownAlgorithm);
        assert_eq!(r.trust, None);
        assert!(!r.post_quantum);
        let r = signature_report(&signature(4, vec![], Status::Invalid), Ok(&store));
        assert_eq!(r.status, SignatureStatusName::Changed);
        assert_eq!(r.trust, None);
        let r = signature_report(
            &signature(1, vec![], Status::NotChecked("section 2 is short".into())),
            Ok(&store),
        );
        assert_eq!(r.status, SignatureStatusName::NotChecked);
        assert_eq!(r.note.as_deref(), Some("section 2 is short"));
    }

    #[test]
    fn thumbprints() {
        let t = thumbprint("0123456789abcdef0123 456789ABCDEF:01234567").unwrap();
        assert_eq!(t[0], 0x01);
        assert_eq!(t[19], 0x67);
        assert_eq!(thumbprint("0123"), None);
        assert_eq!(thumbprint(&"g".repeat(40)), None);
    }

    #[test]
    fn options_only_a_bhive_takes() {
        let pw = Secret::new("pw");
        let to = ["age1x".to_owned()];
        assert!(WaysArgs::default().is_empty());
        let a = WaysArgs {
            password: Some(&pw),
            ..WaysArgs::default()
        };
        assert!(!a.is_empty());
        assert_eq!(a.bhive_only(), None);
        let a = WaysArgs {
            to: &to,
            ..WaysArgs::default()
        };
        assert_eq!(a.bhive_only(), Some("to"));
    }

    #[test]
    fn kinds_and_ways() {
        for kind in SlotKind::ALL {
            let slot = Slot {
                index: 3,
                kind,
                public: Vec::new(),
                description: Description {
                    label: Some("Alice".into()),
                    ..Description::default()
                },
            };
            let w = way_in(&slot);
            assert_eq!(w.slot, 3);
            assert_eq!(w.label.as_deref(), Some("Alice"));
            assert_eq!(w.post_quantum, kind.post_quantum());
            assert_eq!(w.recipient, None);
        }
        assert!(!post_quantum(&[]));
        let public = [3u8, 0, 2, 0, 0xAA, 0xBB, 1, b'x'];
        assert_eq!(credential_id(&public), Some(&[0xAA, 0xBB][..]));
        assert_eq!(credential_id(&[0, 0, 9]), None);
    }

    fn slot(kind: SlotKind, description: Description) -> Slot {
        Slot {
            index: 1,
            kind,
            public: Vec::new(),
            description,
        }
    }

    #[test]
    fn new_key_rebuilds_from_descriptions_only_what_they_say() {
        let x = slot(
            SlotKind::X25519,
            Description {
                public_key: Some(vec![9; 32]),
                ..Description::default()
            },
        );
        assert!(matches!(
            described_recipient(&x).unwrap(),
            Some(Recipient::X25519(k)) if k == [9; 32]
        ));
        // A description of the wrong size, or none: the slot can't be rebuilt.
        let short = slot(
            SlotKind::XWing,
            Description {
                public_key: Some(vec![1; 32]),
                ..Description::default()
            },
        );
        let e = described_recipient(&short).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnsupportedOperation);
        assert!(described_recipient(&slot(SlotKind::Rsa, Description::default())).is_err());
        // Passwords, recovery keys and security keys come from a person, not a description.
        for kind in [SlotKind::Password, SlotKind::RecoveryKey, SlotKind::Fido2] {
            assert!(
                described_recipient(&slot(kind, Description::default()))
                    .unwrap()
                    .is_none()
            );
        }

        // Only keys you have are rebuilt without asking: a This PC key this PC has, your keys
        // and contacts. A slot that only says it is bound to this machine is confirmed: anyone
        // who held the file key could have put their own key there and said so.
        let store = Store::new(std::env::temp_dir().join("beezip-no-such-store"));
        let spki = vec![0x30, 0x59, 7];
        let bound = slot(
            SlotKind::EcP256,
            Description {
                certificate: Some(spki.clone()),
                machine_bound: true,
                ..Description::default()
            },
        );
        assert!(known_recipient(
            &bound,
            Some(&store),
            std::slice::from_ref(&spki)
        ));
        assert!(known_recipient(&bound, None, std::slice::from_ref(&spki)));
        assert!(!known_recipient(&bound, Some(&store), &[]));
        assert!(!known_recipient(
            &bound,
            Some(&store),
            &[vec![0x30, 0x59, 8]]
        ));
        let p384 = slot(SlotKind::EcP384, bound.description.clone());
        assert!(!known_recipient(
            &p384,
            Some(&store),
            std::slice::from_ref(&spki)
        ));
        assert!(!known_recipient(
            &x,
            Some(&store),
            std::slice::from_ref(&spki)
        ));
        assert!(!known_recipient(&x, None, &[]));
        let cert = slot(
            SlotKind::Rsa,
            Description {
                certificate: Some(vec![0x30]),
                ..Description::default()
            },
        );
        assert!(!known_recipient(&cert, Some(&store), &[]));
    }

    #[test]
    fn some_way_in_must_leave_this_pc() {
        let pc = Labelled {
            recipient: Recipient::Ec {
                curve: Curve::P256,
                spki: vec![1],
                certificate: None,
                machine_bound: true,
            },
            label: Some("This PC".into()),
        };
        let pw = password_recipient("pw", Strength::Standard, None);
        assert!(leaves_the_machine(&[], &[]).is_err());
        let e = leaves_the_machine(std::slice::from_ref(&pc), &[]).unwrap_err();
        assert!(e.message.contains("only on this PC"), "{}", e.message);
        leaves_the_machine(&[pc.clone(), pw.clone()], &[]).unwrap();
        // Devices still to ask count as what they will make: Windows Hello and This PC stay
        // here, a security key travels.
        let hello = Device::Fido2 {
            hello: true,
            credential: None,
            label: None,
        };
        let key = Device::Fido2 {
            hello: false,
            credential: None,
            label: None,
        };
        let tpm = Device::ThisPc(None);
        assert!(leaves_the_machine(&[], &[hello.clone(), tpm.clone()]).is_err());
        assert!(
            leaves_the_machine(std::slice::from_ref(&pc), std::slice::from_ref(&hello)).is_err()
        );
        leaves_the_machine(std::slice::from_ref(&pc), std::slice::from_ref(&key)).unwrap();
        leaves_the_machine(&[], &[tpm, key]).unwrap();
        leaves_the_machine(std::slice::from_ref(&pw), &[hello]).unwrap();

        let ways = ways_of(&[pw, pc]);
        assert_eq!(ways.len(), 2);
        assert_eq!(ways[0].kind, SlotKindName::Password);
        assert_eq!(ways[0].label.as_deref(), Some("Password"));
        assert!(ways[0].post_quantum && !ways[0].machine_bound);
        assert_eq!((ways[1].slot, ways[1].kind), (1, SlotKindName::EcP256));
        assert!(ways[1].machine_bound && !ways[1].post_quantum);
        assert!(!post_quantum(&ways));
    }

    #[test]
    fn what_people_are_shown() {
        let p = ArchiveProtectionOutput {
            encrypted: true,
            ways: vec![
                WayIn {
                    slot: 0,
                    kind: SlotKindName::Password,
                    label: Some("Password".into()),
                    recipient: None,
                    fingerprint: None,
                    machine_bound: false,
                    post_quantum: true,
                },
                WayIn {
                    slot: 1,
                    kind: SlotKindName::EcP256,
                    label: Some("This PC".into()),
                    recipient: None,
                    fingerprint: None,
                    machine_bound: true,
                    post_quantum: false,
                },
            ],
            post_quantum: false,
        };
        let text = protection_text(&p);
        assert!(
            text.contains("ways in: 2, not safe from quantum computers"),
            "{text}"
        );
        assert!(
            text.contains("1: EC P-256 key, \"This PC\", this PC only"),
            "{text}"
        );
        assert!(text.contains("could have changed them"), "{text}");
        let store = Store::new(std::env::temp_dir().join("beezip-no-such-store"));
        let changed = signature_report(&signature(1, vec![5; 1984], Status::Invalid), Ok(&store));
        let text = signatures_text(&[changed]);
        assert!(text.contains("CHANGED after it was signed"), "{text}");
        assert!(text.contains(&fingerprint(&[5; 1984])), "{text}");
    }

    #[test]
    fn uvarints_and_certificate_signers() {
        let mut d: &[u8] = &[0xAC, 0x02, 5];
        assert_eq!(uvarint(&mut d), Some(300));
        assert_eq!(d, &[5]);
        assert_eq!(
            signer_certificates(&certificates(&[b"a", b"bc"]))
                .unwrap()
                .len(),
            2
        );
        // Trailing bytes, or more than 8 certificates: not a signer.
        let mut t = certificates(&[b"a"]);
        t.push(0);
        assert_eq!(signer_certificates(&t), None);
        let many: Vec<&[u8]> = vec![b"a"; 9];
        assert_eq!(signer_certificates(&certificates(&many)), None);
    }

    #[test]
    fn verify_wants_nothing_changed_and_someone_you_trust() {
        let store = Store::new(std::env::temp_dir().join("beezip-no-such-store"));
        let report = |status, trust| SignatureReport {
            trust,
            ..signature_report(&signature(1, vec![4; 1984], status), Ok(&store))
        };
        let valid = |trust| report(Status::Valid, Some(trust));
        let changed = report(Status::Invalid, None);

        let e = verified(&[], false).unwrap_err();
        assert!(e.message.contains("isn't signed"), "{}", e.message);
        // A valid signature from someone you trust passes; beside one that failed, nothing does.
        verified(&[valid(TrustName::Contact)], false).unwrap();
        verified(&[valid(TrustName::Yours)], false).unwrap();
        verified(&[valid(TrustName::Trusted)], false).unwrap();
        let e = verified(&[changed.clone(), valid(TrustName::Yours)], false).unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureRequired);
        assert!(
            e.message.contains("changed after it was signed"),
            "{}",
            e.message
        );
        let e = verified(&[valid(TrustName::Yours), changed], true).unwrap_err();
        assert!(e.message.contains("changed after"), "{}", e.message);
        // A stranger's valid signature passes only when `require_signer` named them.
        let e = verified(&[valid(TrustName::Unknown)], false).unwrap_err();
        assert!(e.message.contains("doesn't know"), "{}", e.message);
        assert!(verified(&[valid(TrustName::Expired)], false).is_err());
        verified(&[valid(TrustName::Unknown)], true).unwrap();
        let e = verified(
            &[report(Status::NotChecked("no digests".into()), None)],
            true,
        )
        .unwrap_err();
        assert!(e.message.contains("could be checked"), "{}", e.message);
    }
}
