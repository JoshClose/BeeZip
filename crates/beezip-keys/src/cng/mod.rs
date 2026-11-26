//! Windows: certificate stores, CNG keys in software, on smart cards and in the TPM, "This PC",
//! and chain checks (docs/M14.md §6, §14; the Windows spike in target/m14-spikes/winkeys).
//!
//! What the spike found, which this respects: CNG's `BCRYPT_KDF_HKDF` is broken and can crash
//! the process, so EC slots use `BCRYPT_KDF_HMAC` with the slot's context as `KDF_HMAC_KEY`;
//! ECDSA keys can't do ECDH; TPM RSA-OAEP needs an empty label; the TPM provider refuses
//! `NCRYPT_SILENT_FLAG` on delete; its provider-handle property is borrowed, not owned; TPM
//! keys get no Key Usage property. Every call is silent unless the user chose the way in (a
//! slot's `device`) or is signing: then a smart card's or TPM key's PIN dialog, Windows' own,
//! may show, parented to the window the caller gives (`NCRYPT_WINDOW_HANDLE_PROPERTY`). The
//! user's stores are opened read only and never changed; certificates whose keys are in legacy
//! CryptoAPI providers (which CNG-only acquisition can't open) are listed without a key and
//! skipped as ways in.

#![allow(unsafe_code)]

mod win;

use std::sync::{Arc, Mutex};

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::{
        crypt::{
            Curve, KeySource, SlotKind, SlotSecret, SlotView,
            cert::{self, Certificate, KeyAlgorithm},
            ecdh, rsa, sig,
        },
        sign::{Algorithm, MAX_CERTIFICATES, MESSAGE_LEN, Signer},
    },
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ECDH_P256_ALGORITHM,
    NCRYPT_PIN_PROPERTY,
};

pub use win::Chain;
use win::{Cert, Key, Provider, Store, WinError};

/// The names of "This PC" keys in the TPM start with this.
pub const THIS_PC_PREFIX: &str = "BeeZip This PC ";

/// A certificate in one of the user's stores, as `certificates.list` shows it.
#[derive(Debug, Clone)]
pub struct StoreCertificate {
    /// For a certificate whose private key is here and is an ECDSA key (which can't agree
    /// keys), `key_agreement` is `Some(false)`, so [`Certificate::slot_kind`] gives the reason.
    pub certificate: Certificate,
    /// `My` (Personal) or `AddressBook` (Other People).
    pub store: String,
    /// Where its private key is, when this machine has it.
    pub key: Option<KeyHome>,
    /// Windows trusts its chain (from what Windows has cached, without going online).
    pub trusted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyHome {
    Software,
    SmartCard,
    Tpm,
}

fn key_home(cert: &Cert) -> Option<KeyHome> {
    if cert.has_key_handle() {
        return Some(KeyHome::Software);
    }
    let info = cert.prov_info()?;
    if info.provider == "Microsoft Platform Crypto Provider" {
        Some(KeyHome::Tpm)
    } else if info.provider.contains("Smart Card") {
        Some(KeyHome::SmartCard)
    } else if info.prov_type == 0 {
        Some(KeyHome::Software)
    } else {
        // A legacy CryptoAPI provider, which BeeZip doesn't use.
        None
    }
}

fn describe(cert: &Cert, store: &str) -> Option<StoreCertificate> {
    let mut certificate = cert::parse_der(cert.der()).ok()?;
    let key = key_home(cert);
    if key.is_some() && matches!(certificate.algorithm, KeyAlgorithm::Ec(_)) {
        // Opening a key reads it, silently; it doesn't use it.
        if let Ok(k) = cert.private_key(true)
            && k.algorithm().starts_with("ECDSA")
        {
            certificate.key_agreement = Some(false);
        }
    }
    let trusted = cert.chain(None, false).is_ok_and(|c| c.trusted());
    Some(StoreCertificate {
        certificate,
        store: store.to_owned(),
        key,
        trusted,
    })
}

/// The certificates of Personal and Other People, each with what it can do
/// ([`Certificate::slot_kind`], [`Certificate::sign_algorithm`]). Certificates that don't parse
/// are left out.
pub fn certificates() -> Result<Vec<StoreCertificate>> {
    let mut out = Vec::new();
    for name in ["My", "AddressBook"] {
        // Other People may not exist yet: nothing has been put there.
        let Ok(store) = Store::user(name) else {
            continue;
        };
        out.extend(
            store
                .certificates()
                .iter()
                .filter_map(|c| describe(c, name)),
        );
    }
    Ok(out)
}

/// A certificate whose private key may be here.
struct CertKey {
    cert: Cert,
    certificate: Certificate,
    /// Whether its key is an ECDSA key, once looked at.
    ecdsa: Option<bool>,
}

impl CertKey {
    /// Whether its key may agree keys: not an ECDSA key behind an EC certificate. Opening a
    /// key reads it, silently; a key that won't open silently isn't known to be ECDSA.
    fn may_agree(&mut self) -> bool {
        if !matches!(self.certificate.algorithm, KeyAlgorithm::Ec(_)) {
            return true;
        }
        let cert = &self.cert;
        let ecdsa = *self.ecdsa.get_or_insert_with(|| {
            cert.private_key(true)
                .is_ok_and(|k| k.algorithm().starts_with("ECDSA"))
        });
        !ecdsa
    }
}

/// A "This PC" key: a TPM ECDH P-256 key with no certificate.
#[derive(Debug, Clone)]
struct ThisPc {
    name: String,
    spki: Vec<u8>,
    point: Vec<u8>,
}

/// Windows' certificate keys and "This PC" keys, as a key source.
pub struct CngSource {
    certs: Vec<CertKey>,
    this_pc: Vec<ThisPc>,
    /// The window a PIN dialog belongs to, for a way in the user chose.
    window: Option<isize>,
}

fn kind_fits(kind: SlotKind, algorithm: KeyAlgorithm) -> bool {
    matches!(
        (kind, algorithm),
        (SlotKind::Rsa, KeyAlgorithm::Rsa { .. })
            | (SlotKind::EcP256, KeyAlgorithm::Ec(Curve::P256))
            | (SlotKind::EcP384, KeyAlgorithm::Ec(Curve::P384))
    )
}

impl CngSource {
    fn new(stores: &[&Store], this_pc: Vec<ThisPc>) -> Self {
        let certs = stores
            .iter()
            .flat_map(|s| s.certificates())
            .filter(|c| key_home(c).is_some())
            .filter_map(|cert| {
                let certificate = cert::parse_der(cert.der()).ok()?;
                Some(CertKey {
                    cert,
                    certificate,
                    ecdsa: None,
                })
            })
            .collect();
        Self {
            certs,
            this_pc,
            window: None,
        }
    }

    fn cert_fits(c: &CertKey, slot: &SlotView<'_>) -> bool {
        kind_fits(slot.kind, c.certificate.algorithm)
            && cert::tag_matches(slot, &c.certificate.spki)
    }

    fn this_pc_fits(k: &ThisPc, slot: &SlotView<'_>) -> bool {
        slot.kind == SlotKind::EcP256 && cert::tag_matches(slot, &k.spki)
    }
}

/// The secret of `slot` with `key`, whose public key is `recipient` (an EC point; empty for
/// RSA). `None` when it would need a person and `device` is false; any other failure is an
/// error, which [`try_key`] reports only for a way in the user chose.
fn open_with(
    key: &Key,
    recipient: &[u8],
    slot: &SlotView<'_>,
    device: bool,
) -> Result<Option<SlotSecret>> {
    let silent = !device;
    if silent && key.needs_pin() {
        // Never tried without its PIN: a TPM counts failed tries towards its lockout.
        return Ok(None);
    }
    let quiet = |e: WinError| -> Result<Option<SlotSecret>> {
        if silent && e.needs_person() {
            Ok(None)
        } else {
            Err(e.into())
        }
    };
    match slot.kind {
        SlotKind::Rsa => {
            let ct = rsa::ciphertext(slot).ok_or_else(|| Error::corrupt("a damaged RSA slot"))?;
            match key.decrypt_oaep(ct, silent) {
                Ok(plain) => rsa::from_plaintext(plain).map(Some),
                Err(e) => quiet(e),
            }
        }
        SlotKind::EcP256 | SlotKind::EcP384 => {
            if key.algorithm().starts_with("ECDSA") {
                return Err(Error::new(
                    ErrorKind::InvalidArgs,
                    "this certificate's key is an ECDSA key: it can sign but can't agree keys, \
                     so it can't open archives",
                ));
            }
            let point = ecdh::ephemeral(slot).ok_or_else(|| Error::corrupt("a damaged EC slot"))?;
            let context = slot.context(recipient);
            match key.ecdh_prk(point, &context, silent) {
                Ok(prk) => Ok(Some(SlotSecret::Extracted(prk))),
                Err(e) => quiet(e),
            }
        }
        _ => Ok(None),
    }
}

/// One key's try at a slot. Silently (`device` false) a key that can't open it, for whatever
/// reason (a PIN it needs, a key CNG can't open, an ECDSA key, a TPM in lockout), is nothing
/// here, so the archive's other ways in are still tried; the reason is reported only for a way
/// in the user chose.
fn try_key(
    key: impl FnOnce() -> Result<(Key, Vec<u8>)>,
    slot: &SlotView<'_>,
    device: bool,
) -> Result<Option<SlotSecret>> {
    match key().and_then(|(key, recipient)| open_with(&key, &recipient, slot, device)) {
        Err(_) if !device => Ok(None),
        other => other,
    }
}

impl KeySource for CngSource {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        // An ECDSA key behind an EC certificate can't open the slot: not offered.
        self.certs
            .iter_mut()
            .any(|c| Self::cert_fits(c, slot) && c.may_agree())
            || self.this_pc.iter().any(|k| Self::this_pc_fits(k, slot))
    }

    /// With `device`, a PIN dialog Windows shows belongs to the source's window.
    fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>> {
        let window = self.window;
        for c in self.certs.iter().filter(|c| Self::cert_fits(c, slot)) {
            let key = || {
                let key = if device {
                    c.cert.private_key_for(window)?
                } else {
                    c.cert.private_key(true)?
                };
                let recipient = match c.certificate.algorithm {
                    KeyAlgorithm::Ec(curve) => ecdh::point_of_spki(curve, &c.certificate.spki)?,
                    _ => Vec::new(),
                };
                Ok((key, recipient))
            };
            if let Some(secret) = try_key(key, slot, device)? {
                return Ok(Some(secret));
            }
        }
        for k in self.this_pc.iter().filter(|k| Self::this_pc_fits(k, slot)) {
            let key = || {
                let key = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER)
                    .and_then(|p| p.open_key(&k.name))?;
                if device {
                    // Best effort: the TPM's PIN dialog over the window in front otherwise.
                    let _ = key.parent(window);
                }
                Ok((key, k.point.clone()))
            };
            if let Some(secret) = try_key(key, slot, device)? {
                return Ok(Some(secret));
            }
        }
        Ok(None)
    }
}

fn this_pc_keys() -> Vec<ThisPc> {
    let Ok(provider) = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER) else {
        return Vec::new();
    };
    let names = provider.key_names().unwrap_or_default();
    names
        .into_iter()
        .filter(|n| n.starts_with(THIS_PC_PREFIX))
        .filter_map(|name| {
            let key = provider.open_key(&name).ok()?;
            let point = win::point_of_blob(&key.export(BCRYPT_ECCPUBLIC_BLOB).ok()?)?;
            let spki = ecdh::spki_of_point(Curve::P256, &point).ok()?;
            Some(ThisPc { name, spki, point })
        })
        .collect()
}

/// A key source over the Personal store's keys and "This PC" keys. The PIN dialogs Windows
/// shows for a way in the user chose belong to `window` (the HWND of the window that started
/// the job), or without one to the window in front.
pub fn source(window: Option<isize>) -> Result<Box<dyn KeySource + Send>> {
    let my = Store::user("My").ok();
    let stores: Vec<&Store> = my.iter().collect();
    let mut source = CngSource::new(&stores, this_pc_keys());
    source.window = window;
    Ok(Box::new(source))
}

fn no_tpm(e: WinError) -> Error {
    Error::new(
        ErrorKind::UnsupportedOperation,
        format!("this PC has no TPM that BeeZip can use ({})", e.what),
    )
}

/// Codes that mean no TPM is behind the provider (TPM and TBS errors), or that it can't make
/// this kind of key: the provider opens on a PC without one. A TPM in lockout is there.
fn tpm_absent(e: &WinError) -> bool {
    // TPM_E_DEFEND_LOCK_RUNNING, TPM_20_E_LOCKOUT
    let lockout = matches!(e.code, 0x8028_0803 | 0x8028_0921);
    (matches!(e.code >> 16, 0x8028 | 0x8029) && !lockout)
        || matches!(
            e.code,
            // NTE_NOT_SUPPORTED, NTE_DEVICE_NOT_READY, NTE_DEVICE_NOT_FOUND
            0x8009_0029 | 0x8009_0030 | 0x8009_0035
        )
}

/// A failure making a This PC key: no TPM where none is there, else what went wrong.
fn tpm_failure(e: WinError) -> Error {
    if tpm_absent(&e) { no_tpm(e) } else { e.into() }
}

/// A new "This PC" key in the TPM (ECDH P-256), optionally with a PIN: its name and
/// SubjectPublicKeyInfo. No Key Usage is set (the TPM refuses it); a PIN is set as a property,
/// silently. With a PIN, opening asks for it in Windows' own dialog.
pub fn create_this_pc(pin: Option<&str>) -> Result<(String, Vec<u8>)> {
    let provider = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER).map_err(no_tpm)?;
    let mut id = [0u8; 8];
    win::random(&mut id)?;
    let name = format!(
        "{THIS_PC_PREFIX}{}",
        id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let key = provider
        .create_key(NCRYPT_ECDH_P256_ALGORITHM, Some(&name))
        .map_err(tpm_failure)?;
    if let Some(pin) = pin {
        // An unfinalized key isn't written: dropping it leaves nothing behind. A PIN the TPM
        // refuses is that, not a missing TPM.
        key.set_prop(NCRYPT_PIN_PROPERTY, &win::wz_bytes(pin))
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidArgs,
                    format!("the TPM refused the PIN ({})", e.what),
                )
            })?;
    }
    key.finalize().map_err(tpm_failure)?;
    let spki = key
        .export(BCRYPT_ECCPUBLIC_BLOB)
        .ok()
        .and_then(|b| win::point_of_blob(&b))
        .and_then(|p| ecdh::spki_of_point(Curve::P256, &p).ok());
    match spki {
        Some(spki) => Ok((name, spki)),
        None => {
            let _ = key.delete();
            Err(Error::new(
                ErrorKind::Io,
                "the TPM made a key whose public key BeeZip couldn't read",
            ))
        }
    }
}

/// The "This PC" keys in the TPM: names and SubjectPublicKeyInfos.
pub fn this_pc() -> Vec<(String, Vec<u8>)> {
    this_pc_keys()
        .into_iter()
        .map(|k| (k.name, k.spki))
        .collect()
}

/// Deletes a "This PC" key. Only BeeZip's own keys, by their prefix: never anything else.
pub fn delete_this_pc(name: &str) -> Result<()> {
    if !name.starts_with(THIS_PC_PREFIX) {
        return Err(Error::new(
            ErrorKind::InvalidArgs,
            format!("\"{name}\" isn't a This PC key"),
        ));
    }
    let provider = Provider::open(MS_PLATFORM_CRYPTO_PROVIDER).map_err(no_tpm)?;
    let key = provider.open_key(name).map_err(|e| {
        Error::new(
            ErrorKind::NotFound,
            format!("no This PC key \"{name}\" ({})", e.what),
        )
    })?;
    Ok(key.delete()?)
}

/// Windows' chain engine on a signer's certificates, the signer's first. First from what
/// Windows has cached alone: the certificates came with the archive, so their URLs are its
/// maker's, and following them would tell the maker who opened it and when (or stall opening).
/// Only a chain that leads to a root Windows trusts is built again with revocation checked,
/// which may ask the issuer online (decision 25).
pub fn chain(certificates: &[Vec<u8>]) -> Result<Chain> {
    let first = certificates
        .first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidArgs, "no certificate"))?;
    let store = Store::memory()?;
    for c in &certificates[1..] {
        store.add(c)?;
    }
    let leaf = store.add(first)?;
    let cached = leaf.chain(Some(&store), false)?;
    if !cached.anchored() {
        return Ok(cached);
    }
    Ok(leaf.chain(Some(&store), true)?)
}

/// A signer for the certificate with this SHA-1 thumbprint, whose key is on this machine. The
/// PIN dialog signing may show belongs to `window`, or without one to the window in front.
pub fn signer(thumbprint: &[u8; 20], window: Option<isize>) -> Result<Arc<dyn Signer>> {
    let store = Store::user("My")?;
    signer_in(&store, thumbprint, window)
}

fn signer_in(
    store: &Store,
    thumbprint: &[u8; 20],
    window: Option<isize>,
) -> Result<Arc<dyn Signer>> {
    let hex: String = thumbprint.iter().map(|b| format!("{b:02x}")).collect();
    let cert = store.find_sha1(thumbprint).ok_or_else(|| {
        Error::new(
            ErrorKind::NotFound,
            format!("no certificate {hex} in Personal"),
        )
    })?;
    let certificate = cert::parse_der(cert.der())?;
    let mut algorithm = crate::files::may_sign(&certificate)?;
    let no_key = |e: WinError| {
        Error::new(
            ErrorKind::NotFound,
            format!(
                "the certificate \"{}\" has no private key here that BeeZip can use ({})",
                certificate.subject, e.what
            ),
        )
    };
    let key = match cert.private_key(true) {
        Ok(k) => k,
        // A smart card may ask for its PIN to be opened at all: signing is the user's choice.
        Err(e) if e.needs_person() => cert.private_key_for(window).map_err(no_key)?,
        Err(e) => return Err(no_key(e)),
    };
    // Signing isn't silent: its PIN dialog belongs to the window. Best effort, as for opening.
    let _ = key.parent(window);
    let key_algorithm = key.algorithm();
    if key_algorithm.starts_with("ECDH") {
        return Err(Error::new(
            ErrorKind::InvalidArgs,
            format!(
                "the certificate \"{}\" has a key that agrees keys but can't sign",
                certificate.subject
            ),
        ));
    }
    if algorithm == Algorithm::RsaPss && key.provider_name().contains("Smart Card") {
        // Not every card's driver does PSS; every one does PKCS #1 v1.5 (bhive.md §13.4).
        algorithm = Algorithm::RsaPkcs1;
    }
    // The chain the machine has, without its root, which a reader must have anyway. A chain
    // that stops short of a root ends with an intermediate, which stays.
    let (mut ders, complete) = cert
        .chain(None, false)
        .map(|c| {
            let complete = c.complete();
            (c.certificates, complete)
        })
        .unwrap_or_default();
    if ders.first().map(Vec::as_slice) != Some(cert.der()) {
        ders = vec![cert.der().to_vec()];
    }
    if ders.len() > 1 && complete && ders.last().is_some_and(|d| cert::self_issued(d)) {
        ders.pop();
    }
    ders.truncate(MAX_CERTIFICATES);
    Ok(Arc::new(CngSigner {
        _cert: cert,
        key: Mutex::new(key),
        algorithm,
        signer: sig::signer_bytes(&ders)?,
    }))
}

/// A certificate's key in CNG, signing.
struct CngSigner {
    /// Keeps the key's certificate context, which may own the key's handle.
    _cert: Cert,
    key: Mutex<Key>,
    algorithm: Algorithm,
    signer: Vec<u8>,
}

impl Signer for CngSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn signer_bytes(&self) -> Vec<u8> {
        self.signer.clone()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        let hash = cert::digest(self.algorithm, message)?;
        let key = self
            .key
            .lock()
            .map_err(|_| Error::new(ErrorKind::Io, "a signer's key was poisoned"))?;
        // Not silent: a smart card's or TPM key's PIN dialog is Windows' (docs/M14.md §11).
        Ok(key.sign_hash(self.algorithm, &hash, false)?)
    }
}

#[cfg(test)]
mod tests;
