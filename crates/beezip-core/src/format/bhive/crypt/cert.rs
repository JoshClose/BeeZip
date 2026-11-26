//! Certificates, public keys and private-key files: what kind of slot or signature a key can
//! make, what to show, and the pure-Rust half of opening and signing with a key file
//! (docs/M14.md §4, §6, §11; bhive.md §12.5, §13.4).
//!
//! Certificates come as DER or PEM (`.cer`, `.crt`, `.der`, `.pem`), and a key without one as
//! a `PUBLIC KEY` (its SubjectPublicKeyInfo). Private keys come as PKCS #8 (`PRIVATE KEY`, and
//! `ENCRYPTED PRIVATE KEY` under a password), PKCS #1 (`RSA PRIVATE KEY`) or SEC 1
//! (`EC PRIVATE KEY`), in PEM or DER; each becomes a [`PrivateKey`] holding PKCS #8 DER.

use der::{Decode, Encode};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;
use spki::{DecodePublicKey, ObjectIdentifier};
use zeroize::Zeroizing;

use super::{Curve, SlotKind, SlotSecret, SlotView, label};
use crate::{
    Error, ErrorKind, Result,
    format::bhive::{
        layout::{Bytes, put_uvarint},
        sign::{self, Algorithm},
    },
};

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// id-ecDH: an EC key marked for key agreement only (RFC 5480).
const EC_DH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.12");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

/// A public key's algorithm, from its SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa { bits: u32 },
    Ec(Curve),
    Other,
}

impl KeyAlgorithm {
    /// `rsa-2048`, `ec-p256`, as `certificates.list` shows it.
    pub fn name(self) -> String {
        match self {
            Self::Rsa { bits } => format!("rsa-{bits}"),
            Self::Ec(Curve::P256) => "ec-p256".into(),
            Self::Ec(Curve::P384) => "ec-p384".into(),
            Self::Other => "other".into(),
        }
    }
}

/// A certificate, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub spki: Vec<u8>,
    pub algorithm: KeyAlgorithm,
    pub subject: String,
    pub issuer: String,
    /// Seconds since 1970.
    pub not_before: i64,
    pub not_after: i64,
    /// What its key usage allows; `None` when the certificate doesn't say.
    pub key_encipherment: Option<bool>,
    pub key_agreement: Option<bool>,
    pub digital_signature: Option<bool>,
    /// SHA-1 of the DER, as Windows shows it.
    pub thumbprint: [u8; 20],
}

impl Certificate {
    /// The slot it can be encrypted to, or why not (docs/M14.md §4: ECDSA-only keys, RSA under
    /// 2,048 bits, a key usage that forbids it). An expired or untrusted certificate can be
    /// encrypted to, with a warning ([`Certificate::expired`]): encryption doesn't depend on
    /// trust.
    pub fn slot_kind(&self) -> std::result::Result<SlotKind, String> {
        match self.algorithm {
            KeyAlgorithm::Rsa { .. } => {
                check_rsa(&self.spki)?;
                if self.key_encipherment == Some(false) {
                    return Err("its key usage doesn't allow encrypting keys to it".into());
                }
                Ok(SlotKind::Rsa)
            }
            KeyAlgorithm::Ec(curve) => {
                if self.key_agreement == Some(false) {
                    return Err(
                        "it is an ECDSA certificate: its key can sign but can't agree \
                         keys, so nothing can be encrypted to it"
                            .into(),
                    );
                }
                Ok(match curve {
                    Curve::P256 => SlotKind::EcP256,
                    Curve::P384 => SlotKind::EcP384,
                })
            }
            KeyAlgorithm::Other => Err("its key is neither RSA nor EC on P-256 or P-384".into()),
        }
    }

    /// The algorithm its key signs with, or why it can't sign (bhive.md §13.4): RSA-PSS for
    /// RSA (a key that can't do PSS uses [`Algorithm::RsaPkcs1`] instead), ECDSA on the key's
    /// curve. An expired certificate isn't refused here; [`Certificate::expired`] says so.
    pub fn sign_algorithm(&self) -> std::result::Result<Algorithm, String> {
        if self.digital_signature == Some(false) {
            return Err("its key usage doesn't allow signatures".into());
        }
        match self.algorithm {
            KeyAlgorithm::Rsa { .. } => {
                check_rsa(&self.spki)?;
                Ok(Algorithm::RsaPss)
            }
            KeyAlgorithm::Ec(Curve::P256) => Ok(Algorithm::EcdsaP256),
            KeyAlgorithm::Ec(Curve::P384) => Ok(Algorithm::EcdsaP384),
            KeyAlgorithm::Other => Err("its key is neither RSA nor EC on P-256 or P-384".into()),
        }
    }

    /// Whether `now` (seconds since 1970) is outside its validity.
    pub fn expired(&self, now: i64) -> bool {
        now < self.not_before || now > self.not_after
    }

    /// A key with no certificate, from its SubjectPublicKeyInfo: no names, no limits on its
    /// use, and the SHA-1 of the SubjectPublicKeyInfo as its thumbprint.
    pub fn from_spki(spki: &[u8]) -> Result<Self> {
        let algorithm = spki_algorithm(spki)?;
        Ok(Self {
            der: Vec::new(),
            spki: spki.to_vec(),
            algorithm,
            subject: String::new(),
            issuer: String::new(),
            not_before: i64::MIN,
            not_after: i64::MAX,
            key_encipherment: None,
            key_agreement: None,
            digital_signature: None,
            thumbprint: sha1(spki),
        })
    }

    /// The recipient a writer makes a slot for, or why it can't be one.
    pub fn recipient(&self, machine_bound: bool) -> std::result::Result<super::Recipient, String> {
        let certificate = (!self.der.is_empty()).then(|| self.der.clone());
        Ok(match self.slot_kind()? {
            SlotKind::Rsa => super::Recipient::Rsa {
                spki: self.spki.clone(),
                certificate,
            },
            kind => super::Recipient::Ec {
                curve: if kind == SlotKind::EcP256 {
                    Curve::P256
                } else {
                    Curve::P384
                },
                spki: self.spki.clone(),
                certificate,
                machine_bound,
            },
        })
    }

    /// The thumbprint in hex, as Windows shows it and `--to-cert` takes it.
    pub fn thumbprint_hex(&self) -> String {
        self.thumbprint.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidArgs, message)
}

fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let mut out = [0; 20];
    out.copy_from_slice(&sha1::Sha1::digest(data));
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
    out
}

/// The PEM blocks in `text`, as their labels and bytes. Text around and between them (as
/// OpenSSL writes before a certificate) is ignored.
pub fn pem_blocks(text: &[u8]) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"-----END ";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = memchr::memmem::find(rest, BEGIN) {
        let block = &rest[start..];
        let end = memchr::memmem::find(block, END)
            .ok_or_else(|| invalid("a PEM block has no END line"))?;
        let close = memchr::memmem::find(&block[end + END.len()..], b"-----")
            .map(|i| end + END.len() + i + 5)
            .ok_or_else(|| invalid("a PEM block's END line is cut off"))?;
        let (label, bytes) = der::pem::decode_vec(&block[..close])
            .map_err(|e| invalid(format!("a PEM block doesn't decode: {e}")))?;
        out.push((label.to_owned(), Zeroizing::new(bytes)));
        rest = &block[close..];
    }
    Ok(out)
}

fn is_pem(bytes: &[u8]) -> bool {
    memchr::memmem::find(bytes, b"-----BEGIN ").is_some()
}

/// A certificate from DER or PEM; from PEM, the first `CERTIFICATE` block.
pub fn parse(bytes: &[u8]) -> Result<Certificate> {
    parse_all(bytes)?
        .into_iter()
        .next()
        .ok_or_else(|| invalid("the file has no certificate"))
}

/// Every certificate in a file: one DER certificate, or each `CERTIFICATE` block of a PEM file,
/// in order (a signer's own first, as a chain is written).
pub fn parse_all(bytes: &[u8]) -> Result<Vec<Certificate>> {
    if !is_pem(bytes) {
        return Ok(vec![parse_der(bytes)?]);
    }
    pem_blocks(bytes)?
        .iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| parse_der(der))
        .collect()
}

/// A public key from a file: a certificate, or a `PUBLIC KEY` (DER or PEM) as a certificate
/// with no names ([`Certificate::from_spki`]).
pub fn parse_public(bytes: &[u8]) -> Result<Certificate> {
    if is_pem(bytes) {
        for (label, der) in pem_blocks(bytes)? {
            match label.as_str() {
                "CERTIFICATE" => return parse_der(&der),
                "PUBLIC KEY" => return Certificate::from_spki(&der),
                _ => {}
            }
        }
        return Err(invalid("the file has no certificate or public key"));
    }
    parse_der(bytes).or_else(|e| Certificate::from_spki(bytes).map_err(|_| e))
}

fn parse_der(der: &[u8]) -> Result<Certificate> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| invalid(format!("not a certificate: {e}")))?;
    let tbs = cert.tbs_certificate();
    let spki = tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|e| invalid(format!("a certificate's public key doesn't encode: {e}")))?;
    let usage = tbs
        .get_extension::<x509_cert::ext::pkix::KeyUsage>()
        .map_err(|e| invalid(format!("a certificate's key usage doesn't parse: {e}")))?
        .map(|(_, ku)| ku);
    let unix = |t: x509_cert::time::Time| {
        i64::try_from(t.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
    };
    Ok(Certificate {
        der: der.to_vec(),
        algorithm: spki_algorithm(&spki)?,
        spki,
        subject: display_name(tbs.subject()),
        issuer: display_name(tbs.issuer()),
        not_before: unix(tbs.validity().not_before),
        not_after: unix(tbs.validity().not_after),
        key_encipherment: usage.as_ref().map(|u| u.key_encipherment()),
        key_agreement: usage.as_ref().map(|u| u.key_agreement()),
        digital_signature: usage
            .as_ref()
            .map(|u| u.digital_signature() || u.non_repudiation()),
        thumbprint: sha1(der),
    })
}

/// A name as people read it: its common name, else its organisation, else all of it.
fn display_name(name: &x509_cert::name::Name) -> String {
    let find = |oid: ObjectIdentifier| {
        name.iter_rdn()
            .flat_map(|rdn| rdn.iter())
            .filter(|atv| atv.oid == oid)
            .find_map(|atv| {
                let v = &atv.value;
                v.decode_as::<der::asn1::Utf8StringRef<'_>>()
                    .map(|s| s.as_str().to_owned())
                    .or_else(|_| {
                        v.decode_as::<der::asn1::PrintableStringRef<'_>>()
                            .map(|s| s.as_str().to_owned())
                    })
                    .or_else(|_| {
                        v.decode_as::<der::asn1::Ia5StringRef<'_>>()
                            .map(|s| s.as_str().to_owned())
                    })
                    .ok()
            })
    };
    find(COMMON_NAME)
        .or_else(|| find(ORGANIZATION))
        .unwrap_or_else(|| name.to_string())
}

fn named_curve(parameters: Option<der::asn1::AnyRef<'_>>) -> Option<Curve> {
    match parameters.and_then(|p| p.decode_as::<ObjectIdentifier>().ok()) {
        Some(c) if c == SECP256R1 => Some(Curve::P256),
        Some(c) if c == SECP384R1 => Some(Curve::P384),
        _ => None,
    }
}

/// A key's algorithm from its SubjectPublicKeyInfo.
pub fn spki_algorithm(spki: &[u8]) -> Result<KeyAlgorithm> {
    let info = spki::SubjectPublicKeyInfoRef::from_der(spki)
        .map_err(|e| invalid(format!("not a public key: {e}")))?;
    let oid = info.algorithm.oid;
    if oid == RSA_ENCRYPTION {
        let key = rsa::PublicKey::from_public_key_der(spki)
            .map_err(|e| invalid(format!("an RSA public key doesn't parse: {e}")))?;
        return Ok(KeyAlgorithm::Rsa {
            bits: key.n().bit_width(),
        });
    }
    if oid == EC_PUBLIC_KEY || oid == EC_DH {
        return Ok(
            named_curve(info.algorithm.parameters).map_or(KeyAlgorithm::Other, KeyAlgorithm::Ec)
        );
    }
    Ok(KeyAlgorithm::Other)
}

/// RSA's limits (bhive.md §12.5 and §13.4): 2,048 to 8,192 bits, an odd exponent from 3 to
/// 2^32 − 1.
pub fn check_rsa(spki: &[u8]) -> std::result::Result<(), String> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| format!("its RSA key doesn't parse: {e}"))?;
    let bits = key.n().bit_width();
    if !sign::RSA_BITS.contains(&bits) {
        return Err(if bits < *sign::RSA_BITS.start() {
            format!("its RSA key has {bits} bits; BeeZip needs 2,048 or more")
        } else {
            format!("its RSA key has {bits} bits; BeeZip takes at most 8,192")
        });
    }
    let e = key.e().to_be_bytes();
    let first = e.iter().position(|&b| b != 0).unwrap_or(e.len());
    let e = &e[first..];
    let exponent = (e.len() <= 8)
        .then(|| e.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
        .filter(|x| sign::RSA_EXPONENT.contains(x) && x % 2 == 1);
    if exponent.is_none() {
        return Err("its RSA key's exponent is outside 3 to 2^32 − 1, or even".into());
    }
    Ok(())
}

/// The tag of a slot of kind 5 to 7 for the key whose SubjectPublicKeyInfo is `spki`, over
/// `rest`: the RSA ciphertext, or the ephemeral public key (bhive.md §12.5, "Tags").
pub fn tag(kind: SlotKind, spki: &[u8], rest: &[u8]) -> [u8; 4] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &sha256(spki));
    let mut m = ring::hmac::Context::with_key(&key);
    m.update(label::TAG);
    m.update(&[kind.id()]);
    m.update(rest);
    let mut out = [0; 4];
    out.copy_from_slice(&m.sign().as_ref()[..4]);
    out
}

/// Whether `slot` is tagged for the key whose SubjectPublicKeyInfo is `spki`.
pub fn tag_matches(slot: &SlotView<'_>, spki: &[u8]) -> bool {
    match (slot.tag(), slot.tag_for(spki)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The signer field for certificates (bhive.md §13.4): a `uvarint` count, 1 to 8, then each
/// certificate's DER with its `uvarint` length, the signer's first.
pub fn chain_bytes(certificates: &[Vec<u8>]) -> Result<Vec<u8>> {
    if certificates.is_empty() || certificates.len() > sign::MAX_CERTIFICATES {
        return Err(invalid(format!(
            "a signature carries 1 to {} certificates, not {}",
            sign::MAX_CERTIFICATES,
            certificates.len()
        )));
    }
    let mut out = Vec::new();
    put_uvarint(&mut out, certificates.len() as u64);
    for c in certificates {
        put_uvarint(&mut out, c.len() as u64);
        out.extend_from_slice(c);
    }
    Ok(out)
}

/// The certificates of a signer field, DER, the signer's first.
pub fn chain(signer: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut b = Bytes::new(signer);
    let n = b.uvarint()?;
    if n == 0 || n > sign::MAX_CERTIFICATES as u64 {
        return Err(Error::corrupt(format!(
            "a signer field with {n} certificates"
        )));
    }
    let mut out = Vec::new();
    for _ in 0..n {
        let len = usize::try_from(b.uvarint()?)
            .map_err(|_| Error::corrupt("a certificate's length is too large"))?;
        out.push(b.take(len)?.to_vec());
    }
    if b.left() != 0 {
        return Err(Error::corrupt("bytes after a signer field's certificates"));
    }
    Ok(out)
}

/// What a certificate algorithm signs: the SHA-256 of the message, or SHA-384 for ECDSA P-384
/// (bhive.md §13.4). For a key in a device, which signs a hash.
pub fn digest(algorithm: Algorithm, message: &[u8]) -> Result<Vec<u8>> {
    Ok(match algorithm {
        Algorithm::RsaPss | Algorithm::RsaPkcs1 | Algorithm::EcdsaP256 => sha256(message).to_vec(),
        Algorithm::EcdsaP384 => ring::digest::digest(&ring::digest::SHA384, message)
            .as_ref()
            .to_vec(),
        Algorithm::MlDsa65Ed25519 => {
            return Err(invalid("a BeeZip signing key isn't a certificate's"));
        }
    })
}

/// A private key from a file, held as PKCS #8 DER and wiped when dropped.
pub struct PrivateKey {
    pkcs8: Zeroizing<Vec<u8>>,
    algorithm: KeyAlgorithm,
    spki: Vec<u8>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey({:?}, ***)", self.algorithm)
    }
}

fn bad_key(e: &dyn std::fmt::Display) -> Error {
    invalid(format!("a private key doesn't parse: {e}"))
}

impl PrivateKey {
    /// From PKCS #8 DER, unencrypted.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
        let info = pkcs8::PrivateKeyInfoRef::try_from(pkcs8).map_err(|e| bad_key(&e))?;
        let oid = info.algorithm.oid;
        let spki = if oid == RSA_ENCRYPTION {
            let key = rsa::PrivateKey::from_pkcs8_der(pkcs8).map_err(|e| bad_key(&e))?;
            spki::EncodePublicKey::to_public_key_der(&key.to_public_key())
                .map_err(|e| bad_key(&e))?
                .into_vec()
        } else if oid == EC_PUBLIC_KEY {
            match named_curve(info.algorithm.parameters) {
                Some(Curve::P256) => {
                    let key = p256::SecretKey::from_pkcs8_der(pkcs8).map_err(|e| bad_key(&e))?;
                    spki::EncodePublicKey::to_public_key_der(&key.public_key())
                        .map_err(|e| bad_key(&e))?
                        .into_vec()
                }
                Some(Curve::P384) => {
                    let key = p384::SecretKey::from_pkcs8_der(pkcs8).map_err(|e| bad_key(&e))?;
                    spki::EncodePublicKey::to_public_key_der(&key.public_key())
                        .map_err(|e| bad_key(&e))?
                        .into_vec()
                }
                None => {
                    return Err(invalid(
                        "an EC private key on a curve other than P-256 or P-384",
                    ));
                }
            }
        } else {
            return Err(invalid("a private key that is neither RSA nor EC"));
        };
        Ok(Self {
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
            algorithm: spki_algorithm(&spki)?,
            spki,
        })
    }

    /// The private keys in a file: PEM (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`,
    /// `RSA PRIVATE KEY`, `EC PRIVATE KEY`; other blocks, such as certificates, are skipped) or
    /// DER (PKCS #8, plain or encrypted, or SEC 1). An encrypted key needs `password`.
    pub fn from_file(bytes: &[u8], password: Option<&str>) -> Result<Vec<Self>> {
        if !is_pem(bytes) {
            return Ok(vec![Self::from_der(bytes, password)?]);
        }
        let mut out = Vec::new();
        for (label, der) in pem_blocks(bytes)? {
            out.push(match label.as_str() {
                "PRIVATE KEY" => Self::from_pkcs8(&der)?,
                "ENCRYPTED PRIVATE KEY" => Self::decrypt(&der, password)?,
                "RSA PRIVATE KEY" => {
                    use rsa::pkcs1::DecodeRsaPrivateKey;
                    let key = rsa::PrivateKey::from_pkcs1_der(&der).map_err(|e| bad_key(&e))?;
                    let pkcs8 = key.to_pkcs8_der().map_err(|e| bad_key(&e))?;
                    Self::from_pkcs8(pkcs8.as_bytes())?
                }
                "EC PRIVATE KEY" => Self::from_sec1(&der)?,
                _ => continue,
            });
        }
        if out.is_empty() {
            return Err(invalid("the file has no private key"));
        }
        Ok(out)
    }

    fn from_der(der: &[u8], password: Option<&str>) -> Result<Self> {
        if pkcs8::PrivateKeyInfoRef::try_from(der).is_ok() {
            return Self::from_pkcs8(der);
        }
        if pkcs8::EncryptedPrivateKeyInfoRef::try_from(der).is_ok() {
            return Self::decrypt(der, password);
        }
        Self::from_sec1(der).map_err(|_| invalid("not a private key in PKCS #8, PKCS #1 or SEC 1"))
    }

    fn from_sec1(der: &[u8]) -> Result<Self> {
        let pkcs8 = if let Ok(k) = p256::SecretKey::from_sec1_der(der) {
            k.to_pkcs8_der()
        } else if let Ok(k) = p384::SecretKey::from_sec1_der(der) {
            k.to_pkcs8_der()
        } else {
            return Err(invalid(
                "an EC private key that doesn't parse, or not on P-256 or P-384",
            ));
        };
        Self::from_pkcs8(pkcs8.map_err(|e| bad_key(&e))?.as_bytes())
    }

    fn decrypt(der: &[u8], password: Option<&str>) -> Result<Self> {
        let info = pkcs8::EncryptedPrivateKeyInfoRef::try_from(der).map_err(|e| bad_key(&e))?;
        let Some(password) = password else {
            return Err(Error::new(
                ErrorKind::PasswordRequired,
                "the private key is encrypted: give its password",
            ));
        };
        let plain = info.decrypt(password).map_err(|_| {
            Error::new(
                ErrorKind::WrongPassword,
                "the private key's password is wrong",
            )
        })?;
        Self::from_pkcs8(plain.as_bytes())
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Its public key's SubjectPublicKeyInfo, DER.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// Whether this key fits `slot`: its kind and tag (bhive.md §12.5).
    pub fn fits(&self, slot: &SlotView<'_>) -> bool {
        let kind_fits = matches!(
            (slot.kind, self.algorithm),
            (SlotKind::Rsa, KeyAlgorithm::Rsa { .. })
                | (SlotKind::EcP256, KeyAlgorithm::Ec(Curve::P256))
                | (SlotKind::EcP384, KeyAlgorithm::Ec(Curve::P384))
        );
        kind_fits && tag_matches(slot, &self.spki)
    }

    /// The secret of `slot`, when this key fits it; `None` otherwise.
    pub fn slot_secret(&self, slot: &SlotView<'_>) -> Result<Option<SlotSecret>> {
        if !self.fits(slot) {
            return Ok(None);
        }
        match self.algorithm {
            KeyAlgorithm::Rsa { .. } => super::rsa::secret(slot, &self.pkcs8).map(Some),
            KeyAlgorithm::Ec(curve) => super::ecdh::secret(slot, curve, &self.pkcs8).map(Some),
            KeyAlgorithm::Other => Ok(None),
        }
    }

    /// The algorithm this key signs with (RSA-PSS, ECDSA on its curve).
    pub fn sign_algorithm(&self) -> Result<Algorithm> {
        match self.algorithm {
            KeyAlgorithm::Rsa { .. } => {
                check_rsa(&self.spki).map_err(invalid)?;
                Ok(Algorithm::RsaPss)
            }
            KeyAlgorithm::Ec(Curve::P256) => Ok(Algorithm::EcdsaP256),
            KeyAlgorithm::Ec(Curve::P384) => Ok(Algorithm::EcdsaP384),
            KeyAlgorithm::Other => Err(invalid("the key can't sign")),
        }
    }

    /// The signature of `message` with `algorithm` (bhive.md §13.4): RSA-PSS with SHA-256 and
    /// a 32-byte salt, or ECDSA as `r ‖ s`. A key file can always do PSS, so it never signs
    /// with PKCS #1 v1.5.
    pub fn sign(&self, algorithm: Algorithm, message: &[u8]) -> Result<Vec<u8>> {
        use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
        let fail = |e: &dyn std::fmt::Display| invalid(format!("signing failed: {e}"));
        match (algorithm, self.algorithm) {
            (Algorithm::RsaPss, KeyAlgorithm::Rsa { .. }) => {
                check_rsa(&self.spki).map_err(invalid)?;
                let key = rsa::PrivateKey::from_pkcs8_der(&self.pkcs8).map_err(|e| fail(&e))?;
                Ok(
                    rsa::pss::SigningKey::<rsa::sha2::Sha256>::new_with_salt_len(key, 32)
                        .try_sign_with_rng(&mut getrandom::SysRng, message)
                        .map_err(|e| fail(&e))?
                        .to_vec(),
                )
            }
            (Algorithm::EcdsaP256, KeyAlgorithm::Ec(Curve::P256)) => {
                let key =
                    p256::ecdsa::SigningKey::from_pkcs8_der(&self.pkcs8).map_err(|e| fail(&e))?;
                let sig: p256::ecdsa::Signature = key.try_sign(message).map_err(|e| fail(&e))?;
                Ok(sig.to_bytes().to_vec())
            }
            (Algorithm::EcdsaP384, KeyAlgorithm::Ec(Curve::P384)) => {
                let key =
                    p384::ecdsa::SigningKey::from_pkcs8_der(&self.pkcs8).map_err(|e| fail(&e))?;
                let sig: p384::ecdsa::Signature = key.try_sign(message).map_err(|e| fail(&e))?;
                Ok(sig.to_bytes().to_vec())
            }
            _ => Err(invalid(format!("this key can't sign with {algorithm:?}"))),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    pub(crate) fn hex(s: &serde_json::Value) -> Vec<u8> {
        let s = s.as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_vectors_keys_are_what_they_say() {
        let v = vectors();
        for (name, want) in [
            ("rsa", KeyAlgorithm::Rsa { bits: 2048 }),
            ("p256", KeyAlgorithm::Ec(Curve::P256)),
            ("p384", KeyAlgorithm::Ec(Curve::P384)),
        ] {
            let spki = hex(&v["slots"][name]["spki"]);
            assert_eq!(spki_algorithm(&spki).unwrap(), want, "{name}");
            let key = PrivateKey::from_pkcs8(&hex(&v["slots"][name]["pkcs8"])).unwrap();
            assert_eq!(key.spki(), spki, "{name}");
            assert_eq!(key.algorithm(), want, "{name}");
            let bare = Certificate::from_spki(&spki).unwrap();
            assert!(bare.slot_kind().is_ok(), "{name}");
            assert!(bare.der.is_empty());
        }
        assert_eq!(KeyAlgorithm::Rsa { bits: 2048 }.name(), "rsa-2048");
        assert!(spki_algorithm(b"not a key").is_err());
    }

    #[test]
    fn tags_are_the_specifications() {
        let v = vectors();
        for name in ["rsa", "p256", "p384"] {
            let vec = &v["slots"][name];
            let slot = hex(&vec["slot"]);
            let kind = SlotKind::from_id(slot[0]).unwrap();
            let public = &slot[4..slot.len() - super::super::SLOT_TAIL_LEN];
            let rest = if kind == SlotKind::Rsa {
                &public[6..]
            } else {
                &public[4..]
            };
            assert_eq!(
                tag(kind, &hex(&vec["spki"]), rest).to_vec(),
                hex(&vec["tag"])
            );
        }
    }

    #[test]
    fn a_chain_round_trips_and_its_limits_hold() {
        let certs = vec![vec![1, 2, 3], vec![4; 200]];
        let field = chain_bytes(&certs).unwrap();
        assert_eq!(&field[..2], &[2, 3]);
        assert_eq!(chain(&field).unwrap(), certs);
        assert!(chain_bytes(&[]).is_err());
        assert!(chain_bytes(&vec![vec![0]; 9]).is_err());
        assert!(chain(&[0]).is_err());
        assert!(chain(&[9, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let mut long = field.clone();
        long.push(0);
        assert!(chain(&long).is_err());
        assert!(chain(&field[..field.len() - 1]).is_err());
    }

    /// Every algorithm signs, and `ring` (as a reader checks) accepts it.
    #[test]
    fn key_files_sign_as_ring_checks() {
        use ring::signature as rs;
        let v = vectors();
        let message = sign::message(2, &[7; 32], b"signer", b"");
        let cases: [(&str, Algorithm, &'static dyn rs::VerificationAlgorithm); 3] = [
            ("rsa", Algorithm::RsaPss, &rs::RSA_PSS_2048_8192_SHA256),
            ("p256", Algorithm::EcdsaP256, &rs::ECDSA_P256_SHA256_FIXED),
            ("p384", Algorithm::EcdsaP384, &rs::ECDSA_P384_SHA384_FIXED),
        ];
        for (name, algorithm, ring_alg) in cases {
            let key = PrivateKey::from_pkcs8(&hex(&v["slots"][name]["pkcs8"])).unwrap();
            let sig = key.sign(algorithm, &message).unwrap();
            let spki = spki::SubjectPublicKeyInfoRef::from_der(key.spki()).unwrap();
            let public = rs::UnparsedPublicKey::new(ring_alg, spki.subject_public_key.raw_bytes());
            public
                .verify(&message, &sig)
                .unwrap_or_else(|_| panic!("{name} {algorithm:?}"));
            let mut bad = message;
            bad[20] ^= 1;
            assert!(public.verify(&bad, &sig).is_err());
        }
        let rsa = PrivateKey::from_pkcs8(&hex(&v["slots"]["rsa"]["pkcs8"])).unwrap();
        assert_eq!(rsa.sign_algorithm().unwrap(), Algorithm::RsaPss);
        assert!(rsa.sign(Algorithm::EcdsaP256, &message).is_err());
        assert!(rsa.sign(Algorithm::RsaPkcs1, &message).is_err());
        assert!(rsa.sign(Algorithm::MlDsa65Ed25519, &message).is_err());
        assert_eq!(digest(Algorithm::EcdsaP384, b"x").unwrap().len(), 48);
        assert_eq!(digest(Algorithm::RsaPss, b"x").unwrap().len(), 32);
    }

    #[test]
    fn pem_blocks_skip_what_is_around_them() {
        let pem = b"Bag Attributes\n-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n\
            text\n-----BEGIN X-----\nBAU=\n-----END X-----\n";
        let blocks = pem_blocks(pem).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, "PUBLIC KEY");
        assert_eq!(*blocks[0].1, vec![1, 2, 3]);
        assert_eq!(*blocks[1].1, vec![4, 5]);
        assert!(pem_blocks(b"-----BEGIN X-----\nAQID\n").is_err());
    }
}
