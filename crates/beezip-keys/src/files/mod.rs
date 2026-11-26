//! Key files and certificate files, on every system (docs/M14.md §6): PEM and PKCS #8 private
//! keys, plain or under a password, PKCS #1 and SEC 1 keys; `.cer`, `.crt`, `.der`, `.pem`
//! certificates and public keys. Age identity files (`AGE-SECRET-KEY-…`) are PR C's
//! (`identity`): [`source`] leaves them to it.
//!
//! The test keys and certificates in `testdata/` are published on purpose (its README).

use std::{path::Path, sync::Arc};

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::{
        crypt::{
            KeySource, SlotSecret, SlotView,
            cert::{self, Certificate, PrivateKey},
        },
        sign::{Algorithm, MESSAGE_LEN, Signer},
    },
};

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        let kind = if e.kind() == std::io::ErrorKind::NotFound {
            ErrorKind::NotFound
        } else {
            ErrorKind::Io
        };
        Error::new(kind, format!("{}: {e}", path.display()))
    })
}

/// Whether a file holds age identities rather than PEM or DER keys.
fn is_age_identity(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| {
        s.lines()
            .map(str::trim)
            .any(|l| l.starts_with("AGE-SECRET-KEY-"))
    })
}

/// A key source over private-key files given for one job (`--identity`). A file under a
/// password needs `password`; age identity files are skipped, for PR C's source.
pub fn source(paths: &[&Path], password: Option<&str>) -> Result<Box<dyn KeySource + Send>> {
    let mut keys = Vec::new();
    for path in paths {
        let bytes = read(path)?;
        if is_age_identity(&bytes) {
            continue;
        }
        let found = PrivateKey::from_file(&bytes, password)
            .map_err(|e| Error::new(e.kind, format!("{}: {}", path.display(), e.message)))?;
        keys.extend(found);
    }
    Ok(Box::new(FileKeys { keys }))
}

/// Private keys from files, as a key source: tried silently, since a file needs no device.
pub struct FileKeys {
    keys: Vec<PrivateKey>,
}

impl FileKeys {
    pub fn new(keys: Vec<PrivateKey>) -> Self {
        Self { keys }
    }
}

impl KeySource for FileKeys {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        self.keys.iter().any(|k| k.fits(slot))
    }

    fn secret(&mut self, slot: &SlotView<'_>, _device: bool) -> Result<Option<SlotSecret>> {
        for key in &self.keys {
            match key.slot_secret(slot) {
                Ok(Some(secret)) => return Ok(Some(secret)),
                Ok(None) => {}
                // A tag that matched by chance (one in 2^32): not this key's slot.
                Err(e) if e.kind == ErrorKind::KeyRequired => {}
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }
}

/// A certificate, or a public key, from a file: to encrypt to, or to add as a contact.
pub fn certificate(path: &Path) -> Result<Certificate> {
    cert::parse_public(&read(path)?)
        .map_err(|e| Error::new(e.kind, format!("{}: {}", path.display(), e.message)))
}

/// Seconds since 1970, now.
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Whether `certificate` may sign now, and with which algorithm: its key usage allows
/// signatures, its key is within §13.4's limits, and it hasn't expired (a signature from an
/// expired certificate would be shown as expired at once).
pub(crate) fn may_sign(certificate: &Certificate) -> Result<Algorithm> {
    let algorithm = certificate.sign_algorithm().map_err(|why| {
        Error::new(
            ErrorKind::InvalidArgs,
            format!("{} can't sign: {why}", name_of(certificate)),
        )
    })?;
    if certificate.expired(now()) {
        return Err(Error::new(
            ErrorKind::InvalidArgs,
            format!(
                "{} can't sign: it isn't valid now (it expired, or isn't valid yet)",
                name_of(certificate)
            ),
        ));
    }
    Ok(algorithm)
}

fn name_of(certificate: &Certificate) -> String {
    if certificate.subject.is_empty() {
        "the key".into()
    } else {
        format!("the certificate \"{}\"", certificate.subject)
    }
}

/// A signer for a certificate whose private key is in a file. A certificate file may hold the
/// chain after the signer's own certificate (PEM); the signature carries them all, at most 8.
pub fn signer(certificate: &Path, key: &Path, password: Option<&str>) -> Result<Arc<dyn Signer>> {
    let chain = cert::parse_all(&read(certificate)?)?;
    let Some(first) = chain.first() else {
        return Err(Error::new(
            ErrorKind::InvalidArgs,
            format!("{}: no certificate", certificate.display()),
        ));
    };
    let algorithm = may_sign(first)?;
    let keys = PrivateKey::from_file(&read(key)?, password)?;
    let key = keys
        .into_iter()
        .find(|k| k.spki() == first.spki)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidArgs,
                format!(
                    "{} holds no private key for {}",
                    key.display(),
                    name_of(first)
                ),
            )
        })?;
    let ders: Vec<Vec<u8>> = chain.iter().map(|c| c.der.clone()).collect();
    Ok(Arc::new(FileSigner {
        key,
        algorithm,
        signer: cert::chain_bytes(&ders)?,
    }))
}

/// A certificate's key in a file, signing.
struct FileSigner {
    key: PrivateKey,
    algorithm: Algorithm,
    signer: Vec<u8>,
}

impl Signer for FileSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn signer_bytes(&self) -> Vec<u8> {
        self.signer.clone()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        self.key.sign(self.algorithm, message)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use beezip_core::format::bhive::crypt::{Curve, KEY_ID_LEN, SLOT_TAIL_LEN, SlotKind};

    use super::*;

    pub(crate) fn data(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/files/testdata")
            .join(name)
    }

    pub(crate) fn vectors() -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/bhive-m14/vectors.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    pub(crate) fn hex(s: &serde_json::Value) -> Vec<u8> {
        let s = s.as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A view of a whole slot's bytes.
    pub(crate) fn view<'a>(slot: &'a [u8], key_id: &'a [u8; KEY_ID_LEN]) -> SlotView<'a> {
        let framed = &slot[..slot.len() - SLOT_TAIL_LEN];
        SlotView {
            index: 0,
            kind: SlotKind::from_id(slot[0]).unwrap(),
            key_id,
            framed,
            public: &framed[4..],
        }
    }

    pub(crate) fn secret_bytes(s: SlotSecret) -> Vec<u8> {
        match s {
            SlotSecret::Shared(s) => s.to_vec(),
            SlotSecret::Extracted(p) => p.to_vec(),
        }
    }

    /// DER is read as DER, whatever text is inside it: a certificate that carries another's PEM
    /// is still itself. Here the PEM is written over the signature, which nothing here checks.
    #[test]
    fn a_der_certificate_holding_pem_is_itself() {
        let mut der = std::fs::read(data("rsa.der")).unwrap();
        let p256 = std::fs::read(data("p256.crt")).unwrap();
        let block = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        let at = der.len() - 200;
        der[at..at + block.len()].copy_from_slice(block);
        for parsed in [
            cert::parse(&der),
            cert::parse_der(&der),
            cert::parse_public(&der),
        ] {
            assert_eq!(parsed.unwrap().subject, "BeeZip test rsa");
        }
        assert_eq!(cert::parse_all(&der).unwrap().len(), 1);
        // A DER certificate followed by PEM is neither: it is read as the PEM it holds.
        let mut both = std::fs::read(data("rsa.der")).unwrap();
        both.extend_from_slice(&p256);
        assert!(cert::parse_der(&both).is_err());
        assert_eq!(cert::parse(&both).unwrap().subject, "BeeZip test p256");
    }

    #[test]
    fn certificates_parse_and_say_what_they_can_do() {
        let rsa = certificate(&data("rsa.crt")).unwrap();
        assert_eq!(rsa.subject, "BeeZip test rsa");
        assert_eq!(rsa.issuer, "BeeZip test rsa");
        assert_eq!(rsa.algorithm, cert::KeyAlgorithm::Rsa { bits: 2048 });
        assert_eq!(rsa.slot_kind(), Ok(SlotKind::Rsa));
        assert_eq!(rsa.sign_algorithm(), Ok(Algorithm::RsaPss));
        assert_eq!(rsa.key_encipherment, Some(true));
        assert!(!rsa.expired(now()));
        assert_eq!(certificate(&data("rsa.der")).unwrap(), rsa);
        assert_eq!(rsa.thumbprint_hex().len(), 40);

        let p256 = certificate(&data("p256.crt")).unwrap();
        assert_eq!(p256.slot_kind(), Ok(SlotKind::EcP256));
        assert_eq!(p256.sign_algorithm(), Ok(Algorithm::EcdsaP256));
        let p384 = certificate(&data("p384.crt")).unwrap();
        assert_eq!(p384.slot_kind(), Ok(SlotKind::EcP384));
        assert_eq!(p384.sign_algorithm(), Ok(Algorithm::EcdsaP384));
        assert!(matches!(
            p384.recipient(false),
            Ok(beezip_core::format::bhive::crypt::Recipient::Ec {
                curve: Curve::P384,
                certificate: Some(_),
                ..
            })
        ));

        let public = certificate(&data("p256.pub")).unwrap();
        assert_eq!(public.spki, p256.spki);
        assert!(public.der.is_empty());
        assert_eq!(public.slot_kind(), Ok(SlotKind::EcP256));

        let chain = cert::parse_all(&std::fs::read(data("chain.pem")).unwrap()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].subject, "BeeZip test leaf");
        assert_eq!(chain[0].issuer, "BeeZip test CA");
        assert_eq!(chain[0].spki, p256.spki);
        assert!(certificate(&data("missing.crt")).is_err());
        assert!(certificate(&data("README.md")).is_err());
    }

    #[test]
    fn certificates_that_cant_be_encrypted_to_are_refused_with_the_reason() {
        let ecdsa = certificate(&data("p256-ecdsa.crt")).unwrap();
        assert!(ecdsa.slot_kind().unwrap_err().contains("ECDSA"));
        // An ECDSA certificate still signs.
        assert_eq!(ecdsa.sign_algorithm(), Ok(Algorithm::EcdsaP256));
        let small = certificate(&data("rsa1024.crt")).unwrap();
        assert!(small.slot_kind().unwrap_err().contains("1024 bits"));
        assert!(small.sign_algorithm().is_err());
        let sign_only = certificate(&data("rsa-sign-only.crt")).unwrap();
        assert!(sign_only.slot_kind().unwrap_err().contains("key usage"));
        // An expired certificate can be encrypted to (with a warning), not signed with.
        let expired = certificate(&data("rsa-expired.crt")).unwrap();
        assert_eq!(expired.slot_kind(), Ok(SlotKind::Rsa));
        assert!(expired.expired(now()));
        assert!(
            may_sign(&expired)
                .unwrap_err()
                .message
                .contains("valid now")
        );
    }

    #[test]
    fn key_files_open_the_vectors_slots() {
        let v = vectors();
        let key_id: [u8; KEY_ID_LEN] = hex(&v["slots"]["key_id"]).try_into().unwrap();
        let mut keys = source(
            &[
                &data("rsa-pkcs1.key"),
                &data("p256-sec1.key"),
                &data("p384-encrypted.key"),
            ],
            Some("honey"),
        )
        .unwrap();
        for (name, want) in [("rsa", "secret"), ("p256", "prk"), ("p384", "prk")] {
            let slot = hex(&v["slots"][name]["slot"]);
            let view = view(&slot, &key_id);
            assert!(keys.offers(&view), "{name}");
            let secret = keys.secret(&view, false).unwrap().unwrap();
            assert_eq!(secret_bytes(secret), hex(&v["slots"][name][want]), "{name}");
        }
        let password = hex(&v["slots"]["password"]["slot"]);
        assert!(!keys.offers(&view(&password, &key_id)));
        assert!(
            keys.secret(&view(&password, &key_id), false)
                .unwrap()
                .is_none()
        );
        // Only the RSA key: the EC slots aren't its.
        let mut rsa = source(&[&data("rsa.key")], None).unwrap();
        let p256 = hex(&v["slots"]["p256"]["slot"]);
        assert!(!rsa.offers(&view(&p256, &key_id)));
    }

    #[test]
    fn a_key_under_a_password_needs_the_right_one() {
        let path = data("p384-encrypted.key");
        let missing = source(&[&path], None).err().unwrap();
        assert_eq!(missing.kind, ErrorKind::PasswordRequired);
        let wrong = source(&[&path], Some("comb")).err().unwrap();
        assert_eq!(wrong.kind, ErrorKind::WrongPassword);
        // A certificate is no private key.
        assert!(source(&[&data("rsa.crt")], None).is_err());
    }

    #[test]
    fn age_identity_files_are_left_to_their_own_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("me.txt");
        std::fs::write(&path, "# created: 2026-11-26\nAGE-SECRET-KEY-1QQQQ\n").unwrap();
        let mut keys = source(&[&path], None).unwrap();
        let v = vectors();
        let key_id = [0; KEY_ID_LEN];
        let slot = hex(&v["slots"]["rsa"]["slot"]);
        assert!(!keys.offers(&view(&slot, &key_id)));
    }

    #[test]
    fn certificates_with_their_keys_sign() {
        let message = [5; MESSAGE_LEN];
        for (crt, key, algorithm, len) in [
            ("rsa.crt", "rsa.key", Algorithm::RsaPss, 256),
            ("p256.crt", "p256-sec1.key", Algorithm::EcdsaP256, 64),
            ("p256-ecdsa.crt", "p256.key", Algorithm::EcdsaP256, 64),
            ("p384.crt", "p384-encrypted.key", Algorithm::EcdsaP384, 96),
        ] {
            let s = signer(&data(crt), &data(key), Some("honey")).unwrap();
            assert_eq!(s.algorithm(), algorithm, "{crt}");
            let chain = cert::chain(&s.signer_bytes()).unwrap();
            assert_eq!(
                chain,
                vec![
                    std::fs::read(data(crt))
                        .map(|b| cert::parse(&b).unwrap().der)
                        .unwrap()
                ]
            );
            assert_eq!(s.sign(&message).unwrap().len(), len, "{crt}");
        }
        let chained = signer(&data("chain.pem"), &data("p256.key"), None).unwrap();
        assert_eq!(cert::chain(&chained.signer_bytes()).unwrap().len(), 2);
    }

    #[test]
    fn signing_is_refused_with_the_reason() {
        let refused = |crt: &str, key: &str| signer(&data(crt), &data(key), None).err().unwrap();
        assert!(
            refused("rsa-expired.crt", "rsa.key")
                .message
                .contains("valid now")
        );
        assert!(
            refused("rsa1024.crt", "rsa.key")
                .message
                .contains("1024 bits")
        );
        assert!(
            refused("rsa.crt", "p256.key")
                .message
                .contains("no private key")
        );
        assert!(
            refused("rsa.crt", "rsa.crt")
                .message
                .contains("no private key")
        );
    }
}
