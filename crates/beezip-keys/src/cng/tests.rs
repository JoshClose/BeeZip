//! CNG with throwaway keys: imported into the software provider in memory (nothing persisted),
//! or made in the TPM under unique names and deleted even when a test fails. No test shows UI,
//! tries a wrong PIN, or touches the user's own keys and certificates (their stores are only
//! read).

use windows::Win32::Security::Cryptography::*;

use super::*;
use crate::files::tests::{data, hex, secret_bytes, vectors, view};
use beezip_core::format::bhive::crypt::{KEY_ID_LEN, MadeSlot, SLOT_TAIL_LEN, cert::PrivateKey};

/// The software provider, open for the whole run: keys attached to certificates in memory stop
/// working when the provider they came from is closed.
fn software() -> std::sync::Arc<Provider> {
    static SOFTWARE: std::sync::OnceLock<std::sync::Arc<Provider>> = std::sync::OnceLock::new();
    SOFTWARE
        .get_or_init(|| Provider::open(MS_KEY_STORAGE_PROVIDER).unwrap())
        .clone()
}

/// A key file's EC key as an ECDH or ECDSA key in CNG's software provider, in memory only.
fn import_ec(pkcs8: &[u8], curve: Curve, agree: bool) -> Key {
    let point = ecdh::point_of_spki(curve, PrivateKey::from_pkcs8(pkcs8).unwrap().spki()).unwrap();
    let d = ecdh::scalar(curve, pkcs8).unwrap();
    let magic = match (curve, agree) {
        (Curve::P256, true) => BCRYPT_ECDH_PRIVATE_P256_MAGIC,
        (Curve::P384, true) => BCRYPT_ECDH_PRIVATE_P384_MAGIC,
        (Curve::P256, false) => BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
        (Curve::P384, false) => BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
    };
    let mut blob = magic.to_le_bytes().to_vec();
    blob.extend_from_slice(&(d.len() as u32).to_le_bytes());
    blob.extend_from_slice(&point[1..]);
    blob.extend_from_slice(&d);
    software().import(BCRYPT_ECCPRIVATE_BLOB, &blob).unwrap()
}

fn import_rsa(pkcs8: &[u8]) -> Key {
    software()
        .import(NCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkcs8)
        .unwrap()
}

fn pkcs8_of(file: &str) -> Vec<u8> {
    PrivateKey::from_file(&std::fs::read(data(file)).unwrap(), Some("honey")).unwrap()[0]
        .pkcs8()
        .to_vec()
}

/// A store in memory holding the certificate in `crt`, with `key` attached to it: a
/// certificate whose key is here.
fn store_with(crt: &str, key: Key) -> (Store, Cert) {
    let store = Store::memory().unwrap();
    let der = cert::parse(&std::fs::read(data(crt)).unwrap()).unwrap().der;
    let c = store.add(&der).unwrap();
    c.attach(key).unwrap();
    (store, c)
}

/// A whole slot's bytes for a made slot, with a zero tail (no envelope here).
fn slot_bytes(kind: SlotKind, made: &MadeSlot) -> Vec<u8> {
    let mut slot = vec![kind.id(), 0];
    slot.extend_from_slice(&((made.public.len() + SLOT_TAIL_LEN) as u16).to_le_bytes());
    slot.extend_from_slice(&made.public);
    slot.extend_from_slice(&[0; SLOT_TAIL_LEN]);
    slot
}

fn shared(made: &MadeSlot) -> &[u8] {
    match &made.secret {
        SlotSecret::Shared(s) => s,
        SlotSecret::Extracted(_) => panic!("a writer has S"),
    }
}

#[test]
fn the_vectors_slots_open_through_cng_software_keys() {
    let v = vectors();
    let key_id: [u8; KEY_ID_LEN] = hex(&v["slots"]["key_id"]).try_into().unwrap();
    for (name, crt, want) in [
        ("rsa", "rsa.crt", "secret"),
        ("p256", "p256.crt", "prk"),
        ("p384", "p384.crt", "prk"),
    ] {
        let pkcs8 = hex(&v["slots"][name]["pkcs8"]);
        let key = match name {
            "rsa" => import_rsa(&pkcs8),
            "p256" => import_ec(&pkcs8, Curve::P256, true),
            _ => import_ec(&pkcs8, Curve::P384, true),
        };
        let (store, _cert) = store_with(crt, key);
        let mut source = CngSource::new(&[&store], Vec::new());
        let slot = hex(&v["slots"][name]["slot"]);
        let view = view(&slot, &key_id);
        assert!(source.offers(&view), "{name}");
        let secret = source.secret(&view, false).unwrap().unwrap();
        assert_eq!(secret_bytes(secret), hex(&v["slots"][name][want]), "{name}");
        let password = hex(&v["slots"]["password"]["slot"]);
        assert!(!source.offers(&crate::files::tests::view(&password, &key_id)));
    }
}

#[test]
fn made_slots_open_through_cng() {
    let key_id = [6; KEY_ID_LEN];
    for (crt, key) in [
        ("rsa.crt", import_rsa(&pkcs8_of("rsa.key"))),
        (
            "p384.crt",
            import_ec(&pkcs8_of("p384.key"), Curve::P384, true),
        ),
    ] {
        let certificate = cert::parse(&std::fs::read(data(crt)).unwrap()).unwrap();
        let kind = certificate.slot_kind().unwrap();
        let made = match kind {
            SlotKind::Rsa => rsa::make(&certificate.spki).unwrap(),
            _ => ecdh::make(Curve::P384, &certificate.spki).unwrap(),
        };
        let slot = slot_bytes(kind, &made);
        let view = view(&slot, &key_id);
        let want = match kind {
            SlotKind::Rsa => shared(&made).to_vec(),
            _ => secret_bytes(ecdh::extract(&view, &made.recipient_key, shared(&made))),
        };
        let (store, _cert) = store_with(crt, key);
        let mut source = CngSource::new(&[&store], Vec::new());
        let secret = source.secret(&view, false).unwrap().unwrap();
        assert_eq!(secret_bytes(secret), want, "{crt}");
    }
}

#[test]
fn ecdsa_keys_are_refused_for_encryption() {
    let v = vectors();
    let key_id: [u8; KEY_ID_LEN] = hex(&v["slots"]["key_id"]).try_into().unwrap();
    let key = import_ec(&hex(&v["slots"]["p256"]["pkcs8"]), Curve::P256, false);
    // A certificate whose usage allows agreement, with an ECDSA key behind it.
    let (store, cert) = store_with("p256.crt", key);
    let listed = describe(&cert, "My").unwrap();
    assert_eq!(listed.key, Some(KeyHome::Software));
    assert!(!listed.trusted);
    assert!(
        listed
            .certificate
            .slot_kind()
            .unwrap_err()
            .contains("ECDSA")
    );
    let mut source = CngSource::new(&[&store], Vec::new());
    let slot = hex(&v["slots"]["p256"]["slot"]);
    let err = source.secret(&view(&slot, &key_id), false).unwrap_err();
    assert!(err.message.contains("ECDSA"), "{}", err.message);
}

#[test]
fn certificates_sign_through_cng_and_windows_checks_them() {
    let message = [7; MESSAGE_LEN];
    let mut other = message;
    other[0] ^= 1;
    for (crt, file, algorithm) in [
        ("rsa.crt", "rsa.key", Algorithm::RsaPss),
        ("p256-ecdsa.crt", "p256.key", Algorithm::EcdsaP256),
        ("p384.crt", "p384.key", Algorithm::EcdsaP384),
    ] {
        let key = match algorithm {
            Algorithm::RsaPss => import_rsa(&pkcs8_of(file)),
            Algorithm::EcdsaP256 => import_ec(&pkcs8_of(file), Curve::P256, false),
            _ => import_ec(&pkcs8_of(file), Curve::P384, false),
        };
        let (store, cert) = store_with(crt, key);
        let thumbprint = cert::parse(cert.der()).unwrap().thumbprint;
        let signer = signer_in(&store, &thumbprint).unwrap();
        assert_eq!(signer.algorithm(), algorithm, "{crt}");
        assert_eq!(
            cert::chain(&signer.signer_bytes()).unwrap(),
            vec![cert.der().to_vec()]
        );
        let hash = cert::digest(algorithm, &message).unwrap();
        let sig = signer.sign(&message).unwrap();
        assert!(cert.verify(algorithm, &hash, &sig).unwrap(), "{crt}");
        let bad = cert::digest(algorithm, &other).unwrap();
        assert!(!cert.verify(algorithm, &bad, &sig).unwrap(), "{crt}");
        // A key file's signature checks the same way.
        let files = crate::files::signer(&data(crt), &data(file), None).unwrap();
        assert_eq!(files.signer_bytes(), signer.signer_bytes());
        assert!(
            cert.verify(algorithm, &hash, &files.sign(&message).unwrap())
                .unwrap()
        );
    }
}

#[test]
fn signing_is_refused_with_the_reason() {
    let refused = |crt: &str, key: Key| {
        let (store, cert) = store_with(crt, key);
        let thumbprint = cert::parse(cert.der()).unwrap().thumbprint;
        signer_in(&store, &thumbprint).err().unwrap()
    };
    let expired = refused("rsa-expired.crt", import_rsa(&pkcs8_of("rsa.key")));
    assert!(expired.message.contains("valid now"), "{}", expired.message);
    let ecdh = refused(
        "p256.crt",
        import_ec(&pkcs8_of("p256.key"), Curve::P256, true),
    );
    assert!(ecdh.message.contains("can't sign"), "{}", ecdh.message);
    let store = Store::memory().unwrap();
    assert_eq!(
        signer_in(&store, &[0; 20]).err().unwrap().kind,
        ErrorKind::NotFound
    );
}

/// The user's own stores, read only: listing them and making a source never fails on what
/// they hold (legacy CryptoAPI keys included) and changes nothing.
#[test]
fn the_users_stores_are_read_without_changing_them() {
    let count = |name: &str| Store::user(name).map_or(0, |s| s.certificates().len());
    let before = (count("My"), count("AddressBook"));
    let listed = certificates().unwrap();
    for c in &listed {
        assert!(c.store == "My" || c.store == "AddressBook");
        assert_eq!(c.certificate.thumbprint_hex().len(), 40);
    }
    let v = vectors();
    let key_id = [1; KEY_ID_LEN];
    let slot = hex(&v["slots"]["rsa"]["slot"]);
    let mut source = source().unwrap();
    assert!(!source.offers(&view(&slot, &key_id)));
    assert!(
        source
            .secret(&view(&slot, &key_id), false)
            .unwrap()
            .is_none()
    );
    assert_eq!((count("My"), count("AddressBook")), before);
}

#[test]
fn chains_report_a_self_signed_certificate_as_untrusted() {
    let der = cert::parse(&std::fs::read(data("rsa.crt")).unwrap())
        .unwrap()
        .der;
    let c = chain(&[der]).unwrap();
    assert!(!c.trusted());
    assert!(!c.revoked());
    assert!(!c.expired());
    let expired = cert::parse(&std::fs::read(data("rsa-expired.crt")).unwrap())
        .unwrap()
        .der;
    assert!(chain(&[expired]).unwrap().expired());
    let pem = std::fs::read(data("chain.pem")).unwrap();
    let ders: Vec<_> = cert::parse_all(&pem)
        .unwrap()
        .into_iter()
        .map(|c| c.der)
        .collect();
    let c = chain(&ders).unwrap();
    assert_eq!(c.certificates.len(), 2);
    assert!(!c.trusted());
}

// The TPM: CI's runners have none, so each test returns early without one.

fn tpm() -> Option<std::sync::Arc<Provider>> {
    match Provider::open(MS_PLATFORM_CRYPTO_PROVIDER) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("no TPM here: {}", e.what);
            None
        }
    }
}

/// Deletes the TPM key it names when dropped, even when a test fails.
struct Doomed {
    name: String,
    pin: Option<&'static str>,
}

impl Drop for Doomed {
    fn drop(&mut self) {
        let Some(tpm) = tpm() else { return };
        if let Ok(key) = tpm.open_key(&self.name) {
            if let Some(pin) = self.pin {
                let _ = key.set_prop(NCRYPT_PIN_PROPERTY, &win::wz_bytes(pin));
            }
            if let Err(e) = key.delete() {
                eprintln!("couldn't delete the test key {}: {}", self.name, e.what);
            }
        }
    }
}

fn test_name(what: &str) -> String {
    let mut id = [0u8; 6];
    win::random(&mut id).unwrap();
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!("BeeZip test {what} {id}")
}

/// A "This PC" key, or `None` where the TPM can't make one (CI's runners open its provider
/// but have no TPM behind it).
fn this_pc_key(pin: Option<&'static str>) -> Option<(String, Vec<u8>, Doomed)> {
    match create_this_pc(pin) {
        Ok((name, spki)) => {
            let doomed = Doomed {
                name: name.clone(),
                pin,
            };
            Some((name, spki, doomed))
        }
        Err(e) if e.kind == ErrorKind::UnsupportedOperation => {
            eprintln!("no TPM here: {}", e.message);
            None
        }
        Err(e) => panic!("{}", e.message),
    }
}

/// A TPM key made under a throwaway name, or `None` where there's no TPM behind the provider.
fn tpm_key(
    tpm: &std::sync::Arc<Provider>,
    algorithm: windows_core::PCWSTR,
    bits: Option<u32>,
) -> Option<(Key, Doomed)> {
    let absent = |e: &WinError| {
        matches!(e.code >> 16, 0x8028 | 0x8029)
            || matches!(e.code, 0x8009_0029 | 0x8009_0030 | 0x8009_0035)
    };
    let name = test_name("key");
    let made = tpm.create_key(algorithm, Some(&name)).and_then(|key| {
        if let Some(bits) = bits {
            key.set_prop(NCRYPT_LENGTH_PROPERTY, &bits.to_le_bytes())?;
        }
        key.finalize()?;
        Ok(key)
    });
    match made {
        Ok(key) => Some((key, Doomed { name, pin: None })),
        Err(e) if absent(&e) => {
            eprintln!("no TPM here: {}", e.what);
            None
        }
        Err(e) => panic!("{}", e.what),
    }
}

/// BCrypt's check of a signature under an exported public key.
fn verify_blob(
    alg: BCRYPT_ALG_HANDLE,
    blob_type: windows_core::PCWSTR,
    blob: &[u8],
    algorithm: Algorithm,
    hash: &[u8],
    sig: &[u8],
) -> bool {
    let pss = BCRYPT_PSS_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        cbSalt: 32,
    };
    let (pad, flags) = match algorithm {
        Algorithm::RsaPss => (
            Some(&pss as *const _ as *const std::ffi::c_void),
            BCRYPT_PAD_PSS,
        ),
        _ => (None, BCRYPT_FLAGS(0)),
    };
    let mut key = BCRYPT_KEY_HANDLE::default();
    // SAFETY: the blob is read only; the key is destroyed before returning.
    unsafe {
        assert!(BCryptImportKeyPair(alg, None, blob_type, &mut key, blob, 0).0 >= 0);
        let ok = BCryptVerifySignature(key, pad, hash, sig, flags).0 >= 0;
        let _ = BCryptDestroyKey(key);
        ok
    }
}

#[test]
fn this_pc_keys_open_their_slots() {
    if tpm().is_none() {
        return;
    }
    let Some((name, spki, _doomed)) = this_pc_key(None) else {
        return;
    };
    assert!(name.starts_with(THIS_PC_PREFIX));
    assert!(this_pc().iter().any(|(n, s)| *n == name && *s == spki));
    let made = ecdh::make(Curve::P256, &spki).unwrap();
    let slot = slot_bytes(SlotKind::EcP256, &made);
    let key_id = [4; KEY_ID_LEN];
    let view = view(&slot, &key_id);
    let want = secret_bytes(ecdh::extract(&view, &made.recipient_key, shared(&made)));
    let mut source = source().unwrap();
    assert!(source.offers(&view));
    let secret = source.secret(&view, false).unwrap().unwrap();
    assert_eq!(secret_bytes(secret), want);
    delete_this_pc(&name).unwrap();
    assert!(!this_pc().iter().any(|(n, _)| *n == name));
    assert!(delete_this_pc("BeeZip test not a This PC key").is_err());
}

#[test]
fn a_this_pc_key_with_a_pin_is_never_tried_without_it() {
    let Some(tpm) = tpm() else { return };
    // A throwaway key's PIN, given silently as a property: never a wrong one.
    const PIN: &str = "BeeZip-test-4821";
    let Some((name, spki, _doomed)) = this_pc_key(Some(PIN)) else {
        return;
    };
    let made = ecdh::make(Curve::P256, &spki).unwrap();
    let slot = slot_bytes(SlotKind::EcP256, &made);
    let key_id = [5; KEY_ID_LEN];
    let view = view(&slot, &key_id);
    let mut source = source().unwrap();
    assert!(source.offers(&view));
    assert!(source.secret(&view, false).unwrap().is_none());
    // With its PIN, as Windows' dialog gives it when the user chooses this way in.
    let key = tpm.open_key(&name).unwrap();
    assert!(key.needs_pin());
    key.set_prop(NCRYPT_PIN_PROPERTY, &win::wz_bytes(PIN))
        .unwrap();
    let context = view.context(&made.recipient_key);
    let prk = key
        .ecdh_prk(ecdh::ephemeral(&view).unwrap(), &context, true)
        .unwrap();
    let want = secret_bytes(ecdh::extract(&view, &made.recipient_key, shared(&made)));
    assert_eq!(prk.to_vec(), want);
}

#[test]
fn tpm_keys_unwrap_and_sign_silently() {
    let Some(tpm) = tpm() else { return };
    // RSA-2048 (this TPM has no RSA-3072): OAEP with no label, and PSS.
    let Some((key, _doomed)) = tpm_key(&tpm, NCRYPT_RSA_ALGORITHM, Some(2048)) else {
        return;
    };
    let blob = key.export(BCRYPT_RSAPUBLIC_BLOB).unwrap();
    let (n, e) = win::rsa_of_blob(&blob).unwrap();
    let made = rsa::make(&cert::rsa_spki(&n, &e).unwrap()).unwrap();
    let slot = slot_bytes(SlotKind::Rsa, &made);
    let key_id = [7; KEY_ID_LEN];
    let opened = open_with(&key, &[], &view(&slot, &key_id), false)
        .unwrap()
        .unwrap();
    assert_eq!(secret_bytes(opened), shared(&made));
    let hash = [9; 32];
    let sig = key.sign_hash(Algorithm::RsaPss, &hash, true).unwrap();
    assert!(verify_blob(
        BCRYPT_RSA_ALG_HANDLE,
        BCRYPT_RSAPUBLIC_BLOB,
        &blob,
        Algorithm::RsaPss,
        &hash,
        &sig
    ));

    // ECDSA P-256.
    let Some((key, _doomed)) = tpm_key(&tpm, NCRYPT_ECDSA_P256_ALGORITHM, None) else {
        return;
    };
    let blob = key.export(BCRYPT_ECCPUBLIC_BLOB).unwrap();
    let sig = key.sign_hash(Algorithm::EcdsaP256, &hash, true).unwrap();
    assert_eq!(sig.len(), 64);
    assert!(verify_blob(
        BCRYPT_ECDSA_P256_ALG_HANDLE,
        BCRYPT_ECCPUBLIC_BLOB,
        &blob,
        Algorithm::EcdsaP256,
        &hash,
        &sig
    ));
}
