//! A `.p12` or `.pfx` through Security.framework (docs/M14.md §6). macOS imports PKCS #12 only
//! into a keychain, the login one unless told otherwise, so each file gets a keychain of its
//! own: made in a new folder under the temporary folder, under a random password (no prompt),
//! the file imported into it, and deleted with the folder when the key source or signer is
//! dropped, on every path, errors included. The login keychain is never touched.
//!
//! While it exists, macOS lists the throwaway keychain in the user's keychain search list
//! (`SecKeychainCreate` adds it); deleting it takes it out again (`SecKeychainDelete`, which
//! security-framework doesn't wrap, so it is called here).

#![allow(unsafe_code)]

use std::{
    ffi::{CString, c_char, c_void},
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::{
        crypt::{
            KeySource, SlotSecret, SlotView,
            cert::{self, Certificate},
            sig,
        },
        sign::{Algorithm, MAX_CERTIFICATES, MESSAGE_LEN, Signer},
    },
};
use security_framework::{
    identity::SecIdentity,
    import_export::{ImportedIdentity, Pkcs12ImportOptions},
    key::Algorithm as SecAlgorithm,
    os::macos::keychain::{CreateOptions, KeychainSettings, SecKeychain},
    random::SecRandom,
};
use zeroize::Zeroizing;

use super::{KeychainSigner, fits, keychain_error, open};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainOpen(path_name: *const c_char, keychain: *mut *mut c_void) -> i32;
    fn SecKeychainDelete(keychain_or_array: *const c_void) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: *const c_void);
}

/// `errSecAuthFailed` and `errSecPkcs12VerifyFailure`: what `SecPKCS12Import` gives for a wrong
/// password (the second also when this macOS can't check the file's MAC).
const WRONG_PASSWORD: [i32; 2] = [-25293, -25264];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random(buf: &mut [u8]) -> Result<()> {
    SecRandom::default()
        .copy_bytes(buf)
        .map_err(|e| keychain_error("random bytes", e))
}

/// A keychain of one `.pfx`'s own, deleted with its folder when dropped.
pub(crate) struct TempKeychain {
    keychain: SecKeychain,
    dir: PathBuf,
    path: PathBuf,
}

impl TempKeychain {
    fn new() -> Result<Self> {
        let mut id = [0u8; 16];
        random(&mut id)?;
        let dir = std::env::temp_dir().join(format!("beezip-pfx-{}", hex(&id)));
        // A new folder only this user can open; never one that is there already.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| keychain_error("a folder for the .pfx file's keychain", e))?;
        let path = dir.join("pfx.keychain");
        let mut secret = Zeroizing::new([0u8; 32]);
        let made = random(&mut secret[..]).and_then(|()| {
            let password = Zeroizing::new(hex(&secret[..]));
            CreateOptions::new()
                .password(&password)
                .prompt_user(false)
                .create(&path)
                .map_err(|e| keychain_error("a keychain for the .pfx file", e))
        });
        let keychain = match made {
            Ok(k) => k,
            Err(e) => {
                delete_keychain(&path);
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let mut temp = Self {
            keychain,
            dir,
            path,
        };
        // Never locked while BeeZip uses it, so it never asks for its password.
        let _ = temp.keychain.set_settings(&KeychainSettings::new());
        Ok(temp)
    }
}

impl Drop for TempKeychain {
    fn drop(&mut self) {
        delete_keychain(&self.path);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Deletes the keychain at `path`: out of the search list, and its file. Silent; a keychain
/// that isn't there is nothing to do.
fn delete_keychain(path: &Path) {
    let Ok(name) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let mut keychain: *mut c_void = std::ptr::null_mut();
    // SAFETY: `name` is a NUL-terminated path that outlives the call, and `keychain` receives
    // a reference that is released below, once.
    unsafe {
        if SecKeychainOpen(name.as_ptr(), &mut keychain) == 0 && !keychain.is_null() {
            let _ = SecKeychainDelete(keychain.cast_const());
            CFRelease(keychain.cast_const());
        }
    }
}

/// The `.pfx`'s identities, imported into a keychain of their own. With no password, the
/// empty one is tried (Security.framework needs one), and `PasswordRequired` is asked for.
fn import(bytes: &[u8], password: Option<&str>) -> Result<(TempKeychain, Vec<ImportedIdentity>)> {
    let temp = TempKeychain::new()?;
    let imported = Pkcs12ImportOptions::new()
        .passphrase(password.unwrap_or(""))
        .keychain(temp.keychain.clone())
        .import(bytes);
    match imported {
        Ok(items) => Ok((temp, items)),
        // `temp` is dropped, and its keychain deleted, on the way out.
        Err(e) if WRONG_PASSWORD.contains(&e.code()) => Err(match password {
            None => Error::new(
                ErrorKind::PasswordRequired,
                "the .pfx file is under a password: give its password",
            ),
            Some(_) => Error::new(
                ErrorKind::WrongPassword,
                "the .pfx file's password is wrong, or this macOS can't read how it was made \
                 (OpenSSL 3's AES files need `openssl pkcs12 -legacy` for older macOS)",
            ),
        }),
        Err(e) => Err(Error::new(
            ErrorKind::InvalidArgs,
            format!("macOS couldn't read the .pfx file ({e})"),
        )),
    }
}

/// The identities that came out of the file, with their certificates parsed, and each one's
/// chain as the file gave it.
fn identities(items: Vec<ImportedIdentity>) -> Vec<(SecIdentity, Certificate, Vec<Vec<u8>>)> {
    items
        .into_iter()
        .filter_map(|item| {
            let identity = item.identity?;
            let der = identity.certificate().ok()?.to_der();
            let certificate = cert::parse_der(&der).ok()?;
            let chain = item
                .cert_chain
                .unwrap_or_default()
                .iter()
                .map(|c| c.to_der())
                .collect();
            Some((identity, certificate, chain))
        })
        .collect()
}

fn no_key() -> Error {
    Error::new(
        ErrorKind::InvalidArgs,
        "the .pfx file holds no certificate with its private key",
    )
}

/// A `.pfx`'s keys, with the keychain that holds them: tried silently, as a key file is (the
/// keys were imported by BeeZip into a keychain of its own, so using them asks nothing).
struct PfxSource {
    identities: Vec<(SecIdentity, Certificate)>,
    _keychain: TempKeychain,
}

impl KeySource for PfxSource {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        self.identities.iter().any(|(_, c)| fits(c, slot))
    }

    fn secret(&mut self, slot: &SlotView<'_>, _device: bool) -> Result<Option<SlotSecret>> {
        let Some((id, certificate)) = self.identities.iter().find(|(_, c)| fits(c, slot)) else {
            return Ok(None);
        };
        let key = id
            .private_key()
            .map_err(|e| keychain_error("the .pfx file's private key", e))?;
        open(&key, certificate, slot).map(Some)
    }
}

pub(crate) fn source(bytes: &[u8], password: Option<&str>) -> Result<Box<dyn KeySource + Send>> {
    let (keychain, items) = import(bytes, password)?;
    let identities: Vec<(SecIdentity, Certificate)> = identities(items)
        .into_iter()
        .map(|(id, c, _)| (id, c))
        .collect();
    if identities.is_empty() {
        return Err(no_key());
    }
    Ok(Box::new(PfxSource {
        identities,
        _keychain: keychain,
    }))
}

/// A `.pfx`'s signer, with the keychain that holds its key.
struct PfxSigner {
    signer: KeychainSigner,
    _keychain: TempKeychain,
}

impl Signer for PfxSigner {
    fn algorithm(&self) -> Algorithm {
        self.signer.algorithm()
    }

    fn signer_bytes(&self) -> Vec<u8> {
        self.signer.signer_bytes()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        self.signer.sign(message)
    }
}

/// The signer for the first certificate in the `.pfx` that may sign, or why the first can't,
/// carrying the chain the file gives, without its root.
pub(crate) fn signer(bytes: &[u8], password: Option<&str>) -> Result<Arc<dyn Signer>> {
    let (keychain, items) = import(bytes, password)?;
    let mut first_refusal = None;
    for (id, certificate, chain) in identities(items) {
        let algorithm = match crate::files::may_sign(&certificate) {
            Ok(a) => a,
            Err(e) => {
                first_refusal.get_or_insert(e);
                continue;
            }
        };
        let key = id
            .private_key()
            .map_err(|e| keychain_error("the .pfx file's private key", e))?;
        // A key that can't do PSS signs with PKCS #1 v1.5 (docs/bhive.md §13.4). Trying it
        // asks nothing: the key is in BeeZip's own keychain.
        let algorithm = if algorithm == Algorithm::RsaPss
            && key
                .create_signature(SecAlgorithm::RSASignatureDigestPSSSHA256, &[0; 32])
                .is_err()
        {
            Algorithm::RsaPkcs1
        } else {
            algorithm
        };
        let mut ders = if chain.first() == Some(&certificate.der) {
            chain
        } else {
            vec![certificate.der.clone()]
        };
        if ders.len() > 1 && ders.last().is_some_and(|d| cert::self_issued(d)) {
            ders.pop();
        }
        ders.truncate(MAX_CERTIFICATES);
        return Ok(Arc::new(PfxSigner {
            signer: KeychainSigner {
                key,
                algorithm,
                signer: sig::signer_bytes(&ders)?,
            },
            _keychain: keychain,
        }));
    }
    Err(first_refusal.unwrap_or_else(no_key))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use beezip_core::format::bhive::{
        crypt::{Protection, SlotKind},
        sign::Signing,
    };
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};

    use super::*;
    use crate::files::{
        e2e::{
            HONEY, KeyCtx, check_signed_by, create, extract, read_tree, self_signed, signatures,
            slot_kinds, to_certificate, tree,
        },
        tests::data,
    };

    fn read(f: &str) -> Vec<u8> {
        std::fs::read(data(f)).unwrap()
    }

    /// The thumbprints of the identities in the login keychain.
    fn login_identities() -> BTreeSet<String> {
        let Ok(login) = SecKeychain::default() else {
            return BTreeSet::new();
        };
        ItemSearchOptions::new()
            .class(ItemClass::identity())
            .keychains(&[login])
            .load_refs(true)
            .limit(Limit::All)
            .search()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| match r {
                SearchResult::Ref(Reference::Identity(id)) => {
                    let der = id.certificate().ok()?.to_der();
                    Some(cert::parse_der(&der).ok()?.thumbprint_hex())
                }
                _ => None,
            })
            .collect()
    }

    /// A throwaway keychain is made in a folder of its own and gone, folder and all, once
    /// dropped.
    #[test]
    fn a_pfx_keychain_is_deleted_when_dropped() {
        let temp = TempKeychain::new().unwrap();
        let dir = temp.dir.clone();
        // macOS may name the file `pfx.keychain-db`.
        let files = std::fs::read_dir(&dir).unwrap().count();
        assert!(files > 0, "no keychain in {}", dir.display());
        drop(temp);
        assert!(!dir.exists(), "{}", dir.display());
    }

    /// RSA and P-256 `.pfx` files open archives sealed to their certificates and sign, through
    /// keychains of their own; the login keychain gains no identity, and no keychain is left.
    #[test]
    fn pfx_files_open_and_sign_and_leave_the_login_keychain_alone() {
        let before = login_identities();
        let ours: Vec<String> = ["rsa.crt", "p256.crt"]
            .iter()
            .map(|f| cert::parse(&read(f)).unwrap().thumbprint_hex())
            .collect();
        for t in &ours {
            assert!(!before.contains(t), "{t} is in the login keychain already");
        }
        let root = tempfile::tempdir().unwrap();
        let input = tree(root.path());
        let want = read_tree(&input);
        for (i, (pfx, crt, kind, algorithm)) in [
            ("rsa-3des.pfx", "rsa.crt", SlotKind::Rsa, Algorithm::RsaPss),
            (
                "p256-3des.pfx",
                "p256.crt",
                SlotKind::EcP256,
                Algorithm::EcdsaP256,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let archive = root.path().join(format!("{pfx}.bhive"));
            create(
                &archive,
                &input,
                Some(Protection::New(vec![to_certificate(crt)])),
                None,
            )
            .unwrap();
            assert_eq!(slot_kinds(&archive), [Some(kind)]);
            let source = crate::pfx::source(&read(pfx), Some(HONEY)).unwrap();
            let mut cx = KeyCtx::new(Some(source));
            let got = extract(&archive, &root.path().join(format!("x{i}")), &mut cx).unwrap();
            assert_eq!(got, want, "{pfx}");
            assert!(cx.asked.is_empty(), "{pfx}: {:?}", cx.asked);

            let signer = crate::pfx::signer(&read(pfx), Some(HONEY)).unwrap();
            // PKCS #1 v1.5 where this macOS's key can't do PSS.
            let algorithm = match signer.algorithm() {
                Algorithm::RsaPkcs1 if algorithm == Algorithm::RsaPss => Algorithm::RsaPkcs1,
                _ => algorithm,
            };
            assert_eq!(signer.algorithm(), algorithm, "{pfx}");
            let signed = root.path().join(format!("signed{i}.bhive"));
            create(
                &signed,
                &input,
                None,
                Some(Signing {
                    signers: vec![signer.clone()],
                    time: None,
                }),
            )
            .unwrap();
            let report = signatures(&signed, &mut KeyCtx::new(None));
            check_signed_by(&report, &signer, algorithm, &self_signed(crt));
        }
        // OpenSSL 3's AES files: read where this macOS can.
        for pfx in ["rsa.pfx", "p256.pfx"] {
            if let Err(e) = crate::pfx::source(&read(pfx), Some(HONEY)) {
                eprintln!("this macOS doesn't read {pfx}: {}", e.message);
            }
        }

        // No new identity in the login keychain (one gone since is someone else's doing).
        let after = login_identities();
        let new: Vec<&String> = after.difference(&before).collect();
        assert!(
            new.is_empty(),
            "new identities in the login keychain: {new:?}"
        );
        for t in &ours {
            assert!(!after.contains(t), "{t} reached the login keychain");
        }
    }

    #[test]
    fn a_pfx_password_is_asked_for_and_checked() {
        let bytes = read("rsa-3des.pfx");
        let e = crate::pfx::source(&bytes, None).err().unwrap();
        assert_eq!(e.kind, ErrorKind::PasswordRequired, "{}", e.message);
        let e = crate::pfx::signer(&bytes, Some("comb")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::WrongPassword, "{}", e.message);
        // Bytes that aren't a .pfx are refused with macOS's reason.
        let e = crate::pfx::source(&read("rsa.der"), None).err().unwrap();
        assert_eq!(e.kind, ErrorKind::InvalidArgs, "{}", e.message);
    }
}
