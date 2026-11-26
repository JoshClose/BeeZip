//! A `.pfx` opened in memory (docs/M14.md §6): `PFXImportCertStore` with `PKCS12_NO_PERSIST_KEY`
//! puts its certificates in a store in memory and its keys in CNG's software provider without
//! persisting them, attached to their certificates as `CERT_NCRYPT_KEY_HANDLE_PROP_ID`, which
//! [`super::win::Cert::private_key`] reads. Nothing reaches the user's stores or key
//! containers. The keys then open slots and sign as a store's keys do.

use std::sync::Arc;

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::{
        crypt::{KeySource, SlotSecret, SlotView, cert},
        sign::Signer,
    },
};

use super::{
    CngSource,
    win::{Store, WinError},
};

/// `ERROR_INVALID_PASSWORD` as an HRESULT: what `PFXImportCertStore` gives for a wrong one.
const ERROR_INVALID_PASSWORD: u32 = 0x8007_0056;

/// The `.pfx` in a store in memory. With no password, none and then the empty one are tried, as
/// tools write either for "no password".
fn open(bytes: &[u8], password: Option<&str>) -> Result<Store> {
    let opened = match password {
        Some(p) => Store::pfx(bytes, Some(p)),
        None => Store::pfx(bytes, None).or_else(|e| {
            if e.code == ERROR_INVALID_PASSWORD {
                Store::pfx(bytes, Some(""))
            } else {
                Err(e)
            }
        }),
    };
    opened.map_err(|e: WinError| match (e.code, password) {
        (ERROR_INVALID_PASSWORD, None) => Error::new(
            ErrorKind::PasswordRequired,
            "the .pfx file is under a password: give its password",
        ),
        (ERROR_INVALID_PASSWORD, Some(_)) => Error::new(
            ErrorKind::WrongPassword,
            "the .pfx file's password is wrong",
        ),
        _ => Error::new(
            ErrorKind::InvalidArgs,
            format!("Windows couldn't read the .pfx file ({})", e.what),
        ),
    })
}

fn no_key() -> Error {
    Error::new(
        ErrorKind::InvalidArgs,
        "the .pfx file holds no certificate with its private key",
    )
}

/// A `.pfx`'s keys, with the store in memory that holds them.
struct PfxSource {
    keys: CngSource,
    _store: Store,
}

impl KeySource for PfxSource {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        self.keys.offers(slot)
    }

    fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>> {
        self.keys.secret(slot, device)
    }
}

/// The `.pfx`'s keys as a key source (`--identity`).
pub(crate) fn source(bytes: &[u8], password: Option<&str>) -> Result<Box<dyn KeySource + Send>> {
    let store = open(bytes, password)?;
    let keys = CngSource::new(&[&store], Vec::new());
    if keys.certs.is_empty() {
        return Err(no_key());
    }
    Ok(Box::new(PfxSource {
        keys,
        _store: store,
    }))
}

/// A signer for the `.pfx`'s certificate that has its key (`--sign`): the first that may sign,
/// or why the first can't. Its chain is built with the file's other certificates.
pub(crate) fn signer(bytes: &[u8], password: Option<&str>) -> Result<Arc<dyn Signer>> {
    let store = open(bytes, password)?;
    let mut first_refusal = None;
    for c in store.certificates().iter().filter(|c| c.has_key_handle()) {
        let Ok(parsed) = cert::parse_der(c.der()) else {
            continue;
        };
        match super::signer_with(&store, &parsed.thumbprint, Some(&store)) {
            Ok(signer) => return Ok(signer),
            Err(e) => {
                first_refusal.get_or_insert(e);
            }
        }
    }
    Err(first_refusal.unwrap_or_else(no_key))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::PathBuf};

    use beezip_core::format::bhive::{
        crypt::{Protection, SlotKind},
        sign::{Algorithm, MESSAGE_LEN, Signing},
    };
    use windows::Win32::Security::Cryptography::MS_KEY_STORAGE_PROVIDER;

    use super::*;
    use crate::{
        cng::win::{Provider, Store},
        files::{
            e2e::{
                HONEY, KeyCtx, check_signed_by, create, extract, read_tree, self_signed,
                signatures, slot_kinds, to_certificate, tree,
            },
            tests::data,
        },
    };

    fn read(f: &str) -> Vec<u8> {
        std::fs::read(data(f)).unwrap()
    }

    /// What a `.pfx` opened in memory must leave as it was: the user's Personal store, the keys
    /// CNG's software provider has persisted, and the legacy CryptoAPI's key containers.
    #[derive(Debug, PartialEq, Eq)]
    struct Persisted {
        personal: BTreeSet<String>,
        cng_keys: BTreeSet<String>,
        capi_containers: BTreeSet<PathBuf>,
    }

    fn files_under(dir: PathBuf) -> BTreeSet<PathBuf> {
        let mut out = BTreeSet::new();
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.insert(path);
                }
            }
        }
        out
    }

    fn persisted() -> Persisted {
        let personal = Store::user("My")
            .map(|s| {
                s.certificates()
                    .iter()
                    .filter_map(|c| cert::parse_der(c.der()).ok())
                    .map(|c| c.thumbprint_hex())
                    .collect()
            })
            .unwrap_or_default();
        let cng_keys = Provider::open(MS_KEY_STORAGE_PROVIDER)
            .and_then(|p| p.key_names())
            .unwrap()
            .into_iter()
            .collect();
        let capi_containers = std::env::var_os("APPDATA")
            .map(|a| files_under(PathBuf::from(a).join("Microsoft/Crypto/RSA")))
            .unwrap_or_default();
        Persisted {
            personal,
            cng_keys,
            capi_containers,
        }
    }

    /// The test certificates' thumbprints, which must never be in Personal.
    fn test_thumbprints() -> Vec<String> {
        ["rsa.crt", "p256.crt"]
            .iter()
            .map(|f| cert::parse(&read(f)).unwrap().thumbprint_hex())
            .collect()
    }

    /// RSA and P-256 `.pfx` files, AES and 3DES, open archives sealed to their certificates and
    /// sign (Windows imports a `.pfx`'s EC key as an ECDH key, which its software provider
    /// also signs with). All in memory: Personal, CNG's persisted keys and CryptoAPI's
    /// containers are the same after as before.
    #[test]
    fn pfx_files_open_and_sign_in_memory_and_leave_nothing() {
        let before = persisted();
        for t in test_thumbprints() {
            assert!(!before.personal.contains(&t), "{t} is in Personal already");
        }

        let root = tempfile::tempdir().unwrap();
        let input = tree(root.path());
        let want = read_tree(&input);
        let opens = [
            ("rsa.pfx", "rsa.crt", SlotKind::Rsa),
            ("rsa-3des.pfx", "rsa.crt", SlotKind::Rsa),
            ("p256.pfx", "p256.crt", SlotKind::EcP256),
        ];
        for (i, (pfx, crt, kind)) in opens.into_iter().enumerate() {
            let archive = root.path().join(format!("{pfx}.bhive"));
            create(
                &archive,
                &input,
                Some(Protection::New(vec![to_certificate(crt)])),
                None,
            )
            .unwrap();
            assert_eq!(slot_kinds(&archive), [Some(kind)]);
            // Opened silently, as a key file is.
            let source = crate::pfx::source(&read(pfx), Some(HONEY)).unwrap();
            let mut cx = KeyCtx::new(Some(source));
            let got = extract(&archive, &root.path().join(format!("x{i}")), &mut cx).unwrap();
            assert_eq!(got, want, "{pfx}");
            assert!(cx.asked.is_empty(), "{pfx}: {:?}", cx.asked);
        }

        let signs = [
            ("rsa.pfx", Some(HONEY), "rsa.crt", Algorithm::RsaPss),
            ("rsa-3des.pfx", Some(HONEY), "rsa.crt", Algorithm::RsaPss),
            ("p256.pfx", Some(HONEY), "p256.crt", Algorithm::EcdsaP256),
            (
                "p256-ecdsa.pfx",
                None,
                "p256-ecdsa.crt",
                Algorithm::EcdsaP256,
            ),
        ];
        for (i, (pfx, password, crt, algorithm)) in signs.into_iter().enumerate() {
            // Signed with it: the signature checks, and its self-signed signer is unknown.
            let signer = crate::pfx::signer(&read(pfx), password).unwrap();
            assert_eq!(signer.algorithm(), algorithm, "{pfx}");
            assert_eq!(
                beezip_core::format::bhive::crypt::sig::certificates(&signer.signer_bytes())
                    .unwrap(),
                vec![cert::parse(&read(crt)).unwrap().der]
            );
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
            assert!(!signer.sign(&[3; MESSAGE_LEN]).unwrap().is_empty());
        }
        let after = persisted();
        assert_eq!(after, before, "a .pfx left something behind");
        for t in test_thumbprints() {
            assert!(!after.personal.contains(&t), "{t} reached Personal");
        }
    }

    #[test]
    fn a_pfx_password_is_asked_for_and_checked() {
        let bytes = read("rsa.pfx");
        let e = crate::pfx::source(&bytes, None).err().unwrap();
        assert_eq!(e.kind, ErrorKind::PasswordRequired, "{}", e.message);
        let e = crate::pfx::source(&bytes, Some("comb")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::WrongPassword, "{}", e.message);
        let e = crate::pfx::signer(&bytes, Some("comb")).err().unwrap();
        assert_eq!(e.kind, ErrorKind::WrongPassword, "{}", e.message);
        // A .pfx with an empty password needs none given.
        let open = read("p256-ecdsa.pfx");
        assert!(crate::pfx::source(&open, None).is_ok());
        assert!(crate::pfx::signer(&open, None).is_ok());
        // Bytes that aren't a .pfx are refused with Windows' reason.
        let e = crate::pfx::source(&read("rsa.der"), None).err().unwrap();
        assert_eq!(e.kind, ErrorKind::InvalidArgs, "{}", e.message);
    }
}
