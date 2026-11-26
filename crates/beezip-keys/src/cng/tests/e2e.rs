//! End to end through CNG: archives sealed to certificates (RSA, P-256, P-384) and opened by
//! their keys in CNG's software provider (imported in memory, attached to certificates in a
//! store in memory: nothing persisted), archives signed by those keys, and an archive sealed to
//! a "This PC" key and opened by the TPM, where there is one. Windows' chain engine finds the
//! self-signed signers untrusted.

use std::sync::Arc;

use beezip_core::{
    OpenOptions,
    format::bhive::{
        BhiveReader,
        crypt::{Labelled, Protection, Recipient, UnlockAnswer},
        sign::Signing,
    },
    source::Source,
};

use super::*;
use crate::files::e2e::{
    HONEY, KeyCtx, check_signed_by, create, extract, read_tree, self_signed, signatures,
    slot_kinds, small_password, to_certificate, tree,
};

/// A store in memory with each certificate and its key attached.
fn store_of(pairs: Vec<(&str, Key)>) -> Store {
    let store = Store::memory().unwrap();
    for (crt, key) in pairs {
        let der = cert::parse(&std::fs::read(data(crt)).unwrap()).unwrap().der;
        store.add(&der).unwrap().attach(key).unwrap();
    }
    store
}

/// RSA, ECDH P-256 and ECDH P-384 keys behind the test certificates.
fn the_three() -> Store {
    store_of(vec![
        ("rsa.crt", import_rsa(&pkcs8_of("rsa.key"))),
        (
            "p256.crt",
            import_ec(&pkcs8_of("p256.key"), Curve::P256, true),
        ),
        (
            "p384.crt",
            import_ec(&pkcs8_of("p384.key"), Curve::P384, true),
        ),
    ])
}

fn cng(store: &Store) -> Option<Box<dyn KeySource + Send>> {
    Some(Box::new(CngSource::new(&[store], Vec::new())))
}

#[test]
fn archives_sealed_to_certificates_open_through_cng() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let store = the_three();
    for (i, (crt, kind)) in [
        ("rsa.crt", SlotKind::Rsa),
        ("p256.crt", SlotKind::EcP256),
        ("p384.crt", SlotKind::EcP384),
    ]
    .into_iter()
    .enumerate()
    {
        let archive = root.path().join(format!("{crt}.bhive"));
        create(
            &archive,
            &input,
            Some(Protection::New(vec![to_certificate(crt)])),
            None,
        )
        .unwrap();
        assert_eq!(slot_kinds(&archive), [Some(kind)]);
        // Opened silently: a software key needs nobody.
        let mut cx = KeyCtx::new(cng(&store));
        let got = extract(&archive, &root.path().join(format!("x{i}")), &mut cx).unwrap();
        assert_eq!(got, want, "{crt}");
        assert!(cx.asked.is_empty(), "{crt}: {:?}", cx.asked);
        // A store without the key: the way in is asked for, and isn't here.
        let empty = Store::memory().unwrap();
        let mut cx = KeyCtx::new(cng(&empty));
        let e = extract(&archive, &root.path().join(format!("y{i}")), &mut cx)
            .err()
            .unwrap();
        assert_eq!(e.kind, ErrorKind::KeyRequired, "{crt}: {}", e.message);
        assert!(!cx.asked[0].ways[0].here);
    }

    // One archive for all three: CNG opens it with the first that fits, the RSA slot.
    let archive = root.path().join("all.bhive");
    let ways = ["rsa.crt", "p256.crt", "p384.crt"]
        .map(to_certificate)
        .to_vec();
    create(&archive, &input, Some(Protection::New(ways)), None).unwrap();
    let source = Source::new(&archive, Vec::new(), &OpenOptions::default()).unwrap();
    let r = BhiveReader::open(source, &mut KeyCtx::new(cng(&store))).unwrap();
    assert_eq!(r.unlocked().unwrap().opened_by(), 0);
    // With only the P-384 key, that one.
    let p384 = store_of(vec![(
        "p384.crt",
        import_ec(&pkcs8_of("p384.key"), Curve::P384, true),
    )]);
    let source = Source::new(&archive, Vec::new(), &OpenOptions::default()).unwrap();
    let r = BhiveReader::open(source, &mut KeyCtx::new(cng(&p384))).unwrap();
    assert_eq!(r.unlocked().unwrap().opened_by(), 2);
}

/// An EC certificate whose key in CNG is ECDSA can't open its slot: silently it is nothing
/// here, so the archive's password still opens it; chosen as the way in, the Unlock prompt is
/// asked again for the password, and with no answer left it says why.
#[test]
fn an_ecdsa_key_never_opens_an_archive_and_its_other_ways_in_still_do() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let archive = root.path().join("ecdsa.bhive");
    create(
        &archive,
        &input,
        Some(Protection::New(vec![
            to_certificate("p256.crt"),
            small_password(HONEY),
        ])),
        None,
    )
    .unwrap();
    let ecdsa = || {
        store_of(vec![(
            "p256.crt",
            import_ec(&pkcs8_of("p256.key"), Curve::P256, false),
        )])
    };
    let store = ecdsa();
    let mut cx = KeyCtx::answering(cng(&store), vec![UnlockAnswer::Password(HONEY.into())]);
    let got = extract(&archive, &root.path().join("x"), &mut cx).unwrap();
    assert_eq!(got, want);
    assert_eq!(cx.asked.len(), 1);
    assert!(!cx.asked[0].ways[0].here, "an ECDSA key isn't offered");

    let store = ecdsa();
    let mut cx = KeyCtx::answering(cng(&store), vec![UnlockAnswer::Way(0)]);
    let e = extract(&archive, &root.path().join("y"), &mut cx)
        .err()
        .unwrap();
    assert!(e.message.contains("ECDSA"), "{}", e.message);
    assert_eq!(cx.asked.len(), 2, "asked again, for the password");

    let store = ecdsa();
    let mut cx = KeyCtx::answering(
        cng(&store),
        vec![UnlockAnswer::Way(0), UnlockAnswer::Password(HONEY.into())],
    );
    let got = extract(&archive, &root.path().join("z"), &mut cx).unwrap();
    assert_eq!(got, want);
}

/// Signed by certificates' keys in CNG: RSA-PSS, ECDSA P-256 and P-384, plain and sealed to a
/// certificate that CNG opens. Every signature checks, and Windows finds the self-signed signer
/// untrusted, so it is unknown, shown by its subject.
#[test]
fn archives_signed_through_cng_check_and_their_signers_are_unknown() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let opener = store_of(vec![("rsa.crt", import_rsa(&pkcs8_of("rsa.key")))]);
    for (i, (crt, file, algorithm)) in [
        ("rsa.crt", "rsa.key", Algorithm::RsaPss),
        ("p256-ecdsa.crt", "p256.key", Algorithm::EcdsaP256),
        ("p384.crt", "p384.key", Algorithm::EcdsaP384),
    ]
    .into_iter()
    .enumerate()
    {
        let key = match algorithm {
            Algorithm::RsaPss => import_rsa(&pkcs8_of(file)),
            Algorithm::EcdsaP256 => import_ec(&pkcs8_of(file), Curve::P256, false),
            _ => import_ec(&pkcs8_of(file), Curve::P384, false),
        };
        let (store, cert) = store_with(crt, key);
        let thumbprint = cert::parse(cert.der()).unwrap().thumbprint;
        let signer: Arc<dyn Signer> = signer_in(&store, &thumbprint, None).unwrap();
        let signing = || {
            Some(Signing {
                signers: vec![signer.clone()],
                time: None,
            })
        };

        let plain = root.path().join(format!("signed{i}.bhive"));
        create(&plain, &input, None, signing()).unwrap();
        let report = signatures(&plain, &mut KeyCtx::new(None));
        check_signed_by(&report, &signer, algorithm, &self_signed(crt));
        // Windows' chain engine, as trust asks it: a self-signed root nobody installed.
        let carried = sig::certificates(&report.signatures[0].signer).unwrap();
        assert_eq!(carried, vec![cert.der().to_vec()]);
        let c = chain(&carried).unwrap();
        assert!(!c.trusted() && !c.anchored() && !c.revoked(), "{crt}");

        let sealed = root.path().join(format!("sealed{i}.bhive"));
        create(
            &sealed,
            &input,
            Some(Protection::New(vec![to_certificate("rsa.crt")])),
            signing(),
        )
        .unwrap();
        let report = signatures(&sealed, &mut KeyCtx::new(cng(&opener)));
        check_signed_by(&report, &signer, algorithm, &self_signed(crt));
        let got = extract(
            &sealed,
            &root.path().join(format!("s{i}")),
            &mut KeyCtx::new(cng(&opener)),
        )
        .unwrap();
        assert_eq!(got, want);
    }
}

/// A "This PC" key: the archive is sealed to its public key, bound to this machine, and a
/// password; the TPM opens it silently (no PIN). Skipped where there's no TPM, as on CI's
/// runners.
#[test]
fn an_archive_sealed_to_this_pc_opens_through_the_tpm() {
    if tpm().is_none() {
        return;
    }
    let Some((name, spki, _doomed)) = this_pc_key(None) else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let archive = root.path().join("this-pc.bhive");
    let way = Labelled {
        recipient: Recipient::Ec {
            curve: Curve::P256,
            spki: spki.clone(),
            certificate: None,
            machine_bound: true,
        },
        label: Some("This PC".into()),
    };
    // Not alone: an archive only this PC opens is refused (docs/M14.md decision 11).
    let ways = vec![way, small_password(HONEY)];
    create(&archive, &input, Some(Protection::New(ways)), None).unwrap();
    assert_eq!(
        slot_kinds(&archive),
        [Some(SlotKind::EcP256), Some(SlotKind::Password)]
    );
    let ours = || -> Option<Box<dyn KeySource + Send>> {
        let keys = this_pc_keys()
            .into_iter()
            .filter(|k| k.name == name)
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);
        Some(Box::new(CngSource::new(&[], keys)))
    };
    let mut cx = KeyCtx::new(ours());
    let got = extract(&archive, &root.path().join("x"), &mut cx).unwrap();
    assert_eq!(got, want);
    assert!(cx.asked.is_empty(), "{:?}", cx.asked);
    let source = Source::new(&archive, Vec::new(), &OpenOptions::default()).unwrap();
    let r = BhiveReader::open(source, &mut KeyCtx::new(ours())).unwrap();
    let d = r.unlocked().unwrap().descriptions().unwrap();
    assert!(d[0].machine_bound);
    assert_eq!(d[0].certificate.as_deref(), Some(spki.as_slice()));
    assert_eq!(d[0].label.as_deref(), Some("This PC"));
}
