//! End to end with key files, on every system: archives sealed to certificates (RSA, P-256,
//! P-384) and opened through the envelope with a key-file source, and archives signed with a
//! certificate's key file, whose signatures check and whose self-signed signer is someone
//! nobody vouches for. The helpers are shared with CNG's end-to-end tests.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use beezip_core::{
    CreateOptions, Ctx, Error, ErrorKind, FsOptions, OpenOptions, OverwriteChoice, Progress,
    Result, Selection, WriteSpec,
    format::bhive::{
        BhiveReader, BhiveWriteOptions, Level,
        crypt::{
            KeySource, Labelled, Protection, Recipient, SlotKind, Strength, UnlockAnswer,
            UnlockRequest, envelope::KeyBlock,
        },
        sign::{Algorithm, Report, Signer, Signing, Status},
    },
    ops,
    source::Source,
};
use zeroize::Zeroizing;

use super::tests::data;
use crate::{
    identity::Store,
    trust::{Trust, trust},
};

pub(crate) const HONEY: &str = "honey";

/// A context with nobody at it but the answers it was given, one per attempt, and a key
/// source. It keeps every request it was asked.
pub(crate) struct KeyCtx {
    source: Option<Box<dyn KeySource + Send>>,
    answers: Vec<UnlockAnswer>,
    pub(crate) asked: Vec<UnlockRequest>,
}

impl KeyCtx {
    pub(crate) fn new(source: Option<Box<dyn KeySource + Send>>) -> Self {
        Self::answering(source, Vec::new())
    }

    pub(crate) fn answering(
        source: Option<Box<dyn KeySource + Send>>,
        answers: Vec<UnlockAnswer>,
    ) -> Self {
        Self {
            source,
            answers,
            asked: Vec::new(),
        }
    }
}

impl Ctx for KeyCtx {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn progress(&mut self, _: &Progress) {}

    fn warn(&mut self, _: String) {}

    fn password(&mut self, _: Option<&str>, _: u32) -> Result<String> {
        Err(Error::new(
            ErrorKind::PasswordRequired,
            "a password is required",
        ))
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        Err(Error::new(
            ErrorKind::Conflict,
            format!("`{}` already exists", existing.display()),
        ))
    }

    fn unlock(&mut self, request: &UnlockRequest) -> Result<UnlockAnswer> {
        self.asked.push(request.clone());
        self.answers
            .get(request.attempt as usize)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::KeyRequired, "nothing left to answer"))
    }

    fn key_source(&mut self) -> Option<&mut dyn KeySource> {
        self.source
            .as_mut()
            .map(|s| s.as_mut() as &mut dyn KeySource)
    }
}

/// A password at a cost a test can afford.
pub(crate) fn small_password(password: &str) -> Labelled {
    Labelled {
        recipient: Recipient::Password {
            password: Zeroizing::new(password.to_owned()),
            strength: Strength::Cost {
                memory_kib: 256,
                passes: 1,
                lanes: 2,
            },
        },
        label: Some("Password".into()),
    }
}

/// The way in for the certificate in the test file `crt`, labelled with its name.
pub(crate) fn to_certificate(crt: &str) -> Labelled {
    let certificate = super::certificate(&data(crt)).unwrap();
    Labelled {
        recipient: certificate.recipient(false).unwrap(),
        label: Some(crt.into()),
    }
}

/// A few files under `root/in`: words, noise, an empty one, several cells' worth.
pub(crate) fn tree(root: &Path) -> PathBuf {
    let input = root.join("in");
    fs::create_dir_all(input.join("sub")).unwrap();
    let words: Vec<u8> = b"the bees keep their honey in wax cells "
        .iter()
        .copied()
        .cycle()
        .take(50_000)
        .collect();
    let mut s = 0x9E37_79B9_7F4A_7C15_u64;
    let noise: Vec<u8> = (0..30_000)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect();
    fs::write(input.join("words.txt"), words).unwrap();
    fs::write(input.join("sub/noise.bin"), noise).unwrap();
    fs::write(input.join("sub/empty"), b"").unwrap();
    input
}

/// Every file under `dir`, by its path relative to it.
pub(crate) fn read_tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let path = e.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path.strip_prefix(dir).unwrap().to_string_lossy();
                out.insert(rel.replace('\\', "/"), fs::read(&path).unwrap());
            }
        }
    }
    out
}

/// `input` as a `.bhive` at `archive`, sealed and signed as given.
pub(crate) fn create(
    archive: &Path,
    input: &Path,
    protection: Option<Protection>,
    signing: Option<Signing>,
) -> Result<()> {
    let spec = WriteSpec::Bhive(BhiveWriteOptions {
        level: Level::Fast,
        threads: 2,
        cell_size: Some(16 << 10),
        protection,
        signing,
        ..BhiveWriteOptions::default()
    });
    ops::create(
        archive,
        &[input.to_path_buf()],
        &spec,
        &CreateOptions::default(),
        &mut KeyCtx::new(None),
    )
    .map(|_| ())
}

/// The kinds of the archive's slots, in order.
pub(crate) fn slot_kinds(archive: &Path) -> Vec<Option<SlotKind>> {
    let bytes = fs::read(archive).unwrap();
    let header: [u8; 16] = bytes[..16].try_into().unwrap();
    let block = KeyBlock::read(&header, &mut &bytes[16..]).unwrap();
    block.slots.iter().map(|(kind, _)| *kind).collect()
}

/// Whether the archive holds `name` in the clear.
pub(crate) fn in_the_clear(archive: &Path, name: &[u8]) -> bool {
    fs::read(archive)
        .unwrap()
        .windows(name.len())
        .any(|w| w == name)
}

/// Extracts `archive` with `cx` and gives back what came out.
pub(crate) fn extract(
    archive: &Path,
    dest: &Path,
    cx: &mut dyn Ctx,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let report = ops::extract(
        archive,
        dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        cx,
    )?;
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    Ok(read_tree(&dest.join("in")))
}

/// The archive's signatures, as a reader checks them, opened with `cx`.
pub(crate) fn signatures(archive: &Path, cx: &mut dyn Ctx) -> Report {
    let source = Source::new(archive, Vec::new(), &OpenOptions::default()).unwrap();
    BhiveReader::open(source, cx).unwrap().signatures().clone()
}

/// One valid signature by `signer`, with `algorithm`, that nobody vouches for: shown as `who`.
pub(crate) fn check_signed_by(
    report: &Report,
    signer: &Arc<dyn Signer>,
    algorithm: Algorithm,
    who: &str,
) {
    assert!(report.all_valid(), "{report:?}");
    assert_eq!(report.signatures.len(), 1);
    let s = &report.signatures[0];
    assert_eq!(s.status, Status::Valid);
    assert_eq!(s.algorithm, algorithm.id());
    assert_eq!(s.signer, signer.signer_bytes());
    let keys = tempfile::tempdir().unwrap();
    let store = Store::new(keys.path().to_owned());
    assert_eq!(
        trust(&store, s).unwrap(),
        Trust::Unknown { who: who.into() },
        "{algorithm:?}"
    );
}

/// What is shown for a self-signed test certificate.
pub(crate) fn self_signed(crt: &str) -> String {
    let c = super::certificate(&data(crt)).unwrap();
    assert_eq!(c.subject, c.issuer);
    format!("{} (self-signed)", c.subject)
}

/// RSA, P-256 and P-384: each archive is opened silently by its certificate's key file (one of
/// them under a password), and by nobody else.
#[test]
fn archives_sealed_to_certificates_open_with_their_key_files() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let keys = [
        ("rsa.crt", "rsa-pkcs1.key", None, SlotKind::Rsa),
        ("p256.crt", "p256-sec1.key", None, SlotKind::EcP256),
        (
            "p384.crt",
            "p384-encrypted.key",
            Some(HONEY),
            SlotKind::EcP384,
        ),
    ];
    for (i, (crt, key, password, kind)) in keys.into_iter().enumerate() {
        let archive = root.path().join(format!("{crt}.bhive"));
        create(
            &archive,
            &input,
            Some(Protection::New(vec![to_certificate(crt)])),
            None,
        )
        .unwrap();
        assert_eq!(slot_kinds(&archive), [Some(kind)]);
        assert!(!in_the_clear(&archive, b"words.txt"), "{crt}");

        // Opened silently: nobody is asked anything.
        let source = super::source(&[&data(key)], password).unwrap();
        let mut cx = KeyCtx::new(Some(source));
        let got = extract(&archive, &root.path().join(format!("x{i}")), &mut cx).unwrap();
        assert_eq!(got, want, "{crt}");
        assert!(cx.asked.is_empty(), "{crt}: {:?}", cx.asked);

        // The slot says whom it is for.
        let source = Source::new(&archive, Vec::new(), &OpenOptions::default()).unwrap();
        let mut cx = KeyCtx::new(Some(super::source(&[&data(key)], password).unwrap()));
        let r = BhiveReader::open(source, &mut cx).unwrap();
        let d = r.unlocked().unwrap().descriptions().unwrap();
        let der = super::certificate(&data(crt)).unwrap().der;
        assert_eq!(d[0].certificate.as_deref(), Some(der.as_slice()), "{crt}");
        assert_eq!(d[0].label.as_deref(), Some(crt));
        assert!(!d[0].machine_bound);

        // Another certificate's key isn't offered, so the way in is asked for, and there's
        // nobody to answer.
        let (other, other_password) = match i {
            0 => ("p256.key", None),
            _ => ("rsa.key", None),
        };
        let source = super::source(&[&data(other)], other_password).unwrap();
        let mut cx = KeyCtx::new(Some(source));
        let e = extract(&archive, &root.path().join(format!("y{i}")), &mut cx)
            .err()
            .unwrap();
        assert_eq!(e.kind, ErrorKind::KeyRequired, "{crt}: {}", e.message);
        assert_eq!(cx.asked.len(), 1);
        assert!(!cx.asked[0].ways[0].here, "{crt}");
        // With no key at all, the same.
        let e = extract(
            &archive,
            &root.path().join(format!("z{i}")),
            &mut KeyCtx::new(None),
        )
        .err()
        .unwrap();
        assert_eq!(e.kind, ErrorKind::KeyRequired, "{crt}: {}", e.message);
    }
}

/// One archive for three certificates and a password: any one key file opens it, and so does
/// the password.
#[test]
fn an_archive_for_several_certificates_opens_with_any_of_their_keys() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    let archive = root.path().join("all.bhive");
    let ways = vec![
        to_certificate("rsa.crt"),
        to_certificate("p256.crt"),
        to_certificate("p384.crt"),
        small_password(HONEY),
    ];
    create(&archive, &input, Some(Protection::New(ways)), None).unwrap();
    assert_eq!(
        slot_kinds(&archive),
        [
            Some(SlotKind::Rsa),
            Some(SlotKind::EcP256),
            Some(SlotKind::EcP384),
            Some(SlotKind::Password)
        ]
    );
    for (i, (key, password)) in [
        ("rsa.key", None),
        ("p256.key", None),
        ("p384-encrypted.key", Some(HONEY)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut cx = KeyCtx::new(Some(super::source(&[&data(key)], password).unwrap()));
        let got = extract(&archive, &root.path().join(format!("x{i}")), &mut cx).unwrap();
        assert_eq!(got, want, "{key}");
        assert!(cx.asked.is_empty());
    }
    let mut cx = KeyCtx::answering(None, vec![UnlockAnswer::Password(HONEY.into())]);
    let got = extract(&archive, &root.path().join("pw"), &mut cx).unwrap();
    assert_eq!(got, want);
    assert_eq!(cx.asked.len(), 1);
    assert_eq!(cx.asked[0].ways.len(), 4);
    assert!(cx.asked[0].ways.iter().all(|w| !w.here));
}

/// Signed with a certificate's key file: RSA-PSS, ECDSA P-256 and P-384, plain and sealed. Every
/// signature checks, and the self-signed signer is unknown, shown by its subject.
#[test]
fn archives_signed_with_key_files_check_and_their_signers_are_unknown() {
    let root = tempfile::tempdir().unwrap();
    let input = tree(root.path());
    let want = read_tree(&input);
    for (i, (crt, key, algorithm)) in [
        ("rsa.crt", "rsa.key", Algorithm::RsaPss),
        ("p256-ecdsa.crt", "p256.key", Algorithm::EcdsaP256),
        ("p384.crt", "p384.key", Algorithm::EcdsaP384),
    ]
    .into_iter()
    .enumerate()
    {
        let signer = super::signer(&data(crt), &data(key), None).unwrap();
        assert_eq!(signer.algorithm(), algorithm);
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
        let got = extract(
            &plain,
            &root.path().join(format!("p{i}")),
            &mut KeyCtx::new(None),
        )
        .unwrap();
        assert_eq!(got, want);

        // Sealed to another certificate as well: the signature is inside, and checks once the
        // archive is opened.
        let sealed = root.path().join(format!("sealed{i}.bhive"));
        create(
            &sealed,
            &input,
            Some(Protection::New(vec![to_certificate("p384.crt")])),
            signing(),
        )
        .unwrap();
        let signer_der = super::certificate(&data(crt)).unwrap().der;
        assert!(!in_the_clear(&sealed, &signer_der[..64]), "{crt}");
        let opener = || Some(super::source(&[&data("p384.key")], None).unwrap());
        let report = signatures(&sealed, &mut KeyCtx::new(opener()));
        check_signed_by(&report, &signer, algorithm, &self_signed(crt));
        let got = extract(
            &sealed,
            &root.path().join(format!("s{i}")),
            &mut KeyCtx::new(opener()),
        )
        .unwrap();
        assert_eq!(got, want);
    }

    // A chain: the leaf's key signs, both certificates are carried, and the leaf is shown with
    // its issuer, which nobody trusts either.
    let signer = super::signer(&data("chain.pem"), &data("p256.key"), None).unwrap();
    let chained = root.path().join("chained.bhive");
    create(
        &chained,
        &input,
        None,
        Some(Signing {
            signers: vec![signer.clone()],
            time: None,
        }),
    )
    .unwrap();
    let report = signatures(&chained, &mut KeyCtx::new(None));
    check_signed_by(
        &report,
        &signer,
        Algorithm::EcdsaP256,
        "BeeZip test leaf (issued by BeeZip test CA)",
    );
}
