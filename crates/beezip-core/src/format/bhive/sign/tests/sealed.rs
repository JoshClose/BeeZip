//! Encrypted and signed (docs/M14.md §11): both at once, the rewrites that keep the contents
//! and so the signatures, the edits that drop them, and archive.sign on an encrypted archive.

use super::*;
use crate::{
    ArchiveKind,
    edit::{ConvertOptions, ConvertReport, convert},
    format::bhive::crypt::{
        Labelled, Protection, Recipient, Strength,
        envelope::{KeyBlock, Unlocked},
    },
};

const HONEY: &str = "honey";
const CLOVER: &str = "clover";

/// A password at a cost a test can afford.
fn password(p: &str) -> Labelled {
    Labelled {
        recipient: Recipient::Password {
            password: Zeroizing::new(p.to_owned()),
            strength: Strength::Cost {
                memory_kib: 256,
                passes: 1,
                lanes: 2,
            },
        },
        label: None,
    }
}

fn sealed_spec(signing: Option<Signing>, protection: Option<Protection>) -> WriteSpec {
    WriteSpec::Bhive(BhiveWriteOptions {
        cell_size: Some(4096),
        threads: 1,
        signing,
        protection,
        ..BhiveWriteOptions::default()
    })
}

fn honey() -> Option<Protection> {
    Some(Protection::New(vec![password(HONEY)]))
}

fn cx(answer: Option<&str>) -> SimpleCtx {
    match answer {
        Some(a) => SimpleCtx::new().with_password(a),
        None => SimpleCtx::new(),
    }
}

fn create_as(t: &Tree, name: &str, spec: &WriteSpec) -> PathBuf {
    let out = t.dir.path().join(name);
    crate::ops::create(
        &out,
        &t.inputs,
        spec,
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    out
}

fn open_as(path: &Path, answer: Option<&str>) -> crate::Result<BhiveReader> {
    let source = Source::new(path, Vec::new(), &OpenOptions::default())?;
    BhiveReader::open(source, &mut cx(answer))
}

/// Section 3 as the archive has it.
fn section3(r: &BhiveReader) -> Vec<u8> {
    r.carried().expect("signed").section.clone()
}

fn unlocked(path: &Path, answer: &str) -> Arc<Unlocked> {
    open_as(path, Some(answer))
        .unwrap()
        .unlocked()
        .unwrap()
        .clone()
}

/// The tree's files, as they were written.
fn files(t: &Tree) -> Vec<Vec<u8>> {
    t.inputs.iter().map(|p| std::fs::read(p).unwrap()).collect()
}

/// `src` converted into a `.bhive` at `out` as `spec` says, entries copied as they are.
fn convert_as(
    src: &Path,
    out: &Path,
    spec: &WriteSpec,
    decrypt: bool,
    answer: Option<&str>,
) -> crate::Result<ConvertReport> {
    let opts = ConvertOptions {
        raw: true,
        decrypt,
        ..ConvertOptions::default()
    };
    let open = OpenOptions::default();
    convert(
        src,
        out,
        ArchiveKind::Bhive,
        spec,
        &opts,
        &open,
        &mut cx(answer),
    )
}

/// Opened with `answer`: every signature valid, by these signers in this order, a digest for
/// every cell, and every file as it was written.
fn check_signed(t: &Tree, path: &Path, answer: Option<&str>, by: &[&Arc<dyn Signer>]) {
    let mut r = open_as(path, answer).unwrap();
    let report = r.signatures().clone();
    assert!(report.all_valid(), "{report:?}");
    let who: Vec<Vec<u8>> = report.signatures.iter().map(|s| s.signer.clone()).collect();
    let want: Vec<Vec<u8>> = by.iter().map(|s| s.signer_bytes()).collect();
    assert_eq!(who, want);
    assert_eq!(report.digests.as_ref().unwrap().len(), r.cells().len());
    assert_eq!(read_all(&mut r).unwrap(), files(t));
}

#[test]
fn encrypted_and_signed_archives_round_trip() {
    let t = tree();
    let (key, cert) = (hybrid(), CertSigner::ec("p256"));
    let spec = sealed_spec(Some(signing(vec![key.clone(), cert.clone()])), honey());
    let path = create_as(&t, "s.bhive", &spec);
    check_signed(&t, &path, Some(HONEY), &[&key, &cert]);
    // Sealed with the index: who signed it isn't in the clear, and it opens only with a way
    // in.
    let bytes = std::fs::read(&path).unwrap();
    let signer = key.signer_bytes();
    assert!(!bytes.windows(64).any(|w| w == &signer[..64]));
    assert!(open_as(&path, None).is_err());
}

#[test]
fn rewrites_that_keep_the_contents_keep_the_signatures() {
    let t = tree();
    let key = hybrid();
    let plain = create(&t, "p.bhive", Some(signing(vec![key.clone()])));
    let was = section3(&open_as(&plain, None).unwrap());
    let cells = open_as(&plain, None).unwrap().cells().len();
    let same = |path: &Path, answer: Option<&str>| {
        check_signed(&t, path, answer, &[&key]);
        assert_eq!(section3(&open_as(path, answer).unwrap()), was);
    };

    // Encrypted: every cell copied as it is stored, and sealed.
    let e1 = t.dir.path().join("e1.bhive");
    let done = convert_as(&plain, &e1, &sealed_spec(None, honey()), false, None).unwrap();
    assert_eq!((done.copied, done.recompressed), (3, 0));
    same(&e1, Some(HONEY));
    assert_eq!(open_as(&e1, Some(HONEY)).unwrap().cells().len(), cells);

    // New key: a new file key, every cell sealed again under it.
    let e2 = t.dir.path().join("e2.bhive");
    let spec = sealed_spec(None, Some(Protection::New(vec![password(CLOVER)])));
    convert_as(&e1, &e2, &spec, false, Some(HONEY)).unwrap();
    same(&e2, Some(CLOVER));
    assert!(open_as(&e2, Some(HONEY)).is_err());

    // A way in added under the same file key: the cells go as they are sealed.
    let e3 = t.dir.path().join("e3.bhive");
    let change = Protection::Change {
        from: unlocked(&e2, CLOVER),
        remove: Vec::new(),
        add: vec![password(HONEY)],
    };
    let spec = sealed_spec(None, Some(change));
    convert_as(&e2, &e3, &spec, false, Some(CLOVER)).unwrap();
    same(&e3, Some(HONEY));
    same(&e3, Some(CLOVER));

    // Taken out of the seal: the manifest leaves the encryption out.
    let back = t.dir.path().join("back.bhive");
    convert_as(&e3, &back, &sealed_spec(None, None), true, Some(HONEY)).unwrap();
    same(&back, None);
}

#[test]
fn a_rewrite_adds_a_signer_beside_the_others_and_an_edit_drops_them() {
    let t = tree();
    let (one, two) = (hybrid(), CertSigner::ec("p384"));
    let spec = sealed_spec(Some(signing(vec![one.clone()])), honey());
    let e = create_as(&t, "e.bhive", &spec);
    let first = section3(&open_as(&e, Some(HONEY)).unwrap());

    // A second signer: the first signature stays byte for byte.
    let both = t.dir.path().join("both.bhive");
    let spec = sealed_spec(Some(signing(vec![two.clone()])), None);
    let done = convert_as(&e, &both, &spec, false, Some(HONEY)).unwrap();
    assert_eq!(done.recompressed, 0);
    check_signed(&t, &both, Some(HONEY), &[&one, &two]);
    let section = section3(&open_as(&both, Some(HONEY)).unwrap());
    assert_eq!(records(&section).unwrap()[0], records(&first).unwrap()[0]);

    // The first signer again: its new signature replaces its old one.
    let again = t.dir.path().join("again.bhive");
    let spec = sealed_spec(Some(signing(vec![one.clone()])), None);
    convert_as(&both, &again, &spec, false, Some(HONEY)).unwrap();
    check_signed(&t, &again, Some(HONEY), &[&two, &one]);

    // A rename changes the contents: the signatures go, unless it is signed again.
    let rename = EditOp::Rename {
        from: "c.txt".into(),
        to: "d.txt".into(),
    };
    let edit = |path: &Path, signing: Option<Signing>| {
        crate::edit::edit(
            path,
            &rename,
            &mut |_| Ok(sealed_spec(signing.clone(), None)),
            &EditOptions::default(),
            &mut cx(Some(HONEY)),
        )
        .unwrap();
    };
    edit(&again, None);
    let mut r = open_as(&again, Some(HONEY)).unwrap();
    assert!(!r.signatures().is_signed());
    assert!(r.carried().is_none());
    assert_eq!(read_all(&mut r).unwrap(), files(&t));
    edit(&both, Some(signing(vec![one.clone()])));
    check_signed(&t, &both, Some(HONEY), &[&one]);
}

#[test]
fn a_signed_copy_checks_each_cell_against_its_digest() {
    let t = tree();
    let path = create(&t, "p.bhive", Some(signing(vec![hybrid()])));
    let cell = open_as(&path, None).unwrap().cells()[2];
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[cell.offset as usize] ^= 1;
    std::fs::write(&path, &bytes).unwrap();

    // Signing anew vouches for the bytes in the file: no copy is made, in the clear or sealed.
    let out = t.dir.path().join("out.bhive");
    for protection in [None, honey()] {
        let spec = sealed_spec(Some(signing(vec![hybrid()])), protection);
        let e = convert_as(&path, &out, &spec, false, None).unwrap_err();
        assert!(e.message.contains("cell 2 isn't what was signed"), "{e}");
        assert!(!out.exists());
    }

    // Copied as it is, the archive keeps its signature, and the cell still fails.
    convert_as(&path, &out, &sealed_spec(None, None), false, None).unwrap();
    let mut r = open_as(&out, None).unwrap();
    assert!(r.signatures().all_valid());
    let e = read_all(&mut r).unwrap_err();
    assert!(
        e.message.contains("changed after the archive was signed"),
        "{e}"
    );
}

/// The slots' bytes, the archive id, and each sealed cell's bytes in the file.
fn layout_of(path: &Path) -> (Vec<Vec<u8>>, [u8; 32], Vec<Vec<u8>>) {
    let bytes = std::fs::read(path).unwrap();
    let header: [u8; 16] = bytes[..16].try_into().unwrap();
    let k = KeyBlock::read(&header, &mut &bytes[16..]).unwrap();
    let slots = k
        .slots
        .iter()
        .map(|(_, r)| k.bytes[r.clone()].to_vec())
        .collect();
    let cells = open_as(path, Some(HONEY))
        .unwrap()
        .cells()
        .iter()
        .map(|c| {
            let len = layout::sealed_len(u64::from(c.stored)) as usize;
            bytes[c.offset as usize..c.offset as usize + len].to_vec()
        })
        .collect();
    (slots, k.archive_id, cells)
}

#[test]
fn archive_sign_signs_an_encrypted_archive() {
    let t = tree();
    let (one, two) = (hybrid(), CertSigner::rsa("rsa2048", true));
    let path = create_as(&t, "e.bhive", &sealed_spec(None, honey()));
    let before = layout_of(&path);
    let run = |opts: SignOptions, answer: Option<&str>| sign(&path, &opts, &mut cx(answer));
    let adding = |s: &Arc<dyn Signer>| SignOptions {
        signing: signing(vec![s.clone()]),
        ..SignOptions::default()
    };

    // Without a way in, or with a wrong one, nothing changes.
    let bytes = std::fs::read(&path).unwrap();
    assert!(run(adding(&one), None).is_err());
    assert!(run(adding(&one), Some(CLOVER)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);

    let done = run(adding(&one), Some(HONEY)).unwrap();
    assert_eq!((done.added, done.removed, done.hashed), (1, 0, true));
    assert!(done.signatures.all_valid());
    check_signed(&t, &path, Some(HONEY), &[&one]);
    // The slots and the sealed cells stay as they are; the archive id is new.
    let after = layout_of(&path);
    assert_eq!(after.0, before.0);
    assert_eq!(after.2, before.2);
    assert_ne!(after.1, before.1);
    let first = section3(&open_as(&path, Some(HONEY)).unwrap());

    // A second signer beside the first, whose signature stays byte for byte.
    let done = run(adding(&two), Some(HONEY)).unwrap();
    assert_eq!((done.added, done.removed, done.hashed), (1, 0, false));
    check_signed(&t, &path, Some(HONEY), &[&one, &two]);
    let section = section3(&open_as(&path, Some(HONEY)).unwrap());
    assert_eq!(records(&section).unwrap()[0], records(&first).unwrap()[0]);

    // The first removed, then every one; the digests stay.
    let removing = SignOptions {
        remove: vec![0],
        ..SignOptions::default()
    };
    assert_eq!(run(removing, Some(HONEY)).unwrap().removed, 1);
    check_signed(&t, &path, Some(HONEY), &[&two]);
    let all = SignOptions {
        remove_all: true,
        ..SignOptions::default()
    };
    assert_eq!(run(all, Some(HONEY)).unwrap().removed, 1);
    let mut r = open_as(&path, Some(HONEY)).unwrap();
    assert!(!r.signatures().is_signed());
    assert!(r.signatures().digests.is_some());
    assert_eq!(read_all(&mut r).unwrap(), files(&t));
    assert_eq!(layout_of(&path).2, before.2);
}
