//! Signing and checking: the specification's vectors and example, every algorithm, every limit
//! of bhive.md §13.3 and §13.4, and which changes keep a signature (docs/M14.md §11).

use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use ml_dsa::B32;
use ring::{
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, ED25519, EcdsaKeyPair,
        RSA_PKCS1_SHA256, RSA_PSS_SHA256, RsaKeyPair, UnparsedPublicKey,
    },
};
use zeroize::Zeroizing;

mod sealed;

use super::{
    edit::{Resign, resign},
    *,
};
use crate::{
    ArchiveReader, CreateOptions, ErrorKind, Limits, OpenOptions, SimpleCtx, WriteSpec,
    edit::{
        EditOp, EditOptions,
        sign::{SignOptions, sign},
    },
    format::bhive::{
        BhiveReader, BhiveWriteOptions,
        crypt::{
            mldsa::{HybridKey, HybridSigner},
            sig,
        },
        layout::{
            self, HEADER_LEN, INDEX_HEAD_LEN, IndexHead, RECORD_LEN, Record, checksum, parse_index,
        },
    },
    source::Source,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/bhive-m14")
        .join(name)
}

fn example() -> serde_json::Value {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("vectors.json")).unwrap()).unwrap();
    v["signed_example"].clone()
}

fn get(ex: &serde_json::Value, k: &str) -> Vec<u8> {
    hex(ex[k].as_str().unwrap())
}

/// A PEM file of `testdata/` as DER.
fn der(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/format/bhive/sign/testdata")
        .join(name);
    let pem = std::fs::read(path).unwrap();
    der::pem::decode_vec(&pem).unwrap().1
}

/// The example's key, signing ML-DSA deterministically as the specification's example does.
struct Deterministic(HybridKey);

impl Signer for Deterministic {
    fn algorithm(&self) -> Algorithm {
        Algorithm::MlDsa65Ed25519
    }

    fn signer_bytes(&self) -> Vec<u8> {
        self.0.public().unwrap().to_vec()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        self.0.sign_with(message, &B32::default())
    }
}

fn example_key() -> HybridKey {
    let ex = example();
    let mut seeds = Zeroizing::new([0; 64]);
    seeds[..32].copy_from_slice(&get(&ex, "ed25519_seed"));
    seeds[32..].copy_from_slice(&get(&ex, "mldsa_seed"));
    HybridKey { seeds }
}

/// A certificate's key in a file, signing through `ring` as `beezip-keys` would.
enum CertKey {
    Rsa(RsaKeyPair, bool),
    Ec(EcdsaKeyPair, Algorithm),
}

struct CertSigner {
    key: CertKey,
    certificates: Vec<Vec<u8>>,
}

impl CertSigner {
    fn rsa(name: &str, pss: bool) -> Arc<dyn Signer> {
        let key = RsaKeyPair::from_pkcs8(&der(&format!("{name}.key.pem"))).unwrap();
        Arc::new(Self {
            key: CertKey::Rsa(key, pss),
            certificates: vec![der(&format!("{name}.crt.pem"))],
        })
    }

    fn ec(name: &str) -> Arc<dyn Signer> {
        let (alg, algorithm) = match name {
            "p256" => (&ECDSA_P256_SHA256_FIXED_SIGNING, Algorithm::EcdsaP256),
            _ => (&ECDSA_P384_SHA384_FIXED_SIGNING, Algorithm::EcdsaP384),
        };
        let key =
            EcdsaKeyPair::from_pkcs8(alg, &der(&format!("{name}.key.pem")), &SystemRandom::new())
                .unwrap();
        Arc::new(Self {
            key: CertKey::Ec(key, algorithm),
            certificates: vec![der(&format!("{name}.crt.pem"))],
        })
    }
}

impl Signer for CertSigner {
    fn algorithm(&self) -> Algorithm {
        match &self.key {
            CertKey::Rsa(_, true) => Algorithm::RsaPss,
            CertKey::Rsa(_, false) => Algorithm::RsaPkcs1,
            CertKey::Ec(_, a) => *a,
        }
    }

    fn signer_bytes(&self) -> Vec<u8> {
        sig::signer_bytes(&self.certificates).unwrap()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        Ok(match &self.key {
            CertKey::Rsa(key, pss) => {
                let mut out = vec![0; key.public().modulus_len()];
                let padding: &dyn ring::signature::RsaEncoding = if *pss {
                    &RSA_PSS_SHA256
                } else {
                    &RSA_PKCS1_SHA256
                };
                key.sign(padding, &rng, message, &mut out).unwrap();
                out
            }
            CertKey::Ec(key, _) => key.sign(&rng, message).unwrap().as_ref().to_vec(),
        })
    }
}

/// A signer that claims to be another algorithm, or signs another way: what a broken
/// `beezip-keys` signer might do.
struct Claims {
    inner: Arc<dyn Signer>,
    algorithm: Algorithm,
}

impl Signer for Claims {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn signer_bytes(&self) -> Vec<u8> {
        self.inner.signer_bytes()
    }

    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        self.inner.sign(message)
    }
}

fn hybrid() -> Arc<dyn Signer> {
    Arc::new(HybridSigner::new(HybridKey::generate().unwrap()).unwrap())
}

fn every_algorithm() -> Vec<Arc<dyn Signer>> {
    vec![
        hybrid(),
        CertSigner::rsa("rsa2048", true),
        CertSigner::rsa("rsa2048", false),
        CertSigner::ec("p256"),
        CertSigner::ec("p384"),
    ]
}

fn signing(signers: Vec<Arc<dyn Signer>>) -> Signing {
    Signing {
        signers,
        time: Some(1_767_225_600),
    }
}

/// An archive's header, raw index and its parse.
fn index_of(bytes: &[u8]) -> ([u8; 16], Vec<u8>, Index) {
    let mut header = [0; HEADER_LEN];
    header.copy_from_slice(&bytes[..HEADER_LEN]);
    let offset = layout::parse_footer(&bytes[bytes.len() - 16..]).unwrap();
    let head = IndexHead::parse(&bytes[offset as usize..offset as usize + INDEX_HEAD_LEN]).unwrap();
    let stored = &bytes[offset as usize + INDEX_HEAD_LEN..bytes.len() - 16];
    let raw = if head.zstd {
        zstd::bulk::decompress(stored, head.raw as usize).unwrap()
    } else {
        stored.to_vec()
    };
    let index = parse_index(&raw, offset, None).unwrap();
    (header, raw, index)
}

/// The archive with its index's raw bytes replaced, its checksum right.
fn with_index(bytes: &[u8], raw: &[u8]) -> Vec<u8> {
    let offset = layout::parse_footer(&bytes[bytes.len() - 16..]).unwrap();
    let mut out = bytes[..offset as usize].to_vec();
    let head = IndexHead {
        zstd: false,
        stored: raw.len() as u64,
        raw: raw.len() as u64,
        checksum: checksum(raw),
    };
    out.extend_from_slice(&head.encode());
    out.extend_from_slice(raw);
    out.extend_from_slice(&layout::footer(offset));
    out
}

/// `raw` with its sections after the entries replaced by `sections`.
fn with_sections(raw: &[u8], index: &Index, sections: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = raw[..index.entry_bytes.end].to_vec();
    for (id, body) in sections {
        put_uvarint(&mut out, *id);
        put_uvarint(&mut out, body.len() as u64);
        out.extend_from_slice(body);
    }
    out
}

fn sections_of(index: &Index) -> Vec<(u64, Vec<u8>)> {
    index
        .sections
        .iter()
        .map(|s| (s.id, s.body.clone()))
        .collect()
}

fn statuses(r: &Report) -> Vec<Status> {
    r.signatures.iter().map(|s| s.status.clone()).collect()
}

fn not_checked(s: &Status) -> bool {
    matches!(s, Status::NotChecked(_))
}

/// Files of their own, in a folder that goes when it does.
struct Tree {
    dir: tempfile::TempDir,
    inputs: Vec<PathBuf>,
}

fn tree() -> Tree {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let mut inputs = Vec::new();
    for (name, len) in [("a.txt", 3000usize), ("b.bin", 70_000), ("c.txt", 5)] {
        let p = src.join(name);
        let data: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
        std::fs::write(&p, data).unwrap();
        inputs.push(p);
    }
    Tree { dir, inputs }
}

fn spec(signing: Option<Signing>) -> WriteSpec {
    WriteSpec::Bhive(BhiveWriteOptions {
        cell_size: Some(4096),
        threads: 1,
        signing,
        ..BhiveWriteOptions::default()
    })
}

/// A `.bhive` of the tree, signed by `signing`, as its bytes.
fn create(t: &Tree, name: &str, signing: Option<Signing>) -> PathBuf {
    let out = t.dir.path().join(name);
    crate::ops::create(
        &out,
        &t.inputs,
        &spec(signing),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    out
}

fn open_report(path: &Path, opts: &OpenOptions) -> crate::Result<(BhiveReader, Report)> {
    let r = BhiveReader::open(Source::new(path, Vec::new(), opts)?, &mut SimpleCtx::new())?;
    let report = r.signatures().clone();
    Ok((r, report))
}

fn read_all(r: &mut BhiveReader) -> crate::Result<Vec<Vec<u8>>> {
    let mut cx = SimpleCtx::new();
    let n = r.entries(&mut cx)?.len();
    let mut out = Vec::new();
    for id in 0..n {
        let mut data = Vec::new();
        r.open_entry(id, &mut cx)?
            .read_to_end(&mut data)
            .map_err(|e| crate::io::read_error(&e))?;
        out.push(data);
    }
    Ok(out)
}

// The specification's vectors and example.

#[test]
fn the_manifest_fingerprint_and_section_are_the_specifications() {
    let ex = example();
    let bytes = std::fs::read(fixture("spec-signed.bhive")).unwrap();
    let (header, raw, index) = index_of(&bytes);
    assert_eq!(raw, get(&ex, "index_raw"));
    assert_eq!(
        manifest(&header, &raw, &index).unwrap().to_vec(),
        get(&ex, "manifest")
    );
    // Feature bit 0 isn't in the manifest: encrypting changes nothing there.
    let mut encrypted = header;
    encrypted[12] |= 1;
    assert_eq!(
        manifest(&encrypted, &raw, &index).unwrap(),
        manifest(&header, &raw, &index).unwrap()
    );
    let mut other = header;
    other[13] = 1;
    assert_ne!(
        manifest(&other, &raw, &index).unwrap(),
        manifest(&header, &raw, &index).unwrap()
    );

    let signer = [get(&ex, "ed25519_public"), get(&ex, "mldsa_public")].concat();
    assert_eq!(fingerprint(&signer), ex["fingerprint"].as_str().unwrap());
    assert_eq!(
        signed_attributes(1_767_225_600),
        get(&ex, "signed_attributes")
    );

    // The writer's section 3, ML-DSA signed deterministically, is the example's byte for byte.
    let m: [u8; 32] = get(&ex, "manifest").try_into().unwrap();
    let s = Signing {
        signers: vec![Arc::new(Deterministic(example_key()))],
        time: Some(1_767_225_600),
    };
    let body = section(&s, &m).unwrap();
    let mut framed = Vec::new();
    put_uvarint(&mut framed, 3);
    put_uvarint(&mut framed, body.len() as u64);
    framed.extend_from_slice(&body);
    assert_eq!(framed, get(&ex, "section_3"));
}

#[test]
fn the_specifications_signed_example_checks() {
    let ex = example();
    let (mut r, report) =
        open_report(&fixture("spec-signed.bhive"), &OpenOptions::default()).unwrap();
    assert_eq!(statuses(&report), [Status::Valid]);
    let s = &report.signatures[0];
    assert_eq!(s.algorithm, 1);
    assert_eq!(s.time, Some(1_767_225_600));
    assert_eq!(
        s.signer,
        [get(&ex, "ed25519_public"), get(&ex, "mldsa_public")].concat()
    );
    assert_eq!(
        report.digests,
        Some(vec![get(&ex, "cell_digest").try_into().unwrap()])
    );
    assert!(report.all_valid());
    // It reads as spec-small.bhive does, every cell checked against its digest.
    let files = read_all(&mut r).unwrap();
    assert!(files.iter().any(|f| f == b"honeycomb\n"));
}

/// Ed25519 at its edges, as `ring` 0.17 checks it (bhive.md §13.4): cofactorless, `S` below
/// the group order, the encodings as `ring` takes them. A reader on another library must say
/// the same of each. Made by a short Python program from RFC 8032's first key.
#[test]
fn ed25519_edges_are_rings() {
    #[rustfmt::skip]
    let cases = [
        ("valid", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "6268697665312065646765", "0d20c4e0e5c868934f911081713fc25aa464dd1166b251cdc4501b10bec6974cbdefec1d27e9ae33353e73f7b0d8946dcb69c52011462f65e44cb08b70ed0d0e", true),
        ("S + L", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "6268697665312065646765", "0d20c4e0e5c868934f911081713fc25aa464dd1166b251cdc4501b10bec6974caac3e27a414cc18b0bdb6a9a8fd27382cb69c52011462f65e44cb08b70ed0d1e", false),
        ("S's top bit", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "6268697665312065646765", "0d20c4e0e5c868934f911081713fc25aa464dd1166b251cdc4501b10bec6974cbdefec1d27e9ae33353e73f7b0d8946dcb69c52011462f65e44cb08b70ed0d8e", false),
        ("R of mixed order", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "6268697665312065646765", "127c63622f6340975de2025fe51d933ba790918ce80820755e129a1e2aa49da805a46a1b7667528c14d25b2f5e50d2285496a2bfd5bb4ef3a6bf66a4f2218200", false),
        ("A of mixed order", "9158312a9a8d6e3b34c891d6d61444f8b8211c5117ebad15bdb0bd68b07e0245", "626869766531206564676500", "0d20c4e0e5c868934f911081713fc25aa464dd1166b251cdc4501b10bec6974c7ab7376a8302ad550f6ce7865a298db4c787e3d5ca23575211b8ebed0605280f", false),
        ("A the identity", "0100000000000000000000000000000000000000000000000000000000000000", "6268697665312065646765", "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", true),
        ("A of order 8, k ≡ 0", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "626869766531206564676502", "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", true),
        ("A not canonical", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "6268697665312065646765", "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", true),
        ("R not canonical", "0100000000000000000000000000000000000000000000000000000000000000", "6268697665312065646765", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000", false),
        ("A off the curve", "0200000000000000000000000000000000000000000000000000000000000000", "6268697665312065646765", "0d20c4e0e5c868934f911081713fc25aa464dd1166b251cdc4501b10bec6974cbdefec1d27e9ae33353e73f7b0d8946dcb69c52011462f65e44cb08b70ed0d0e", false),
    ];
    let got: Vec<(&str, bool)> = cases
        .iter()
        .map(|(name, public, message, signature, _)| {
            let ok = UnparsedPublicKey::new(&ED25519, hex(public))
                .verify(&hex(message), &hex(signature))
                .is_ok();
            (*name, ok)
        })
        .collect();
    let want: Vec<(&str, bool)> = cases.iter().map(|c| (c.0, c.4)).collect();
    assert_eq!(got, want);

    // The cases the Python reader is tested with (ed25519-edges.json): `ring` must give each
    // the verdict the file does.
    let shared = fixture("ed25519-edges.json");
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&shared).unwrap_or_else(|e| panic!("{}: {e}", shared.display())),
    )
    .unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 10, "{}", cases.len());
    for c in cases {
        let field = |k: &str| hex(c[k].as_str().unwrap());
        let ok = UnparsedPublicKey::new(&ED25519, field("public"))
            .verify(&field("message"), &field("signature"))
            .is_ok();
        assert_eq!(Some(ok), c["valid"].as_bool(), "{}", c["name"]);
    }
}

// Every algorithm, written and read.

#[test]
fn every_algorithm_signs_and_checks() {
    let t = tree();
    let path = create(&t, "all.bhive", Some(signing(every_algorithm())));
    let (mut r, report) = open_report(&path, &OpenOptions::default()).unwrap();
    assert_eq!(statuses(&report), vec![Status::Valid; 5]);
    let algorithms: Vec<u8> = report.signatures.iter().map(|s| s.algorithm).collect();
    assert_eq!(algorithms, [1, 2, 3, 4, 5]);
    assert!(
        report
            .signatures
            .iter()
            .all(|s| s.time == Some(1_767_225_600))
    );
    assert_eq!(report.digests.as_ref().unwrap().len(), r.cells().len());
    assert!(r.cells().len() > 3, "several cells: {}", r.cells().len());
    let files = read_all(&mut r).unwrap();
    for (data, input) in files.iter().zip(&t.inputs) {
        assert_eq!(data, &std::fs::read(input).unwrap());
    }
}

/// Signatures made by OpenSSL with the test keys: RSA-PSS and PKCS #1 v1.5, with exponents
/// of 65,537 and 3 (which `ring` won't sign with, and checks), and ECDSA as `r ‖ s`.
#[test]
fn openssl_signatures_check() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/format/bhive/sign/testdata/openssl-signatures.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let message = hex(v["message"].as_str().unwrap());
    let all = v["signatures"].as_array().unwrap();
    assert_eq!(all.len(), 6);
    for s in all {
        let algorithm = s["algorithm"].as_u64().unwrap() as u8;
        let spki = sig::spki_of(&der(s["certificate"].as_str().unwrap())).unwrap();
        let signature = hex(s["signature"].as_str().unwrap());
        assert!(
            sig::verify(algorithm, &spki, &message, &signature).unwrap(),
            "{s}"
        );
        let mut bad = signature.clone();
        bad[10] ^= 1;
        assert!(
            !sig::verify(algorithm, &spki, &message, &bad).unwrap(),
            "{s}"
        );
        assert!(!sig::verify(algorithm, &spki, b"another message", &signature).unwrap());
    }
}

#[test]
fn an_unsigned_archive_has_no_digests_or_signatures() {
    let t = tree();
    let path = create(&t, "plain.bhive", None);
    let (_, report) = open_report(&path, &OpenOptions::default()).unwrap();
    assert_eq!(report, Report::default());
    assert!(!report.is_signed());
    let (_, _, index) = index_of(&std::fs::read(&path).unwrap());
    assert!(index.section(SECTION_DIGESTS).is_none());
}

#[test]
fn a_signer_the_reader_would_refuse_fails_the_write() {
    let t = tree();
    let bad = |signer: Arc<dyn Signer>| {
        let out = t.dir.path().join("bad.bhive");
        crate::ops::create(
            &out,
            &t.inputs,
            &spec(Some(signing(vec![signer]))),
            &CreateOptions::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap_err()
    };
    // A P-256 key claiming P-384; an RSA key claiming PSS while signing PKCS #1 v1.5.
    let e = bad(Arc::new(Claims {
        inner: CertSigner::ec("p256"),
        algorithm: Algorithm::EcdsaP384,
    }));
    assert!(e.message.contains("curve"), "{e}");
    let e = bad(Arc::new(Claims {
        inner: CertSigner::rsa("rsa2048", false),
        algorithm: Algorithm::RsaPss,
    }));
    assert!(e.message.contains("doesn't check"), "{e}");
    // Too many signers is refused before anything is written.
    let many: Vec<Arc<dyn Signer>> = (0..17).map(|_| CertSigner::ec("p256")).collect();
    assert!(ready(&signing(many.clone())).is_err());
    let out = t.dir.path().join("many.bhive");
    assert!(
        crate::ops::create(
            &out,
            &t.inputs,
            &spec(Some(signing(many))),
            &CreateOptions::default(),
            &mut SimpleCtx::new(),
        )
        .is_err()
    );
    assert!(!out.exists());
}

// What keeps a signature, and what drops it.

/// The archive written again with every journal emptied: each cell moves, the contents don't
/// (journals are for recovery, and the manifest doesn't cover them).
fn relayout(bytes: &[u8]) -> Vec<u8> {
    let (header, raw, index) = index_of(bytes);
    let mut out = header.to_vec();
    let mut at = HEADER_LEN;
    let mut cells = Vec::new();
    for _ in &index.cells {
        let head: [u8; RECORD_LEN] = bytes[at..at + RECORD_LEN].try_into().unwrap();
        let (rec, _) = Record::parse(&head).unwrap();
        let data_at = at + RECORD_LEN + rec.journal_stored as usize;
        let data = &bytes[data_at..data_at + rec.stored as usize];
        at = data_at + rec.stored as usize;
        let empty = Record {
            journal_zstd: false,
            journal_items: 0,
            journal_raw: 0,
            journal_stored: 0,
            ..rec
        };
        out.extend_from_slice(&empty.encode(&[]));
        cells.push(empty.cell(out.len() as u64));
        out.extend_from_slice(data);
    }
    let entries = &raw[index.entry_bytes.clone()];
    let sections: Vec<(u64, &[u8])> = index
        .sections
        .iter()
        .map(|s| (s.id, s.body.as_slice()))
        .collect();
    let new_raw = layout::encode_index_with(&cells, None, index.entry_count, entries, &sections);
    let offset = out.len() as u64;
    let head = IndexHead {
        zstd: false,
        stored: new_raw.len() as u64,
        raw: new_raw.len() as u64,
        checksum: checksum(&new_raw),
    };
    out.extend_from_slice(&head.encode());
    out.extend_from_slice(&new_raw);
    out.extend_from_slice(&layout::footer(offset));
    out
}

#[test]
fn signatures_survive_a_change_of_layout() {
    let t = tree();
    let path = create(
        &t,
        "s.bhive",
        Some(signing(vec![hybrid(), CertSigner::ec("p256")])),
    );
    let bytes = std::fs::read(&path).unwrap();
    let moved = relayout(&bytes);
    assert_ne!(moved.len(), bytes.len());
    let (h0, r0, i0) = index_of(&bytes);
    let (h1, r1, i1) = index_of(&moved);
    assert_ne!(i0.cells[1].offset, i1.cells[1].offset);
    assert_eq!(
        manifest(&h0, &r0, &i0).unwrap(),
        manifest(&h1, &r1, &i1).unwrap()
    );
    let moved_path = t.dir.path().join("moved.bhive");
    std::fs::write(&moved_path, &moved).unwrap();
    let (mut r, report) = open_report(&moved_path, &OpenOptions::default()).unwrap();
    assert_eq!(statuses(&report), [Status::Valid, Status::Valid]);
    assert_eq!(read_all(&mut r).unwrap().len(), t.inputs.len());

    // Odd sections are outside the manifest: the level changed, one added.
    let mut sections = sections_of(&i0);
    for s in &mut sections {
        if s.0 == layout::SECTION_LEVEL {
            s.1 = vec![4];
        }
    }
    sections.push((7, b"a later version's".to_vec()));
    let raw = with_sections(&r0, &i0, &sections);
    let offset = layout::parse_footer(&bytes[bytes.len() - 16..]).unwrap();
    let index = parse_index(&raw, offset, None).unwrap();
    assert_eq!(
        statuses(&check(&h0, &raw, &index)),
        [Status::Valid, Status::Valid]
    );
}

#[test]
fn any_change_to_the_contents_fails_them() {
    let t = tree();
    let path = create(
        &t,
        "s.bhive",
        Some(signing(vec![hybrid(), CertSigner::rsa("rsa2048", true)])),
    );
    let bytes = std::fs::read(&path).unwrap();
    let (header, raw, index) = index_of(&bytes);
    let offset = layout::parse_footer(&bytes[bytes.len() - 16..]).unwrap();
    let checked = |raw: &[u8]| {
        let index = parse_index(raw, offset, None).unwrap();
        statuses(&check(&header, raw, &index))
    };
    assert_eq!(checked(&raw), [Status::Valid, Status::Valid]);
    let invalid = vec![Status::Invalid, Status::Invalid];

    // A byte of the entries: a path's last letter.
    let mut changed = raw.clone();
    let at = (index.entry_bytes.start..index.entry_bytes.end)
        .find(|&i| changed[i..].starts_with(b"a.txt"))
        .unwrap();
    changed[at] = b'z';
    assert_eq!(checked(&changed), invalid);

    // A cell's raw length or checksum in the table.
    for field in [12usize, 18] {
        let mut changed = raw.clone();
        let row = 1 + 26 * 2;
        changed[row + field] ^= 1;
        let i = parse_index(&changed, offset, None).unwrap();
        assert_ne!(i.cells[2], index.cells[2], "field {field}");
        assert_eq!(
            statuses(&check(&header, &changed, &i)),
            invalid,
            "field {field}"
        );
    }
    // Its coder's parameter. These cells' coders take only 0, so it is the parse that changes.
    let mut changed = index.clone();
    changed.cells[2].param ^= 1;
    assert_eq!(statuses(&check(&header, &raw, &changed)), invalid);

    // A digest in section 2, an even section added, the header's version.
    let mut sections = sections_of(&index);
    sections
        .iter_mut()
        .find(|s| s.0 == SECTION_DIGESTS)
        .unwrap()
        .1[40] ^= 1;
    assert_eq!(checked(&with_sections(&raw, &index, &sections)), invalid);
    let mut sections = sections_of(&index);
    sections.push((4, b"new contents".to_vec()));
    assert_eq!(checked(&with_sections(&raw, &index, &sections)), invalid);
    let mut other = header;
    other[8] = 2;
    assert_eq!(statuses(&check(&other, &raw, &index)), invalid);

    // A stored byte of a cell: its signatures still verify, and the cell fails its digest
    // when it is read, before it is decoded.
    let mut damaged = bytes.clone();
    let cell = &index.cells[1];
    damaged[cell.offset as usize + 5] ^= 1;
    let p = t.dir.path().join("damaged.bhive");
    std::fs::write(&p, &damaged).unwrap();
    let (mut r, report) = open_report(&p, &OpenOptions::default()).unwrap();
    assert_eq!(statuses(&report), [Status::Valid, Status::Valid]);
    let e = read_all(&mut r).unwrap_err();
    assert!(
        e.message.contains("changed after the archive was signed"),
        "{e}"
    );
}

#[test]
fn a_signature_moved_from_another_archive_fails() {
    let t = tree();
    let key: Arc<dyn Signer> = hybrid();
    let a = create(&t, "a.bhive", Some(signing(vec![key.clone()])));
    std::fs::write(&t.inputs[2], b"other").unwrap();
    let b = create(&t, "b.bhive", Some(signing(vec![key])));
    let a = std::fs::read(a).unwrap();
    let b = std::fs::read(b).unwrap();
    let (_, _, index_a) = index_of(&a);
    let (header_b, raw_b, index_b) = index_of(&b);
    let mut sections = sections_of(&index_b);
    let theirs = index_a.section(SECTION_SIGNATURES).unwrap().to_vec();
    sections
        .iter_mut()
        .find(|s| s.0 == SECTION_SIGNATURES)
        .unwrap()
        .1 = theirs;
    let raw = with_sections(&raw_b, &index_b, &sections);
    let moved = with_index(&b, &raw);
    let (_, raw, index) = index_of(&moved);
    assert_eq!(statuses(&check(&header_b, &raw, &index)), [Status::Invalid]);
}

#[test]
fn a_recovered_archive_is_unsigned() {
    let t = tree();
    let path = create(&t, "s.bhive", Some(signing(vec![CertSigner::ec("p384")])));
    let bytes = std::fs::read(&path).unwrap();
    let cut = t.dir.path().join("cut.bhive");
    std::fs::write(&cut, &bytes[..bytes.len() - 40]).unwrap();
    let opts = OpenOptions {
        recover: true,
        ..OpenOptions::default()
    };
    let (r, report) = open_report(&cut, &opts).unwrap();
    assert!(r.recovered().is_some());
    assert_eq!(report, Report::default());
}

// The limits of §13.3 and §13.4.

/// A record of `algorithm` by `signer` with these signed attributes, signed by `with`.
fn record_with(with: &dyn Signer, manifest: &[u8; 32], attributes: &[u8]) -> Vec<u8> {
    let algorithm = with.algorithm().id();
    let who = with.signer_bytes();
    let signature = with
        .sign(&message(algorithm, manifest, &who, attributes))
        .unwrap();
    let mut out = vec![algorithm, 0];
    put_bytes(&mut out, &who);
    put_bytes(&mut out, attributes);
    put_bytes(&mut out, &signature);
    put_bytes(&mut out, &[]);
    out
}

/// A signed archive's parts, and a way to check other section 3 bodies against them.
struct Signed {
    header: [u8; 16],
    raw: Vec<u8>,
    index: Index,
    manifest: [u8; 32],
}

impl Signed {
    fn new(t: &Tree) -> Self {
        let path = create(t, "l.bhive", Some(signing(vec![CertSigner::ec("p256")])));
        let (header, raw, index) = index_of(&std::fs::read(path).unwrap());
        let manifest = manifest(&header, &raw, &index).unwrap();
        Self {
            header,
            raw,
            index,
            manifest,
        }
    }

    /// The report with section 3 replaced by `body` (none: removed), and section 2 by
    /// `digests` when given.
    fn with(&self, body: Option<Vec<u8>>, digests: Option<Option<Vec<u8>>>) -> Report {
        let mut sections: Vec<(u64, Vec<u8>)> = sections_of(&self.index)
            .into_iter()
            .filter(|s| s.0 != SECTION_SIGNATURES && s.0 != SECTION_DIGESTS)
            .collect();
        let d = match digests {
            Some(d) => d,
            None => self.index.section(SECTION_DIGESTS).map(<[u8]>::to_vec),
        };
        if let Some(d) = d {
            sections.push((SECTION_DIGESTS, d));
        }
        if let Some(b) = body {
            sections.push((SECTION_SIGNATURES, b));
        }
        sections.sort_by_key(|s| s.0);
        let raw = with_sections(&self.raw, &self.index, &sections);
        let index = parse_index(&raw, u64::MAX / 2, None).unwrap();
        check(&self.header, &raw, &index)
    }

    fn of(&self, records: &[Vec<u8>]) -> Report {
        let mut body = Vec::new();
        put_uvarint(&mut body, records.len() as u64);
        for r in records {
            put_bytes(&mut body, r);
        }
        self.with(Some(body), None)
    }
}

#[test]
fn sixteen_signatures_at_most_and_a_mebibyte() {
    let t = tree();
    let s = Signed::new(&t);
    let p256 = CertSigner::ec("p256");
    let one = record(p256.as_ref(), &s.manifest, 0).unwrap();
    assert_eq!(
        statuses(&s.of(&vec![one.clone(); 16])),
        vec![Status::Valid; 16]
    );
    let seventeen = s.of(&vec![one.clone(); 17]);
    assert_eq!(seventeen.signatures.len(), 1);
    assert!(not_checked(&seventeen.signatures[0].status));
    assert!(assemble(&vec![one.clone(); 17]).is_err());
    assert!(not_checked(&s.of(&[]).signatures[0].status));

    // Over 1 MiB, with an unsigned attribute that makes it so.
    let mut big = one.clone();
    big.truncate(big.len() - 1);
    put_bytes(&mut big, &vec![0; MAX_SECTION_LEN]);
    let r = s.of(&[big.clone()]);
    assert_eq!(r.signatures.len(), 1);
    assert!(not_checked(&r.signatures[0].status));
    assert!(assemble(&[big]).is_err());

    // Unsigned attributes, whatever they hold, change nothing.
    let mut extra = one.clone();
    extra.truncate(extra.len() - 1);
    put_bytes(&mut extra, &[1, 3, 9, 9, 9]);
    assert_eq!(statuses(&s.of(&[extra])), [Status::Valid]);
    // Unsigned attributes that break the rules of fields: the record doesn't parse.
    let mut broken = one.clone();
    broken.truncate(broken.len() - 1);
    put_bytes(&mut broken, &[2, 0, 1, 0]);
    assert!(not_checked(&s.of(&[broken]).signatures[0].status));

    // Bytes after the last record, and a record cut short, which leaves the others.
    let mut body = Vec::new();
    put_uvarint(&mut body, 1);
    put_bytes(&mut body, &one);
    body.push(0);
    assert!(not_checked(&s.with(Some(body), None).signatures[0].status));
    let cut = one[..one.len() - 3].to_vec();
    let r = s.of(&[cut, one.clone()]);
    assert!(not_checked(&r.signatures[0].status));
    assert_eq!(r.signatures[1].status, Status::Valid);
}

#[test]
fn section_2_must_be_whole() {
    let t = tree();
    let s = Signed::new(&t);
    let one = record(CertSigner::ec("p256").as_ref(), &s.manifest, 0).unwrap();
    let body = {
        let mut b = Vec::new();
        put_uvarint(&mut b, 1);
        put_bytes(&mut b, &one);
        b
    };
    let mut short = s.index.section(SECTION_DIGESTS).unwrap().to_vec();
    short.pop();
    let r = s.with(Some(body.clone()), Some(Some(short)));
    assert!(not_checked(&r.signatures[0].status), "{r:?}");
    assert_eq!(r.digests, None);
    let r = s.with(Some(body), Some(None));
    assert!(not_checked(&r.signatures[0].status), "{r:?}");
    assert_eq!(r.digests, None);
    // Digests without signatures are still checked as cells are read.
    let r = s.with(None, None);
    assert!(r.signatures.is_empty());
    assert_eq!(r.digests.as_ref().unwrap().len(), s.index.cells.len());
}

#[test]
fn signed_attributes_with_odd_tags_are_critical() {
    let t = tree();
    let s = Signed::new(&t);
    let p256 = CertSigner::ec("p256");
    let time = signed_attributes(5);
    let with = |extra: &[(u64, &[u8])]| {
        let mut attributes = time.clone();
        for (tag, value) in extra {
            put_uvarint(&mut attributes, *tag);
            put_bytes(&mut attributes, value);
        }
        let r = s.of(&[record_with(p256.as_ref(), &s.manifest, &attributes)]);
        r.signatures[0].clone()
    };
    let ok = with(&[]);
    assert_eq!((ok.status, ok.time), (Status::Valid, Some(5)));
    assert_eq!(with(&[(2, b"later")]).status, Status::Valid);
    assert_eq!(with(&[(1_000, b"")]).status, Status::Valid);
    assert!(not_checked(&with(&[(3, b"critical")]).status));
    assert!(not_checked(&with(&[(2, b""), (2, b"")]).status));

    // Out of order, the time twice, a time that doesn't parse.
    let mut twice = time.clone();
    twice.extend_from_slice(&time);
    let r = s.of(&[record_with(p256.as_ref(), &s.manifest, &twice)]);
    assert!(not_checked(&r.signatures[0].status));
    let r = s.of(&[record_with(p256.as_ref(), &s.manifest, &[1, 2, 0x80, 0x80])]);
    assert!(not_checked(&r.signatures[0].status));
    // No attributes at all: no time, and it verifies.
    let r = s.of(&[record_with(p256.as_ref(), &s.manifest, &[])]);
    assert_eq!(
        (r.signatures[0].status.clone(), r.signatures[0].time),
        (Status::Valid, None)
    );
}

#[test]
fn unknown_algorithms_and_broken_signers_are_not_checked() {
    let t = tree();
    let s = Signed::new(&t);
    let mut unknown = record(CertSigner::ec("p256").as_ref(), &s.manifest, 0).unwrap();
    unknown[0] = 9;
    assert_eq!(statuses(&s.of(&[unknown])), [Status::UnknownAlgorithm(9)]);

    // A BeeZip key of the wrong length; a signature of the wrong length fails.
    let h = hybrid();
    let mut good = record(h.as_ref(), &s.manifest, 0).unwrap();
    assert_eq!(statuses(&s.of(&[good.clone()])), [Status::Valid]);
    let last = good.len() - 2;
    good[last] ^= 1;
    assert_eq!(statuses(&s.of(&[good])), [Status::Invalid]);
    let short = Claims {
        inner: Arc::new(Short(h.clone())),
        algorithm: Algorithm::MlDsa65Ed25519,
    };
    assert!(not_checked(
        &statuses(&s.of(&[record_with(&short, &s.manifest, &[])]))[0]
    ));
}

/// A BeeZip key whose signer field is a byte short.
struct Short(Arc<dyn Signer>);

impl Signer for Short {
    fn algorithm(&self) -> Algorithm {
        self.0.algorithm()
    }
    fn signer_bytes(&self) -> Vec<u8> {
        let mut b = self.0.signer_bytes();
        b.pop();
        b
    }
    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>> {
        self.0.sign(message)
    }
}

#[test]
fn eight_certificates_at_most() {
    let cert = der("p256.crt.pem");
    for n in 1..=8 {
        let b = sig::signer_bytes(&vec![cert.clone(); n]).unwrap();
        assert_eq!(sig::certificates(&b).unwrap().len(), n);
    }
    assert!(sig::signer_bytes(&vec![cert.clone(); 9]).is_err());
    assert!(sig::signer_bytes(&[]).is_err());
    let mut nine = Vec::new();
    put_uvarint(&mut nine, 9);
    for _ in 0..9 {
        put_bytes(&mut nine, &cert);
    }
    assert!(sig::certificates(&nine).is_err());
    assert!(sig::certificates(&[0]).is_err());
    let mut after = sig::signer_bytes(std::slice::from_ref(&cert)).unwrap();
    after.push(0);
    assert!(sig::certificates(&after).is_err());

    // Nine certificates in a signature: it couldn't be checked.
    let t = tree();
    let s = Signed::new(&t);
    let chain = CertSigner {
        key: CertKey::Ec(
            EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &der("p256.key.pem"),
                &SystemRandom::new(),
            )
            .unwrap(),
            Algorithm::EcdsaP256,
        ),
        certificates: vec![cert.clone(); 8],
    };
    assert_eq!(
        statuses(&s.of(&[record_with(&chain, &s.manifest, &[])])),
        [Status::Valid]
    );
    let mut rec = record_with(&chain, &s.manifest, &[]);
    // The same record with a ninth certificate spliced into its signer field.
    let who = nine.clone();
    rec = {
        let parts = parts(&rec).unwrap();
        let mut out = vec![parts.algorithm, 0];
        put_bytes(&mut out, &who);
        put_bytes(&mut out, parts.signed);
        put_bytes(&mut out, parts.signature);
        put_bytes(&mut out, &[]);
        out
    };
    assert!(not_checked(&statuses(&s.of(&[rec]))[0]));
}

/// A SubjectPublicKeyInfo for an RSA key of this modulus and exponent, big-endian.
fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = body.len();
        if n < 128 {
            out.push(n as u8);
        } else {
            let len = n.to_be_bytes();
            let skip = len.iter().position(|&b| b != 0).unwrap();
            out.push(0x80 | (len.len() - skip) as u8);
            out.extend_from_slice(&len[skip..]);
        }
        out.extend_from_slice(body);
        out
    }
    let int = |v: &[u8]| {
        let mut b = Vec::new();
        if v[0] & 0x80 != 0 {
            b.push(0);
        }
        b.extend_from_slice(v);
        tlv(0x02, &b)
    };
    let key = tlv(0x30, &[int(modulus), int(exponent)].concat());
    let alg = tlv(
        0x30,
        &[tlv(0x06, &hex("2a864886f70d010101")), tlv(0x05, &[])].concat(),
    );
    let bits = tlv(0x03, &[&[0u8][..], &key].concat());
    tlv(0x30, &[alg, bits].concat())
}

#[test]
fn rsa_keys_are_kept_to_the_limits() {
    let modulus = |bits: usize| {
        let mut m = vec![0xFFu8; bits.div_ceil(8)];
        let top = bits % 8;
        if top != 0 {
            m[0] = (1 << top) - 1;
        }
        m
    };
    let checks = |m: &[u8], e: &[u8]| sig::verify(2, &rsa_spki(m, e), b"m", &[0; 256]);
    // Within the limits: the key is used, and this signature doesn't verify.
    assert!(!checks(&modulus(2048), &[1, 0, 1]).unwrap());
    assert!(!checks(&modulus(8192), &[3]).unwrap());
    assert!(!checks(&modulus(2048), &hex("ffffffff")).unwrap());
    // Outside them: the signature couldn't be checked.
    for (bits, e) in [
        (2047, hex("010001")),
        (8193, hex("010001")),
        (1024, hex("010001")),
        (2048, hex("01")),
        (2048, hex("02")),
        (2048, hex("010000")),
        (2048, hex("0100000001")),
        (2048, hex("ffffffffffffffffff")),
    ] {
        let e = checks(&modulus(bits), &e);
        assert!(e.is_err(), "{bits} bits: {e:?}");
    }
    // A real 1,024-bit certificate, and the 2,048-bit one with exponent 3.
    let spki = sig::spki_of(&der("rsa1024.crt.pem")).unwrap();
    assert!(sig::verify(2, &spki, b"m", &[0; 128]).is_err());
    let spki = sig::spki_of(&der("rsa2048-e3.crt.pem")).unwrap();
    assert!(!sig::verify(3, &spki, b"m", &[0; 256]).unwrap());
}

#[test]
fn a_key_must_be_its_algorithms() {
    let spki = |name: &str| sig::spki_of(&der(&format!("{name}.crt.pem"))).unwrap();
    let refused = |alg: u8, name: &str| sig::verify(alg, &spki(name), b"m", &[0; 96]).is_err();
    for (alg, name) in [
        (2, "p256"),
        (3, "p384"),
        (4, "p384"),
        (4, "rsa2048"),
        (4, "ed25519"),
        (5, "p256"),
        (5, "ed25519"),
        (2, "ed25519"),
        (1, "p256"),
        (9, "p256"),
    ] {
        assert!(refused(alg, name), "{alg} {name}");
    }
    for (alg, name) in [(2, "rsa2048"), (3, "rsa2048"), (4, "p256"), (5, "p384")] {
        assert!(!refused(alg, name), "{alg} {name}");
    }
    assert!(sig::spki_of(b"not a certificate").is_err());
}

// archive.sign, and edits.

fn sign_with(path: &Path, opts: SignOptions) -> crate::Result<crate::edit::sign::SignReport> {
    sign(path, &opts, &mut SimpleCtx::new())
}

#[test]
fn archive_sign_adds_and_removes_and_keeps_the_contents() {
    let t = tree();
    let path = create(&t, "u.bhive", None);
    let before = std::fs::read(&path).unwrap();
    let (_, r0, i0) = index_of(&before);

    // Signing an archive with no digests reads its cells once.
    let first = hybrid();
    let done = sign_with(
        &path,
        SignOptions {
            signing: signing(vec![first.clone()]),
            ..SignOptions::default()
        },
    )
    .unwrap();
    assert!(done.hashed);
    assert_eq!((done.added, done.removed), (1, 0));
    assert_eq!(statuses(&done.signatures), [Status::Valid]);
    let after = std::fs::read(&path).unwrap();
    let offset = layout::parse_footer(&before[before.len() - 16..]).unwrap() as usize;
    assert_eq!(
        after[..offset],
        before[..offset],
        "every cell block as it was"
    );
    let (_, r1, i1) = index_of(&after);
    assert_eq!(r1[..i1.entry_bytes.end], r0[..i0.entry_bytes.end]);

    // A second signer keeps the first signature as it is.
    let done = sign_with(
        &path,
        SignOptions {
            signing: signing(vec![CertSigner::rsa("rsa2048", false)]),
            ..SignOptions::default()
        },
    )
    .unwrap();
    assert!(!done.hashed);
    assert_eq!(statuses(&done.signatures), [Status::Valid, Status::Valid]);
    assert_eq!(done.signatures.signatures[0].signer, first.signer_bytes());
    let (_, report) = open_report(&path, &OpenOptions::default()).unwrap();
    assert_eq!(report, done.signatures);

    // Removing the first leaves the second; removing all leaves none, and the digests.
    let done = sign_with(
        &path,
        SignOptions {
            remove: vec![0],
            ..SignOptions::default()
        },
    )
    .unwrap();
    assert_eq!(statuses(&done.signatures), [Status::Valid]);
    assert_eq!(done.signatures.signatures[0].algorithm, 3);
    assert!(
        sign_with(
            &path,
            SignOptions {
                remove: vec![1],
                ..SignOptions::default()
            },
        )
        .is_err()
    );
    let done = sign_with(
        &path,
        SignOptions {
            remove_all: true,
            ..SignOptions::default()
        },
    )
    .unwrap();
    assert_eq!(done.removed, 1);
    assert!(!done.signatures.is_signed());
    assert!(done.signatures.digests.is_some());
    let (mut r, _) = open_report(&path, &OpenOptions::default()).unwrap();
    let files = read_all(&mut r).unwrap();
    for (data, input) in files.iter().zip(&t.inputs) {
        assert_eq!(data, &std::fs::read(input).unwrap());
    }

    // Nothing to do, and an archive that isn't a .bhive.
    assert!(sign_with(&path, SignOptions::default()).is_err());
    let zip = t.dir.path().join("z.zip");
    crate::ops::create(
        &zip,
        &t.inputs,
        &WriteSpec::Zip(Default::default()),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let e = sign_with(
        &zip,
        SignOptions {
            signing: signing(vec![hybrid()]),
            ..SignOptions::default()
        },
    )
    .unwrap_err();
    assert!(e.message.contains("only a .bhive"), "{e}");

    // A cut archive, and one that says it is encrypted but has no key block, are left as they
    // are.
    let bytes = std::fs::read(&path).unwrap();
    let cut = t.dir.path().join("cut.bhive");
    std::fs::write(&cut, &bytes[..bytes.len() - 40]).unwrap();
    let mut encrypted = bytes.clone();
    encrypted[12] |= 1;
    let sealed = t.dir.path().join("sealed.bhive");
    std::fs::write(&sealed, &encrypted).unwrap();
    for (p, was) in [
        (&cut, &bytes[..bytes.len() - 40]),
        (&sealed, &encrypted[..]),
    ] {
        let opts = SignOptions {
            signing: signing(vec![hybrid()]),
            ..SignOptions::default()
        };
        assert!(sign_with(p, opts).is_err());
        assert_eq!(std::fs::read(p).unwrap(), was);
    }
}

#[test]
fn resign_keeps_a_zstd_index_and_checks_the_file() {
    let t = tree();
    let path = create(&t, "z.bhive", Some(signing(vec![CertSigner::ec("p384")])));
    let bytes = std::fs::read(&path).unwrap();
    let mut out = Vec::new();
    let done = resign(
        &mut std::io::Cursor::new(&bytes),
        &mut out,
        &Resign {
            signing: signing(vec![CertSigner::ec("p256")]),
            ..Resign::default()
        },
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(statuses(&done.report), [Status::Valid, Status::Valid]);
    let (_, _, index) = index_of(&out);
    assert!(index.section(SECTION_SIGNATURES).is_some());
    // A file that isn't a .bhive's end is refused, and nothing is written.
    let mut out = Vec::new();
    assert!(
        resign(
            &mut std::io::Cursor::new(&bytes[..bytes.len() - 1]),
            &mut out,
            &Resign::default(),
            &mut SimpleCtx::new(),
        )
        .is_err()
    );
    assert!(out.is_empty());
}

/// A `.bhive` of `bytes`'s header and an index head that claims a terabyte, over a zstd frame
/// that doesn't say its size: one raw block of one byte.
fn claims_a_terabyte(bytes: &[u8]) -> Vec<u8> {
    // The magic, a frame header with no content size and a 1 KiB window, the last block.
    let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x09, 0x00, 0x00, b'x'];
    assert_eq!(zstd::stream::decode_all(&frame[..]).unwrap(), b"x");
    let mut out = bytes[..HEADER_LEN].to_vec();
    let head = IndexHead {
        zstd: true,
        stored: frame.len() as u64,
        raw: 1 << 40,
        checksum: checksum(b"x"),
    };
    out.extend_from_slice(&head.encode());
    out.extend_from_slice(&frame);
    out.extend_from_slice(&layout::footer(HEADER_LEN as u64));
    out
}

#[test]
fn archive_sign_keeps_the_readers_limits() {
    let t = tree();
    let path = create(&t, "u.bhive", None);
    let bytes = std::fs::read(&path).unwrap();
    let add = |open: OpenOptions| SignOptions {
        open,
        signing: signing(vec![hybrid()]),
        ..SignOptions::default()
    };

    // An index that would take a terabyte to decode: refused before any of it is read.
    let hostile = claims_a_terabyte(&bytes);
    let p = t.dir.path().join("hostile.bhive");
    std::fs::write(&p, &hostile).unwrap();
    let e = open_report(&p, &OpenOptions::default()).err().unwrap();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    let e = sign_with(&p, add(OpenOptions::default())).unwrap_err();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    assert!(e.message.contains("the index needs 1048576 MiB"), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), hostile);
    let e = resign(
        &mut std::io::Cursor::new(&hostile),
        &mut Vec::new(),
        &Resign::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");

    // Entries over `max_entries`, as the reader counts them.
    let few = OpenOptions {
        limits: Limits {
            max_entries: Some(2),
            ..Limits::default()
        },
        ..OpenOptions::default()
    };
    let e = open_report(&path, &few).err().unwrap();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    let e = sign_with(&path, add(few)).unwrap_err();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    sign_with(&path, add(OpenOptions::default())).unwrap();
}

/// A new signature vouches for the bytes in the file, not for what section 2 says of them: a
/// section 2 that holds other cells' digests (cells of the same raw length and checksum, which
/// a reader that ignores section 2 would show the same) isn't signed.
#[test]
fn archive_sign_checks_the_cells_against_their_digests() {
    let t = tree();
    // An unsigned archive with digests: signed when it was made, its signature removed.
    let path = create(&t, "d.bhive", Some(signing(vec![hybrid()])));
    let done = sign_with(
        &path,
        SignOptions {
            remove_all: true,
            ..SignOptions::default()
        },
    )
    .unwrap();
    assert!(!done.signatures.is_signed() && done.signatures.digests.is_some());
    let bytes = std::fs::read(&path).unwrap();
    let (_, raw, index) = index_of(&bytes);
    assert!(index.cells.len() > 3);
    let add = || SignOptions {
        signing: signing(vec![hybrid()]),
        ..SignOptions::default()
    };
    let p = t.dir.path().join("other.bhive");

    // Section 2 with another cell 1.
    let mut sections = sections_of(&index);
    sections
        .iter_mut()
        .find(|s| s.0 == SECTION_DIGESTS)
        .unwrap()
        .1[32 + 7] ^= 1;
    let lying = with_index(&bytes, &with_sections(&raw, &index, &sections));
    std::fs::write(&p, &lying).unwrap();
    let e = sign_with(&p, add()).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    assert!(
        e.message.contains("cell 1 doesn't match its digest") && e.message.contains("test it"),
        "{e}"
    );
    assert_eq!(std::fs::read(&p).unwrap(), lying);

    // A cell changed after its digest was made.
    let mut damaged = bytes.clone();
    damaged[index.cells[2].offset as usize + 1] ^= 1;
    std::fs::write(&p, &damaged).unwrap();
    let e = sign_with(&p, add()).unwrap_err();
    assert!(e.message.contains("cell 2 doesn't match"), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), damaged);

    // Cells that match: signed, section 2 as it was.
    let done = sign_with(&path, add()).unwrap();
    assert!(!done.hashed);
    assert_eq!(statuses(&done.signatures), [Status::Valid]);
    let (_, _, after) = index_of(&std::fs::read(&path).unwrap());
    assert_eq!(
        after.section(SECTION_DIGESTS),
        index.section(SECTION_DIGESTS)
    );
}

#[test]
fn archive_sign_counts_every_signature_it_drops() {
    let t = tree();
    let path = create(
        &t,
        "r.bhive",
        Some(signing(vec![hybrid(), CertSigner::ec("p256")])),
    );
    let bytes = std::fs::read(&path).unwrap();
    let (_, raw, index) = index_of(&bytes);
    let p = t.dir.path().join("changed.bhive");

    // Section 2 cut short: signing makes it again, and drops both signatures over it.
    let mut sections = sections_of(&index);
    sections
        .iter_mut()
        .find(|s| s.0 == SECTION_DIGESTS)
        .unwrap()
        .1
        .pop();
    std::fs::write(
        &p,
        with_index(&bytes, &with_sections(&raw, &index, &sections)),
    )
    .unwrap();
    let mut cx = SimpleCtx::new();
    let opts = SignOptions {
        signing: signing(vec![CertSigner::ec("p384")]),
        ..SignOptions::default()
    };
    let done = sign(&p, &opts, &mut cx).unwrap();
    assert!(done.hashed);
    assert_eq!((done.added, done.removed), (1, 2));
    assert_eq!(statuses(&done.signatures), [Status::Valid]);
    assert!(
        cx.warnings
            .iter()
            .any(|w| w.contains("2 signatures were made without whole cell digests")),
        "{:?}",
        cx.warnings
    );

    // A section 3 that doesn't parse, all removed: as many as it says it holds, or the one
    // signature it is listed as when that can't be read either.
    for (says, removed) in [(2u64, 2usize), (40, 1)] {
        let mut sections = sections_of(&index);
        let body = &mut sections
            .iter_mut()
            .find(|s| s.0 == SECTION_SIGNATURES)
            .unwrap()
            .1;
        body.clear();
        put_uvarint(body, says);
        body.push(7);
        std::fs::write(
            &p,
            with_index(&bytes, &with_sections(&raw, &index, &sections)),
        )
        .unwrap();
        let (_, report) = open_report(&p, &OpenOptions::default()).unwrap();
        assert_eq!(report.signatures.len(), 1);
        assert!(not_checked(&report.signatures[0].status));
        let e = sign_with(
            &p,
            SignOptions {
                remove: vec![0],
                ..SignOptions::default()
            },
        )
        .unwrap_err();
        assert!(e.message.contains("remove them all first"), "{e}");
        let mut cx = SimpleCtx::new();
        let opts = SignOptions {
            remove_all: true,
            ..SignOptions::default()
        };
        let done = sign(&p, &opts, &mut cx).unwrap();
        assert_eq!(done.removed, removed, "says {says}");
        assert!(!done.signatures.is_signed());
        assert_eq!(cx.warnings.len(), 1, "{:?}", cx.warnings);
    }
}

#[test]
fn an_edit_of_the_contents_drops_the_signatures() {
    let t = tree();
    let path = create(&t, "e.bhive", Some(signing(vec![hybrid()])));
    crate::edit::edit(
        &path,
        &EditOp::Rename {
            from: "c.txt".into(),
            to: "d.txt".into(),
        },
        &mut |_| Ok(spec(None)),
        &EditOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let (mut r, report) = open_report(&path, &OpenOptions::default()).unwrap();
    assert!(!report.is_signed());
    assert_eq!(read_all(&mut r).unwrap().len(), 3);
}

// What signing costs (docs/M14.md §11): SHA-256 over every cell's stored bytes.

#[test]
#[ignore = "a timing, run by hand in release: cargo test --release -p beezip-core --lib -- --ignored signing_costs --nocapture"]
fn signing_costs() {
    use std::time::Instant;
    let big = vec![0x5Au8; 256 << 20];
    let best = |f: &mut dyn FnMut()| {
        (0..5)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed().as_secs_f64()
            })
            .fold(f64::MAX, f64::min)
    };
    let s = best(&mut || {
        cell_digest(&big).unwrap();
    });
    println!("SHA-256, one thread: {:.2} GiB/s", 0.25 / s);

    // The workspace's sources, or the folder `BEEZIP_SIGNING_INPUT` names, on one thread
    // (`BEEZIP_SIGNING_THREADS` for more): what signing adds to the work, which a busy machine
    // hides less than it hides a time on every core. Signed and unsigned take turns, the best
    // of seven each.
    let sources = std::env::var_os("BEEZIP_SIGNING_INPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
    let threads = std::env::var("BEEZIP_SIGNING_THREADS")
        .ok()
        .and_then(|t| t.parse().ok())
        .unwrap_or(1);
    let dir = tempfile::tempdir().unwrap();
    let key = hybrid();
    for level in [
        crate::format::bhive::Level::Fast,
        crate::format::bhive::Level::Balanced,
    ] {
        let mut times = [f64::MAX; 2];
        let mut size = 0;
        for _ in 0..7 {
            for (signed, best) in times.iter_mut().enumerate() {
                let spec = WriteSpec::Bhive(BhiveWriteOptions {
                    level,
                    threads,
                    signing: (signed == 1).then(|| signing(vec![key.clone()])),
                    ..BhiveWriteOptions::default()
                });
                let out = dir.path().join("t.bhive");
                let _ = std::fs::remove_file(&out);
                let t = Instant::now();
                crate::ops::create(
                    &out,
                    std::slice::from_ref(&sources),
                    &spec,
                    &CreateOptions::default(),
                    &mut SimpleCtx::new(),
                )
                .unwrap();
                *best = best.min(t.elapsed().as_secs_f64());
                size = std::fs::metadata(&out).unwrap().len();
            }
        }
        println!(
            "{level:?}, {threads} thread(s): {:.3} s, signed {:.3} s ({:+.1} %), {:.1} MiB \
             signed, its digests {:.1} ms at that rate",
            times[0],
            times[1],
            (times[1] / times[0] - 1.0) * 100.0,
            size as f64 / f64::from(1 << 20),
            size as f64 / f64::from(1 << 30) / (0.25 / s) * 1000.0
        );
    }
}
