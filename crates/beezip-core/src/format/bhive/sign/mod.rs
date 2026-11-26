//! Signatures on a `.bhive` (bhive.md §13, docs/M14.md §11): the cells' digests (index
//! section 2), the manifest, the signature section (3), and checking them. Encrypted or not.
//! Your BeeZip signing key signs through `crypt::mldsa`; certificates sign through
//! `beezip-keys` (PR D), which implements [`Signer`] for them.
//!
//! - The writer calls [`ready`] before it writes anything, [`cell_digest`] for every cell's
//!   stored bytes, then [`manifest_of`] and [`section`] for its index.
//! - The reader calls [`check`] with the index it found; each cell is checked against its
//!   digest as it is read.
//! - [`edit::resign`] adds and removes signatures on an existing archive (`archive.sign`).

pub mod edit;
#[cfg(test)]
mod tests;

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use super::layout::{Bytes, Cell, Index, SECTION_DIGESTS, SECTION_SIGNATURES, put_uvarint};
use crate::{
    Error, ErrorKind, Result,
    format::bhive::crypt::{label, mldsa, sig},
};

/// The message every algorithm signs is this long (bhive.md §13.3).
pub const MESSAGE_LEN: usize = 113;
/// What a reader checks at most (bhive.md §13.3, §13.4).
pub const MAX_SIGNATURES: usize = 16;
pub const MAX_CERTIFICATES: usize = 8;
pub const MAX_SECTION_LEN: usize = 1 << 20;
pub const RSA_BITS: std::ops::RangeInclusive<u32> = 2048..=8192;
/// An RSA exponent is odd and from 3 to 2^32 − 1.
pub const RSA_EXPONENT: std::ops::RangeInclusive<u64> = 3..=0xFFFF_FFFF;
/// Signed attribute 1: the time the signer says it signed (bhive.md §13.3).
pub const ATTRIBUTE_TIME: u64 = 1;

/// A signature algorithm (bhive.md §13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Your BeeZip signing key: ML-DSA-65 and Ed25519.
    MlDsa65Ed25519 = 1,
    RsaPss = 2,
    RsaPkcs1 = 3,
    EcdsaP256 = 4,
    EcdsaP384 = 5,
}

impl Algorithm {
    pub const ALL: [Self; 5] = [
        Self::MlDsa65Ed25519,
        Self::RsaPss,
        Self::RsaPkcs1,
        Self::EcdsaP256,
        Self::EcdsaP384,
    ];

    pub const fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.id() == id)
    }

    /// Whether a quantum computer can't forge it.
    pub const fn post_quantum(self) -> bool {
        matches!(self, Self::MlDsa65Ed25519)
    }
}

/// Makes one signature: your BeeZip key ([`mldsa::HybridSigner`]), or a certificate's key in
/// CNG, the Keychain or a file (`beezip-keys`, PR D).
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> Algorithm;
    /// The signer field: the public key, or the certificates (bhive.md §13.4).
    fn signer_bytes(&self) -> Vec<u8>;
    /// The signature of the 113-byte message. A smart card or TPM key may show Windows' PIN
    /// dialog here. ECDSA signatures are `r ‖ s`, not DER.
    fn sign(&self, message: &[u8; MESSAGE_LEN]) -> Result<Vec<u8>>;
}

/// What a writer signs with.
#[derive(Clone, Default)]
pub struct Signing {
    pub signers: Vec<Arc<dyn Signer>>,
    /// The signing time each signature claims, as seconds since 1970; `None` is now.
    pub time: Option<i64>,
}

impl std::fmt::Debug for Signing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algorithms: Vec<_> = self.signers.iter().map(|s| s.algorithm()).collect();
        f.debug_struct("Signing")
            .field("signers", &algorithms)
            .field("time", &self.time)
            .finish()
    }
}

impl Signing {
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
    out
}

/// SHA-256 of a cell's stored bytes, before sealing (bhive.md §13.2). The writer calls it for
/// every cell when it signs; the reader checks each cell against section 2 before decoding.
pub fn cell_digest(stored: &[u8]) -> Result<[u8; 32]> {
    Ok(sha256(stored))
}

/// The whole SHA-256 of a signer field: what `--require-signer` matches (bhive.md §13.5).
pub fn signer_id(signer: &[u8]) -> [u8; 32] {
    sha256(signer)
}

/// The fingerprint people compare (bhive.md §13.5): the first 10 bytes of the SHA-256 of the
/// signer bytes, in base32, as four groups of four: `VCPC-QSVP-2XKC-VCIZ`.
pub fn fingerprint(signer: &[u8]) -> String {
    const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let h = sha256(signer);
    let mut bits = 0u128;
    for &b in &h[..10] {
        bits = (bits << 8) | u128::from(b);
    }
    let mut out = String::with_capacity(19);
    for i in 0..16 {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(char::from(B32[((bits >> (75 - 5 * i)) & 31) as usize]));
    }
    out
}

fn too_many(n: usize) -> Error {
    Error::invalid_args(format!(
        "an archive carries at most {MAX_SIGNATURES} signatures, not {n}"
    ))
}

/// Whether a writer can sign with `signing`: every algorithm is built, and readers take that
/// many signatures. Called before anything is written, so a create that can't sign fails at
/// once.
pub fn ready(signing: &Signing) -> Result<()> {
    if signing.signers.len() > MAX_SIGNATURES {
        return Err(too_many(signing.signers.len()));
    }
    Ok(())
}

/// The manifest of an index (bhive.md §13.1), from the file's header, the index's raw bytes
/// and their parse.
pub fn manifest(header: &[u8; 16], raw: &[u8], index: &Index) -> Result<[u8; 32]> {
    let version = u16::from_le_bytes([header[8], header[9]]);
    let features = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    let entries = raw
        .get(index.entry_bytes.clone())
        .ok_or_else(|| Error::corrupt("bhive: the entries lie outside the index"))?;
    let even: Vec<(u64, &[u8])> = index
        .sections
        .iter()
        .filter(|s| s.id % 2 == 0)
        .map(|s| (s.id, s.body.as_slice()))
        .collect();
    manifest_of(
        version,
        features,
        &index.cells,
        index.entry_count,
        entries,
        &even,
    )
}

/// The manifest from a writer's parts: the header's version and features (bit 0 is cleared
/// here), its cells, its entries' items as encoded, and its sections with even ids, in order.
/// Odd ids among `even_sections` are left out.
pub fn manifest_of(
    version: u16,
    features: u32,
    cells: &[Cell],
    entry_count: u64,
    entries: &[u8],
    even_sections: &[(u64, &[u8])],
) -> Result<[u8; 32]> {
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(label::MANIFEST);
    h.update(&version.to_le_bytes());
    h.update(&(features & !super::layout::FEATURE_ENCRYPTED).to_le_bytes());
    h.update(&(cells.len() as u64).to_le_bytes());
    for c in cells {
        h.update(&c.raw.to_le_bytes());
        h.update(&[c.coder.id(), c.param]);
        h.update(&c.checksum.to_le_bytes());
    }
    h.update(&entry_count.to_le_bytes());
    h.update(&(entries.len() as u64).to_le_bytes());
    h.update(entries);
    let mut head = Vec::with_capacity(20);
    for (id, body) in even_sections.iter().filter(|(id, _)| id % 2 == 0) {
        head.clear();
        put_uvarint(&mut head, *id);
        put_uvarint(&mut head, body.len() as u64);
        h.update(&head);
        h.update(body);
    }
    let mut out = [0; 32];
    out.copy_from_slice(h.finish().as_ref());
    Ok(out)
}

/// The 113-byte message for `algorithm` (bhive.md §13.3): the label, the algorithm, the
/// manifest, and the SHA-256 of the signer bytes and of the signed attributes.
pub fn message(
    algorithm: u8,
    manifest: &[u8; 32],
    signer: &[u8],
    signed_attributes: &[u8],
) -> [u8; MESSAGE_LEN] {
    let mut m = [0; MESSAGE_LEN];
    let (l, rest) = m.split_at_mut(label::SIGNATURE.len());
    l.copy_from_slice(label::SIGNATURE);
    rest[0] = algorithm;
    rest[1..33].copy_from_slice(manifest);
    rest[33..65].copy_from_slice(&sha256(signer));
    rest[65..97].copy_from_slice(&sha256(signed_attributes));
    m
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_uvarint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// A `uvarint` length and that many bytes.
fn take_bytes<'a>(b: &mut Bytes<'a>) -> Result<&'a [u8]> {
    let n = b.uvarint()?;
    let n = usize::try_from(n).map_err(|_| Error::corrupt("bhive: a length too large"))?;
    b.take(n)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The signed attributes BeeZip writes: the time.
pub fn signed_attributes(time: i64) -> Vec<u8> {
    let mut value = Vec::with_capacity(10);
    super::layout::put_svarint(&mut value, time);
    let mut out = Vec::with_capacity(12);
    put_uvarint(&mut out, ATTRIBUTE_TIME);
    put_bytes(&mut out, &value);
    out
}

/// One signature record of section 3 (bhive.md §13.3), by `signer`, of `manifest`, claiming
/// `time`. It is checked as a reader would before it is kept, so a signer that returns the
/// wrong form (a DER ECDSA signature, a key outside the limits) fails here, not later.
pub fn record(signer: &dyn Signer, manifest: &[u8; 32], time: i64) -> Result<Vec<u8>> {
    let algorithm = signer.algorithm().id();
    let who = signer.signer_bytes();
    let attributes = signed_attributes(time);
    let signature = signer.sign(&message(algorithm, manifest, &who, &attributes))?;
    let mut out = Vec::with_capacity(who.len() + signature.len() + 32);
    out.extend_from_slice(&[algorithm, 0]);
    put_bytes(&mut out, &who);
    put_bytes(&mut out, &attributes);
    put_bytes(&mut out, &signature);
    put_bytes(&mut out, &[]);
    let info = check_record(&out, manifest, Ok(()));
    match info.status {
        Status::Valid => Ok(out),
        Status::Invalid => Err(Error::new(
            ErrorKind::Io,
            format!("bhive: the signature with algorithm {algorithm} doesn't check"),
        )),
        Status::UnknownAlgorithm(a) => Err(Error::unsupported(format!(
            "bhive: signature algorithm {a} is unknown"
        ))),
        Status::NotChecked(why) => Err(Error::invalid_args(format!(
            "this signer can't sign a .bhive: {why}"
        ))),
    }
}

/// Section 3's body from records already made: the count, then each record.
pub fn assemble(records: &[Vec<u8>]) -> Result<Vec<u8>> {
    if records.is_empty() || records.len() > MAX_SIGNATURES {
        return Err(too_many(records.len()));
    }
    let mut out = Vec::new();
    put_uvarint(&mut out, records.len() as u64);
    for r in records {
        put_bytes(&mut out, r);
    }
    if out.len() > MAX_SECTION_LEN {
        return Err(Error::limit(format!(
            "the signatures take {} bytes, over the {MAX_SECTION_LEN} a reader takes",
            out.len()
        )));
    }
    Ok(out)
}

/// Section 3's body: each signer's signature of the manifest, at `signing.time`.
pub fn section(signing: &Signing, manifest: &[u8; 32]) -> Result<Vec<u8>> {
    ready(signing)?;
    let time = signing.time.unwrap_or_else(now);
    let records = signing
        .signers
        .iter()
        .map(|s| record(s.as_ref(), manifest, time))
        .collect::<Result<Vec<_>>>()?;
    assemble(&records)
}

/// What became of one signature when the archive was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// It verifies, and section 2 is whole. Whether to trust the signer is the caller's
    /// question (docs/M14.md §11).
    Valid,
    /// It doesn't verify: the archive changed after it was signed, or the signature is
    /// damaged.
    Invalid,
    /// An algorithm this BeeZip doesn't know.
    UnknownAlgorithm(u8),
    /// It couldn't be checked, and why: section 2 or 3 is malformed, a critical (odd) signed
    /// attribute is unknown, a key is outside the limits or doesn't match the algorithm.
    NotChecked(String),
}

/// One signature, as section 3 holds it, and its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    pub algorithm: u8,
    /// The signer field: a public key, or certificates.
    pub signer: Vec<u8>,
    /// Signed attribute 1, as the signer claims it.
    pub time: Option<i64>,
    pub status: Status,
}

/// The signatures of an archive, checked against its index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub signatures: Vec<SignatureInfo>,
    /// Section 2, when the index has it: one digest per cell, in table order.
    pub digests: Option<Vec<[u8; 32]>>,
}

impl Report {
    /// Whether the archive carries signatures, whatever became of them.
    pub fn is_signed(&self) -> bool {
        !self.signatures.is_empty()
    }

    /// Whether every signature verifies.
    pub fn all_valid(&self) -> bool {
        self.is_signed() && self.signatures.iter().all(|s| s.status == Status::Valid)
    }
}

/// Section 2 as digests, when it holds one for each of `cells` cells.
pub fn digests(body: &[u8], cells: usize) -> Option<Vec<[u8; 32]>> {
    if Some(body.len()) != cells.checked_mul(32) {
        return None;
    }
    Some(body.as_chunks::<32>().0.to_vec())
}

/// Section 3's records, or why it doesn't parse as a whole (bhive.md §13.3).
pub fn records(body: &[u8]) -> std::result::Result<Vec<&[u8]>, String> {
    if body.len() > MAX_SECTION_LEN {
        return Err(format!(
            "the signatures take {} bytes, over {MAX_SECTION_LEN}",
            body.len()
        ));
    }
    let mut b = Bytes::new(body);
    let count = b.uvarint().map_err(|e| e.message)?;
    if count == 0 || count > MAX_SIGNATURES as u64 {
        return Err(format!(
            "the archive says it has {count} signatures, not 1 to {MAX_SIGNATURES}"
        ));
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(take_bytes(&mut b).map_err(|e| e.message)?);
    }
    if b.left() != 0 {
        return Err("bytes after the last signature".into());
    }
    Ok(out)
}

/// The parts of one signature record.
struct Parts<'a> {
    algorithm: u8,
    signer: &'a [u8],
    signed: &'a [u8],
    signature: &'a [u8],
}

fn parts(record: &[u8]) -> Result<Parts<'_>> {
    let mut b = Bytes::new(record);
    let algorithm = b.u8()?;
    let _reserved = b.u8()?;
    let signer = take_bytes(&mut b)?;
    let signed = take_bytes(&mut b)?;
    let signature = take_bytes(&mut b)?;
    // Unsigned attributes: none is known yet, and they never change the status.
    let _unsigned = take_bytes(&mut b)?;
    if b.left() != 0 {
        return Err(Error::corrupt("bytes after a signature record"));
    }
    Ok(Parts {
        algorithm,
        signer,
        signed,
        signature,
    })
}

/// The time a record's signed attributes claim, or why the signature can't be checked: they
/// don't parse, or one this reader doesn't know is critical (an odd tag).
fn attributes(signed: &[u8]) -> std::result::Result<Option<i64>, String> {
    let mut b = Bytes::new(signed);
    let mut last = None;
    let mut time = None;
    while b.left() > 0 {
        let tag = b.uvarint().map_err(|e| e.message)?;
        let value = take_bytes(&mut b).map_err(|e| e.message)?;
        if last.is_some_and(|l| l >= tag) {
            return Err(format!("signed attribute {tag} is out of order"));
        }
        last = Some(tag);
        match tag {
            ATTRIBUTE_TIME => {
                let mut v = Bytes::new(value);
                let t = v.svarint().map_err(|e| e.message)?;
                if v.left() != 0 {
                    return Err("the signing time doesn't parse".into());
                }
                time = Some(t);
            }
            t if t % 2 == 1 => {
                return Err(format!(
                    "it has signed attribute {t}, which this BeeZip doesn't know and must"
                ));
            }
            _ => {}
        }
    }
    Ok(time)
}

/// Whether one signature verifies, by its algorithm.
fn verify(parts: &Parts<'_>, message: &[u8; MESSAGE_LEN]) -> Status {
    let Some(algorithm) = Algorithm::from_id(parts.algorithm) else {
        return Status::UnknownAlgorithm(parts.algorithm);
    };
    let checked = match algorithm {
        Algorithm::MlDsa65Ed25519 => {
            if parts.signer.len() != mldsa::PUBLIC_LEN {
                return Status::NotChecked(format!(
                    "a signing key of {} bytes, not {}",
                    parts.signer.len(),
                    mldsa::PUBLIC_LEN
                ));
            }
            mldsa::verify(parts.signer, message, parts.signature)
        }
        _ => sig::certificates(parts.signer)
            .and_then(|certs| sig::spki_of(&certs[0]))
            .and_then(|spki| sig::verify(parts.algorithm, &spki, message, parts.signature)),
    };
    match checked {
        Ok(true) => Status::Valid,
        Ok(false) => Status::Invalid,
        Err(e) => Status::NotChecked(
            e.message
                .strip_prefix("bhive: ")
                .unwrap_or(&e.message)
                .to_owned(),
        ),
    }
}

/// One record of section 3, checked against `manifest`. `digests` is why section 2 isn't
/// whole, when it isn't: a signature then can't be checked.
fn check_record(
    record: &[u8],
    manifest: &[u8; 32],
    digests: std::result::Result<(), &str>,
) -> SignatureInfo {
    let parts = match parts(record) {
        Ok(p) => p,
        Err(e) => {
            return SignatureInfo {
                algorithm: record.first().copied().unwrap_or(0),
                signer: Vec::new(),
                time: None,
                status: Status::NotChecked(format!("the signature doesn't parse: {}", e.message)),
            };
        }
    };
    let mut info = SignatureInfo {
        algorithm: parts.algorithm,
        signer: parts.signer.to_vec(),
        time: None,
        status: Status::Valid,
    };
    if Algorithm::from_id(parts.algorithm).is_none() {
        info.status = Status::UnknownAlgorithm(parts.algorithm);
        return info;
    }
    match attributes(parts.signed) {
        Ok(time) => info.time = time,
        Err(why) => {
            info.status = Status::NotChecked(why);
            return info;
        }
    }
    if let Err(why) = digests {
        info.status = Status::NotChecked(why.to_owned());
        return info;
    }
    let message = message(parts.algorithm, manifest, parts.signer, parts.signed);
    info.status = verify(&parts, &message);
    info
}

/// Reads sections 2 and 3 from `index` and checks every signature against the manifest of
/// `header` and `raw`. Never fails the archive: a signature that can't be checked says so in
/// its status, and a section 3 that doesn't parse at all is one signature that couldn't be
/// checked, of algorithm 0. A recovered archive has no index, and is unsigned.
pub fn check(header: &[u8; 16], raw: &[u8], index: &Index) -> Report {
    let section2 = index.section(SECTION_DIGESTS);
    let section3 = index.section(SECTION_SIGNATURES);
    let digests = section2.and_then(|d| digests(d, index.cells.len()));
    let Some(section3) = section3 else {
        return Report {
            signatures: Vec::new(),
            digests,
        };
    };
    let not_checked = |why: String| SignatureInfo {
        algorithm: 0,
        signer: Vec::new(),
        time: None,
        status: Status::NotChecked(why),
    };
    let records = match records(section3) {
        Ok(r) => r,
        Err(why) => {
            return Report {
                signatures: vec![not_checked(why)],
                digests,
            };
        }
    };
    let manifest = match manifest(header, raw, index) {
        Ok(m) => m,
        Err(e) => {
            return Report {
                signatures: vec![not_checked(e.message)],
                digests,
            };
        }
    };
    let whole = match (section2, &digests) {
        (_, Some(_)) => Ok(()),
        (None, None) => Err("the archive has no cell digests (index section 2)"),
        (Some(_), None) => Err("the cell digests (index section 2) don't match the cells"),
    };
    Report {
        signatures: records
            .iter()
            .map(|r| check_record(r, &manifest, whole))
            .collect(),
        digests,
    }
}
