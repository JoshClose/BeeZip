//! Adding and removing signatures on an existing `.bhive` (`archive.sign`, docs/M14.md §11)
//! without touching its contents: the header and every cell block are copied byte for byte,
//! and only the index's sections 2 and 3 change. The signatures kept still verify, since the
//! manifest covers what doesn't change.

use std::io::{Read, Seek, SeekFrom, Write};

use super::{
    MAX_SIGNATURES, Report, Signing, assemble, check, digests, manifest_of, ready, record, records,
    sha256,
};
use crate::{
    Ctx, Error, ErrorKind, Limits, Result,
    format::bhive::{
        coder,
        crypt::not_built,
        layout::{
            self, Bytes, FEATURE_ENCRYPTED, FOOTER_LEN, HEADER_LEN, INDEX_HEAD_LEN, IndexHead,
            SECTION_DIGESTS, SECTION_SIGNATURES, checksum, parse_index, put_uvarint,
        },
    },
    io::{read_error, write_error},
};

/// What `archive.sign` changes.
#[derive(Debug, Clone, Default)]
pub struct Resign {
    /// New signatures, by these signers.
    pub signing: Signing,
    /// Signatures removed, by their place in the archive's list (from 0).
    pub remove: Vec<usize>,
    /// Remove every signature the archive has, before adding any.
    pub remove_all: bool,
    /// What reading the index may take, as when the archive is opened: `decoder_memory` for
    /// its raw bytes, `max_entries` for its entries.
    pub limits: Limits,
}

/// What `archive.sign` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resigned {
    /// The signatures afterwards, checked.
    pub report: Report,
    pub added: usize,
    /// The signatures the archive had that it no longer has: those named, every one when
    /// asked, and those over a section 2 that had to be made again.
    pub removed: usize,
    /// Section 2 was made: the archive had no whole digests. (Adding a signature reads every
    /// cell either way, to make the digests or to check the cells against them.)
    pub hashed: bool,
}

fn bad(what: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("bhive: {what}"))
}

fn read_at<R: Read + Seek>(input: &mut R, at: u64, len: usize) -> Result<Vec<u8>> {
    input
        .seek(SeekFrom::Start(at))
        .map_err(|e| read_error(&e))?;
    let mut out = vec![0; len];
    input.read_exact(&mut out).map_err(|e| read_error(&e))?;
    Ok(out)
}

/// SHA-256 of `len` bytes at `at`, a buffer at a time.
fn hash_at<R: Read + Seek>(input: &mut R, at: u64, len: u64, cx: &mut dyn Ctx) -> Result<[u8; 32]> {
    input
        .seek(SeekFrom::Start(at))
        .map_err(|e| read_error(&e))?;
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0; (1 << 20).min(len as usize)];
    let mut left = len;
    while left > 0 {
        cx.check()?;
        let n = buf.len().min(left as usize);
        input
            .read_exact(&mut buf[..n])
            .map_err(|e| read_error(&e))?;
        h.update(&buf[..n]);
        left -= n as u64;
    }
    let mut out = [0; 32];
    out.copy_from_slice(h.finish().as_ref());
    Ok(out)
}

/// The index `head` describes may be read: its raw bytes and its stored bytes within
/// `decoder_memory`, as the reader keeps them (read.rs).
fn memory_limit(head: &IndexHead, limits: &Limits) -> Result<()> {
    let need = head.raw.max(head.stored);
    if need > limits.decoder_memory {
        return Err(Error::limit(format!(
            "bhive: the index needs {} MiB (limit `decoder_memory`)",
            need.div_ceil(1 << 20)
        )));
    }
    Ok(())
}

/// How many signatures a section 3 that doesn't parse says it holds, when that much of it
/// reads and is within the limit.
fn claimed(body: &[u8]) -> Option<usize> {
    let n = Bytes::new(body).uvarint().ok()?;
    (1..=MAX_SIGNATURES as u64)
        .contains(&n)
        .then_some(n as usize)
}

/// Writes `input`, an unencrypted `.bhive` opened from its index, to `out` with its
/// signatures changed as `what` says. Every byte before the index block is copied as it is.
/// The signatures kept are kept byte for byte. Adding a signature reads every cell once: a
/// section 2 that is whole must match the cells, or nothing is signed (a signature vouches for
/// the bytes in the file, as the writer's does, not for what section 2 says of them); one that
/// isn't whole is made again, which drops the signatures over it.
pub fn resign<R: Read + Seek>(
    input: &mut R,
    out: &mut dyn Write,
    what: &Resign,
    cx: &mut dyn Ctx,
) -> Result<Resigned> {
    ready(&what.signing)?;
    let len = input.seek(SeekFrom::End(0)).map_err(|e| read_error(&e))?;
    if len < (HEADER_LEN + INDEX_HEAD_LEN + FOOTER_LEN) as u64 {
        return Err(bad("the file is too short to hold an index"));
    }
    let mut header = [0; HEADER_LEN];
    header.copy_from_slice(&read_at(input, 0, HEADER_LEN)?);
    let features = layout::check_header(&header)?;
    if features & FEATURE_ENCRYPTED != 0 {
        // The index is sealed, and an edit writes a new archive id (docs/bhive.md §12.2).
        return Err(not_built("signing an encrypted .bhive"));
    }
    let footer = read_at(input, len - FOOTER_LEN as u64, FOOTER_LEN)?;
    let offset = layout::parse_footer(&footer)
        .filter(|&o| o >= HEADER_LEN as u64 && o <= len - (INDEX_HEAD_LEN + FOOTER_LEN) as u64)
        .ok_or_else(|| bad("the footer doesn't point to an index"))?;
    let head = IndexHead::parse(&read_at(input, offset, INDEX_HEAD_LEN)?)?;
    let ends = offset
        .checked_add(INDEX_HEAD_LEN as u64)
        .and_then(|n| n.checked_add(head.stored))
        .and_then(|n| n.checked_add(FOOTER_LEN as u64));
    if ends != Some(len) {
        return Err(bad("the index and the footer don't end the file"));
    }
    // The limits the reader keeps: an index head may claim any raw size.
    memory_limit(&head, &what.limits)?;
    let stored = read_at(input, offset + INDEX_HEAD_LEN as u64, head.stored as usize)?;
    let raw = if head.zstd {
        coder::unzstd(&stored, head.raw as usize, "the index")?
    } else {
        stored
    };
    if checksum(&raw) != head.checksum {
        return Err(bad("the index fails its checksum"));
    }
    let index = parse_index(&raw, offset, what.limits.max_entries)?;

    // The signatures kept, as they are, and how many the archive had.
    let (mut kept, had): (Vec<Vec<u8>>, usize) = match index.section(SECTION_SIGNATURES) {
        None => (Vec::new(), 0),
        Some(body) => match records(body) {
            Ok(r) if what.remove_all => (Vec::new(), r.len()),
            Ok(r) => {
                let n = r.len();
                (r.into_iter().map(<[u8]>::to_vec).collect(), n)
            }
            Err(why) if what.remove_all => {
                // Opened, the archive lists them as one signature that couldn't be checked.
                let n = claimed(body);
                cx.warn(match n {
                    Some(n) => format!(
                        "the archive's {n} signatures can't be read ({why}); they are removed"
                    ),
                    None => format!(
                        "the archive's signatures can't be read ({why}), and how many there \
                         were is unknown; they are removed"
                    ),
                });
                (Vec::new(), n.unwrap_or(1))
            }
            Err(why) => {
                return Err(Error::invalid_args(format!(
                    "the archive's signatures can't be read ({why}); remove them all first"
                )));
            }
        },
    };
    let mut remove = what.remove.clone();
    remove.sort_unstable();
    remove.dedup();
    if !what.remove_all {
        if let Some(&n) = remove.iter().find(|&&n| n >= kept.len()) {
            return Err(Error::invalid_args(format!(
                "the archive has {} signatures; there is no signature {}",
                kept.len(),
                n + 1
            )));
        }
        for &n in remove.iter().rev() {
            kept.remove(n);
        }
    }

    // Section 2. Adding a signature reads every cell once: a whole section 2 is checked
    // against the cells, and one that isn't whole is made from them.
    let mut section2 = index.section(SECTION_DIGESTS).map(<[u8]>::to_vec);
    let have = section2
        .as_deref()
        .and_then(|d| digests(d, index.cells.len()));
    let mut hashed = false;
    if !what.signing.is_empty() {
        let mut all = Vec::with_capacity(index.cells.len() * 32);
        for (n, c) in index.cells.iter().enumerate() {
            let digest = hash_at(input, c.offset, u64::from(c.stored), cx)?;
            if have.as_ref().is_some_and(|d| d[n] != digest) {
                return Err(bad(format!(
                    "cell {n} doesn't match its digest in the index, so the archive isn't \
                     signed; test it to see what changed"
                )));
            }
            all.extend_from_slice(&digest);
        }
        if have.is_none() {
            if !kept.is_empty() {
                cx.warn(format!(
                    "the archive's {} signatures were made without whole cell digests; they \
                     are removed",
                    kept.len()
                ));
                kept.clear();
            }
            section2 = Some(all);
            hashed = true;
        }
    }
    let removed = had - kept.len();

    // The new signatures, of the manifest with that section 2.
    let entries = &raw[index.entry_bytes.clone()];
    let mut even: Vec<(u64, &[u8])> = index
        .sections
        .iter()
        .filter(|s| s.id % 2 == 0 && s.id != SECTION_DIGESTS)
        .map(|s| (s.id, s.body.as_slice()))
        .collect();
    if let Some(d) = &section2 {
        even.push((SECTION_DIGESTS, d));
        even.sort_by_key(|(id, _)| *id);
    }
    let manifest = manifest_of(
        u16::from_le_bytes([header[8], header[9]]),
        features,
        &index.cells,
        index.entry_count,
        entries,
        &even,
    )?;
    let time = what.signing.time.unwrap_or_else(super::now);
    let mut added = 0;
    for s in &what.signing.signers {
        cx.check()?;
        kept.push(record(s.as_ref(), &manifest, time)?);
        added += 1;
    }
    let section3 = if kept.is_empty() {
        None
    } else {
        Some(assemble(&kept)?)
    };

    // The index: everything to the end of the entries as it is, then the sections in order.
    let mut sections: Vec<(u64, &[u8])> = index
        .sections
        .iter()
        .filter(|s| s.id != SECTION_DIGESTS && s.id != SECTION_SIGNATURES)
        .map(|s| (s.id, s.body.as_slice()))
        .collect();
    if let Some(d) = &section2 {
        sections.push((SECTION_DIGESTS, d));
    }
    if let Some(s) = &section3 {
        sections.push((SECTION_SIGNATURES, s));
    }
    sections.sort_by_key(|(id, _)| *id);
    let mut new_raw = raw[..index.entry_bytes.end].to_vec();
    for (id, body) in &sections {
        put_uvarint(&mut new_raw, *id);
        put_uvarint(&mut new_raw, body.len() as u64);
        new_raw.extend_from_slice(body);
    }
    let packed = if head.zstd {
        zstd::bulk::compress(&new_raw, 6)
            .map_err(|e| Error::new(ErrorKind::Io, format!("bhive: zstd: {e}")))?
    } else {
        Vec::new()
    };
    let (body, zstd) = if head.zstd && packed.len() < new_raw.len() {
        (&packed[..], true)
    } else {
        (&new_raw[..], false)
    };
    let new_head = IndexHead {
        zstd,
        stored: body.len() as u64,
        raw: new_raw.len() as u64,
        checksum: checksum(&new_raw),
    };

    // Everything before the index, byte for byte, then the new index and footer.
    input.seek(SeekFrom::Start(0)).map_err(|e| read_error(&e))?;
    let mut buf = vec![0; 1 << 20];
    let mut left = offset;
    while left > 0 {
        cx.check()?;
        let n = buf.len().min(left as usize);
        input
            .read_exact(&mut buf[..n])
            .map_err(|e| read_error(&e))?;
        out.write_all(&buf[..n]).map_err(|e| write_error(&e))?;
        left -= n as u64;
    }
    out.write_all(&new_head.encode())
        .and_then(|()| out.write_all(body))
        .and_then(|()| out.write_all(&layout::footer(offset)))
        .and_then(|()| out.flush())
        .map_err(|e| write_error(&e))?;

    let new_index = parse_index(&new_raw, offset, None)?;
    debug_assert_eq!(
        sha256(entries),
        sha256(&new_raw[new_index.entry_bytes.clone()])
    );
    Ok(Resigned {
        report: check(&header, &new_raw, &new_index),
        added,
        removed,
        hashed,
    })
}
