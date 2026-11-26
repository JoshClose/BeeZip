//! Suite 1's primitives (bhive.md §12.1): AES-256-GCM through `ring`, HMAC-SHA256, HKDF-SHA256,
//! random bytes, and comparisons in constant time. Sealing in segments (§12.8) is here too.
//!
//! Under a fuzzer, opening a sealed part takes its bytes as they are, without the tag, and every
//! MAC and commitment compares equal, as checksums do (`layout::sums`): a fuzzer can't make a tag
//! fit, and what lies behind one (the slots' framing, a record, the index, a cell's decoder) is
//! what it is there to reach. Every other check still runs.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{SEGMENT, TAG_LEN};
use crate::{Error, ErrorKind, Result, format::bhive::layout::bad};

/// A sealed segment's length: 1 MiB and its tag.
pub const SEALED_SEGMENT: usize = SEGMENT + TAG_LEN;

fn failed(what: &str) -> Error {
    Error::new(ErrorKind::Io, format!("bhive: {what} failed"))
}

thread_local! {
    /// A seed and a counter, while [`seeded`] runs on this thread.
    static SEEDED: std::cell::RefCell<Option<([u8; 32], u64)>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` with this thread's random bytes made from `seed`, so that `cargo xtask
/// gen-fixtures` writes the same encrypted fixtures every time. Never for an archive anyone
/// keeps: its keys are as good as the seed is secret.
#[doc(hidden)]
pub fn seeded<T>(seed: [u8; 32], f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            SEEDED.with(|s| *s.borrow_mut() = None);
        }
    }
    SEEDED.with(|s| *s.borrow_mut() = Some((seed, 0)));
    let _reset = Reset;
    f()
}

/// `N` bytes from the system's random generator.
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    let seeded = SEEDED.with(|s| {
        let mut s = s.borrow_mut();
        let (seed, counter) = s.as_mut()?;
        for (i, chunk) in out.chunks_mut(32).enumerate() {
            let block = hmac(
                &seed[..],
                &[&counter.to_le_bytes(), &(i as u64).to_le_bytes()],
            );
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        *counter += 1;
        Some(())
    });
    if seeded.is_some() {
        return Ok(out);
    }
    getrandom::fill(&mut out).map_err(|e| {
        Error::new(
            ErrorKind::Io,
            format!("bhive: the system's random generator failed: {e}"),
        )
    })?;
    Ok(out)
}

/// HMAC-SHA256 of the parts, one after another.
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let mut m = ring::hmac::Context::with_key(&key);
    for p in parts {
        m.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(m.sign().as_ref());
    out
}

/// `HKDF(ikm, salt, info)`: Extract, then Expand to 32 bytes (bhive.md §12.1).
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out[..])
        .unwrap_or_else(|_| unreachable!("32 bytes is a length HKDF-SHA256 expands to"));
    out
}

/// HKDF-Expand of a PRK to 64 bytes: a slot's wrap key, then its commitment (§12.4 step 3).
pub fn expand64(prk: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0u8; 64]);
    hkdf::Hkdf::<Sha256>::from_prk(prk)
        .unwrap_or_else(|_| unreachable!("a 32-byte PRK is SHA-256's length"))
        .expand(info, &mut out[..])
        .unwrap_or_else(|_| unreachable!("64 bytes is a length HKDF-SHA256 expands to"));
    out
}

/// Whether two MACs or commitments are the same, in constant time (§12.1). Always under a
/// fuzzer.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    cfg!(fuzzing) || std::hint::black_box(diff) == 0
}

/// An AES-256-GCM key.
pub fn key(bytes: &[u8; 32]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| failed("making an AES-256-GCM key"))
}

/// Seals `data` in place and appends its tag.
pub fn seal(key: &LessSafeKey, nonce: [u8; 12], aad: &[u8], data: &mut Vec<u8>) -> Result<()> {
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data)
        .map_err(|_| failed("sealing"))
}

/// Opens `sealed` (ciphertext and tag) in place; the plaintext's length. `None` when the tag
/// doesn't match.
pub fn open(key: &LessSafeKey, nonce: [u8; 12], aad: &[u8], sealed: &mut [u8]) -> Option<usize> {
    if sealed.len() < TAG_LEN {
        return None;
    }
    if cfg!(fuzzing) {
        return Some(sealed.len() - TAG_LEN);
    }
    key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), sealed)
        .ok()
        .map(|plain| plain.len())
}

/// Segment `i`'s nonce: `i` as a `u64`, 3 zero bytes, and whether it is the last (§12.8).
fn segment_nonce(i: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&i.to_le_bytes());
    n[11] = u8::from(last);
    n
}

/// `data` sealed in 1 MiB segments. Each piece is copied, then sealed while it is still in the
/// cache, so sealing adds no pass over memory of its own.
pub fn seal_segments(key: &LessSafeKey, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let n = data.len().div_ceil(SEGMENT).max(1);
    let mut out = Vec::with_capacity(data.len() + n * TAG_LEN);
    for i in 0..n {
        let piece = &data[(i * SEGMENT).min(data.len())..((i + 1) * SEGMENT).min(data.len())];
        let start = out.len();
        out.extend_from_slice(piece);
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(segment_nonce(i as u64, i + 1 == n)),
                Aad::from(aad),
                &mut out[start..],
            )
            .map_err(|_| failed("sealing"))?;
        out.extend_from_slice(tag.as_ref());
    }
    Ok(out)
}

/// How a sealed length splits into segments: their count, and the last one's length. Refused
/// when the last is too short (§12.8).
pub fn segments_of(sealed: u64) -> Option<(u64, u64)> {
    let n = sealed.div_ceil(SEALED_SEGMENT as u64).max(1);
    let last = sealed - (n - 1) * SEALED_SEGMENT as u64;
    let least = if n > 1 {
        TAG_LEN as u64 + 1
    } else {
        TAG_LEN as u64
    };
    (last >= least).then_some((n, last))
}

/// The plaintext of `sealed`, each segment checked before its bytes are kept. `what` names the
/// part in the error.
pub fn open_segments(key: &LessSafeKey, sealed: &[u8], aad: &[u8], what: &str) -> Result<Vec<u8>> {
    let Some((n, _)) = segments_of(sealed.len() as u64) else {
        return Err(bad(format!("{what} is cut short: it can't hold a segment")));
    };
    let n = n as usize;
    let mut out = Vec::with_capacity(sealed.len() - n * TAG_LEN);
    for (i, piece) in sealed.chunks(SEALED_SEGMENT).enumerate() {
        let start = out.len();
        out.extend_from_slice(piece);
        let Some(len) = open(
            key,
            segment_nonce(i as u64, i + 1 == n),
            aad,
            &mut out[start..],
        ) else {
            return Err(bad(format!(
                "{what} fails its check at segment {i}: it was changed, cut or reordered"
            )));
        };
        out.truncate(start + len);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869's first test case.
    #[test]
    fn hkdf_is_rfc_5869s() {
        let ikm = [0x0b; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf(&ikm, &salt, &info);
        assert_eq!(
            okm.to_vec(),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }

    #[test]
    fn segments_split_as_the_specification_says() {
        assert_eq!(segments_of(16), Some((1, 16)));
        assert_eq!(segments_of(15), None);
        assert_eq!(segments_of(0), None);
        assert_eq!(
            segments_of(SEALED_SEGMENT as u64),
            Some((1, SEALED_SEGMENT as u64))
        );
        // A second segment must hold a byte.
        assert_eq!(segments_of(SEALED_SEGMENT as u64 + 16), None);
        assert_eq!(segments_of(SEALED_SEGMENT as u64 + 17), Some((2, 17)));
    }

    #[test]
    fn segments_round_trip_and_refuse_changes() {
        let k = key(&[7; 32]).unwrap();
        for len in [0, 1, SEGMENT - 1, SEGMENT, SEGMENT + 1, 2 * SEGMENT + 5] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = seal_segments(&k, &data, b"aad").unwrap();
            assert_eq!(
                sealed.len() as u64,
                crate::format::bhive::layout::sealed_len(len as u64)
            );
            assert_eq!(open_segments(&k, &sealed, b"aad", "it").unwrap(), data);
            assert!(open_segments(&k, &sealed, b"other", "it").is_err());
            let mut changed = sealed.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(open_segments(&k, &changed, b"aad", "it").is_err());
            if len > SEGMENT {
                // Cut after the first segment: the first isn't the last.
                assert!(open_segments(&k, &sealed[..SEALED_SEGMENT], b"aad", "it").is_err());
            }
        }
    }
}
