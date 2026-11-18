//! Content-defined chunks (docs/M13.md §3): a file is cut where a rolling hash of its bytes
//! hits a pattern, so an insertion moves only the cuts near it, and a chunk seen before is
//! stored once. None of this is in the format: a reader sees extents.
//!
//! The spike's chunker, as it was measured: a gear hash (one table entry a byte, shifted in),
//! chunks of at least 4 KiB and at most 64 KiB, a cut where the hash's low 14 bits are zero,
//! about 16 KiB past the minimum. A file is cut in segments of 4 MiB, each on its own, so
//! segments can be cut and hashed on different threads and the cuts never depend on how the
//! file was read.

/// A file is chunked in pieces of this size, each from its own start.
pub const SEGMENT: usize = 4 << 20;
pub const MIN: usize = 4 << 10;
pub const MAX: usize = 64 << 10;
const MASK: u64 = (1 << 14) - 1;
/// Chunks shorter than this are stored where they fall: an extent into another cell costs a
/// reader that cell, and saves little.
pub const MIN_SHARED: usize = 512;

/// The gear table: splitmix64 from a fixed seed.
const GEAR: [u64; 256] = {
    let mut gear = [0u64; 256];
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut i = 0;
    while i < 256 {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        gear[i] = z ^ (z >> 31);
        i += 1;
    }
    gear
};

/// Where the chunk that starts `data` ends: `data.len()` when it is the last.
pub fn cut(data: &[u8]) -> usize {
    let end = data.len().min(MAX);
    let mut h = 0u64;
    for (k, &b) in data[..end].iter().enumerate().skip(MIN) {
        h = (h << 1).wrapping_add(GEAR[usize::from(b)]);
        if h & MASK == 0 {
            return k + 1;
        }
    }
    end
}

/// A chunk of a file's bytes: where it ends in them, and its BLAKE3 (zeros for a chunk shorter
/// than [`MIN_SHARED`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub end: usize,
    pub hash: [u8; 32],
}

/// The chunks of `data`, a file's bytes from a segment boundary on: cut segment by segment and
/// appended to `out` with ends counted from the start of `data`.
pub fn chunks(data: &[u8], out: &mut Vec<Chunk>) {
    let mut start = 0;
    while start < data.len() {
        let segment = &data[start..data.len().min(start - start % SEGMENT + SEGMENT)];
        let mut at = 0;
        while at < segment.len() {
            let len = cut(&segment[at..]);
            // A chunk too short to share is never looked up, so it needs no hash: most of a
            // tree of small files is such chunks.
            let hash = if len >= MIN_SHARED {
                *blake3::hash(&segment[at..at + len]).as_bytes()
            } else {
                [0; 32]
            };
            out.push(Chunk {
                end: start + at + len,
                hash,
            });
            at += len;
        }
        start += segment.len();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Bytes with no pattern: xorshift.
    pub(crate) fn noise(len: usize, mut s: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            v.extend_from_slice(&s.to_le_bytes());
        }
        v.truncate(len);
        v
    }

    fn ends(data: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        chunks(data, &mut out);
        out.iter().map(|c| c.end).collect()
    }

    #[test]
    fn chunks_keep_their_bounds_and_cover_the_data() {
        let data = noise(3 << 20, 7);
        let e = ends(&data);
        assert_eq!(e.last(), Some(&data.len()));
        let mut start = 0;
        for (i, &end) in e.iter().enumerate() {
            let len = end - start;
            assert!(len <= MAX, "{len}");
            assert!(len >= MIN || i == e.len() - 1, "{len}");
            start = end;
        }
        // About 16 KiB past the minimum.
        let mean = data.len() / e.len();
        assert!((12 << 10..28 << 10).contains(&mean), "{mean}");
        assert!(ends(&[]).is_empty());
        assert_eq!(ends(&data[..100]), [100]);
    }

    #[test]
    fn an_insertion_moves_only_the_cuts_near_it() {
        let data = noise(2 << 20, 11);
        let mut shifted = data[..500_000].to_vec();
        shifted.extend_from_slice(b"seventeen bytes!!");
        shifted.extend_from_slice(&data[500_000..]);
        let hashes = |d: &[u8]| {
            let mut out = Vec::new();
            chunks(d, &mut out);
            out.into_iter().map(|c| c.hash).collect::<Vec<_>>()
        };
        let (a, b) = (hashes(&data), hashes(&shifted));
        let same = b.iter().filter(|h| a.contains(h)).count();
        assert!(same + 4 >= b.len(), "{same} of {}", b.len());
    }

    #[test]
    fn a_segment_is_cut_on_its_own() {
        let data = noise(SEGMENT + (1 << 20), 3);
        let all = ends(&data);
        assert!(all.contains(&SEGMENT));
        let second: Vec<usize> = ends(&data[SEGMENT..])
            .into_iter()
            .map(|e| e + SEGMENT)
            .collect();
        assert!(all.ends_with(&second));
        let first = ends(&data[..SEGMENT]);
        assert_eq!(all[..first.len()], first[..]);
    }
}
