//! LZVN, the LZ77 behind Apple-compressed files of decmpfs types 7 and 8 (docs/M5.md §5.11),
//! BeeZip's own decoder.
//!
//! Each opcode is a literal of up to 271 bytes, a match of up to 271 bytes, or a short literal
//! followed by a match. A match's distance may be given again by the next opcode by leaving it
//! out (`pre_d`, `sml_m`, `lrg_m`). The opcodes, by their first byte:
//!
//! | bits | name | literal | match | distance | bytes |
//! |---|---|---|---|---|---|
//! | `LLMMMDDD` (`DDD` ≠ 110, 111) | `sml_d` | `LL` | `MMM` + 3 | `DDD` and the next byte | 2 |
//! | `LLMMM111` | `lrg_d` | `LL` | `MMM` + 3 | the next two, little-endian | 3 |
//! | `LLMMM110` (`LL` ≠ 0) | `pre_d` | `LL` | `MMM` + 3 | the last one | 1 |
//! | `101LLMMM` | `med_d` | `LL` | `MMM`, then 2 bits, + 3 | 14 bits | 3 |
//! | `1110LLLL` | `sml_l` | `LLLL` | | | 1 |
//! | `11100000` | `lrg_l` | the next byte + 16 | | | 2 |
//! | `1111MMMM` | `sml_m` | | `MMMM` | the last one | 1 |
//! | `11110000` | `lrg_m` | | the next byte + 16 | the last one | 2 |
//!
//! `0x06` ends the stream, `0x0E` and `0x16` do nothing, and the rest of `00xxx110`, `0111xxxx`
//! and `1101xxxx` are undefined. The literal's bytes follow the opcode.

/// Decodes `src`, which must decode to at most `max` bytes. The stream ends at its end-of-stream
/// opcode or where `src` does.
pub fn decode(src: &[u8], max: usize) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(max.min(1 << 20));
    let mut dist = 0usize;
    let mut i = 0usize;
    let byte = |at: usize| src.get(at).copied().map(usize::from);
    let word = |at: usize| Some(byte(at)? | byte(at + 1)? << 8);
    while let Some(&op) = src.get(i) {
        let short = || format!("the stream ends inside an opcode at {i}");
        // (opcode length, literal, match, new distance)
        let (len, lit, mat, d) = match op {
            0x06 => return Ok(out),
            0x0E | 0x16 => (1, 0, 0, None),
            0x1E | 0x26 | 0x2E | 0x36 | 0x3E | 0x70..=0x7F | 0xD0..=0xDF => {
                return Err(format!("an undefined opcode {op:#04x} at {i}"));
            }
            0xA0..=0xBF => {
                let w = word(i + 1).ok_or_else(short)?;
                let lit = usize::from(op >> 3) & 3;
                let mat = ((usize::from(op & 7) << 2) | (w & 3)) + 3;
                (3, lit, mat, Some(w >> 2))
            }
            0xE0 => (2, byte(i + 1).ok_or_else(short)? + 16, 0, None),
            0xE1..=0xEF => (1, usize::from(op & 0x0F), 0, None),
            0xF0 => (2, 0, byte(i + 1).ok_or_else(short)? + 16, None),
            0xF1..=0xFF => (1, 0, usize::from(op & 0x0F), None),
            _ => {
                let lit = usize::from(op >> 6);
                let mat = usize::from((op >> 3) & 7) + 3;
                match op & 7 {
                    7 => (3, lit, mat, Some(word(i + 1).ok_or_else(short)?)),
                    6 => (1, lit, mat, None),
                    low => {
                        let d = (usize::from(low) << 8) | byte(i + 1).ok_or_else(short)?;
                        (2, lit, mat, Some(d))
                    }
                }
            }
        };
        let start = i + len;
        let literal = src
            .get(start..start + lit)
            .ok_or_else(|| format!("the stream ends inside a literal at {i}"))?;
        if out.len() + lit + mat > max {
            return Err(format!("it decodes to more than {max} bytes"));
        }
        out.extend_from_slice(literal);
        if let Some(d) = d {
            dist = d;
        }
        if mat > 0 {
            if dist == 0 || dist > out.len() {
                return Err(format!(
                    "a match at {i} reaches {dist} bytes back from {}",
                    out.len()
                ));
            }
            let from = out.len() - dist;
            for k in 0..mat {
                let b = out[from + k];
                out.push(b);
            }
        }
        i = start + lit;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EOS: [u8; 8] = [0x06, 0, 0, 0, 0, 0, 0, 0];

    fn stream(ops: &[&[u8]]) -> Vec<u8> {
        let mut s: Vec<u8> = ops.concat();
        s.extend_from_slice(&EOS);
        s
    }

    #[test]
    fn hand_made_vectors() {
        // sml_l "abc", then sml_d with no literal: 6 bytes at distance 3.
        let s = stream(&[&[0xE3, b'a', b'b', b'c'], &[(3 << 3), 3]]);
        assert_eq!(decode(&s, 100).unwrap(), b"abcabcabc");
        // sml_d with a 3-byte literal and a 4-byte match at distance 3.
        let s = stream(&[&[0xC0 | (1 << 3), 3, b'x', b'y', b'z']]);
        assert_eq!(decode(&s, 100).unwrap(), b"xyzxyzx");
        // pre_d reuses it: a 1-byte literal, then 3 more at distance 3.
        let s = stream(&[&[0xC0 | (1 << 3), 3, b'x', b'y', b'z'], &[0x46, b'!']]);
        assert_eq!(decode(&s, 100).unwrap(), b"xyzxyzx!zx!");
        // sml_m and lrg_m at the last distance; a nop between.
        let s = stream(&[
            &[0xE2, b'a', b'b'],
            &[0x0E],
            &[0x00, 2],
            &[0xF2],
            &[0xF0, 0],
        ]);
        let mut want = b"ab".to_vec();
        for _ in 0..(3 + 2 + 16) {
            want.push(want[want.len() - 2]);
        }
        assert_eq!(decode(&s, 100).unwrap(), want);
        // lrg_l, lrg_d at distance 300, med_d.
        let lit: Vec<u8> = (0..=255u8).chain(0..44).collect();
        let mut s = vec![0xE0, 255];
        s.extend_from_slice(&lit[..271]);
        s.push(0xEF);
        s.extend_from_slice(&lit[271..286]);
        s.push(0xEE);
        s.extend_from_slice(&lit[286..]);
        s.extend_from_slice(&[(7 << 3) | 7, 44, 1]); // 10 bytes at distance 300
        // med_d: no literal, match ((5 << 2) | 2) + 3 = 25, distance 7 (w = 7 << 2 | 2).
        let w: u16 = (7 << 2) | 2;
        s.extend_from_slice(&[0xA0 | 5, w as u8, (w >> 8) as u8]);
        s.extend_from_slice(&EOS);
        let mut want = lit.clone();
        for _ in 0..10 {
            want.push(want[want.len() - 300]);
        }
        for _ in 0..25 {
            want.push(want[want.len() - 7]);
        }
        assert_eq!(decode(&s, 1000).unwrap(), want);
    }

    #[test]
    fn bad_streams_fail() {
        // A match before anything, or before the first distance.
        assert!(decode(&stream(&[&[0x00, 1]]), 100).is_err());
        assert!(decode(&stream(&[&[0xF3]]), 100).is_err());
        // Undefined opcodes.
        for op in [0x1E, 0x70, 0x7F, 0xD0, 0xDF] {
            assert!(decode(&stream(&[&[op]]), 100).is_err(), "{op:#x}");
        }
        // Cut inside an opcode or a literal.
        assert!(decode(&[0xA0, 1], 100).is_err());
        assert!(decode(&[0xE5, b'a'], 100).is_err());
        // More than allowed.
        assert!(decode(&stream(&[&[0xE3, b'a', b'b', b'c']]), 2).is_err());
        // An empty stream, and one without its end marker.
        assert_eq!(decode(&EOS, 0).unwrap(), b"");
        assert_eq!(decode(&[0xE1, b'q'], 10).unwrap(), b"q");
    }

    /// lzfse_rust writes inputs under 4 KiB as an LZVN block (`bvxn`, the decoded and encoded
    /// sizes, the stream with its end marker): an encoder that isn't ours.
    #[test]
    fn decodes_lzfse_rusts_lzvn_blocks() {
        let mut x = 7u32;
        let mut inputs: Vec<Vec<u8>> = vec![
            b"The quick brown fox jumps over the lazy dog. ".repeat(40),
            (0..3000u32).map(|i| (i % 251) as u8).collect(),
            vec![0u8; 4000],
        ];
        inputs.push(
            (0..3500)
                .map(|i| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    if i % 7 < 3 { b'a' } else { (x >> 24) as u8 }
                })
                .collect(),
        );
        let mut seen = 0;
        for input in &inputs {
            let mut enc = Vec::new();
            lzfse_rust::encode_bytes(input, &mut enc).unwrap();
            if !enc.starts_with(b"bvxn") {
                continue;
            }
            seen += 1;
            let raw = u32::from_le_bytes(enc[4..8].try_into().unwrap()) as usize;
            let payload = u32::from_le_bytes(enc[8..12].try_into().unwrap()) as usize;
            assert_eq!(raw, input.len());
            let out = decode(&enc[12..12 + payload], raw).unwrap();
            assert_eq!(&out, input);
        }
        assert!(seen >= 2, "lzfse_rust wrote {seen} LZVN blocks");
    }
}
