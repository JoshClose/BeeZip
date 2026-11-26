//! Bech32 (BIP 173) without the 90-character limit, for age's key strings and BeeZip's
//! `bzsig1…` (bhive.md §13.5): post-quantum keys run to thousands of characters. Also the
//! fingerprint people compare by eye (bhive.md §13.5).
//!
//! The checksum is BIP 173's (Bech32, not Bech32m), as age's keys use. It is guaranteed to
//! catch up to 4 mistyped characters only in strings of up to 89; in longer ones a mistake is
//! still caught but for one chance in about a billion, as for age's post-quantum keys.

use zeroize::Zeroizing;

use super::{mldsa, xwing};
use crate::{Error, ErrorKind, Result};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// The human-readable parts of the key strings, lowercase, as [`decode`] gives them.
pub mod hrp {
    pub const X25519_PUBLIC: &str = "age";
    pub const X25519_SECRET: &str = "age-secret-key-";
    pub const XWING_PUBLIC: &str = "age1pq";
    pub const XWING_SECRET: &str = "age-secret-key-pq-";
    pub const SIGNING_PUBLIC: &str = "bzsig";
    pub const SIGNING_SECRET: &str = "bzsig-secret-key-";
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The HRP as the checksum takes it, lowercase.
fn hrp_expand(hrp: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let lower = hrp.iter().map(u8::to_ascii_lowercase);
    lower
        .clone()
        .map(|c| c >> 5)
        .chain([0])
        .chain(lower.map(|c| c & 31))
}

fn checksum(hrp: &[u8], values: &[u8]) -> [u8; 6] {
    let pm = polymod(
        hrp_expand(hrp)
            .chain(values.iter().copied())
            .chain([0; 6]),
    ) ^ 1;
    let mut out = [0; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((pm >> (5 * (5 - i))) & 31) as u8;
    }
    out
}

/// Bytes as 5-bit groups, the last padded with zero bits.
fn to_5bit(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// 5-bit groups back to bytes: at most 4 bits of padding, all zero (BIP 173).
fn from_5bit(values: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(values.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &v in values {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    (bits < 5 && acc == 0).then_some(out)
}

/// `hrp` lowercase gives a lowercase string, uppercase an uppercase one.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let upper = hrp.bytes().any(|c| c.is_ascii_uppercase());
    let values = to_5bit(data);
    let check = checksum(hrp.as_bytes(), &values);
    let mut s = String::with_capacity(hrp.len() + 1 + values.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for v in values.iter().chain(&check) {
        let c = char::from(CHARSET[usize::from(*v)]);
        s.push(if upper { c.to_ascii_uppercase() } else { c });
    }
    s
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidArgs, message)
}

/// The human-readable part (lowercase) and the data. A mixed-case string is refused.
pub fn decode(text: &str) -> Result<(String, Vec<u8>)> {
    let bytes = text.as_bytes();
    if bytes.iter().any(|c| !(33..=126).contains(c)) {
        return Err(invalid(
            "not a key string: it has spaces or characters outside ASCII",
        ));
    }
    let lower = bytes.iter().any(u8::is_ascii_lowercase);
    let upper = bytes.iter().any(u8::is_ascii_uppercase);
    if lower && upper {
        return Err(invalid(
            "not a key string: it mixes upper- and lowercase letters",
        ));
    }
    let Some(sep) = bytes.iter().rposition(|&c| c == b'1') else {
        return Err(invalid("not a key string: it has no `1` separator"));
    };
    let (hrp, rest) = (&bytes[..sep], &bytes[sep + 1..]);
    if hrp.is_empty() || rest.len() < 6 {
        return Err(invalid("not a key string: it is too short"));
    }
    let mut values = Vec::with_capacity(rest.len());
    for &c in rest {
        let c = c.to_ascii_lowercase();
        match CHARSET.iter().position(|&x| x == c) {
            Some(v) => values.push(v as u8),
            None => {
                return Err(invalid(format!(
                    "not a key string: `{}` can't appear in one",
                    char::from(c)
                )));
            }
        }
    }
    if polymod(hrp_expand(hrp).chain(values.iter().copied())) != 1 {
        return Err(invalid(
            "its checksum is wrong: a character is mistyped or missing",
        ));
    }
    values.truncate(values.len() - 6);
    let data = from_5bit(&values).ok_or_else(|| invalid("not a key string: bad padding"))?;
    let hrp = String::from_utf8_lossy(hrp).to_ascii_lowercase();
    Ok((hrp, data))
}

/// A key as text: what it is and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyText {
    /// `age1…`
    X25519Public([u8; 32]),
    /// `AGE-SECRET-KEY-1…`
    X25519Secret(zeroize::Zeroizing<[u8; 32]>),
    /// `age1pq1…`
    XWingPublic(Box<[u8; 1216]>),
    /// `AGE-SECRET-KEY-PQ-1…`
    XWingSecret(zeroize::Zeroizing<[u8; 32]>),
    /// `bzsig1…`: an Ed25519 and an ML-DSA-65 public key (bhive.md §13.5).
    SigningPublic(Box<[u8; 1984]>),
    /// `BZSIG-SECRET-KEY-1…`: the two seeds.
    SigningSecret(zeroize::Zeroizing<[u8; 64]>),
}

impl KeyText {
    /// Whether it is a private key.
    pub const fn is_secret(&self) -> bool {
        matches!(
            self,
            Self::X25519Secret(_) | Self::XWingSecret(_) | Self::SigningSecret(_)
        )
    }

    /// A public key's bytes: what its fingerprint and a slot description are of. `None` for a
    /// private key.
    pub fn public_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::X25519Public(k) => Some(k),
            Self::XWingPublic(k) => Some(&k[..]),
            Self::SigningPublic(k) => Some(&k[..]),
            _ => None,
        }
    }

    /// The public half of a private key; a public key is itself. A signing key's needs
    /// ML-DSA (`mldsa`).
    pub fn public(&self) -> Result<Self> {
        Ok(match self {
            Self::X25519Secret(k) => Self::X25519Public(super::x25519::public_of(k)),
            Self::XWingSecret(k) => Self::XWingPublic(xwing::public_of(k)?),
            Self::SigningSecret(k) => {
                Self::SigningPublic(mldsa::HybridKey { seeds: k.clone() }.public()?)
            }
            public => public.clone(),
        })
    }
}

fn exact<const N: usize>(what: &str, data: &[u8]) -> Result<[u8; N]> {
    data.try_into().map_err(|_| {
        invalid(format!(
            "{what} holds {N} bytes; this one holds {}",
            data.len()
        ))
    })
}

/// Reads any of [`KeyText`]'s forms; anything else is `InvalidArgs` with what it looked like.
/// Spaces and line ends around it are ignored.
pub fn parse_key(text: &str) -> Result<KeyText> {
    let text = text.trim();
    let (hrp, data) = decode(text).map_err(|e| {
        // Say what it looked like when its start is one BeeZip knows.
        let lower = text.to_ascii_lowercase();
        let what = if lower.starts_with(hrp::X25519_SECRET) || lower.starts_with(hrp::SIGNING_SECRET)
        {
            "a private key"
        } else if lower.starts_with("age1") || lower.starts_with("bzsig1") {
            "a public key"
        } else {
            return e;
        };
        invalid(format!("{what}, but {}", e.message))
    })?;
    let data = Zeroizing::new(data);
    let key = match hrp.as_str() {
        hrp::X25519_PUBLIC => KeyText::X25519Public(exact("an age1 key", &data)?),
        hrp::X25519_SECRET => {
            KeyText::X25519Secret(Zeroizing::new(exact("an AGE-SECRET-KEY-1 key", &data)?))
        }
        hrp::XWING_PUBLIC => {
            let key: [u8; xwing::PUBLIC_KEY_LEN] = exact("an age1pq1 key", &data)?;
            xwing::check_public_key(&key)?;
            KeyText::XWingPublic(Box::new(key))
        }
        hrp::XWING_SECRET => {
            KeyText::XWingSecret(Zeroizing::new(exact("an AGE-SECRET-KEY-PQ-1 key", &data)?))
        }
        hrp::SIGNING_PUBLIC => KeyText::SigningPublic(Box::new(exact::<{ mldsa::PUBLIC_LEN }>(
            "a bzsig1 key",
            &data,
        )?)),
        hrp::SIGNING_SECRET => {
            KeyText::SigningSecret(Zeroizing::new(exact("a BZSIG-SECRET-KEY-1 key", &data)?))
        }
        other if other.starts_with("age1") || other.starts_with("age-plugin-") => {
            return Err(invalid(format!(
                "`{other}1…` is a key of an age plugin, which BeeZip doesn't run (docs/M14.md §12)"
            )));
        }
        other => {
            return Err(invalid(format!(
                "`{other}1…` isn't a kind of key BeeZip knows: it takes age1…, age1pq1… and \
                 bzsig1… keys, and their private keys"
            )));
        }
    };
    Ok(key)
}

/// The text of a key: public keys lowercase, private keys uppercase, as age writes them.
pub fn key_text(key: &KeyText) -> String {
    match key {
        KeyText::X25519Public(k) => encode(hrp::X25519_PUBLIC, k),
        KeyText::X25519Secret(k) => encode("AGE-SECRET-KEY-", &k[..]),
        KeyText::XWingPublic(k) => encode(hrp::XWING_PUBLIC, &k[..]),
        KeyText::XWingSecret(k) => encode("AGE-SECRET-KEY-PQ-", &k[..]),
        KeyText::SigningPublic(k) => encode(hrp::SIGNING_PUBLIC, &k[..]),
        KeyText::SigningSecret(k) => encode("BZSIG-SECRET-KEY-", &k[..]),
    }
}

/// A fingerprint, for people to compare (bhive.md §13.5): the first 10 bytes of the SHA-256 of
/// a public key's bytes (a signer's bytes, or an `age1…` or `age1pq1…` key's), in RFC 4648
/// base32, as 16 characters in groups of four. Never for matching: that takes the whole hash.
pub fn fingerprint(public: &[u8]) -> String {
    const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let hash = ring::digest::digest(&ring::digest::SHA256, public);
    let mut out = String::with_capacity(19);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0);
    for &b in &hash.as_ref()[..10] {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if n > 0 && n % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(B32[((acc >> bits) & 31) as usize]));
            n += 1;
        }
        acc &= (1 << bits) - 1;
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    pub(crate) fn hex(s: &serde_json::Value) -> Vec<u8> {
        let s = s.as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// age's own example keys (tests/fixtures/keys/age-spec-examples.txt): an X25519
    /// identity and its recipient, then an MLKEM768-X25519 identity and its recipient.
    pub(crate) fn age_examples() -> Vec<String> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/keys/age-spec-examples.txt"
        );
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| l.trim().to_owned())
            .collect()
    }

    #[test]
    fn bip173_valid_strings() {
        for s in [
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
        ] {
            decode(s).unwrap_or_else(|e| panic!("{s}: {e:?}"));
        }
    }

    #[test]
    fn bip173_invalid_strings() {
        for s in [
            "pzry9x0s0muk",
            "1pzry9x0s0muk",
            "x1b4n0q5v",
            "li1dgmt3",
            "A1G7SGD8",
            "10a06t8",
            "1qzzfhee",
            "a12UEL5L",
            "de1lg7wt\u{ff}",
        ] {
            assert!(decode(s).is_err(), "{s}");
        }
    }

    #[test]
    fn long_data_round_trips_without_a_length_limit() {
        let data: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        let s = encode("bzsig", &data);
        assert!(s.len() > 4000);
        assert_eq!(decode(&s).unwrap(), ("bzsig".into(), data.clone()));
        let up = encode("BZSIG", &data);
        assert_eq!(up, s.to_ascii_uppercase());
        assert_eq!(decode(&up).unwrap().1, data);
    }

    #[test]
    fn the_specifications_key_strings() {
        let v = vectors();
        let x = &v["slots"]["x25519"];
        let pk: [u8; 32] = hex(&x["recipient_public"]).try_into().unwrap();
        let sk: [u8; 32] = hex(&x["recipient_secret"]).try_into().unwrap();
        let w = &v["slots"]["xwing"];
        let xpk: [u8; 1216] = hex(&w["recipient_public"]).try_into().unwrap();
        let seed: [u8; 32] = hex(&w["recipient_seed"]).try_into().unwrap();
        let s = &v["signed_example"];
        let mut signer = hex(&s["ed25519_public"]);
        signer.extend(hex(&s["mldsa_public"]));
        let mut seeds = hex(&s["ed25519_seed"]);
        seeds.extend(hex(&s["mldsa_seed"]));
        for (key, text) in [
            (KeyText::X25519Public(pk), &x["recipient_text"]),
            (KeyText::X25519Secret(Zeroizing::new(sk)), &x["secret_text"]),
            (KeyText::XWingPublic(Box::new(xpk)), &w["recipient_text"]),
            (KeyText::XWingSecret(Zeroizing::new(seed)), &w["secret_text"]),
            (
                KeyText::SigningPublic(Box::new(signer.clone().try_into().unwrap())),
                &s["signer_text"],
            ),
            (
                KeyText::SigningSecret(Zeroizing::new(seeds.try_into().unwrap())),
                &s["secret_text"],
            ),
        ] {
            let text = text.as_str().unwrap();
            assert_eq!(key_text(&key), text);
            assert_eq!(parse_key(text).unwrap(), key);
            assert_eq!(key.is_secret(), key.public_bytes().is_none());
        }
        assert_eq!(fingerprint(&signer), s["fingerprint"].as_str().unwrap());
        assert_eq!(fingerprint(&signer), "VCPC-QSVP-2XKC-VCIZ");
    }

    #[test]
    fn ages_example_keys() {
        let ex = age_examples();
        assert_eq!(ex.len(), 4);
        let KeyText::X25519Secret(sk) = parse_key(&ex[0]).unwrap() else {
            panic!("not an X25519 identity")
        };
        // age's example identity is 0x42 repeated.
        assert_eq!(*sk, [0x42; 32]);
        for text in &ex {
            assert_eq!(&key_text(&parse_key(text).unwrap()), text);
        }
        // Each identity gives its recipient: X25519, and X-Wing through the draft's key
        // derivation (bhive.md §12.5, kinds 3 and 4).
        for pair in ex.chunks(2) {
            let public = parse_key(&pair[0]).unwrap().public().unwrap();
            assert_eq!(key_text(&public), pair[1]);
        }
    }

    #[test]
    fn refusals_say_why() {
        let ex = age_examples();
        // A changed character: the checksum.
        let mut bad = ex[1].clone().into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'q' { b'p' } else { b'q' };
        let e = parse_key(std::str::from_utf8(&bad).unwrap()).unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidArgs);
        assert!(e.message.starts_with("a public key, but its checksum"), "{}", e.message);
        let mut bad = ex[2].clone().into_bytes();
        bad[30] = if bad[30] == b'Q' { b'P' } else { b'Q' };
        let e = parse_key(std::str::from_utf8(&bad).unwrap()).unwrap_err();
        assert!(e.message.starts_with("a private key, but its checksum"), "{}", e.message);
        // Mixed case.
        let mixed = format!("A{}", &ex[1][1..]);
        let e = parse_key(&mixed).unwrap_err();
        assert!(e.message.contains("mixes"), "{}", e.message);
        // A prefix BeeZip doesn't know, with a good checksum.
        let e = parse_key(&encode("ssh", &[0; 32])).unwrap_err();
        assert!(e.message.contains("`ssh1…`"), "{}", e.message);
        // An age plugin's recipient.
        let e = parse_key(&encode("age1yubikey", &[0; 33])).unwrap_err();
        assert!(e.message.contains("plugin"), "{}", e.message);
        // The right prefix, the wrong length.
        let e = parse_key(&encode("age", &[0; 31])).unwrap_err();
        assert!(e.message.contains("32 bytes"), "{}", e.message);
        // A post-quantum key whose ML-KEM half isn't a key.
        let e = parse_key(&encode("age1pq", &[0xff; 1216])).unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidArgs);
        // Padding bits that aren't zero: 32 bytes are 52 groups with 4 bits of padding.
        let mut values = to_5bit(&[0; 32]);
        *values.last_mut().unwrap() = 1;
        let check = checksum(b"age", &values);
        let s: String = "age1"
            .chars()
            .chain(
                values
                    .iter()
                    .chain(&check)
                    .map(|v| char::from(CHARSET[usize::from(*v)])),
            )
            .collect();
        assert!(parse_key(&s).unwrap_err().message.contains("padding"));
        // Not a key at all.
        assert_eq!(parse_key("").unwrap_err().kind, ErrorKind::InvalidArgs);
        assert_eq!(parse_key("hunter2").unwrap_err().kind, ErrorKind::InvalidArgs);
    }

    #[test]
    fn surrounding_space_is_ignored() {
        let ex = age_examples();
        assert!(parse_key(&format!("  {}\r\n", ex[1])).is_ok());
    }
}
