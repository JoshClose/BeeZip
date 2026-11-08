//! ACE's encryption: its Blowfish ([`super::blowfish`]) in CBC mode from a zero IV, on
//! little-endian words, keyed with one SHA-1 compression of the password under ACE's own
//! padding. ACE has no password check, so a wrong password shows only as data that fails to
//! decode or fails its CRC. Passwords are taken as UTF-8, as acefile takes them.

use std::io::{self, Read};

use super::blowfish::Blowfish;

const BLOCK: usize = 8;
/// acefile truncates passwords here before deriving the key.
const MAX_PASSWORD: usize = 50;
const SHA1_INIT: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// The 160-bit key: SHA-1's compression function, once, over the password, a 0x80 byte and
/// zeros, read as little-endian words, with the password's length in bits as the 16th word.
/// The message schedule doesn't rotate, as in SHA-0.
fn derive_key(password: &[u8]) -> [u32; 5] {
    let pw = &password[..password.len().min(MAX_PASSWORD)];
    let mut block = [0u8; 60];
    block[..pw.len()].copy_from_slice(pw);
    block[pw.len()] = 0x80;
    let mut w = [0u32; 80];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    w[15] = (pw.len() as u32) << 3;
    for i in 16..80 {
        w[i] = w[i - 16] ^ w[i - 14] ^ w[i - 8] ^ w[i - 3];
    }
    let [mut a, mut b, mut c, mut d, mut e] = SHA1_INIT;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..20 => ((b & c) | (!b & d), 0x5A82_7999),
            20..40 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..60 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(wi)
            .wrapping_add(k);
        (a, b, c, d, e) = (t, a, b.rotate_left(30), c, d);
    }
    let mut key = [a, b, c, d, e];
    for (k, init) in key.iter_mut().zip(SHA1_INIT) {
        *k = k.wrapping_add(init);
    }
    key
}

fn cipher(password: &str) -> Box<Blowfish> {
    Blowfish::new(&derive_key(password.as_bytes()))
}

fn words(block: &[u8; BLOCK]) -> (u32, u32) {
    let [a, b, c, d, e, f, g, h] = *block;
    (
        u32::from_le_bytes([a, b, c, d]),
        u32::from_le_bytes([e, f, g, h]),
    )
}

fn bytes((l, r): (u32, u32)) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out[..4].copy_from_slice(&l.to_le_bytes());
    out[4..].copy_from_slice(&r.to_le_bytes());
    out
}

/// Decrypts what `inner` holds, which must be whole 8-byte blocks.
pub struct Decrypt<R> {
    inner: R,
    cipher: Box<Blowfish>,
    /// The last ciphertext block.
    iv: (u32, u32),
    buf: Box<[u8]>,
    start: usize,
    end: usize,
}

impl<R: Read> Decrypt<R> {
    pub fn new(inner: R, password: &str) -> Self {
        Self {
            inner,
            cipher: cipher(password),
            iv: (0, 0),
            buf: vec![0u8; 16 * 1024].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        let mut have = 0;
        while have < self.buf.len() {
            match self.inner.read(&mut self.buf[have..]) {
                Ok(0) => break,
                Ok(n) => {
                    have += n;
                    if have % BLOCK == 0 {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if have % BLOCK != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the encrypted data isn't whole 8-byte blocks",
            ));
        }
        for chunk in self.buf[..have].as_chunks_mut::<BLOCK>().0 {
            let sealed = words(chunk);
            let (l, r) = self.cipher.decrypt(sealed.0, sealed.1);
            *chunk = bytes((l ^ self.iv.0, r ^ self.iv.1));
            self.iv = sealed;
        }
        self.start = 0;
        self.end = have;
        Ok(())
    }
}

impl<R: Read> Read for Decrypt<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.start == self.end {
            self.fill()?;
        }
        let n = buf.len().min(self.end - self.start);
        buf[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

/// `data` encrypted as ACE encrypts an entry's packed data, zero-padded to whole blocks. BeeZip
/// writes no ACE archives: this is for building test archives.
#[doc(hidden)]
pub fn encrypt(password: &str, data: &[u8]) -> Vec<u8> {
    let cipher = cipher(password);
    let mut out = data.to_vec();
    out.resize(data.len().div_ceil(BLOCK) * BLOCK, 0);
    let mut iv = (0, 0);
    for chunk in out.as_chunks_mut::<BLOCK>().0 {
        let (l, r) = words(chunk);
        iv = cipher.encrypt(l ^ iv.0, r ^ iv.1);
        *chunk = bytes(iv);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_matches_acefile() {
        // acefile's `AceBlowfish._derive_key` doctest.
        assert_eq!(
            derive_key(b"123456789"),
            [
                3_071_200_156,
                3_325_860_325,
                4_058_316_933,
                1_308_772_094,
                896_611_998
            ]
        );
    }

    fn decrypt(password: &str, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Decrypt::new(data, password).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn decryption_matches_acefile() {
        // acefile's `AceBlowfish` doctest: two calls on one engine, so the second block chains
        // from the first.
        let mut two = vec![0xFF; 8];
        two.extend_from_slice(&[0xC7; 8]);
        let plain = decrypt("123456789", &two).unwrap();
        assert_eq!(&plain[..8], b"\xb7wF@5.er");
        assert_eq!(&plain[8..], b"eE\x05\xc4\xa5\x85)\xbc");
        // And its `EncryptedFileIO` doctest.
        assert_eq!(
            decrypt("123456789", b"7777777777777777").unwrap(),
            b"\t_\xd0a}\x1dh\xdd>h\xe7VJ*_\xea"
        );
        assert!(decrypt("123456789", &[b'7'; 17]).is_err(), "a cut block");
    }

    #[test]
    fn encryption_round_trips() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i * 31) as u8).collect();
        let sealed = encrypt("pässwörd", &data);
        assert_eq!(sealed.len(), 40_000);
        assert_ne!(sealed[..64], data[..64]);
        assert_eq!(decrypt("pässwörd", &sealed).unwrap(), data);
        assert_ne!(decrypt("password", &sealed).unwrap(), data);
        let short = encrypt("x", b"abc");
        assert_eq!(&decrypt("x", &short).unwrap()[..3], b"abc");
    }
}
