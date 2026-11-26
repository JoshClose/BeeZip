//! `.pfx` and `.p12` files (PKCS #12): a certificate and its private key under a password, given
//! for one job (`--identity` to open, `--sign` to sign; docs/M14.md §6).
//!
//! - **Windows** reads the file into a certificate store in memory and its keys into CNG's
//!   software provider without persisting them ([`crate::cng`]).
//! - **macOS** reads it through Security.framework, which imports PKCS #12 only into a
//!   keychain: each file gets a throwaway keychain of its own, deleted when the job is done
//!   with it (`mac::pfx`).
//!
//! Either way nothing is written to your certificate stores, key containers or keychains, and
//! nothing is left afterwards. Linux has no system to read one with, and BeeZip no PKCS #12
//! reader of its own (`p12-keystore`, 35 new crates, was left out because Windows and macOS
//! read `.pfx` themselves, docs/M14.md §2), so there it is refused with what to do instead.

use std::sync::Arc;

use beezip_core::{
    Result,
    format::bhive::{crypt::KeySource, sign::Signer},
};

/// Whether `bytes` are a PKCS #12 file: a `PFX` (RFC 7292 §4) whose version is 3 and whose
/// content is PKCS #7 data or signed data. Nothing else BeeZip reads starts so: certificates,
/// PKCS #8 and PKCS #1 keys start with another SEQUENCE or with version 0, SEC 1 keys with 1.
/// The `PFX` and its content may be BER with an indefinite length, which RFC 7292 allows and
/// some programs write.
pub fn is_pfx(bytes: &[u8]) -> bool {
    /// The bytes after a tag and length at `bytes[0]`, when the tag is `tag`: as long as the
    /// length says, or the rest for an indefinite length (BER's 0x80, ended by two zero bytes
    /// that only a parser needs to find).
    fn inside(bytes: &[u8], tag: u8) -> Option<&[u8]> {
        let (&t, rest) = bytes.split_first()?;
        let (&first, rest) = rest.split_first()?;
        if t != tag {
            return None;
        }
        let (len, rest) = match first {
            0x80 => return Some(rest),
            0..0x80 => (usize::from(first), rest),
            _ => {
                let n = usize::from(first & 0x7F);
                if n > 4 || rest.len() < n {
                    return None;
                }
                let len = rest[..n]
                    .iter()
                    .fold(0usize, |len, &b| (len << 8) | usize::from(b));
                (len, &rest[n..])
            }
        };
        rest.get(..len)
    }
    // PKCS #7 data (1.2.840.113549.1.7.1) or signed data (….7.2).
    const PKCS7: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07];
    let Some(pfx) = inside(bytes, 0x30) else {
        return false;
    };
    let Some(after_version) = pfx.strip_prefix(&[0x02, 0x01, 0x03]) else {
        return false;
    };
    inside(after_version, 0x30).is_some_and(|auth_safe| {
        auth_safe
            .strip_prefix(PKCS7)
            .is_some_and(|rest| matches!(rest.first(), Some(1 | 2)))
    })
}

/// What to do with a `.pfx` where BeeZip can't open one.
#[cfg(not(any(windows, target_os = "macos")))]
fn refused() -> beezip_core::Error {
    beezip_core::Error::new(
        beezip_core::ErrorKind::UnsupportedOperation,
        "BeeZip opens .pfx and .p12 files on Windows and macOS. Here, convert it to PEM files \
         first (`openssl pkcs12 -in FILE -out key.pem`, which keeps the key under a password) \
         and give that file instead",
    )
}

/// The private keys of a `.pfx`, as a key source: tried silently, as a key file is. `password`
/// `None` tries none and an empty one, and asks for one (`PasswordRequired`) when the file has
/// one; a wrong one is `WrongPassword`.
pub fn source(bytes: &[u8], password: Option<&str>) -> Result<Box<dyn KeySource + Send>> {
    #[cfg(windows)]
    {
        crate::cng::pfx::source(bytes, password)
    }
    #[cfg(target_os = "macos")]
    {
        crate::mac::pfx::source(bytes, password)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (bytes, password);
        Err(refused())
    }
}

/// A signer for the certificate in a `.pfx` that has its private key, carrying the other
/// certificates of its chain that the file or the system has. Its password as for [`source`].
pub fn signer(bytes: &[u8], password: Option<&str>) -> Result<Arc<dyn Signer>> {
    #[cfg(windows)]
    {
        crate::cng::pfx::signer(bytes, password)
    }
    #[cfg(target_os = "macos")]
    {
        crate::mac::pfx::signer(bytes, password)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (bytes, password);
        Err(refused())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::data;

    #[test]
    fn pfx_files_are_told_from_other_key_files() {
        for f in [
            "rsa.pfx",
            "rsa-3des.pfx",
            "p256.pfx",
            "p256-3des.pfx",
            "p256-ecdsa.pfx",
        ] {
            assert!(is_pfx(&std::fs::read(data(f)).unwrap()), "{f}");
        }
        for f in [
            "rsa.crt",
            "rsa.der",
            "rsa.key",
            "rsa-pkcs1.key",
            "p256-sec1.key",
            "p384-encrypted.key",
            "p256.pub",
            "README.md",
        ] {
            let bytes = std::fs::read(data(f)).unwrap();
            assert!(!is_pfx(&bytes), "{f}");
            // As DER where the file is PEM.
            if let Ok(blocks) = beezip_core::format::bhive::crypt::cert::pem_blocks(&bytes) {
                for (label, der) in blocks {
                    assert!(!is_pfx(&der), "{f}: {label}");
                }
            }
        }
        assert!(!is_pfx(&[]));
        assert!(!is_pfx(&[
            0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x03
        ]));
        let mut cut = std::fs::read(data("rsa.pfx")).unwrap();
        cut.truncate(40);
        assert!(!is_pfx(&cut));
    }

    /// BER's indefinite lengths, which some programs write for the `PFX` and its content: the
    /// tag, version 3 and the PKCS #7 type are still what tell a `.pfx`.
    #[test]
    fn pfx_files_with_indefinite_lengths_are_told_too() {
        const DATA: [u8; 11] = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];
        let ber = |outer: &[u8], version: u8, inner: &[u8], oid: &[u8]| {
            [
                outer,
                &[0x02, 0x01, version],
                inner,
                oid,
                &[0xA0, 0x80, 0, 0, 0, 0],
            ]
            .concat()
        };
        let (indefinite, definite) = ([0x30, 0x80].as_slice(), [0x30, 0x0D].as_slice());
        assert!(is_pfx(&ber(indefinite, 3, indefinite, &DATA)));
        assert!(is_pfx(&ber(indefinite, 3, definite, &DATA)));
        // Signed data (….7.2) too.
        let mut signed = DATA;
        signed[10] = 2;
        assert!(is_pfx(&ber(indefinite, 3, indefinite, &signed)));
        // Another version, another content type, another tag: not a .pfx.
        assert!(!is_pfx(&ber(indefinite, 0, indefinite, &DATA)));
        let mut enveloped = DATA;
        enveloped[10] = 3;
        assert!(!is_pfx(&ber(indefinite, 3, indefinite, &enveloped)));
        assert!(!is_pfx(&ber(&[0x31, 0x80], 3, indefinite, &DATA)));
        assert!(!is_pfx(&ber(indefinite, 3, &[0x31, 0x80], &DATA)));
        assert!(!is_pfx(&[0x30, 0x80]));
    }

    /// Where BeeZip can't open a `.pfx`, it says so, and what to do instead, before any password
    /// is asked for.
    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn pfx_files_are_refused_here_with_what_to_do() {
        let bytes = std::fs::read(data("rsa.pfx")).unwrap();
        for e in [
            source(&bytes, None).err().unwrap(),
            signer(&bytes, None).err().unwrap(),
            source(&bytes, Some("honey")).err().unwrap(),
        ] {
            assert_eq!(e.kind, beezip_core::ErrorKind::UnsupportedOperation);
            assert!(e.message.contains("openssl pkcs12"), "{}", e.message);
        }
    }
}
