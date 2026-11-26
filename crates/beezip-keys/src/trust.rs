//! Whom a signature is from, and whether to trust it (docs/M14.md §11, decision 25): your own
//! key, a contact, or a certificate whose chain the system trusts (Windows' chain engine with
//! its revocation check, macOS's trust evaluation; on Linux only contacts). Signers are matched
//! on their whole signer bytes, never on a fingerprint (bhive.md §13.5); the fingerprint is
//! what is shown for someone unknown.

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::{
        crypt::{bech32, cert, sig},
        sign::{Algorithm, SignatureInfo},
    },
};

use crate::identity::{KeyEntry, KeyKind, Store, signing};

/// Who signed, as BeeZip shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// One of your own signing keys.
    Yours(String),
    /// A contact's key or certificate, by the name you gave it.
    Contact(String),
    /// A certificate the system trusts, by its subject.
    Certificate {
        subject: String,
    },
    /// A certificate someone vouches for (a contact, or an issuer the system trusts) that has
    /// since expired or been revoked. An untrusted certificate is `Unknown`, whatever its dates.
    Expired {
        subject: String,
    },
    Revoked {
        subject: String,
    },
    /// Nobody you know: the fingerprint, or the certificate's subject and issuer.
    Unknown {
        who: String,
    },
}

/// The fingerprint people compare (bhive.md §13.5): the first 10 bytes of the SHA-256 of the
/// signer bytes in base32, 16 characters in groups of four. The signing module's, here too.
pub use beezip_core::format::bhive::sign::fingerprint;

/// What is shown for a certificate nobody vouches for: its subject and issuer.
fn who(certificate: &cert::Certificate) -> String {
    if certificate.issuer.is_empty() || certificate.issuer == certificate.subject {
        format!("{} (self-signed)", certificate.subject)
    } else {
        format!("{} (issued by {})", certificate.subject, certificate.issuer)
    }
}

/// Your keys and contacts, or none while that part isn't built (`identity`, PRs C and H).
fn not_built(e: &Error) -> bool {
    e.kind == ErrorKind::UnsupportedOperation
}

fn entries(store: &Store) -> Result<Vec<KeyEntry>> {
    match store.list() {
        Err(e) if not_built(&e) => Ok(Vec::new()),
        other => other,
    }
}

/// Your own signing keys' and contacts' entries whose key bytes are `signer`.
fn known(store: &Store, signer: &[u8]) -> Result<Option<Trust>> {
    let own = match signing::own_signers(store) {
        Ok(own) => own,
        Err(e) if not_built(&e) => Vec::new(),
        Err(e) => return Err(e),
    };
    let entries = entries(store)?;
    let print = fingerprint(signer);
    if own.iter().any(|k| k.as_slice() == signer) {
        // Matched on the whole key; the name is the entry with its fingerprint.
        let name = entries
            .iter()
            .find(|e| e.own && e.kind == KeyKind::Signing && e.fingerprint == print)
            .map_or_else(|| print.clone(), |e| e.name.clone());
        return Ok(Some(Trust::Yours(name)));
    }
    for e in entries
        .iter()
        .filter(|e| !e.own && e.kind == KeyKind::Signing)
    {
        if let Ok(bech32::KeyText::SigningPublic(key)) = bech32::parse_key(&e.public)
            && key.as_slice() == signer
        {
            return Ok(Some(Trust::Contact(e.name.clone())));
        }
    }
    Ok(None)
}

/// The contact whose certificate is the signer's own, matched on the whole certificate (never a
/// fingerprint). A contact's certificate is kept as its PEM text; until contacts can hold
/// certificates (`keys.import` of one is not built yet), nobody matches.
fn certificate_contact(store: &Store, leaf: &[u8]) -> Result<Option<String>> {
    Ok(entries(store)?
        .into_iter()
        .filter(|e| !e.own && e.public.contains("-----BEGIN"))
        .find(|e| cert::parse(e.public.as_bytes()).is_ok_and(|c| c.der == leaf))
        .map(|e| e.name))
}

/// The trust of one valid signature.
pub fn trust(store: &Store, signature: &SignatureInfo) -> Result<Trust> {
    let unknown = || Trust::Unknown {
        who: fingerprint(&signature.signer),
    };
    match Algorithm::from_id(signature.algorithm) {
        Some(Algorithm::MlDsa65Ed25519) => {
            Ok(known(store, &signature.signer)?.unwrap_or_else(unknown))
        }
        Some(_) => certificate_trust(store, &signature.signer),
        None => Ok(unknown()),
    }
}

/// A certificate signer: a contact, or revoked, expired or trusted by the system, or unknown. A
/// certificate whose key usage forbids signatures is unknown, whatever its chain. Its dates and
/// revocation are only reported for a certificate someone vouches for (a contact, or an issuer
/// the system trusts): an archive's maker chooses everything else about a certificate it
/// carries, its name and dates included, so an untrusted one is unknown whatever they say.
fn certificate_trust(store: &Store, signer: &[u8]) -> Result<Trust> {
    let Ok(chain) = sig::certificates(signer) else {
        return Ok(Trust::Unknown {
            who: fingerprint(signer),
        });
    };
    // DER from the archive: never read as PEM.
    let Some(Ok(first)) = chain.first().map(|der| cert::parse_der(der)) else {
        return Ok(Trust::Unknown {
            who: fingerprint(signer),
        });
    };
    if first.digital_signature == Some(false) {
        return Ok(Trust::Unknown { who: who(&first) });
    }
    let subject = first.subject.clone();
    let expired = first.expired(crate::files::now());
    if let Some(name) = certificate_contact(store, &first.der)? {
        return Ok(if expired {
            Trust::Expired { subject }
        } else {
            Trust::Contact(name)
        });
    }
    Ok(match system_trust(&chain) {
        System::Untrusted => Trust::Unknown { who: who(&first) },
        System::Revoked => Trust::Revoked { subject },
        System::Expired => Trust::Expired { subject },
        System::Trusted if expired => Trust::Expired { subject },
        System::Trusted => Trust::Certificate { subject },
    })
}

/// What the system makes of a chain. `Expired` and `Revoked` are only for a chain the system
/// otherwise trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(any(windows, target_os = "macos")),
    allow(dead_code, reason = "Linux has no system trust for signing")
)]
enum System {
    Trusted,
    Expired,
    Revoked,
    Untrusted,
}

/// Windows' chain engine: from what Windows has cached first, then, for a chain whose root
/// Windows trusts, with revocation checked (which may ask the issuer online, decision 25).
#[cfg(windows)]
fn system_trust(chain: &[Vec<u8>]) -> System {
    match crate::cng::chain(chain) {
        Ok(c) if !c.anchored() => System::Untrusted,
        Ok(c) if c.revoked() => System::Revoked,
        Ok(c) if c.expired() => System::Expired,
        Ok(_) => System::Trusted,
        Err(_) => System::Untrusted,
    }
}

/// macOS's trust evaluation, offline first in the same way.
#[cfg(target_os = "macos")]
fn system_trust(chain: &[Vec<u8>]) -> System {
    use crate::mac::Evaluation;
    match crate::mac::evaluate(chain) {
        Ok(Evaluation::Trusted) => System::Trusted,
        Ok(Evaluation::Expired) => System::Expired,
        Ok(Evaluation::Revoked) => System::Revoked,
        _ => System::Untrusted,
    }
}

/// Linux has no system trust for signing: a certificate is known only as a contact.
#[cfg(not(any(windows, target_os = "macos")))]
fn system_trust(_chain: &[Vec<u8>]) -> System {
    System::Untrusted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::{data, hex, vectors};
    use beezip_core::format::bhive::sign::Status;

    fn signature(algorithm: u8, signer: Vec<u8>) -> SignatureInfo {
        SignatureInfo {
            algorithm,
            signer,
            time: None,
            status: Status::Valid,
        }
    }

    #[test]
    fn fingerprints_are_the_specifications() {
        let v = vectors();
        let ex = &v["signed_example"];
        let signer = [hex(&ex["ed25519_public"]), hex(&ex["mldsa_public"])].concat();
        assert_eq!(fingerprint(&signer), ex["fingerprint"].as_str().unwrap());
    }

    #[test]
    fn an_unknown_key_is_shown_by_its_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_owned());
        let signer = vec![7; 1984];
        assert_eq!(
            trust(&store, &signature(1, signer.clone())).unwrap(),
            Trust::Unknown {
                who: fingerprint(&signer)
            }
        );
        assert!(matches!(
            trust(&store, &signature(9, signer)).unwrap(),
            Trust::Unknown { .. }
        ));
    }

    /// A certificate nobody vouches for is unknown, its subject and issuer shown as what they
    /// claim: expired or not, since its maker chose its dates as they chose its name.
    #[test]
    fn untrusted_certificates_are_unknown_whatever_their_dates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_owned());
        let der = |f: &str| cert::parse(&std::fs::read(data(f)).unwrap()).unwrap().der;
        let rsa = sig::signer_bytes(&[der("rsa.crt")]).unwrap();
        assert_eq!(
            trust(&store, &signature(2, rsa)).unwrap(),
            Trust::Unknown {
                who: "BeeZip test rsa (self-signed)".into()
            }
        );
        let expired = sig::signer_bytes(&[der("rsa-expired.crt")]).unwrap();
        assert_eq!(
            trust(&store, &signature(2, expired)).unwrap(),
            Trust::Unknown {
                who: "BeeZip test rsa-expired (self-signed)".into()
            }
        );
        let pem = std::fs::read(data("chain.pem")).unwrap();
        let chain: Vec<_> = cert::parse_all(&pem)
            .unwrap()
            .into_iter()
            .map(|c| c.der)
            .collect();
        assert_eq!(
            trust(&store, &signature(4, sig::signer_bytes(&chain).unwrap())).unwrap(),
            Trust::Unknown {
                who: "BeeZip test leaf (issued by BeeZip test CA)".into()
            }
        );
        assert!(matches!(
            trust(&store, &signature(4, vec![1, 2])).unwrap(),
            Trust::Unknown { .. }
        ));
    }
}
