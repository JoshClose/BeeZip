//! Whom a signature is from, and whether to trust it (docs/M14.md §11, decision 25): your own
//! key, a contact, or a certificate whose chain the system trusts (Windows' chain engine with
//! its revocation check, macOS's trust evaluation; on Linux only contacts). PR D builds it,
//! with PR H for your own signing keys.

use beezip_core::{Result, format::bhive::sign::SignatureInfo};

use crate::{identity::Store, not_built};

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
    /// A certificate, trusted or not, that has since expired or been revoked.
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

/// The trust of one valid signature.
pub fn trust(store: &Store, signature: &SignatureInfo) -> Result<Trust> {
    let _ = (store, signature);
    Err(not_built("checking signers"))
}
