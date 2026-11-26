//! A software authenticator for tests: it registers credentials and answers hmac-secret as
//! CTAP 2.1 §12.5 does (HMAC-SHA256 under a random secret per credential, one with user
//! verification and one without), with no device and no dialog. BeeZip's commands never use
//! it; tests here and in the crates above do, to seal an archive to a security-key slot and
//! open it again end to end.

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::crypt::fido2::{self, hmac_secret, prf_salt},
};
use zeroize::Zeroizing;

use super::{Attachment, Authenticator, NewCredential, SecretRequest, Support};

/// What a test asked of the mock, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Make {
        attachment: Attachment,
    },
    Secret {
        attachment: Attachment,
        prf: bool,
        uv: bool,
    },
    Delete,
}

#[derive(Clone)]
struct Credential {
    id: Vec<u8>,
    rp_id: String,
    with_uv: Zeroizing<[u8; 32]>,
    without_uv: Zeroizing<[u8; 32]>,
    platform: bool,
}

/// One security key and one Windows Hello, in memory.
#[derive(Clone)]
pub struct MockAuthenticator {
    /// What it says it can do: everything, unless a test says otherwise.
    pub support: Support,
    /// New credentials get hmac-secret.
    pub hmac_secret: bool,
    /// Every hmac-secret request fails as a closed dialog.
    pub cancel_secrets: bool,
    /// What was asked.
    pub calls: Vec<Call>,
    credentials: Vec<Credential>,
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl MockAuthenticator {
    pub fn new() -> Self {
        Self {
            support: Support {
                security_keys: true,
                hello: true,
                api_version: 9,
            },
            hmac_secret: true,
            cancel_secrets: false,
            calls: Vec::new(),
            credentials: Vec::new(),
        }
    }

    /// How many credentials it holds.
    pub fn credentials(&self) -> usize {
        self.credentials.len()
    }
}

impl std::fmt::Debug for MockAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockAuthenticator")
            .field("support", &self.support)
            .field("credentials", &self.credentials.len())
            .field("calls", &self.calls)
            .finish()
    }
}

impl Authenticator for MockAuthenticator {
    fn support(&self) -> Support {
        self.support
    }

    fn make_credential(
        &mut self,
        rp_id: &str,
        user_id: &[u8],
        attachment: Attachment,
    ) -> Result<NewCredential> {
        self.calls.push(Call::Make { attachment });
        if user_id.is_empty() || user_id.len() > 64 {
            return Err(Error::invalid_args("a user id is 1 to 64 bytes"));
        }
        // A security key's id is often its wrapped key, 48 bytes or more; Hello's are 32.
        let mut id = fido2::new_salt()?.to_vec();
        if attachment != Attachment::Platform {
            id.extend_from_slice(&fido2::new_salt()?[..16]);
        }
        self.credentials.push(Credential {
            id: id.clone(),
            rp_id: rp_id.to_string(),
            with_uv: Zeroizing::new(fido2::new_salt()?),
            without_uv: Zeroizing::new(fido2::new_salt()?),
            platform: attachment == Attachment::Platform,
        });
        Ok(NewCredential {
            id,
            hmac_secret: self.hmac_secret,
        })
    }

    fn hmac_secret(&mut self, request: &SecretRequest<'_>) -> Result<Zeroizing<[u8; 32]>> {
        self.calls.push(Call::Secret {
            attachment: request.attachment,
            prf: request.prf,
            uv: request.uv,
        });
        if self.cancel_secrets {
            return Err(Error::cancelled());
        }
        let Some(c) = self
            .credentials
            .iter()
            .find(|c| c.id == request.credential_id && c.rp_id == request.rp_id)
        else {
            return Err(Error::new(
                ErrorKind::KeyRequired,
                "no security key or Windows Hello here has this credential",
            ));
        };
        let salt = if request.prf {
            prf_salt(request.salt)
        } else {
            *request.salt
        };
        let cred_random = if request.uv {
            &c.with_uv
        } else {
            &c.without_uv
        };
        Ok(hmac_secret(cred_random, &salt))
    }

    fn is_platform_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> bool {
        self.credentials
            .iter()
            .any(|c| c.platform && c.id == credential_id && c.rp_id == rp_id)
    }

    fn delete_platform_credential(&mut self, credential_id: &[u8]) -> Result<()> {
        self.calls.push(Call::Delete);
        let before = self.credentials.len();
        self.credentials
            .retain(|c| !(c.platform && c.id == credential_id));
        if self.credentials.len() == before {
            return Err(Error::new(ErrorKind::NotFound, "no such credential"));
        }
        Ok(())
    }
}
