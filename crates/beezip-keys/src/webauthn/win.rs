//! The authenticator behind webauthn.dll: a security key over USB, NFC or Bluetooth, a phone,
//! or Windows Hello. Registering and asking for hmac-secret always show Windows Security's
//! dialog; [`support`] and the list of this PC's credentials show nothing.
//!
//! - **Registering** (`WebAuthNAuthenticatorMakeCredential`): BeeZip's relying party, a random
//!   user id (so a new credential never replaces another one on the device), ES256 or RS256,
//!   user verification required, no attestation. A security key's credential isn't resident
//!   (it lives in its id, so the key's storage isn't used) and asks for the `hmac-secret`
//!   extension; Windows Hello's asks for PRF (`bEnablePrf`, options version 6), which is how
//!   Windows offers hmac-secret there, and from options version 8 for PRF's output for the
//!   slot's salt (`pPRFGlobalEval`). Windows 11 then sets `bPrfEnabled` and returns the output
//!   in the attestation's `pHmacSecret` (version 7 or later), wiped in Windows' copy before it is
//!   freed; given `bEnablePrf` alone, it says PRF is off (wave 2, Windows 11 build 26300).
//! - **Asking for hmac-secret** (`WebAuthNAuthenticatorGetAssertion`): the slot's credential as
//!   the only one allowed, `pHmacSecretSaltValues.pGlobalHmacSalt` the slot's salt (options
//!   version 6 or later), with `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` when the salt
//!   goes to the authenticator as it is and without it for PRF; the output is the assertion's
//!   `pHmacSecret` (version 3 or later), wiped in Windows' copy before it is freed.
#![allow(unsafe_code)]

use std::ffi::c_void;

use beezip_core::{Error, ErrorKind, Result, format::bhive::crypt::fido2};
use zeroize::{Zeroize, Zeroizing};

use super::{
    Attachment, Authenticator, MIN_API, MIN_API_HELLO, NewCredential, SecretRequest, Support,
    ffi::{self, Api},
};

/// How long Windows' dialog waits, as guidance: two minutes.
const TIMEOUT_MS: u32 = 120_000;

/// What this PC offers, asked of webauthn.dll without showing anything.
pub fn support() -> Support {
    let Some(api) = ffi::api() else {
        return Support::NONE;
    };
    let security_keys = api.version >= MIN_API;
    Support {
        security_keys,
        hello: security_keys && api.version >= MIN_API_HELLO && api.platform_authenticator(),
        api_version: api.version,
    }
}

/// webauthn.dll, with the window its dialogs belong to.
pub struct WebAuthn {
    window: Option<isize>,
}

impl WebAuthn {
    /// Windows' dialogs will belong to `window`, or without one to the window in front.
    pub fn new(window: Option<isize>) -> Self {
        Self { window }
    }

    fn api(&self) -> Result<&'static Api> {
        match ffi::api() {
            Some(api) if api.version >= MIN_API => Ok(api),
            Some(api) => Err(Error::unsupported(format!(
                "this Windows can't ask security keys for hmac-secret (webauthn.dll API version \
                 {}; {MIN_API} or later is needed)",
                api.version
            ))),
            None => Err(Error::unsupported(
                "this Windows has no webauthn.dll, which security keys need",
            )),
        }
    }

    fn window(&self) -> *mut c_void {
        match self.window {
            Some(w) => w as *mut c_void,
            None => ffi::foreground_window(),
        }
    }
}

impl Attachment {
    fn code(self) -> u32 {
        match self {
            Self::Any => ffi::AUTHENTICATOR_ATTACHMENT_ANY,
            Self::Platform => ffi::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            Self::CrossPlatform => ffi::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        }
    }
}

/// What a failed call means for people: a closed dialog is `Cancelled`, a device without the
/// credential `KeyRequired`.
fn error(api: &Api, hr: i32, doing: &str) -> Error {
    let name = api.error_name(hr);
    match hr as u32 {
        ffi::hr::CANCELLED | ffi::hr::NTE_USER_CANCELLED => Error::cancelled(),
        ffi::hr::TIMEOUT => Error::new(
            ErrorKind::Cancelled,
            format!("{doing}: Windows' dialog timed out"),
        ),
        ffi::hr::NTE_NOT_FOUND | ffi::hr::NTE_DEVICE_NOT_FOUND => Error::new(
            ErrorKind::KeyRequired,
            format!(
                "{doing}: no security key or Windows Hello here has this credential ({name}, \
                 0x{hr:08X})"
            ),
        ),
        ffi::hr::NTE_INVALID_PARAMETER | ffi::hr::NTE_NOT_SUPPORTED | ffi::hr::NOT_SUPPORTED => {
            Error::unsupported(format!(
                "{doing}: Windows refused the request ({name}, 0x{hr:08X})"
            ))
        }
        _ => Error::new(
            ErrorKind::Io,
            format!("{doing} failed: {name} (0x{hr:08X})"),
        ),
    }
}

/// A random challenge in client data that looks like a browser's. Nothing checks the signature
/// the authenticator makes over it: only the hmac-secret output is used.
fn client_data(kind: &str) -> Result<Vec<u8>> {
    let challenge = fido2::new_salt()?;
    Ok(format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        base64url(&challenge),
        fido2::RP_ID
    )
    .into_bytes())
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
        }
    }
    out
}

/// An attestation Windows allocated, freed when dropped. A PRF output in it is wiped first, as
/// an assertion's is.
struct AttestationGuard<'a>(&'a Api, *mut ffi::CredentialAttestation);

impl Drop for AttestationGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: Windows allocated it, and it is freed once. `pHmacSecret` is read only when
        // the attestation's version says it is there (7 or later), and its buffers are wiped
        // within their lengths.
        unsafe {
            let a = &*self.1;
            if a.dw_version >= 7 && !a.p_hmac_secret.is_null() {
                wipe(&*a.p_hmac_secret);
            }
            (self.0.free_credential_attestation)(self.1)
        }
    }
}

/// Wipes an hmac-secret output in Windows' memory.
///
/// # Safety
/// Its pointers are null or point to buffers of their lengths, writable until freed.
unsafe fn wipe(h: &ffi::HmacSecretSalt) {
    for (p, n) in [(h.pb_first, h.cb_first), (h.pb_second, h.cb_second)] {
        if !p.is_null() && n > 0 {
            // SAFETY: as the caller promises.
            unsafe { std::slice::from_raw_parts_mut(p, n as usize) }.zeroize();
        }
    }
}

/// An assertion Windows allocated, freed when dropped. Any hmac-secret output in it is wiped
/// first, on every path: Windows' copy is heap memory it hands to the caller until it is freed.
struct AssertionGuard<'a>(&'a Api, *mut ffi::Assertion);

impl Drop for AssertionGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: Windows allocated it, and it is freed once. `pHmacSecret` is read only when
        // the assertion's version says it is there (3 or later), and its buffers are wiped
        // within their lengths.
        unsafe {
            let a = &*self.1;
            if a.dw_version >= 3 && !a.p_hmac_secret.is_null() {
                wipe(&*a.p_hmac_secret);
            }
            (self.0.free_assertion)(self.1)
        }
    }
}

impl Authenticator for WebAuthn {
    fn support(&self) -> Support {
        support()
    }

    fn make_credential(
        &mut self,
        rp_id: &str,
        user_id: &[u8],
        attachment: Attachment,
        prf_salt: Option<&[u8; 32]>,
    ) -> Result<NewCredential> {
        let api = self.api()?;
        let rp_id_w = ffi::wide(rp_id);
        let rp_name = ffi::wide("BeeZip");
        let rp = ffi::RpEntityInformation {
            dw_version: ffi::RP_ENTITY_INFORMATION_VERSION,
            pwsz_id: rp_id_w.as_ptr(),
            pwsz_name: rp_name.as_ptr(),
            pwsz_icon: std::ptr::null(),
        };
        let user_name = ffi::wide("BeeZip archives");
        let mut user_id = user_id.to_vec();
        let user = ffi::UserEntityInformation {
            dw_version: ffi::USER_ENTITY_INFORMATION_VERSION,
            cb_id: user_id.len() as u32,
            pb_id: user_id.as_mut_ptr(),
            pwsz_name: user_name.as_ptr(),
            pwsz_icon: std::ptr::null(),
            pwsz_display_name: user_name.as_ptr(),
        };
        let mut algorithms = [
            ffi::CoseCredentialParameter {
                dw_version: ffi::COSE_CREDENTIAL_PARAMETER_VERSION,
                pwsz_credential_type: ffi::CREDENTIAL_TYPE_PUBLIC_KEY,
                l_alg: ffi::COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
            },
            ffi::CoseCredentialParameter {
                dw_version: ffi::COSE_CREDENTIAL_PARAMETER_VERSION,
                pwsz_credential_type: ffi::CREDENTIAL_TYPE_PUBLIC_KEY,
                l_alg: ffi::COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256,
            },
        ];
        let parameters = ffi::CoseCredentialParameters {
            c_credential_parameters: algorithms.len() as u32,
            p_credential_parameters: algorithms.as_mut_ptr(),
        };
        let mut json = client_data("webauthn.create")?;
        let client = ffi::ClientData {
            dw_version: ffi::CLIENT_DATA_VERSION,
            cb_client_data_json: json.len() as u32,
            pb_client_data_json: json.as_mut_ptr(),
            pwsz_hash_alg_id: ffi::HASH_ALGORITHM_SHA_256,
        };
        let hello = attachment == Attachment::Platform;
        let mut yes: ffi::Bool = 1;
        let mut extensions = [ffi::Extension {
            pwsz_extension_identifier: ffi::EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cb_extension: size_of::<ffi::Bool>() as u32,
            pv_extension: (&raw mut yes).cast(),
        }];
        let mut options = ffi::MakeCredentialOptions {
            dw_version: ffi::make_options_version(api.version),
            dw_timeout_milliseconds: TIMEOUT_MS,
            dw_authenticator_attachment: attachment.code(),
            dw_user_verification_requirement: ffi::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dw_attestation_conveyance_preference: ffi::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            ..Default::default()
        };
        let mut eval = prf_salt.copied().unwrap_or_default();
        let mut eval_salt = ffi::HmacSecretSalt {
            cb_first: ffi::CTAP_ONE_HMAC_SECRET_LENGTH,
            pb_first: eval.as_mut_ptr(),
            cb_second: 0,
            pb_second: std::ptr::null_mut(),
        };
        if hello {
            // The field is in options version 6 (API version 6), which `support` requires
            // for Windows Hello.
            options.b_enable_prf = 1;
            // PRF's output for the salt, with the credential: version 8 (API version 8). The
            // salt goes as a PRF input (no HMAC_SECRET_VALUES_FLAG), as unlocking sends it.
            if prf_salt.is_some() && options.dw_version >= 8 {
                options.p_prf_global_eval = &raw mut eval_salt;
            }
        } else {
            options.extensions = ffi::Extensions {
                c_extensions: extensions.len() as u32,
                p_extensions: extensions.as_mut_ptr(),
            };
        }
        let mut out = std::ptr::null_mut();
        // SAFETY: every pointer is to a live, initialised structure of webauthn.h's layout,
        // whose strings are NUL-terminated and whose lengths are their buffers'; all outlive the
        // call. `out` is a valid out pointer.
        let hr = unsafe {
            (api.make_credential)(
                self.window(),
                &rp,
                &user,
                &parameters,
                &client,
                &options,
                &mut out,
            )
        };
        if hr < 0 {
            return Err(error(api, hr, "registering the security key"));
        }
        if out.is_null() {
            return Err(Error::new(
                ErrorKind::Io,
                "registering the security key: Windows returned nothing",
            ));
        }
        let guard = AttestationGuard(api, out);
        // SAFETY: Windows returned a valid attestation, freed only when `guard` drops; each
        // field is read only when its version says it is there.
        unsafe {
            let a = &*guard.1;
            let id = ffi::bytes(a.pb_credential_id, a.cb_credential_id).to_vec();
            let mut hmac_secret = false;
            if a.dw_version >= 2 && !a.extensions.p_extensions.is_null() {
                let extensions = std::slice::from_raw_parts(
                    a.extensions.p_extensions,
                    a.extensions.c_extensions as usize,
                );
                for e in extensions {
                    if ffi::wide_to_string(e.pwsz_extension_identifier) == "hmac-secret"
                        && e.cb_extension as usize == size_of::<ffi::Bool>()
                        && !e.pv_extension.is_null()
                        && *e.pv_extension.cast::<ffi::Bool>() != 0
                    {
                        hmac_secret = true;
                    }
                }
            }
            if a.dw_version >= 5 && a.b_prf_enabled != 0 {
                hmac_secret = true;
            }
            let mut prf_output = None;
            if prf_salt.is_some() && a.dw_version >= 7 && !a.p_hmac_secret.is_null() {
                let h = &*a.p_hmac_secret;
                if !h.pb_first.is_null() && h.cb_first == ffi::CTAP_ONE_HMAC_SECRET_LENGTH {
                    let mut out = Zeroizing::new([0; 32]);
                    out.copy_from_slice(ffi::bytes(h.pb_first, h.cb_first));
                    prf_output = Some(out);
                }
            }
            Ok(NewCredential {
                id,
                hmac_secret,
                prf_output,
            })
        }
    }

    fn hmac_secret(&mut self, request: &SecretRequest<'_>) -> Result<Zeroizing<[u8; 32]>> {
        let api = self.api()?;
        let doing = match request.attachment {
            Attachment::Platform => "asking Windows Hello",
            _ => "asking the security key",
        };
        let rp_id = ffi::wide(request.rp_id);
        let mut json = client_data("webauthn.get")?;
        let client = ffi::ClientData {
            dw_version: ffi::CLIENT_DATA_VERSION,
            cb_client_data_json: json.len() as u32,
            pb_client_data_json: json.as_mut_ptr(),
            pwsz_hash_alg_id: ffi::HASH_ALGORITHM_SHA_256,
        };
        let mut id = request.credential_id.to_vec();
        let mut credential = ffi::Credential {
            dw_version: ffi::CREDENTIAL_VERSION,
            cb_id: id.len() as u32,
            pb_id: id.as_mut_ptr(),
            pwsz_credential_type: ffi::CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        let mut salt = *request.salt;
        let mut salt_values = ffi::HmacSecretSalt {
            cb_first: ffi::CTAP_ONE_HMAC_SECRET_LENGTH,
            pb_first: salt.as_mut_ptr(),
            cb_second: 0,
            pb_second: std::ptr::null_mut(),
        };
        let mut salts = ffi::HmacSecretSaltValues {
            p_global_hmac_salt: &raw mut salt_values,
            c_cred_with_hmac_secret_salt_list: 0,
            p_cred_with_hmac_secret_salt_list: std::ptr::null_mut(),
        };
        let options = ffi::GetAssertionOptions {
            dw_version: ffi::get_options_version(api.version),
            dw_timeout_milliseconds: TIMEOUT_MS,
            credential_list: ffi::Credentials {
                c_credentials: 1,
                p_credentials: &raw mut credential,
            },
            dw_authenticator_attachment: request.attachment.code(),
            dw_user_verification_requirement: if request.uv {
                ffi::USER_VERIFICATION_REQUIREMENT_REQUIRED
            } else {
                ffi::USER_VERIFICATION_REQUIREMENT_DISCOURAGED
            },
            dw_flags: if request.prf {
                0
            } else {
                ffi::AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG
            },
            p_hmac_secret_salt_values: &raw mut salts,
            ..Default::default()
        };
        let mut out = std::ptr::null_mut();
        // SAFETY: as in `make_credential`: live structures of webauthn.h's layout, valid
        // strings and lengths, a valid out pointer.
        let hr = unsafe {
            (api.get_assertion)(self.window(), rp_id.as_ptr(), &client, &options, &mut out)
        };
        if hr < 0 {
            return Err(error(api, hr, doing));
        }
        if out.is_null() {
            return Err(Error::new(
                ErrorKind::Io,
                format!("{doing}: Windows returned nothing"),
            ));
        }
        let guard = AssertionGuard(api, out);
        // SAFETY: Windows returned a valid assertion, freed only when `guard` drops (which
        // wipes the output in Windows' copy, whichever way this returns); fields are read only
        // when its version says they are there.
        unsafe {
            let a = &*guard.1;
            let used = ffi::bytes(a.credential.pb_id, a.credential.cb_id);
            if used != request.credential_id {
                return Err(Error::new(
                    ErrorKind::Io,
                    format!("{doing}: the answer is for another credential"),
                ));
            }
            if a.dw_version < 3 || a.p_hmac_secret.is_null() {
                return Err(Error::unsupported(format!(
                    "{doing}: no hmac-secret came back; the authenticator may not support it"
                )));
            }
            let h = &*a.p_hmac_secret;
            if h.pb_first.is_null() || h.cb_first != ffi::CTAP_ONE_HMAC_SECRET_LENGTH {
                return Err(Error::unsupported(format!(
                    "{doing}: the hmac-secret that came back isn't 32 bytes"
                )));
            }
            let mut secret = Zeroizing::new([0; 32]);
            secret.copy_from_slice(ffi::bytes(h.pb_first, h.cb_first));
            Ok(secret)
        }
    }

    fn is_platform_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> bool {
        let Ok(api) = self.api() else {
            return false;
        };
        let Some((list, free)) = api.platform_credentials else {
            return false;
        };
        let rp_id = ffi::wide(rp_id);
        let options = ffi::GetCredentialsOptions {
            dw_version: ffi::GET_CREDENTIALS_OPTIONS_VERSION,
            pwsz_rp_id: rp_id.as_ptr(),
            b_browser_in_private_mode: 0,
        };
        let mut out = std::ptr::null_mut();
        // SAFETY: a valid options structure and out pointer. It shows nothing; with no
        // credentials it fails with NTE_NOT_FOUND.
        let hr = unsafe { list(&options, &mut out) };
        if hr < 0 || out.is_null() {
            return false;
        }
        // SAFETY: Windows returned a valid list, freed once below; every entry's id is read
        // within its length.
        unsafe {
            let l = &*out;
            let found = !l.pp_credential_details.is_null()
                && std::slice::from_raw_parts(
                    l.pp_credential_details,
                    l.c_credential_details as usize,
                )
                .iter()
                .any(|&d| {
                    !d.is_null()
                        && ffi::bytes((*d).pb_credential_id, (*d).cb_credential_id) == credential_id
                });
            free(out);
            found
        }
    }

    fn delete_platform_credential(&mut self, credential_id: &[u8]) -> Result<()> {
        let api = self.api()?;
        let Some(delete) = api.delete_platform_credential else {
            return Err(Error::unsupported(
                "this Windows can't delete Windows Hello credentials",
            ));
        };
        // SAFETY: the id and its length.
        let hr = unsafe { delete(credential_id.len() as u32, credential_id.as_ptr()) };
        if hr < 0 {
            return Err(error(api, hr, "deleting the Windows Hello credential"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use beezip_core::format::bhive::crypt::{Recipient, SlotKind, SlotSecret};

    use super::*;
    use crate::webauthn::tests::view_of;

    #[test]
    fn base64url_is_rfc_4648s() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url(&[0; 32]).len(), 43);
    }

    #[test]
    fn client_data_is_json() {
        let json = client_data("webauthn.get").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["type"], "webauthn.get");
        assert_eq!(v["challenge"].as_str().unwrap().len(), 43);
    }

    /// webauthn.dll's version and whether Windows Hello is set up, asked without any dialog.
    /// A CI runner may have neither.
    #[test]
    fn support_shows_nothing() {
        let s = support();
        eprintln!("{s:?}");
        assert_eq!(s, crate::webauthn::support());
        if s.api_version == 0 {
            assert_eq!(s, Support::NONE);
        }
        assert!(!s.hello || s.security_keys);
        assert_eq!(s.security_keys, s.api_version >= MIN_API);
        // Listing this PC's credentials for a relying party nobody uses shows nothing either.
        assert!(!WebAuthn::new(None).is_platform_credential("beezip.test.invalid", &[1, 2, 3]));
    }

    #[test]
    fn errors_say_what_happened() {
        let Some(api) = ffi::api() else {
            return;
        };
        let e = |hr: u32| error(api, hr as i32, "asking the security key");
        assert_eq!(e(ffi::hr::CANCELLED).kind, ErrorKind::Cancelled);
        assert_eq!(e(ffi::hr::NTE_USER_CANCELLED).kind, ErrorKind::Cancelled);
        assert_eq!(e(ffi::hr::TIMEOUT).kind, ErrorKind::Cancelled);
        assert_eq!(e(ffi::hr::NTE_NOT_FOUND).kind, ErrorKind::KeyRequired);
        assert_eq!(
            e(ffi::hr::NTE_INVALID_PARAMETER).kind,
            ErrorKind::UnsupportedOperation
        );
        let other = e(0x8000_4005);
        assert_eq!(other.kind, ErrorKind::Io);
        assert!(other.message.contains("0x80004005"), "{}", other.message);
    }

    /// Registers a credential on a security key, makes a slot, and opens it, as BeeZip does,
    /// then asks the same credential for a PRF salt twice. Shows Windows' dialog five times.
    #[test]
    #[ignore = "needs a person: a FIDO2 security key, its PIN and five touches"]
    fn a_security_key_opens_its_slot() {
        let recipient = crate::webauthn::recipient(false, None, None).unwrap();
        let Recipient::Fido2 {
            credential_id,
            rp_id,
            salt,
            prf,
            secret,
            machine_bound,
        } = &recipient
        else {
            panic!("not a security-key recipient");
        };
        assert!(!prf && !machine_bound);
        let made = fido2::make(credential_id, rp_id, salt, *prf, secret).unwrap();
        let (key_id, framed) = view_of(&made.public);
        let view = beezip_core::format::bhive::crypt::SlotView {
            index: 0,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
            commitment: &[0; 32],
        };
        let mut source = crate::webauthn::source(None).unwrap();
        assert!(source.offers(&view));
        let Some(SlotSecret::Shared(again)) = source.secret(&view, true).unwrap() else {
            panic!("no secret");
        };
        assert_eq!(again.as_slice(), secret.as_slice());

        let mut w = WebAuthn::new(None);
        let ask = |w: &mut WebAuthn| {
            w.hmac_secret(&SecretRequest {
                rp_id,
                credential_id,
                salt,
                prf: true,
                uv: true,
                attachment: Attachment::CrossPlatform,
            })
            .unwrap()
        };
        let a = ask(&mut w);
        assert_eq!(a, ask(&mut w));
        assert_ne!(a.as_slice(), secret.as_slice(), "PRF hashes the salt first");
    }

    /// The same with Windows Hello, deleting the credential it registers. Shows Windows Hello's
    /// prompt three times: registering (which gives the secret too), unlocking, and a raw salt.
    #[test]
    #[ignore = "needs a person: Windows Hello's face, fingerprint or PIN, three times"]
    fn windows_hello_opens_its_slot() {
        struct Delete(Vec<u8>);
        impl Drop for Delete {
            fn drop(&mut self) {
                let _ = WebAuthn::new(None).delete_platform_credential(&self.0);
            }
        }
        if !support().hello {
            eprintln!("Windows Hello isn't set up here");
            return;
        }
        let recipient = crate::webauthn::recipient(true, None, None).unwrap();
        let Recipient::Fido2 {
            credential_id,
            rp_id,
            salt,
            prf,
            secret,
            machine_bound,
        } = &recipient
        else {
            panic!("not a security-key recipient");
        };
        let _delete = Delete(credential_id.clone());
        assert!(*prf && *machine_bound);
        let mut w = WebAuthn::new(None);
        assert!(w.is_platform_credential(rp_id, credential_id));
        let made = fido2::make(credential_id, rp_id, salt, *prf, secret).unwrap();
        let (key_id, framed) = view_of(&made.public);
        let view = beezip_core::format::bhive::crypt::SlotView {
            index: 0,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
            commitment: &[0; 32],
        };
        let mut source = crate::webauthn::source(None).unwrap();
        let Some(SlotSecret::Shared(again)) = source.secret(&view, true).unwrap() else {
            panic!("no secret");
        };
        assert_eq!(again.as_slice(), secret.as_slice());
        // With the salt as it is, the answer differs (or Windows refuses raw salts for Hello).
        match w.hmac_secret(&SecretRequest {
            rp_id,
            credential_id,
            salt,
            prf: false,
            uv: true,
            attachment: Attachment::Platform,
        }) {
            Ok(raw) => assert_ne!(raw.as_slice(), secret.as_slice()),
            Err(e) => eprintln!("raw salts with Windows Hello: {}", e.message),
        }
    }
}
