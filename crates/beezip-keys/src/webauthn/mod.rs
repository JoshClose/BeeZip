//! Security keys and Windows Hello through webauthn.dll (docs/M14.md §4, slot kind 8): making a
//! slot's recipient, and a key source that asks the authenticator for a slot's hmac-secret.
//!
//! - **Windows only.** webauthn.dll is how a program reaches FIDO2 authenticators on Windows
//!   without administrator rights; on macOS and Linux [`support`] reports none and the others
//!   say why (docs/M14.md §12).
//! - **Every registration and every unlock shows Windows' dialog** (a PIN, a touch, Windows
//!   Hello's face, fingerprint or PIN), so BeeZip asks only when the user chose this way in:
//!   [`KeySource::secret`] with `device` set. [`support`] and [`KeySource::offers`] show
//!   nothing.
//! - **User verification is always required** for the slots BeeZip makes, so a stolen key
//!   without its PIN opens nothing.
//! - **Windows Hello** is the platform authenticator behind the same calls. Whether it can do
//!   hmac-secret depends on the Windows build, so BeeZip tries: a registration that comes back
//!   without it is deleted and refused, and BeeZip offers "This PC" instead (docs/M14.md §4).
//! - **The authenticator is a trait** ([`Authenticator`]), so the slot logic is tested with
//!   [`mock::MockAuthenticator`] and no device; tests of the real one need a person and are
//!   ignored.

pub mod mock;

#[cfg(windows)]
mod ffi;
#[cfg(windows)]
mod win;

use beezip_core::{
    Error, Result,
    format::bhive::crypt::{KeySource, Recipient, SlotKind, SlotSecret, SlotView, fido2},
};
use zeroize::Zeroizing;

/// The oldest webauthn.dll API that can ask for hmac-secret when unlocking: assertion options
/// version 6 (`pHmacSecretSaltValues`) and assertions version 3 (`pHmacSecret`).
pub const MIN_API: u32 = 4;
/// The oldest that can turn on PRF when registering (`bEnablePrf`, options version 6), which
/// Windows Hello needs.
pub const MIN_API_HELLO: u32 = 6;

/// What this machine can do, found without showing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Support {
    /// webauthn.dll can ask security keys for hmac-secret.
    pub security_keys: bool,
    /// Windows Hello is set up and webauthn.dll is new enough to try it. Whether this Windows
    /// gives hmac-secret for it is known only once a registration answers.
    pub hello: bool,
    /// webauthn.dll's API version (9 on Windows 11 in 2026); 0 without one, as on macOS and
    /// Linux.
    pub api_version: u32,
}

impl Support {
    pub const NONE: Self = Self {
        security_keys: false,
        hello: false,
        api_version: 0,
    };
}

/// What this machine can do: webauthn.dll's API version and whether Windows Hello is set up.
/// Shows nothing.
pub fn support() -> Support {
    #[cfg(windows)]
    {
        win::support()
    }
    #[cfg(not(windows))]
    {
        Support::NONE
    }
}

/// Registers a credential (or uses `credential`), asks it for the hmac-secret of a fresh
/// salt, and returns the recipient core makes the slot from. Shows Windows' dialog, parented to
/// `window` when there is one: twice for a new credential, once for one given.
pub fn recipient(
    hello: bool,
    credential: Option<&[u8]>,
    window: Option<isize>,
) -> Result<Recipient> {
    #[cfg(windows)]
    {
        recipient_with(&mut win::WebAuthn::new(window), hello, credential)
    }
    #[cfg(not(windows))]
    {
        let _ = (hello, credential, window);
        Err(off_windows())
    }
}

/// A key source for kind-8 slots: offers every one this machine could open, and asks the
/// authenticator only when the user chose it.
pub fn source(window: Option<isize>) -> Result<Box<dyn KeySource + Send>> {
    #[cfg(windows)]
    {
        Ok(Box::new(Fido2Source::new(win::WebAuthn::new(window))))
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        Ok(Box::new(Fido2Source::new(Unavailable)))
    }
}

/// Which authenticators Windows may offer in its dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    /// Any: Windows Hello, a security key, a phone.
    Any,
    /// Windows Hello.
    Platform,
    /// A security key, or a phone.
    CrossPlatform,
}

/// A credential just registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredential {
    pub id: Vec<u8>,
    /// It was made with hmac-secret (or PRF), which BeeZip needs.
    pub hmac_secret: bool,
}

/// An hmac-secret to ask a credential for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRequest<'a> {
    pub rp_id: &'a str,
    pub credential_id: &'a [u8],
    pub salt: &'a [u8; 32],
    /// The salt is a PRF input: Windows hashes it first (bhive.md §12.5, flag bit 0).
    pub prf: bool,
    /// User verification is required (flag bit 1); otherwise discouraged, since the
    /// authenticator answers differently with and without it.
    pub uv: bool,
    pub attachment: Attachment,
}

/// What BeeZip asks of an authenticator: webauthn.dll's, or a mock's in tests.
pub trait Authenticator {
    /// What it can do. Shows nothing.
    fn support(&self) -> Support;

    /// Registers a credential for `rp_id`, with user verification. Shows a dialog.
    fn make_credential(
        &mut self,
        rp_id: &str,
        user_id: &[u8],
        attachment: Attachment,
    ) -> Result<NewCredential>;

    /// The credential's hmac-secret output for a salt. Shows a dialog.
    fn hmac_secret(&mut self, request: &SecretRequest<'_>) -> Result<Zeroizing<[u8; 32]>>;

    /// Whether the credential is one of this PC's Windows Hello credentials. Shows nothing.
    fn is_platform_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> bool;

    /// Deletes one of this PC's Windows Hello credentials. Shows nothing.
    fn delete_platform_credential(&mut self, credential_id: &[u8]) -> Result<()>;
}

impl<A: Authenticator + ?Sized> Authenticator for &mut A {
    fn support(&self) -> Support {
        (**self).support()
    }

    fn make_credential(
        &mut self,
        rp_id: &str,
        user_id: &[u8],
        attachment: Attachment,
    ) -> Result<NewCredential> {
        (**self).make_credential(rp_id, user_id, attachment)
    }

    fn hmac_secret(&mut self, request: &SecretRequest<'_>) -> Result<Zeroizing<[u8; 32]>> {
        (**self).hmac_secret(request)
    }

    fn is_platform_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> bool {
        (**self).is_platform_credential(rp_id, credential_id)
    }

    fn delete_platform_credential(&mut self, credential_id: &[u8]) -> Result<()> {
        (**self).delete_platform_credential(credential_id)
    }
}

/// [`recipient`] with any authenticator. A security key's slot takes its salt as it is; Windows
/// Hello's takes it as a PRF input (see [`fido2`]). A Windows Hello credential registered here
/// is deleted again when the rest fails, so nothing is left behind.
pub fn recipient_with<A: Authenticator + ?Sized>(
    auth: &mut A,
    hello: bool,
    credential: Option<&[u8]>,
) -> Result<Recipient> {
    let support = auth.support();
    if !support.security_keys {
        return Err(unavailable(support));
    }
    if hello && !support.hello {
        return Err(Error::unsupported(
            "Windows Hello isn't set up on this PC, or this Windows can't open archives with \
             it; \"This PC\" works instead",
        ));
    }
    let attachment = if hello {
        Attachment::Platform
    } else {
        Attachment::CrossPlatform
    };
    let rp_id = fido2::RP_ID;
    let (id, registered) = match credential {
        Some(id) => (id.to_vec(), None),
        None => {
            // A random user id: one shared by two credentials would make a device keep only
            // the newer one, and the older archive would no longer open.
            let user_id = fido2::new_salt()?;
            let c = auth.make_credential(rp_id, &user_id[..16], attachment)?;
            (c.id, Some(c.hmac_secret))
        }
    };
    let undo = |auth: &mut A, e: Error| -> Error {
        if hello && registered.is_some() {
            let _ = auth.delete_platform_credential(&id);
        }
        e
    };
    if registered == Some(false) {
        return Err(undo(
            auth,
            Error::unsupported(if hello {
                "Windows Hello on this PC can't give the hmac-secret BeeZip opens archives \
                 with; \"This PC\" works instead"
            } else {
                "this security key can't give the hmac-secret BeeZip opens archives with"
            }),
        ));
    }
    if id.is_empty() || id.len() > fido2::MAX_CREDENTIAL_ID {
        return Err(undo(
            auth,
            Error::unsupported(format!(
                "the credential's id is {} bytes; a slot holds 1 to {}",
                id.len(),
                fido2::MAX_CREDENTIAL_ID
            )),
        ));
    }
    let salt = match fido2::new_salt() {
        Ok(s) => s,
        Err(e) => return Err(undo(auth, e)),
    };
    let prf = hello;
    let secret = match auth.hmac_secret(&SecretRequest {
        rp_id,
        credential_id: &id,
        salt: &salt,
        prf,
        uv: true,
        attachment,
    }) {
        Ok(s) => s,
        Err(e) => return Err(undo(auth, e)),
    };
    Ok(Recipient::Fido2 {
        credential_id: id,
        rp_id: rp_id.to_string(),
        salt,
        prf,
        secret,
        machine_bound: hello,
    })
}

/// A key source over an authenticator, for kind-8 slots.
pub struct Fido2Source<A> {
    auth: A,
    support: Support,
}

impl<A: Authenticator> Fido2Source<A> {
    pub fn new(auth: A) -> Self {
        let support = auth.support();
        Self { auth, support }
    }

    pub fn authenticator(&self) -> &A {
        &self.auth
    }

    pub fn into_authenticator(self) -> A {
        self.auth
    }
}

impl<A: Authenticator> KeySource for Fido2Source<A> {
    /// Every well-formed kind-8 slot, when this machine can ask an authenticator: which
    /// security key holds a credential can't be known without a touch.
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        slot.kind == SlotKind::Fido2 && self.support.security_keys && fido2::parse(slot).is_ok()
    }

    fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>> {
        if slot.kind != SlotKind::Fido2 || !device {
            return Ok(None);
        }
        let s = fido2::parse(slot)?;
        if !self.support.security_keys {
            return Err(unavailable(self.support));
        }
        // Straight to Windows Hello when the credential is this PC's; otherwise Windows offers
        // what it has (its list of Hello credentials may be incomplete while Hello is locked).
        let attachment = if self.auth.is_platform_credential(s.rp_id, s.credential_id) {
            Attachment::Platform
        } else {
            Attachment::Any
        };
        let secret = self.auth.hmac_secret(&SecretRequest {
            rp_id: s.rp_id,
            credential_id: s.credential_id,
            salt: s.salt,
            prf: s.prf,
            uv: s.uv,
            attachment,
        })?;
        Ok(Some(SlotSecret::Shared(Zeroizing::new(secret.to_vec()))))
    }
}

/// Why this machine can't use a security key.
fn unavailable(support: Support) -> Error {
    if cfg!(windows) && support.api_version > 0 {
        Error::unsupported(format!(
            "this Windows can't ask security keys for hmac-secret (webauthn.dll API version {}; \
             {MIN_API} or later is needed)",
            support.api_version
        ))
    } else if cfg!(windows) {
        Error::unsupported("this Windows has no webauthn.dll, which security keys need")
    } else {
        off_windows()
    }
}

fn off_windows() -> Error {
    Error::unsupported(
        "security keys and Windows Hello open archives only on Windows for now (docs/M14.md §12)",
    )
}

/// No authenticator: macOS and Linux.
#[cfg(not(windows))]
struct Unavailable;

#[cfg(not(windows))]
impl Authenticator for Unavailable {
    fn support(&self) -> Support {
        Support::NONE
    }

    fn make_credential(&mut self, _: &str, _: &[u8], _: Attachment) -> Result<NewCredential> {
        Err(off_windows())
    }

    fn hmac_secret(&mut self, _: &SecretRequest<'_>) -> Result<Zeroizing<[u8; 32]>> {
        Err(off_windows())
    }

    fn is_platform_credential(&mut self, _: &str, _: &[u8]) -> bool {
        false
    }

    fn delete_platform_credential(&mut self, _: &[u8]) -> Result<()> {
        Err(off_windows())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use beezip_core::{
        ErrorKind,
        format::bhive::crypt::{KEY_ID_LEN, MadeSlot, SLOT_TAIL_LEN},
    };

    use super::{
        mock::{Call, MockAuthenticator},
        *,
    };

    /// A key id and a kind-8 slot's head and public part, as a key block frames them.
    pub(crate) fn view_of(public: &[u8]) -> ([u8; KEY_ID_LEN], Vec<u8>) {
        let mut framed = vec![SlotKind::Fido2.id(), 0];
        framed.extend_from_slice(&((public.len() + SLOT_TAIL_LEN) as u16).to_le_bytes());
        framed.extend_from_slice(public);
        ([0x6b; KEY_ID_LEN], framed)
    }

    fn slot_for(recipient: &Recipient) -> MadeSlot {
        let Recipient::Fido2 {
            credential_id,
            rp_id,
            salt,
            prf,
            secret,
            ..
        } = recipient
        else {
            panic!("not a security-key recipient");
        };
        fido2::make(credential_id, rp_id, salt, *prf, secret).unwrap()
    }

    fn shared(s: Option<SlotSecret>) -> Vec<u8> {
        match s {
            Some(SlotSecret::Shared(s)) => s.to_vec(),
            other => panic!("{other:?}"),
        }
    }

    /// Opens `public` through a source over `auth`, as the envelope will: offers, then the
    /// secret once the user chose it.
    fn open<A: Authenticator>(auth: A, public: &[u8]) -> (Result<Option<SlotSecret>>, A) {
        let (key_id, framed) = view_of(public);
        let view = SlotView {
            index: 1,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
        };
        let mut source = Fido2Source::new(auth);
        assert!(source.offers(&view));
        assert!(
            source.secret(&view, false).unwrap().is_none(),
            "never touched unless chosen"
        );
        let secret = source.secret(&view, true);
        (secret, source.into_authenticator())
    }

    /// A security key: registered, asked for a salt, made into a slot, and opened again with
    /// the same secret. Two dialogs to make it, one to open it.
    #[test]
    fn a_security_key_round_trips() {
        let mut key = MockAuthenticator::new();
        let recipient = recipient_with(&mut key, false, None).unwrap();
        let Recipient::Fido2 {
            rp_id,
            prf,
            secret,
            machine_bound,
            ..
        } = &recipient
        else {
            panic!("not a security-key recipient");
        };
        assert_eq!(rp_id, fido2::RP_ID);
        assert!(!prf, "a security key gets the salt as it is");
        assert!(!machine_bound);
        let made = slot_for(&recipient);
        assert_eq!(made.public[0], fido2::FLAG_UV);
        let (opened, key) = open(key, &made.public);
        assert_eq!(shared(opened.unwrap()), secret.as_slice());
        assert_eq!(
            key.calls,
            [
                Call::Make {
                    attachment: Attachment::CrossPlatform
                },
                Call::Secret {
                    attachment: Attachment::CrossPlatform,
                    prf: false,
                    uv: true
                },
                Call::Secret {
                    attachment: Attachment::Any,
                    prf: false,
                    uv: true
                },
            ]
        );
    }

    /// Windows Hello: a PRF slot, bound to this machine, opened straight through Hello.
    #[test]
    fn windows_hello_round_trips() {
        let mut hello = MockAuthenticator::new();
        let recipient = recipient_with(&mut hello, true, None).unwrap();
        let Recipient::Fido2 {
            prf,
            secret,
            machine_bound,
            ..
        } = &recipient
        else {
            panic!("not a security-key recipient");
        };
        assert!(*prf && *machine_bound);
        let made = slot_for(&recipient);
        assert_eq!(made.public[0], fido2::FLAG_PRF | fido2::FLAG_UV);
        let (opened, hello) = open(hello, &made.public);
        assert_eq!(shared(opened.unwrap()), secret.as_slice());
        assert_eq!(
            hello.calls.last(),
            Some(&Call::Secret {
                attachment: Attachment::Platform,
                prf: true,
                uv: true
            })
        );
    }

    /// A credential given (for "New key", docs/M14.md §3): one dialog, a new salt, a new secret.
    #[test]
    fn a_known_credential_needs_no_registration() {
        let mut key = MockAuthenticator::new();
        let first = recipient_with(&mut key, false, None).unwrap();
        let Recipient::Fido2 {
            credential_id,
            salt,
            secret,
            ..
        } = &first
        else {
            panic!("not a security-key recipient");
        };
        key.calls.clear();
        let second = recipient_with(&mut key, false, Some(credential_id)).unwrap();
        let Recipient::Fido2 {
            credential_id: id2,
            salt: salt2,
            secret: secret2,
            ..
        } = &second
        else {
            panic!("not a security-key recipient");
        };
        assert_eq!(id2, credential_id);
        assert_ne!(salt2, salt, "every slot written is new");
        assert_ne!(secret2, secret);
        assert_eq!(key.calls.len(), 1);
        assert!(matches!(key.calls[0], Call::Secret { .. }));
        // Both slots open.
        let (opened, key) = open(key, &slot_for(&first).public);
        assert_eq!(shared(opened.unwrap()), secret.as_slice());
        let (opened, _) = open(key, &slot_for(&second).public);
        assert_eq!(shared(opened.unwrap()), secret2.as_slice());
    }

    #[test]
    fn another_key_doesnt_open_it() {
        let mut key = MockAuthenticator::new();
        let made = slot_for(&recipient_with(&mut key, false, None).unwrap());
        let (opened, _) = open(MockAuthenticator::new(), &made.public);
        assert_eq!(opened.err().unwrap().kind, ErrorKind::KeyRequired);
    }

    /// Slots made by other programs: the salt as it is or as PRF, with or without user
    /// verification. Each is asked for as the slot says, and gives what the key computes.
    #[test]
    fn slots_are_asked_for_as_their_flags_say() {
        let mut key = MockAuthenticator::new();
        let c = key
            .make_credential(fido2::RP_ID, &[1; 16], Attachment::CrossPlatform)
            .unwrap();
        let salt = [0x33; 32];
        let mut answers = Vec::new();
        for (prf, uv) in [(false, false), (false, true), (true, false), (true, true)] {
            let expected = key
                .hmac_secret(&SecretRequest {
                    rp_id: fido2::RP_ID,
                    credential_id: &c.id,
                    salt: &salt,
                    prf,
                    uv,
                    attachment: Attachment::Any,
                })
                .unwrap();
            let mut public = fido2::make(&c.id, fido2::RP_ID, &salt, prf, &expected)
                .unwrap()
                .public;
            if !uv {
                public[0] &= !fido2::FLAG_UV;
            }
            let (opened, k) = open(key, &public);
            key = k;
            assert_eq!(shared(opened.unwrap()), expected.as_slice());
            assert_eq!(
                key.calls.last(),
                Some(&Call::Secret {
                    attachment: Attachment::Any,
                    prf,
                    uv
                })
            );
            answers.push(expected);
        }
        // Four different answers for one salt, as an authenticator gives.
        for i in 0..answers.len() {
            for j in i + 1..answers.len() {
                assert_ne!(answers[i], answers[j]);
            }
        }
    }

    #[test]
    fn other_slots_and_unchosen_ways_are_left_alone() {
        let key_id = [0; KEY_ID_LEN];
        let framed = [SlotKind::Password.id(), 0, 128, 0];
        let view = SlotView {
            index: 0,
            kind: SlotKind::Password,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
        };
        let mut source = Fido2Source::new(MockAuthenticator::new());
        assert!(!source.offers(&view));
        assert!(source.secret(&view, true).unwrap().is_none());
        assert!(source.authenticator().calls.is_empty());

        // A malformed kind-8 slot isn't offered, and is refused if chosen.
        let (key_id, framed) = view_of(&[fido2::FLAG_UV, 0, 0, 0]);
        let view = SlotView {
            index: 0,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
        };
        assert!(!source.offers(&view));
        assert_eq!(
            source.secret(&view, true).err().unwrap().kind,
            ErrorKind::Corrupt
        );
        assert!(source.authenticator().calls.is_empty());
    }

    #[test]
    fn a_machine_without_webauthn_refuses_and_says_why() {
        let mut none = MockAuthenticator::new();
        none.support = Support::NONE;
        let e = recipient_with(&mut none, false, None).err().unwrap();
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation);
        assert!(none.calls.is_empty());

        let made = slot_for(&recipient_with(&mut MockAuthenticator::new(), false, None).unwrap());
        let (key_id, framed) = view_of(&made.public);
        let view = SlotView {
            index: 0,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
        };
        let mut source = Fido2Source::new(none);
        assert!(!source.offers(&view));
        assert!(source.secret(&view, false).unwrap().is_none());
        assert_eq!(
            source.secret(&view, true).err().unwrap().kind,
            ErrorKind::UnsupportedOperation
        );
        assert!(source.authenticator().calls.is_empty());

        let mut old = MockAuthenticator::new();
        old.support.hello = false;
        let e = recipient_with(&mut old, true, None).err().unwrap();
        assert!(e.message.contains("This PC"), "{}", e.message);
        assert!(old.calls.is_empty());
    }

    /// A Windows Hello registration that comes back without hmac-secret, or whose second
    /// dialog is cancelled, leaves no credential behind.
    #[test]
    fn a_failed_windows_hello_registration_is_deleted() {
        let mut hello = MockAuthenticator::new();
        hello.hmac_secret = false;
        let e = recipient_with(&mut hello, true, None).err().unwrap();
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation);
        assert!(e.message.contains("This PC"), "{}", e.message);
        assert_eq!(hello.credentials(), 0);
        assert_eq!(hello.calls.last(), Some(&Call::Delete));

        let mut hello = MockAuthenticator::new();
        hello.cancel_secrets = true;
        let e = recipient_with(&mut hello, true, None).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Cancelled);
        assert_eq!(hello.credentials(), 0);

        // A security key's credential lives in its id, so there is nothing to delete.
        let mut key = MockAuthenticator::new();
        key.hmac_secret = false;
        assert!(recipient_with(&mut key, false, None).is_err());
        assert!(!key.calls.contains(&Call::Delete));
    }

    #[test]
    fn off_windows_there_is_none() {
        if cfg!(windows) {
            return;
        }
        assert_eq!(support(), Support::NONE);
        assert_eq!(
            recipient(false, None, None).err().unwrap().kind,
            ErrorKind::UnsupportedOperation
        );
        let made = slot_for(&recipient_with(&mut MockAuthenticator::new(), false, None).unwrap());
        let (key_id, framed) = view_of(&made.public);
        let view = SlotView {
            index: 0,
            kind: SlotKind::Fido2,
            key_id: &key_id,
            framed: &framed,
            public: &framed[4..],
        };
        let mut source = source(None).unwrap();
        assert!(!source.offers(&view));
        let e = source.secret(&view, true).err().unwrap();
        assert!(e.message.contains("only on Windows"), "{}", e.message);
    }
}
