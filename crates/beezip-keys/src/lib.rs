//! BeeZip's system key stores (docs/M14.md §6, §8): what opens an encrypted `.bhive` and what
//! signs one, when it lives outside the archive. Core stays free of `unsafe` and of system
//! APIs; this crate reaches them and hands core a
//! [`KeySource`] and [`beezip_core::format::bhive::sign::Signer`]s.
//!
//! - [`identity`]: your own keys and your contacts, sealed by the system (DPAPI-NG, the login
//!   Keychain, a 0600 file) (PR C); [`identity::signing`], your signing key (PR H).
//! - [`files`]: key files and certificate files, everywhere (PR D); [`pfx`], `.pfx` files,
//!   opened in memory on Windows.
//! - [`trust`]: whom a signature is from (PR D, with PR H).
//! - `cng` (Windows): certificate stores, smart cards, TPM keys and "This PC", chain checks
//!   (PR D). `mac` (macOS): Keychain identities (PR D).
//! - [`webauthn`]: security keys and Windows Hello through webauthn.dll (PR E); on macOS and
//!   Linux it reports none.
//!
//! `unsafe` is denied here as everywhere; a platform module that calls a system API opts out
//! with `#![allow(unsafe_code)]` at its top, and wraps every handle in an RAII type.

use beezip_core::{
    Error, ErrorKind, Result,
    format::bhive::crypt::{KeySource, SlotSecret, SlotView},
};

pub mod files;
pub mod identity;
pub mod pfx;
pub mod trust;

#[cfg(windows)]
pub mod cng;
#[cfg(target_os = "macos")]
pub mod mac;
pub mod webauthn;
#[cfg(any(windows, test))]
mod window;

/// The window of the terminal this process runs in: the window Windows' own dialogs (a smart
/// card's or TPM key's PIN, Windows Security's for a security key or Windows Hello) belong to
/// when a command runs in a terminal, as the CLI's do. conhost's console window; the Windows
/// Terminal window that owns ConPTY's hidden one; else the window in front, where the command
/// was typed (`window::dialog_window`). `None` without a console, and on macOS and Linux.
pub fn console_window() -> Option<isize> {
    #[cfg(windows)]
    {
        window::dialog_window(&webauthn::ffi::Desktop)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// What M14's parts return until their PR builds them.
pub fn not_built(what: &str) -> Error {
    Error::new(
        ErrorKind::UnsupportedOperation,
        format!("{what} is not built yet (docs/M14.md)"),
    )
}

/// Every place a key may be, in the order a reader tries them: your own keys (silently), key
/// files given for this job, then the system's certificates and devices, which may need a PIN
/// or a touch and are only used for the way in the user chose.
#[derive(Default)]
pub struct Sources {
    pub sources: Vec<Box<dyn KeySource + Send>>,
}

impl Sources {
    /// What this machine has: your keys, the system's stores and devices. The commands layer
    /// adds key files given with `--identity` (PR F).
    pub fn system() -> Self {
        Self::default()
    }

    pub fn push(&mut self, source: Box<dyn KeySource + Send>) {
        self.sources.push(source);
    }
}

impl KeySource for Sources {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        self.sources.iter_mut().any(|s| s.offers(slot))
    }

    fn needs_pin(&mut self, slot: &SlotView<'_>) -> bool {
        self.sources.iter_mut().any(|s| s.needs_pin(slot))
    }

    fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>> {
        for s in &mut self.sources {
            if let Some(secret) = s.secret(slot, device)? {
                return Ok(Some(secret));
            }
        }
        Ok(None)
    }

    fn secret_with_pin(&mut self, slot: &SlotView<'_>, pin: &str) -> Result<Option<SlotSecret>> {
        for s in &mut self.sources {
            if let Some(secret) = s.secret_with_pin(slot, pin)? {
                return Ok(Some(secret));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use beezip_core::format::bhive::crypt::{KEY_ID_LEN, SlotKind};
    use zeroize::Zeroizing;

    use super::*;

    /// Has every slot's key: with a PIN, which BeeZip asks for, it opens only with that PIN and
    /// gives the PIN as the secret.
    struct Pinned(Option<&'static str>);

    impl KeySource for Pinned {
        fn offers(&mut self, _: &SlotView<'_>) -> bool {
            true
        }

        fn needs_pin(&mut self, _: &SlotView<'_>) -> bool {
            self.0.is_some()
        }

        fn secret(&mut self, _: &SlotView<'_>, _: bool) -> Result<Option<SlotSecret>> {
            Ok(None)
        }

        fn secret_with_pin(&mut self, _: &SlotView<'_>, pin: &str) -> Result<Option<SlotSecret>> {
            Ok((self.0 == Some(pin))
                .then(|| SlotSecret::Shared(Zeroizing::new(pin.as_bytes().to_vec()))))
        }
    }

    /// The sources together need a PIN when one of them does, and the PIN reaches each.
    #[test]
    fn a_pin_reaches_the_source_that_asked_for_it() {
        let key_id = [0; KEY_ID_LEN];
        let view = SlotView {
            index: 0,
            kind: SlotKind::EcP256,
            key_id: &key_id,
            framed: &[],
            public: &[],
            commitment: &[0; 32],
        };
        let mut sources = Sources::default();
        sources.push(Box::new(Pinned(None)));
        assert!(!sources.needs_pin(&view));
        sources.push(Box::new(Pinned(Some("4821"))));
        assert!(sources.needs_pin(&view));
        assert!(sources.secret_with_pin(&view, "0000").unwrap().is_none());
        match sources.secret_with_pin(&view, "4821").unwrap() {
            Some(SlotSecret::Shared(s)) => assert_eq!(s.as_slice(), b"4821"),
            other => panic!("{other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    /// It asks the real desktop, whatever the tests run in: a console, a terminal's hidden one,
    /// or none.
    #[test]
    fn console_window_answers() {
        let window = super::console_window();
        if cfg!(not(windows)) {
            assert_eq!(window, None);
        }
    }
}
