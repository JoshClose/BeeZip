//! Where a private key of yours is kept, sealed by the system (docs/M14.md §6, decision 14):
//! - **Windows:** a file in the store's `keys` folder, sealed with DPAPI-NG for this Windows
//!   account (`LOCAL=user`): silent, and useless to anyone else or on another PC;
//! - **macOS:** the login Keychain, as a generic password;
//! - **elsewhere:** a file in the store's `keys` folder that only you can read (0600), as age
//!   and ssh keep theirs.
//!
//! Each key is named by its `id` (the store's record of it), so two stores never share one.

use std::path::Path;

use beezip_core::Result;
use zeroize::Zeroizing;

/// Keeps `secret` as `id` in the store at `keys` (its `keys` folder).
pub fn put(keys: &Path, id: &str, secret: &[u8]) -> Result<()> {
    imp::put(keys, id, secret)
}

/// The secret kept as `id`.
pub fn get(keys: &Path, id: &str) -> Result<Zeroizing<Vec<u8>>> {
    imp::get(keys, id)
}

/// Forgets the secret kept as `id`; one that isn't there is no error.
pub fn remove(keys: &Path, id: &str) -> Result<()> {
    imp::remove(keys, id)
}

/// A secret's file, where the system keeps it in one.
#[cfg(not(target_os = "macos"))]
fn file(keys: &Path, id: &str, ext: &str) -> std::path::PathBuf {
    keys.join(format!("{id}.{ext}"))
}

#[cfg(not(target_os = "macos"))]
fn remove_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
mod imp {
    use std::path::Path;

    use beezip_core::Result;
    use zeroize::Zeroizing;

    use crate::identity::dpapi;

    pub fn put(keys: &Path, id: &str, secret: &[u8]) -> Result<()> {
        let blob = dpapi::protect(secret)?;
        super::super::write_atomic(&super::file(keys, id, "dpapi"), &blob)
    }

    pub fn get(keys: &Path, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let blob = std::fs::read(super::file(keys, id, "dpapi"))?;
        dpapi::unprotect(&blob)
    }

    pub fn remove(keys: &Path, id: &str) -> Result<()> {
        super::remove_file(&super::file(keys, id, "dpapi"))
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::Path;

    use beezip_core::{Error, ErrorKind, Result};
    use security_framework::passwords;
    use zeroize::Zeroizing;

    /// The Keychain item's service; its account is the store's folder and the key's id.
    const SERVICE: &str = "BeeZip key";

    fn account(keys: &Path, id: &str) -> String {
        format!("{}:{id}", keys.display())
    }

    fn keychain(what: &str, e: &security_framework::base::Error) -> Error {
        Error::new(
            ErrorKind::Io,
            format!("the Keychain couldn't {what} the key: {e}"),
        )
    }

    pub fn put(keys: &Path, id: &str, secret: &[u8]) -> Result<()> {
        passwords::set_generic_password(SERVICE, &account(keys, id), secret)
            .map_err(|e| keychain("keep", &e))
    }

    pub fn get(keys: &Path, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        passwords::get_generic_password(SERVICE, &account(keys, id))
            .map(Zeroizing::new)
            .map_err(|e| keychain("find", &e))
    }

    pub fn remove(keys: &Path, id: &str) -> Result<()> {
        // errSecItemNotFound: already gone.
        match passwords::delete_generic_password(SERVICE, &account(keys, id)) {
            Err(e) if e.code() != -25300 => Err(keychain("delete", &e)),
            _ => Ok(()),
        }
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
mod imp {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    use beezip_core::{Error, ErrorKind, Result};
    use zeroize::Zeroizing;

    pub fn put(keys: &Path, id: &str, secret: &[u8]) -> Result<()> {
        // The folder too is yours alone.
        std::fs::set_permissions(keys, std::fs::Permissions::from_mode(0o700))?;
        let path = super::file(keys, id, "key");
        let tmp = path.with_extension("key.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(secret)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn get(keys: &Path, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = super::file(keys, id, "key");
        let mode = std::fs::metadata(&path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::new(
                ErrorKind::Unsafe,
                format!(
                    "{} can be read by others (mode {:o}); make it yours alone with chmod 600",
                    path.display(),
                    mode & 0o777
                ),
            ));
        }
        Ok(Zeroizing::new(std::fs::read(&path)?))
    }

    pub fn remove(keys: &Path, id: &str) -> Result<()> {
        super::remove_file(&super::file(keys, id, "key"))
    }
}
