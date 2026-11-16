//! The Microsoft Store package (docs/M12.md): its identity, which Partner Center assigned to the
//! product and which never changes, and whether this process runs from it. `xtask dist` writes
//! the identity into the package's manifest; the menu DLL knows the package by its own class, the
//! Store root.
//!
//! Inside the package (§3), the menu is the package's own, the updater is off, "Copy as CLI"
//! names the `beezip` alias, and a settings file Windows redirected into the package's private
//! folder is reported where other programs can open it ([`outside_path`]).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// `Package/Identity/Name`.
pub const NAME: &str = "CloseConsultingInc.BeeZip";
/// `Package/Identity/Publisher`: Partner Center's, not a certificate's. Microsoft signs the
/// package with it after certification.
pub const PUBLISHER: &str = "CN=B81ECA8F-95E1-4C2B-B747-FE4DA97C8BFC";
/// `Package/Properties/PublisherDisplayName`: the developer account's publisher name.
pub const PUBLISHER_DISPLAY_NAME: &str = "Close Consulting, Inc";
/// The package family name: the name and a hash of the publisher.
pub const FAMILY: &str = "CloseConsultingInc.BeeZip_x5m1y1n6e4ce4";
/// The product's Store ID, for links to its page.
pub const STORE_ID: &str = "9P9HHSVMM3M3";
/// The app's ID in the manifest; with [`FAMILY`], its AUMID (`<family>!BeeZip`).
pub const APP_ID: &str = "BeeZip";

/// This process, running from the Store package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    /// The package's full name: `CloseConsultingInc.BeeZip_<version>_x64__<hash>`.
    pub full_name: String,
}

/// The Store package this process runs from, if it does: its package identity is the Store
/// family's. Any other identity (the sparse package's, a development package's) isn't the Store
/// copy. Debug builds take `BEEZIP_STORE=1` instead, so the app can be tried as the Store copy
/// without a package. Asked once per process; a unit test can stand in for the Store copy on its
/// own thread ([`AsStore`]).
pub fn current() -> Option<Current> {
    #[cfg(test)]
    if let Some(test) = TEST.with(|t| t.borrow().clone()) {
        return test;
    }
    static CURRENT: OnceLock<Option<Current>> = OnceLock::new();
    CURRENT
        .get_or_init(|| {
            if cfg!(debug_assertions) && std::env::var_os("BEEZIP_STORE").is_some_and(|v| v == "1")
            {
                return Some(Current {
                    full_name: format!("{NAME}_0.0.0.0_x64__{}", hash()),
                });
            }
            identity()
                .filter(|(family, _)| family == FAMILY)
                .map(|(_, full_name)| Current { full_name })
        })
        .clone()
}

/// Whether this process is the Store copy.
pub fn running() -> bool {
    current().is_some()
}

#[cfg(test)]
thread_local! {
    static TEST: std::cell::RefCell<Option<Option<Current>>> = const { std::cell::RefCell::new(None) };
}

/// While it lives, this thread is the Store copy (unit tests only; the shell's are Windows').
#[cfg(all(test, windows))]
pub(crate) struct AsStore;

#[cfg(all(test, windows))]
impl AsStore {
    pub(crate) fn new() -> Self {
        TEST.with(|t| {
            *t.borrow_mut() = Some(Some(Current {
                full_name: format!("{NAME}_9.9.9.0_x64__{}", hash()),
            }));
        });
        Self
    }
}

#[cfg(all(test, windows))]
impl Drop for AsStore {
    fn drop(&mut self) {
        TEST.with(|t| *t.borrow_mut() = None);
    }
}

/// What `shell.install` and `shell.uninstall` answer in the Store copy, whose menu is the
/// package's own (docs/M12.md §3.2).
pub(crate) fn menu_refusal() -> crate::CmdError {
    crate::CmdError::new(
        crate::ErrorCode::UnsupportedOperation,
        "The Microsoft Store package provides Explorer's menu. To remove it, uninstall BeeZip.",
    )
}

/// The publisher hash in [`FAMILY`].
fn hash() -> &'static str {
    FAMILY.rsplit('_').next().unwrap_or_default()
}

/// This process's package family and full name, if it has a package identity.
#[cfg(windows)]
fn identity() -> Option<(String, String)> {
    let id = windows::ApplicationModel::Package::Current()
        .ok()?
        .Id()
        .ok()?;
    Some((
        id.FamilyName().ok()?.to_string(),
        id.FullName().ok()?.to_string(),
    ))
}

#[cfg(not(windows))]
fn identity() -> Option<(String, String)> {
    None
}

/// `path` as other programs see it. Inside the Store package, Windows redirects a folder the
/// package creates directly under `%APPDATA%` or `%LOCALAPPDATA%` into the package's
/// `LocalCache`, and only the package sees it at its usual path (docs/M12.md §3.5): on a machine
/// that never had BeeZip, that's `%APPDATA%\BeeZip` and its `config.toml`. When the file is there,
/// this is its real path, which Notepad and Explorer can open. Anywhere else, and outside the
/// package, it's `path`.
pub fn outside_path(path: &Path) -> PathBuf {
    if !running() {
        return path.to_path_buf();
    }
    let (Some(roaming), Some(local)) = (dirs::config_dir(), dirs::data_local_dir()) else {
        return path.to_path_buf();
    };
    redirected(path, &roaming, &local)
        .filter(|p| p.exists())
        .unwrap_or_else(|| path.to_path_buf())
}

/// Where the package's write virtualization keeps `path`, if it's under `roaming` or `local`:
/// `<local>\Packages\<family>\LocalCache\{Roaming,Local}\…`. Paths already under `Packages`
/// aren't redirected.
fn redirected(path: &Path, roaming: &Path, local: &Path) -> Option<PathBuf> {
    let packages = local.join("Packages");
    if path.starts_with(&packages) {
        return None;
    }
    let cache = packages.join(FAMILY).join("LocalCache");
    if let Ok(rest) = path.strip_prefix(roaming) {
        return Some(cache.join("Roaming").join(rest));
    }
    if let Ok(rest) = path.strip_prefix(local) {
        return Some(cache.join("Local").join(rest));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_family_is_the_names() {
        assert!(FAMILY.starts_with(&format!("{NAME}_")));
        assert_eq!(hash(), "x5m1y1n6e4ce4");
    }

    /// Windows' paths: elsewhere `\` doesn't separate them, and nothing is redirected anyway.
    #[cfg(windows)]
    #[test]
    fn redirected_paths_go_into_the_packages_local_cache() {
        let roaming = Path::new(r"C:\Users\u\AppData\Roaming");
        let local = Path::new(r"C:\Users\u\AppData\Local");
        let cache = local.join("Packages").join(FAMILY).join("LocalCache");
        assert_eq!(
            redirected(&roaming.join(r"BeeZip\config.toml"), roaming, local),
            Some(cache.join(r"Roaming\BeeZip\config.toml"))
        );
        assert_eq!(
            redirected(&local.join(r"BeeZip\x.json"), roaming, local),
            Some(cache.join(r"Local\BeeZip\x.json"))
        );
        assert_eq!(
            redirected(&cache.join(r"Roaming\BeeZip\config.toml"), roaming, local),
            None
        );
        assert_eq!(
            redirected(Path::new(r"D:\settings\config.toml"), roaming, local),
            None
        );
    }

    /// Outside the package (the tests' own process), a path is what it is.
    #[test]
    fn outside_the_package_nothing_moves() {
        if running() {
            return; // BEEZIP_STORE=1 in a debug run
        }
        let p = dirs::config_dir()
            .unwrap_or_default()
            .join(r"BeeZip\config.toml");
        assert_eq!(outside_path(&p), p);
    }
}
