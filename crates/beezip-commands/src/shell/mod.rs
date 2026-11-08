//! Explorer registration (docs/M4.md §5), behind `shell.status`, `shell.install` and
//! `shell.uninstall`, and `settings.set` when `[shell]` changes:
//! - [`classic`]: the classic menu's HKCU keys, with or without the cascade;
//! - [`mirror`]: `HKCU\Software\BeeZip\Shell`, the settings the DLL reads;
//! - [`package`]: the Windows 11 menu's sparse package, through `PackageManager`;
//! - [`files`]: DLLs an upgrade or uninstall left behind, which Explorer may still hold;
//! - [`system`]: the Windows build and Developer Mode.
//!
//! Windows only, and safe Rust only (windows-registry, and windows' WinRT projection). Every key
//! goes through one [`Hive`], so tests write under a key of their own and never touch the real
//! menu; a test's hive has no package at all.

#[cfg(windows)]
pub(crate) mod classic;
#[cfg(windows)]
pub(crate) mod files;
#[cfg(windows)]
pub(crate) mod mirror;
#[cfg(windows)]
pub(crate) mod package;
#[cfg(windows)]
pub(crate) mod system;

use std::path::{Path, PathBuf};

use crate::{CmdError, ErrorCode};

/// The key under `HKEY_CURRENT_USER` that stands for `Software`: the real one, or a test's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hive {
    base: String,
}

impl Hive {
    /// The real registry: `HKCU\Software\Classes\…`, `HKCU\Software\BeeZip\Shell`. Debug
    /// builds take `BEEZIP_SHELL_BASE` instead, so the CLI's tests can't change the menu of a
    /// developer who has BeeZip installed.
    pub fn real() -> Self {
        let base = std::env::var("BEEZIP_SHELL_BASE")
            .ok()
            .filter(|b| cfg!(debug_assertions) && !b.is_empty());
        Self {
            base: base.unwrap_or_else(|| "Software".into()),
        }
    }

    /// `HKCU\Software\BeeZip-test-<pid>-<name>`, for one test. The caller deletes it.
    #[cfg(test)]
    pub fn test(name: &str) -> Self {
        Self {
            base: format!(r"Software\BeeZip-test-{}-{name}", std::process::id()),
        }
    }

    /// The package's name, `BeeZip`, for the real registry only. Packages have no test base, so
    /// a test's hive, and a debug build's `BEEZIP_SHELL_BASE`, never find or change one.
    pub fn package_name(&self) -> Option<&'static str> {
        (self.base == "Software").then_some("BeeZip")
    }

    /// `rest` under the base: `Classes\CLSID\{…}`.
    pub fn key(&self, rest: &str) -> String {
        format!(r"{}\{rest}", self.base)
    }

    #[cfg(all(test, windows))]
    pub fn base(&self) -> &str {
        &self.base
    }
}

/// Every publisher BeeZip's package has had, which is the subject of the certificate that signed
/// it: the development certificate's, then each production one (docs/M6.md §9.2). Packages are
/// looked up under each, so `shell.status` and `shell.install` find and replace a registration
/// made by an older install. `cargo xtask dist` refuses to sign a package whose publisher isn't
/// here.
pub const PUBLISHERS: &[&str] = &["CN=BeeZip Dev"];

/// The signed package's name in the install folder, from `cargo xtask dist` when it signs.
pub const MSIX: &str = "beezip-sparse.msix";
/// The folder in the install folder holding the unsigned package's `AppxManifest.xml` and logos.
pub const SPARSE: &str = "sparse";

/// The same path, ignoring case and a trailing separator, as Windows does.
pub fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        p.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .to_lowercase()
    };
    norm(a) == norm(b)
}

/// The CLI's and the app's install folder: `<dir>` for `<dir>\bin\beezip.exe` and for
/// `<dir>\BeeZip.exe`.
pub fn install_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let bin = dir
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case("bin"));
    Some(if bin { dir.parent()? } else { dir }.to_path_buf())
}

/// Whether `name` is a staged DLL: `beezip_shell_0.1.0.dll` from the installer,
/// `beezip_shell_<n>.dll` from `xtask shell`. Cargo's own `beezip_shell.dll` isn't one, so
/// clean-up never deletes a build's output.
pub fn is_dll_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("beezip_shell_") && lower.ends_with(".dll")
}

/// The DLL in an install folder: this version's, or else the newest staged one. In a
/// development build's folder, cargo's own `beezip_shell.dll`.
pub fn default_dll(dir: &Path) -> Option<PathBuf> {
    let own = dir.join(format!("beezip_shell_{}.dll", env!("CARGO_PKG_VERSION")));
    if own.is_file() {
        return Some(own);
    }
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| is_dll_name(&e.file_name().to_string_lossy()))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max()
        .map(|(_, p)| p)
        .or_else(|| Some(dir.join("beezip_shell.dll")).filter(|p| p.is_file()))
}

/// After `settings.set` changed `[shell]`: the mirror follows, and so do the classic menu's
/// verbs when the cascade changed, or the items without the cascade. Nothing happens when the
/// menu isn't installed. Returns what it did.
#[cfg(windows)]
pub fn follow(hive: &Hive, shell: &crate::config::ShellConfig) -> Result<Vec<String>, CmdError> {
    let Some(before) = mirror::read(hive) else {
        return Ok(Vec::new());
    };
    let hidden = shell.items.hidden();
    mirror::set_menu(hive, &hidden, shell.cascade)?;
    let Some(keys) = classic::read(hive) else {
        return Ok(Vec::new());
    };
    let verbs_change = keys.cascade != shell.cascade || (!shell.cascade && before.hidden != hidden);
    match keys.dll.or(before.dll) {
        Some(dll) if verbs_change => classic::register(hive, &dll, shell.cascade, &hidden),
        _ => Ok(Vec::new()),
    }
}

#[cfg(not(windows))]
pub fn follow(_: &Hive, _: &crate::config::ShellConfig) -> Result<Vec<String>, CmdError> {
    Ok(Vec::new())
}

/// A registry error, with what was being done.
#[cfg(windows)]
pub(crate) fn reg_error(doing: &str, e: &windows_result::Error) -> CmdError {
    CmdError::new(ErrorCode::Io, format!("{doing}: {}", e.message()))
        .with_details(serde_json::json!({ "hresult": format!("{:#010x}", e.code().0) }))
}

/// The `shell.*` commands that change the system, on anything but Windows.
#[cfg(not(windows))]
pub(crate) fn unsupported() -> CmdError {
    CmdError::new(
        ErrorCode::UnsupportedOperation,
        "Explorer's menu is only on Windows",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dll_names() {
        assert!(is_dll_name("beezip_shell_0.1.0.dll"));
        assert!(is_dll_name("BEEZIP_SHELL_17.DLL"));
        assert!(!is_dll_name("beezip_shell.dll"));
        assert!(!is_dll_name("beezip_shell_0.1.0.pdb"));
        assert!(!is_dll_name("other.dll"));
    }

    #[test]
    fn the_newest_dll_is_the_default() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(default_dll(dir.path()), None);
        let cargo = dir.path().join("beezip_shell.dll");
        std::fs::write(&cargo, "").unwrap();
        assert_eq!(default_dll(dir.path()), Some(cargo));
        let old = dir.path().join("beezip_shell_0.0.9.dll");
        std::fs::write(&old, "").unwrap();
        assert_eq!(default_dll(dir.path()), Some(old));
        let own = dir
            .path()
            .join(format!("beezip_shell_{}.dll", env!("CARGO_PKG_VERSION")));
        std::fs::write(&own, "").unwrap();
        assert_eq!(default_dll(dir.path()), Some(own));
    }
}
