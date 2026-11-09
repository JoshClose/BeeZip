//! The portable copy (Windows): `BeeZip_<V>_x64-portable.zip`, the installer's programs without
//! the installer. Unzip it anywhere and run `BeeZip.exe`. Before 1.0.0 it's a release's only
//! Windows download (release.yml), and a copy of it never installs an update: the app's
//! `update.rs` only links to the new zip.
//!
//! At the zip's root, so Windows' own Extract All gives a folder of them:
//! - `BeeZip.exe`, signed here in a signed build, since Tauri signs it only inside the installer;
//! - `bin\beezip.exe`, the CLI, where the installer puts it: beside `BeeZip.exe` it would be the
//!   same file to Windows. "Copy as CLI" and `shell install` look for it there;
//! - `beezip_shell_<V>.dll`, so Settings > Explorer menu > Install works from the folder. That's
//!   the classic menu: Windows 11's own needs the installer's signed package;
//! - `README.txt` (`packaging/windows/portable.txt`), `LICENSE-MIT`, `LICENSE-APACHE` and
//!   `THIRD_PARTY_NOTICES.md`.
//!
//! With `TAURI_SIGNING_PRIVATE_KEY`, the zip gets an updater signature bound to its version, as
//! the installer does, and `latest.json` names it under [`KEY`], which a portable copy looks up.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use anyhow::{Context, bail};
use beezip_commands::{Engine, NonInteractive, discard_events, registry};
use serde_json::json;

use super::{check, dll_name, pnpm, sig};
use crate::sign::{self, Mode};

/// The portable copy's key in `latest.json`'s `platforms` (the app's `update.rs` looks it up).
pub const KEY: &str = "windows-x86_64-portable";

/// The README's template, `{version}` filled in.
const README: &str = "packaging/windows/portable.txt";

/// The zip's name, beside the installer's `BeeZip_<V>_x64-setup.exe`.
pub fn zip_name(version: &str) -> String {
    format!("BeeZip_{version}_x64-portable.zip")
}

/// The programs that go in, as the build left them.
pub struct Programs<'a> {
    /// `BeeZip.exe` in the target folder, unsigned even in a signed build.
    pub app: &'a Path,
    pub cli: &'a Path,
    pub dll: &'a Path,
}

/// Every file in the zip but the README: where it comes from, and its name there.
pub fn contents(root: &Path, programs: &Programs, version: &str) -> Vec<(PathBuf, String)> {
    let mut files = vec![
        (programs.app.to_path_buf(), "BeeZip.exe".to_owned()),
        (programs.cli.to_path_buf(), "bin/beezip.exe".to_owned()),
        (programs.dll.to_path_buf(), dll_name(version)),
    ];
    for doc in ["LICENSE-MIT", "LICENSE-APACHE", "THIRD_PARTY_NOTICES.md"] {
        files.push((root.join(doc), doc.to_owned()));
    }
    files
}

/// `README.txt` for `version`, with Windows' line ends.
pub fn readme(root: &Path, version: &str) -> anyhow::Result<String> {
    let path = root.join(README);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text
        .replace("{version}", version)
        .replace("\r\n", "\n")
        .replace('\n', "\r\n"))
}

/// Stages the zip's files in `stage`, signs the staged `BeeZip.exe` in a signed build, and
/// writes the zip into `out`; with the updater's key, its `.sig` too. Returns the zip's path.
pub fn build(
    root: &Path,
    programs: &Programs,
    version: &str,
    mode: Mode,
    stage: &Path,
    out: &Path,
) -> anyhow::Result<PathBuf> {
    if stage.exists() {
        std::fs::remove_dir_all(stage).with_context(|| format!("removing {}", stage.display()))?;
    }
    for (from, name) in contents(root, programs, version) {
        let to = stage.join(&name);
        std::fs::create_dir_all(to.parent().unwrap_or(stage))?;
        std::fs::copy(&from, &to)
            .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    }
    std::fs::write(stage.join("README.txt"), readme(root, version)?)?;
    if mode != Mode::None {
        let app = stage.join("BeeZip.exe");
        sign::sign(root, mode, &app, None)?;
        if !sign::pe_signed(&app)? {
            bail!("{} isn't signed after sign.ps1", app.display());
        }
    }

    std::fs::create_dir_all(out)?;
    let zip = out.join(zip_name(version));
    let signature = sig(&zip);
    for stale in [&zip, &signature] {
        if stale.exists() {
            std::fs::remove_file(stale).with_context(|| format!("removing {}", stale.display()))?;
        }
    }
    let mut inputs: Vec<PathBuf> = std::fs::read_dir(stage)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    inputs.sort();
    Engine::new(registry())
        .invoke(
            "archive.create",
            json!({ "output": zip, "inputs": inputs }),
            Arc::new(NonInteractive),
            discard_events(),
        )
        .and_then(|job| job.join())
        .map_err(|e| anyhow::anyhow!("archive.create {}: {}", zip.display(), e.message))?;

    let key = std::env::var("TAURI_SIGNING_PRIVATE_KEY").unwrap_or_default();
    if !key.trim().is_empty() {
        // The key's password comes from TAURI_SIGNING_PRIVATE_KEY_PASSWORD; no prompt.
        let mut signer = pnpm();
        signer
            .current_dir(root.join("apps/desktop"))
            .args(["tauri", "signer", "sign", "--app-version", version])
            .arg(&zip)
            .stdin(Stdio::null());
        check(signer.status(), "pnpm tauri signer sign")?;
        if !signature.is_file() {
            bail!("tauri signer sign left no {}", signature.display());
        }
    }
    println!("portable copy: {}", zip.display());
    Ok(zip)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn holds_the_programs_where_the_installer_puts_them() {
        let root = Path::new("/repo");
        let programs = Programs {
            app: Path::new("/t/dist/release/BeeZip.exe"),
            cli: Path::new("/t/dist-cli/release/beezip.exe"),
            dll: Path::new("/t/dist-cli/release/beezip_shell.dll"),
        };
        let names: Vec<String> = contents(root, &programs, "0.2.0")
            .into_iter()
            .map(|(_, name)| name)
            .collect();
        assert_eq!(
            names,
            [
                "BeeZip.exe",
                "bin/beezip.exe",
                "beezip_shell_0.2.0.dll",
                "LICENSE-MIT",
                "LICENSE-APACHE",
                "THIRD_PARTY_NOTICES.md"
            ]
        );
        assert_eq!(zip_name("0.2.0"), "BeeZip_0.2.0_x64-portable.zip");
    }

    #[test]
    fn the_readme_names_its_version_with_windows_line_ends() {
        let text = readme(&crate::codegen::workspace_root(), "0.2.0").unwrap();
        assert!(text.starts_with("BeeZip 0.2.0, portable\r\n"), "{text}");
        assert!(!text.replace("\r\n", "").contains('\n'));
        assert!(!text.contains('{'));
    }
}
