//! Signing for `xtask dist` (docs/M6.md §9.2): `BEEZIP_SIGN` picks how, and
//! `packaging/windows/sign.ps1` is the one place that signs.
//!
//! - `none` (the default): nothing is signed, and the Windows 11 menu's `.msix` stays out of the
//!   installer, since nothing could install it without admin.
//! - `dev`: the development certificate from `xtask dev-cert`, `CN=BeeZip Dev` (`--sign-dev`).
//! - `pfx`: a certificate in a file, `BEEZIP_SIGN_PFX` with `BEEZIP_SIGN_PFX_PASSWORD`.
//! - `artifact`: Azure Artifact Signing, through signtool and its dlib, signed in with the Azure
//!   CLI (on CI, azure/login with OIDC).
//!
//! When it signs, Tauri gets `bundle.windows.signCommand` (sign.ps1, once per file), and `dist`
//! signs the `.msix` itself through the same script, which Tauri never passes it. sign.ps1 also
//! signs Tauri's copy of `nsExec.dll`, which Tauri leaves out.
//!
//! The package's publisher must be the certificate's subject, exactly as Windows writes it
//! (signtool refuses a package otherwise, even for the order of the subject's parts), and one of
//! `beezip_commands::shell::PUBLISHERS`, so that `shell.status` and `shell.install` recognise the
//! package. `dist` signs the CLI first and takes the subject from its signature, so it never has
//! to be typed in, and Artifact Signing's (which exists only while it signs) works the same way.
//! `BEEZIP_SIGN_PUBLISHER`, when set, must be the same.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};
use beezip_commands::shell::PUBLISHERS;
use serde_json::{Value, json};

use crate::sparse::DEV_PUBLISHER;

/// The script, from the workspace root.
pub const SCRIPT: &str = "packaging/windows/sign.ps1";

/// How `xtask dist` signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    None,
    Dev,
    Pfx,
    Artifact,
}

impl Mode {
    /// From `BEEZIP_SIGN`; `--sign-dev` is `dev`. `env` reads an environment variable.
    pub fn from_env(sign_dev: bool, env: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Mode> {
        let set = env("BEEZIP_SIGN")
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty());
        let mode = match set.as_deref() {
            None | Some("none") => Mode::None,
            Some("dev") => Mode::Dev,
            Some("pfx") => Mode::Pfx,
            Some("artifact") => Mode::Artifact,
            Some(other) => bail!("BEEZIP_SIGN is `{other}`: it must be none, dev, pfx or artifact"),
        };
        match (sign_dev, mode) {
            (false, _) | (true, Mode::Dev) => Ok(mode),
            (true, Mode::None) if set.is_none() => Ok(Mode::Dev),
            (true, mode) => bail!(
                "--sign-dev signs with the development certificate, but BEEZIP_SIGN is {}",
                mode.name()
            ),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Mode::None => "none",
            Mode::Dev => "dev",
            Mode::Pfx => "pfx",
            Mode::Artifact => "artifact",
        }
    }

    /// The environment variables this mode can't sign without, missing from `env`: checked
    /// before a build of several minutes rather than at its end.
    pub fn missing(self, env: &dyn Fn(&str) -> Option<String>) -> Vec<&'static str> {
        let needs: &[&str] = match self {
            Mode::None | Mode::Dev => &[],
            Mode::Pfx => &["BEEZIP_SIGN_PFX"],
            Mode::Artifact => &[
                "BEEZIP_ARTIFACT_ENDPOINT",
                "BEEZIP_ARTIFACT_ACCOUNT",
                "BEEZIP_ARTIFACT_PROFILE",
                "BEEZIP_ARTIFACT_DLIB",
            ],
        };
        needs
            .iter()
            .copied()
            .filter(|n| env(n).is_none_or(|v| v.trim().is_empty()))
            .collect()
    }
}

/// The publisher of the Windows 11 menu's package. Unsigned builds keep the development one:
/// their package is only ever registered under Developer Mode. Signed ones take `signer`, the
/// subject of the certificate that signed the CLI; `wanted` is `BEEZIP_SIGN_PUBLISHER`, which
/// may repeat it but not contradict it.
pub fn publisher(mode: Mode, wanted: Option<&str>, signer: Option<&str>) -> anyhow::Result<String> {
    if mode == Mode::None {
        return Ok(DEV_PUBLISHER.to_owned());
    }
    let signer = signer.context("the CLI was signed, but its signature has no signer")?;
    if let Some(w) = wanted
        .map(str::trim)
        .filter(|w| !w.is_empty() && *w != signer)
    {
        bail!(
            "BEEZIP_SIGN_PUBLISHER is `{w}`, but the certificate's subject is `{signer}`: the \
             package's publisher must be the certificate's subject, exactly as Windows writes it"
        );
    }
    let publisher = signer.to_owned();
    if !PUBLISHERS.contains(&publisher.as_str()) {
        bail!(
            "the package's publisher would be `{publisher}`, which isn't in PUBLISHERS in \
             crates/beezip-commands/src/shell/mod.rs: add it there, so `shell.status` and \
             `shell.install` recognise this package and replace the older ones"
        );
    }
    Ok(publisher)
}

/// Tauri's `bundle.windows.signCommand`: sign.ps1 with the file as the only argument. Windows
/// PowerShell, which every Windows has. The script's path has forward slashes: Tauri hands the
/// uninstaller's command to NSIS in Rust's `Debug` format, which would double backslashes.
pub fn sign_command(root: &Path) -> Value {
    let script = root.join(SCRIPT).display().to_string().replace('\\', "/");
    json!({
        "cmd": "powershell.exe",
        "args": [
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "%1"
        ],
    })
}

/// sign.ps1 in Windows PowerShell, signing as `mode`. Started from PowerShell 7, Windows
/// PowerShell would inherit 7's module path and load its modules (devcert.rs): without it, it
/// uses its own. The same goes for Tauri, which starts the script through the signCommand.
pub fn script(root: &Path, mode: Mode) -> Command {
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ])
    .arg(root.join(SCRIPT));
    environment(&mut cmd, mode);
    cmd
}

/// What every process that may run sign.ps1 needs: `BEEZIP_SIGN` (`--sign-dev` sets none), and
/// no PowerShell 7 module path.
pub fn environment(cmd: &mut Command, mode: Mode) {
    cmd.env("BEEZIP_SIGN", mode.name())
        .env_remove("PSModulePath");
}

/// The subject of the certificate that signed `file`, as Windows writes it; None when it isn't
/// signed.
pub fn signer(root: &Path, file: &Path) -> anyhow::Result<Option<String>> {
    let out = script(root, Mode::None)
        .arg(file)
        .arg("-Signer")
        .output()
        .context("starting powershell.exe")?;
    if !out.status.success() {
        bail!(
            "sign.ps1 -Signer failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let subject = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Ok(Some(subject).filter(|s| !s.is_empty()))
}

/// Signs `file` through sign.ps1; a package's `publisher` must be the certificate's subject.
pub fn sign(root: &Path, mode: Mode, file: &Path, publisher: Option<&str>) -> anyhow::Result<()> {
    let mut cmd = script(root, mode);
    cmd.arg(file);
    if let Some(p) = publisher {
        cmd.arg("-Publisher").arg(p);
    }
    let status = cmd.status().context("starting powershell.exe")?;
    if !status.success() {
        bail!("sign.ps1 couldn't sign {}: {status}", file.display());
    }
    Ok(())
}

/// Whether a PE file (an `.exe` or `.dll`) carries an Authenticode signature: its certificate
/// table, the fifth data directory, isn't empty. It says nothing of whether the signature is
/// valid or trusted; signtool and Windows judge that.
pub fn pe_signed(path: &Path) -> anyhow::Result<bool> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    certificate_table(&bytes)
        .with_context(|| format!("{} isn't a PE file", path.display()))
        .map(|(offset, size)| {
            offset != 0
                && size != 0
                && usize::try_from(u64::from(offset) + u64::from(size))
                    .is_ok_and(|end| end <= bytes.len())
        })
}

/// The certificate table's file offset and size, from a PE's optional header.
fn certificate_table(pe: &[u8]) -> Option<(u32, u32)> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(pe.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(pe.get(at..at + 4)?.try_into().ok()?));
    if pe.get(..2)? != b"MZ" {
        return None;
    }
    let header = usize::try_from(u32_at(0x3C)?).ok()?;
    if pe.get(header..header + 4)? != b"PE\0\0" {
        return None;
    }
    let optional = header + 24;
    // The data directories follow the optional header's fixed part: 96 bytes in PE32, 112 in
    // PE32+; the certificate table is the fifth, of eight bytes each.
    let directories = match u16_at(optional)? {
        0x10B => optional + 96,
        0x20B => optional + 112,
        _ => return None,
    };
    let count = u32_at(directories - 4)?;
    if count < 5 {
        return Some((0, 0));
    }
    Some((u32_at(directories + 32)?, u32_at(directories + 36)?))
}

/// Whether an `.msix` is signed: makeappx's packages hold `AppxSignature.p7x` only once signtool
/// has signed them.
pub fn msix_signed(path: &Path) -> anyhow::Result<bool> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let name = b"AppxSignature.p7x";
    Ok(bytes.windows(name.len()).any(|w| w == name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn env(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name: &str| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn the_mode_comes_from_the_environment_or_sign_dev() {
        assert_eq!(Mode::from_env(false, &env(&[])).unwrap(), Mode::None);
        assert_eq!(
            Mode::from_env(false, &env(&[("BEEZIP_SIGN", "")])).unwrap(),
            Mode::None
        );
        assert_eq!(
            Mode::from_env(false, &env(&[("BEEZIP_SIGN", " PFX ")])).unwrap(),
            Mode::Pfx
        );
        assert_eq!(
            Mode::from_env(false, &env(&[("BEEZIP_SIGN", "artifact")])).unwrap(),
            Mode::Artifact
        );
        assert!(Mode::from_env(false, &env(&[("BEEZIP_SIGN", "yes")])).is_err());
        assert_eq!(Mode::from_env(true, &env(&[])).unwrap(), Mode::Dev);
        assert_eq!(
            Mode::from_env(true, &env(&[("BEEZIP_SIGN", "dev")])).unwrap(),
            Mode::Dev
        );
        assert!(Mode::from_env(true, &env(&[("BEEZIP_SIGN", "pfx")])).is_err());
        assert!(Mode::from_env(true, &env(&[("BEEZIP_SIGN", "none")])).is_err());
    }

    #[test]
    fn missing_settings_are_named_before_the_build() {
        assert!(Mode::None.missing(&env(&[])).is_empty());
        assert!(Mode::Dev.missing(&env(&[])).is_empty());
        assert_eq!(Mode::Pfx.missing(&env(&[])), ["BEEZIP_SIGN_PFX"]);
        let some = env(&[
            (
                "BEEZIP_ARTIFACT_ENDPOINT",
                "https://eus.codesigning.azure.net",
            ),
            ("BEEZIP_ARTIFACT_ACCOUNT", "beezip"),
            ("BEEZIP_ARTIFACT_PROFILE", " "),
        ]);
        assert_eq!(
            Mode::Artifact.missing(&some),
            ["BEEZIP_ARTIFACT_PROFILE", "BEEZIP_ARTIFACT_DLIB"]
        );
    }

    #[test]
    fn the_publisher_is_the_certificates_subject_and_must_be_known() {
        // Unsigned: the development publisher, whatever BEEZIP_SIGN_PUBLISHER says.
        assert_eq!(publisher(Mode::None, None, None).unwrap(), DEV_PUBLISHER);
        assert_eq!(
            publisher(Mode::None, Some("CN=Other"), None).unwrap(),
            DEV_PUBLISHER
        );
        // Signed: the signer's subject, which BEEZIP_SIGN_PUBLISHER may repeat but not contradict.
        for mode in [Mode::Dev, Mode::Pfx, Mode::Artifact] {
            assert_eq!(
                publisher(mode, None, Some(DEV_PUBLISHER)).unwrap(),
                DEV_PUBLISHER
            );
            assert_eq!(
                publisher(mode, Some(" CN=BeeZip Dev "), Some(DEV_PUBLISHER)).unwrap(),
                DEV_PUBLISHER
            );
            assert!(publisher(mode, Some("CN=Other"), Some(DEV_PUBLISHER)).is_err());
            assert!(publisher(mode, None, None).is_err());
        }
        let unknown = publisher(
            Mode::Artifact,
            None,
            Some("C=US, O=Josh Close, CN=Josh Close"),
        )
        .unwrap_err()
        .to_string();
        assert!(unknown.contains("PUBLISHERS"), "{unknown}");
        assert!(unknown.contains("add it there"), "{unknown}");
    }

    #[test]
    fn the_sign_command_takes_the_file_as_its_only_argument() {
        let cmd = sign_command(Path::new(r"C:\src\beezip"));
        assert_eq!(cmd["cmd"], "powershell.exe");
        let args: Vec<&str> = cmd["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert_eq!(args.last(), Some(&"%1"));
        assert_eq!(args.iter().filter(|a| **a == "%1").count(), 1);
        assert!(args.contains(&"C:/src/beezip/packaging/windows/sign.ps1"));
        assert!(!args.iter().any(|a| a.contains('\\')));
    }

    /// A PE header: `MZ`, the PE signature at 0x80, then the optional header with `dirs` data
    /// directories, the fifth being (`offset`, `size`).
    fn pe(magic: u16, dirs: u32, offset: u32, size: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let optional = 0x80 + 24;
        b[optional..optional + 2].copy_from_slice(&magic.to_le_bytes());
        let directories = optional + if magic == 0x20B { 112 } else { 96 };
        b[directories - 4..directories].copy_from_slice(&dirs.to_le_bytes());
        b[directories + 32..directories + 36].copy_from_slice(&offset.to_le_bytes());
        b[directories + 36..directories + 40].copy_from_slice(&size.to_le_bytes());
        b
    }

    #[test]
    fn a_signature_is_a_certificate_table() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.dll");
        for (bytes, signed) in [
            (pe(0x20B, 16, 0x300, 0x100), true),
            (pe(0x10B, 16, 0x300, 0x100), true),
            (pe(0x20B, 16, 0, 0), false),
            (pe(0x10B, 4, 0x300, 0x100), false),
            // A table past the end of the file is no signature.
            (pe(0x20B, 16, 0x300, 0x101), false),
        ] {
            std::fs::write(&file, bytes).unwrap();
            assert_eq!(pe_signed(&file).unwrap(), signed);
        }
        std::fs::write(&file, b"not a PE").unwrap();
        assert!(pe_signed(&file).is_err());
    }

    #[test]
    fn a_package_is_signed_once_it_holds_its_signature() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.msix");
        std::fs::write(&file, b"PK\x03\x04AppxManifest.xml...AppxBlockMap.xml").unwrap();
        assert!(!msix_signed(&file).unwrap());
        std::fs::write(&file, b"PK\x03\x04AppxManifest.xml...AppxSignature.p7x").unwrap();
        assert!(msix_signed(&file).unwrap());
    }
}
