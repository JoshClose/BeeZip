//! `cargo xtask dev-cert` (docs/M4.md §9): the code-signing certificate `dist --sign-dev` signs
//! the Windows 11 menu's package with.
//!
//! - It makes `CN=BeeZip Dev` in `CurrentUser\My`, or reuses one that is there and valid, so
//!   running it again never piles up certificates.
//! - It exports the public part to `target/dev-cert/BeeZip-Dev.cer`.
//! - It doesn't trust it. Windows installs a signed package only when the signature chains to
//!   `LocalMachine\TrustedPeople` or a trusted root (`CurrentUser\TrustedPeople` isn't enough,
//!   §16, item 2), which takes admin, so it prints the elevated command instead of running it.
//!
//! Everyday development doesn't need any of this: `xtask shell --mode modern` registers the
//! unsigned package under Developer Mode.

use std::process::Command;

use anyhow::{Context, bail};

use crate::codegen::workspace_root;
use crate::sparse::PUBLISHER;

/// Runs in Windows PowerShell, which every Windows has. The subject and the file come in
/// through the environment, so nothing needs quoting. The extensions are code signing
/// (`2.5.29.37`, EKU 1.3.6.1.5.5.7.3.3) and an end entity's basic constraints (`2.5.29.19`), as
/// Microsoft's page on signing packages makes it.
const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$subject = $env:BEEZIP_CERT_SUBJECT
$cert = Get-ChildItem Cert:\CurrentUser\My |
  Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(1) } |
  Sort-Object NotAfter -Descending | Select-Object -First 1
if ($cert) { $made = 'reused' } else {
  $cert = New-SelfSignedCertificate -Type Custom -Subject $subject -FriendlyName 'BeeZip Dev' `
    -KeyUsage DigitalSignature -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(2) `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
  $made = 'made'
}
Export-Certificate -Cert $cert -FilePath $env:BEEZIP_CERT_FILE -Force | Out-Null
"$made $($cert.Thumbprint) $($cert.NotAfter.ToString('yyyy-MM-dd'))"
"#;

pub fn run() -> anyhow::Result<()> {
    if !cfg!(windows) {
        bail!("dev-cert is for Windows");
    }
    let dir = workspace_root().join("target/dev-cert");
    std::fs::create_dir_all(&dir)?;
    let cer = dir.join("BeeZip-Dev.cer");
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            SCRIPT,
        ])
        .env("BEEZIP_CERT_SUBJECT", PUBLISHER)
        .env("BEEZIP_CERT_FILE", &cer)
        // Started from PowerShell 7, Windows PowerShell inherits its module path, loads 7's
        // security module, and has no Cert: drive (seen on CI). Without it, it uses its own.
        .env_remove("PSModulePath")
        .output()
        .context("starting powershell.exe")?;
    if !out.status.success() {
        bail!(
            "making the certificate failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut words = stdout.split_whitespace();
    let (made, thumbprint, until) = (words.next(), words.next(), words.next());
    let (Some(made), Some(thumbprint), Some(until)) = (made, thumbprint, until) else {
        bail!("powershell said: {stdout}");
    };
    println!(
        "{made} the \"{PUBLISHER}\" certificate in CurrentUser\\My ({thumbprint}, valid until {until})"
    );
    println!("exported it to {}", cer.display());
    println!(
        "To install packages signed with it, trust it once, from an elevated PowerShell:\n  \
         Import-Certificate -FilePath '{}' -CertStoreLocation Cert:\\LocalMachine\\TrustedPeople",
        cer.display()
    );
    Ok(())
}
