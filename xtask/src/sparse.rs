//! The Windows 11 menu's sparse package (docs/M4.md §5.2, §9): its manifest, from
//! `packaging/windows/sparse/AppxManifest.xml`, and its logos, from the app's icons. `dist` stages
//! them in the installer, and when it signs (docs/M6.md §9.2) packs them into
//! `beezip-sparse.msix` and signs that; `shell --mode modern` registers them unsigned, under
//! Developer Mode.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use beezip_menu::clsid;

/// The development certificate's subject (`xtask dev-cert`), and the publisher of every package
/// that certificate signs or that is never signed. A production certificate's packages are
/// published by its subject (`sign::publisher`).
pub const DEV_PUBLISHER: &str = "CN=BeeZip Dev";
/// The logos the manifest names, from `apps/desktop/src-tauri/icons`.
const LOGOS: [&str; 3] = [
    "StoreLogo.png",
    "Square44x44Logo.png",
    "Square150x150Logo.png",
];

/// A package version has four parts of at most 65535: `0.1.0` is `0.1.0.0`. A pre-release or
/// build suffix is dropped.
pub fn package_version(version: &str) -> anyhow::Result<String> {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let mut parts: Vec<u16> = core
        .split('.')
        .map(|p| p.parse::<u16>())
        .collect::<Result<_, _>>()
        .with_context(|| format!("{version} isn't a version a package can have"))?;
    if parts.is_empty() || parts.len() > 4 {
        bail!("{version} isn't a version a package can have");
    }
    parts.resize(4, 0);
    Ok(parts
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

/// The manifest for `version`, naming `dll` as the menu's DLL in the external location, published
/// by `publisher`, which must be the subject of the certificate that signs the package.
pub fn manifest(root: &Path, version: &str, dll: &str, publisher: &str) -> anyhow::Result<String> {
    let path = root.join("packaging/windows/sparse/AppxManifest.xml");
    let template =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let class = clsid::braced(clsid::MODERN_ROOT);
    let text = template
        .replace("{{VERSION}}", &package_version(version)?)
        .replace("{{PUBLISHER}}", &xml_attribute(publisher))
        .replace("{{DLL}}", dll)
        .replace("{{CLSID}}", class.trim_matches(['{', '}']));
    if let Some(at) = text.find("{{") {
        bail!("{} has an unknown placeholder at byte {at}", path.display());
    }
    Ok(text)
}

/// A value for a double-quoted XML attribute. A subject may hold `"` (`O="Foo, Inc."`) or `&`.
fn xml_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Writes the manifest and the logos into `out`, which is emptied first.
pub fn stage(
    root: &Path,
    out: &Path,
    version: &str,
    dll: &str,
    publisher: &str,
) -> anyhow::Result<()> {
    if out.exists() {
        std::fs::remove_dir_all(out).with_context(|| format!("emptying {}", out.display()))?;
    }
    std::fs::create_dir_all(out)?;
    std::fs::write(
        out.join("AppxManifest.xml"),
        manifest(root, version, dll, publisher)?,
    )?;
    let icons = root.join("apps/desktop/src-tauri/icons");
    for logo in LOGOS {
        std::fs::copy(icons.join(logo), out.join(logo))
            .with_context(|| format!("copying {logo}"))?;
    }
    Ok(())
}

/// Packs `dir` into `msix`, unsigned: `sign::sign` signs it. `/nv` skips makeappx's semantic
/// checks, which would look for the DLL and `BeeZip.exe` inside the package: they are in the
/// external location.
pub fn pack(dir: &Path, msix: &Path) -> anyhow::Result<()> {
    let makeappx = sdk_tool("makeappx.exe")?;
    let _ = std::fs::remove_file(msix);
    run(Command::new(&makeappx)
        .args(["pack", "/o", "/nv", "/d"])
        .arg(dir)
        .arg("/p")
        .arg(msix))
    .context("makeappx pack")
}

fn run(cmd: &mut Command) -> anyhow::Result<()> {
    let out = cmd.output().context("starting it")?;
    if !out.status.success() {
        bail!(
            "{}\n{}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// A tool from the newest Windows SDK: `Windows Kits\10\bin\<version>\x64\<name>`.
fn sdk_tool(name: &str) -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("ProgramFiles(x86)")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"))
        .join(r"Windows Kits\10\bin");
    let mut versions: Vec<(Vec<u32>, PathBuf)> = std::fs::read_dir(&base)
        .with_context(|| format!("no Windows SDK in {}", base.display()))?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let v: Vec<u32> = e
                .file_name()
                .to_str()?
                .split('.')
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?;
            let tool = e.path().join("x64").join(name);
            tool.is_file().then_some((v, tool))
        })
        .collect();
    versions.sort();
    versions
        .pop()
        .map(|(_, p)| p)
        .with_context(|| format!("no {name} in any Windows SDK under {}", base.display()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::codegen::workspace_root;

    #[test]
    fn versions_have_four_parts() {
        assert_eq!(package_version("0.1.0").unwrap(), "0.1.0.0");
        assert_eq!(package_version("1.2.3-beta.1").unwrap(), "1.2.3.0");
        assert_eq!(package_version("1.2.3.4").unwrap(), "1.2.3.4");
        assert!(package_version("1.70000.0").is_err());
        assert!(package_version("1.2.3.4.5").is_err());
    }

    #[test]
    fn the_publisher_is_escaped() {
        let text = manifest(
            &workspace_root(),
            "0.1.1",
            "beezip_shell_0.1.1.dll",
            r#"CN=A & B, O="A & B, Inc.", C=US"#,
        )
        .unwrap();
        assert!(text.contains(r#"Publisher="CN=A &amp; B, O=&quot;A &amp; B, Inc.&quot;, C=US""#));
    }

    #[test]
    fn the_manifest_is_filled_in() {
        let text = manifest(
            &workspace_root(),
            "0.1.1",
            "beezip_shell_0.1.1.dll",
            DEV_PUBLISHER,
        )
        .unwrap();
        assert!(text.contains(r#"Version="0.1.1.0""#));
        assert!(text.contains(r#"Publisher="CN=BeeZip Dev""#));
        assert!(text.contains(r#"Path="beezip_shell_0.1.1.dll""#));
        assert_eq!(
            text.matches(r#""03CB0FA0-5D6C-4547-9B65-956DE58D1AF2""#)
                .count(),
            3,
            "the class and both verbs"
        );
        assert!(!text.contains("{{"));
    }
}
