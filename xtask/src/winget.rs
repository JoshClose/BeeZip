//! `cargo xtask winget [--version V] [--local]`: the winget manifest for `BeeZip.BeeZip`
//! (docs/M6.md §9.6), its three files (version, default locale en-US, installer) in schema
//! 1.12.0, from the templates in `packaging/winget/`, written to
//! `target/winget/manifests/b/BeeZip/BeeZip/<V>/`, the folder they take in microsoft/winget-pkgs.
//!
//! - The version is the workspace's unless `--version` says otherwise.
//! - The installer's SHA-256 comes from the GitHub release vV, draft or published (`gh`, signed
//!   in), or with `--local` from the installer `xtask dist` built here (release, else debug), as
//!   CI does to validate the manifest.
//! - Its URL is always where the release serves it once published (a draft's assets have a
//!   temporary one).
//! - The extensions are `xtask dist`'s associations, so the three lists never differ.
//!
//! Submitting the manifest to winget-pkgs is the user's (docs/M6.md §14).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::codegen::workspace_root;
use crate::{dist, release};

/// `winget`'s flags.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WingetArgs<'a> {
    /// The workspace's version when not given.
    pub version: Option<&'a str>,
    /// From the installer `xtask dist` built here, not from the GitHub release.
    pub local: bool,
}

/// The templates, from the workspace root, and the files they become.
const TEMPLATES: &str = "packaging/winget";
const FILES: [&str; 3] = [
    "BeeZip.BeeZip.yaml",
    "BeeZip.BeeZip.locale.en-US.yaml",
    "BeeZip.BeeZip.installer.yaml",
];
/// Where the manifests go, under `target/winget`: winget-pkgs' own layout.
const OUT: [&str; 6] = ["target", "winget", "manifests", "b", "BeeZip", "BeeZip"];

pub fn run(args: WingetArgs) -> anyhow::Result<()> {
    let root = workspace_root();
    let version = match args.version {
        Some(v) => v.to_owned(),
        None => release::workspace_version(&root)?,
    };
    release::check_version(&version)?;
    let installer = dist::installer_name(&version);
    let sha256 = if args.local {
        let built = local_installer(&root, &installer)?;
        println!("the installer: {}", built.display());
        sha256_file(&built)?
    } else {
        from_release(&version, &installer)?
    };
    let extensions: Vec<String> = dist::associations()?
        .iter()
        .filter_map(|a| a["ext"][0].as_str().map(str::to_owned))
        .collect();
    let fill = Fill {
        version: &version,
        installer_url: &release::download_url(&version, &installer),
        sha256: &sha256,
        release_notes_url: &release::release_url(&version),
        repo_url: &release::repo_url(),
        extensions: &extensions,
    };

    let out = OUT
        .iter()
        .fold(root.clone(), |p, part| p.join(part))
        .join(&version);
    if out.exists() {
        std::fs::remove_dir_all(&out).with_context(|| format!("emptying {}", out.display()))?;
    }
    std::fs::create_dir_all(&out)?;
    for file in FILES {
        let template = root.join(TEMPLATES).join(file);
        let text = std::fs::read_to_string(&template)
            .with_context(|| format!("reading {}", template.display()))?;
        let text = render(&text, &fill).with_context(|| format!("filling in {file}"))?;
        std::fs::write(out.join(file), text)?;
    }
    println!("wrote BeeZip.BeeZip {version} to {}", out.display());
    println!(
        "check it with `winget validate --manifest {}`; submitting it to microsoft/winget-pkgs \
         is yours, once the release is published",
        out.display()
    );
    Ok(())
}

/// What the templates' placeholders become.
struct Fill<'a> {
    version: &'a str,
    installer_url: &'a str,
    /// Hex, upper case, as winget-pkgs writes it.
    sha256: &'a str,
    release_notes_url: &'a str,
    repo_url: &'a str,
    extensions: &'a [String],
}

/// A template filled in, without its `##` notes.
fn render(template: &str, fill: &Fill) -> anyhow::Result<String> {
    if fill.extensions.is_empty() {
        bail!("no file extensions");
    }
    let extensions: Vec<String> = fill
        .extensions
        .iter()
        .map(|e| format!("- {}", yaml_scalar(e)))
        .collect();
    let mut out = String::new();
    for line in template.lines().filter(|l| !l.starts_with("##")) {
        out.push_str(line);
        out.push('\n');
    }
    let out = out
        .replace("{{VERSION}}", fill.version)
        .replace("{{INSTALLER_URL}}", fill.installer_url)
        .replace("{{INSTALLER_SHA256}}", fill.sha256)
        .replace("{{RELEASE_NOTES_URL}}", fill.release_notes_url)
        .replace("{{REPO_URL}}", fill.repo_url)
        .replace("{{FILE_EXTENSIONS}}", &extensions.join("\n"));
    if let Some(at) = out.find("{{") {
        bail!("an unknown placeholder at byte {at}");
    }
    Ok(out)
}

/// An extension as a YAML scalar that stays a string: `001` would be a number and `no` false,
/// so anything but a word starting with a letter is quoted.
fn yaml_scalar(text: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "y", "n", "yes", "no", "on", "off", "true", "false", "null", "nan", "inf",
    ];
    let word = text.starts_with(|c: char| c.is_ascii_alphabetic())
        && text.chars().all(|c| c.is_ascii_alphanumeric())
        && !KEYWORDS.contains(&text.to_ascii_lowercase().as_str());
    if word {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "''"))
    }
}

/// The installer `xtask dist` built for this version: the release build's, else the debug one's.
fn local_installer(root: &Path, name: &str) -> anyhow::Result<PathBuf> {
    ["release", "debug"]
        .iter()
        .map(|profile| {
            ["target", "dist", profile, "bundle", "nsis", name]
                .iter()
                .fold(root.to_path_buf(), |p, part| p.join(part))
        })
        .find(|p| p.is_file())
        .with_context(|| {
            format!("no {name} under target/dist/{{release,debug}}: run `cargo xtask dist` first")
        })
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex_upper(&Sha256::digest(&bytes)))
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// The installer's SHA-256 from the GitHub release vV: the digest GitHub keeps for the asset, or
/// else the asset itself, downloaded and hashed.
fn from_release(version: &str, installer: &str) -> anyhow::Result<String> {
    let tag = format!("v{version}");
    let out = Command::new("gh")
        .args(["release", "view", &tag, "--repo", release::REPO])
        .args(["--json", "assets,isDraft"])
        .output()
        .context("starting gh (GitHub's CLI), which reads the release")?;
    if !out.status.success() {
        bail!(
            "gh release view {tag} failed: {}(is there a release {tag}, and is gh signed in?)",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let view: Value = serde_json::from_slice(&out.stdout).context("reading gh's answer")?;
    let state = if view["isDraft"] == true {
        "draft"
    } else {
        "published"
    };
    println!("the installer: {installer} in the {state} release {tag}");
    if let Some(sha) = asset_sha256(&view, installer)? {
        return Ok(sha);
    }
    let dir = std::env::temp_dir().join(format!("beezip-winget-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let status = Command::new("gh")
        .args(["release", "download", &tag, "--repo", release::REPO])
        .args(["--pattern", installer, "--clobber", "--dir"])
        .arg(&dir)
        .status()
        .context("starting gh")?;
    let sha = if status.success() {
        sha256_file(&dir.join(installer))
    } else {
        Err(anyhow::anyhow!(
            "gh release download {tag} {installer} failed: {status}"
        ))
    };
    let _ = std::fs::remove_dir_all(&dir);
    sha
}

/// The SHA-256 GitHub reports for the release's asset `name`, if it reports one; an error if the
/// release has no such asset.
fn asset_sha256(view: &Value, name: &str) -> anyhow::Result<Option<String>> {
    let asset = view["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"] == name)
        .with_context(|| format!("the release has no {name}"))?;
    Ok(asset["digest"]
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_uppercase))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;

    fn fill<'a>(extensions: &'a [String]) -> Fill<'a> {
        Fill {
            version: "1.2.3",
            installer_url: "https://github.com/JoshClose/BeeZip/releases/download/v1.2.3/BeeZip_1.2.3_x64-setup.exe",
            sha256: "21D6FB8954E5BE5694839C9CFB1CAE8AF701E781D7F4150FD384520049BEEC67",
            release_notes_url: "https://github.com/JoshClose/BeeZip/releases/tag/v1.2.3",
            repo_url: "https://github.com/JoshClose/BeeZip",
            extensions,
        }
    }

    fn rendered() -> Vec<(&'static str, String)> {
        let extensions: Vec<String> = ["001", "7z", "no", "zip"].map(String::from).to_vec();
        let root = workspace_root();
        FILES
            .iter()
            .map(|f| {
                let template = std::fs::read_to_string(root.join(TEMPLATES).join(f)).unwrap();
                (*f, render(&template, &fill(&extensions)).unwrap())
            })
            .collect()
    }

    /// A top-level `Key: value` line's value.
    fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}: ")))
            .map(str::trim)
    }

    #[test]
    fn every_file_is_schema_1_12_and_this_version() {
        for (file, text) in rendered() {
            assert!(!text.contains("{{"), "{file}");
            assert!(
                !text.contains("##"),
                "{file}: the template's notes stay out"
            );
            assert_eq!(field(&text, "ManifestVersion"), Some("1.12.0"), "{file}");
            assert!(
                text.starts_with("# yaml-language-server: $schema=https://aka.ms/winget-manifest."),
                "{file}"
            );
            assert!(text.contains(".1.12.0.schema.json\n"), "{file}");
            assert_eq!(field(&text, "PackageIdentifier"), Some("BeeZip.BeeZip"));
            assert_eq!(field(&text, "PackageVersion"), Some("1.2.3"), "{file}");
            assert!(!text.contains('\r') && !text.contains('\t'), "{file}");
        }
    }

    #[test]
    fn the_installer_is_per_user_nullsoft_with_its_switches() {
        let all = rendered();
        let (_, text) = all
            .iter()
            .find(|(f, _)| f.ends_with("installer.yaml"))
            .unwrap();
        assert_eq!(field(text, "ManifestType"), Some("installer"));
        assert_eq!(field(text, "InstallerType"), Some("nullsoft"));
        assert_eq!(field(text, "Scope"), Some("user"));
        assert_eq!(field(text, "UpgradeBehavior"), Some("install"));
        assert_eq!(field(text, "ProductCode"), Some("BeeZip"));
        for line in [
            "  Silent: /S\n",
            "  SilentWithProgress: /P\n",
            "  InstallLocation: /D=<INSTALLPATH>\n",
            "Commands:\n- beezip\n",
            "  Publisher: BeeZip\n",
            "  DisplayVersion: 1.2.3\n",
            "  InstallerUrl: https://github.com/JoshClose/BeeZip/releases/download/v1.2.3/BeeZip_1.2.3_x64-setup.exe\n",
            "  InstallerSha256: 21D6FB8954E5BE5694839C9CFB1CAE8AF701E781D7F4150FD384520049BEEC67\n",
            "FileExtensions:\n- '001'\n- '7z'\n- 'no'\n- zip\nProductCode: BeeZip\n",
        ] {
            assert!(text.contains(line), "{line:?} in\n{text}");
        }
        let (_, locale) = all.iter().find(|(f, _)| f.contains("locale")).unwrap();
        assert_eq!(field(locale, "Publisher"), Some("BeeZip"));
        assert_eq!(field(locale, "PackageLocale"), Some("en-US"));
        assert_eq!(
            field(locale, "ReleaseNotesUrl"),
            Some("https://github.com/JoshClose/BeeZip/releases/tag/v1.2.3")
        );
        assert_eq!(
            field(locale, "PublisherSupportUrl"),
            Some("https://github.com/JoshClose/BeeZip/issues")
        );
    }

    #[test]
    fn the_extensions_are_the_associations() {
        // The real list: every association, each a valid winget FileExtensions entry.
        let list: Vec<String> = dist::associations()
            .unwrap()
            .iter()
            .map(|a| a["ext"][0].as_str().unwrap().to_owned())
            .collect();
        assert!(list.len() <= 512, "winget takes at most 512");
        let template =
            std::fs::read_to_string(workspace_root().join(TEMPLATES).join(FILES[2])).unwrap();
        let text = render(&template, &fill(&list)).unwrap();
        for ext in &list {
            assert!(
                ext.len() <= 64
                    && !ext.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|', '.'])
            );
            assert!(
                text.contains(&format!("\n- {}\n", yaml_scalar(ext))),
                "{ext}"
            );
        }
        assert!(render(&template, &fill(&[])).is_err());
    }

    #[test]
    fn scalars_that_would_not_be_strings_are_quoted() {
        assert_eq!(yaml_scalar("zip"), "zip");
        assert_eq!(yaml_scalar("tbz2"), "tbz2");
        assert_eq!(yaml_scalar("001"), "'001'");
        assert_eq!(yaml_scalar("7z"), "'7z'");
        assert_eq!(yaml_scalar("No"), "'No'");
        assert_eq!(yaml_scalar("a'b"), "'a''b'");
    }

    #[test]
    fn the_hash_comes_from_the_release() {
        let view = json!({
            "isDraft": true,
            "assets": [
                { "name": "latest.json", "digest": "sha256:00" },
                {
                    "name": "BeeZip_1.2.3_x64-setup.exe",
                    "digest": "sha256:21d6fb8954e5be5694839c9cfb1cae8af701e781d7f4150fd384520049beec67",
                },
            ]
        });
        assert_eq!(
            asset_sha256(&view, "BeeZip_1.2.3_x64-setup.exe")
                .unwrap()
                .as_deref(),
            Some("21D6FB8954E5BE5694839C9CFB1CAE8AF701E781D7F4150FD384520049BEEC67")
        );
        // No digest (an older GitHub): download and hash instead.
        let view = json!({ "assets": [{ "name": "BeeZip_1.2.3_x64-setup.exe" }] });
        assert_eq!(
            asset_sha256(&view, "BeeZip_1.2.3_x64-setup.exe").unwrap(),
            None
        );
        assert!(asset_sha256(&view, "BeeZip_9.9.9_x64-setup.exe").is_err());
    }

    #[test]
    fn hashes_are_upper_case_hex() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(
            sha256_file(&file).unwrap(),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
    }
}
