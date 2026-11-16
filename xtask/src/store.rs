//! The Microsoft Store package (docs/M12.md §2): `bundle/store/BeeZip_<V>_x64.msix`, the
//! installer's programs with a full manifest (`packaging/windows/store/AppxManifest.xml`), the
//! logos `xtask icons` makes and a `resources.pri` indexing them. `dist` builds it on Windows from
//! the portable copy's staged files, so a signed build's programs are signed in it too.
//!
//! The package itself is never signed: Microsoft signs it after certification, under Partner
//! Center's publisher, which no certificate of ours has. The layout stays beside it, so
//! `Add-AppxPackage -Register <layout>\AppxManifest.xml` installs it under Developer Mode.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use beezip_commands::shell::store;
use beezip_menu::clsid;
use serde_json::Value;

use crate::dist::{Os, associations};
use crate::icons::{STORE_ASSETS, STORE_ASSETS_DIR};
use crate::sparse::{package_version, run, sdk_tool};

/// The manifest's template.
const TEMPLATE: &str = "packaging/windows/store/AppxManifest.xml";
/// makepri's config: one `resources.pri`, no resource packages.
const PRI_CONFIG: &str = "packaging/windows/store/priconfig.xml";
/// The installer's documents that go in, beside the programs. The portable copy's README is
/// about unzipping it, so it stays out.
const DOCUMENTS: [&str; 3] = ["LICENSE-MIT", "LICENSE-APACHE", "THIRD_PARTY_NOTICES.md"];

/// The package's name, beside the installer's `BeeZip_<V>_x64-setup.exe`.
pub fn msix_name(version: &str) -> String {
    format!("BeeZip_{version}_x64.msix")
}

/// Whether `version` can be a Store version. A package version drops a pre-release's suffix, so
/// `0.7.0-rc.1` would be `0.7.0.0`, the release's own number in the Store.
pub fn has_store_version(version: &str) -> bool {
    !version.contains(['-', '+'])
}

/// One `uap:FileTypeAssociation` per association `dist` gives the installer. A name must be
/// lowercase letters, digits and `-`, starting with a letter: `7z` is `x7z`, `001` is `x001`.
fn associations_xml(associations: &[Value]) -> anyhow::Result<String> {
    let mut out = Vec::new();
    for a in associations {
        let description = a["description"].as_str().unwrap_or("Archive");
        for ext in a["ext"].as_array().into_iter().flatten() {
            let ext = ext
                .as_str()
                .context("an association's extension isn't a string")?
                .to_ascii_lowercase();
            let mut name: String = ext
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect();
            if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
                name.insert(0, 'x');
            }
            out.push(format!(
                "        <uap:Extension Category=\"windows.fileTypeAssociation\">\n\
                 \x20         <uap:FileTypeAssociation Name=\"{name}\">\n\
                 \x20           <uap:DisplayName>{}</uap:DisplayName>\n\
                 \x20           <uap:SupportedFileTypes><uap:FileType>.{}</uap:FileType></uap:SupportedFileTypes>\n\
                 \x20         </uap:FileTypeAssociation>\n\
                 \x20       </uap:Extension>",
                xml_text(description),
                xml_text(&ext),
            ));
        }
    }
    if out.is_empty() {
        bail!("no file associations for the Store package");
    }
    Ok(out.join("\n"))
}

fn xml_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The manifest for `version`, naming `dll`, with `associations` (`dist::associations`).
pub fn manifest(
    root: &Path,
    version: &str,
    dll: &str,
    associations: &[Value],
) -> anyhow::Result<String> {
    let path = root.join(TEMPLATE);
    let template =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let class = clsid::braced(clsid::STORE_ROOT);
    let text = template
        .replace("{{NAME}}", store::NAME)
        .replace("{{PUBLISHER}}", &xml_text(store::PUBLISHER))
        .replace(
            "{{PUBLISHER_DISPLAY_NAME}}",
            &xml_text(store::PUBLISHER_DISPLAY_NAME),
        )
        .replace("{{VERSION}}", &package_version(version)?)
        .replace("{{DLL}}", dll)
        .replace("{{CLSID}}", class.trim_matches(['{', '}']))
        .replace("{{ASSOCIATIONS}}", &associations_xml(associations)?);
    if let Some(at) = text.find("{{") {
        bail!("{} has an unknown placeholder at byte {at}", path.display());
    }
    Ok(text)
}

/// The files `layout` copies from the portable copy's stage: the programs, at the paths the
/// manifest names, and the documents. Not `bin/beezip.exe`: without its alias, which needs
/// Microsoft's waiver for a hidden application, nothing could start it (docs/M12.md §14).
pub fn program_files(version: &str) -> Vec<String> {
    let mut files = vec!["BeeZip.exe".to_owned(), crate::dist::dll_name(version)];
    files.extend(DOCUMENTS.iter().map(|d| (*d).to_owned()));
    files
}

/// Lays out the package in `layout`, emptied first: the programs from `stage` (the portable
/// copy's), the logos, the manifest and `resources.pri`. `work` holds the copy of the logos
/// makepri indexes.
pub fn layout(
    root: &Path,
    stage: &Path,
    version: &str,
    layout: &Path,
    work: &Path,
) -> anyhow::Result<()> {
    for dir in [layout, work] {
        if dir.exists() {
            std::fs::remove_dir_all(dir).with_context(|| format!("emptying {}", dir.display()))?;
        }
        std::fs::create_dir_all(dir)?;
    }
    for name in program_files(version) {
        let (from, to) = (stage.join(&name), layout.join(&name));
        std::fs::create_dir_all(to.parent().unwrap_or(layout))?;
        std::fs::copy(&from, &to)
            .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    }
    // The logos go into the layout, and into a folder of their own for makepri to index, so
    // the index holds the logos and not every program as a resource too.
    let indexed = work.join("indexed");
    for dir in [layout.join("Assets"), indexed.join("Assets")] {
        std::fs::create_dir_all(&dir)?;
        for (name, _) in STORE_ASSETS {
            let from = root.join(STORE_ASSETS_DIR).join(name);
            std::fs::copy(&from, dir.join(name))
                .with_context(|| format!("copying {}: run `cargo xtask icons`", from.display()))?;
        }
    }
    let manifest_path = layout.join("AppxManifest.xml");
    std::fs::write(
        &manifest_path,
        manifest(
            root,
            version,
            &crate::dist::dll_name(version),
            &associations(Os::Windows)?,
        )?,
    )?;

    let makepri = sdk_tool("makepri.exe")?;
    let config = root.join(PRI_CONFIG);
    run(Command::new(&makepri)
        .args(["new", "/pr"])
        .arg(&indexed)
        .arg("/cf")
        .arg(&config)
        .arg("/mn")
        .arg(&manifest_path)
        .arg("/of")
        .arg(layout.join("resources.pri"))
        .arg("/o"))
    .context("makepri new")?;
    // One index: a split one (`resources.scale-200.pri`) belongs in a bundle's resource package.
    for entry in std::fs::read_dir(layout)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(".pri") && name != "resources.pri" {
            bail!("makepri wrote {name} beside resources.pri: check {PRI_CONFIG}");
        }
    }
    Ok(())
}

/// Packs `layout` into `msix`, unsigned. makeappx checks the manifest against the files: the
/// programs, the DLL and the logos must be there.
pub fn pack(layout: &Path, msix: &Path) -> anyhow::Result<()> {
    let makeappx = sdk_tool("makeappx.exe")?;
    if msix.exists() {
        std::fs::remove_file(msix).with_context(|| format!("removing {}", msix.display()))?;
    }
    run(Command::new(&makeappx)
        .args(["pack", "/o", "/d"])
        .arg(layout)
        .arg("/p")
        .arg(msix))
    .context("makeappx pack")
}

/// The package for `version` in `out` (`bundle/store`), from the portable copy's `stage`, with
/// its layout beside it. A pre-release gets none.
pub fn build(
    root: &Path,
    stage: &Path,
    version: &str,
    out: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    if !has_store_version(version) {
        println!("no Store package for {version}: a pre-release has no Store version");
        return Ok(None);
    }
    let layout_dir = out.join("layout");
    layout(root, stage, version, &layout_dir, &out.join("work"))?;
    let msix = out.join(msix_name(version));
    pack(&layout_dir, &msix)?;
    println!("Store package: {}", msix.display());
    Ok(Some(msix))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;
    use crate::codegen::workspace_root;

    fn sample() -> Vec<Value> {
        vec![
            json!({ "ext": ["7z"], "name": "BeeZip.7z", "description": "7z archive" }),
            json!({ "ext": ["001"], "name": "BeeZip.001", "description": "Split archive, first part" }),
            json!({ "ext": ["tar"], "name": "BeeZip.tar", "description": "Tar & such <archive>" }),
        ]
    }

    #[test]
    fn the_manifest_is_filled_in() {
        let text = manifest(
            &workspace_root(),
            "0.7.0",
            "beezip_shell_0.7.0.dll",
            &sample(),
        )
        .unwrap();
        assert!(text.contains(r#"<Identity Name="CloseConsultingInc.BeeZip" Publisher="CN=B81ECA8F-95E1-4C2B-B747-FE4DA97C8BFC" Version="0.7.0.0" ProcessorArchitecture="x64" />"#));
        assert!(
            text.contains("<PublisherDisplayName>Close Consulting, Inc</PublisherDisplayName>")
        );
        assert!(text.contains(r#"Path="beezip_shell_0.7.0.dll""#));
        assert_eq!(
            text.matches(r#""E6ACE5B2-5C8B-4F4B-AB86-8A29BE5AAB16""#)
                .count(),
            3,
            "the Store root: the class and both verbs"
        );
        assert!(
            !text.contains("03CB0FA0"),
            "never the sparse package's class"
        );
        assert_eq!(text.matches("<Application ").count(), 1, "the app alone");
        assert!(
            !text.contains("AppListEntry"),
            "a hidden application needs Microsoft's waiver (docs/M12.md §14)"
        );
        assert!(
            !text.contains(r#"Name="unvirtualizedResources""#),
            "decision 1"
        );
        let comment = &text[..text.find("-->").unwrap()];
        assert!(
            !comment.contains("<uap:"),
            "nothing filled into the comment"
        );
        assert!(!text.contains("{{"));
    }

    #[test]
    fn associations_get_valid_names_and_escaped_text() {
        let xml = associations_xml(&sample()).unwrap();
        assert!(xml.contains(r#"Name="x7z""#));
        assert!(xml.contains(r#"Name="x001""#));
        assert!(xml.contains(r#"Name="tar""#));
        assert!(xml.contains("<uap:FileType>.001</uap:FileType>"));
        assert!(xml.contains("Tar &amp; such &lt;archive&gt;"));
        assert!(associations_xml(&[]).is_err());
    }

    /// The package associates exactly what the installer associates.
    #[test]
    fn every_installer_association_is_in_the_manifest() {
        let all = associations(Os::Windows).unwrap();
        let text = manifest(&workspace_root(), "0.7.0", "beezip_shell_0.7.0.dll", &all).unwrap();
        let exts: Vec<&str> = all
            .iter()
            .flat_map(|a| a["ext"].as_array().unwrap())
            .map(|e| e.as_str().unwrap())
            .collect();
        assert_eq!(text.matches("<uap:FileType>").count(), exts.len());
        for ext in exts {
            assert!(
                text.contains(&format!("<uap:FileType>.{ext}</uap:FileType>")),
                "{ext}"
            );
        }
    }

    #[test]
    fn pre_releases_get_no_package() {
        assert!(has_store_version("0.7.0"));
        assert!(!has_store_version("0.7.0-rc.1"));
        assert!(!has_store_version("0.7.0+build.5"));
    }

    #[test]
    fn the_programs_are_where_the_manifest_runs_them() {
        let files = program_files("0.7.0");
        let text = manifest(
            &workspace_root(),
            "0.7.0",
            "beezip_shell_0.7.0.dll",
            &sample(),
        )
        .unwrap();
        assert!(files.contains(&"BeeZip.exe".to_owned()));
        assert!(text.contains(r#"Executable="BeeZip.exe""#));
        assert!(!files.iter().any(|f| f.starts_with("bin/")), "no command line");
        assert!(!text.contains(r"bin\"));
        assert!(files.contains(&"beezip_shell_0.7.0.dll".to_owned()));
        assert!(!files.iter().any(|f| f == "README.txt"));
    }

    /// Every logo the manifest names exists as a file of `xtask icons`, under some qualifier.
    #[test]
    fn the_manifests_logos_are_made() {
        let text = manifest(
            &workspace_root(),
            "0.7.0",
            "beezip_shell_0.7.0.dll",
            &sample(),
        )
        .unwrap();
        for logo in ["StoreLogo", "Square44x44Logo", "Square150x150Logo"] {
            assert!(text.contains(&format!(r"Assets\{logo}.png")), "{logo}");
            assert!(
                STORE_ASSETS
                    .iter()
                    .any(|(n, _)| n.starts_with(&format!("{logo}."))),
                "{logo}"
            );
        }
        for (name, _) in STORE_ASSETS {
            assert!(
                workspace_root().join(STORE_ASSETS_DIR).join(name).is_file(),
                "{name}"
            );
        }
    }
}
