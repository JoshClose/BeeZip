//! `cargo xtask dist [--debug] [--version V]`: the Windows installer (docs/M3.md §5.5, M4 §9).
//!
//! 1. The CLI and the Explorer menu's DLL are built into their own target dir,
//!    `target/dist-cli`, so the GUI's rename to `BeeZip.exe` can't clobber `beezip.exe` on a
//!    case-insensitive file system. The DLL is staged as `beezip_shell_<V>.dll`, a new name for
//!    each version, so an upgrade never has to replace a file Explorer has loaded.
//! 2. `target/dist/tauri.dist.json` is written from `packaging/windows/tauri.dist.json`, with the
//!    staged resources, the NSIS hooks and the file associations, which come from `formats.list`
//!    so the list has one source. It stays out of `tauri.conf.json` because tauri-build copies
//!    resources when the app compiles and fails on a missing one.
//! 3. `pnpm tauri build --bundles nsis --config target/dist/tauri.dist.json` builds the installer,
//!    with `CARGO_TARGET_DIR=target/dist`: the rename to `BeeZip.exe` in `target/debug` would
//!    replace the development `beezip.exe`, which Windows sees as the same file.
//!
//! `--version V` builds the installer as version V (the workspace's otherwise), so the upgrade
//! check can build 0.1.0 and 0.1.1 from one tree.
//!
//! The Windows 11 menu's package goes in as well (M4 §9): `sparse\` holds its manifest, naming
//! this version's DLL, and its logos, which `beezip shell install --mode modern --dev` registers
//! under Developer Mode. `--sign-dev` also packs them into `beezip-sparse.msix`, signed with
//! `xtask dev-cert`'s certificate, which the installer's `shell install` registers on Windows 11
//! where that certificate is trusted. An unsigned `.msix` is never shipped: nothing can install
//! it without admin.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use anyhow::{Context, bail};
use beezip_commands::shell::{MSIX, SPARSE};
use beezip_commands::{Engine, NonInteractive, discard_events, registry};
use serde_json::{Value, json};

use crate::codegen::workspace_root;

/// Zip-based document formats BeeZip reads but leaves to their own apps.
const DOCUMENTS: &[&str] = &[
    "jar", "war", "apk", "aab", "ipa", "xpi", "vsix", "nupkg", "whl", "docx", "xlsx", "pptx",
    "odt", "ods", "odp", "epub", "appx", "msix",
];

/// Extensions that only name a later part of a set; the first part is what people open.
const LATER_PARTS: &[&str] = &["r00"];

/// Extensions Windows opens itself: it mounts disk images and shows cabinets as folders, and
/// taking those over would surprise people (docs/M5.md §5.12). Explorer's menu still offers
/// BeeZip's items for them.
const WINDOWS_OWNS: &[&str] = &["cab", "iso"];

pub fn run(debug: bool, version: Option<&str>, sign_dev: bool) -> anyhow::Result<()> {
    let root = workspace_root();
    let profile = if debug { "debug" } else { "release" };
    let version = version.unwrap_or(env!("CARGO_PKG_VERSION"));

    println!("building the CLI and the Explorer menu ({profile})");
    let mut cargo = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cargo
        .current_dir(&root)
        .args([
            "build",
            "--locked",
            "-p",
            "beezip-cli",
            "-p",
            "beezip-shell",
        ])
        .arg("--target-dir")
        .arg(root.join("target/dist-cli"));
    if !debug {
        cargo.arg("--release");
    }
    check(cargo.status(), "cargo build -p beezip-cli -p beezip-shell")?;
    let built = root.join("target/dist-cli").join(profile);
    let cli = built.join(format!("beezip{}", std::env::consts::EXE_SUFFIX));
    let dll = built.join("beezip_shell.dll");
    for f in [&cli, &dll] {
        if !f.is_file() {
            bail!("{} wasn't built", f.display());
        }
    }

    let dir = root.join("target/dist");
    std::fs::create_dir_all(&dir)?;
    let sparse = dir.join(SPARSE);
    crate::sparse::stage(&root, &sparse, version, &dll_name(version))?;
    let msix = if sign_dev {
        let msix = dir.join(MSIX);
        crate::sparse::pack_and_sign(&sparse, &msix)?;
        println!("packed and signed {}", msix.display());
        Some(msix)
    } else {
        None
    };
    let package = Package {
        sparse: &sparse,
        msix: msix.as_deref(),
    };
    let config = config(&root, &cli, &dll, version, &package)?;
    let config_path = dir.join("tauri.dist.json");
    std::fs::write(&config_path, serde_json::to_string_pretty(&config)? + "\n")?;
    println!("wrote {}", config_path.display());

    println!("building the installer ({profile})");
    let mut tauri = pnpm();
    tauri
        .current_dir(root.join("apps/desktop"))
        .env("CARGO_TARGET_DIR", &dir)
        .args(["tauri", "build", "--bundles", "nsis", "--config"])
        .arg(&config_path);
    if debug {
        tauri.arg("--debug");
    }
    check(tauri.status(), "pnpm tauri build")?;

    let bundle = dir.join(profile).join("bundle/nsis");
    let installers: Vec<PathBuf> = std::fs::read_dir(&bundle)
        .with_context(|| format!("reading {}", bundle.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "exe"))
        .collect();
    if installers.is_empty() {
        bail!("no installer in {}", bundle.display());
    }
    for i in installers {
        println!("installer: {}", i.display());
    }
    Ok(())
}

fn check(status: std::io::Result<std::process::ExitStatus>, what: &str) -> anyhow::Result<()> {
    let status = status.with_context(|| format!("starting {what}"))?;
    if !status.success() {
        bail!("{what} failed: {status}");
    }
    Ok(())
}

/// pnpm is a `.cmd` shim on Windows, which `Command` doesn't look for.
fn pnpm() -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/d", "/c", "pnpm"]);
        c
    } else {
        Command::new("pnpm")
    }
}

/// Forward slashes, which Tauri's config and NSIS both take.
fn slashes(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// The DLL's name in the install folder.
pub fn dll_name(version: &str) -> String {
    format!("beezip_shell_{version}.dll")
}

/// The Windows 11 menu's package, staged: the manifest's folder, and the signed `.msix`.
struct Package<'a> {
    sparse: &'a Path,
    msix: Option<&'a Path>,
}

fn config(
    root: &Path,
    cli: &Path,
    dll: &Path,
    version: &str,
    package: &Package,
) -> anyhow::Result<Value> {
    let template = root.join("packaging/windows/tauri.dist.json");
    let mut config: Value = serde_json::from_str(
        &std::fs::read_to_string(&template)
            .with_context(|| format!("reading {}", template.display()))?,
    )?;
    let bundle = config
        .get_mut("bundle")
        .context("the template has no `bundle`")?;
    let mut resources = serde_json::Map::new();
    resources.insert(slashes(cli), json!("bin/beezip.exe"));
    resources.insert(slashes(dll), json!(dll_name(version)));
    resources.insert(
        slashes(&root.join("THIRD_PARTY_NOTICES.md")),
        json!("THIRD_PARTY_NOTICES.md"),
    );
    for entry in std::fs::read_dir(package.sparse)? {
        let path = entry?.path();
        let name = path.file_name().context("a staged file without a name")?;
        resources.insert(
            slashes(&path),
            json!(format!("{SPARSE}/{}", name.to_string_lossy())),
        );
    }
    if let Some(msix) = package.msix {
        resources.insert(slashes(msix), json!(MSIX));
    }
    bundle["resources"] = Value::Object(resources);
    let associations = associations()?;
    let hooks = hooks(root, &associations, version)?;
    bundle["fileAssociations"] = Value::Array(associations);
    bundle["windows"]["nsis"]["installerHooks"] = json!(slashes(&hooks));
    config["version"] = json!(version);
    Ok(config)
}

/// `target/dist/hooks.nsh`: the DLL's name, `packaging/windows/hooks.nsh`, and the list of
/// associations its hooks walk.
fn hooks(root: &Path, associations: &[Value], version: &str) -> anyhow::Result<PathBuf> {
    let template = root.join("packaging/windows/hooks.nsh");
    let mut text = format!(
        "; Generated by `cargo xtask dist`: the Explorer menu's DLL in this version.\n\
         !define BEEZIP_SHELL_DLL \"{}\"\n\n",
        dll_name(version)
    );
    text.push_str(
        &std::fs::read_to_string(&template)
            .with_context(|| format!("reading {}", template.display()))?,
    );
    text.push_str("\n; Generated by `cargo xtask dist` from formats.list.\n");
    text.push_str("!macro BEEZIP_FOR_EACH_ASSOCIATION MACRO\n");
    for a in associations {
        let ext = a["ext"][0]
            .as_str()
            .context("an association without an extension")?;
        let class = a["name"]
            .as_str()
            .context("an association without a name")?;
        text.push_str(&format!(
            "  !insertmacro ${{MACRO}} \"{ext}\" \"{class}\"\n"
        ));
    }
    text.push_str("!macroend\n");
    let path = root.join("target/dist/hooks.nsh");
    std::fs::create_dir_all(root.join("target/dist"))?;
    std::fs::write(&path, text)?;
    Ok(path)
}

/// One association per extension, `BeeZip.<ext>`, from `formats.list`: every archive and
/// compressed-file extension BeeZip reads, but not the document formats, later parts, or what
/// Windows opens itself, plus `.001` for numbered volume sets.
pub fn associations() -> anyhow::Result<Vec<Value>> {
    let formats = Engine::new(registry())
        .invoke(
            "formats.list",
            json!({}),
            Arc::new(NonInteractive),
            discard_events(),
        )
        .map_err(|e| anyhow::anyhow!("formats.list: {}", e.message))?
        .join()
        .map_err(|e| anyhow::anyhow!("formats.list: {}", e.message))?;
    let mut by_ext: BTreeMap<String, String> = BTreeMap::new();
    let mut add = |list: &Value, what: String| {
        for e in list
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let ext = e.trim_start_matches('.').to_ascii_lowercase();
            if ext.is_empty()
                || DOCUMENTS.contains(&ext.as_str())
                || LATER_PARTS.contains(&ext.as_str())
                || WINDOWS_OWNS.contains(&ext.as_str())
            {
                continue;
            }
            by_ext.entry(ext).or_insert_with(|| what.clone());
        }
    };
    for f in formats["formats"].as_array().into_iter().flatten() {
        if f["caps"]["list"] == true {
            // "ZIP archive", but "Apple disk image" and "Debian package" as they are.
            let name = f["name"].as_str().unwrap_or("");
            let what = if name.ends_with(" image") || name.ends_with(" package") {
                name.to_owned()
            } else {
                format!("{name} archive")
            };
            add(&f["extensions"], what);
        }
    }
    for c in formats["codecs"].as_array().into_iter().flatten() {
        add(
            &c["extensions"],
            format!("{} compressed file", c["name"].as_str().unwrap_or("")),
        );
    }
    by_ext.insert("001".into(), "Split archive, first part".into());
    Ok(by_ext
        .into_iter()
        .map(|(ext, description)| {
            json!({
                "ext": [ext],
                "name": format!("BeeZip.{ext}"),
                "description": description,
                "role": "Editor",
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn associations_cover_the_archives_but_not_documents() {
        let list = associations().unwrap();
        let exts: Vec<&str> = list.iter().map(|a| a["ext"][0].as_str().unwrap()).collect();
        for want in [
            "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "tzst",
            "lz", "tlz", "lzma", "lz4", "br", "sz", "cbz", "cb7", "cbr", "001", "cpio", "ar",
            "deb", "udeb", "rpm", "lzh", "lha", "z", "taz", "lzo", "tzo",
        ] {
            assert!(exts.contains(&want), "{want} is missing from {exts:?}");
        }
        for not in ["docx", "jar", "epub", "r00", "cab", "iso", "a", "lib"] {
            assert!(!exts.contains(&not), "{not} shouldn't be associated");
        }
        assert_eq!(list[0]["name"], format!("BeeZip.{}", exts[0]));
    }
}
