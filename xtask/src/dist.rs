//! `cargo xtask dist [--debug]`: the Windows installer (docs/M3.md §5.5).
//!
//! 1. The CLI is built into its own target dir, `target/dist-cli`, so the GUI's rename to
//!    `BeeZip.exe` can't clobber `beezip.exe` on a case-insensitive file system.
//! 2. `target/dist/tauri.dist.json` is written from `packaging/windows/tauri.dist.json`, with the
//!    staged resources, the NSIS hooks and the file associations, which come from `formats.list`
//!    so the list has one source. It stays out of `tauri.conf.json` because tauri-build copies
//!    resources when the app compiles and fails on a missing one.
//! 3. `pnpm tauri build --bundles nsis --config target/dist/tauri.dist.json` builds the installer,
//!    with `CARGO_TARGET_DIR=target/dist`: the rename to `BeeZip.exe` in `target/debug` would
//!    replace the development `beezip.exe`, which Windows sees as the same file.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use anyhow::{Context, bail};
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

pub fn run(debug: bool) -> anyhow::Result<()> {
    let root = workspace_root();
    let profile = if debug { "debug" } else { "release" };

    println!("building the CLI ({profile})");
    let mut cargo = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cargo
        .current_dir(&root)
        .args(["build", "--locked", "-p", "beezip-cli", "--target-dir"])
        .arg(root.join("target/dist-cli"));
    if !debug {
        cargo.arg("--release");
    }
    check(cargo.status(), "cargo build -p beezip-cli")?;
    let exe = format!("beezip{}", std::env::consts::EXE_SUFFIX);
    let cli = root.join("target/dist-cli").join(profile).join(&exe);
    if !cli.is_file() {
        bail!("{} wasn't built", cli.display());
    }

    let config = config(&root, &cli)?;
    let dir = root.join("target/dist");
    std::fs::create_dir_all(&dir)?;
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

fn config(root: &Path, cli: &Path) -> anyhow::Result<Value> {
    let template = root.join("packaging/windows/tauri.dist.json");
    let mut config: Value = serde_json::from_str(
        &std::fs::read_to_string(&template)
            .with_context(|| format!("reading {}", template.display()))?,
    )?;
    let bundle = config
        .get_mut("bundle")
        .context("the template has no `bundle`")?;
    bundle["resources"] = json!({
        slashes(cli): "bin/beezip.exe",
        slashes(&root.join("THIRD_PARTY_NOTICES.md")): "THIRD_PARTY_NOTICES.md",
    });
    bundle["fileAssociations"] = Value::Array(associations()?);
    bundle["windows"]["nsis"]["installerHooks"] =
        json!(slashes(&root.join("packaging/windows/hooks.nsh")));
    Ok(config)
}

/// One association per extension, `BeeZip.<ext>`, from `formats.list`: every archive and
/// compressed-file extension BeeZip reads, but not the document formats or later parts, plus
/// `.001` for numbered volume sets.
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
            {
                continue;
            }
            by_ext.entry(ext).or_insert_with(|| what.clone());
        }
    };
    for f in formats["formats"].as_array().into_iter().flatten() {
        if f["caps"]["list"] == true {
            add(
                &f["extensions"],
                format!("{} archive", f["name"].as_str().unwrap_or("")),
            );
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
            "lz", "tlz", "lzma", "lz4", "br", "sz", "cbz", "cb7", "cbr", "001",
        ] {
            assert!(exts.contains(&want), "{want} is missing from {exts:?}");
        }
        for not in ["docx", "jar", "epub", "r00"] {
            assert!(!exts.contains(&not), "{not} shouldn't be associated");
        }
        assert_eq!(list[0]["name"], format!("BeeZip.{}", exts[0]));
    }
}
