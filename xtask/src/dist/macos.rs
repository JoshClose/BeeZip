//! `cargo xtask dist` on macOS (docs/M6.md §9.7): the app and its disk image, arm64.
//!
//! 1. The CLI is built into `target/dist-cli` and goes in the app at `Contents/MacOS/bin/beezip`:
//!    APFS ignores case, so `MacOS/beezip` would be the app's own `MacOS/BeeZip`. `open.rs`'s
//!    `cli_program` finds it there for "Copy as CLI".
//! 2. Tauri signs only the app's main binary, so the CLI is signed first, with the identity in
//!    `APPLE_SIGNING_IDENTITY` (a Developer ID, hardened runtime and a timestamp) or ad hoc (`-`)
//!    without one; Tauri then signs the app the same way (`signingIdentity`, which that variable
//!    overrides). An ad-hoc app downloaded on macOS 15 or later opens only after System Settings ›
//!    Privacy & Security › Open Anyway.
//! 3. `target/dist/tauri.dist.json` is written from `packaging/macos/tauri.dist.json`, with the
//!    CLI, the notices and the file associations, each naming its content type where macOS
//!    declares one ([`UTI`]).
//! 4. `pnpm tauri build --bundles app,dmg`, then `codesign --verify --deep --strict` of the app.
//! 5. With `TAURI_SIGNING_PRIVATE_KEY`, Tauri also makes `BeeZip.app.tar.gz` and its `.sig`, the
//!    updater's bundle; they're copied to versioned names for the release, and `latest.json` is
//!    written beside them (`darwin-aarch64-app`, the key the updater looks for first).

use std::{path::Path, process::Command};

use anyhow::{Context, bail};
use serde_json::{Value, json};

use super::{
    Os, Updatable, associations, build_cli, check, pnpm, profile, sig, slashes, template, updater,
    write_latest_json, write_overlay,
};

/// Extensions macOS opens itself: disk images, and installer packages.
pub const SYSTEM_OWNS: &[&str] = &["dmg", "iso", "pkg", "mpkg"];

/// The content types (UTIs) macOS declares for associated extensions, as macOS 26.7 on CI's
/// runner reported them (`UTType(filenameExtension:)`, docs/M6.md §16). The others have only
/// dynamic types, so their associations name the extension alone.
const UTI: &[(&str, &str)] = &[
    ("7z", "org.7-zip.7-zip-archive"),
    ("bz2", "public.bzip2-archive"),
    ("cab", "com.microsoft.cab"),
    ("cpio", "public.cpio-archive"),
    ("gz", "org.gnu.gnu-zip-archive"),
    ("tar", "public.tar-archive"),
    ("tbz", "public.tar-bzip2-archive"),
    ("tbz2", "public.tar-bzip2-archive"),
    ("tgz", "org.gnu.gnu-zip-tar-archive"),
    ("txz", "org.tukaani.tar-xz-archive"),
    ("xar", "com.apple.xar-archive"),
    ("xz", "org.tukaani.xz-archive"),
    ("z", "public.z-archive"),
    ("zip", "public.zip-archive"),
];

/// `ext`'s content type, if macOS declares one.
pub fn content_type(ext: &str) -> Option<&'static str> {
    UTI.iter().find(|(e, _)| *e == ext).map(|(_, u)| *u)
}

/// Where the CLI goes, under `Contents/`.
const CLI_IN_APP: &str = "MacOS/bin/beezip";

/// The identity everything is signed with: `APPLE_SIGNING_IDENTITY`, or ad hoc.
fn identity(env: &dyn Fn(&str) -> Option<String>) -> String {
    env("APPLE_SIGNING_IDENTITY")
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "-".into())
}

/// `codesign`'s arguments for `identity`: a Developer ID gets the hardened runtime and a
/// timestamp, which notarization requires; an ad-hoc signature can have neither timestamp.
fn codesign_args(identity: &str) -> Vec<String> {
    let mut args = vec![
        "--force".into(),
        "--sign".into(),
        identity.into(),
        "--identifier".into(),
        "app.beezip.cli".into(),
    ];
    if identity == "-" {
        args.push("--timestamp=none".into());
    } else {
        args.extend(["--options".into(), "runtime".into(), "--timestamp".into()]);
    }
    args
}

/// The overlay for Tauri: the template, the version, the CLI, the notices, the associations and
/// the updater's part.
fn config(
    root: &Path,
    cli: &Path,
    version: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<Value> {
    let mut config = template(root, "macos")?;
    config["version"] = json!(version);
    let bundle = config
        .get_mut("bundle")
        .context("the template has no `bundle`")?;
    bundle["macOS"]["files"] = json!({ CLI_IN_APP: slashes(cli) });
    bundle["resources"] = json!({
        slashes(&root.join("THIRD_PARTY_NOTICES.md")): "THIRD_PARTY_NOTICES.md"
    });
    bundle["fileAssociations"] = Value::Array(associations(Os::Mac)?);
    updater(root, &mut config, env)?;
    Ok(config)
}

pub fn run(root: &Path, debug: bool, version: &str) -> anyhow::Result<()> {
    let env = |name: &str| std::env::var(name).ok();
    let profile = profile(debug);
    let identity = identity(&env);
    if identity == "-" {
        println!("signing ad hoc (no APPLE_SIGNING_IDENTITY)");
    } else {
        println!("signing as {identity}");
    }

    println!("building the CLI ({profile})");
    let cli = build_cli(root, debug, &["beezip-cli"])?.join("beezip");
    if !cli.is_file() {
        bail!("{} wasn't built", cli.display());
    }
    check(
        Command::new("codesign")
            .args(codesign_args(&identity))
            .arg(&cli)
            .status(),
        "codesign of the CLI",
    )?;

    let dir = root.join("target/dist");
    std::fs::create_dir_all(&dir)?;
    let config_path = dir.join("tauri.dist.json");
    write_overlay(&config(root, &cli, version, &env)?, &config_path)?;

    let bundle = dir.join(profile).join("bundle");
    let app = bundle.join("macos/BeeZip.app");
    let updatable = bundle.join(format!("macos/BeeZip_{version}_aarch64.app.tar.gz"));
    // What an earlier build left would describe another build.
    for stale in [
        app.clone(),
        updatable.clone(),
        sig(&updatable),
        bundle.join("macos").join(super::LATEST_JSON),
    ] {
        if stale.is_dir() {
            std::fs::remove_dir_all(&stale)?;
        } else if stale.exists() {
            std::fs::remove_file(&stale)?;
        }
    }

    println!("building the app and its disk image ({profile})");
    let mut tauri = pnpm();
    tauri
        .current_dir(root.join("apps/desktop"))
        .env("CARGO_TARGET_DIR", &dir)
        .args(["tauri", "build", "--bundles", "app,dmg", "--config"])
        .arg(&config_path);
    if debug {
        tauri.arg("--debug");
    }
    check(tauri.status(), "pnpm tauri build")?;

    if !app.join("Contents").join(CLI_IN_APP).is_file() {
        bail!("{} has no {CLI_IN_APP}", app.display());
    }
    check(
        Command::new("codesign")
            .args(["--verify", "--deep", "--strict", "--verbose=2"])
            .arg(&app)
            .status(),
        "codesign --verify of the app",
    )?;
    let dmg = bundle
        .join("dmg")
        .join(format!("BeeZip_{version}_aarch64.dmg"));
    if !dmg.is_file() {
        bail!("no disk image at {}", dmg.display());
    }
    println!("app: {}", app.display());
    println!("disk image: {}", dmg.display());

    // The updater's bundle, under a name of its own in the release.
    let made = bundle.join("macos/BeeZip.app.tar.gz");
    if sig(&made).is_file() {
        std::fs::copy(&made, &updatable)?;
        std::fs::copy(sig(&made), sig(&updatable))?;
        write_latest_json(
            version,
            &[Updatable {
                key: "darwin-aarch64-app",
                file: &updatable,
            }],
            &bundle.join("macos"),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn ad_hoc_unless_an_identity_is_named() {
        let none = |_: &str| None;
        assert_eq!(identity(&none), "-");
        let blank = |_: &str| Some("  ".to_owned());
        assert_eq!(identity(&blank), "-");
        let named = |_: &str| Some("Developer ID Application: X (TEAM)".to_owned());
        assert_eq!(identity(&named), "Developer ID Application: X (TEAM)");
        assert_eq!(
            codesign_args("-"),
            [
                "--force",
                "--sign",
                "-",
                "--identifier",
                "app.beezip.cli",
                "--timestamp=none"
            ]
        );
        assert_eq!(
            codesign_args("Developer ID Application: X (TEAM)")[5..],
            ["--options", "runtime", "--timestamp"]
        );
    }

    #[test]
    fn the_overlay_has_the_cli_the_notices_and_the_associations() {
        let root = crate::codegen::workspace_root();
        let env = |_: &str| None;
        let cli = Path::new("/x/target/dist-cli/release/beezip");
        let c = config(&root, cli, "1.2.3", &env).unwrap();
        assert_eq!(c["version"], "1.2.3");
        assert_eq!(c["mainBinaryName"], "BeeZip");
        assert_eq!(c["bundle"]["macOS"]["signingIdentity"], "-");
        assert_eq!(
            c["bundle"]["macOS"]["files"][CLI_IN_APP],
            "/x/target/dist-cli/release/beezip"
        );
        let resources = c["bundle"]["resources"].as_object().unwrap();
        assert_eq!(resources.len(), 1);
        assert!(resources.values().all(|v| v == "THIRD_PARTY_NOTICES.md"));
        let list = c["bundle"]["fileAssociations"].as_array().unwrap();
        let exts: Vec<&str> = list.iter().map(|a| a["ext"][0].as_str().unwrap()).collect();
        for want in [
            "zip", "7z", "rar", "tar", "gz", "xz", "zst", "cab", "xar", "001",
        ] {
            assert!(exts.contains(&want), "{want} is missing");
        }
        for not in SYSTEM_OWNS {
            assert!(!exts.contains(not), "{not} is macOS's");
        }
        // A name macOS can show, not a Windows class name.
        let zip = list.iter().find(|a| a["ext"][0] == "zip").unwrap();
        assert_eq!(zip["name"], "ZIP archive");
        assert_eq!(super::super::null_at(&c, ""), None);
    }

    #[test]
    fn every_content_type_is_for_an_associated_extension() {
        let exts: Vec<String> = associations(Os::Mac)
            .unwrap()
            .iter()
            .map(|a| a["ext"][0].as_str().unwrap().to_owned())
            .collect();
        for (ext, uti) in UTI {
            assert!(
                exts.iter().any(|e| e == ext),
                "{ext} ({uti}) isn't associated"
            );
        }
    }
}
