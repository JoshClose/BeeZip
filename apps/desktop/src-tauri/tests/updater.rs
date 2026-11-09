//! The updater's signature check (docs/M6.md §9.4, §10), through tauri-plugin-updater itself on
//! BeeZip's own updater config: only the bytes signed, for the version signed, install, and an
//! older version isn't offered. An integration test, so that only test binaries get the Common
//! Controls manifest Tauri's mock runtime needs on Windows (build.rs).
#![allow(clippy::unwrap_used)]

use tauri_plugin_updater::UpdaterExt;

/// A throwaway key's public half and a signature it made, bound to version 0.1.1, of
/// `PAYLOAD` (`pnpm tauri signer sign --app-version 0.1.1`). The private half was discarded.
const THROWAWAY_PUBKEY: &str = include_str!("updater/throwaway.key.pub");
const SIGNATURE_0_1_1: &str = include_str!("updater/payload-0.1.1.sig");
const PAYLOAD: &[u8] = b"BeeZip update test payload\n";

/// An app on BeeZip's own updater config (tauri.conf.json), with the throwaway key, at
/// version 0.1.0.
fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let mut updater = conf["plugins"]["updater"].clone();
    assert_eq!(
        updater["requireSignedVersion"], true,
        "a signature must carry its version"
    );
    updater["pubkey"] = THROWAWAY_PUBKEY.trim().into();
    let mut context = tauri::test::mock_context(tauri::test::noop_assets());
    context
        .config_mut()
        .plugins
        .0
        .insert("updater".into(), updater);
    tauri::test::mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(context)
        .unwrap()
}

/// A release manifest as latest.json carries it.
fn release(version: &str, signature: &str) -> serde_json::Value {
    let platform = serde_json::json!({
        "signature": signature,
        "url": "https://github.com/JoshClose/BeeZip/releases/download/v0.1.1/BeeZip_0.1.1_x64-setup.exe",
    });
    serde_json::json!({
        "version": version,
        "platforms": {
            "windows-x86_64-nsis": platform,
            "windows-x86_64": platform,
            "linux-x86_64": platform,
            "darwin-aarch64": platform,
        }
    })
}

#[test]
fn only_the_signed_bytes_of_the_signed_version_install() {
    let app = mock_app();
    let updater = app.updater_builder().build().unwrap();

    let update = updater
        .restore_update(release("0.1.1", SIGNATURE_0_1_1))
        .unwrap()
        .expect("0.1.1 is newer than 0.1.0");
    update.verify(PAYLOAD).unwrap();

    // One byte changed.
    let mut tampered = PAYLOAD.to_vec();
    tampered[0] ^= 1;
    assert!(update.verify(&tampered).is_err());

    // 0.1.1's installer offered as 0.1.2: its signature carries 0.1.1.
    let inflated = updater
        .restore_update(release("0.1.2", SIGNATURE_0_1_1))
        .unwrap()
        .unwrap();
    assert!(inflated.verify(PAYLOAD).is_err());

    // Another key's signature.
    let other = SIGNATURE_0_1_1.replace('A', "B");
    let forged = updater
        .restore_update(release("0.1.1", &other))
        .unwrap()
        .unwrap();
    assert!(forged.verify(PAYLOAD).is_err());

    // Not newer: nothing is offered.
    assert!(
        updater
            .restore_update(release("0.0.9", SIGNATURE_0_1_1))
            .unwrap()
            .is_none()
    );
    assert!(
        updater
            .restore_update(release("0.1.0", SIGNATURE_0_1_1))
            .unwrap()
            .is_none()
    );
}

/// A portable copy (update.rs `PORTABLE`) finds the zip's entry, and only that: a manifest
/// without one offers it nothing, rather than the installer.
#[test]
fn a_portable_copy_finds_the_zip() {
    let app = mock_app();
    let updater = app
        .updater_builder()
        .target("windows-x86_64-portable")
        .build()
        .unwrap();
    let zip = "https://github.com/JoshClose/BeeZip/releases/download/v0.1.1/BeeZip_0.1.1_x64-portable.zip";
    let mut manifest = release("0.1.1", SIGNATURE_0_1_1);
    manifest["platforms"]["windows-x86_64-portable"] =
        serde_json::json!({ "signature": SIGNATURE_0_1_1, "url": zip });
    let update = updater.restore_update(manifest).unwrap().unwrap();
    assert_eq!(update.download_url.as_str(), zip);

    assert!(
        updater
            .restore_update(release("0.1.1", SIGNATURE_0_1_1))
            .is_err(),
        "no zip in the release"
    );
}
