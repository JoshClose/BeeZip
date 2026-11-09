fn main() {
    // Declaring the app's commands makes tauri-build generate `allow-cmd-*` permissions, which
    // capabilities/default.json grants to the main window.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "cmd_run",
            "cmd_cancel",
            "cmd_respond",
            "cmd_list",
            "cmd_launched",
            "cmd_drag_out",
            "cmd_update_check",
            "cmd_update_install",
        ]),
    ))
    .expect("failed to run tauri-build");

    // Integration tests build Tauri's mock runtime, which imports from Common Controls 6 and so
    // doesn't load without the manifest asking for it (STATUS_ENTRYPOINT_NOT_FOUND). tauri-build
    // gives it to the app only; the test binaries get the same one here.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("common-controls.manifest");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-tests=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
}
