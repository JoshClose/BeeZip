fn main() {
    // Declaring the app's commands makes tauri-build generate `allow-cmd-*` permissions, which
    // capabilities/default.json grants to the main window.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "cmd_run",
            "cmd_cancel",
            "cmd_respond",
            "cmd_list",
        ]),
    ))
    .expect("failed to run tauri-build");
}
