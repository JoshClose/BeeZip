//! The BeeZip desktop app: a Tauri shell over the shared command engine.

mod ipc;

use beezip_commands::{Engine, EngineOptions, Policy, config, registry};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // The config is read once at startup (docs/M1.md §4.1). Unknown keys only warn; the UI shows
    // warnings in M3.
    let loaded = config::load();
    let options = EngineOptions::from_config(loaded.config, Policy::unrestricted());
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Engine::with_options(registry(), options))
        .invoke_handler(tauri::generate_handler![
            ipc::cmd_run,
            ipc::cmd_cancel,
            ipc::cmd_respond,
            ipc::cmd_list
        ])
        .run(tauri::generate_context!())
        .expect("error while running the BeeZip app");
}
