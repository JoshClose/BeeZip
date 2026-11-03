//! The BeeZip desktop app: a Tauri shell over the shared command engine.

mod ipc;

use beezip_commands::{Engine, registry};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Engine::new(registry()))
        .invoke_handler(tauri::generate_handler![
            ipc::cmd_run,
            ipc::cmd_cancel,
            ipc::cmd_respond,
            ipc::cmd_list
        ])
        .run(tauri::generate_context!())
        .expect("error while running the BeeZip app");
}
