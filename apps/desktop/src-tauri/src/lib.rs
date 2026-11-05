//! The BeeZip desktop app: a Tauri shell over the shared command engine.

mod ipc;
mod open;
mod prompts;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use beezip_commands::{Engine, EngineOptions, Policy, Theme, config, registry};
use tauri::{Manager, RunEvent};

use crate::prompts::GuiInteractor;

/// How long quitting waits for cancelled jobs to remove their partial files, as `beezip mcp`
/// does on disconnect.
const EXIT_WAIT: Duration = Duration::from_secs(10);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // The config is read at startup (docs/M1.md §4.1), and replaced by `settings.set`
    // (docs/M4.md §7.3); its warnings go to the page.
    let loaded = config::load();
    let warnings = loaded.warnings.clone();
    let theme = loaded
        .config
        .as_ref()
        .map(|c| c.desktop.theme)
        .unwrap_or_default();
    let options = EngineOptions::from_loaded(loaded, Policy::unrestricted());
    let engine = Engine::with_options(registry(), options);
    let gui = Arc::new(GuiInteractor::new({
        let engine = engine.clone();
        move |job| engine.is_cancelled(job)
    }));
    let app = tauri::Builder::default()
        // First, as the plugin requires: a second BeeZip.exe hands its arguments to this one
        // and exits before it builds anything.
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            open::forward(app, &args, &cwd);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(engine)
        .manage(gui)
        .setup(move |app| {
            // App-wide, before the window exists, so it opens in the right theme and later
            // windows and changes follow it (docs/M4.md §7.5). On this, the main thread, the
            // call takes effect at once.
            app.handle().set_theme(tauri_theme(theme));
            open::create_main_window(app, warnings.clone(), theme)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::cmd_run,
            ipc::cmd_cancel,
            ipc::cmd_respond,
            ipc::cmd_list
        ])
        .build(tauri::generate_context!())
        .expect("error while building the BeeZip app");
    app.run(|app, event| {
        if let RunEvent::Exit = event {
            cancel_and_wait(app);
        }
    });
}

/// `[desktop] theme` as Tauri takes it: `None` follows Windows.
fn tauri_theme(theme: Theme) -> Option<tauri::Theme> {
    match theme {
        Theme::System => None,
        Theme::Light => Some(tauri::Theme::Light),
        Theme::Dark => Some(tauri::Theme::Dark),
    }
}

/// Cancels whatever still runs and waits, up to [`EXIT_WAIT`], for it to clean up.
fn cancel_and_wait(app: &tauri::AppHandle) {
    let engine = app.state::<Engine>();
    let gui = app.state::<Arc<GuiInteractor>>();
    for job in engine.jobs() {
        engine.cancel(job.id);
        gui.cancel_job(job.id);
    }
    let start = Instant::now();
    while !engine.jobs().is_empty() && start.elapsed() < EXIT_WAIT {
        std::thread::sleep(Duration::from_millis(50));
    }
}
