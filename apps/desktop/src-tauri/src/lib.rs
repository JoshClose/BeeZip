//! The BeeZip desktop app: a Tauri shell over the shared command engine.

mod ipc;
mod job;
mod open;
mod opened;
mod prompts;
mod update;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use beezip_commands::{Engine, EngineOptions, Policy, Theme, config, registry};
use tauri::{Emitter, Listener, Manager, RunEvent, WindowEvent};

use crate::{
    open::{MAIN, Pending, Warnings},
    opened::{ENTRY_CHANGED, Forget, OPENED_FORGET, Opened},
    prompts::GuiInteractor,
};

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
    let options = EngineOptions {
        // The settings page's Install: a click on the menu starts this app.
        shell_app: std::env::current_exe().ok(),
        ..EngineOptions::from_loaded(loaded, Policy::unrestricted())
    };
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
        // Updates (docs/M6.md §9.4), driven from Rust only: the page has no updater permission.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(engine)
        .manage(gui)
        .manage(Warnings(Mutex::new(warnings)))
        .manage(Arc::new(Opened::default()))
        .manage(Pending::default())
        .manage(update::Updates::default())
        // Back from an editor: entries opened from the tabs that changed (docs/M5.md §8.3).
        .on_window_event(|window, event| {
            if window.label() == MAIN && matches!(event, WindowEvent::Focused(true)) {
                let app = window.app_handle();
                for changed in app.state::<Arc<Opened>>().changed() {
                    let _ = app.emit_to(MAIN, ENTRY_CHANGED, changed);
                }
            }
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            app.listen_any(OPENED_FORGET, move |event| {
                if let Ok(forget) = serde_json::from_str::<Forget>(event.payload()) {
                    handle.state::<Arc<Opened>>().forget(&forget.paths);
                }
            });
            // App-wide, before any window exists, so each opens in the right theme and later
            // windows and changes follow it (docs/M4.md §7.5). On this, the main thread, the
            // call takes effect at once.
            app.handle().set_theme(tauri_theme(theme));
            // Requests nobody read: BeeZip wasn't running, or couldn't start (§3.3).
            std::thread::spawn(|| {
                job::sweep(&job::jobs_dir(), SystemTime::now(), job::MAX_REQUEST_AGE)
            });
            let args: Vec<String> = std::env::args().collect();
            let cwd = std::env::current_dir().unwrap_or_default();
            let launch = open::parse_args(&args, Path::new(&cwd));
            open::show(app.handle(), open::plan(app.handle(), launch))?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::cmd_run,
            ipc::cmd_cancel,
            ipc::cmd_respond,
            ipc::cmd_list,
            ipc::cmd_launched,
            update::cmd_update_check,
            update::cmd_update_install
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

/// Cancels whatever still runs and waits, up to [`EXIT_WAIT`], for it to clean up. Quitting
/// does this, and so does the updater just before it starts the installer.
pub(crate) fn cancel_and_wait(app: &tauri::AppHandle) {
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
