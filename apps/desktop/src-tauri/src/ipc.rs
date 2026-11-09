//! The app's Tauri commands (PLAN §1, Desktop). Every BeeZip command goes through `cmd_run`, so
//! adding a command never touches this file; the others cancel, answer prompts, list commands,
//! and hand the main window the launches that arrived before it listened. The updater's two
//! are in update.rs.

use std::sync::Arc;

use beezip_commands::{
    CmdError, CommandInfo, Engine, EventSink, JobEvent, JobId, JsonObject, PromptReply,
};
use serde::Serialize;
use serde_json::Value;
use tauri::{State, Window, ipc::Channel};

use crate::{
    open::{MAIN, Pending, Queued},
    opened::Opened,
    prompts::GuiInteractor,
};

/// Starts command `name` and streams its events to `on_event`. Returns the job id at once.
#[tauri::command]
pub fn cmd_run(
    window: Window,
    engine: State<'_, Engine>,
    gui: State<'_, Arc<GuiInteractor>>,
    opened: State<'_, Arc<Opened>>,
    name: String,
    args: Value,
    on_event: Channel<JobEvent>,
) -> Result<JobId, CmdError> {
    // A send fails only if the webview has gone away, and then nobody is listening.
    let mut sink: EventSink = Arc::new(move |event| {
        let _ = on_event.send(event);
    });
    // The main window asks whether to update an archive whose opened entry changed.
    if name == "entry.open" && window.label() == MAIN {
        sink = opened.watch(&args, sink);
    }
    let interactor: Arc<GuiInteractor> = Arc::clone(&gui);
    let job = engine.invoke(&name, args, interactor, sink)?;
    Ok(job.id())
}

/// Requests cancellation of a running job, and answers its pending prompt with `Cancel`.
/// `false` if it already ended.
#[tauri::command]
pub fn cmd_cancel(
    engine: State<'_, Engine>,
    gui: State<'_, Arc<GuiInteractor>>,
    job: JobId,
) -> bool {
    let running = engine.cancel(job);
    gui.cancel_job(job);
    running
}

/// Answers a job's `Prompt` event. An unknown or already answered prompt is `NotFound`.
#[tauri::command]
pub fn cmd_respond(
    gui: State<'_, Arc<GuiInteractor>>,
    job: JobId,
    prompt: u64,
    reply: PromptReply,
) -> Result<(), CmdError> {
    gui.respond(job, prompt, reply)
}

/// The main window's page listens for `open-paths` and `open-dialog` now: the launches that
/// arrived before, and events from here on (docs/M6.md §8.1). Other windows get nothing.
#[tauri::command]
pub fn cmd_launched(window: Window, pending: State<'_, Pending>) -> Queued {
    if window.label() == MAIN {
        let queued = pending.drain();
        crate::open::trace(|| format!("the page took {:?}", queued.paths));
        queued
    } else {
        Queued::default()
    }
}

/// A command the page may run, with the input schema the palette builds its form from.
#[derive(Debug, Serialize)]
pub struct GuiCommand {
    #[serde(flatten)]
    pub info: CommandInfo,
    pub input_schema: JsonObject,
}

/// The commands the desktop app can run.
#[tauri::command]
pub fn cmd_list(engine: State<'_, Engine>) -> Vec<GuiCommand> {
    gui_commands(&engine)
}

pub fn gui_commands(engine: &Engine) -> Vec<GuiCommand> {
    engine
        .registry()
        .entries()
        .iter()
        .filter(|e| e.surfaces.gui && offered_here(e.name, cfg!(windows)))
        .map(|e| GuiCommand {
            info: e.info(),
            input_schema: (*e.input_schema).clone(),
        })
        .collect()
}

/// Explorer's menu is only on Windows, so elsewhere the palette leaves out `shell.*`, which
/// would only fail there (docs/M6.md §8.3).
fn offered_here(name: &str, windows: bool) -> bool {
    windows || !name.starts_with("shell.")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use beezip_commands::registry;

    use super::*;

    #[test]
    fn commands_come_with_their_schemas() {
        let list = gui_commands(&Engine::new(registry()));
        let line = list.iter().find(|c| c.info.name == "cli.line").unwrap();
        assert!(line.input_schema["properties"]["command"].is_object());
        let json = serde_json::to_value(&list[0]).unwrap();
        assert!(json["name"].is_string() && json["input_schema"].is_object());
        let shell = list.iter().any(|c| c.info.name.starts_with("shell."));
        assert_eq!(shell, cfg!(windows), "shell.* only on Windows");
    }

    #[test]
    fn explorers_commands_are_offered_on_windows_only() {
        assert!(offered_here("shell.status", true));
        assert!(!offered_here("shell.status", false));
        assert!(!offered_here("shell.install", false));
        assert!(offered_here("archive.list", false));
        assert!(offered_here("settings.get", false));
    }
}
