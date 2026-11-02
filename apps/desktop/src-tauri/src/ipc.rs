//! The app's only four Tauri commands (PLAN §1, Desktop). Every BeeZip command goes through
//! `cmd_run`, so adding a command never touches this file.

use std::sync::Arc;

use beezip_commands::{
    CmdError, CommandInfo, Engine, EventSink, JobEvent, JobId, NonInteractive, PromptReply,
};
use serde_json::Value;
use tauri::{State, ipc::Channel};

/// Starts command `name` and streams its events to `on_event`. Returns the job id at once.
#[tauri::command]
pub fn cmd_run(
    engine: State<'_, Engine>,
    name: String,
    args: Value,
    on_event: Channel<JobEvent>,
) -> Result<JobId, CmdError> {
    // A send fails only if the webview has gone away, and then nobody is listening.
    let sink: EventSink = Arc::new(move |event| {
        let _ = on_event.send(event);
    });
    // Prompts get answered through cmd_respond from M3; until then they fail with a hint.
    let job = engine.invoke(&name, args, Arc::new(NonInteractive), sink)?;
    Ok(job.id())
}

/// Requests cancellation of a running job. `false` if it already ended.
#[tauri::command]
pub fn cmd_cancel(engine: State<'_, Engine>, job: JobId) -> bool {
    engine.cancel(job)
}

/// Answers a job's `Prompt` event. No command prompts yet, so there is never a pending prompt.
#[tauri::command]
pub fn cmd_respond(job: JobId, prompt: u64, reply: PromptReply) -> Result<(), CmdError> {
    let _ = reply;
    Err(CmdError::not_found(format!(
        "job {job} has no pending prompt {prompt}"
    )))
}

/// The commands the desktop app can run.
#[tauri::command]
pub fn cmd_list(engine: State<'_, Engine>) -> Vec<CommandInfo> {
    engine
        .registry()
        .entries()
        .iter()
        .filter(|e| e.surfaces.gui)
        .map(|e| e.info())
        .collect()
}
