//! The app's Tauri commands (PLAN §1, Desktop). Every BeeZip command goes through `cmd_run`, so
//! adding a command never touches this file; the others cancel, answer prompts, list commands,
//! lock an archive again when its tab closes, and hand the main window the launches that
//! arrived before it listened. The updater's two are in update.rs, and the page's "I have
//! rendered" in reveal.rs.

use std::{path::PathBuf, sync::Arc};

use beezip_commands::{
    CmdError, CommandInfo, Engine, EventSink, JobEvent, JobId, JsonObject, KeptUnlocks, Policy,
    PromptReply,
};
use serde::Serialize;
use serde_json::Value;
use tauri::{State, Window, ipc::Channel};

use crate::{
    open::{MAIN, Pending, Queued},
    opened::Opened,
    prompts::GuiInteractor,
};

/// The HWND of `window`, as [`Policy::window`] takes it; `None` off Windows.
pub fn hwnd(window: &Window) -> Option<isize> {
    #[cfg(windows)]
    {
        window.hwnd().ok().map(|h| h.0 as isize)
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        None
    }
}

/// What a job started from `window` runs under: the engine's policy, with Windows' PIN and
/// security-key dialogs belonging to that window (docs/M14.md §6), not to whatever is in front,
/// and the archives kept unlocked as `kept_unlocks` says ([`kept_unlocks`]). At
/// [`KeptUnlocks::Keep`] (a tab's jobs and its drags), an encrypted archive the job opens stays
/// unlocked for the next job on it until its tab closes ([`cmd_lock`]).
pub fn policy_for(
    engine: &Engine,
    window: Option<isize>,
    kept_unlocks: KeptUnlocks,
) -> Arc<Policy> {
    Arc::new(Policy {
        window,
        kept_unlocks,
        ..Policy::clone(&engine.policy())
    })
}

/// What a job started from the window labelled `label` does with the archives kept unlocked
/// (docs/M14.md §8). The main window's jobs open from them; those that belong to a tab
/// (`for_tab`) keep what they open too, since the tab's closing forgets it. Another's (a job
/// window, from Explorer's menu) neither take nor keep.
pub fn kept_unlocks(label: &str, for_tab: bool) -> KeptUnlocks {
    match (label == MAIN, for_tab) {
        (true, true) => KeptUnlocks::Keep,
        (true, false) => KeptUnlocks::Use,
        (false, _) => KeptUnlocks::Off,
    }
}

/// Starts command `name` and streams its events to `on_event`. Returns the job id at once. The
/// job's devices show their dialogs over the window that started it: the main window, or the
/// job window of a request from Explorer. The main window's jobs open encrypted archives from
/// what its tabs kept unlocked, and those of a tab (`for_tab`, the page's `forTab`) keep what
/// they open for it ([`kept_unlocks`]).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn cmd_run(
    window: Window,
    engine: State<'_, Engine>,
    gui: State<'_, Arc<GuiInteractor>>,
    opened: State<'_, Arc<Opened>>,
    name: String,
    args: Value,
    on_event: Channel<JobEvent>,
    for_tab: Option<bool>,
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
    let kept = kept_unlocks(window.label(), for_tab.unwrap_or(false));
    let policy = policy_for(&engine, hwnd(&window), kept);
    let job = engine.invoke_with_policy(&name, args, interactor, sink, policy)?;
    Ok(job.id())
}

/// Locks the archive at `path` again: what unlocked it for the main window's jobs is wiped from
/// memory, so the next job on it asks again (docs/M14.md §8). The page calls it when the
/// archive's tab closes. Returns how many ways in were forgotten.
#[tauri::command]
pub fn cmd_lock(engine: State<'_, Engine>, path: PathBuf) -> usize {
    engine.unlocks().forget(&path)
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

    /// A job the page starts runs under the engine's policy, with its window's handle for
    /// Windows' dialogs, taking and keeping archives unlocked as it says.
    #[test]
    fn a_job_gets_the_engines_policy_and_its_window() {
        let engine = Engine::new(registry());
        let policy = policy_for(&engine, Some(0x5e1f), KeptUnlocks::Keep);
        assert_eq!(policy.window, Some(0x5e1f));
        assert_eq!(policy.limits, engine.policy().limits);
        assert!(!policy.unattended);
        assert_eq!(policy.kept_unlocks, KeptUnlocks::Keep);
        assert_eq!(
            engine.policy().window,
            None,
            "the engine's own is left alone"
        );
        assert_eq!(engine.policy().kept_unlocks, KeptUnlocks::Off);
        let job_window = policy_for(&engine, None, KeptUnlocks::Off);
        assert_eq!(job_window.window, None);
        assert_eq!(job_window.kept_unlocks, KeptUnlocks::Off);
    }

    /// Only a tab's jobs keep what unlocks an archive: the main window's other jobs only take
    /// what tabs kept, and a job window's do neither, whatever its page says.
    #[test]
    fn only_a_tabs_jobs_keep_archives_unlocked() {
        assert_eq!(kept_unlocks(MAIN, true), KeptUnlocks::Keep);
        assert_eq!(kept_unlocks(MAIN, false), KeptUnlocks::Use);
        assert_eq!(kept_unlocks("job-1", true), KeptUnlocks::Off);
        assert_eq!(kept_unlocks("job-1", false), KeptUnlocks::Off);
        assert!(KeptUnlocks::Use.uses() && !KeptUnlocks::Use.keeps());
        assert!(KeptUnlocks::Keep.uses() && KeptUnlocks::Keep.keeps());
        assert!(!KeptUnlocks::Off.uses() && !KeptUnlocks::Off.keeps());
    }
}
