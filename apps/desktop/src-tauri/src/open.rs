//! Launches (docs/M3.md §5.4, docs/M4.md §6.2): what `BeeZip.exe` was started with, and what a
//! second `BeeZip.exe` forwards to this one. Windows are created only when something needs
//! them: the main window for archives, dialogs and plain launches, a job window for each
//! request from Explorer's menu.
//!
//! A new window's page gets its startup data through an initialization script, so it has them
//! before any listener could miss an event. A main window that already exists gets them as the
//! `open-paths` and `open-dialog` events, once its page listens for them: until then they wait
//! in [`Pending`], which the page drains with `cmd_launched` (docs/M6.md §8.1). Explorer starts
//! one `BeeZip.exe` per file when several are opened at once, so the second often arrives while
//! the first is still starting.
//!
//! Windows are created on the main thread only, so a forwarded launch can't race `setup` into
//! building a second main window.

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use beezip_commands::{Engine, Theme};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, WebviewWindowBuilder};

use crate::job::{self, JobStartup, Routed};

/// The main window: tabs, dialogs and the jobs panel.
pub const MAIN: &str = "main";

/// The event a second instance's paths arrive as.
pub const OPEN_PATHS: &str = "open-paths";

/// The event a dialog for the main window arrives as.
pub const OPEN_DIALOG: &str = "open-dialog";

/// A dialog the main window opens on its own: `{ "dialog": "extract", "paths": [...] }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "dialog", rename_all = "snake_case")]
pub enum OpenDialog {
    /// The extract dialog, for the one archive in `paths`.
    Extract { paths: Vec<PathBuf> },
    /// The create dialog, with `paths` as its inputs.
    Create { paths: Vec<PathBuf> },
}

/// What a window's page finds in `window.__BEEZIP__` before its scripts run.
#[derive(Debug, Serialize)]
pub struct Startup {
    /// Archives to open, absolute.
    pub paths: Vec<PathBuf>,
    /// How "Copy as CLI" starts its line: `beezip`, or the full path of a `beezip.exe` that
    /// isn't on PATH.
    pub cli: String,
    /// Problems with `config.toml`, shown once, by the first main window.
    pub warnings: Vec<String>,
    /// `[desktop] theme`, as the window opened with it.
    pub theme: Theme,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialog: Option<OpenDialog>,
    /// A job window's steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job: Option<JobStartup>,
}

/// The config's warnings, until the first main window takes them.
pub struct Warnings(pub Mutex<Vec<String>>);

/// What forwarded launches asked of the main window before its page listened for it.
#[derive(Debug, Default)]
pub struct Pending(Mutex<Queued>);

/// Archives and a dialog for the main window's page, as `cmd_launched` returns them.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Queued {
    /// The page listens: events go straight to it.
    #[serde(skip)]
    ready: bool,
    pub paths: Vec<PathBuf>,
    pub dialog: Option<OpenDialog>,
}

impl Pending {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queued> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new main window's page doesn't listen yet.
    pub fn not_ready(&self) {
        self.lock().ready = false;
    }

    /// Hands `paths` and `dialog` to `send` if the page listens, or keeps them for it. Under the
    /// lock, so nothing slips between the page's drain and an event.
    pub fn deliver(
        &self,
        paths: Vec<PathBuf>,
        dialog: Option<OpenDialog>,
        send: impl FnOnce(Vec<PathBuf>, Option<OpenDialog>),
    ) {
        let mut q = self.lock();
        if q.ready {
            send(paths, dialog);
        } else {
            q.paths.extend(paths);
            if dialog.is_some() {
                q.dialog = dialog;
            }
        }
    }

    /// The page listens now: what waited for it, and events from here on.
    pub fn drain(&self) -> Queued {
        let mut q = self.lock();
        q.ready = true;
        Queued {
            ready: true,
            paths: std::mem::take(&mut q.paths),
            dialog: q.dialog.take(),
        }
    }
}

/// What a launch asks for.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Launch {
    /// Files to open, absolute.
    pub paths: Vec<PathBuf>,
    /// The request file of `--job <file>`.
    pub job: Option<PathBuf>,
}

/// A process's arguments (`argv[0]` first), resolved against `cwd`: `--job FILE` (or
/// `--job=FILE`), and paths. Other flags are ignored, and `--` ends them.
pub fn parse_args(args: &[String], cwd: &Path) -> Launch {
    let resolve = |a: &str| {
        let p = cwd.join(a);
        std::path::absolute(&p).unwrap_or(p)
    };
    let mut launch = Launch::default();
    let mut options = true;
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg.is_empty() {
            continue;
        }
        if options {
            if arg == "--" {
                options = false;
                continue;
            }
            if arg == "--job" {
                launch.job = args.next().map(|f| resolve(f));
                continue;
            }
            if let Some(file) = arg.strip_prefix("--job=") {
                launch.job = Some(resolve(file));
                continue;
            }
            if arg.starts_with('-') {
                continue;
            }
        }
        launch.paths.push(resolve(arg));
    }
    launch
}

/// The `beezip` executable "Copy as CLI" names: `bin\beezip.exe` beside an installed
/// `BeeZip.exe`, or `beezip.exe` beside it (in development, the same `target\debug`).
pub fn cli_program(exe: &Path, path_var: Option<&std::ffi::OsStr>) -> String {
    let name = format!("beezip{}", std::env::consts::EXE_SUFFIX);
    let Some(dir) = exe.parent() else {
        return "beezip".into();
    };
    for candidate in [dir.join("bin").join(&name), dir.join(&name)] {
        if !candidate.is_file() {
            continue;
        }
        let folder = candidate.parent().unwrap_or(dir);
        let on_path =
            path_var.is_some_and(|p| std::env::split_paths(p).any(|d| same_dir(&d, folder)));
        return if on_path {
            "beezip".into()
        } else {
            candidate.display().to_string()
        };
    }
    "beezip".into()
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// `window.__BEEZIP__ = …;` for a new window. A main window (no `job`) takes the config's
/// warnings, so only the first one shows them.
pub fn startup_script(
    app: &AppHandle,
    paths: Vec<PathBuf>,
    dialog: Option<OpenDialog>,
    job: Option<JobStartup>,
) -> String {
    let warnings = match (&job, app.try_state::<Warnings>()) {
        (None, Some(w)) => std::mem::take(&mut *w.0.lock().unwrap_or_else(|e| e.into_inner())),
        _ => Vec::new(),
    };
    // The theme now: the settings page may have changed it since startup.
    let theme = app
        .state::<Engine>()
        .config()
        .as_ref()
        .as_ref()
        .map(|c| c.desktop.theme)
        .unwrap_or_default();
    let exe = std::env::current_exe().unwrap_or_default();
    let startup = Startup {
        paths,
        cli: cli_program(&exe, std::env::var_os("PATH").as_deref()),
        warnings,
        theme,
        dialog,
        job,
    };
    let json = serde_json::to_string(&startup).unwrap_or_else(|_| "{}".into());
    format!("window.__BEEZIP__ = {json};")
}

/// Builds the main window (`create: false` in tauri.conf.json) with its startup data. On the
/// main thread only.
pub fn create_main_window(
    app: &AppHandle,
    paths: Vec<PathBuf>,
    dialog: Option<OpenDialog>,
) -> tauri::Result<()> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN)
        .cloned()
        .unwrap_or_default();
    if let Some(pending) = app.try_state::<Pending>() {
        pending.not_ready();
    }
    with_browser_args(
        WebviewWindowBuilder::from_config(app, &config)?
            .initialization_script(startup_script(app, paths, dialog, None)),
    )
    .build()?;
    Ok(())
}

/// wry's own WebView2 arguments, which a window's `additional_browser_args` replaces: no mini
/// menu, no SmartScreen inside the page, and autoplay as Tauri asks for it.
const WRY_BROWSER_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection \
                                --autoplay-policy=no-user-gesture-required";

/// The arguments for every window's WebView2: wry's own, with `WEBVIEW2_ADDITIONAL_BROWSER_
/// ARGUMENTS` merged in when it's set (its `--disable-features` and `--enable-features` lists
/// joined). WebView2 reads that variable itself, but whether it or the app's arguments win
/// depends on the runtime: 157 takes the variable's, 156 the app's. msedgedriver drives WebView2
/// through it (`--remote-debugging-port`), as BeeZip's E2E test does (docs/M6.md §16, PR 5).
/// `None` when it isn't set: wry's defaults then.
pub fn browser_args(env: Option<&str>) -> Option<String> {
    let env = env.map(str::trim).filter(|e| !e.is_empty())?;
    let mut args: Vec<String> = Vec::new();
    let mut lists: Vec<(&str, Vec<String>)> = Vec::new();
    for arg in WRY_BROWSER_ARGS
        .split_whitespace()
        .chain(env.split_whitespace())
    {
        let list = ["--disable-features=", "--enable-features="]
            .into_iter()
            .find(|p| arg.starts_with(p));
        match list {
            Some(prefix) => {
                let at = match lists.iter().position(|(p, _)| *p == prefix) {
                    Some(at) => at,
                    None => {
                        lists.push((prefix, Vec::new()));
                        args.push(prefix.to_owned());
                        lists.len() - 1
                    }
                };
                for f in arg[prefix.len()..].split(',').filter(|f| !f.is_empty()) {
                    if !lists[at].1.iter().any(|x| x == f) {
                        lists[at].1.push(f.to_owned());
                    }
                }
            }
            None if !args.iter().any(|a| a == arg) => args.push(arg.to_owned()),
            None => {}
        }
    }
    Some(
        args.into_iter()
            .map(|a| match lists.iter().find(|(p, _)| *p == a) {
                Some((p, features)) => format!("{p}{}", features.join(",")),
                None => a,
            })
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// `builder` with [`browser_args`], when `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` is set. Every
/// window gets the same, as WebView2 needs windows sharing a profile to.
pub fn with_browser_args<'a, R: tauri::Runtime, M: Manager<R>>(
    builder: WebviewWindowBuilder<'a, R, M>,
) -> WebviewWindowBuilder<'a, R, M> {
    let env = std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").ok();
    match browser_args(env.as_deref()) {
        Some(args) => builder.additional_browser_args(&args),
        None => builder,
    }
}

/// The request file of a `--job` launch, unless it's gone: the updater restarts BeeZip with
/// the arguments it had, and the menu's request was deleted when first read. A launch whose
/// request is gone is a plain launch (docs/M6.md §9.3).
pub fn request_file(launch: &Launch) -> Option<&Path> {
    let gone = |f: &Path| matches!(std::fs::symlink_metadata(f), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    launch.job.as_deref().filter(|f| !gone(f))
}

/// Plans a launch, on any thread: reads and plans a job request. [`show`] carries it out.
pub fn plan(app: &AppHandle, launch: Launch) -> Routed {
    let mut routed = match request_file(&launch) {
        Some(file) => job::route(job::plan(&app.state::<Engine>(), file)),
        None => Routed::default(),
    };
    routed.open.extend(launch.paths);
    routed
}

/// Carries out a planned launch, on the main thread: opens or reuses the windows its steps
/// need. A plain launch shows the main window.
pub fn show(app: &AppHandle, mut routed: Routed) -> tauri::Result<()> {
    let job_steps = std::mem::take(&mut routed.job);
    let job_window = !job_steps.is_empty();
    if job_window {
        job::create_job_window(app, job_steps)?;
    }
    // The main window: for archives and dialogs, for a plain launch, and for a request that
    // has nothing else to show.
    if routed.open.is_empty() && routed.dialog.is_none() && job_window {
        return Ok(());
    }
    if app.get_webview_window(MAIN).is_none() {
        return create_main_window(app, routed.open, routed.dialog);
    }
    app.state::<Pending>()
        .deliver(routed.open, routed.dialog, |paths, dialog| {
            if !paths.is_empty() {
                let _ = app.emit_to(MAIN, OPEN_PATHS, &paths);
            }
            if let Some(dialog) = &dialog {
                let _ = app.emit_to(MAIN, OPEN_DIALOG, dialog);
            }
        });
    focus_main(app)
}

fn focus_main(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    Ok(())
}

/// A second `BeeZip.exe` started and handed over its arguments. Its request is planned on
/// another thread, and its windows built from the event loop: building one inside this callback
/// would deadlock (WebView2), and `run_on_main_thread` called from here would run at once.
pub fn forward(app: &AppHandle, args: &[String], cwd: &str) {
    let request = parse_args(args, Path::new(cwd));
    let app = app.clone();
    std::thread::spawn(move || {
        let routed = plan(&app, request);
        let handle = app.clone();
        let posted = app.run_on_main_thread(move || {
            if let Err(e) = show(&handle, routed) {
                eprintln!("BeeZip: a forwarded launch failed: {e}");
            }
        });
        if let Err(e) = posted {
            eprintln!("BeeZip: a forwarded launch failed: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn startup_arguments_resolve_against_the_working_directory() {
        let cwd = std::env::temp_dir();
        let launch = parse_args(
            &args(&["BeeZip.exe", "a.7z", "--flag", "", "sub/../b.zip"]),
            &cwd,
        );
        assert_eq!(launch.paths.len(), 2);
        assert_eq!(
            launch.paths[0],
            std::path::absolute(cwd.join("a.7z")).unwrap()
        );
        assert!(launch.paths[1].is_absolute());
        assert_eq!(launch.job, None);
        let abs = if cfg!(windows) {
            r"C:\x\y.rar"
        } else {
            "/x/y.rar"
        };
        let launch = parse_args(&args(&["BeeZip.exe", abs]), &cwd);
        assert_eq!(launch.paths, [PathBuf::from(abs)]);
        assert_eq!(parse_args(&args(&["BeeZip.exe"]), &cwd), Launch::default());
    }

    #[test]
    fn the_job_file_is_not_an_archive_to_open() {
        let cwd = std::env::temp_dir();
        let file = cwd.join("BeeZip").join("jobs").join("x.json");
        let file_arg = file.display().to_string();
        let launch = parse_args(&args(&["BeeZip.exe", "--job", &file_arg]), &cwd);
        assert_eq!(launch.job.as_deref(), Some(file.as_path()));
        assert!(launch.paths.is_empty(), "{launch:?}");

        let joined = format!("--job={file_arg}");
        let launch = parse_args(&args(&["BeeZip.exe", &joined, "a.zip"]), &cwd);
        assert_eq!(launch.job.as_deref(), Some(file.as_path()));
        assert_eq!(
            launch.paths,
            [std::path::absolute(cwd.join("a.zip")).unwrap()]
        );

        // After `--`, everything is a path, even `--job`.
        let launch = parse_args(&args(&["BeeZip.exe", "--", "--job", "-x.zip"]), &cwd);
        assert_eq!(launch.job, None);
        assert_eq!(launch.paths.len(), 2);

        // `--job` with nothing after it asks for nothing.
        assert_eq!(
            parse_args(&args(&["BeeZip.exe", "--job"]), &cwd),
            Launch::default()
        );
    }

    #[test]
    fn webview2s_variable_is_merged_with_wrys_arguments() {
        assert_eq!(browser_args(None), None);
        assert_eq!(browser_args(Some("  ")), None);
        assert_eq!(
            browser_args(Some("--remote-debugging-port=9222")).unwrap(),
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection \
             --autoplay-policy=no-user-gesture-required --remote-debugging-port=9222"
        );
        // msedgedriver's, shortened: one --disable-features list, nothing twice.
        assert_eq!(
            browser_args(Some(
                "--disable-features=IgnoreDuplicateNavs,msWebOOUI --remote-debugging-port=0 \
                 --enable-features=A --enable-features=B --remote-debugging-port=0"
            ))
            .unwrap(),
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,IgnoreDuplicateNavs \
             --autoplay-policy=no-user-gesture-required --remote-debugging-port=0 \
             --enable-features=A,B"
        );
    }

    #[test]
    fn a_launch_whose_request_is_gone_is_a_plain_launch() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.json");
        let launch = Launch {
            paths: Vec::new(),
            job: Some(file.clone()),
        };
        assert_eq!(request_file(&launch), None);
        std::fs::write(&file, "{}").unwrap();
        assert_eq!(request_file(&launch), Some(file.as_path()));
        assert_eq!(request_file(&Launch::default()), None);
    }

    #[test]
    fn launches_wait_until_the_page_listens() {
        let pending = Pending::default();
        let sent = std::cell::RefCell::new(Vec::new());
        let send = |paths: Vec<PathBuf>, dialog: Option<OpenDialog>| {
            sent.borrow_mut().push((paths, dialog));
        };
        pending.deliver(vec!["a.zip".into()], None, send);
        let extract = OpenDialog::Extract {
            paths: vec!["c.7z".into()],
        };
        pending.deliver(vec!["b.zip".into()], Some(extract.clone()), send);
        assert!(sent.borrow().is_empty(), "nobody listens yet");

        let drained = pending.drain();
        assert_eq!(drained.paths, [PathBuf::from("a.zip"), "b.zip".into()]);
        assert_eq!(drained.dialog, Some(extract));
        assert_eq!(
            serde_json::to_value(&drained).unwrap(),
            serde_json::json!({
                "paths": ["a.zip", "b.zip"],
                "dialog": { "dialog": "extract", "paths": ["c.7z"] }
            })
        );
        assert_eq!(pending.drain().paths, Vec::<PathBuf>::new());

        // Once it listens, launches go straight through, until a new main window starts.
        pending.deliver(vec!["d.zip".into()], None, send);
        assert_eq!(sent.borrow().len(), 1);
        pending.not_ready();
        pending.deliver(vec!["e.zip".into()], None, send);
        assert_eq!(sent.borrow().len(), 1);
        assert_eq!(pending.drain().paths, [PathBuf::from("e.zip")]);
    }

    #[test]
    fn dialogs_serialise_as_the_page_reads_them() {
        let d = OpenDialog::Extract {
            paths: vec![PathBuf::from("a.zip")],
        };
        assert_eq!(
            serde_json::to_value(&d).unwrap(),
            serde_json::json!({ "dialog": "extract", "paths": ["a.zip"] })
        );
        let d = OpenDialog::Create {
            paths: vec![PathBuf::from("x")],
        };
        assert_eq!(serde_json::to_value(&d).unwrap()["dialog"], "create");
    }

    #[test]
    fn the_cli_is_found_beside_the_app() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("BeeZip.exe");
        let name = format!("beezip{}", std::env::consts::EXE_SUFFIX);
        assert_eq!(cli_program(&exe, None), "beezip", "nothing found");

        std::fs::write(dir.path().join(&name), "").unwrap();
        let beside = dir.path().join(&name).display().to_string();
        assert_eq!(cli_program(&exe, None), beside);

        std::fs::create_dir(dir.path().join("bin")).unwrap();
        std::fs::write(dir.path().join("bin").join(&name), "").unwrap();
        let installed = dir.path().join("bin").join(&name).display().to_string();
        assert_eq!(cli_program(&exe, None), installed);
        let path = std::env::join_paths([dir.path().join("bin")]).unwrap();
        assert_eq!(cli_program(&exe, Some(&path)), "beezip", "bin is on PATH");
    }
}
