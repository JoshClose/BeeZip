//! Opening files (docs/M3.md §5.4): the paths `BeeZip.exe` starts with reach the page through
//! an initialization script, so it has them before any listener could miss an event; the
//! paths a second instance forwards arrive as the `open-paths` event.

use std::path::{Path, PathBuf};

use beezip_commands::Theme;
use serde::Serialize;
use tauri::{App, AppHandle, Emitter, Manager, WebviewWindowBuilder};

/// The window every page lives in.
pub const MAIN: &str = "main";

/// The event a second instance's paths arrive as.
pub const OPEN_PATHS: &str = "open-paths";

/// What the page finds in `window.__BEEZIP__` before its scripts run.
#[derive(Debug, Serialize)]
pub struct Startup {
    /// Files to open, absolute.
    pub paths: Vec<PathBuf>,
    /// How "Copy as CLI" starts its line: `beezip`, or the full path of a `beezip.exe` that
    /// isn't on PATH.
    pub cli: String,
    /// Problems with `config.toml`, shown once.
    pub warnings: Vec<String>,
    /// `[desktop] theme`, as the window opened with it.
    pub theme: Theme,
}

/// The paths among a process's arguments (`argv[0]` first), resolved against `cwd`. Flags
/// are left out; Explorer passes full paths.
pub fn paths_from_args(args: &[String], cwd: &Path) -> Vec<PathBuf> {
    args.iter()
        .skip(1)
        .filter(|a| !a.is_empty() && !a.starts_with('-'))
        .map(|a| {
            let p = cwd.join(a);
            std::path::absolute(&p).unwrap_or(p)
        })
        .collect()
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

/// Builds the main window (`create: false` in tauri.conf.json) with the startup script.
pub fn create_main_window(app: &App, warnings: Vec<String>, theme: Theme) -> tauri::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir().unwrap_or_default();
    let exe = std::env::current_exe().unwrap_or_default();
    let startup = Startup {
        paths: paths_from_args(&args, &cwd),
        cli: cli_program(&exe, std::env::var_os("PATH").as_deref()),
        warnings,
        theme,
    };
    let json = serde_json::to_string(&startup).unwrap_or_else(|_| "{}".into());
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN)
        .cloned()
        .unwrap_or_default();
    WebviewWindowBuilder::from_config(app.handle(), &config)?
        .initialization_script(format!("window.__BEEZIP__ = {json};"))
        .build()?;
    Ok(())
}

/// A second `BeeZip.exe` started: open its paths here, and bring the window forward.
pub fn forward(app: &AppHandle, args: &[String], cwd: &str) {
    let paths = paths_from_args(args, Path::new(cwd));
    if !paths.is_empty() {
        let _ = app.emit_to(MAIN, OPEN_PATHS, &paths);
    }
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn startup_arguments_resolve_against_the_working_directory() {
        let cwd = std::env::temp_dir();
        let args: Vec<String> = ["BeeZip.exe", "a.7z", "--flag", "", "sub/../b.zip"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let paths = paths_from_args(&args, &cwd);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], std::path::absolute(cwd.join("a.7z")).unwrap());
        assert!(paths[1].is_absolute());
        let abs = if cfg!(windows) {
            r"C:\x\y.rar"
        } else {
            "/x/y.rar"
        };
        let paths = paths_from_args(&["BeeZip.exe".into(), abs.into()], &cwd);
        assert_eq!(paths, [PathBuf::from(abs)]);
        assert!(paths_from_args(&["BeeZip.exe".into()], &cwd).is_empty());
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
