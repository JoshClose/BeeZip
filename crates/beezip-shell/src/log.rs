//! The debug log (docs/M4.md §4.2), off by default. With `Log = 1` under the settings key, each
//! call appends a line to `%TEMP%\BeeZip\shell.log`, beside the job requests: the time, the
//! process and what was asked. That is how the manual checks see which process served which call.
//! It stays out of `%LOCALAPPDATA%\BeeZip`, which is the per-user install folder: a log there
//! would keep the uninstaller from removing it.

use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static ON: AtomicBool = AtomicBool::new(false);

/// Turned on or off whenever the settings are read.
pub fn set(on: bool) {
    ON.store(on, Ordering::Relaxed);
}

/// Appends `what()` when the log is on. Errors are ignored: the log must never fail a call.
pub fn line(what: impl FnOnce() -> String) {
    if !ON.load(Ordering::Relaxed) {
        return;
    }
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let _ = writeln!(
        file,
        "{}.{:03} pid={} {} {}",
        ms / 1000,
        ms % 1000,
        std::process::id(),
        exe(),
        what()
    );
}

fn path() -> Option<PathBuf> {
    Some(std::env::temp_dir().join("BeeZip").join("shell.log"))
}

/// The host's file name: `explorer.exe`, `DllHost.exe`, `menu_dump.exe`.
fn exe() -> &'static str {
    static EXE: OnceLock<String> = OnceLock::new();
    EXE.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default()
    })
}
