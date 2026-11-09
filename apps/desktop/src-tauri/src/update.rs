//! Updates (docs/M6.md §8.2, §9.4): tauri-plugin-updater, driven from here only; the page has no
//! updater permission of its own.
//!
//! - **Checking:** the main window's page asks at startup, and BeeZip asks GitHub at most once a
//!   day, when `[updates] check` is on (the default). About's "Check for updates" always asks.
//!   The release found is remembered with the time, so a restart within the day still shows it.
//!   A build without the updater's public key never checks: development builds, and installers
//!   built before `packaging/updater.pub` exists.
//! - **Installing,** only on a click: the installer is downloaded and its signature checked, then
//!   BeeZip waits for running jobs to finish, then the plugin runs `on_before_exit` (which cancels
//!   whatever started meanwhile and waits for its partial files to go, as quitting does), starts
//!   the installer with `/P /UPDATE /R` and exits the process at once: `RunEvent::Exit` never
//!   comes.
//! - **The signature** must carry the release's version (`requireSignedVersion`), so neither a
//!   signature made for another version nor a downgrade installs. Older versions aren't offered.
//! - **A portable copy** (Windows: no `uninstall.exe` beside `BeeZip.exe`, as with the release's
//!   zip) never installs one: the installer would put a second BeeZip beside it. It looks up the
//!   zip's entry in `latest.json`, [`PORTABLE`], and the banner links to the new zip instead.

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use beezip_commands::Engine;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State, ipc::Channel};
use tauri_plugin_updater::{Update, UpdaterExt};

/// How often BeeZip asks GitHub on its own.
pub const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// Where the last check is remembered, in BeeZip's local data folder.
const STATE_FILE: &str = "update-check.json";

/// The portable zip's entry in `latest.json` (xtask's `dist::portable::KEY`).
pub const PORTABLE: &str = "windows-x86_64-portable";

/// What Tauri's NSIS installer puts beside `BeeZip.exe`, and nothing else does.
const UNINSTALLER: &str = "uninstall.exe";

/// Whether the program at `exe` was installed: the installer's uninstaller is beside it.
pub fn installed_at(exe: &Path) -> bool {
    exe.parent().is_some_and(|d| d.join(UNINSTALLER).is_file())
}

/// Whether this copy is a portable one: on Windows, one that wasn't installed. Elsewhere each
/// bundle updates itself (the AppImage, deb, rpm and app).
fn portable() -> bool {
    cfg!(windows) && !std::env::current_exe().is_ok_and(|exe| installed_at(&exe))
}

/// The update found, until it's installed.
#[derive(Default)]
pub struct Updates(Mutex<Option<Update>>);

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Checked {
    /// Nothing was asked: `reason` says why.
    Off { reason: String },
    /// This is the newest version.
    UpToDate { version: String },
    /// A newer version.
    Available {
        version: String,
        current: String,
        /// The release's page on GitHub.
        notes_url: String,
        /// The new zip, for a portable copy, which doesn't install updates: the banner links to
        /// it.
        #[serde(skip_serializing_if = "Option::is_none")]
        download_url: Option<String>,
    },
}

/// How an install is going, for the banner.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum Progress {
    Downloading {
        done: u64,
        total: Option<u64>,
    },
    /// Downloaded and checked; jobs are still running.
    Waiting {
        jobs: usize,
    },
    /// The installer starts and BeeZip closes.
    Installing,
}

/// The last automatic check, as `update-check.json` keeps it.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Remembered {
    /// Seconds since 1970.
    checked: u64,
    /// The release manifest found then, if it was an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release: Option<serde_json::Value>,
}

/// The updater's public key in this build's config, if it has one.
fn has_key(app: &AppHandle) -> bool {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("pubkey"))
        .and_then(|k| k.as_str())
        .is_some_and(|k| !k.trim().is_empty())
}

fn state_path(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .app_local_data_dir()
        .ok()
        .map(|d| d.join(STATE_FILE))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether an automatic check is due: never checked, a day gone, or a clock that went back.
pub fn due(last: u64, now: u64) -> bool {
    last == 0 || now < last || now - last >= CHECK_EVERY.as_secs()
}

/// The release's page: its notes.
pub fn notes_url(version: &str) -> String {
    format!("https://github.com/JoshClose/BeeZip/releases/tag/v{version}")
}

fn available(update: &Update, portable: bool) -> Checked {
    Checked::Available {
        version: update.version.clone(),
        current: update.current_version.clone(),
        notes_url: notes_url(&update.version),
        download_url: portable.then(|| update.download_url.to_string()),
    }
}

/// The updater, whose `on_before_exit` does what quitting does. A portable copy's looks up the
/// zip's entry.
fn updater(app: &AppHandle, portable: bool) -> Result<tauri_plugin_updater::Updater, String> {
    let handle = app.clone();
    let mut builder = app.updater_builder().on_before_exit(move || {
        crate::cancel_and_wait(&handle);
        handle.cleanup_before_exit();
    });
    if portable {
        builder = builder.target(PORTABLE);
    }
    builder.build().map_err(|e| e.to_string())
}

/// Checks for an update. `force` (About's button) asks GitHub whatever the setting and the day;
/// otherwise BeeZip asks at most once a day, and only when `[updates] check` is on.
#[tauri::command]
pub async fn cmd_update_check(
    app: AppHandle,
    updates: State<'_, Updates>,
    force: bool,
) -> Result<Checked, String> {
    let version = app.package_info().version.to_string();
    if !has_key(&app) {
        return Ok(Checked::Off {
            reason: "This build of BeeZip doesn't look for updates.".into(),
        });
    }
    let enabled = app
        .state::<Engine>()
        .config()
        .as_ref()
        .as_ref()
        .map_or(true, |c| c.updates.check);
    if !force && !enabled {
        return Ok(Checked::Off {
            reason: "Looking for updates is off in Settings.".into(),
        });
    }
    let portable = portable();
    let updater = updater(&app, portable)?;
    let path = state_path(&app);
    let remembered: Remembered = path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let found = if force || due(remembered.checked, now()) {
        let found = updater.check().await.map_err(|e| e.to_string())?;
        let keep = Remembered {
            checked: now(),
            release: found.as_ref().map(|u| u.raw_json.clone()),
        };
        if let Some(p) = &path {
            let _ = std::fs::create_dir_all(p.parent().unwrap_or(p));
            let _ = std::fs::write(p, serde_json::to_vec(&keep).unwrap_or_default());
        }
        found
    } else {
        // Checked today: the release found then, if it's still newer than this version. Its
        // manifest isn't trusted: the installer's signature must still carry its version.
        match remembered.release {
            Some(raw) => updater.restore_update(raw).ok().flatten(),
            None => None,
        }
    };
    let answer = found
        .as_ref()
        .map_or(Checked::UpToDate { version }, |u| available(u, portable));
    *updates.0.lock().unwrap_or_else(|e| e.into_inner()) = found;
    Ok(answer)
}

/// Downloads the update found, checks its signature, waits for running jobs to finish, then
/// installs it: BeeZip exits and the installer restarts it. Returns only on failure.
#[tauri::command]
pub async fn cmd_update_install(
    app: AppHandle,
    updates: State<'_, Updates>,
    on_progress: Channel<Progress>,
) -> Result<(), String> {
    if portable() {
        return Err(
            "A portable copy of BeeZip doesn't install updates: download the new version from \
             the banner."
                .into(),
        );
    }
    let Some(update) = updates.0.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
        return Err("There's no update to install: check for updates first.".into());
    };
    let mut done = 0u64;
    let bytes = update
        .download(
            |chunk, total| {
                done += chunk as u64;
                let _ = on_progress.send(Progress::Downloading { done, total });
            },
            || {},
        )
        .await
        .map_err(|e| {
            format!(
                "The update to {} couldn't be downloaded: {e}",
                update.version
            )
        })?;
    // Jobs the user started run to the end. `on_before_exit` cancels any that start after this.
    let waiting = app.clone();
    let progress = on_progress.clone();
    tauri::async_runtime::spawn_blocking(move || {
        loop {
            let jobs = waiting.state::<Engine>().jobs().len();
            if jobs == 0 {
                break;
            }
            let _ = progress.send(Progress::Waiting { jobs });
            std::thread::sleep(Duration::from_millis(250));
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    let _ = on_progress.send(Progress::Installing);
    // The updater that found it gave it `on_before_exit`.
    update.install(bytes).map_err(|e| {
        format!(
            "The update to {} couldn't be installed: {e}",
            update.version
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn checks_at_most_once_a_day() {
        let day = CHECK_EVERY.as_secs();
        assert!(due(0, 1_000), "never checked");
        assert!(!due(1_000, 1_000 + day - 1));
        assert!(due(1_000, 1_000 + day));
        assert!(due(5_000, 1_000), "the clock went back");
    }

    #[test]
    fn answers_serialise_as_the_page_reads_them() {
        let a = Checked::Available {
            version: "0.1.1".into(),
            current: "0.1.0".into(),
            notes_url: notes_url("0.1.1"),
            download_url: None,
        };
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::json!({
                "status": "available",
                "version": "0.1.1",
                "current": "0.1.0",
                "notes_url": "https://github.com/JoshClose/BeeZip/releases/tag/v0.1.1"
            })
        );
        let zip = "https://github.com/JoshClose/BeeZip/releases/download/v0.1.1/BeeZip_0.1.1_x64-portable.zip";
        let portable = Checked::Available {
            version: "0.1.1".into(),
            current: "0.1.0".into(),
            notes_url: notes_url("0.1.1"),
            download_url: Some(zip.into()),
        };
        assert_eq!(
            serde_json::to_value(&portable).unwrap()["download_url"],
            zip
        );
        let p = Progress::Downloading {
            done: 5,
            total: Some(10),
        };
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            serde_json::json!({ "stage": "downloading", "done": 5, "total": 10 })
        );
    }

    #[test]
    fn an_installed_copy_has_the_installers_uninstaller_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("BeeZip.exe");
        assert!(!installed_at(&exe), "the zip's copy, or a build");
        std::fs::write(dir.path().join(UNINSTALLER), b"").unwrap();
        assert!(installed_at(&exe));
    }
}
