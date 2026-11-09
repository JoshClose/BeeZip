//! Dragging entries out of an archive into Explorer (docs/M6.md §8.4), Windows only.
//!
//! The page's `dragstart` on selected rows calls [`cmd_drag_out`] with `archive.extract`'s
//! arguments, less `dest`. BeeZip then runs the OLE drag the way 7-Zip's File Manager does
//! (`PanelDrag.cpp`): its data object names files in a fresh temp folder that don't exist yet,
//! and only extracts them when a target that accepts the drop asks for them after the button
//! goes up (ole.rs). The extraction is an ordinary job, so the page shows its progress and
//! prompts; win.rs says where the drag runs so that they keep coming.

#[cfg(windows)]
mod ole;
#[cfg(windows)]
mod win;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use beezip_commands::{CmdError, EventSink, JobEvent};
use serde::Serialize;
use serde_json::{Value, json};
use tauri::{AppHandle, ipc::Channel};

#[cfg(windows)]
pub use win::init;

/// How a drag ended, as the page gets it.
// Only drag/win.rs makes and uses these; off Windows the command just refuses.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DragOutcome {
    /// Dropped on a target, which took the files.
    Dropped,
    /// Let go over nothing that takes files, over BeeZip itself, or Escape.
    Cancelled,
    /// Dropped, but the extraction failed; its job's events said why.
    Failed,
}

/// Drags the entries `args` names (`archive.extract`'s arguments: `archive`, `entries`,
/// `strip_components`, `password`, `name_encoding`) out of the window, while the mouse button
/// that started the page's `dragstart` is still down. The extraction's events go to
/// `on_event`, as `cmd_run`'s do. Resolves when the drag is over.
#[tauri::command]
pub async fn cmd_drag_out(
    app: AppHandle,
    args: Value,
    on_event: Channel<JobEvent>,
) -> Result<DragOutcome, CmdError> {
    // A send fails only if the webview has gone away, and then nobody is listening.
    let sink: EventSink = Arc::new(move |event| {
        let _ = on_event.send(event);
    });
    #[cfg(windows)]
    {
        win::drag_out(&app, args, sink).await
    }
    #[cfg(not(windows))]
    {
        let _ = (app, args, sink);
        Err(CmdError::new(
            beezip_commands::ErrorCode::UnsupportedOperation,
            "dragging entries out is only on Windows; use Extract",
        ))
    }
}

/// Debug builds say on stderr how each drag went, for checks that can't hold a mouse button
/// (docs/M6.md §16 PR 7). Release builds say nothing.
// Only drag/win.rs makes and uses these; off Windows the command just refuses.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn trace(what: impl FnOnce() -> String) {
    if cfg!(debug_assertions) {
        eprintln!("BeeZip drag: {}", what());
    }
}

/// Where drags extract to, one fresh folder each: `%TEMP%\BeeZip\drag`.
pub fn drag_dir() -> PathBuf {
    std::env::temp_dir().join("BeeZip").join("drag")
}

/// A drag lasts as long as its extraction, which the 2 GiB cap keeps short: a drag folder older
/// than this was left by a BeeZip that didn't get to remove it (killed during a drop).
pub const MAX_FOLDER_AGE: Duration = Duration::from_secs(60 * 60);

/// Removes the `drag-*` folders in `dir` last changed before `now - max_age`, with whatever
/// they hold. Returns how many went.
pub fn sweep(dir: &Path, now: SystemTime, max_age: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("drag-"))
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| {
            e.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age > max_age))
        })
        .filter(|e| std::fs::remove_dir_all(e.path()).is_ok())
        .count()
}

/// The page's `archive.extract` arguments, into `dest`: as named (not into a folder named after
/// the archive), and a later entry of the same name replacing an earlier one, since `dest` is
/// new and empty. The keys BeeZip sets are refused.
// Only drag/win.rs makes and uses these; off Windows the command just refuses.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn extract_args(args: Value, dest: &Path) -> Result<Value, CmdError> {
    let Value::Object(mut map) = args else {
        return Err(CmdError::invalid_args(
            "a drag takes archive.extract's arguments, as an object",
        ));
    };
    for key in ["dest", "smart", "overwrite", "dry_run"] {
        if map.contains_key(key) {
            return Err(CmdError::invalid_args(format!(
                "a drag sets archive.extract's `{key}` itself"
            )));
        }
    }
    map.insert("dest".into(), json!(dest));
    map.insert("smart".into(), json!(false));
    map.insert("overwrite".into(), json!("always"));
    Ok(Value::Object(map))
}

/// What a drop hands its target: the items the extraction left at the top of `dir`, by name.
// Only drag/win.rs makes and uses these; off Windows the command just refuses.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn dropped_items(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut items = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    items.sort();
    Ok(items)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use beezip_commands::ErrorCode;

    use super::*;

    #[test]
    fn the_page_names_the_entries_and_beezip_the_rest() {
        let dest = Path::new("T").join("drag-1");
        let args = extract_args(
            json!({ "archive": "a.zip", "entries": ["docs/a.md"], "strip_components": 1, "password": "pw" }),
            &dest,
        )
        .unwrap();
        assert_eq!(
            args,
            json!({
                "archive": "a.zip", "entries": ["docs/a.md"], "strip_components": 1, "password": "pw",
                "dest": dest, "smart": false, "overwrite": "always",
            })
        );
        for key in ["dest", "smart", "overwrite", "dry_run"] {
            let err = extract_args(json!({ "archive": "a.zip", key: true }), &dest).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgs);
            assert!(err.message.contains(key), "{}", err.message);
        }
        assert!(extract_args(json!(["a.zip"]), &dest).is_err());
    }

    #[test]
    fn old_drag_folders_are_swept_with_what_they_hold() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("drag-old");
        let new = dir.path().join("drag-new");
        let other = dir.path().join("other");
        for d in [&old, &new, &other] {
            std::fs::create_dir_all(d.join("sub")).unwrap();
            std::fs::write(d.join("sub").join("f.txt"), "x").unwrap();
        }
        std::fs::write(dir.path().join("drag-file"), "").unwrap();
        // Read the folders' times as they are now, then look two hours ahead.
        let later = SystemTime::now() + Duration::from_secs(2 * 60 * 60);
        let fresh = std::fs::metadata(&new).unwrap().modified().unwrap();
        assert_eq!(
            sweep(dir.path(), fresh, MAX_FOLDER_AGE),
            0,
            "nothing old yet"
        );
        assert_eq!(sweep(dir.path(), later, MAX_FOLDER_AGE), 2);
        assert!(!old.exists() && !new.exists());
        assert!(other.exists() && dir.path().join("drag-file").exists());
        assert_eq!(sweep(&dir.path().join("none"), later, MAX_FOLDER_AGE), 0);
    }

    #[test]
    fn the_drop_lists_the_top_items_in_order() {
        let dir = tempfile::tempdir().unwrap();
        assert!(dropped_items(dir.path()).unwrap().is_empty());
        std::fs::write(dir.path().join("b.txt"), "").unwrap();
        std::fs::create_dir_all(dir.path().join("a").join("deep")).unwrap();
        assert_eq!(
            dropped_items(dir.path()).unwrap(),
            [dir.path().join("a"), dir.path().join("b.txt")]
        );
        assert!(dropped_items(&dir.path().join("gone")).is_err());
    }
}
