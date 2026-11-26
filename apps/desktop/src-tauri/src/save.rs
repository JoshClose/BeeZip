//! Saving text the page made, such as a new recovery key (docs/M14.md §8). The person picks the
//! file in the system's Save dialog, shown from here, so the page can't write a file anywhere
//! they didn't choose.

use std::path::Path;

use beezip_commands::{CmdError, ErrorCode};
use tauri::Window;
use tauri_plugin_dialog::DialogExt;

/// Asks where to save `text`, suggesting `name`, and writes it there. `None` when the person
/// cancels. Async, so the dialog waits off the main thread, where it runs.
#[tauri::command]
pub async fn cmd_save_text(
    window: Window,
    name: String,
    text: String,
) -> Result<Option<String>, CmdError> {
    let picked = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_file_name(file_name(&name))
        .add_filter("Text", &["txt"])
        .blocking_save_file();
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked
        .into_path()
        .map_err(|e| CmdError::new(ErrorCode::Io, format!("can't save there: {e}")))?;
    write_text(&path, &text)?;
    Ok(Some(path.display().to_string()))
}

/// The suggested name, without anything a file name can't hold on any system.
fn file_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '-',
            c if c.is_control() => '-',
            c => c,
        })
        .collect();
    let clean = clean.trim().trim_matches('.').to_string();
    if clean.is_empty() {
        "BeeZip.txt".to_string()
    } else {
        clean
    }
}

/// Writes `text`, replacing what was there: the Save dialog has already asked about that.
fn write_text(path: &Path, text: &str) -> Result<(), CmdError> {
    std::fs::write(path, text).map_err(|e| {
        CmdError::new(
            ErrorCode::Io,
            format!("couldn't write {}: {e}", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn writes_the_text_and_replaces_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a recovery key.txt");
        std::fs::write(&path, "old, and longer than the new text").unwrap();
        write_text(&path, "123456-000000\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "123456-000000\n");
    }

    #[test]
    fn a_missing_folder_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = write_text(&dir.path().join("no/such/folder.txt"), "x").unwrap_err();
        assert_eq!(err.code, ErrorCode::Io);
    }

    #[test]
    fn suggested_names_are_file_names() {
        assert_eq!(file_name("a recovery key.txt"), "a recovery key.txt");
        assert_eq!(
            file_name("x/y:z recovery key.txt"),
            "x-y-z recovery key.txt"
        );
        assert_eq!(file_name(" .. "), "BeeZip.txt");
    }
}
