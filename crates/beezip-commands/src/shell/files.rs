//! DLLs left behind (docs/M4.md §5.6). While `explorer.exe` has a DLL loaded it can't be deleted,
//! but it can be moved within its volume, and the moved copy goes once the process lets go. So
//! every `beezip_shell_*.dll` in the folder but the one in use is:
//! 1. deleted;
//! 2. failing that, moved to `%TEMP%\BeeZip-shell-<random>.dll`;
//! 3. if the move fails too, left in place;
//!
//! and for any file left behind, an HKCU `RunOnce` value deletes it at the next sign-in. That
//! lets an uninstall remove the install folder even while Explorer holds the DLL.

use std::hash::{BuildHasher, RandomState};
use std::path::{Path, PathBuf};

use windows_registry::CURRENT_USER;

use super::{Hive, is_dll_name, reg_error};
use crate::CmdError;

const RUN_ONCE: &str = r"Microsoft\Windows\CurrentVersion\RunOnce";

/// Cleans `dir` of every DLL but `keep`. Returns what it did.
pub fn clean(hive: &Hive, dir: &Path, keep: Option<&Path>) -> Result<Vec<String>, CmdError> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let keep = keep.map(normalise);
    let mut actions = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !is_dll_name(&entry.file_name().to_string_lossy())
            || !path.is_file()
            || keep.as_deref() == Some(&*normalise(&path))
        {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            actions.push(format!("deleted {}", path.display()));
            continue;
        }
        let moved = moved_name();
        let left = if std::fs::rename(&path, &moved).is_ok() {
            if std::fs::remove_file(&moved).is_ok() {
                actions.push(format!("deleted {}", path.display()));
                continue;
            }
            actions.push(format!(
                "moved {} to {}, which is in use; it goes at the next sign-in",
                path.display(),
                moved.display()
            ));
            moved
        } else {
            actions.push(format!(
                "left {}, which is in use; it goes at the next sign-in",
                path.display()
            ));
            path
        };
        delete_at_sign_in(hive, &left)?;
    }
    Ok(actions)
}

/// A free name in `%TEMP%`, on the system volume like the install folder.
fn moved_name() -> PathBuf {
    let n = RandomState::new().hash_one(std::time::SystemTime::now());
    std::env::temp_dir().join(format!("BeeZip-shell-{n:016x}.dll"))
}

fn normalise(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

/// An HKCU `RunOnce` value that deletes `path` at the next sign-in.
fn delete_at_sign_in(hive: &Hive, path: &Path) -> Result<(), CmdError> {
    let key = CURRENT_USER
        .create(hive.key(RUN_ONCE))
        .map_err(|e| reg_error("asking Windows to delete an old DLL", &e))?;
    let name = format!(
        "BeeZip-shell-{:016x}",
        RandomState::new().hash_one(path.as_os_str())
    );
    key.set_string(
        name,
        format!("cmd.exe /d /c del /f /q \"{}\"", path.display()),
    )
    .map_err(|e| reg_error("asking Windows to delete an old DLL", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletes_every_dll_but_the_one_kept() {
        let hive = Hive::test("files");
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("beezip_shell_0.1.1.dll");
        for name in [
            "beezip_shell_0.1.0.dll",
            "beezip_shell_0.1.1.dll",
            "beezip_shell.dll",
            "notes.txt",
        ] {
            std::fs::write(dir.path().join(name), "").unwrap();
        }
        let actions = clean(&hive, dir.path(), Some(&keep)).unwrap();
        assert_eq!(actions.len(), 1, "{actions:?}");
        assert!(actions[0].starts_with("deleted"), "{actions:?}");
        assert!(keep.is_file());
        assert!(dir.path().join("notes.txt").is_file());
        assert!(
            dir.path().join("beezip_shell.dll").is_file(),
            "cargo's output stays"
        );
        assert!(!dir.path().join("beezip_shell_0.1.0.dll").exists());
        assert!(CURRENT_USER.open(hive.key(RUN_ONCE)).is_err());
    }

    #[test]
    fn a_file_in_use_is_moved_and_deleted_at_sign_in() {
        let hive = Hive::test("files-locked");
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("beezip_shell_0.1.0.dll");
        std::fs::write(&old, "").unwrap();
        // An open handle without FILE_SHARE_DELETE stands in for Explorer's loaded image: the
        // file can't be deleted or moved, so it stays and RunOnce gets it.
        let held = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1) // FILE_SHARE_READ
                .open(&old)
                .unwrap()
        };
        let actions = clean(&hive, dir.path(), None).unwrap();
        assert!(actions[0].starts_with("left"), "{actions:?}");
        let key = CURRENT_USER.open(hive.key(RUN_ONCE)).unwrap();
        let values: Vec<String> = key
            .values()
            .unwrap()
            .map(|(_, v)| String::try_from(v).unwrap_or_default())
            .collect();
        assert_eq!(
            values,
            [format!("cmd.exe /d /c del /f /q \"{}\"", old.display())]
        );
        drop(held);
        let _ = CURRENT_USER.remove_tree(hive.base());
    }
}
