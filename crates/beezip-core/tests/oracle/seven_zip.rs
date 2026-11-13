//! 7-Zip as a test oracle (docs/M11.md §7): BeeZip never runs it, but tests compare BeeZip's
//! reading and writing with what it extracts. Included by the tests that need it
//! (`#[path = "oracle/seven_zip.rs"] mod seven_zip;`).

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// An installed 7-Zip: its console program and what its banner says ("7-Zip 26.00").
#[derive(Debug, Clone)]
pub struct SevenZip {
    pub exe: PathBuf,
    pub name: String,
}

/// 7-Zip, from `BEEZIP_7Z`, then `7z`, `7zz` or `7za` on PATH, then 7-Zip's own folder on
/// Windows; `None` when there's none that runs. With `BEEZIP_REQUIRE_7Z` set to 1 (CI on
/// Windows), a missing one fails the test instead.
pub fn find() -> Option<SevenZip> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("BEEZIP_7Z") {
        candidates.push(PathBuf::from(p));
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in ["7z", "7zz", "7za"] {
                let exe = dir
                    .join(name)
                    .with_extension(std::env::consts::EXE_EXTENSION);
                candidates.push(exe);
            }
        }
    }
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
            if let Some(dir) = std::env::var_os(var) {
                candidates.push(Path::new(&dir).join("7-Zip").join("7z.exe"));
            }
        }
    }
    let found = candidates
        .into_iter()
        .filter(|p| p.is_file())
        .find_map(|exe| {
            let out = Command::new(&exe).arg("i").output().ok()?;
            let text = String::from_utf8_lossy(&out.stdout);
            let line = text.lines().find(|l| l.trim_start().starts_with("7-Zip"))?;
            let name = line
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");
            Some(SevenZip { exe, name })
        });
    if found.is_none() && std::env::var("BEEZIP_REQUIRE_7Z").as_deref() == Ok("1") {
        panic!("this test compares with 7-Zip, and there's none (BEEZIP_REQUIRE_7Z=1)");
    }
    found
}
