//! `beezip 7zip install` end to end, with a stand-in winget (`BEEZIP_WINGET`) and the 7-Zip
//! search pointed at a scratch folder (`BEEZIP_7Z_SEARCH`), so nothing is installed and the
//! machine's own 7-Zip is never touched. Both overrides are for debug builds only.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

fn beezip(search: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_beezip"));
    c.env("BEEZIP_CONFIG", "no-such-beezip-config.toml")
        .env("BEEZIP_7Z_SEARCH", search);
    c
}

/// What the command printed as JSON, and its exit code.
fn install(search: &Path, winget: &Path) -> (i32, Value) {
    let out = beezip(search)
        .env("BEEZIP_WINGET", winget)
        .args(["7zip", "install", "--output", "json"])
        .output()
        .unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap(), json)
}

fn formats(search: &Path, winget: &Path) -> Value {
    let out = beezip(search)
        .env("BEEZIP_WINGET", winget)
        .args(["formats", "--output", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    serde_json::from_slice::<Value>(&out.stdout).unwrap()["seven_zip"].clone()
}

#[test]
fn no_winget_points_to_the_download_page() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out) = install(dir.path(), &dir.path().join("no-winget.exe"));
    assert_eq!(code, 5, "{out}");
    let message = out["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("https://7-zip.org/download.html"),
        "{message}"
    );
    assert_eq!(
        out["error"]["details"]["url"],
        "https://7-zip.org/download.html"
    );
    let status = formats(dir.path(), &dir.path().join("no-winget.exe"));
    assert_eq!(status["fix"], "download", "{status}");
    assert_eq!(status["name"], Value::Null);
}

/// A stand-in winget: it records its arguments beside itself, prints `lines`, copies the
/// files in `copies` (a stand-in for installing), and exits with `exit`.
#[cfg(windows)]
fn fake_winget(dir: &Path, lines: &[&str], copies: &[(PathBuf, PathBuf)], exit: u32) -> PathBuf {
    let mut body = String::from("@echo off\r\necho %*> \"%~dp0args.txt\"\r\n");
    for l in lines {
        body += &format!("echo {l}\r\n");
    }
    for (from, to) in copies {
        body += &format!(
            "copy /y \"{}\" \"{}\" >nul\r\n",
            from.display(),
            to.display()
        );
    }
    body += &format!("exit /b {}\r\n", exit.cast_signed());
    let exe = dir.join("winget.cmd");
    std::fs::write(&exe, body).unwrap();
    exe
}

#[cfg(windows)]
fn args_given(winget: &Path) -> Option<String> {
    std::fs::read_to_string(winget.with_file_name("args.txt"))
        .ok()
        .map(|s| s.trim().to_owned())
}

/// The machine's 7-Zip, through `beezip formats` with no override, to stand in for one winget
/// installs. `BEEZIP_REQUIRE_7Z=1` (CI) fails without one.
#[cfg(windows)]
fn real_seven_zip() -> Option<PathBuf> {
    let out = Command::new(env!("CARGO_BIN_EXE_beezip"))
        .env("BEEZIP_CONFIG", "no-such-beezip-config.toml")
        .env_remove("BEEZIP_7Z_SEARCH")
        .args(["formats", "--output", "json"])
        .output()
        .unwrap();
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    let path = json["seven_zip"]["path"].as_str().map(PathBuf::from);
    if path.is_none() {
        assert!(
            std::env::var("BEEZIP_REQUIRE_7Z").as_deref() != Ok("1"),
            "BEEZIP_REQUIRE_7Z=1, and there's no 7-Zip"
        );
        eprintln!("no 7-Zip here: skipping the install that makes one appear");
    }
    path
}

#[cfg(windows)]
#[test]
fn install_runs_winget_and_finds_what_it_installed() {
    let search = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let Some(real) = real_seven_zip() else { return };
    let real_dir = real.parent().unwrap();
    let copies = [
        (real.clone(), search.path().join("7z.exe")),
        (real_dir.join("7z.dll"), search.path().join("7z.dll")),
    ];
    let winget = fake_winget(
        bin.path(),
        &[
            "Found 7-Zip [7zip.7zip] Version 26.06",
            "Successfully installed",
        ],
        &copies,
        0,
    );
    assert_eq!(formats(search.path(), &winget)["fix"], "install");

    let (code, out) = install(search.path(), &winget);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        args_given(&winget).as_deref(),
        Some(
            "install --id 7zip.7zip --exact --source winget --accept-package-agreements \
             --accept-source-agreements --disable-interactivity"
        )
    );
    assert_eq!(out["action"], "installed");
    assert!(
        out["status"]["name"]
            .as_str()
            .unwrap()
            .starts_with("7-Zip "),
        "{out}"
    );
    assert_eq!(out["status"]["fix"], Value::Null);

    // Now it's there: nothing to do, and winget isn't run.
    std::fs::remove_file(bin.path().join("args.txt")).unwrap();
    let (code, out) = install(search.path(), &winget);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["action"], "none");
    assert_eq!(args_given(&winget), None);

    // The human line.
    let human = beezip(search.path())
        .env("BEEZIP_WINGET", &winget)
        .args(["7zip", "install"])
        .output()
        .unwrap();
    let said = String::from_utf8(human.stdout).unwrap();
    assert!(
        said.trim_end().ends_with("is new enough; nothing to do."),
        "{said}"
    );
}

#[cfg(windows)]
#[test]
fn winget_that_installs_nothing_usable_is_an_error() {
    let search = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let winget = fake_winget(bin.path(), &["Successfully installed"], &[], 0);
    let (code, out) = install(search.path(), &winget);
    assert_eq!(code, 12, "{out}");
    assert_eq!(out["error"]["code"], "BackendUnavailable");
    assert_eq!(
        out["error"]["message"],
        "winget finished, but BeeZip still finds no 7-Zip it can use: not found."
    );
}

#[cfg(windows)]
#[test]
fn a_declined_prompt_is_a_cancel_and_a_failure_names_wingets_code() {
    let search = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let winget = fake_winget(
        bin.path(),
        &["Starting package install..."],
        &[],
        0x8A15_010C,
    );
    let (code, out) = install(search.path(), &winget);
    assert_eq!(code, 130, "{out}");
    assert_eq!(out["error"]["code"], "Cancelled");
    assert!(
        out["error"]["message"]
            .as_str()
            .unwrap()
            .contains("declined"),
        "{out}"
    );

    let winget = fake_winget(
        bin.path(),
        &["Downloading https://example.invalid/7z.msi"],
        &[],
        0x8A15_0008,
    );
    let (code, out) = install(search.path(), &winget);
    assert_eq!(code, 13, "{out}");
    assert_eq!(out["error"]["details"]["winget_exit"], "0x8A150008");

    // The log reaches stderr as winget's lines come.
    let human = beezip(search.path())
        .env("BEEZIP_WINGET", &winget)
        .args(["7zip", "install"])
        .output()
        .unwrap();
    let err = String::from_utf8(human.stderr).unwrap();
    assert!(
        err.contains("info: Downloading https://example.invalid/7z.msi"),
        "{err}"
    );
    assert!(err.contains("error[Io]: winget couldn't download"), "{err}");
}

/// A file BeeZip's own readers refuse, which goes to 7-Zip: an AES-encrypted QCOW2 (BeeZip reads
/// 7-Zip's CramFS variant itself since M11, docs/M11.md §6.1).
fn sevenzip_only() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty/vdisk/q-aes.qcow2")
}

/// What `beezip list` on that image says without 7-Zip, with `winget` as the winget there is.
fn list_error(search: &Path, winget: &Path) -> String {
    let out = beezip(search)
        .env("BEEZIP_WINGET", winget)
        .arg("list")
        .arg(sevenzip_only())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(12));
    String::from_utf8(out.stderr).unwrap()
}

#[test]
fn without_winget_the_error_names_no_install_command() {
    let dir = tempfile::tempdir().unwrap();
    let err = list_error(dir.path(), &dir.path().join("no-winget.exe"));
    assert!(err.contains("needs 7-Zip 25.01 or newer"), "{err}");
    assert!(!err.contains("beezip 7zip install"), "{err}");
}

#[cfg(windows)]
#[test]
fn with_winget_the_error_names_the_install_command() {
    let search = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let winget = fake_winget(bin.path(), &[], &[], 0);
    let err = list_error(search.path(), &winget);
    assert!(
        err.trim_end().ends_with(
            "or set its path in Settings. `beezip 7zip install` installs it with winget."
        ),
        "{err}"
    );
    // Asking changed nothing: winget wasn't run.
    assert_eq!(args_given(&winget), None);
}
