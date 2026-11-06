//! A click (docs/M4.md §4.3): write the job request, start BeeZip with `--job <file>`, and pass
//! on the right to come to the front. No archive work ever runs in Explorer.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::hash::{BuildHasher, RandomState};
use std::io::{ErrorKind, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use beezip_menu::{Item, JobRequest};
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows::Win32::UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow};
use windows_core::{HRESULT, PCWSTR, Result};

use crate::settings::Settings;

/// Where requests go: `%TEMP%\BeeZip\jobs`, the folder BeeZip accepts them from.
pub fn jobs_dir() -> PathBuf {
    std::env::temp_dir().join("BeeZip").join("jobs")
}

pub fn run(item: Item, paths: Vec<PathBuf>, settings: &Settings) -> Result<()> {
    let json = JobRequest::new(item, paths)
        .to_json()
        .map_err(|_| windows_core::Error::from(E_INVALIDARG))?;
    let app = settings
        .app
        .clone()
        .or_else(beside_dll)
        .ok_or_else(|| windows_core::Error::from(E_FAIL))?;
    let file = write_new(&jobs_dir(), &json).map_err(io_error)?;
    // Pass on the right to come to the front. Naming the child doesn't work: it can't be named
    // until it has started (`ERROR_INVALID_PARAMETER` right after the spawn), and when BeeZip is
    // already running the child only hands the job over, which a right it never got can't
    // follow (§16, PR 4 item 15). So any process may take the front until the user's next input.
    // SAFETY: plain call; failing only means the window may open behind.
    let allowed = unsafe { AllowSetForegroundWindow(ASFW_ANY) };
    crate::log::line(|| format!("AllowSetForegroundWindow(ASFW_ANY) -> {allowed:?}"));
    let child = Command::new(&app)
        .arg("--job")
        .arg(&file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(_) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&file);
            Err(io_error(e))
        }
    }
}

/// Writes `text` to a new `<random>.json` in `dir`, never over an existing file.
fn write_new(dir: &Path, text: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let random = RandomState::new();
    for attempt in 0u32..16 {
        let a = random.hash_one((std::process::id(), attempt, std::time::SystemTime::now()));
        let b = RandomState::new().hash_one(a);
        let path = dir.join(format!("{a:016x}{b:016x}.json"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(text.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(ErrorKind::AlreadyExists.into())
}

fn io_error(e: std::io::Error) -> windows_core::Error {
    match e.raw_os_error() {
        Some(code) => HRESULT::from_win32(code as u32).into(),
        None => E_FAIL.into(),
    }
}

/// `BeeZip.exe` in the DLL's folder: the installed layout, when the settings don't name the app.
fn beside_dll() -> Option<PathBuf> {
    let dll = dll_path()?;
    let app = dll.parent()?.join("BeeZip.exe");
    app.is_file().then_some(app)
}

/// This DLL's own path.
pub fn dll_path() -> Option<PathBuf> {
    let mut module = HMODULE::default();
    // SAFETY: FROM_ADDRESS takes any address inside the module, here a function of ours, and
    // UNCHANGED_REFCOUNT leaves the module's count alone, so nothing needs freeing.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(dll_path as *const u16),
            &mut module,
        )
    }
    .ok()?;
    let mut buf = vec![0u16; 32 * 1024];
    // SAFETY: `module` is this DLL, loaded while this code runs; the buffer is ours.
    let n = unsafe { GetModuleFileNameW(Some(module), &mut buf) } as usize;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(OsString::from_wide(&buf[..n])))
}
