//! Stands in for `BeeZip.exe` when tests and manual checks click the menu (docs/M4.md §10). It
//! records its arguments, the job request it was given and the package identity it runs with,
//! then deletes the request as BeeZip would:
//! `{ "args": [...], "request": "<the file's text>", "package": "BeeZip_…" | null }` goes to
//! `stub_app-<pid>.json` in `BEEZIP_STUB_OUT`, or beside the executable. A click on Windows 11's
//! menu starts it with the package's identity (§16, item 8); a click on the classic menu without.
#![allow(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = match args.as_slice() {
        [flag, file] if flag == "--job" => {
            let text = std::fs::read_to_string(file).ok();
            let _ = std::fs::remove_file(file);
            text
        }
        _ => None,
    };
    let dir = std::env::var_os("BEEZIP_STUB_OUT")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok()?.parent().map(Into::into))
        .unwrap_or_default();
    let out = serde_json::json!({ "args": args, "request": request, "package": package() });
    let path = dir.join(format!("stub_app-{}.json", std::process::id()));
    // Written under another name first, so a reader never sees half a file.
    let partial = path.with_extension("partial");
    if std::fs::write(&partial, out.to_string()).is_ok() {
        let _ = std::fs::rename(&partial, &path);
    }
}

/// This process's package full name, when it has an identity.
#[cfg(windows)]
fn package() -> Option<String> {
    use windows::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
    use windows_core::PWSTR;

    let mut buf = vec![0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `len` is the buffer's length in u16s, and the call writes at most that many.
    let err = unsafe { GetCurrentPackageFullName(&mut len, Some(PWSTR(buf.as_mut_ptr()))) };
    if err.is_err() || len == 0 {
        return None; // APPMODEL_ERROR_NO_PACKAGE: no identity
    }
    let n = (len as usize - 1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

#[cfg(not(windows))]
fn package() -> Option<String> {
    None
}
