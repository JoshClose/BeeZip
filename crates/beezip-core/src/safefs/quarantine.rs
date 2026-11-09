//! macOS's quarantine (docs/M6.md §8.3), [`motw`](super::motw)'s counterpart. A browser marks
//! what it downloads with a `com.apple.quarantine` extended attribute, and Gatekeeper checks a
//! marked app before it first runs. Archive Utility copies the archive's attribute to every file
//! it extracts, so an app that came in a download is still checked; BeeZip does the same. The
//! value (`flags;time;agent;id`) is copied as it is. Elsewhere there's nothing to read or write.

use std::{io, path::Path};

/// The attribute's name.
#[cfg(target_os = "macos")]
const NAME: &std::ffi::CStr = c"com.apple.quarantine";

/// A value longer than this isn't a quarantine record (they're about 60 bytes).
#[cfg(target_os = "macos")]
const MAX: usize = 4096;

/// `path`'s quarantine record, if it has one.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn read(path: &Path) -> Option<Vec<u8>> {
    let path = c_path(path).ok()?;
    let mut buf = vec![0u8; MAX];
    // SAFETY: `path` and `NAME` are NUL-terminated, and `buf` holds `buf.len()` bytes.
    let got = unsafe {
        libc::getxattr(
            path.as_ptr(),
            NAME.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            0,
        )
    };
    let got = usize::try_from(got).ok().filter(|&n| n > 0)?;
    buf.truncate(got);
    Some(buf)
}

/// Gives `path` the quarantine record `value`.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn write(path: &Path, value: &[u8]) -> io::Result<()> {
    let path = c_path(path)?;
    // SAFETY: `path` and `NAME` are NUL-terminated, and `value` holds `value.len()` bytes.
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            NAME.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path with a NUL byte"))
}

/// Nothing marks downloads here.
#[cfg(not(target_os = "macos"))]
pub fn read(_path: &Path) -> Option<Vec<u8>> {
    None
}

/// Nothing marks downloads here.
#[cfg(not(target_os = "macos"))]
pub fn write(_path: &Path, _value: &[u8]) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn quarantine_records_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.zip");
        std::fs::write(&file, b"zip").unwrap();
        assert_eq!(read(&file), None);
        let record = b"0083;6912f0a1;Safari;3F8C1B9E-4C1A-4E5B-9E0F-1D2C3B4A5968";
        write(&file, record).unwrap();
        assert_eq!(read(&file).as_deref(), Some(&record[..]));
        // The data is untouched.
        assert_eq!(std::fs::read(&file).unwrap(), b"zip");
        assert_eq!(read(&dir.path().join("missing")), None);
    }
}
