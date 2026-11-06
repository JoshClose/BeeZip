//! The system's code pages, which "auto" reads names in when they aren't UTF-8 (docs/M5.md §6):
//! the OEM code page for zip, as Explorer and 7-Zip read zip names, and the ANSI code page for
//! the other formats. Read once from `HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage`,
//! which any user can read, so no unsafe code is needed. Off Windows, 437 and 1252.

use std::sync::OnceLock;

use beezip_core::{NameDecoding, NameEncoding};

/// `(OEMCP, ACP)`.
pub fn system() -> (u16, u16) {
    static PAGES: OnceLock<(u16, u16)> = OnceLock::new();
    *PAGES.get_or_init(|| {
        let d = NameDecoding::default();
        let (oem, ansi) = read();
        (oem.unwrap_or(d.oem), ansi.unwrap_or(d.ansi))
    })
}

/// How names are read with `encoding`, on this system.
pub fn decoding(encoding: NameEncoding) -> NameDecoding {
    let (oem, ansi) = system();
    NameDecoding {
        encoding,
        oem,
        ansi,
    }
}

#[cfg(windows)]
fn read() -> (Option<u16>, Option<u16>) {
    let Ok(key) =
        windows_registry::LOCAL_MACHINE.open(r"SYSTEM\CurrentControlSet\Control\Nls\CodePage")
    else {
        return (None, None);
    };
    let page = |name: &str| key.get_string(name).ok()?.trim().parse::<u16>().ok();
    (page("OEMCP"), page("ACP"))
}

#[cfg(not(windows))]
fn read() -> (Option<u16>, Option<u16>) {
    (None, None)
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(windows)]
    fn windows_has_code_pages() {
        let (oem, ansi) = super::read();
        assert!(oem.is_some() && ansi.is_some(), "{oem:?} {ansi:?}");
    }
}
