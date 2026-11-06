//! What Windows is (docs/M4.md §5.5), from HKLM values that any user can read.

use windows_registry::LOCAL_MACHINE;

/// `CurrentBuildNumber`: 19045 for Windows 10 22H2, 22000 and up for Windows 11.
pub fn build() -> Option<u32> {
    LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()?
        .get_string("CurrentBuildNumber")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Developer Mode: `AppModelUnlock\AllowDevelopmentWithoutDevLicense`.
pub fn developer_mode() -> bool {
    LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock")
        .and_then(|k| k.get_u32("AllowDevelopmentWithoutDevLicense"))
        .is_ok_and(|v| v != 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_windows_has_a_build() {
        assert!(super::build().is_some_and(|b| b >= 10_240));
    }
}
