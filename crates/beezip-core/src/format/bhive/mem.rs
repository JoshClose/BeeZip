//! How much memory the machine has: the writer keeps cells in flight within a share of it, and
//! the reader its decoded cells (docs/M13.md §3). xz's preset 9 takes 674 MiB a cell to
//! compress; thirty-two of those at once isn't a thing to do on a 16 GiB machine.

/// The machine's physical memory in bytes, when the system says.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn physical() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..MEMORYSTATUSEX::default()
    };
    // SAFETY: the struct is ours and `dwLength` is its size, as the call expects.
    let ok = unsafe { GlobalMemoryStatusEx(&raw mut status) };
    (ok != 0 && status.ullTotalPhys > 0).then_some(status.ullTotalPhys)
}

/// Linux: `MemTotal` of `/proc/meminfo`.
#[cfg(target_os = "linux")]
pub fn physical() -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib = info
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    (kib > 0).then_some(kib * 1024)
}

/// macOS: `hw.memsize`.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn physical() -> Option<u64> {
    let mut size = 0u64;
    let mut len = size_of::<u64>();
    // SAFETY: the name is a C string, and the value and its length are ours and of the size
    // `hw.memsize` has; nothing is set.
    let rc = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&raw mut size).cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == size_of::<u64>() && size > 0).then_some(size)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn physical() -> Option<u64> {
    None
}

/// The memory a job's cells may take when nobody set it: a quarter of the machine's, at least
/// 512 MiB, and 2 GiB when the machine doesn't say.
pub fn budget() -> u64 {
    physical().map_or(2 << 30, |total| (total / 4).max(512 << 20))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every system BeeZip is built for says how much memory it has.
    #[test]
    fn the_machine_says_how_much_memory_it_has() {
        let total = physical().expect("physical memory");
        assert!(total > 256 << 20, "{total}");
        assert!(total < 1 << 50, "{total}");
        assert!(budget() >= 512 << 20);
    }
}
