//! Whether a folder is on a disk that pays for seeks, a spinning one: parallel extraction gives
//! it one worker when the thread count is left to BeeZip, since small writes side by side make
//! its head seek more (docs/M6.md §6.3).

use std::path::Path;

/// `Some(true)` on a disk that pays for seeks, `Some(false)` on one that doesn't (an SSD), and
/// `None` when the system can't say: a network share, a volume across several disks, or not
/// Windows.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn seek_penalty(path: &Path) -> Option<bool> {
    use std::{
        os::windows::ffi::OsStrExt,
        ptr::{null, null_mut},
    };

    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, GetVolumeNameForVolumeMountPointW,
            GetVolumePathNameW, OPEN_EXISTING,
        },
        System::{
            IO::DeviceIoControl,
            Ioctl::{
                IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_PROPERTY_QUERY,
                StorageDeviceSeekPenaltyProperty,
            },
        },
    };

    /// DEVICE_SEEK_PENALTY_DESCRIPTOR with its BOOLEAN as a byte: windows-sys makes it a
    /// `bool`, which a driver's byte must not be trusted to be.
    #[repr(C)]
    struct SeekPenalty {
        version: u32,
        size: u32,
        incurs: u8,
    }

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut mount = [0u16; 1024];
    // SAFETY: the name is NUL-terminated and the buffer is ours, with its length.
    let ok = unsafe { GetVolumePathNameW(wide.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) };
    if ok == 0 {
        return None;
    }
    // `\\?\Volume{GUID}\` is 49 characters.
    let mut volume = [0u16; 64];
    // SAFETY: `mount` came back NUL-terminated; the buffer is ours, with its length.
    let ok = unsafe {
        GetVolumeNameForVolumeMountPointW(mount.as_ptr(), volume.as_mut_ptr(), volume.len() as u32)
    };
    if ok == 0 {
        return None;
    }
    // The volume's device is its name without the trailing backslash.
    let end = volume.iter().position(|&c| c == 0)?;
    let mut device = volume[..end].to_vec();
    if device.last() == Some(&u16::from(b'\\')) {
        device.pop();
    }
    if device.is_empty() {
        return None;
    }
    device.push(0);
    // SAFETY: a NUL-terminated name. Asking for no access needs no rights; the handle is
    // closed below.
    let handle = unsafe {
        CreateFileW(
            device.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return None;
    }
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceSeekPenaltyProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let mut answer = SeekPenalty {
        version: 0,
        size: 0,
        incurs: 0,
    };
    let mut got = 0u32;
    // SAFETY: the query and the answer are ours, with their sizes; no overlapped I/O.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&raw const query).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            (&raw mut answer).cast(),
            size_of::<SeekPenalty>() as u32,
            &raw mut got,
            null_mut(),
        )
    };
    // SAFETY: the handle is open, and ours.
    unsafe { CloseHandle(handle) };
    let _ = (answer.version, answer.size);
    // The byte is the ninth.
    (ok != 0 && got >= 9).then_some(answer.incurs != 0)
}

#[cfg(not(windows))]
pub fn seek_penalty(_: &Path) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn asking_never_fails() {
        // A local SSD answers Some(false) (this machine's NVMe drive does); the CI runners'
        // virtual disks don't answer at all. Either way the question is safe to ask.
        let dir = std::env::temp_dir();
        let answer = super::seek_penalty(&dir);
        if cfg!(not(windows)) {
            assert_eq!(answer, None);
        }
    }
}
