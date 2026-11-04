//! UnRAR 7.1's structs as `dll.hpp` declares them: under `#pragma pack(push, 1)`.
//!
//! unrar_sys 0.5.8 declares them `#[repr(C)]` only, so every `RARHeaderDataEx` field after
//! `FileAttr` lands at the wrong offset there: `DictSize` reads `HashType`, the times shift, and
//! UnRAR writes a link's target through a `RedirName` pointer taken from the wrong bytes (the
//! M3 spike crashed on a symlink). These copies are packed and passed to unrar_sys's functions
//! by pointer cast (docs/M3.md §3.4, §11).

use std::os::raw::{c_char, c_uint};

pub use unrar_sys::{Callback, LPARAM, UINT, WCHAR};

/// `struct RARHeaderDataEx`.
#[repr(C, packed)]
pub struct HeaderDataEx {
    pub arc_name: [c_char; 1024],
    pub arc_name_w: [WCHAR; 1024],
    pub file_name: [c_char; 1024],
    pub file_name_w: [WCHAR; 1024],
    pub flags: c_uint,
    pub pack_size: c_uint,
    pub pack_size_high: c_uint,
    pub unp_size: c_uint,
    pub unp_size_high: c_uint,
    pub host_os: c_uint,
    pub file_crc: c_uint,
    pub file_time: c_uint,
    pub unp_ver: c_uint,
    pub method: c_uint,
    pub file_attr: c_uint,
    pub cmt_buf: *mut c_char,
    pub cmt_buf_size: c_uint,
    pub cmt_size: c_uint,
    pub cmt_state: c_uint,
    pub dict_size: c_uint,
    pub hash_type: c_uint,
    pub hash: [u8; 32],
    pub redir_type: c_uint,
    pub redir_name: *mut WCHAR,
    pub redir_name_size: c_uint,
    pub dir_target: c_uint,
    pub mtime_low: c_uint,
    pub mtime_high: c_uint,
    pub ctime_low: c_uint,
    pub ctime_high: c_uint,
    pub atime_low: c_uint,
    pub atime_high: c_uint,
    pub arc_name_ex: *mut WCHAR,
    pub arc_name_ex_size: c_uint,
    pub file_name_ex: *mut WCHAR,
    pub file_name_ex_size: c_uint,
    pub reserved: [c_uint; 982],
}

/// `struct RAROpenArchiveDataEx`.
#[repr(C, packed)]
pub struct OpenArchiveDataEx {
    pub arc_name: *const c_char,
    pub arc_name_w: *const WCHAR,
    pub open_mode: c_uint,
    pub open_result: c_uint,
    pub cmt_buf: *mut c_char,
    pub cmt_buf_size: c_uint,
    pub cmt_size: c_uint,
    pub cmt_state: c_uint,
    pub flags: c_uint,
    pub callback: Option<Callback>,
    pub user_data: LPARAM,
    pub op_flags: c_uint,
    pub cmt_buf_w: *mut WCHAR,
    pub reserved: [c_uint; 25],
}

const WCHAR_SIZE: usize = std::mem::size_of::<WCHAR>();

// 10 244 bytes with Windows' 16-bit wchar_t, 14 340 with the 32-bit one Linux has. Every
// pointer is 8 bytes on the 64-bit targets BeeZip builds for.
const _: () = assert!(std::mem::size_of::<*const u8>() == 8);
const _: () = assert!(
    std::mem::size_of::<HeaderDataEx>() == 1024 * 2 + 1024 * 2 * WCHAR_SIZE + 4100,
    "RARHeaderDataEx is laid out as dll.hpp declares it"
);
const _: () = assert!(WCHAR_SIZE != 2 || std::mem::size_of::<HeaderDataEx>() == 10_244);
const _: () = assert!(WCHAR_SIZE != 4 || std::mem::size_of::<HeaderDataEx>() == 14_340);
const _: () = assert!(std::mem::size_of::<OpenArchiveDataEx>() == 176);

pub const RAR_OM_LIST: c_uint = 0;
pub const RAR_OM_EXTRACT: c_uint = 1;

pub const RAR_SKIP: i32 = 0;
pub const RAR_TEST: i32 = 1;

pub const RAR_VOL_ASK: LPARAM = 0;

pub const UCM_CHANGEVOLUME: UINT = 0;
pub const UCM_PROCESSDATA: UINT = 1;
pub const UCM_NEEDPASSWORD: UINT = 2;
pub const UCM_CHANGEVOLUMEW: UINT = 3;
pub const UCM_NEEDPASSWORDW: UINT = 4;
pub const UCM_LARGEDICT: UINT = 5;

/// `RAROpenArchiveEx` through unrar_sys's declaration.
///
/// # Safety
/// `data` must point at a valid, packed `RAROpenArchiveDataEx`, and the strings, buffers and
/// callback state it names must outlive the handle.
pub unsafe fn open(data: *mut OpenArchiveDataEx) -> *const unrar_sys::Handle {
    // SAFETY: the caller's contract; the layout is dll.hpp's.
    unsafe { unrar_sys::RAROpenArchiveEx(data.cast()) }
}

/// `RARReadHeaderEx` through unrar_sys's declaration.
///
/// # Safety
/// `h` must be an open handle and `data` a valid, packed `RARHeaderDataEx` whose buffers are
/// as large as it says.
pub unsafe fn read_header(h: *const unrar_sys::Handle, data: *mut HeaderDataEx) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { unrar_sys::RARReadHeaderEx(h, data.cast()) }
}

/// `RARProcessFileW` with no destination: BeeZip only tests or skips, so UnRAR never creates a
/// file and none of its own path handling runs.
///
/// # Safety
/// `h` must be an open handle.
pub unsafe fn process(h: *const unrar_sys::Handle, op: i32) -> i32 {
    // SAFETY: the caller's contract; null paths are allowed for RAR_TEST and RAR_SKIP.
    unsafe { unrar_sys::RARProcessFileW(h, op, std::ptr::null(), std::ptr::null()) }
}

/// `RARCloseArchive`.
///
/// # Safety
/// `h` must be an open handle, and isn't used again.
pub unsafe fn close(h: *const unrar_sys::Handle) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { unrar_sys::RARCloseArchive(h) }
}
