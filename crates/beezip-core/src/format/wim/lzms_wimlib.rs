//! LZMS chunks on Linux and macOS through wimlib's library (docs/M11.md §6.2), loaded at run
//! time the way `lzms_win.rs` loads `cabinet.dll` on Windows. wimlib's public compression API
//! (`wimlib.h`: `wimlib_create_decompressor`, `wimlib_decompress`, `wimlib_free_decompressor`)
//! decodes a WIM's or an ESD's chunk as stored, given its exact size, one decoder per worker.
//! Nothing of wimlib is built into BeeZip: it's the system's own library (LGPLv3+), found by its
//! soname on Linux and in Homebrew's and MacPorts' folders on macOS, and loaded only when an
//! LZMS image is read. Without it, an LZMS image is `UnsupportedOperation`, saying how to
//! install it.
#![allow(unsafe_code)]

use std::{
    ffi::{CStr, c_int, c_void},
    sync::OnceLock,
};

use crate::Error;

/// `WIMLIB_COMPRESSION_TYPE_LZMS`.
const LZMS: c_int = 3;
/// The largest chunk LZMS allows (wimlib's limit too).
pub const MAX_CHUNK: usize = 1 << 30;

type CreateFn = unsafe extern "C" fn(c_int, usize, *mut *mut c_void) -> c_int;
type DecompressFn =
    unsafe extern "C" fn(*const c_void, usize, *mut c_void, usize, *mut c_void) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);

struct Api {
    create: CreateFn,
    decompress: DecompressFn,
    free: FreeFn,
}

#[cfg(target_os = "macos")]
const NAMES: &[&CStr] = &[
    c"/opt/homebrew/lib/libwim.15.dylib",
    c"/usr/local/lib/libwim.15.dylib",
    c"/opt/local/lib/libwim.15.dylib",
];
#[cfg(not(target_os = "macos"))]
const NAMES: &[&CStr] = &[c"libwim.so.15"];

/// The library, once loaded; `None` when it isn't installed.
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        for name in NAMES {
            // SAFETY: a NUL-terminated name; the handle is never closed.
            let h = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if h.is_null() {
                continue;
            }
            // SAFETY: the library is loaded and stays loaded; the names are NUL-terminated.
            let sym = |s: &CStr| unsafe { libc::dlsym(h, s.as_ptr()) };
            let (c, d, f) = (
                sym(c"wimlib_create_decompressor"),
                sym(c"wimlib_decompress"),
                sym(c"wimlib_free_decompressor"),
            );
            if c.is_null() || d.is_null() || f.is_null() {
                continue;
            }
            // SAFETY: wimlib.h's signatures for these three functions.
            return Some(unsafe {
                Api {
                    create: std::mem::transmute::<*mut c_void, CreateFn>(c),
                    decompress: std::mem::transmute::<*mut c_void, DecompressFn>(d),
                    free: std::mem::transmute::<*mut c_void, FreeFn>(f),
                }
            });
        }
        None
    })
    .as_ref()
}

fn unavailable() -> Error {
    Error::unsupported(if cfg!(target_os = "macos") {
        "wim: LZMS, which BeeZip decodes through wimlib; install it (`brew install wimlib`)"
    } else {
        "wim: LZMS, which BeeZip decodes through wimlib's library; install it (on Debian and \
         Ubuntu `apt install wimtools`, on Fedora `dnf install wimlib`)"
    })
}

pub fn available() -> bool {
    LzmsDecoder::new().is_ok()
}

/// One decoder, for one worker at a time.
pub struct LzmsDecoder {
    handle: *mut c_void,
}

// SAFETY: a decoder may move to another thread; it's never used by two at once (no `Sync`).
unsafe impl Send for LzmsDecoder {}

impl LzmsDecoder {
    pub fn new() -> Result<Self, Error> {
        let api = api().ok_or_else(unavailable)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: `handle` is written on success.
        let rc = unsafe { (api.create)(LZMS, MAX_CHUNK, &mut handle) };
        if rc != 0 || handle.is_null() {
            return Err(unavailable());
        }
        Ok(Self { handle })
    }

    /// Decodes one raw chunk into exactly `out.len()` bytes.
    pub fn decode(&mut self, input: &[u8], out: &mut [u8]) -> Result<(), Error> {
        if out.len() > MAX_CHUNK {
            return Err(Error::corrupt(format!(
                "wim: an LZMS chunk of {} bytes, more than LZMS allows",
                out.len()
            )));
        }
        if input.is_empty() || out.is_empty() {
            return Err(Error::corrupt("wim: an empty LZMS chunk"));
        }
        let api = api().ok_or_else(unavailable)?;
        // SAFETY: both buffers are valid for their lengths; the decoder is this one's, used by
        // one thread at a time.
        let rc = unsafe {
            (api.decompress)(
                input.as_ptr().cast(),
                input.len(),
                out.as_mut_ptr().cast(),
                out.len(),
                self.handle,
            )
        };
        if rc != 0 {
            return Err(Error::corrupt("wim: an LZMS chunk doesn't decode"));
        }
        Ok(())
    }
}

impl Drop for LzmsDecoder {
    fn drop(&mut self) {
        if let Some(api) = api() {
            // SAFETY: made by `create`, freed once.
            unsafe { (api.free)(self.handle) };
        }
    }
}
