//! LZMS chunks through Windows' own decoder (docs/M8.md §5.3, decision 9): the Compression API
//! of `cabinet.dll` (Windows 8 and later), in block mode (`COMPRESS_ALGORITHM_LZMS |
//! COMPRESS_RAW`), which decodes a WIM's or an ESD's chunk as stored when it's given the chunk's
//! exact size. LZMS has no public specification, and every other decoder found is LGPL, a port
//! of wimlib's, or taken from disassembling Windows.
//!
//! - **Loading:** `cabinet.dll` isn't a KnownDLL, so a load-time import would be looked for in
//!   the application's folder first. It's loaded at run time from System32 only
//!   (`LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_SYSTEM32`), the first time an LZMS image is
//!   read, and stays loaded.
//! - **Threads:** a decoder used by two threads at once crashes (tested in the M8 spike), so
//!   [`LzmsDecoder`] is `Send` and not `Sync`: one per worker.
//! - **Damage:** the API sometimes decodes damaged input "successfully" to wrong bytes, so every
//!   blob's SHA-1 is checked; what it refuses is `Corrupt`. Chunks over 1 GiB, which it refuses at
//!   once, aren't passed to it.
#![allow(unsafe_code)]

use std::{ffi::c_void, sync::OnceLock};

use windows_sys::Win32::{
    Foundation::GetLastError,
    System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
};

use crate::Error;

const COMPRESS_ALGORITHM_LZMS: u32 = 5;
const COMPRESS_RAW: u32 = 0x2000_0000;
/// The largest chunk the API decodes; past it `Decompress` fails at once.
pub const MAX_CHUNK: usize = 1 << 30;

type CreateFn = unsafe extern "system" fn(u32, *const c_void, *mut isize) -> i32;
type DecompressFn =
    unsafe extern "system" fn(isize, *const c_void, usize, *mut c_void, usize, *mut usize) -> i32;
type CloseFn = unsafe extern "system" fn(isize) -> i32;

struct Api {
    create: CreateFn,
    decompress: DecompressFn,
    close: CloseFn,
}

/// The API, once loaded; `None` when `cabinet.dll` or its functions aren't there.
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        let name: Vec<u16> = "cabinet.dll\0".encode_utf16().collect();
        // SAFETY: the name is NUL-terminated UTF-16; no file handle; System32 only.
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return None;
        }
        // SAFETY: the module is loaded (and never freed); the names are NUL-terminated.
        let (create, decompress, close) = unsafe {
            (
                GetProcAddress(module, c"CreateDecompressor".as_ptr().cast())?,
                GetProcAddress(module, c"Decompress".as_ptr().cast())?,
                GetProcAddress(module, c"CloseDecompressor".as_ptr().cast())?,
            )
        };
        type Proc = unsafe extern "system" fn() -> isize;
        // SAFETY: the Compression API's documented signatures (compressapi.h).
        unsafe {
            Some(Api {
                create: std::mem::transmute::<Proc, CreateFn>(create),
                decompress: std::mem::transmute::<Proc, DecompressFn>(decompress),
                close: std::mem::transmute::<Proc, CloseFn>(close),
            })
        }
    })
    .as_ref()
}

fn unavailable() -> Error {
    Error::unsupported(
        "wim: LZMS, which BeeZip decodes through Windows' Compression API, isn't available here",
    )
}

/// Whether LZMS chunks can be decoded here: `cabinet.dll` loads and makes a decoder.
pub fn available() -> bool {
    LzmsDecoder::new().is_ok()
}

/// One LZMS decoder, for one worker at a time.
pub struct LzmsDecoder {
    handle: isize,
}

// SAFETY: a handle may move to another thread; it's never used by two at once (no `Sync`).
unsafe impl Send for LzmsDecoder {}

impl LzmsDecoder {
    pub fn new() -> Result<Self, Error> {
        let api = api().ok_or_else(unavailable)?;
        let mut handle = 0isize;
        // SAFETY: no allocation routines (the API's own); `handle` is written on success.
        let ok = unsafe {
            (api.create)(
                COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW,
                std::ptr::null(),
                &mut handle,
            )
        };
        if ok == 0 {
            Err(unavailable())
        } else {
            Ok(Self { handle })
        }
    }

    /// Decodes one raw chunk into exactly `out.len()` bytes, the size the image gives. A damaged
    /// chunk can also decode to wrong bytes with no error: the blob's SHA-1 catches that.
    pub fn decode(&mut self, input: &[u8], out: &mut [u8]) -> Result<(), Error> {
        if out.len() > MAX_CHUNK {
            return Err(Error::unsupported(format!(
                "wim: an LZMS chunk of {} bytes, more than Windows' decoder takes",
                out.len()
            )));
        }
        if input.is_empty() || out.is_empty() {
            return Err(Error::corrupt("wim: an empty LZMS chunk"));
        }
        let api = api().ok_or_else(unavailable)?;
        let mut got = 0usize;
        // SAFETY: both buffers are valid for their lengths; the handle is this decoder's, used
        // by one thread at a time.
        let ok = unsafe {
            (api.decompress)(
                self.handle,
                input.as_ptr().cast(),
                input.len(),
                out.as_mut_ptr().cast(),
                out.len(),
                &mut got,
            )
        };
        if ok == 0 {
            // SAFETY: no other call in between.
            let code = unsafe { GetLastError() };
            return Err(Error::corrupt(format!(
                "wim: an LZMS chunk doesn't decode (Windows error {code})"
            )));
        }
        if got != out.len() {
            return Err(Error::corrupt(format!(
                "wim: an LZMS chunk decodes to {got} bytes, not {}",
                out.len()
            )));
        }
        Ok(())
    }
}

impl Drop for LzmsDecoder {
    fn drop(&mut self) {
        if let Some(api) = api() {
            // SAFETY: the handle came from `create` and is closed once.
            unsafe { (api.close)(self.handle) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows' compressor makes a chunk; the decoder gets it back, and refuses damage or a
    /// chunk too large before calling.
    #[test]
    fn decodes_what_windows_compresses() {
        let mut d = LzmsDecoder::new().expect("cabinet.dll on Windows 8 and later");
        let data: Vec<u8> = (0..60_000u32).map(|i| (i % 97 + i / 5000) as u8).collect();
        let packed = compress(&data);
        assert!(packed.len() < data.len() / 4);
        let mut out = vec![0u8; data.len()];
        d.decode(&packed, &mut out).unwrap();
        assert!(out == data);
        // Again with the same decoder.
        out.fill(0);
        d.decode(&packed, &mut out).unwrap();
        assert!(out == data);
        let e = d.decode(&packed[..packed.len() / 2], &mut out).unwrap_err();
        assert_eq!(e.kind, crate::ErrorKind::Corrupt);
        let e = d.decode(&[], &mut out).unwrap_err();
        assert_eq!(e.kind, crate::ErrorKind::Corrupt);
        assert!(available());
    }

    /// The API's own LZMS compressor, raw, for the test above.
    fn compress(data: &[u8]) -> Vec<u8> {
        type CreateC = unsafe extern "system" fn(u32, *const c_void, *mut isize) -> i32;
        type CompressFn = unsafe extern "system" fn(
            isize,
            *const c_void,
            usize,
            *mut c_void,
            usize,
            *mut usize,
        ) -> i32;
        type CloseC = unsafe extern "system" fn(isize) -> i32;
        type Proc = unsafe extern "system" fn() -> isize;
        let name: Vec<u16> = "cabinet.dll\0".encode_utf16().collect();
        // SAFETY: as in `api`, for the compressor's three functions.
        unsafe {
            let m = LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            assert!(!m.is_null());
            let create: CreateC = std::mem::transmute::<Proc, CreateC>(
                GetProcAddress(m, c"CreateCompressor".as_ptr().cast()).unwrap(),
            );
            let compress: CompressFn = std::mem::transmute::<Proc, CompressFn>(
                GetProcAddress(m, c"Compress".as_ptr().cast()).unwrap(),
            );
            let close: CloseC = std::mem::transmute::<Proc, CloseC>(
                GetProcAddress(m, c"CloseCompressor".as_ptr().cast()).unwrap(),
            );
            let mut h = 0isize;
            assert_ne!(
                create(
                    COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW,
                    std::ptr::null(),
                    &mut h
                ),
                0
            );
            let mut out = vec![0u8; data.len() + 4096];
            let mut n = 0usize;
            assert_ne!(
                compress(
                    h,
                    data.as_ptr().cast(),
                    data.len(),
                    out.as_mut_ptr().cast(),
                    out.len(),
                    &mut n
                ),
                0
            );
            close(h);
            out.truncate(n);
            out
        }
    }
}
