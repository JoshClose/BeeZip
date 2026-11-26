//! DPAPI-NG for this Windows account (`LOCAL=user`): what seals your private keys on Windows
//! (docs/M14.md §6). Silent: no dialog, under a millisecond (the Windows spike).
#![allow(unsafe_code)]

use beezip_core::{Error, ErrorKind, Result};
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::{
        Cryptography::{
            NCRYPT_SILENT_FLAG, NCryptCloseProtectionDescriptor, NCryptCreateProtectionDescriptor,
            NCryptProtectSecret, NCryptUnprotectSecret,
        },
        NCRYPT_DESCRIPTOR_HANDLE,
    },
};
use windows_core::w;
use zeroize::{Zeroize, Zeroizing};

fn failed(what: &str, e: &windows_core::Error) -> Error {
    Error::new(
        ErrorKind::Io,
        format!(
            "Windows couldn't {what} the key (DPAPI-NG): {}",
            e.message()
        ),
    )
}

/// A protection descriptor, closed when dropped.
struct Descriptor(NCRYPT_DESCRIPTOR_HANDLE);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the handle came from NCryptCreateProtectionDescriptor and is closed once.
        unsafe {
            let _ = NCryptCloseProtectionDescriptor(self.0);
        }
    }
}

/// Memory NCrypt allocated with LocalAlloc: wiped and freed when dropped.
struct Local {
    ptr: *mut u8,
    len: usize,
}

impl Local {
    fn bytes(&self) -> &[u8] {
        if self.ptr.is_null() {
            return &[];
        }
        // SAFETY: NCrypt returned `len` bytes at `ptr`, which live until `drop`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        // SAFETY: as in `bytes`; freed once, with the allocator NCrypt used.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr, self.len).zeroize();
            let _ = LocalFree(Some(HLOCAL(self.ptr.cast())));
        }
    }
}

/// `secret`, sealed for this Windows account.
pub fn protect(secret: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: the descriptor string is a static wide string; the out pointers are valid locals
    // whose memory `Local` frees.
    unsafe {
        let descriptor = Descriptor(
            NCryptCreateProtectionDescriptor(w!("LOCAL=user"), 0)
                .map_err(|e| failed("seal", &e))?,
        );
        let mut out = Local {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut len = 0u32;
        NCryptProtectSecret(
            descriptor.0,
            NCRYPT_SILENT_FLAG.0,
            secret,
            None,
            None,
            &mut out.ptr,
            &mut len,
        )
        .map_err(|e| failed("seal", &e))?;
        out.len = len as usize;
        Ok(out.bytes().to_vec())
    }
}

/// What [`protect`] sealed. Another account's or another PC's blob fails.
pub fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // SAFETY: as in `protect`.
    unsafe {
        let mut out = Local {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut len = 0u32;
        NCryptUnprotectSecret(
            None,
            NCRYPT_SILENT_FLAG,
            blob,
            None,
            None,
            &mut out.ptr,
            &mut len,
        )
        .map_err(|e| failed("unseal", &e))?;
        out.len = len as usize;
        Ok(Zeroizing::new(out.bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let secret = b"AGE-SECRET-KEY-PQ-1 not a real key";
        let blob = protect(secret).unwrap();
        assert!(!blob.windows(secret.len()).any(|w| w == secret));
        assert_eq!(&unprotect(&blob).unwrap()[..], secret);
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(unprotect(&bad).is_err());
        assert!(unprotect(&[]).is_err());
    }
}
