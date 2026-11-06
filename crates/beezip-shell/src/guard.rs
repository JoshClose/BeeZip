//! Keeping Explorer safe (docs/M4.md §4.2): every COM method body runs in [`guard`], and every
//! object counts itself for `DllCanUnloadNow`.
//!
//! Since Rust 1.81 a panic leaving an `extern "system"` function aborts the process, and
//! `#[implement]` calls our methods from such functions. In `explorer.exe` that would take the
//! taskbar down, so a panic becomes `E_UNEXPECTED` instead.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};

use windows::Win32::Foundation::E_UNEXPECTED;
use windows_core::HRESULT;

use crate::log;

/// Runs a COM method's body. A panic is logged and becomes `E_UNEXPECTED`.
pub fn guard<T>(
    method: &str,
    f: impl FnOnce() -> windows_core::Result<T>,
) -> windows_core::Result<T> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            panicked(method, payload.as_ref());
            Err(E_UNEXPECTED.into())
        }
    }
}

/// [`guard`] for the methods that return a bare `HRESULT`.
pub fn guard_hr(method: &str, f: impl FnOnce() -> HRESULT) -> HRESULT {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(hr) => hr,
        Err(payload) => {
            panicked(method, payload.as_ref());
            E_UNEXPECTED
        }
    }
}

fn panicked(method: &str, payload: &(dyn std::any::Any + Send)) {
    let message = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    log::line(|| format!("{method}: panicked: {message}"));
}

/// Debug builds only: panics in `method` when the settings key's `Panic` value names it, so
/// `tests/com.rs` can check that a panic comes back as `E_UNEXPECTED`.
pub fn forced_panic(method: &str, settings: &crate::settings::Settings) {
    if cfg!(debug_assertions) && settings.panic_in.as_deref() == Some(method) {
        panic!("forced panic in {method}");
    }
}

static LIVE: AtomicUsize = AtomicUsize::new(0);
static LOCKS: AtomicUsize = AtomicUsize::new(0);

/// Held by every COM object the DLL makes, so `DllCanUnloadNow` knows when none is left.
pub struct Live(());

impl Live {
    pub fn new() -> Self {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `IClassFactory::LockServer`.
pub fn lock_server(lock: bool) {
    if lock {
        LOCKS.fetch_add(1, Ordering::SeqCst);
    } else {
        // A client that unlocks more than it locked doesn't take the count below zero.
        let _ = LOCKS.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
    }
}

/// No object is alive and no client holds a lock.
pub fn can_unload() -> bool {
    LIVE.load(Ordering::SeqCst) == 0 && LOCKS.load(Ordering::SeqCst) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_becomes_e_unexpected() {
        let result: windows_core::Result<()> = guard("Test", || panic!("boom"));
        assert_eq!(result.unwrap_err().code(), E_UNEXPECTED);
        assert_eq!(guard_hr("Test", || panic!("boom")), E_UNEXPECTED);
        assert_eq!(guard("Test", || Ok(7)).ok(), Some(7));
    }
}
