//! BeeZip's Explorer context menu (docs/M4.md §4): a COM DLL serving one cascading
//! `IExplorerCommand`, "BeeZip >", to both registrations. The classic menu loads it into
//! `explorer.exe`; the Windows 11 menu, from a sparse package, into `DllHost.exe`.
//!
//! - **One class factory serves every CLSID** in [`beezip_menu::clsid`] and tells the context
//!   from it: the classic root, the modern root, or an item on its own (the classic menu without
//!   the cascade).
//! - **Explorer stays safe:** every COM method runs in [`guard::guard`], which turns a panic into
//!   `E_UNEXPECTED`; nothing builds the menu from the disk; settings come from one registry key.
//! - **A click** writes a job request and starts `BeeZip.exe --job <file>` ([`invoke`]).
//!
//! The second crate with unsafe code, after `beezip-unrar`: the exports, the item array's and
//! `IEnumExplorerCommand::Next`'s pointers, and the Win32 calls, each with a `SAFETY:` comment.
#![cfg(windows)]
#![allow(unsafe_code)]

mod command;
mod guard;
mod invoke;
mod log;
mod settings;

use std::ffi::c_void;

use beezip_menu::{Item, clsid};
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_POINTER, S_FALSE, S_OK,
};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};
use windows::Win32::UI::Shell::IExplorerCommand;
use windows_core::{BOOL, GUID, HRESULT, IUnknown, Interface, Ref, Result, implement};

use crate::command::{Context, ItemCommand, Root};
use crate::guard::{Live, guard, guard_hr};

/// What a class factory makes.
#[derive(Debug, Clone, Copy)]
enum Class {
    Root(Context),
    Item(Item),
}

impl Class {
    fn from_clsid(clsid: u128) -> Option<Self> {
        match clsid {
            clsid::CLASSIC_ROOT => Some(Self::Root(Context::Classic)),
            clsid::MODERN_ROOT => Some(Self::Root(Context::Modern)),
            _ => Item::from_clsid(clsid).map(Self::Item),
        }
    }
}

#[implement(IClassFactory)]
struct Factory {
    class: Class,
    _live: Live,
}

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> Result<()> {
        guard("Factory.CreateInstance", || {
            if out.is_null() || iid.is_null() {
                return Err(E_POINTER.into());
            }
            // SAFETY: `out` is non-null, and COM's contract makes it writable.
            unsafe { out.write(std::ptr::null_mut()) };
            if !outer.is_null() {
                return Err(CLASS_E_NOAGGREGATION.into());
            }
            let settings = settings::read();
            log::line(|| format!("CreateInstance {:?}", self.class));
            let command: IExplorerCommand = match self.class {
                Class::Root(context) => Root::new(context, settings).into(),
                Class::Item(item) => ItemCommand::top_level(item, settings).into(),
            };
            // SAFETY: `iid` and `out` were checked above; `query` writes `out` only on success.
            unsafe { command.query(iid, out) }.ok()
        })
    }

    fn LockServer(&self, lock: BOOL) -> Result<()> {
        guard::lock_server(lock.as_bool());
        Ok(())
    }
}

/// COM's entry point: a class factory for one of BeeZip's CLSIDs.
///
/// # Safety
/// COM's contract: `clsid` and `iid` point at GUIDs, and `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const GUID,
    iid: *const GUID,
    out: *mut *mut c_void,
) -> HRESULT {
    guard_hr("DllGetClassObject", || {
        if clsid.is_null() || iid.is_null() || out.is_null() {
            return E_POINTER;
        }
        // SAFETY: all three were checked non-null; COM passes valid pointers.
        let clsid = unsafe {
            out.write(std::ptr::null_mut());
            clsid.read()
        };
        let Some(class) = Class::from_clsid(clsid.to_u128()) else {
            return CLASS_E_CLASSNOTAVAILABLE;
        };
        let factory: IClassFactory = Factory {
            class,
            _live: Live::new(),
        }
        .into();
        // SAFETY: as above; `query` writes `out` only on success.
        unsafe { factory.query(iid, out) }
    })
}

/// COM asks whether the DLL can go: only once no object is alive and no client holds a lock.
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if guard::can_unload() { S_OK } else { S_FALSE }
}
