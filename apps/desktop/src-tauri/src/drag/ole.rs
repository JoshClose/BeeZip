//! BeeZip's IDataObject and IDropSource for dragging entries out (docs/M6.md §8.4), after the
//! 7-Zip File Manager's (`CPP/7zip/UI/FileManager/PanelDrag.cpp`).
//!
//! Until the mouse button goes up, the data object's `CF_HDROP` names only the drag's temp
//! folder, for targets that read it during `DragEnter`. When [`DropSource`] sees the release over
//! a target that accepts the drop, the target's first `GetData(CF_HDROP)`, from its
//! `IDropTarget::Drop`, runs the extraction on this thread (the UI thread, inside `DoDragDrop`)
//! and gets the extracted items. Copy and move are both allowed and "Preferred DropEffect" says
//! move, so Explorer moves the items out of the temp folder on the same volume and copies them
//! otherwise. There's no `IDataObjectAsyncCapability`, so Explorer has finished with the files
//! when `DoDragDrop` returns, and the temp folder can go.
//!
//! Over BeeZip's own windows the data object names nothing and a release cancels the drag,
//! so BeeZip never drops entries on itself. Formats a target writes back (Performed DropEffect,
//! DropDescription, the drag-image helper's) go to an inner `SHCreateDataObject`.

#![allow(unsafe_code)] // COM and the clipboard formats' memory
#![allow(non_snake_case)] // COM method names

use std::{
    cell::{Cell, RefCell},
    mem::ManuallyDrop,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    rc::Rc,
};

use windows::{
    Win32::{
        Foundation::{
            DATA_S_SAMEFORMATETC, DRAGDROP_S_CANCEL, DRAGDROP_S_DROP, DRAGDROP_S_USEDEFAULTCURSORS,
            DV_E_FORMATETC, E_FAIL, E_NOTIMPL, HGLOBAL, OLE_E_ADVISENOTSUPPORTED, POINT, S_OK,
        },
        System::{
            Com::{
                DATADIR_GET, DVASPECT_CONTENT, FORMATETC, IAdviseSink, IDataObject,
                IDataObject_Impl, IEnumFORMATETC, IEnumSTATDATA, STGMEDIUM, STGMEDIUM_0,
                TYMED_HGLOBAL,
            },
            DataExchange::RegisterClipboardFormatW,
            Memory::{GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalLock, GlobalUnlock},
            Ole::{
                CF_HDROP, DROPEFFECT, DROPEFFECT_COPY, DROPEFFECT_MOVE, DROPEFFECT_NONE,
                DoDragDrop, IDropSource, IDropSource_Impl,
            },
            SystemServices::{MK_LBUTTON, MK_RBUTTON, MODIFIERKEYS_FLAGS},
            Threading::GetCurrentProcessId,
        },
        UI::{
            Shell::{DROPFILES, SHCreateDataObject, SHCreateStdEnumFmtEtc},
            WindowsAndMessaging::{
                GA_ROOT, GetAncestor, GetCursorPos, GetWindowThreadProcessId, IDC_NO, LoadCursorW,
                SetCursor, WindowFromPoint,
            },
        },
    },
    core::{BOOL, Error, HRESULT, Ref, Result, implement, w},
};

/// Extracts the dragged entries into the temp folder and returns the items to drop. `Err`
/// fails the drop; the job's events have told the page why.
pub type Materialize = Box<dyn FnOnce() -> std::result::Result<Vec<PathBuf>, String>>;

/// Whether the cursor is over one of BeeZip's own windows.
pub type OverOwnWindow = Rc<dyn Fn() -> bool>;

/// Where the extraction is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// The button is still down, or went up and the target hasn't asked yet.
    Waiting,
    /// Running, inside a `GetData`: a `GetData` meanwhile gets nothing.
    Extracting,
    /// Extracted: these are the items.
    Ready(Vec<PathBuf>),
    Failed,
}

/// What the data object and the drop source share. Both live on the UI thread.
pub struct State {
    /// The button went up over a target that accepts the drop.
    pub released: Cell<bool>,
    /// The last effect the target reported (GiveFeedback).
    pub effect: Cell<DROPEFFECT>,
    pub stage: RefCell<Stage>,
    pub over_own_window: OverOwnWindow,
}

impl State {
    pub fn new(over_own_window: OverOwnWindow) -> Self {
        Self {
            released: Cell::new(false),
            effect: Cell::new(DROPEFFECT_NONE),
            stage: RefCell::new(Stage::Waiting),
            over_own_window,
        }
    }
}

#[implement(IDataObject)]
pub struct LazyFiles {
    temp_dir: PathBuf,
    state: Rc<State>,
    materialize: Cell<Option<Materialize>>,
    inner: IDataObject,
    cf_preferred: u16,
}

impl LazyFiles {
    pub fn new(temp_dir: PathBuf, state: Rc<State>, materialize: Materialize) -> Result<Self> {
        // SAFETY: no ID lists: an empty shell data object.
        let inner: IDataObject = unsafe { SHCreateDataObject(None, None, None::<&IDataObject>)? };
        // SAFETY: a static wide string.
        let cf_preferred = unsafe { RegisterClipboardFormatW(w!("Preferred DropEffect")) } as u16;
        Ok(Self {
            temp_dir,
            state,
            materialize: Cell::new(Some(materialize)),
            inner,
            cf_preferred,
        })
    }

    fn formats(&self) -> [FORMATETC; 2] {
        let f = |cf: u16| FORMATETC {
            cfFormat: cf,
            ptd: std::ptr::null_mut(),
            dwAspect: DVASPECT_CONTENT.0,
            lindex: -1,
            tymed: TYMED_HGLOBAL.0 as u32,
        };
        [f(CF_HDROP.0), f(self.cf_preferred)]
    }

    fn ours(&self, etc: &FORMATETC) -> Option<u16> {
        let hglobal = etc.tymed & TYMED_HGLOBAL.0 as u32 != 0;
        let content = etc.dwAspect == DVASPECT_CONTENT.0;
        (hglobal && content && (etc.cfFormat == CF_HDROP.0 || etc.cfFormat == self.cf_preferred))
            .then_some(etc.cfFormat)
    }

    /// Over BeeZip itself, before the release, there are no files: Tauri's drop target then
    /// ignores the drag, and the page shows no drop zone.
    fn hidden(&self) -> bool {
        !self.state.released.get() && (self.state.over_own_window)()
    }

    /// The items to drop, extracting them on the first call after the release.
    fn items(&self) -> Result<Vec<PathBuf>> {
        if !self.state.released.get() {
            return Ok(vec![self.temp_dir.clone()]);
        }
        let stage = self.state.stage.borrow().clone();
        match stage {
            Stage::Ready(items) => return Ok(items),
            Stage::Failed | Stage::Extracting => return Err(Error::from(E_FAIL)),
            Stage::Waiting => {}
        }
        let Some(materialize) = self.materialize.take() else {
            return Err(Error::from(E_FAIL));
        };
        *self.state.stage.borrow_mut() = Stage::Extracting;
        // No borrow is held while it runs: it pumps messages, and COM may call back in.
        let (stage, result) = match materialize() {
            Ok(items) => (Stage::Ready(items.clone()), Ok(items)),
            Err(why) => {
                eprintln!("BeeZip drag-out: the extraction failed: {why}");
                (Stage::Failed, Err(Error::from(E_FAIL)))
            }
        };
        *self.state.stage.borrow_mut() = stage;
        result
    }
}

/// A `DROPFILES` block naming `paths`, wide.
pub fn hdrop(paths: &[PathBuf]) -> Result<HGLOBAL> {
    let mut wide: Vec<u16> = Vec::new();
    for p in paths {
        wide.extend(p.as_os_str().encode_wide());
        wide.push(0);
    }
    wide.push(0);
    let header = size_of::<DROPFILES>();
    let bytes = header + wide.len() * 2;
    // SAFETY: a fresh movable block of `bytes`, written only while locked.
    unsafe {
        let h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes)?;
        let p = GlobalLock(h).cast::<u8>();
        if p.is_null() {
            return Err(Error::from_thread());
        }
        let df = p.cast::<DROPFILES>();
        (*df).pFiles = header as u32;
        (*df).fWide = true.into();
        std::ptr::copy_nonoverlapping(wide.as_ptr().cast::<u8>(), p.add(header), wide.len() * 2);
        let _ = GlobalUnlock(h);
        Ok(h)
    }
}

fn dword(v: u32) -> Result<HGLOBAL> {
    // SAFETY: as in `hdrop`, four bytes.
    unsafe {
        let h = GlobalAlloc(GMEM_MOVEABLE, 4)?;
        let p = GlobalLock(h).cast::<u32>();
        if p.is_null() {
            return Err(Error::from_thread());
        }
        *p = v;
        let _ = GlobalUnlock(h);
        Ok(h)
    }
}

impl IDataObject_Impl for LazyFiles_Impl {
    fn GetData(&self, etc: *const FORMATETC) -> Result<STGMEDIUM> {
        // SAFETY: COM hands a valid FORMATETC, or null.
        let Some(etc) = (unsafe { etc.as_ref() }) else {
            return Err(Error::from(DV_E_FORMATETC));
        };
        let global = match self.ours(etc) {
            Some(cf) if cf == CF_HDROP.0 => {
                if self.hidden() {
                    return Err(Error::from(DV_E_FORMATETC));
                }
                hdrop(&self.items()?)?
            }
            // Explorer: move by default (out of the temp folder), copy with Ctrl.
            Some(_) => dword(DROPEFFECT_MOVE.0)?,
            // SAFETY: forwarding the caller's own arguments.
            None => return unsafe { self.inner.GetData(etc) },
        };
        Ok(STGMEDIUM {
            tymed: TYMED_HGLOBAL.0 as u32,
            u: STGMEDIUM_0 { hGlobal: global },
            pUnkForRelease: ManuallyDrop::new(None), // the receiver frees the HGLOBAL
        })
    }

    fn GetDataHere(&self, _etc: *const FORMATETC, _medium: *mut STGMEDIUM) -> Result<()> {
        Err(Error::from(DV_E_FORMATETC))
    }

    fn QueryGetData(&self, etc: *const FORMATETC) -> HRESULT {
        // SAFETY: as in GetData.
        match unsafe { etc.as_ref() } {
            Some(e) if self.ours(e) == Some(CF_HDROP.0) && self.hidden() => DV_E_FORMATETC,
            Some(e) if self.ours(e).is_some() => S_OK,
            // SAFETY: forwarding the caller's own argument.
            Some(_) => unsafe { self.inner.QueryGetData(etc) },
            None => DV_E_FORMATETC,
        }
    }

    fn GetCanonicalFormatEtc(&self, _in: *const FORMATETC, out: *mut FORMATETC) -> HRESULT {
        // SAFETY: `out` is the caller's FORMATETC, or null.
        if let Some(out) = unsafe { out.as_mut() } {
            out.ptd = std::ptr::null_mut();
        }
        DATA_S_SAMEFORMATETC
    }

    fn SetData(
        &self,
        etc: *const FORMATETC,
        medium: *const STGMEDIUM,
        release: BOOL,
    ) -> Result<()> {
        // Performed DropEffect, Paste Succeeded, DropDescription, the drag image…
        // SAFETY: forwarding the caller's own arguments; the inner object takes ownership as asked.
        unsafe { self.inner.SetData(etc, medium, release.as_bool()) }
    }

    fn EnumFormatEtc(&self, direction: u32) -> Result<IEnumFORMATETC> {
        if direction != DATADIR_GET.0 as u32 {
            return Err(Error::from(E_NOTIMPL));
        }
        // SAFETY: the enumerator copies our two formats.
        unsafe { SHCreateStdEnumFmtEtc(&self.formats()) }
    }

    fn DAdvise(&self, _: *const FORMATETC, _: u32, _: Ref<IAdviseSink>) -> Result<u32> {
        Err(Error::from(OLE_E_ADVISENOTSUPPORTED))
    }

    fn DUnadvise(&self, _: u32) -> Result<()> {
        Err(Error::from(OLE_E_ADVISENOTSUPPORTED))
    }

    fn EnumDAdvise(&self) -> Result<IEnumSTATDATA> {
        Err(Error::from(OLE_E_ADVISENOTSUPPORTED))
    }
}

#[implement(IDropSource)]
pub struct DropSource {
    pub state: Rc<State>,
}

impl IDropSource_Impl for DropSource_Impl {
    fn QueryContinueDrag(&self, escape: BOOL, keys: MODIFIERKEYS_FLAGS) -> HRESULT {
        // Escape, or the other button pressed during the drag, as 7-Zip does.
        if escape.as_bool() || keys.0 & MK_RBUTTON.0 != 0 {
            return DRAGDROP_S_CANCEL;
        }
        if keys.0 & MK_LBUTTON.0 != 0 {
            return S_OK;
        }
        // Let go over something that refuses the drop, or over BeeZip itself.
        if self.state.effect.get() == DROPEFFECT_NONE || (self.state.over_own_window)() {
            return DRAGDROP_S_CANCEL;
        }
        self.state.released.set(true);
        DRAGDROP_S_DROP
    }

    fn GiveFeedback(&self, effect: DROPEFFECT) -> HRESULT {
        self.state.effect.set(effect);
        if (self.state.over_own_window)() {
            // Tauri's drop target leaves the effect alone when it gets no files, so the
            // default cursor would offer a move: say no instead.
            // SAFETY: a system cursor, shared; nothing to free.
            if let Ok(no) = unsafe { LoadCursorW(None, IDC_NO) } {
                // SAFETY: as above.
                unsafe { SetCursor(Some(no)) };
                return S_OK;
            }
        }
        DRAGDROP_S_USEDEFAULTCURSORS
    }
}

/// Whether the cursor is over a window of this process: the main window, a job window, or
/// WebView2's windows inside them.
pub fn over_own_window() -> bool {
    let mut pt = POINT::default();
    // SAFETY: plain queries about windows; `pt` and `pid` are locals.
    unsafe {
        if GetCursorPos(&mut pt).is_err() {
            return false;
        }
        let hwnd = WindowFromPoint(pt);
        if hwnd.is_invalid() {
            return false;
        }
        let root = GetAncestor(hwnd, GA_ROOT);
        let mut pid = 0u32;
        GetWindowThreadProcessId(if root.is_invalid() { hwnd } else { root }, Some(&mut pid));
        pid == GetCurrentProcessId()
    }
}

/// How a drag ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Dropped, and the target got the extracted items.
    Dropped,
    /// Let go over nothing that takes files, over BeeZip, or cancelled; or a target took the
    /// drop without asking for the files.
    Cancelled,
    /// Dropped, but the extraction failed.
    Failed,
}

/// `DoDragDrop`'s result, read with what the extraction did.
pub fn outcome(hr: HRESULT, stage: &Stage) -> Result<Outcome> {
    match (hr, stage) {
        (DRAGDROP_S_DROP, Stage::Ready(_)) => Ok(Outcome::Dropped),
        (DRAGDROP_S_DROP, Stage::Failed) => Ok(Outcome::Failed),
        (DRAGDROP_S_DROP | DRAGDROP_S_CANCEL, _) => Ok(Outcome::Cancelled),
        (other, _) => Err(Error::from(other)),
    }
}

/// Runs the OLE drag loop. Call on the UI thread (STA, OLE initialised) while the left button
/// is still down, outside tao's event handler and any WebView2 callback (see win.rs). Blocks
/// until the drop, and the extraction a drop runs, are done; meanwhile the loop and the
/// extraction pump the thread's messages.
pub fn drag(temp_dir: PathBuf, materialize: Materialize, over: OverOwnWindow) -> Result<Outcome> {
    let state = Rc::new(State::new(over));
    let data: IDataObject = LazyFiles::new(temp_dir, state.clone(), materialize)?.into();
    let source: IDropSource = DropSource {
        state: state.clone(),
    }
    .into();
    let mut effect = DROPEFFECT_NONE;
    // SAFETY: both objects outlive the call; `effect` is a local.
    let hr = unsafe {
        DoDragDrop(
            &data,
            &source,
            DROPEFFECT_COPY | DROPEFFECT_MOVE,
            &mut effect,
        )
    };
    let stage = state.stage.borrow().clone();
    outcome(hr, &stage)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use windows::Win32::{
        System::Ole::{OleInitialize, ReleaseStgMedium},
        UI::Shell::{DragQueryFileW, HDROP},
    };

    use super::*;

    const HDROP_ETC: FORMATETC = FORMATETC {
        cfFormat: CF_HDROP.0,
        ptd: std::ptr::null_mut(),
        dwAspect: DVASPECT_CONTENT.0,
        lindex: -1,
        tymed: TYMED_HGLOBAL.0 as u32,
    };

    fn paths_of(mut medium: STGMEDIUM) -> Vec<PathBuf> {
        // SAFETY: a CF_HDROP medium from our GetData, released here.
        unsafe {
            let drop = HDROP(medium.u.hGlobal.0);
            let n = DragQueryFileW(drop, u32::MAX, None);
            let out = (0..n)
                .map(|i| {
                    let mut buf = vec![0u16; 1024];
                    let len = DragQueryFileW(drop, i, Some(&mut buf)) as usize;
                    PathBuf::from(String::from_utf16_lossy(&buf[..len]))
                })
                .collect();
            ReleaseStgMedium(&mut medium);
            out
        }
    }

    /// The error of a `GetData` that must fail; STGMEDIUM has no Debug for `unwrap_err`.
    fn error_of(got: Result<STGMEDIUM>) -> HRESULT {
        match got {
            Ok(_) => panic!("GetData gave a medium"),
            Err(e) => e.code(),
        }
    }

    struct Fixture {
        data: IDataObject,
        source: IDropSource,
        state: Rc<State>,
        calls: Rc<Cell<u32>>,
        own: Rc<Cell<bool>>,
        temp: PathBuf,
    }

    /// A data object whose extraction counts its calls and returns `items`, or fails.
    fn fixture(items: std::result::Result<Vec<PathBuf>, String>) -> Fixture {
        // SAFETY: once per test thread; a second call only says it's done already.
        let _ = unsafe { OleInitialize(None) };
        let temp = PathBuf::from(r"C:\Temp\BeeZip\drag\drag-test");
        let calls = Rc::new(Cell::new(0));
        let own = Rc::new(Cell::new(false));
        let over: OverOwnWindow = {
            let own = own.clone();
            Rc::new(move || own.get())
        };
        let state = Rc::new(State::new(over));
        let materialize: Materialize = {
            let calls = calls.clone();
            Box::new(move || {
                calls.set(calls.get() + 1);
                items
            })
        };
        let data: IDataObject = LazyFiles::new(temp.clone(), state.clone(), materialize)
            .unwrap()
            .into();
        let source: IDropSource = DropSource {
            state: state.clone(),
        }
        .into();
        Fixture {
            data,
            source,
            state,
            calls,
            own,
            temp,
        }
    }

    /// No mouse: the tests call the drop source's methods themselves, as DoDragDrop would.
    fn release_over_explorer(f: &Fixture) {
        // SAFETY: plain COM calls on our own objects.
        unsafe {
            assert_eq!(f.source.QueryContinueDrag(false, MK_LBUTTON), S_OK);
            assert_eq!(
                f.source.GiveFeedback(DROPEFFECT_MOVE),
                DRAGDROP_S_USEDEFAULTCURSORS
            );
            assert_eq!(
                f.source.QueryContinueDrag(false, MODIFIERKEYS_FLAGS(0)),
                DRAGDROP_S_DROP
            );
        }
    }

    #[test]
    fn extracts_once_on_the_first_request_after_the_release() {
        let items = vec![PathBuf::from(r"C:\t\a.txt"), PathBuf::from(r"C:\t\sub")];
        let f = fixture(Ok(items.clone()));
        // SAFETY: plain COM calls on our own objects.
        unsafe {
            assert_eq!(f.data.QueryGetData(&HDROP_ETC), S_OK);
            // DragEnter and DragOver: the folder only, nothing extracted.
            assert_eq!(
                paths_of(f.data.GetData(&HDROP_ETC).unwrap()),
                std::slice::from_ref(&f.temp)
            );
            assert_eq!(f.calls.get(), 0);
            release_over_explorer(&f);
            assert_eq!(f.calls.get(), 0, "nothing runs until the target asks");
            // Drop: the target asks and gets the extracted items.
            assert_eq!(paths_of(f.data.GetData(&HDROP_ETC).unwrap()), items);
            assert_eq!(paths_of(f.data.GetData(&HDROP_ETC).unwrap()), items);
            assert_eq!(f.calls.get(), 1, "extracted once");
            // Our two formats, and move preferred.
            let e = f.data.EnumFormatEtc(DATADIR_GET.0 as u32).unwrap();
            let mut got = [FORMATETC::default(); 4];
            let mut n = 0u32;
            let _ = e.Next(&mut got, Some(&mut n));
            assert_eq!(n, 2);
            let preferred = FORMATETC {
                cfFormat: got[1].cfFormat,
                ..HDROP_ETC
            };
            let mut medium = f.data.GetData(&preferred).unwrap();
            let p = GlobalLock(medium.u.hGlobal).cast::<u32>();
            assert_eq!(*p, DROPEFFECT_MOVE.0);
            let _ = GlobalUnlock(medium.u.hGlobal);
            ReleaseStgMedium(&mut medium);
        }
        assert_eq!(*f.state.stage.borrow(), Stage::Ready(items));
        let stage = f.state.stage.borrow().clone();
        assert_eq!(outcome(DRAGDROP_S_DROP, &stage).unwrap(), Outcome::Dropped);
    }

    #[test]
    fn a_failed_extraction_fails_the_drop_once() {
        let f = fixture(Err("PasswordRequired".into()));
        release_over_explorer(&f);
        // SAFETY: plain COM calls on our own objects.
        unsafe {
            assert_eq!(error_of(f.data.GetData(&HDROP_ETC)), E_FAIL);
            assert_eq!(error_of(f.data.GetData(&HDROP_ETC)), E_FAIL);
        }
        assert_eq!(f.calls.get(), 1);
        let stage = f.state.stage.borrow().clone();
        assert_eq!(outcome(DRAGDROP_S_DROP, &stage).unwrap(), Outcome::Failed);
    }

    #[test]
    fn over_beezip_there_are_no_files_and_a_release_cancels() {
        let f = fixture(Ok(vec![PathBuf::from(r"C:\t\a.txt")]));
        f.own.set(true);
        // SAFETY: plain COM calls on our own objects.
        unsafe {
            // Tauri's drop target asks during DragEnter, and gets nothing.
            assert_eq!(f.data.QueryGetData(&HDROP_ETC), DV_E_FORMATETC);
            assert_eq!(error_of(f.data.GetData(&HDROP_ETC)), DV_E_FORMATETC);
            // Its effect is left as the allowed ones; the cursor says no all the same.
            assert_eq!(f.source.GiveFeedback(DROPEFFECT_MOVE), S_OK);
            assert_eq!(
                f.source.QueryContinueDrag(false, MODIFIERKEYS_FLAGS(0)),
                DRAGDROP_S_CANCEL
            );
        }
        assert!(!f.state.released.get());
        assert_eq!(f.calls.get(), 0);
        let stage = f.state.stage.borrow().clone();
        assert_eq!(
            outcome(DRAGDROP_S_CANCEL, &stage).unwrap(),
            Outcome::Cancelled
        );
    }

    #[test]
    fn refused_escaped_or_right_clicked_drags_cancel_without_extracting() {
        let f = fixture(Ok(vec![]));
        // SAFETY: plain COM calls on our own objects.
        unsafe {
            // Let go over something that refuses.
            assert_eq!(
                f.source.GiveFeedback(DROPEFFECT_NONE),
                DRAGDROP_S_USEDEFAULTCURSORS
            );
            assert_eq!(
                f.source.QueryContinueDrag(false, MODIFIERKEYS_FLAGS(0)),
                DRAGDROP_S_CANCEL
            );
            assert_eq!(
                f.source.QueryContinueDrag(true, MK_LBUTTON),
                DRAGDROP_S_CANCEL
            );
            assert_eq!(
                f.source
                    .QueryContinueDrag(false, MODIFIERKEYS_FLAGS(MK_LBUTTON.0 | MK_RBUTTON.0)),
                DRAGDROP_S_CANCEL
            );
        }
        assert!(!f.state.released.get());
        assert_eq!(f.calls.get(), 0);
        // A target that takes the drop without asking for the files gets nothing extracted.
        assert_eq!(
            outcome(DRAGDROP_S_DROP, &Stage::Waiting).unwrap(),
            Outcome::Cancelled
        );
        assert!(outcome(E_FAIL, &Stage::Waiting).is_err());
    }

    #[test]
    fn a_request_during_the_extraction_gets_nothing() {
        // The extraction pumps messages, so a target could ask again before it ends.
        // SAFETY: once per test thread.
        let _ = unsafe { OleInitialize(None) };
        let state = Rc::new(State::new(Rc::new(|| false)));
        let slot: Rc<RefCell<Option<IDataObject>>> = Rc::default();
        let inside = Rc::new(Cell::new(None));
        let materialize: Materialize = {
            let (slot, inside) = (slot.clone(), inside.clone());
            Box::new(move || {
                let data = slot.borrow().clone().unwrap();
                // SAFETY: a plain COM call on our own object.
                let again = unsafe { data.GetData(&HDROP_ETC) };
                inside.set(Some(again.map(|_| ()).map_err(|e| e.code())));
                Ok(vec![PathBuf::from(r"C:\t\a.txt")])
            })
        };
        let data: IDataObject = LazyFiles::new(PathBuf::from(r"C:\t"), state.clone(), materialize)
            .unwrap()
            .into();
        *slot.borrow_mut() = Some(data.clone());
        state.released.set(true);
        // SAFETY: a plain COM call on our own object.
        let got = paths_of(unsafe { data.GetData(&HDROP_ETC) }.unwrap());
        assert_eq!(got, [PathBuf::from(r"C:\t\a.txt")]);
        assert_eq!(inside.get(), Some(Err(E_FAIL)));
        slot.borrow_mut().take();
    }

    #[test]
    fn a_drop_list_holds_long_and_unicode_paths() {
        let long = PathBuf::from(format!(r"C:\t\{}\ü 名前.txt", "d".repeat(300)));
        let h = hdrop(std::slice::from_ref(&long)).unwrap();
        let medium = STGMEDIUM {
            tymed: TYMED_HGLOBAL.0 as u32,
            u: STGMEDIUM_0 { hGlobal: h },
            pUnkForRelease: ManuallyDrop::new(None),
        };
        // paths_of reads at most 1023 characters.
        assert_eq!(paths_of(medium), [long]);
    }
}
