//! Where drag-out runs (docs/M6.md §8.4): a message-only window of BeeZip's own on the UI
//! thread.
//!
//! `DoDragDrop` runs a modal loop until the drop is over, and the extraction a drop starts
//! pumps messages too, so the page keeps getting its job's progress and prompts. Neither may
//! run where Tauri would start them by itself:
//! - inside a WebView2 event handler, which a sync command's body is: WebView2 doesn't
//!   support a nested message loop there;
//! - inside tao's event handler, where `run_on_main_thread` runs closures: while it runs,
//!   tao holds back every event, and Tauri's messages to the page with them.
//!
//! So the async command posts the drag to this window, and tao's own message loop dispatches
//! it from the top, outside both.

#![allow(unsafe_code)] // Win32 windows and messages

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicIsize, Ordering},
        mpsc,
    },
};

use beezip_commands::{CmdError, Engine, ErrorCode, EventSink, Interactor};
use serde_json::Value;
use tauri::{AppHandle, Manager};
use windows::{
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON, VK_RBUTTON},
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DispatchMessageW, GetSystemMetrics, HWND_MESSAGE, MSG,
            MWMO_INPUTAVAILABLE, MsgWaitForMultipleObjectsEx, PM_REMOVE, PeekMessageW,
            PostMessageW, PostQuitMessage, QS_ALLINPUT, RegisterClassW, SM_SWAPBUTTON,
            TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_NULL, WM_QUIT, WNDCLASSW,
        },
    },
    core::w,
};

use super::{DragOutcome, drag_dir, dropped_items, extract_args, ole, trace};
use crate::prompts::GuiInteractor;

/// The message that carries a [`Request`]; `lParam` is its `Box`.
const WM_DRAG_OUT: u32 = WM_APP + 0x42;

/// The window, once [`init`] made it; 0 before.
static WINDOW: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    /// A drag is running on this thread: another one waits for it to end.
    static DRAGGING: Cell<bool> = const { Cell::new(false) };
}

fn window() -> Option<HWND> {
    match WINDOW.load(Ordering::Acquire) {
        0 => None,
        raw => Some(HWND(raw as *mut _)),
    }
}

/// Makes the window. Call once, on the UI thread, before any drag.
pub fn init() -> windows::core::Result<()> {
    // SAFETY: registering a class with a static name and procedure, then a message-only
    // window of it on this thread.
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(procedure),
            hInstance: instance.into(),
            lpszClassName: w!("BeeZipDragOut"),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(windows::core::Error::from_thread());
        }
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("BeeZipDragOut"),
            None,
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance.into()),
            None,
        )?;
        WINDOW.store(hwnd.0 as isize, Ordering::Release);
    }
    Ok(())
}

/// A drag the page asked for, on its way to the UI thread.
struct Request {
    engine: Engine,
    gui: Arc<GuiInteractor>,
    args: Value,
    sink: EventSink,
    reply: mpsc::Sender<Result<DragOutcome, CmdError>>,
}

/// Posts the drag to the window and waits, off the UI thread, until it's over.
pub async fn drag_out(
    app: &AppHandle,
    args: Value,
    sink: EventSink,
) -> Result<DragOutcome, CmdError> {
    let outcome = post(
        app.state::<Engine>().inner().clone(),
        Arc::clone(app.state::<Arc<GuiInteractor>>().inner()),
        args,
        sink,
    )?;
    tauri::async_runtime::spawn_blocking(move || outcome.recv())
        .await
        .map_err(|e| CmdError::internal(format!("waiting for the drag: {e}")))?
        .map_err(|_| CmdError::internal("the drag ended without an outcome"))?
}

/// Posts the drag to the window; the outcome comes on the receiver.
fn post(
    engine: Engine,
    gui: Arc<GuiInteractor>,
    args: Value,
    sink: EventSink,
) -> Result<mpsc::Receiver<Result<DragOutcome, CmdError>>, CmdError> {
    let hwnd = window().ok_or_else(|| {
        CmdError::new(
            ErrorCode::UnsupportedOperation,
            "dragging out isn't available: BeeZip couldn't set it up at startup",
        )
    })?;
    let (reply, outcome) = mpsc::channel();
    let request = Box::into_raw(Box::new(Request {
        engine,
        gui,
        args,
        sink,
        reply,
    }));
    // SAFETY: the window's procedure takes the box back; if the post fails, this does.
    if let Err(e) =
        unsafe { PostMessageW(Some(hwnd), WM_DRAG_OUT, WPARAM(0), LPARAM(request as isize)) }
    {
        // SAFETY: not posted, so still ours.
        drop(unsafe { Box::from_raw(request) });
        return Err(CmdError::internal(format!("starting the drag: {e}")));
    }
    Ok(outcome)
}

unsafe extern "system" fn procedure(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg != WM_DRAG_OUT {
        // SAFETY: the default for everything else.
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    }
    // SAFETY: `drag_out` posted this box and gave up its ownership.
    let request = unsafe { Box::from_raw(lparam.0 as *mut Request) };
    let reply = request.reply.clone();
    let outcome = if DRAGGING.get() {
        // A dragstart while the last drop is still extracting.
        trace(|| "refused: a drag is still running".into());
        Err(CmdError::new(
            ErrorCode::Conflict,
            "a drag is still running; let it finish first",
        ))
    } else {
        DRAGGING.set(true);
        // A panic mustn't unwind into Windows.
        let outcome = catch_unwind(AssertUnwindSafe(|| run(*request)))
            .unwrap_or_else(|_| Err(CmdError::internal("the drag panicked")));
        DRAGGING.set(false);
        outcome
    };
    let _ = reply.send(outcome);
    LRESULT(0)
}

/// One drag: a fresh temp folder, the OLE loop, then the folder goes.
fn run(request: Request) -> Result<DragOutcome, CmdError> {
    let Request {
        engine,
        gui,
        args,
        sink,
        ..
    } = request;
    // The page's arguments first, against a stand-in folder.
    extract_args(args.clone(), &drag_dir())?;
    // Let go already (a quick flick, while the page measured the selection): DoDragDrop
    // would then wait for the mouse to move before it noticed.
    if !primary_button_down() {
        trace(|| "the button was already up: cancelled".into());
        return Ok(DragOutcome::Cancelled);
    }
    let base = drag_dir();
    let io = |what: &str, e: std::io::Error| CmdError::new(ErrorCode::Io, format!("{what}: {e}"));
    std::fs::create_dir_all(&base).map_err(|e| io("making the drag's temp folder", e))?;
    let temp = tempfile::Builder::new()
        .prefix("drag-")
        .tempdir_in(&base)
        .map_err(|e| io("making the drag's temp folder", e))?
        .keep();
    let args = extract_args(args, &temp)?;
    let materialize: ole::Materialize = {
        let temp = temp.clone();
        Box::new(move || extract(&engine, gui, args, sink, &temp))
    };
    let result = ole::drag(temp.clone(), materialize, Rc::new(ole::over_own_window));
    // Moved items have gone already; copied ones, and anything left, go now.
    let _ = std::fs::remove_dir_all(&temp);
    trace(|| format!("{result:?}"));
    match result {
        Ok(ole::Outcome::Dropped) => Ok(DragOutcome::Dropped),
        Ok(ole::Outcome::Cancelled) => Ok(DragOutcome::Cancelled),
        Ok(ole::Outcome::Failed) => Ok(DragOutcome::Failed),
        Err(e) => Err(CmdError::internal(format!("the drag failed: {e}"))),
    }
}

/// Whether the mouse button that drags (the left one, unless the buttons are swapped) is
/// down now, as the mouse has it rather than as this thread's messages last said.
fn primary_button_down() -> bool {
    // SAFETY: plain queries.
    unsafe {
        let button = if GetSystemMetrics(SM_SWAPBUTTON) != 0 {
            VK_RBUTTON
        } else {
            VK_LBUTTON
        };
        GetAsyncKeyState(i32::from(button.0)) < 0
    }
}

/// Runs `archive.extract` into `temp` as an ordinary job, pumping this thread's messages until
/// it ends, and returns the items to drop.
pub fn extract(
    engine: &Engine,
    gui: Arc<dyn Interactor>,
    args: Value,
    sink: EventSink,
    temp: &Path,
) -> Result<Vec<PathBuf>, String> {
    let job = engine
        .invoke("archive.extract", args, gui, sink)
        .map_err(|e| e.message)?;
    let id = job.id();
    let done: Arc<Mutex<Option<Result<Value, CmdError>>>> = Arc::default();
    {
        let done = Arc::clone(&done);
        let wake = window().map(|h| h.0 as isize);
        std::thread::spawn(move || {
            let result = job.join();
            *done.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
            if let Some(raw) = wake {
                // SAFETY: an empty message, only to wake the pump.
                let _ = unsafe {
                    PostMessageW(Some(HWND(raw as *mut _)), WM_NULL, WPARAM(0), LPARAM(0))
                };
            }
        });
    }
    let finished = || {
        done.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    };
    if let Some(code) = pump_until(&finished) {
        // BeeZip is quitting: stop the job, wait for it, and let the outer loop quit too.
        engine.cancel(id);
        while !finished() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // SAFETY: re-posting the quit this pump took.
        unsafe { PostQuitMessage(code.0 as i32) };
        return Err("BeeZip is closing".into());
    }
    let result = done
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap_or_else(|| Err(CmdError::internal("the job's result went missing")));
    match result {
        Ok(_) => {}
        // Unsafe entries were skipped and the rest extracted, as Extract does.
        Err(e) if e.code == ErrorCode::Unsafe => {}
        Err(e) => return Err(format!("{:?}: {}", e.code, e.message)),
    }
    let items = dropped_items(temp).map_err(|e| e.to_string())?;
    if items.is_empty() {
        return Err("nothing was extracted".into());
    }
    Ok(items)
}

/// Dispatches this thread's messages until `done`, or a `WM_QUIT`, whose code it returns.
fn pump_until(done: &dyn Fn() -> bool) -> Option<WPARAM> {
    let mut msg = MSG::default();
    while !done() {
        // SAFETY: waiting on this thread's queue alone, at most 100 ms.
        unsafe {
            MsgWaitForMultipleObjectsEx(None, 100, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        }
        // SAFETY: the usual loop over this thread's queue.
        while unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
            if msg.message == WM_QUIT {
                return Some(msg.wParam);
            }
            // SAFETY: as above.
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use beezip_commands::{JobEvent, NonInteractive, registry};
    use serde_json::json;

    use super::*;

    /// A zip of `top.txt` and `docs/{a.md,deep/b.md}`, made by BeeZip itself.
    fn archive(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        std::fs::create_dir_all(src.join("docs").join("deep")).unwrap();
        std::fs::write(src.join("top.txt"), "top").unwrap();
        std::fs::write(src.join("docs").join("a.md"), "a").unwrap();
        std::fs::write(src.join("docs").join("deep").join("b.md"), "b").unwrap();
        let zip = dir.join("x.zip");
        let engine = Engine::new(registry());
        engine
            .invoke(
                "archive.create",
                json!({ "output": zip, "inputs": [src.join("top.txt"), src.join("docs")] }),
                Arc::new(NonInteractive),
                beezip_commands::discard_events(),
            )
            .unwrap()
            .join()
            .unwrap();
        zip
    }

    fn events() -> (EventSink, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink: EventSink = {
            let seen = Arc::clone(&seen);
            Arc::new(move |e: JobEvent| {
                let name = serde_json::to_value(&e).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                seen.lock().unwrap().push(name);
            })
        };
        (sink, seen)
    }

    #[test]
    fn a_folder_shown_extracts_flat_into_the_temp_folder() {
        let dir = tempfile::tempdir().unwrap();
        let zip = archive(dir.path());
        let temp = dir.path().join("drag-1");
        std::fs::create_dir(&temp).unwrap();
        let engine = Engine::new(registry());
        let (sink, seen) = events();
        // The page shows `docs` and drags `a.md` and `deep`.
        let args = extract_args(
            json!({ "archive": zip, "entries": ["docs/a.md", "docs/deep"], "strip_components": 1 }),
            &temp,
        )
        .unwrap();
        let items = extract(&engine, Arc::new(NonInteractive), args, sink, &temp).unwrap();
        assert_eq!(items, [temp.join("a.md"), temp.join("deep")]);
        assert_eq!(
            std::fs::read_to_string(temp.join("deep").join("b.md")).unwrap(),
            "b"
        );
        assert!(!temp.join("top.txt").exists());
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first().map(String::as_str), Some("Started"));
        assert_eq!(seen.last().map(String::as_str), Some("Finished"));
    }

    /// The way a drag goes from the page to the window and back, with no button down (no
    /// input is ever sent): it cancels before `DoDragDrop`, which would wait for the mouse to
    /// move, extracts nothing and leaves no temp folder. The drag itself needs a mouse
    /// (docs/M6.md §12).
    #[test]
    fn a_drag_after_the_button_went_up_cancels_and_cleans_up() {
        // SAFETY: OLE on this test thread, which owns the window and pumps it.
        let _ = unsafe { windows::Win32::System::Ole::OleInitialize(None) };
        init().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let zip = archive(dir.path());
        let folders = || -> Vec<PathBuf> {
            std::fs::read_dir(drag_dir())
                .map(|d| d.flatten().map(|e| e.path()).collect())
                .unwrap_or_default()
        };
        let before = folders();
        let (sink, seen) = events();
        let outcome = post(
            Engine::new(registry()),
            Arc::new(GuiInteractor::new(|_| false)),
            json!({ "archive": zip }),
            sink,
        )
        .unwrap();
        if primary_button_down() {
            // Someone is holding the mouse button down on this machine: not a test to run now.
            return;
        }
        let start = std::time::Instant::now();
        let got = loop {
            pump_until(&|| true);
            let mut msg = MSG::default();
            // SAFETY: this thread's queue; the window's procedure runs the drag here.
            while unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
                // SAFETY: as above.
                unsafe { DispatchMessageW(&msg) };
            }
            if let Ok(got) = outcome.try_recv() {
                break got;
            }
            assert!(start.elapsed().as_secs() < 20, "no outcome");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(got.unwrap(), DragOutcome::Cancelled);
        assert!(seen.lock().unwrap().is_empty(), "nothing extracted");
        assert_eq!(folders(), before, "its temp folder is gone");
        // The page's arguments are checked before anything starts.
        let (sink, _) = events();
        let outcome = post(
            Engine::new(registry()),
            Arc::new(GuiInteractor::new(|_| false)),
            json!({ "archive": zip, "dest": "C:/elsewhere" }),
            sink,
        )
        .unwrap();
        let got = loop {
            let mut msg = MSG::default();
            // SAFETY: as above.
            while unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
                // SAFETY: as above.
                unsafe { DispatchMessageW(&msg) };
            }
            if let Ok(got) = outcome.try_recv() {
                break got;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(got.unwrap_err().code, ErrorCode::InvalidArgs);
        assert_eq!(folders(), before);
    }

    #[test]
    fn a_failed_extraction_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let temp = dir.path().join("drag-2");
        std::fs::create_dir(&temp).unwrap();
        let engine = Engine::new(registry());
        let (sink, seen) = events();
        let args =
            extract_args(json!({ "archive": dir.path().join("missing.zip") }), &temp).unwrap();
        let why = extract(&engine, Arc::new(NonInteractive), args, sink, &temp).unwrap_err();
        assert!(why.starts_with("NotFound"), "{why}");
        assert_eq!(
            seen.lock().unwrap().last().map(String::as_str),
            Some("Failed")
        );
    }
}
