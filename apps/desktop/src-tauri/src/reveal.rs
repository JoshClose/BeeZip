//! When a window first appears: the main window, and each job window Explorer's menu opens.
//! WebView2 takes several times longer to start than everything else BeeZip does at launch, and
//! a window shown meanwhile is an empty white rectangle. So on Windows a window comes onto the
//! screen once its page has painted (`cmd_ready`), with BeeZip in it.
//!
//! - **Cloaked, not hidden:** the window is cloaked as it is made (`DWMWA_CLOAK`: the desktop
//!   doesn't draw it) and shown as always, so to Windows and to WebView2 it is an ordinary
//!   visible window: it is activated when it was before, and its page paints. Uncloaking puts a
//!   finished frame on the screen.
//! - **Never made hidden:** WebView2 gives a hidden window's page a background priority, and on
//!   a machine with every core busy that page then took 4 to 7 seconds to start, not 1.4. A
//!   window shown only once its page was ready also came up black for a frame, then in its
//!   background colour, while WebView2 drew its first frame.
//! - **The wait has an end:** [`PAGE_WAIT`] after the webview exists, the window is uncloaked
//!   whatever its page did, so a page that never paints still gives a window.
//! - **Its background is the page's,** light or dark, and follows the theme: it is what shows
//!   wherever the page hasn't painted, at the wait's end above all.
//! - **Elsewhere** nothing changes: there is no cloak, and the page's report does nothing.
//! - **Job windows** wait too. A click on Explorer's menu got its window at once, but empty,
//!   white even in dark mode, until its page painted; now the window comes up when it would
//!   have filled in, with the job in it.

use std::{
    collections::HashSet,
    sync::{Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use tauri::{
    AppHandle, Manager, Runtime, Theme, WebviewWindow, WebviewWindowBuilder, Window, window::Color,
};

use crate::open::trace;

/// Whether a window waits, cloaked, for its page.
pub const WAITS: bool = cfg!(windows);

/// How long after its webview exists a window waits for its page before it is uncloaked
/// anyway. A page paints some 100 ms after it starts to load, and a few hundred on a busy machine.
pub const PAGE_WAIT: Duration = Duration::from_secs(1);

/// The page's `--paper` (src/index.css), light and dark: what the window shows where the page
/// hasn't painted.
pub const PAPER_LIGHT: Color = Color(0xf6, 0xf6, 0xf3, 0xff);
pub const PAPER_DARK: Color = Color(0x18, 0x19, 0x1b, 0xff);

/// `--paper` in `theme`.
pub fn paper(theme: Theme) -> Color {
    match theme {
        Theme::Dark => PAPER_DARK,
        _ => PAPER_LIGHT,
    }
}

/// The windows still waiting for their pages, by label. Until the main window is on the
/// screen, a second launch leaves bringing it up to its page.
#[derive(Debug, Default)]
pub struct Revealed(Mutex<HashSet<String>>);

impl Revealed {
    fn waiting(&self) -> MutexGuard<'_, HashSet<String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new window, `label`, on the screen when made or not.
    pub fn start(&self, label: &str, shown: bool) {
        let mut waiting = self.waiting();
        if shown {
            waiting.remove(label);
        } else {
            waiting.insert(label.to_owned());
        }
    }

    /// Whether the window `label` is on the screen, or about to be.
    pub fn is_set(&self, label: &str) -> bool {
        !self.waiting().contains(label)
    }

    /// Marks the window `label` as on the screen. `true` the first time only, for the one who
    /// then uncloaks it.
    pub fn set(&self, label: &str) -> bool {
        self.waiting().remove(label)
    }
}

/// Builds the window `label` from `builder`, on the main thread: cloaked from the moment it
/// exists (Windows), in the page's background, and uncloaked at the latest [`PAGE_WAIT`] after
/// this returns. A window that couldn't be cloaked is simply there, as it used to be.
pub fn build<R: Runtime, M: Manager<R>>(
    app: &AppHandle<R>,
    label: &str,
    builder: WebviewWindowBuilder<'_, R, M>,
) -> tauri::Result<WebviewWindow<R>> {
    if let Some(revealed) = app.try_state::<Revealed>() {
        revealed.start(label, !WAITS);
    }
    let window = {
        #[cfg(windows)]
        let _cloaking = win::CloakNew::arm();
        builder.build()?
    };
    if WAITS {
        if let Ok(theme) = window.theme() {
            let _ = window.set_background_color(Some(paper(theme)));
        }
        let (app, label) = (app.clone(), label.to_owned());
        std::thread::spawn(move || {
            std::thread::sleep(PAGE_WAIT);
            reveal(&app, &label, "its page didn't say it painted");
        });
    }
    Ok(window)
}

/// Puts the window `label` on the screen, the first time it is asked.
pub fn reveal<R: Runtime>(app: &AppHandle<R>, label: &str, why: &str) {
    let first = app.try_state::<Revealed>().is_some_and(|r| r.set(label));
    if !first {
        return;
    }
    trace(|| format!("window {label} is on the screen: {why}"));
    #[cfg(windows)]
    if let Some(hwnd) = app.get_webview_window(label).and_then(|w| w.hwnd().ok()) {
        win::cloak(hwnd, false);
    }
}

/// The cloak, and the hook that puts it on a window as it is made.
#[cfg(windows)]
#[allow(unsafe_code)] // DWM's cloak and a message hook
mod win {
    use std::cell::Cell;

    use windows::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        Graphics::Dwm::{DWMWA_CLOAK, DwmSetWindowAttribute},
        System::Threading::GetCurrentThreadId,
        UI::WindowsAndMessaging::{
            CWPSTRUCT, CallNextHookEx, GetClassNameW, HC_ACTION, HHOOK, SetWindowsHookExW,
            UnhookWindowsHookEx, WH_CALLWNDPROC, WM_CREATE, WM_SHOWWINDOW,
        },
    };

    use crate::open::trace;

    /// The class of the windows Tauri makes (its default `window_classname`).
    const TAURI_WINDOW: &str = "Tauri Window";

    thread_local! {
        /// Whether a [`CloakNew`] is alive on this thread.
        static ARMED: Cell<bool> = const { Cell::new(false) };
    }

    /// Cloaks or uncloaks a window: shown, with its page painting, but not drawn on the desktop.
    pub fn cloak(hwnd: HWND, on: bool) {
        let value = i32::from(on);
        // SAFETY: `value` is the BOOL the attribute takes, alive for the call; a window that
        // is gone is an error, not undefined behaviour.
        let set = unsafe {
            DwmSetWindowAttribute(
                hwnd,
                DWMWA_CLOAK,
                std::ptr::from_ref(&value).cast(),
                size_of::<i32>() as u32,
            )
        };
        if let Err(e) = set {
            trace(|| format!("a window's cloak ({on}) failed: {e}"));
        }
    }

    /// While this lives, a Tauri window made on this thread is cloaked before it is shown.
    /// Tauri makes a window and its webview in one call and shows the window in between, so
    /// there is no window to cloak before that call and a visible one after it.
    pub struct CloakNew(HHOOK);

    impl CloakNew {
        /// `None` if Windows refuses the hook: the window then comes up uncloaked.
        pub fn arm() -> Option<Self> {
            // SAFETY: `on_message` is a hook procedure for this thread only, removed on drop.
            let hook = unsafe {
                SetWindowsHookExW(WH_CALLWNDPROC, Some(on_message), None, GetCurrentThreadId())
            };
            match hook {
                Ok(hook) => {
                    ARMED.set(true);
                    Some(Self(hook))
                }
                Err(e) => {
                    trace(|| format!("no hook to cloak a new window with: {e}"));
                    None
                }
            }
        }
    }

    impl Drop for CloakNew {
        fn drop(&mut self) {
            ARMED.set(false);
            // SAFETY: the hook `arm` installed, removed once.
            let _ = unsafe { UnhookWindowsHookEx(self.0) };
        }
    }

    /// Sees each message sent to a window of this thread before the window does: a Tauri
    /// window's `WM_CREATE`, and the `WM_SHOWWINDOW` that precedes its first appearance, cloak it.
    unsafe extern "system" fn on_message(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 && ARMED.get() {
            // SAFETY: for HC_ACTION, `lparam` points to the message's CWPSTRUCT.
            let message = unsafe { &*(lparam.0 as *const CWPSTRUCT) };
            let made = message.message == WM_CREATE;
            let shown = message.message == WM_SHOWWINDOW && message.wParam.0 != 0;
            if (made || shown) && is_tauri_window(message.hwnd) {
                cloak(message.hwnd, true);
            }
        }
        // SAFETY: passing the call on, as every hook must.
        unsafe { CallNextHookEx(None, code, wparam, lparam) }
    }

    fn is_tauri_window(hwnd: HWND) -> bool {
        let mut name = [0u16; 32];
        // SAFETY: `name` is a buffer of the length given.
        let len = unsafe { GetClassNameW(hwnd, &mut name) };
        usize::try_from(len).is_ok_and(|len| String::from_utf16_lossy(&name[..len]) == TAURI_WINDOW)
    }
}

/// A window's theme changed (Windows' mode, or the setting): its background follows.
pub fn theme_changed(window: &Window, theme: Theme) {
    if !WAITS {
        return;
    }
    if let Some(window) = window.app_handle().get_webview_window(window.label()) {
        let _ = window.set_background_color(Some(paper(theme)));
    }
}

/// The page has painted: its window, cloaked until now, is on the screen. A window already
/// there is left as it is.
#[tauri::command]
pub fn cmd_ready(window: Window) {
    reveal(window.app_handle(), window.label(), "its page painted");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The colours `--paper` has in index.css, in the order they appear: light, then dark.
    fn css_papers() -> Vec<Color> {
        include_str!("../../src/index.css")
            .lines()
            .filter_map(|l| l.trim().strip_prefix("--paper: #")?.strip_suffix(';'))
            .map(|hex| {
                let n = u32::from_str_radix(hex, 16).unwrap();
                Color((n >> 16) as u8, (n >> 8) as u8, n as u8, 0xff)
            })
            .collect()
    }

    #[test]
    fn the_window_waits_in_the_pages_own_background() {
        assert_eq!(css_papers(), [PAPER_LIGHT, PAPER_DARK]);
        assert_eq!(paper(Theme::Light), PAPER_LIGHT);
        assert_eq!(paper(Theme::Dark), PAPER_DARK);
    }

    #[test]
    fn a_window_comes_onto_the_screen_once() {
        let revealed = Revealed::default();
        revealed.start("main", false);
        assert!(!revealed.is_set("main"));
        assert!(revealed.set("main"), "the page's report uncloaks it");
        assert!(
            !revealed.set("main"),
            "the wait's end finds it on the screen"
        );
        assert!(revealed.is_set("main"));
        // A new main window, after the first was closed, waits again.
        revealed.start("main", false);
        assert!(revealed.set("main"));
        // Where windows aren't cloaked, nobody uncloaks them.
        revealed.start("main", true);
        assert!(!revealed.set("main"));
    }

    #[test]
    fn each_window_waits_for_its_own_page() {
        let revealed = Revealed::default();
        revealed.start("main", false);
        revealed.start("job-1", false);
        revealed.start("job-2", false);
        assert!(revealed.set("job-1"), "a job window's page painted");
        assert!(
            !revealed.is_set("main"),
            "the main window still waits for its own"
        );
        assert!(!revealed.is_set("job-2"));
        assert!(revealed.set("main"));
        assert!(revealed.set("job-2"));
        assert!(!revealed.set("job-1"), "nor is a window uncloaked twice");
        // A window nobody made waiting is on the screen.
        assert!(revealed.is_set("job-3"));
        assert!(!revealed.set("job-3"));
    }
}
