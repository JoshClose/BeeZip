//! The classic context menu for a selection, as Explorer builds it (docs/M4.md §9):
//!
//! ```text
//! cargo run -p beezip-shell --example menu_dump -- [--invoke TITLE] [--wait MS] PATH…
//! ```
//!
//! It asks the shell for the selection's `IContextMenu` (`IShellItemArray` → `BHID_SFUIObject`),
//! as "Show more options" and Windows 10's menu do, fills a popup menu with it, opens each
//! submenu with `WM_INITMENUPOPUP`, and prints the tree: one item per line, submenus indented
//! with " >" after their title, separators as `-----`. Packaged verbs are in it too, served from
//! `DllHost.exe`, so the one tool checks both registrations.
//!
//! `--invoke TITLE` then runs the item with that title (`&` accelerators ignored), as a click
//! would, and keeps the thread's messages moving for `--wait` milliseconds (3000) so a handler
//! that works asynchronously can finish. Exit codes: 0, 1 for an error, 2 for bad arguments,
//! 3 when `--invoke` found no such item.
#![allow(unsafe_code)]

#[cfg(not(windows))]
fn main() {
    eprintln!("menu_dump runs on Windows only");
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    windows_main::main()
}

#[cfg(windows)]
mod windows_main {
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};
    use windows::Win32::UI::Shell::Common::ITEMIDLIST;
    use windows::Win32::UI::Shell::{
        BHID_SFUIObject, CMF_NORMAL, CMINVOKECOMMANDINFO, CMINVOKECOMMANDINFOEX, GCS_VERBW,
        IContextMenu, IContextMenu2, IContextMenu3, ILFree, IShellItemArray,
        SHCreateShellItemArrayFromIDLists, SHParseDisplayName,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreatePopupMenu, DestroyMenu, DispatchMessageW, GetMenuItemCount, GetMenuItemInfoW, HMENU,
        MENUITEMINFOW, MFS_DISABLED, MFT_OWNERDRAW, MFT_SEPARATOR, MIIM_FTYPE, MIIM_ID, MIIM_STATE,
        MIIM_STRING, MIIM_SUBMENU, MSG, PM_REMOVE, PeekMessageW, SW_SHOWNORMAL, TranslateMessage,
        WM_INITMENUPOPUP,
    };
    use windows_core::{HSTRING, Interface, PCSTR, PCWSTR, PSTR};

    const FIRST: u32 = 1;
    // ShObjIdl.h's CMIC_MASK_* values, which windows 0.62 doesn't carry.
    const CMIC_MASK_FLAG_NO_UI: u32 = 0x0000_0400;
    const CMIC_MASK_UNICODE: u32 = 0x0000_4000;
    const LAST: u32 = 0x7FFF;

    struct Args {
        invoke: Option<String>,
        wait: Duration,
        paths: Vec<String>,
    }

    fn args() -> Result<Args, String> {
        let mut out = Args {
            invoke: None,
            wait: Duration::from_millis(3000),
            paths: Vec::new(),
        };
        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--invoke" => out.invoke = Some(it.next().ok_or("--invoke takes a title")?),
                "--wait" => {
                    let ms = it.next().ok_or("--wait takes milliseconds")?;
                    out.wait = Duration::from_millis(ms.parse().map_err(|_| "--wait: a number")?);
                }
                _ => out.paths.push(a),
            }
        }
        if out.paths.is_empty() {
            return Err("usage: menu_dump [--invoke TITLE] [--wait MS] PATH…".into());
        }
        Ok(out)
    }

    pub fn main() -> ExitCode {
        let args = match args() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        match run(&args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("menu_dump: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// One menu item, with the path of titles above it.
    struct Found {
        id: u32,
        title: String,
    }

    fn run(args: &Args) -> windows_core::Result<ExitCode> {
        // SAFETY: once, on this thread, before any COM call.
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.ok()?;
        let array = shell_items(&args.paths)?;
        // SAFETY: `array` is live; the shell returns the selection's context menu.
        let menu: IContextMenu = unsafe { array.BindToHandler(None, &BHID_SFUIObject) }?;
        // SAFETY: plain calls on a menu this function owns until DestroyMenu.
        let hmenu = unsafe { CreatePopupMenu() }?;
        let hr = unsafe { menu.QueryContextMenu(hmenu, 0, FIRST, LAST, CMF_NORMAL) };
        hr.ok()?;
        let mut found = Vec::new();
        dump(&menu, hmenu, 0, &mut found);

        let mut code = ExitCode::SUCCESS;
        if let Some(title) = &args.invoke {
            match found.iter().find(|f| f.title == *title) {
                Some(f) => {
                    println!("invoking {:?} (id {})", f.title, f.id);
                    invoke(&menu, f.id - FIRST)?;
                    pump(args.wait);
                }
                None => {
                    eprintln!("no item titled {title:?}");
                    code = ExitCode::from(3);
                }
            }
        }
        // SAFETY: the menu is ours, and nothing uses it after this.
        let _ = unsafe { DestroyMenu(hmenu) };
        Ok(code)
    }

    /// The selection as the shell sees it: an absolute ID list per path.
    fn shell_items(paths: &[String]) -> windows_core::Result<IShellItemArray> {
        let mut pidls: Vec<*mut ITEMIDLIST> = Vec::new();
        for p in paths {
            let full = std::path::absolute(p).unwrap_or_else(|_| p.into());
            let mut pidl = std::ptr::null_mut();
            // SAFETY: `pidl` receives an ID list this function frees below.
            unsafe {
                SHParseDisplayName(&HSTRING::from(full.as_os_str()), None, &mut pidl, 0, None)
            }?;
            pidls.push(pidl);
        }
        let borrowed: Vec<*const ITEMIDLIST> = pidls.iter().map(|p| p.cast_const()).collect();
        // SAFETY: every pointer is a live ID list from SHParseDisplayName; the array copies them.
        let array = unsafe { SHCreateShellItemArrayFromIDLists(&borrowed) };
        for p in pidls {
            // SAFETY: each was allocated by SHParseDisplayName and is freed once.
            unsafe { ILFree(Some(p.cast_const())) };
        }
        array
    }

    /// Prints `hmenu` from `depth`, opening submenus as Explorer does before showing them.
    fn dump(menu: &IContextMenu, hmenu: HMENU, depth: usize, found: &mut Vec<Found>) {
        // SAFETY: `hmenu` is a live menu filled by the handler.
        let count = unsafe { GetMenuItemCount(Some(hmenu)) };
        let indent = "    ".repeat(depth);
        for i in 0..count.max(0) as u32 {
            let mut text = vec![0u16; 1024];
            let mut info = MENUITEMINFOW {
                cbSize: size_of::<MENUITEMINFOW>() as u32,
                fMask: MIIM_FTYPE | MIIM_ID | MIIM_STATE | MIIM_STRING | MIIM_SUBMENU,
                dwTypeData: windows_core::PWSTR(text.as_mut_ptr()),
                cch: text.len() as u32 - 1,
                ..Default::default()
            };
            // SAFETY: `info` and its buffer outlive the call; `cch` leaves room for the NUL.
            if unsafe { GetMenuItemInfoW(hmenu, i, true, &mut info) }.is_err() {
                continue;
            }
            if info.fType.contains(MFT_SEPARATOR) {
                println!("{indent}-----");
                continue;
            }
            let raw = String::from_utf16_lossy(&text[..info.cch as usize]);
            // The accelerator marks go, and a tab's shortcut text with them.
            let title = raw.split('\t').next().unwrap_or_default().replace('&', "");
            let title = if title.is_empty() && info.fType.contains(MFT_OWNERDRAW) {
                format!(
                    "<owner-drawn{}>",
                    verb(menu, info.wID)
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default()
                )
            } else {
                title
            };
            let disabled = if info.fState.contains(MFS_DISABLED) {
                " [disabled]"
            } else {
                ""
            };
            if info.hSubMenu.is_invalid() {
                println!("{indent}{title}{disabled}");
                found.push(Found {
                    id: info.wID,
                    title,
                });
            } else {
                println!("{indent}{title} >{disabled}");
                open_submenu(menu, info.hSubMenu, i);
                dump(menu, info.hSubMenu, depth + 1, found);
            }
        }
    }

    /// `WM_INITMENUPOPUP`, through `IContextMenu3` or `IContextMenu2`, which is how a handler
    /// fills a submenu it left empty.
    fn open_submenu(menu: &IContextMenu, sub: HMENU, index: u32) {
        let (w, l) = (WPARAM(sub.0 as usize), LPARAM(index as isize));
        if let Ok(m3) = menu.cast::<IContextMenu3>() {
            // SAFETY: `sub` is a live submenu of the menu the handler filled.
            let _ = unsafe { m3.HandleMenuMsg2(WM_INITMENUPOPUP, w, l, None) };
        } else if let Ok(m2) = menu.cast::<IContextMenu2>() {
            // SAFETY: as above.
            let _ = unsafe { m2.HandleMenuMsg(WM_INITMENUPOPUP, w, l) };
        }
    }

    /// The canonical verb of a command id, when the handler gives one.
    fn verb(menu: &IContextMenu, id: u32) -> Option<String> {
        let offset = id.checked_sub(FIRST)?;
        let mut buf = vec![0u16; 256];
        // SAFETY: GCS_VERBW writes at most `cchmax` UTF-16 units into `buf`.
        unsafe {
            menu.GetCommandString(
                offset as usize,
                GCS_VERBW,
                None,
                PSTR(buf.as_mut_ptr().cast()),
                buf.len() as u32 - 1,
            )
        }
        .ok()?;
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..n])).filter(|s| !s.is_empty())
    }

    /// Runs the command at `offset` as a click on it would.
    fn invoke(menu: &IContextMenu, offset: u32) -> windows_core::Result<()> {
        let info = CMINVOKECOMMANDINFOEX {
            cbSize: size_of::<CMINVOKECOMMANDINFOEX>() as u32,
            fMask: CMIC_MASK_UNICODE | CMIC_MASK_FLAG_NO_UI,
            // MAKEINTRESOURCE: a verb given by its offset rather than by name.
            lpVerb: PCSTR(offset as usize as *const u8),
            lpVerbW: PCWSTR(offset as usize as *const u16),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };
        // SAFETY: `info` is a complete CMINVOKECOMMANDINFOEX, which starts with the
        // CMINVOKECOMMANDINFO fields, and lives for the call.
        unsafe { menu.InvokeCommand(std::ptr::from_ref(&info).cast::<CMINVOKECOMMANDINFO>()) }
    }

    /// Dispatches this thread's messages for `wait`.
    fn pump(wait: Duration) {
        let end = Instant::now() + wait;
        while Instant::now() < end {
            let mut msg = MSG::default();
            // SAFETY: plain message loop calls on this thread's queue.
            while unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
                unsafe {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
