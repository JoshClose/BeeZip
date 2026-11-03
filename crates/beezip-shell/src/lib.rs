//! BeeZip Explorer integration: `IExplorerCommand` for the Windows 11 menu and the classic
//! `IContextMenu`, packaged as an in-process COM DLL.
//!
//! An empty stub until M4. When it gains COM methods, each one wraps its body in
//! `catch_unwind` and returns `E_UNEXPECTED` on a panic, because a panic must never unwind into
//! `explorer.exe` (PLAN §1, Explorer integration).
#![cfg(windows)]
