//! BeeZip's bridge to UnRAR (docs/M3.md §3.4). This crate and `beezip-shell` (M4) are the only
//! ones with unsafe code.
//!
//! UnRAR takes only a file name, decodes on its own call stack and hands data to a callback.
//! So a [`Session`] owns one UnRAR handle on a thread of its own and answers messages: read
//! the next header, test an entry (its data comes back in chunks), skip one, close. UnRAR
//! never writes a file: entries are only tested, and the data goes to BeeZip's own sinks.
//!
//! - **One call at a time:** UnRAR keeps its error state in a global (`ErrHandler`), so every
//!   call into it takes one process-wide lock. Two sessions take turns, one UnRAR call at a
//!   time; a long entry holds the lock while it decodes.
//! - **Passwords:** UnRAR asks through its callback, once per handle. The owner answers.
//! - **Stopping:** the callback returns -1 (UnRAR stops) when [`Session::stop`] was called or
//!   the session was dropped. Its body runs inside `catch_unwind`, so a panic can't unwind into
//!   C++.
//!
//! UnRAR 7.1.0 comes from the copy `unrar_sys` 0.5.8 vendors, with that crate's patches. Its
//! license (THIRD_PARTY_NOTICES.md has it in full) asks for this paragraph in the source
//! comments of a package that includes modified UnRAR source:
//!
//! > UnRAR source code may be used in any software to handle RAR archives without limitations
//! > free of charge, but cannot be used to develop RAR (WinRAR) compatible archiver and to
//! > re-create RAR compression algorithm, which is proprietary. Distribution of modified UnRAR
//! > source code in separate form or as a part of other software is permitted, provided that
//! > full text of this paragraph, starting from "UnRAR source code" words, is included in
//! > license, or in documentation if license is not available, and in source code comments of
//! > resulting package.

#![allow(unsafe_code)]

mod ffi;

use std::{
    os::raw::c_int,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender},
    },
    thread::JoinHandle,
};

use ffi::{LPARAM, UINT, WCHAR};

/// UnRAR's result codes (`ERAR_*`).
pub mod code {
    pub const SUCCESS: i32 = 0;
    pub const END_ARCHIVE: i32 = 10;
    pub const NO_MEMORY: i32 = 11;
    pub const BAD_DATA: i32 = 12;
    pub const BAD_ARCHIVE: i32 = 13;
    pub const UNKNOWN_FORMAT: i32 = 14;
    pub const EOPEN: i32 = 15;
    pub const ECREATE: i32 = 16;
    pub const ECLOSE: i32 = 17;
    pub const EREAD: i32 = 18;
    pub const EWRITE: i32 = 19;
    pub const SMALL_BUF: i32 = 20;
    /// Also what an entry ends with when the callback stopped UnRAR.
    pub const UNKNOWN: i32 = 21;
    pub const MISSING_PASSWORD: i32 = 22;
    pub const EREFERENCE: i32 = 23;
    pub const BAD_PASSWORD: i32 = 24;
    pub const LARGE_DICT: i32 = 25;
}

/// Archive flags from opening (`ROADF_*`).
pub mod flags {
    pub const VOLUME: u32 = 0x0001;
    pub const COMMENT: u32 = 0x0002;
    pub const LOCK: u32 = 0x0004;
    pub const SOLID: u32 = 0x0008;
    pub const NEW_NUMBERING: u32 = 0x0010;
    pub const SIGNED: u32 = 0x0020;
    pub const RECOVERY: u32 = 0x0040;
    pub const ENCRYPTED_HEADERS: u32 = 0x0080;
    pub const FIRST_VOLUME: u32 = 0x0100;
}

/// Entry flags (`RHDF_*`).
pub mod entry_flags {
    pub const SPLIT_BEFORE: u32 = 0x01;
    pub const SPLIT_AFTER: u32 = 0x02;
    pub const ENCRYPTED: u32 = 0x04;
    pub const SOLID: u32 = 0x10;
    pub const DIRECTORY: u32 = 0x20;
}

/// `RedirType`: what a link entry is.
pub mod redir {
    pub const NONE: u32 = 0;
    pub const UNIX_SYMLINK: u32 = 1;
    pub const WIN_SYMLINK: u32 = 2;
    pub const JUNCTION: u32 = 3;
    pub const HARDLINK: u32 = 4;
    pub const FILE_COPY: u32 = 5;
}

pub const HOST_WINDOWS: u32 = 2;
pub const HOST_UNIX: u32 = 3;
pub const HASH_CRC32: u32 = 1;
pub const HASH_BLAKE2: u32 = 2;

/// How to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Headers only, even in a solid archive.
    List,
    /// Headers, and entries to test or skip.
    Extract,
}

/// Why something failed: UnRAR's code, and the volume it asked for if one was missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: i32,
    pub missing_volume: Option<String>,
}

impl Failure {
    fn gone() -> Self {
        Self {
            code: code::UNKNOWN,
            missing_volume: None,
        }
    }
}

/// An archive as opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opened {
    /// `flags::*`.
    pub flags: u32,
    pub comment: Option<String>,
}

/// One entry's header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// As UnRAR gives it, with the platform's separator.
    pub name: String,
    /// `entry_flags::*`.
    pub flags: u32,
    pub pack_size: u64,
    pub unp_size: u64,
    pub host_os: u32,
    pub file_crc: u32,
    /// MS-DOS date and time.
    pub file_time: u32,
    pub unp_ver: u32,
    /// `0x30` (store) to `0x35` (best).
    pub method: u32,
    pub file_attr: u32,
    pub dict_size: u64,
    pub hash_type: u32,
    pub hash: [u8; 32],
    pub redir_type: u32,
    pub redir_name: String,
    pub dir_target: bool,
    /// FILETIMEs: 100 ns since 1601, UTC. 0 when not stored.
    pub mtime: u64,
    pub ctime: u64,
    pub atime: u64,
}

impl Header {
    pub fn is_dir(&self) -> bool {
        self.flags & entry_flags::DIRECTORY != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & entry_flags::ENCRYPTED != 0
    }
}

/// Every call into UnRAR holds this.
static UNRAR: Mutex<()> = Mutex::new(());

fn locked<T>(f: impl FnOnce() -> T) -> T {
    let _g = UNRAR.lock().unwrap_or_else(PoisonError::into_inner);
    f()
}

enum Cmd {
    Next,
    Process(i32),
    Close,
}

enum Event {
    Opened(Result<Opened, i32>),
    Header(Result<Option<Box<Header>>, i32>),
    Data(Vec<u8>),
    Done(i32),
    Ask(SyncSender<Option<String>>),
}

/// What the callback sees, through `UserData`. It lives on the session thread until the
/// handle is closed.
struct CallbackState {
    events: SyncSender<Event>,
    stop: Arc<AtomicBool>,
    max_dict_kib: u64,
    missing: Arc<Mutex<Option<String>>>,
}

/// Data chunks are at most this big; UnRAR hands over up to a window at a time.
const CHUNK: usize = 256 * 1024;

extern "C" fn callback(msg: UINT, user: LPARAM, p1: LPARAM, p2: LPARAM) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `user` is the `CallbackState` the session thread passed as UserData, which
        // outlives the handle.
        let st = unsafe { &*(user as *const CallbackState) };
        handle_callback(st, msg, p1, p2)
    }))
    .unwrap_or(-1)
}

fn handle_callback(st: &CallbackState, msg: UINT, p1: LPARAM, p2: LPARAM) -> c_int {
    match msg {
        ffi::UCM_PROCESSDATA => {
            let Ok(len) = usize::try_from(p2) else {
                return -1;
            };
            if st.stop.load(Ordering::Relaxed) || p1 == 0 {
                return -1;
            }
            // SAFETY: UnRAR passes `len` bytes at `p1`, valid for this call.
            let data = unsafe { std::slice::from_raw_parts(p1 as *const u8, len) };
            for chunk in data.chunks(CHUNK) {
                if st.stop.load(Ordering::Relaxed)
                    || st.events.send(Event::Data(chunk.to_vec())).is_err()
                {
                    return -1;
                }
            }
            1
        }
        ffi::UCM_NEEDPASSWORDW => {
            let (tx, rx) = mpsc::sync_channel(1);
            if st.events.send(Event::Ask(tx)).is_err() {
                return -1;
            }
            let Ok(Some(pw)) = rx.recv() else {
                return -1;
            };
            let wide = to_wide(&pw);
            let Ok(room) = usize::try_from(p2) else {
                return -1;
            };
            if p1 == 0 || wide.len() > room {
                return -1;
            }
            // SAFETY: UnRAR's buffer at `p1` holds `p2` wide characters; `wide` ends in NUL
            // and fits.
            unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), p1 as *mut WCHAR, wide.len()) };
            1
        }
        // A volume UnRAR can't find (ASK): refused, and remembered for the error. The next
        // volume opening (NOTIFY): fine. UnRAR sends the narrow form after the wide one, for
        // both.
        ffi::UCM_CHANGEVOLUMEW | ffi::UCM_CHANGEVOLUME => {
            if p2 != ffi::RAR_VOL_ASK {
                return 1;
            }
            if msg == ffi::UCM_CHANGEVOLUMEW && p1 != 0 {
                // SAFETY: UnRAR passes a NUL-terminated wide string.
                let name = unsafe { from_wide_ptr(p1 as *const WCHAR) };
                *st.missing.lock().unwrap_or_else(PoisonError::into_inner) = Some(name);
            }
            -1
        }
        // UnRAR asks for passwords in the wide form only.
        ffi::UCM_NEEDPASSWORD => -1,
        // A dictionary over UnRAR's own limit: allowed up to the owner's.
        ffi::UCM_LARGEDICT => {
            c_int::from(u64::try_from(p1).is_ok_and(|kib| kib <= st.max_dict_kib))
        }
        _ => 0,
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<WCHAR> {
    s.encode_utf16().chain([0]).collect()
}

#[cfg(not(windows))]
fn to_wide(s: &str) -> Vec<WCHAR> {
    s.chars().map(|c| c as WCHAR).chain([0]).collect()
}

#[cfg(windows)]
fn path_wide(p: &Path) -> Vec<WCHAR> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain([0]).collect()
}

#[cfg(not(windows))]
fn path_wide(p: &Path) -> Vec<WCHAR> {
    to_wide(&p.to_string_lossy())
}

#[cfg(windows)]
fn from_wide(w: &[WCHAR]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

#[cfg(not(windows))]
fn from_wide(w: &[WCHAR]) -> String {
    w.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| {
            u32::try_from(c)
                .ok()
                .and_then(char::from_u32)
                .unwrap_or('\u{FFFD}')
        })
        .collect()
}

/// # Safety
/// `p` must point at a NUL-terminated wide string.
unsafe fn from_wide_ptr(p: *const WCHAR) -> String {
    let mut len = 0usize;
    // SAFETY: the caller's contract: there is a NUL within the string.
    while unsafe { *p.add(len) } != 0 && len < 1 << 16 {
        len += 1;
    }
    // SAFETY: `len` characters were just read.
    from_wide(unsafe { std::slice::from_raw_parts(p, len) })
}

fn convert(h: &ffi::HeaderDataEx, name_ex: &[WCHAR], redir: &[WCHAR]) -> Header {
    // Copies of packed fields: references to them would be unaligned.
    let name_w = { h.file_name_w };
    let name = if name_ex.first().is_some_and(|&c| c != 0) {
        from_wide(name_ex)
    } else {
        from_wide(&name_w)
    };
    let u64_of = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    let redir_type = h.redir_type;
    Header {
        name,
        flags: h.flags,
        pack_size: u64_of(h.pack_size, h.pack_size_high),
        unp_size: u64_of(h.unp_size, h.unp_size_high),
        host_os: h.host_os,
        file_crc: h.file_crc,
        file_time: h.file_time,
        unp_ver: h.unp_ver,
        method: h.method,
        file_attr: h.file_attr,
        dict_size: u64::from(h.dict_size) * 1024,
        hash_type: h.hash_type,
        hash: h.hash,
        redir_type,
        redir_name: if redir_type == redir::NONE {
            String::new()
        } else {
            from_wide(redir)
        },
        dir_target: h.dir_target != 0,
        mtime: u64_of(h.mtime_low, h.mtime_high),
        ctime: u64_of(h.ctime_low, h.ctime_high),
        atime: u64_of(h.atime_low, h.atime_high),
    }
}

/// The session thread: opens the archive, then answers commands until `Close` or until the
/// owner goes away, then closes it.
fn run(path: Vec<WCHAR>, mode: Mode, st: Box<CallbackState>, cmds: Receiver<Cmd>) {
    let events = st.events.clone();
    let mut comment = vec![0 as WCHAR; 64 * 1024];
    // SAFETY: an all-zero RAROpenArchiveDataEx is valid (null pointers, no callback).
    let mut data: ffi::OpenArchiveDataEx = unsafe { std::mem::zeroed() };
    data.arc_name_w = path.as_ptr();
    data.open_mode = match mode {
        Mode::List => ffi::RAR_OM_LIST,
        Mode::Extract => ffi::RAR_OM_EXTRACT,
    };
    data.callback = Some(callback);
    data.user_data = &*st as *const CallbackState as LPARAM;
    data.cmt_buf_w = comment.as_mut_ptr();
    data.cmt_buf_size = u32::try_from(comment.len()).unwrap_or(0);
    // SAFETY: `data`, `path`, `comment` and `st` outlive the handle, which is closed below.
    let h = locked(|| unsafe { ffi::open(&mut data) });
    if h.is_null() {
        let result = data.open_result;
        let _ = events.send(Event::Opened(Err(
            i32::try_from(result).unwrap_or(code::UNKNOWN)
        )));
        return;
    }
    let text = match data.cmt_state {
        1 => Some(from_wide(&comment)).filter(|c| !c.is_empty()),
        _ => None,
    };
    let opened = Opened {
        flags: data.flags,
        comment: text,
    };
    if events.send(Event::Opened(Ok(opened))).is_ok() {
        let mut name_ex = vec![0 as WCHAR; 32 * 1024];
        let mut redir_buf = vec![0 as WCHAR; 32 * 1024];
        while let Ok(cmd) = cmds.recv() {
            match cmd {
                Cmd::Next => {
                    name_ex[0] = 0;
                    redir_buf[0] = 0;
                    // SAFETY: an all-zero RARHeaderDataEx is valid; the buffers set below
                    // stay alive for the call.
                    let mut hd: Box<ffi::HeaderDataEx> = Box::new(unsafe { std::mem::zeroed() });
                    hd.file_name_ex = name_ex.as_mut_ptr();
                    hd.file_name_ex_size = u32::try_from(name_ex.len()).unwrap_or(0);
                    hd.redir_name = redir_buf.as_mut_ptr();
                    hd.redir_name_size = u32::try_from(redir_buf.len()).unwrap_or(0);
                    // SAFETY: `h` is open and `hd` is a valid header with live buffers.
                    let r = locked(|| unsafe { ffi::read_header(h, &mut *hd) });
                    let reply = match r {
                        code::SUCCESS => Ok(Some(Box::new(convert(&hd, &name_ex, &redir_buf)))),
                        code::END_ARCHIVE => Ok(None),
                        e => Err(e),
                    };
                    if events.send(Event::Header(reply)).is_err() {
                        break;
                    }
                }
                Cmd::Process(op) => {
                    // SAFETY: `h` is open.
                    let r = locked(|| unsafe { ffi::process(h, op) });
                    if events.send(Event::Done(r)).is_err() {
                        break;
                    }
                }
                Cmd::Close => break,
            }
        }
    }
    // SAFETY: `h` is open and not used after this.
    locked(|| unsafe { ffi::close(h) });
    drop(st);
}

/// One open archive, on a thread of its own. Calls that wait for UnRAR take `ask`, which
/// answers its password requests (`None` refuses).
pub struct Session {
    cmds: Sender<Cmd>,
    events: Option<Receiver<Event>>,
    stop: Arc<AtomicBool>,
    missing: Arc<Mutex<Option<String>>>,
    thread: Option<JoinHandle<()>>,
}

pub type Ask<'a> = &'a mut dyn FnMut() -> Option<String>;

impl Session {
    /// Opens `path` (an archive, the first volume of a set, or a RAR SFX). Dictionaries up to
    /// `max_dict` bytes are allowed past UnRAR's own limit.
    pub fn open(
        path: &Path,
        mode: Mode,
        max_dict: u64,
        ask: Ask<'_>,
    ) -> Result<(Self, Opened), Failure> {
        let (events_tx, events_rx) = mpsc::sync_channel(4);
        let (cmds_tx, cmds_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let missing = Arc::new(Mutex::new(None));
        let st = Box::new(CallbackState {
            events: events_tx,
            stop: stop.clone(),
            max_dict_kib: max_dict / 1024,
            missing: missing.clone(),
        });
        let wide = path_wide(path);
        let thread = std::thread::Builder::new()
            .name("beezip-unrar".into())
            .spawn(move || run(wide, mode, st, cmds_rx))
            .map_err(|_| Failure::gone())?;
        let mut s = Self {
            cmds: cmds_tx,
            events: Some(events_rx),
            stop,
            missing,
            thread: Some(thread),
        };
        let opened = s.wait(ask, |e| match e {
            Event::Opened(r) => Some(r),
            _ => None,
        })?;
        match opened {
            Ok(o) => Ok((s, o)),
            Err(code) => Err(s.failure(code)),
        }
    }

    fn failure(&self, code: i32) -> Failure {
        Failure {
            code,
            missing_volume: self
                .missing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }

    /// Waits for the event `pick` takes, answering password requests and dropping data.
    fn wait<T>(
        &mut self,
        ask: Ask<'_>,
        mut pick: impl FnMut(Event) -> Option<T>,
    ) -> Result<T, Failure> {
        let events = self.events.as_ref().ok_or_else(Failure::gone)?;
        loop {
            match events.recv() {
                Ok(Event::Ask(reply)) => {
                    let _ = reply.send(ask());
                }
                Ok(Event::Data(_)) => {}
                Ok(e) => {
                    if let Some(v) = pick(e) {
                        return Ok(v);
                    }
                }
                Err(_) => return Err(self.failure(code::UNKNOWN)),
            }
        }
    }

    /// The next entry's header, or `None` at the end.
    pub fn next(&mut self, ask: Ask<'_>) -> Result<Option<Header>, Failure> {
        self.cmds.send(Cmd::Next).map_err(|_| Failure::gone())?;
        let r = self.wait(ask, |e| match e {
            Event::Header(r) => Some(r),
            _ => None,
        })?;
        match r {
            Ok(h) => Ok(h.map(|b| *b)),
            Err(code) => Err(self.failure(code)),
        }
    }

    /// Skips the entry whose header was read last. In a solid archive UnRAR still decodes it.
    pub fn skip(&mut self, ask: Ask<'_>) -> Result<(), Failure> {
        self.cmds
            .send(Cmd::Process(ffi::RAR_SKIP))
            .map_err(|_| Failure::gone())?;
        let r = self.wait(ask, |e| match e {
            Event::Done(r) => Some(r),
            _ => None,
        })?;
        match r {
            code::SUCCESS => Ok(()),
            c => Err(self.failure(c)),
        }
    }

    /// Starts testing the entry whose header was read last; [`Session::chunk`] then hands over
    /// its data.
    pub fn test(&mut self) -> Result<(), Failure> {
        self.cmds
            .send(Cmd::Process(ffi::RAR_TEST))
            .map_err(|_| Failure::gone())
    }

    /// The next piece of the entry being tested: `Some(data)`, `None` once it ended well, or
    /// the failure it ended with (a CRC error is `BAD_DATA`).
    pub fn chunk(&mut self, ask: Ask<'_>) -> Result<Option<Vec<u8>>, Failure> {
        let events = self.events.as_ref().ok_or_else(Failure::gone)?;
        loop {
            match events.recv() {
                Ok(Event::Ask(reply)) => {
                    let _ = reply.send(ask());
                }
                Ok(Event::Data(d)) => return Ok(Some(d)),
                Ok(Event::Done(code::SUCCESS)) => return Ok(None),
                Ok(Event::Done(c)) => return Err(self.failure(c)),
                Ok(_) => {}
                Err(_) => return Err(self.failure(code::UNKNOWN)),
            }
        }
    }

    /// Makes UnRAR stop at its next callback: the entry being tested ends with `UNKNOWN`.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
        let _ = self.cmds.send(Cmd::Close);
        // With the receiver gone, a callback blocked on sending data fails and UnRAR returns.
        drop(self.events.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// UnRAR's version of the DLL API, for `formats.list` and tests.
pub fn api_version() -> i32 {
    // SAFETY: takes no arguments and touches no state.
    locked(|| unsafe { unrar_sys::RARGetDllVersion() })
}
