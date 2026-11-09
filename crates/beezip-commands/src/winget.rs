//! winget, for `seven_zip.install` (docs/M6.md §3.8): found on PATH, run with its console
//! hidden, its output turned into lines worth showing, and its exit code into BeeZip's errors.
//!
//! winget prints in the language Windows shows, so nothing is decided from its text: only from
//! its exit codes, which are HRESULTs (winget-cli's
//! `doc/windows/package-manager/winget/returnCodes.md`).

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use crate::{CmdError, ErrorCode};

/// 7-Zip's id in winget's own source.
pub const PACKAGE: &str = "7zip.7zip";
/// Where 7-Zip comes from without winget.
pub const DOWNLOAD_URL: &str = "https://7-zip.org/download.html";

/// winget's program: `winget.exe` on PATH, or in WindowsApps, where its app execution alias
/// lives. Debug builds take `BEEZIP_WINGET` instead: a path, and one that isn't there means
/// there's no winget.
pub fn find() -> Option<PathBuf> {
    if cfg!(debug_assertions)
        && let Some(p) = std::env::var_os("BEEZIP_WINGET")
    {
        let p = PathBuf::from(p);
        return exists(&p).then_some(p);
    }
    if !cfg!(windows) {
        return None;
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let apps = std::env::var_os("LOCALAPPDATA")
        .map(|d| Path::new(&d).join("Microsoft").join("WindowsApps"));
    std::env::split_paths(&path)
        .chain(apps)
        .map(|d| d.join("winget.exe"))
        .find(|p| exists(p))
}

/// The alias is a reparse point that only CreateProcess follows, so `is_file` says no.
fn exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| !m.is_dir())
}

/// What winget is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Install,
    Upgrade,
}

impl Verb {
    /// winget's arguments: 7-Zip from winget's own source only, so no other source can answer
    /// for its id, and never a question nobody would see.
    pub fn args(self) -> [&'static str; 9] {
        let verb = match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
        };
        [
            verb,
            "--id",
            PACKAGE,
            "--exact",
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--disable-interactivity",
        ]
    }
}

/// A piece of winget's output, as BeeZip shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// "Downloading https://…", "Successfully installed".
    Status(String),
    /// A progress bar's figures: "1.00 MB / 1.50 MB", "45%".
    Bar(String),
}

const BAR: [char; 4] = ['█', '▒', '▓', '░'];

/// One `\r`- or `\n`-ended piece of output, cleaned: escape sequences and backspaced
/// characters out, spinner frames and blank pieces dropped, progress bars cut to their figures.
pub fn clean(raw: &str) -> Option<Line> {
    let text = strip_controls(raw);
    let text = text.trim();
    if text
        .chars()
        .all(|c| matches!(c, '-' | '\\' | '|' | '/' | ' '))
    {
        return None;
    }
    if text.contains(BAR) {
        let figures = text.replace(BAR, " ");
        let figures = figures.split_whitespace().collect::<Vec<_>>().join(" ");
        return (!figures.is_empty()).then_some(Line::Bar(figures));
    }
    Some(Line::Status(text.to_owned()))
}

/// `raw` without terminal escape sequences (CSI, OSC and two-character ones) and control
/// characters; a backspace takes back the character before it.
fn strip_controls(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                // CSI: parameters, then a final byte in @..~.
                Some('[') => {
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC: up to BEL or ESC \.
                Some(']') => {
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\u{8}' => {
                out.pop();
            }
            '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Cuts a byte stream into pieces at `\r` and `\n`. Both are ASCII, so a piece never splits a
/// UTF-8 character.
#[derive(Debug, Default)]
pub struct Splitter {
    pending: Vec<u8>,
}

impl Splitter {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == b'\r' || b == b'\n' {
                out.extend(self.finish());
            } else {
                self.pending.push(b);
            }
        }
        out
    }

    /// What's left after the last line end.
    pub fn finish(&mut self) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        let piece = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        Some(piece)
    }
}

/// winget's exit codes that BeeZip tells apart.
pub mod code {
    pub const COMMAND_FAILED: u32 = 0x8A15_0003;
    pub const CTRL_SIGNAL_RECEIVED: u32 = 0x8A15_0005;
    pub const SHELLEXEC_INSTALL_FAILED: u32 = 0x8A15_0006;
    pub const DOWNLOAD_FAILED: u32 = 0x8A15_0008;
    pub const INSTALLER_HASH_MISMATCH: u32 = 0x8A15_0011;
    pub const NO_APPLICATIONS_FOUND: u32 = 0x8A15_0014;
    pub const NO_MANIFEST_FOUND: u32 = 0x8A15_0017;
    pub const UPDATE_NOT_APPLICABLE: u32 = 0x8A15_002B;
    pub const BLOCKED_BY_POLICY: u32 = 0x8A15_003A;
    pub const MSI_INSTALL_FAILED: u32 = 0x8A15_0049;
    pub const PACKAGE_ALREADY_INSTALLED: u32 = 0x8A15_0061;
    pub const INSTALLER_ZERO_BYTE_FILE: u32 = 0x8A15_0086;
    pub const INSTALL_PACKAGE_IN_USE: u32 = 0x8A15_0101;
    pub const INSTALL_IN_PROGRESS: u32 = 0x8A15_0102;
    pub const INSTALL_FILE_IN_USE: u32 = 0x8A15_0103;
    pub const INSTALL_NO_NETWORK: u32 = 0x8A15_0107;
    pub const INSTALL_CONTACT_SUPPORT: u32 = 0x8A15_0108;
    pub const INSTALL_REBOOT_REQUIRED_TO_FINISH: u32 = 0x8A15_0109;
    pub const INSTALL_REBOOT_REQUIRED_FOR_INSTALL: u32 = 0x8A15_010A;
    pub const INSTALL_REBOOT_INITIATED: u32 = 0x8A15_010B;
    pub const INSTALL_CANCELLED_BY_USER: u32 = 0x8A15_010C;
    pub const INSTALL_ALREADY_INSTALLED: u32 = 0x8A15_010D;
    pub const INSTALL_BLOCKED_BY_POLICY: u32 = 0x8A15_010F;
    pub const INSTALL_PACKAGE_IN_USE_BY_APPLICATION: u32 = 0x8A15_0111;
    pub const INSTALL_CUSTOM_ERROR: u32 = 0x8A15_0115;
}

/// How a winget run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Installed or updated.
    Done,
    /// Installed, but Windows needs a restart to finish.
    Restart,
    /// Nothing to do: it's installed, and there's nothing newer.
    Nothing,
    /// winget knows no installed 7-Zip to upgrade, or has no 7-Zip at all.
    NoPackage,
    /// The administrator prompt was declined, or the installer was cancelled.
    Declined,
    Failed(CmdError),
}

/// `0x8A150008`.
pub fn hex(exit: i32) -> String {
    format!("0x{:08X}", exit.cast_unsigned())
}

/// What winget's exit code says, for `verb`. `lines` is what it printed: the last one goes in a
/// message winget's code doesn't explain, and a failure whose output names Windows's "cancelled"
/// error (an elevation prompt declined) counts as declined.
pub fn outcome(verb: Verb, exit: i32, lines: &[String]) -> Outcome {
    use code::*;
    let doing = match verb {
        Verb::Install => "install",
        Verb::Upgrade => "update",
    };
    let fail = |code: ErrorCode, message: String| {
        Outcome::Failed(
            CmdError::new(code, message)
                .with_details(serde_json::json!({ "winget_exit": hex(exit) })),
        )
    };
    let cancelled = || {
        lines.iter().any(|l| {
            l.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w.eq_ignore_ascii_case("0x800704c7") || w == "1223" || w == "1602")
        })
    };
    match exit.cast_unsigned() {
        0 => Outcome::Done,
        INSTALL_REBOOT_REQUIRED_TO_FINISH | INSTALL_REBOOT_INITIATED => Outcome::Restart,
        UPDATE_NOT_APPLICABLE | PACKAGE_ALREADY_INSTALLED | INSTALL_ALREADY_INSTALLED => {
            Outcome::Nothing
        }
        NO_APPLICATIONS_FOUND | NO_MANIFEST_FOUND => Outcome::NoPackage,
        INSTALL_CANCELLED_BY_USER | CTRL_SIGNAL_RECEIVED => Outcome::Declined,
        SHELLEXEC_INSTALL_FAILED
        | COMMAND_FAILED
        | MSI_INSTALL_FAILED
        | INSTALL_CUSTOM_ERROR
        | INSTALL_CONTACT_SUPPORT
            if cancelled() =>
        {
            Outcome::Declined
        }
        DOWNLOAD_FAILED | INSTALL_NO_NETWORK | INSTALLER_ZERO_BYTE_FILE => fail(
            ErrorCode::Io,
            "winget couldn't download 7-Zip's installer. Check the internet connection, then try again."
                .into(),
        ),
        INSTALLER_HASH_MISMATCH => fail(
            ErrorCode::Io,
            "winget refused 7-Zip's installer: it doesn't match the hash winget has for it, so it wasn't run."
                .into(),
        ),
        BLOCKED_BY_POLICY | INSTALL_BLOCKED_BY_POLICY => fail(
            ErrorCode::UnsupportedOperation,
            format!(
                "This PC's policy doesn't let winget {doing} 7-Zip. Ask its administrator for 7-Zip {} or newer.",
                min_version()
            ),
        ),
        INSTALL_IN_PROGRESS => fail(
            ErrorCode::Io,
            "Another installation is running. Try again when it's done.".into(),
        ),
        INSTALL_PACKAGE_IN_USE | INSTALL_FILE_IN_USE | INSTALL_PACKAGE_IN_USE_BY_APPLICATION => {
            fail(
                ErrorCode::Io,
                "7-Zip is in use. Close 7-Zip's windows, then try again.".into(),
            )
        }
        INSTALL_REBOOT_REQUIRED_FOR_INSTALL => fail(
            ErrorCode::Io,
            "Windows needs a restart before 7-Zip can be installed. Restart, then try again."
                .into(),
        ),
        _ => {
            let said = lines
                .last()
                .map(|l| format!(": {l}"))
                .unwrap_or_default();
            fail(
                ErrorCode::Io,
                format!("winget couldn't {doing} 7-Zip ({}){said}", hex(exit)),
            )
        }
    }
}

/// `25.01`.
pub fn min_version() -> String {
    let (major, minor) = beezip_core::backend::MIN_VERSION;
    format!("{major}.{minor:02}")
}

/// What a winget run reports while it runs.
pub trait Watch {
    /// Whether to stop winget now.
    fn cancelled(&self) -> bool;
    /// A piece of output worth showing.
    fn line(&mut self, line: &Line);
    /// winget has been quiet for a moment. It prints in bursts, then waits (a download, the
    /// installer), so the last line of a burst is what it's doing now.
    fn idle(&mut self) {}
}

/// winget's exit code, and the status lines it printed.
#[derive(Debug)]
pub struct Exit {
    pub code: i32,
    pub lines: Vec<String>,
}

/// After winget exits, how long its output may take to close: a program it started can hold
/// the pipes open.
const LINGER: Duration = Duration::from_millis(500);

/// Runs `exe` with `args` until it exits, or until `watch` says stop, which kills it (an
/// elevated installer it started is out of reach, and goes on). Output is read as it comes.
pub fn run(exe: &Path, args: &[&str], watch: &mut dyn Watch) -> Result<Exit, CmdError> {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // A hidden console rather than none: winget is a console program and expects one.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().map_err(|e| {
        CmdError::new(
            ErrorCode::Io,
            format!("couldn't start winget ({}): {e}", exe.display()),
        )
    })?;

    // Each pipe on its own thread; a thread left blocked on a pipe a grandchild holds open
    // ends when that program does.
    let (tx, rx) = mpsc::channel::<(usize, Option<Vec<u8>>)>();
    let pipes: [Option<Box<dyn Read + Send>>; 2] = [
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    ];
    let mut open = 0;
    for (i, pipe) in pipes.into_iter().enumerate() {
        let Some(mut pipe) = pipe else { continue };
        open += 1;
        let tx = tx.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        let _ = tx.send((i, None));
                        break;
                    }
                    Ok(n) => {
                        if tx.send((i, Some(buf[..n].to_vec()))).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
    drop(tx);

    let mut splitters = [Splitter::default(), Splitter::default()];
    let mut lines: Vec<String> = Vec::new();
    let mut take = |piece: String, watch: &mut dyn Watch| {
        let Some(line) = clean(&piece) else { return };
        if let Line::Status(s) = &line {
            if lines.last() == Some(s) {
                return;
            }
            lines.push(s.clone());
        }
        watch.line(&line);
    };
    let mut exited: Option<Instant> = None;
    loop {
        if watch.cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CmdError::cancelled());
        }
        if open > 0 {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok((i, Some(bytes))) => {
                    for piece in splitters[i].push(&bytes) {
                        take(piece, watch);
                    }
                }
                Ok((i, None)) => {
                    if let Some(piece) = splitters[i].finish() {
                        take(piece, watch);
                    }
                    open -= 1;
                }
                Err(RecvTimeoutError::Timeout) => watch.idle(),
                Err(RecvTimeoutError::Disconnected) => open = 0,
            }
        } else {
            thread::sleep(Duration::from_millis(50));
        }
        if exited.is_none()
            && child
                .try_wait()
                .map_err(|e| CmdError::new(ErrorCode::Io, format!("waiting for winget: {e}")))?
                .is_some()
        {
            exited = Some(Instant::now());
        }
        if exited.is_some_and(|t| open == 0 || t.elapsed() >= LINGER) {
            break;
        }
    }
    for s in &mut splitters {
        if let Some(piece) = s.finish() {
            take(piece, watch);
        }
    }
    let status = child
        .wait()
        .map_err(|e| CmdError::new(ErrorCode::Io, format!("waiting for winget: {e}")))?;
    Ok(Exit {
        code: status.code().unwrap_or(-1),
        lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(s: &str) -> Option<Line> {
        Some(Line::Status(s.into()))
    }

    #[test]
    fn output_is_cleaned() {
        assert_eq!(
            clean("Found 7-Zip [7zip.7zip] Version 26.06"),
            status("Found 7-Zip [7zip.7zip] Version 26.06")
        );
        for frame in ["-", "\\", "|", "/", "   ", "", "  - "] {
            assert_eq!(clean(frame), None, "{frame:?}");
        }
        assert_eq!(
            clean("  ██████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  1.00 MB / 1.50 MB"),
            Some(Line::Bar("1.00 MB / 1.50 MB".into()))
        );
        assert_eq!(clean("████████████████"), None);
        assert_eq!(
            clean("\u{1b}[0G\u{1b}[2K\u{1b}[38;5;11mSuccessfully installed\u{1b}[0m"),
            status("Successfully installed")
        );
        assert_eq!(
            clean("\u{1b}]9;4;1;50\u{7}Downloading"),
            status("Downloading")
        );
        assert_eq!(
            clean("-\u{8}\\\u{8}|\u{8}Starting package install..."),
            status("Starting package install...")
        );
        assert_eq!(clean("a\tb"), status("a b"));
    }

    #[test]
    fn pieces_end_at_cr_and_lf() {
        let mut s = Splitter::default();
        assert_eq!(s.push(b"Found 7-Zip\r\nVers"), ["Found 7-Zip"]);
        assert_eq!(
            s.push("ion: 26.06\r-\r\\\r© 1999\r\n".as_bytes()),
            ["Version: 26.06", "-", "\\", "© 1999"]
        );
        assert_eq!(s.push(b"tail"), Vec::<String>::new());
        assert_eq!(s.finish().as_deref(), Some("tail"));
        assert_eq!(s.finish(), None);
    }

    /// A transcript recorded on Windows 11 (winget 1.29) with its output redirected, as BeeZip
    /// runs it: plain CRLF lines in UTF-8.
    #[test]
    fn a_recorded_transcript() {
        let raw = "Found 7-Zip [7zip.7zip]\r\nVersion: 26.06\r\nPublisher: Igor Pavlov\r\nCopyright: Copyright \u{a9} 1999-2026 Igor Pavlov.\r\n";
        let mut s = Splitter::default();
        let lines: Vec<Line> = s
            .push(raw.as_bytes())
            .iter()
            .filter_map(|p| clean(p))
            .collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(
            lines[3],
            Line::Status("Copyright: Copyright © 1999-2026 Igor Pavlov.".into())
        );
    }

    /// What winget 1.29 printed on Windows 10 when the administrator prompt was declined
    /// (2026-11-09): 7-Zip's MSI exits 1602, and winget exits `INSTALL_CANCELLED_BY_USER`.
    #[test]
    fn a_declined_prompt_recorded_on_windows_10() {
        let lines: Vec<String> = [
            "Found 7-Zip [7zip.7zip] Version 26.06",
            "This application is licensed to you by its owner.",
            "Microsoft is not responsible for, nor does it grant any licenses to, third-party packages.",
            "Downloading https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.msi",
            "Successfully verified installer hash",
            "Starting package install...",
            "The installer will request to run as administrator. Expect a prompt.",
            "You cancelled the installation.",
            "Installer failed with exit code: 1602",
        ]
        .map(String::from)
        .to_vec();
        let exit = code::INSTALL_CANCELLED_BY_USER.cast_signed();
        assert_eq!(outcome(Verb::Install, exit, &lines), Outcome::Declined);
        // Were winget to report it as a plain installer failure, its text still says so.
        let failed = code::MSI_INSTALL_FAILED.cast_signed();
        assert_eq!(outcome(Verb::Install, failed, &lines), Outcome::Declined);
    }

    #[test]
    fn arguments() {
        assert_eq!(
            Verb::Install.args().join(" "),
            "install --id 7zip.7zip --exact --source winget --accept-package-agreements --accept-source-agreements --disable-interactivity"
        );
        assert_eq!(Verb::Upgrade.args()[0], "upgrade");
    }

    fn code(c: u32) -> i32 {
        c.cast_signed()
    }

    fn failed(o: Outcome) -> CmdError {
        match o {
            Outcome::Failed(e) => e,
            other => panic!("not a failure: {other:?}"),
        }
    }

    #[test]
    fn exit_codes() {
        use code::*;
        let none: &[String] = &[];
        let o = |c: u32| outcome(Verb::Install, code(c), none);
        assert_eq!(o(0), Outcome::Done);
        assert_eq!(o(UPDATE_NOT_APPLICABLE), Outcome::Nothing);
        assert_eq!(o(PACKAGE_ALREADY_INSTALLED), Outcome::Nothing);
        assert_eq!(o(NO_APPLICATIONS_FOUND), Outcome::NoPackage);
        assert_eq!(o(INSTALL_CANCELLED_BY_USER), Outcome::Declined);
        assert_eq!(o(INSTALL_REBOOT_REQUIRED_TO_FINISH), Outcome::Restart);

        let e = failed(o(DOWNLOAD_FAILED));
        assert_eq!(e.code, ErrorCode::Io);
        assert!(e.message.contains("couldn't download"), "{}", e.message);
        assert_eq!(e.details.unwrap()["winget_exit"], "0x8A150008");
        let e = failed(o(INSTALLER_HASH_MISMATCH));
        assert!(e.message.contains("hash"), "{}", e.message);
        let e = failed(outcome(
            Verb::Upgrade,
            code(INSTALL_BLOCKED_BY_POLICY),
            none,
        ));
        assert_eq!(e.code, ErrorCode::UnsupportedOperation);
        assert!(
            e.message.contains("winget update 7-Zip") && e.message.contains("25.01"),
            "{}",
            e.message
        );

        // An unknown code names itself and winget's last line.
        let said = [
            "Starting package install...".to_owned(),
            "Installer failed with exit code: 5".to_owned(),
        ];
        let e = failed(outcome(Verb::Install, code(0x8A15_0999), &said));
        assert_eq!(
            e.message,
            "winget couldn't install 7-Zip (0x8A150999): Installer failed with exit code: 5"
        );

        // A declined elevation prompt, however winget words it.
        let declined = [
            "Installer failed with exit code: 0x800704c7 : The operation was canceled by the user."
                .to_owned(),
        ];
        assert_eq!(
            outcome(Verb::Install, code(SHELLEXEC_INSTALL_FAILED), &declined),
            Outcome::Declined
        );
        let msi = ["Installer failed with exit code: 1602".to_owned()];
        assert_eq!(
            outcome(Verb::Install, code(MSI_INSTALL_FAILED), &msi),
            Outcome::Declined
        );
        // 1223 inside another number isn't it.
        let size = ["Installer failed with exit code: 12230".to_owned()];
        assert!(matches!(
            outcome(Verb::Install, code(SHELLEXEC_INSTALL_FAILED), &size),
            Outcome::Failed(_)
        ));
    }

    /// Collects what a run reports, and cancels once a line says to.
    #[derive(Default)]
    struct Seen {
        lines: Vec<Line>,
        cancel_on: Option<&'static str>,
        /// How many lines had come at each quiet moment.
        idle_at: Vec<usize>,
    }

    impl Watch for Seen {
        fn cancelled(&self) -> bool {
            self.cancel_on.is_some_and(|on| {
                self.lines
                    .iter()
                    .any(|l| matches!(l, Line::Status(s) if s == on))
            })
        }

        fn line(&mut self, line: &Line) {
            self.lines.push(line.clone());
        }

        fn idle(&mut self) {
            self.idle_at.push(self.lines.len());
        }
    }

    #[cfg(windows)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(
            &p,
            format!("@echo off\r\n{}\r\n", body.replace('\n', "\r\n")),
        )
        .unwrap();
        p
    }

    /// A stand-in winget: its lines arrive in order, stderr's too, and its HRESULT exit code
    /// comes back whole.
    #[cfg(windows)]
    #[test]
    fn a_run_reports_lines_and_the_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let exe = script(
            dir.path(),
            "winget.cmd",
            "echo Found 7-Zip [7zip.7zip] Version 26.06\n\
             echo Found 7-Zip [7zip.7zip] Version 26.06\n\
             echo   ████████▒▒▒▒  1.00 MB / 1.50 MB\n\
             echo Installer failed 1>&2\n\
             exit /b -1978334964",
        );
        let mut seen = Seen::default();
        let exit = run(&exe, &Verb::Install.args(), &mut seen).unwrap();
        assert_eq!(hex(exit.code), "0x8A15010C");
        // The repeated line is shown once.
        assert_eq!(
            exit.lines,
            ["Found 7-Zip [7zip.7zip] Version 26.06", "Installer failed"]
        );
        assert!(
            seen.lines.contains(&Line::Bar("1.00 MB / 1.50 MB".into())),
            "{:?}",
            seen.lines
        );
        assert_eq!(
            outcome(Verb::Install, exit.code, &exit.lines),
            Outcome::Declined
        );
    }

    /// A pause after a burst of lines is reported before the next line, so the job shows the
    /// burst's last line while winget waits.
    #[cfg(windows)]
    #[test]
    fn a_pause_after_a_burst_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let exe = script(
            dir.path(),
            "winget.cmd",
            "echo Found 7-Zip
echo Downloading
ping -n 2 127.0.0.1 >nul
echo Successfully installed",
        );
        let mut seen = Seen::default();
        run(&exe, &[], &mut seen).unwrap();
        assert_eq!(seen.lines.len(), 3, "{:?}", seen.lines);
        assert!(seen.idle_at.contains(&2), "{:?}", seen.idle_at);
    }

    /// Cancel kills winget at once, even while a program it started holds its output open.
    #[cfg(windows)]
    #[test]
    fn cancel_stops_a_run() {
        let dir = tempfile::tempdir().unwrap();
        let exe = script(
            dir.path(),
            "winget.cmd",
            "echo Downloading\nping -n 6 127.0.0.1 >nul\necho never",
        );
        let mut seen = Seen {
            cancel_on: Some("Downloading"),
            ..Seen::default()
        };
        let start = Instant::now();
        let err = run(&exe, &[], &mut seen).unwrap_err();
        assert_eq!(err.code, ErrorCode::Cancelled);
        assert!(
            start.elapsed() < Duration::from_secs(4),
            "{:?}",
            start.elapsed()
        );
        assert!(!seen.lines.contains(&Line::Status("never".into())));
    }

    /// The real winget, where there is one: `--version` only, which changes nothing. It shows
    /// the app execution alias starts with a hidden console and its output read.
    #[test]
    fn the_real_winget_answers() {
        let Some(exe) = find() else {
            eprintln!("no winget here");
            return;
        };
        let exit = run(&exe, &["--version"], &mut Seen::default()).unwrap();
        assert_eq!(exit.code, 0, "{:?}", exit.lines);
        assert!(
            exit.lines.iter().any(|l| l.starts_with('v')),
            "{:?}",
            exit.lines
        );
    }
}
