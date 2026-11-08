//! Running 7-Zip (docs/M6.md §3.3): no console, stdin null or the password, stdout read by the
//! caller, stderr collected on a thread, and the process killed by its handle when the job
//! stops early. No 7-Zip process outlives the [`Run`] that started it.

use std::{
    ffi::OsString,
    io::{self, Read, Write},
    path::Path,
    process::{Child, ChildStdout, Command, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{Error, Result};

/// How much of 7-Zip's stderr is kept; the rest is read and dropped, so 7-Zip never blocks on
/// a full pipe.
const STDERR_CAP: usize = 1 << 20;

/// A 7-Zip command: the console stays hidden, and stdin is null so a prompt reads end of file
/// instead of waiting.
pub fn command(exe: &Path) -> Command {
    let mut c = Command::new(exe);
    c.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console at all: CREATE_NO_WINDOW would still start a conhost.exe for it.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        c.creation_flags(DETACHED_PROCESS);
    }
    #[cfg(not(windows))]
    {
        // 7zz reads its arguments and list files in the locale's charset.
        c.env("LC_ALL", "C.UTF-8");
    }
    c
}

/// A running 7-Zip.
pub struct Run {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    done: bool,
}

/// How a 7-Zip run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// The exit code: 0 ok, 1 warnings, 2 errors, 7 a bad command line, 8 out of memory,
    /// 255 stopped. `None` when it was killed.
    pub code: Option<i32>,
    pub stderr: Vec<u8>,
}

impl Run {
    /// Starts `exe` with `args`. A `password` goes to stdin, which is then closed, so it never
    /// shows on a command line; without one, the caller passes `-p` so 7-Zip never asks.
    pub fn spawn(exe: &Path, args: &[OsString], password: Option<&str>) -> Result<Self> {
        let mut cmd = command(exe);
        cmd.args(args);
        if password.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::io(format!("starting {}", exe.display()), &e))?;
        if let (Some(pw), Some(mut stdin)) = (password, child.stdin.take()) {
            // A few bytes fit in the pipe's buffer, so this can't block on a 7-Zip that never
            // reads them.
            let _ = stdin.write_all(pw.as_bytes());
            let _ = stdin.write_all(b"\n");
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take().map(|mut err| {
            thread::spawn(move || {
                let mut kept = Vec::new();
                let _ = (&mut err).take(STDERR_CAP as u64).read_to_end(&mut kept);
                let _ = io::copy(&mut err, &mut io::sink());
                kept
            })
        });
        Ok(Self {
            child,
            stdout,
            stderr,
            done: false,
        })
    }

    /// 7-Zip's stdout, once.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// Whether 7-Zip has exited.
    pub fn try_wait(&mut self) -> Result<bool> {
        self.child
            .try_wait()
            .map(|s| s.is_some())
            .map_err(|e| Error::io("waiting for 7-Zip", &e))
    }

    /// Stops 7-Zip now, and waits for it to go.
    pub fn kill(&mut self) {
        if !self.done {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.done = true;
        }
    }

    /// Waits for 7-Zip to exit, after its stdout was read to the end (or dropped).
    pub fn finish(mut self) -> Result<Exit> {
        drop(self.stdout.take());
        let status = self
            .child
            .wait()
            .map_err(|e| Error::io("waiting for 7-Zip", &e))?;
        self.done = true;
        let stderr = self
            .stderr
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();
        Ok(Exit {
            code: status.code(),
            stderr,
        })
    }

    /// Kills 7-Zip and returns what it had said on stderr: why a stream ended early.
    pub fn abort(mut self) -> Exit {
        drop(self.stdout.take());
        // It may have exited by itself (an error); then this keeps its code.
        let code = match self.child.try_wait() {
            Ok(Some(status)) => status.code(),
            _ => {
                let _ = self.child.kill();
                self.child.wait().ok().and_then(|s| s.code())
            }
        };
        self.done = true;
        let stderr = self
            .stderr
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();
        Exit { code, stderr }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Runs `exe` to the end, for a short command (the banner, a probe): stdout up to 1 MiB, and
/// a kill after `timeout`.
pub fn output(exe: &Path, args: &[OsString], timeout: Duration) -> Result<(Exit, Vec<u8>)> {
    let mut run = Run::spawn(exe, args, None)?;
    let reader = run.take_stdout().map(|mut out| {
        thread::spawn(move || {
            let mut kept = Vec::new();
            let _ = (&mut out).take(STDERR_CAP as u64).read_to_end(&mut kept);
            let _ = io::copy(&mut out, &mut io::sink());
            kept
        })
    });
    let start = Instant::now();
    loop {
        match run.child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() >= timeout => {
                run.kill();
                return Err(Error::new(
                    crate::ErrorKind::Io,
                    format!(
                        "{} didn't answer within {} s",
                        exe.display(),
                        timeout.as_secs()
                    ),
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(Error::io(format!("running {}", exe.display()), &e)),
        }
    }
    let stdout = reader.and_then(|t| t.join().ok()).unwrap_or_default();
    Ok((run.finish()?, stdout))
}
