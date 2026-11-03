//! How core reaches the job without depending on `beezip-commands` (docs/M1.md §3.1).

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{Error, ErrorKind, Result, io::Counter};

/// Job progress. Byte counts track the compressed input, so they are reliable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub entries_done: u64,
    pub entries_total: Option<u64>,
    /// The entry being processed.
    pub current: Option<String>,
}

/// The answer to an overwrite prompt. `ReplaceAll` and `SkipAll` hold for the rest of the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwriteChoice {
    Replace,
    ReplaceAll,
    Skip,
    SkipAll,
    Rename,
}

/// The job, as core sees it. `JobCtx` in `beezip-commands` implements it by forwarding to the
/// job's interactor; [`SimpleCtx`] is the stand-alone version for tests and fuzzers.
pub trait Ctx {
    fn is_cancelled(&self) -> bool;

    /// Reports progress. Callers may report on every buffer; the implementation throttles.
    fn progress(&mut self, p: &Progress);

    fn warn(&mut self, message: String);

    /// A password for `entry` (or the whole archive). `attempt` counts the passwords that
    /// already failed, so `0` is the first ask. Fails with `PasswordRequired` when nobody can
    /// be asked and with `WrongPassword` once the retries are used up.
    fn password(&mut self, entry: Option<&str>, attempt: u32) -> Result<String>;

    /// What to do about an existing file. Only called for the `ask` overwrite policy.
    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice>;

    /// Called by copy loops between buffers: fails once the job is cancelled. Wrappers such as
    /// [`MeteredCtx`] also report progress here.
    fn check(&mut self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::cancelled())
        } else {
            Ok(())
        }
    }
}

/// A [`Ctx`] with nobody to ask: a fixed password, a fixed overwrite answer, an optional
/// cancellation flag, and warnings collected in a list.
#[derive(Debug, Default)]
pub struct SimpleCtx {
    pub password: Option<String>,
    /// The answer to overwrite prompts; `None` fails them with `Conflict`.
    pub overwrite: Option<OverwriteChoice>,
    pub cancel: Option<Arc<AtomicBool>>,
    pub warnings: Vec<String>,
    pub last_progress: Option<Progress>,
    pub progress_calls: u64,
}

impl SimpleCtx {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    #[must_use]
    pub fn with_overwrite(mut self, choice: OverwriteChoice) -> Self {
        self.overwrite = Some(choice);
        self
    }

    #[must_use]
    pub fn with_cancel(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cancel = Some(flag);
        self
    }
}

impl Ctx for SimpleCtx {
    fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }

    fn progress(&mut self, p: &Progress) {
        self.progress_calls += 1;
        self.last_progress = Some(p.clone());
    }

    fn warn(&mut self, message: String) {
        self.warnings.push(message);
    }

    fn password(&mut self, _entry: Option<&str>, attempt: u32) -> Result<String> {
        match (&self.password, attempt) {
            (Some(pw), 0) => Ok(pw.clone()),
            (Some(_), _) => Err(Error::new(ErrorKind::WrongPassword, "wrong password")),
            (None, _) => Err(Error::new(
                ErrorKind::PasswordRequired,
                "a password is required",
            )),
        }
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        self.overwrite.ok_or_else(|| {
            Error::new(
                ErrorKind::Conflict,
                format!("`{}` already exists", existing.display()),
            )
        })
    }
}

/// What a [`MeteredCtx`] reports: a byte counter on the input and entry counts.
#[derive(Debug, Clone, Default)]
pub struct Meter {
    pub bytes: Counter,
    pub bytes_total: Option<u64>,
    pub entries_done: u64,
    pub entries_total: Option<u64>,
    pub current: Option<String>,
}

impl Meter {
    pub fn new(bytes: Counter, bytes_total: Option<u64>) -> Self {
        Self {
            bytes,
            bytes_total,
            ..Self::default()
        }
    }

    pub fn snapshot(&self) -> Progress {
        Progress {
            bytes_done: self.bytes.get(),
            bytes_total: self.bytes_total,
            entries_done: self.entries_done,
            entries_total: self.entries_total,
            current: self.current.clone(),
        }
    }
}

/// Wraps a job's [`Ctx`] so every [`Ctx::check`] between buffers also reports progress from a
/// [`Meter`]. Readers hand one to their sinks, and writers use one while adding entries.
pub struct MeteredCtx<'a> {
    pub inner: &'a mut dyn Ctx,
    pub meter: &'a Meter,
}

impl<'a> MeteredCtx<'a> {
    pub fn new(inner: &'a mut dyn Ctx, meter: &'a Meter) -> Self {
        Self { inner, meter }
    }

    pub fn report(&mut self) {
        let p = self.meter.snapshot();
        self.inner.progress(&p);
    }
}

impl Ctx for MeteredCtx<'_> {
    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    fn progress(&mut self, p: &Progress) {
        self.inner.progress(p);
    }

    fn warn(&mut self, message: String) {
        self.inner.warn(message);
    }

    fn password(&mut self, entry: Option<&str>, attempt: u32) -> Result<String> {
        self.inner.password(entry, attempt)
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        self.inner.overwrite(existing)
    }

    fn check(&mut self) -> Result<()> {
        self.report();
        self.inner.check()
    }
}
