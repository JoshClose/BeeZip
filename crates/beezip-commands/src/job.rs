use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CmdError, ErrorCode, cache::ArchiveCache, config::Config, engine::Live, policy::Policy,
    wire::Secret,
};

pub type JobId = u64;

/// Job progress. Byte counts come from the compressed input, so they are reliable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Progress {
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub entries_done: u64,
    pub entries_total: Option<u64>,
    /// The entry being processed.
    pub current: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum LogLevel {
    Info,
    Warn,
}

/// A question a job needs answered before it can continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind")]
pub enum Prompt {
    Password { entry: Option<String> },
    Overwrite { path: String },
}

/// A front end's answer to a `Prompt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind")]
pub enum PromptReply {
    Password { password: String },
    Overwrite { choice: OverwriteChoice },
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum OverwriteChoice {
    Replace,
    ReplaceAll,
    Skip,
    SkipAll,
    Rename,
}

/// Everything a job reports, in order: `Started`, then any `Progress`, `Log` or `Prompt`, then
/// exactly one of `Finished`, `Failed` or `Cancelled`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "type")]
pub enum JobEvent {
    Started { job: JobId },
    Progress(Progress),
    Log { level: LogLevel, message: String },
    Prompt { id: u64, prompt: Prompt },
    Finished { output: serde_json::Value },
    Failed { error: CmdError },
    Cancelled,
}

/// Receives a job's events. It is called on the job's thread.
pub type EventSink = Arc<dyn Fn(JobEvent) + Send + Sync>;

/// An [`EventSink`] that drops every event.
pub fn discard_events() -> EventSink {
    Arc::new(|_| {})
}

/// Answers prompts. Each front end does it its own way: a TTY prompt, `cmd_respond` or MCP
/// elicitation.
pub trait Interactor: Send + Sync {
    /// `job` says which job asks: a GUI answers through `cmd_respond(job, id, reply)`.
    fn prompt(&self, job: JobId, id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError>;

    /// Called just before the `Prompt` event goes out, so a reply can't arrive before the
    /// interactor is ready for it. A GUI makes its reply slot here.
    fn expect(&self, _job: JobId, _id: u64) {}
}

/// An [`Interactor`] with nobody to ask: every prompt fails with a hint about which argument to
/// pass instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct NonInteractive;

impl Interactor for NonInteractive {
    fn prompt(&self, _job: JobId, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        Err(match prompt {
            Prompt::Password { .. } => CmdError::new(
                ErrorCode::PasswordRequired,
                "a password is required; pass it as the `password` argument",
            ),
            Prompt::Overwrite { path } => CmdError::new(
                ErrorCode::Conflict,
                format!("`{path}` already exists; pass an `overwrite` policy"),
            ),
        })
    }
}

/// A cancellation flag shared by a job and whoever started it. Jobs check it between buffers.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Progress goes out at most this often; the last update always goes out.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// How many times a job asks for a password before giving up with `WrongPassword`.
pub const PASSWORD_PROMPTS: u32 = 3;

/// A running command's view of its job.
pub struct JobCtx {
    id: JobId,
    cancel: CancelToken,
    sink: EventSink,
    interactor: Arc<dyn Interactor>,
    next_prompt: u64,
    policy: Arc<Policy>,
    /// The engine's config when the job started; `settings.set` changes only later jobs'.
    config: Arc<Result<Config, CmdError>>,
    live: Arc<Live>,
    last_progress: Option<Instant>,
    pending_progress: Option<Progress>,
    /// The password given in the input, or the last one a prompt supplied.
    password: Option<String>,
    password_prompts: u32,
    /// A password reached the reader, which may keep it; the archive cache won't take it back.
    password_used: bool,
    cache: Option<Arc<ArchiveCache>>,
}

impl JobCtx {
    pub(crate) fn new(
        id: JobId,
        cancel: CancelToken,
        sink: EventSink,
        interactor: Arc<dyn Interactor>,
        policy: Arc<Policy>,
        live: Arc<Live>,
        cache: Option<Arc<ArchiveCache>>,
    ) -> Self {
        Self {
            id,
            cancel,
            sink,
            interactor,
            next_prompt: 0,
            policy,
            config: live.config(),
            live,
            last_progress: None,
            pending_progress: None,
            password: None,
            password_prompts: 0,
            password_used: false,
            cache,
        }
    }

    pub fn id(&self) -> JobId {
        self.id
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The engine's archive cache; `None` for a job run without an engine.
    pub fn cache(&self) -> Option<&Arc<ArchiveCache>> {
        self.cache.as_ref()
    }

    /// Whether a password reached the reader during this job.
    pub fn password_used(&self) -> bool {
        self.password_used
    }

    /// The config, or the error that made it unusable (a value of the wrong type).
    pub fn config(&self) -> Result<&Config, CmdError> {
        self.config.as_ref().as_ref().map_err(Clone::clone)
    }

    /// The `config.toml` the engine's config came from: the one `settings.*` read and write.
    pub fn config_path(&self) -> Option<PathBuf> {
        self.live
            .path()
            .cloned()
            .or_else(crate::config::config_path)
    }

    /// Where Explorer's menu is registered: the real registry, or a test's own key.
    pub(crate) fn shell_hive(&self) -> &crate::shell::Hive {
        self.live.shell()
    }

    /// The desktop app's own exe, when the desktop app runs this job.
    pub(crate) fn shell_app(&self) -> Option<&Path> {
        self.live.shell_app()
    }

    /// Gives every later job `config`, and the engine's limits its `[limits]`. This job keeps
    /// the config it started with.
    pub(crate) fn replace_config(&self, config: Config) {
        self.live.replace(config);
    }

    /// The password the input gave, tried before anyone is asked.
    pub fn set_password(&mut self, password: Option<&Secret>) {
        self.password = password.map(|p| p.expose().to_owned());
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// `Err(Cancelled)` once the job has been cancelled; use it with `?` between buffers.
    pub fn check_cancelled(&self) -> Result<(), CmdError> {
        if self.is_cancelled() {
            Err(CmdError::cancelled())
        } else {
            Ok(())
        }
    }

    /// Reports progress, at most every 100 ms. Updates in between are held, and the engine
    /// sends the last one before the job's final event.
    pub fn progress(&mut self, progress: Progress) {
        let now = Instant::now();
        let due = self
            .last_progress
            .is_none_or(|t| now.duration_since(t) >= PROGRESS_INTERVAL);
        if due {
            self.last_progress = Some(now);
            self.pending_progress = None;
            (self.sink)(JobEvent::Progress(progress));
        } else {
            self.pending_progress = Some(progress);
        }
    }

    /// Sends a held progress update, if there is one.
    pub fn flush_progress(&mut self) {
        if let Some(p) = self.pending_progress.take() {
            self.last_progress = Some(Instant::now());
            (self.sink)(JobEvent::Progress(p));
        }
    }

    pub fn log(&self, level: LogLevel, message: impl Into<String>) {
        (self.sink)(JobEvent::Log {
            level,
            message: message.into(),
        });
    }

    /// Emits a `Prompt` event, then blocks until the front end answers.
    pub fn prompt(&mut self, prompt: Prompt) -> Result<PromptReply, CmdError> {
        self.next_prompt += 1;
        let id = self.next_prompt;
        self.interactor.expect(self.id, id);
        (self.sink)(JobEvent::Prompt {
            id,
            prompt: prompt.clone(),
        });
        self.interactor.prompt(self.id, id, &prompt)
    }
}

/// The adapter core reaches the job through (docs/M1.md §3.1).
impl beezip_core::Ctx for JobCtx {
    fn is_cancelled(&self) -> bool {
        JobCtx::is_cancelled(self)
    }

    fn progress(&mut self, p: &beezip_core::Progress) {
        JobCtx::progress(
            self,
            Progress {
                bytes_done: p.bytes_done,
                bytes_total: p.bytes_total,
                entries_done: p.entries_done,
                entries_total: p.entries_total,
                current: p.current.clone(),
            },
        );
    }

    fn warn(&mut self, message: String) {
        self.log(LogLevel::Warn, message);
    }

    /// The input's password first; then up to [`PASSWORD_PROMPTS`] prompts. A prompt that
    /// works is kept for the rest of the job. With nobody to ask, a missing password is
    /// `PasswordRequired` and a wrong one `WrongPassword`.
    fn password(&mut self, entry: Option<&str>, attempt: u32) -> beezip_core::Result<String> {
        use beezip_core::{Error, ErrorKind};
        if attempt == 0
            && let Some(pw) = &self.password
        {
            self.password_used = true;
            return Ok(pw.clone());
        }
        if self.password_prompts >= PASSWORD_PROMPTS {
            return Err(Error::new(ErrorKind::WrongPassword, "wrong password"));
        }
        let reply = self.prompt(Prompt::Password {
            entry: entry.map(str::to_owned),
        });
        match reply {
            Ok(PromptReply::Password { password }) => {
                self.password_prompts += 1;
                self.password_used = true;
                self.password = Some(password.clone());
                Ok(password)
            }
            Ok(PromptReply::Cancel) => Err(Error::cancelled()),
            Ok(other) => Err(Error::invalid_args(format!(
                "expected a password, got {other:?}"
            ))),
            Err(e) if e.code == ErrorCode::PasswordRequired && attempt > 0 => Err(Error::new(
                ErrorKind::WrongPassword,
                "wrong password; pass the right one as the `password` argument",
            )),
            Err(e) => Err(e.into()),
        }
    }

    fn overwrite(&mut self, existing: &Path) -> beezip_core::Result<beezip_core::OverwriteChoice> {
        use beezip_core::{Error, OverwriteChoice as C};
        let reply = self.prompt(Prompt::Overwrite {
            path: existing.display().to_string(),
        });
        match reply {
            Ok(PromptReply::Overwrite { choice }) => Ok(match choice {
                OverwriteChoice::Replace => C::Replace,
                OverwriteChoice::ReplaceAll => C::ReplaceAll,
                OverwriteChoice::Skip => C::Skip,
                OverwriteChoice::SkipAll => C::SkipAll,
                OverwriteChoice::Rename => C::Rename,
            }),
            Ok(PromptReply::Cancel) => Err(Error::cancelled()),
            Ok(other) => Err(Error::invalid_args(format!(
                "expected an overwrite choice, got {other:?}"
            ))),
            Err(e) => Err(e.into()),
        }
    }
}
