use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{CmdError, ErrorCode};

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
    fn prompt(&self, id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError>;
}

/// An [`Interactor`] with nobody to ask: every prompt fails with a hint about which argument to
/// pass instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct NonInteractive;

impl Interactor for NonInteractive {
    fn prompt(&self, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
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

/// A running command's view of its job.
pub struct JobCtx {
    id: JobId,
    cancel: CancelToken,
    sink: EventSink,
    interactor: Arc<dyn Interactor>,
    next_prompt: u64,
}

impl JobCtx {
    pub(crate) fn new(
        id: JobId,
        cancel: CancelToken,
        sink: EventSink,
        interactor: Arc<dyn Interactor>,
    ) -> Self {
        Self {
            id,
            cancel,
            sink,
            interactor,
            next_prompt: 0,
        }
    }

    pub fn id(&self) -> JobId {
        self.id
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

    pub fn progress(&self, progress: Progress) {
        (self.sink)(JobEvent::Progress(progress));
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
        (self.sink)(JobEvent::Prompt {
            id,
            prompt: prompt.clone(),
        });
        self.interactor.prompt(id, &prompt)
    }
}
