//! A job started for a tool call, and the driver that relays its progress and questions
//! (docs/M2.md §3.3).
//!
//! The job runs on its own thread. Progress and questions come back over a channel to the
//! async driver, which holds the MCP request. A question blocks the job thread until the
//! driver answers it, perhaps only on a later request, when an MRTR retry arrives.

use std::sync::Arc;

use beezip_commands::{
    CancelToken, CmdError, Engine, EventSink, Interactor, JobEvent, JobId, Policy, Progress,
    Prompt, PromptReply,
};
use rmcp::{
    RoleServer,
    model::{ProgressNotificationParam, ProgressToken},
    service::{Peer, RequestContext},
};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::prompt;

/// The driver's answer to a question: a reply, or an error that ends the job.
pub type Answer = Result<PromptReply, CmdError>;

enum Step {
    Progress(Progress),
    Question {
        prompt: Prompt,
        reply: oneshot::Sender<Answer>,
    },
}

/// Hands questions to the driver and waits, on the job's thread, for the answer.
struct McpInteractor {
    steps: mpsc::UnboundedSender<Step>,
}

impl Interactor for McpInteractor {
    fn prompt(&self, _job: JobId, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        if let Prompt::Password { .. } = prompt {
            return Err(prompt::password_required());
        }
        let (reply, answer) = oneshot::channel();
        self.steps
            .send(Step::Question {
                prompt: prompt.clone(),
                reply,
            })
            .map_err(|_| CmdError::cancelled())?;
        // The driver drops the sender when the call is cancelled or a parked job expires.
        answer
            .blocking_recv()
            .unwrap_or_else(|_| Err(CmdError::cancelled()))
    }
}

/// A running job, as the driver sees it.
pub struct Job {
    cancel: CancelToken,
    steps: mpsc::UnboundedReceiver<Step>,
    done: tokio::task::JoinHandle<Result<Value, CmdError>>,
}

/// What the job did next.
pub enum Next {
    Done(Result<Value, CmdError>),
    Question {
        prompt: Prompt,
        reply: oneshot::Sender<Answer>,
    },
}

impl Job {
    /// Starts `name` under `policy`.
    pub fn start(
        engine: &Engine,
        name: &str,
        args: Value,
        policy: Policy,
    ) -> Result<Self, CmdError> {
        let (tx, steps) = mpsc::unbounded_channel();
        let progress = tx.clone();
        let sink: EventSink = Arc::new(move |event| {
            if let JobEvent::Progress(p) = event {
                let _ = progress.send(Step::Progress(p));
            }
        });
        let interactor = Arc::new(McpInteractor { steps: tx });
        let handle = engine.invoke_with_policy(name, args, interactor, sink, Arc::new(policy))?;
        let cancel = handle.cancel_token();
        let done = tokio::task::spawn_blocking(move || handle.join());
        Ok(Self {
            cancel,
            steps,
            done,
        })
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Runs until the job ends or asks something, sending its progress to `reporter`. If `ct`
    /// fires first, the job is cancelled.
    pub async fn next(&mut self, reporter: &mut Reporter, ct: &CancellationToken) -> Next {
        loop {
            tokio::select! {
                biased;
                () = ct.cancelled() => {
                    self.cancel();
                    return Next::Done(Err(CmdError::cancelled()));
                }
                step = self.steps.recv() => match step {
                    Some(Step::Progress(p)) => reporter.report(&p).await,
                    Some(Step::Question { prompt, reply }) => {
                        return Next::Question { prompt, reply };
                    }
                    // The job has let go of its channels, so it is ending.
                    None => return Next::Done(joined((&mut self.done).await)),
                },
                result = &mut self.done => {
                    // The last progress update goes out before the result.
                    while let Ok(step) = self.steps.try_recv() {
                        if let Step::Progress(p) = step {
                            reporter.report(&p).await;
                        }
                    }
                    return Next::Done(joined(result));
                }
            }
        }
    }
}

fn joined(
    result: Result<Result<Value, CmdError>, tokio::task::JoinError>,
) -> Result<Value, CmdError> {
    result.unwrap_or_else(|e| Err(CmdError::internal(format!("job task failed: {e}"))))
}

/// Sends `notifications/progress` for a request that asked for them with a `progressToken`.
pub struct Reporter {
    target: Option<(Peer<RoleServer>, ProgressToken)>,
    last: Option<u64>,
}

impl Reporter {
    pub fn new(cx: &RequestContext<RoleServer>) -> Self {
        Self {
            target: cx
                .meta
                .get_progress_token()
                .map(|token| (cx.peer.clone(), token)),
            last: None,
        }
    }

    async fn report(&mut self, p: &Progress) {
        let Some((peer, token)) = &self.target else {
            return;
        };
        // The value must grow with every notification.
        if self.last.is_some_and(|last| p.bytes_done <= last) {
            return;
        }
        self.last = Some(p.bytes_done);
        #[expect(clippy::cast_precision_loss, reason = "progress is approximate")]
        let mut param = ProgressNotificationParam::new(token.clone(), p.bytes_done as f64);
        #[expect(clippy::cast_precision_loss, reason = "progress is approximate")]
        if let Some(total) = p.bytes_total {
            param = param.with_total(total as f64);
        }
        if let Some(current) = &p.current {
            param = param.with_message(current.clone());
        }
        // A client that went away can't be told; the job's result says the rest.
        let _ = peer.notify_progress(param).await;
    }
}
