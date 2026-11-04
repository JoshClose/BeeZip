//! Prompts in the desktop app (docs/M3.md §5.1). A job that asks emits a `Prompt` event and
//! waits here; the page answers with `cmd_respond(job, prompt, reply)`.

use std::{
    collections::HashMap,
    sync::{
        Mutex, MutexGuard, PoisonError,
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    time::Duration,
};

use beezip_commands::{CmdError, Interactor, JobId, Prompt, PromptReply};

/// How often a waiting prompt checks whether its job was cancelled.
const CANCEL_POLL: Duration = Duration::from_millis(100);

type Slot = (JobId, u64);

/// One per process, shared by every job the page starts.
pub struct GuiInteractor {
    /// Whether a job was cancelled or has ended; the engine's `is_cancelled` in the app.
    cancelled: Box<dyn Fn(JobId) -> bool + Send + Sync>,
    senders: Mutex<HashMap<Slot, Sender<PromptReply>>>,
    receivers: Mutex<HashMap<Slot, Receiver<PromptReply>>>,
}

impl GuiInteractor {
    pub fn new(cancelled: impl Fn(JobId) -> bool + Send + Sync + 'static) -> Self {
        Self {
            cancelled: Box::new(cancelled),
            senders: Mutex::new(HashMap::new()),
            receivers: Mutex::new(HashMap::new()),
        }
    }

    fn senders(&self) -> MutexGuard<'_, HashMap<Slot, Sender<PromptReply>>> {
        self.senders.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn receivers(&self) -> MutexGuard<'_, HashMap<Slot, Receiver<PromptReply>>> {
        self.receivers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Answers a pending prompt. An unknown or already answered one is `NotFound`.
    pub fn respond(&self, job: JobId, prompt: u64, reply: PromptReply) -> Result<(), CmdError> {
        let missing = || CmdError::not_found(format!("job {job} has no pending prompt {prompt}"));
        let tx = self.senders().remove(&(job, prompt)).ok_or_else(missing)?;
        tx.send(reply).map_err(|_| missing())
    }

    /// Answers every pending prompt of `job` with `Cancel`.
    pub fn cancel_job(&self, job: JobId) {
        let mut senders = self.senders();
        let slots: Vec<Slot> = senders.keys().filter(|(j, _)| *j == job).copied().collect();
        for slot in slots {
            if let Some(tx) = senders.remove(&slot) {
                let _ = tx.send(PromptReply::Cancel);
            }
        }
    }

    /// Prompts waiting for an answer, for tests.
    #[cfg(test)]
    fn pending(&self) -> usize {
        self.senders().len()
    }
}

impl Interactor for GuiInteractor {
    fn expect(&self, job: JobId, id: u64) {
        let (tx, rx) = mpsc::channel();
        self.senders().insert((job, id), tx);
        self.receivers().insert((job, id), rx);
    }

    fn prompt(&self, job: JobId, id: u64, _prompt: &Prompt) -> Result<PromptReply, CmdError> {
        let rx = match self.receivers().remove(&(job, id)) {
            Some(rx) => rx,
            None => {
                // `expect` always comes first; without it there is nothing to wait on.
                return Err(CmdError::internal(format!(
                    "prompt {id} of job {job} wasn't expected"
                )));
            }
        };
        loop {
            match rx.recv_timeout(CANCEL_POLL) {
                Ok(reply) => return Ok(reply),
                Err(RecvTimeoutError::Timeout) if !(self.cancelled)(job) => {}
                // Cancelled (by `cmd_cancel`, or by closing the window), or the sender went.
                Err(_) => {
                    self.senders().remove(&(job, id));
                    return Ok(PromptReply::Cancel);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Instant,
    };

    use beezip_commands::{ErrorCode, OverwriteChoice};

    use super::*;

    fn ask(gui: &Arc<GuiInteractor>, job: JobId, id: u64) -> thread::JoinHandle<PromptReply> {
        gui.expect(job, id);
        let gui = Arc::clone(gui);
        thread::spawn(move || {
            gui.prompt(job, id, &Prompt::Password { entry: None })
                .unwrap()
        })
    }

    #[test]
    fn a_reply_reaches_the_job() {
        let gui = Arc::new(GuiInteractor::new(|_| false));
        let waiting = ask(&gui, 7, 1);
        // Answering before the job waits works too: the slot exists from `expect`.
        gui.respond(
            7,
            1,
            PromptReply::Overwrite {
                choice: OverwriteChoice::Skip,
            },
        )
        .unwrap();
        assert_eq!(
            waiting.join().unwrap(),
            PromptReply::Overwrite {
                choice: OverwriteChoice::Skip
            }
        );
        assert_eq!(gui.pending(), 0);
    }

    #[test]
    fn unknown_and_answered_prompts_are_not_found() {
        let gui = Arc::new(GuiInteractor::new(|_| false));
        let err = gui.respond(1, 1, PromptReply::Cancel).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        let waiting = ask(&gui, 1, 2);
        gui.respond(1, 2, PromptReply::Cancel).unwrap();
        let err = gui.respond(1, 2, PromptReply::Cancel).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(waiting.join().unwrap(), PromptReply::Cancel);
    }

    #[test]
    fn cancelling_the_job_ends_the_wait() {
        // Through cmd_cancel, which answers the prompt.
        let gui = Arc::new(GuiInteractor::new(|_| false));
        let waiting = ask(&gui, 3, 1);
        gui.cancel_job(3);
        assert_eq!(waiting.join().unwrap(), PromptReply::Cancel);

        // Through the job's token alone, as closing the window does: noticed within a poll.
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let gui = Arc::new(GuiInteractor::new(move |_| flag.load(Ordering::Relaxed)));
        let waiting = ask(&gui, 4, 1);
        thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        cancelled.store(true, Ordering::Relaxed);
        assert_eq!(waiting.join().unwrap(), PromptReply::Cancel);
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(gui.pending(), 0);
        let err = gui.respond(4, 1, PromptReply::Cancel).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }
}
