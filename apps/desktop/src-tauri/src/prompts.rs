//! Prompts in the desktop app (docs/M3.md §5.1). A job that asks emits a `Prompt` event and
//! waits here; the page answers with `cmd_respond(job, prompt, reply)`. The one question that
//! isn't a prompt, whether a password may take more than half the machine's memory (docs/M14.md
//! §5), is a system message box, asked from lib.rs.

use std::{
    collections::HashMap,
    sync::{
        Mutex, MutexGuard, OnceLock, PoisonError,
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    time::Duration,
};

use beezip_commands::{CmdError, Interactor, JobId, Prompt, PromptReply};

/// How often a waiting prompt checks whether its job was cancelled.
const CANCEL_POLL: Duration = Duration::from_millis(100);

type Slot = (JobId, u64);

/// Asks whether a job may use `need` MiB of the machine's `total`, and says yes or no.
type MemoryQuestion = Box<dyn Fn(JobId, u64, u64) -> bool + Send + Sync>;

/// One per process, shared by every job the page starts.
pub struct GuiInteractor {
    /// Whether a job was cancelled or has ended; the engine's `is_cancelled` in the app.
    cancelled: Box<dyn Fn(JobId) -> bool + Send + Sync>,
    senders: Mutex<HashMap<Slot, Sender<PromptReply>>>,
    receivers: Mutex<HashMap<Slot, Receiver<PromptReply>>>,
    /// The memory question, set once the app can show it; until then the answer is no.
    memory: OnceLock<MemoryQuestion>,
}

/// What the memory question says (docs/M14.md §5), in GiB to one decimal.
pub fn memory_question(need_mib: u64, total_mib: u64) -> String {
    let gib = |mib: u64| {
        let tenths = (mib * 10 + 512) / 1024;
        if tenths.is_multiple_of(10) {
            format!("{} GiB", tenths / 10)
        } else {
            format!("{}.{} GiB", tenths / 10, tenths % 10)
        }
    };
    format!(
        "Opening this archive with its password needs {} of memory, more than half of this \
         computer's {}. Other programs may slow down until it's done.\n\nUse that much memory?",
        gib(need_mib),
        gib(total_mib)
    )
}

impl GuiInteractor {
    pub fn new(cancelled: impl Fn(JobId) -> bool + Send + Sync + 'static) -> Self {
        Self {
            cancelled: Box::new(cancelled),
            senders: Mutex::new(HashMap::new()),
            receivers: Mutex::new(HashMap::new()),
            memory: OnceLock::new(),
        }
    }

    /// How the memory question is asked: a message box in the app. Set once.
    pub fn ask_memory_with(&self, ask: impl Fn(JobId, u64, u64) -> bool + Send + Sync + 'static) {
        let _ = self.memory.set(Box::new(ask));
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
    /// Asked on the job's thread, so the message box waits there, not on the main thread.
    fn spend_memory(&self, job: JobId, need_mib: u64, total_mib: u64) -> bool {
        if (self.cancelled)(job) {
            return false;
        }
        self.memory
            .get()
            .is_some_and(|ask| ask(job, need_mib, total_mib))
    }

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

    /// The real commands, through this interactor as the page answers it: an encrypted `.bhive`
    /// none of your keys opens asks with the Unlock prompt, again after a wrong key (docs/M14.md
    /// §8). A recovery key, so no Argon2 runs.
    #[test]
    fn an_encrypted_bhive_opens_through_the_unlock_prompt() {
        use beezip_commands::{
            Engine, EngineOptions, EventSink, JobEvent, PromptReply,
            crypt::{SlotKindName, UnlockReply},
            discard_events, registry,
        };
        use serde_json::json;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        // A settings folder of its own: nobody's keys.
        let engine = Engine::with_options(
            registry(),
            EngineOptions {
                config_path: Some(dir.path().join("config.toml")),
                ..EngineOptions::default()
            },
        );
        let gui = Arc::new(GuiInteractor::new({
            let engine = engine.clone();
            move |job| engine.is_cancelled(job)
        }));
        let archive = dir.path().join("a.bhive");
        let made = engine
            .invoke(
                "archive.create",
                json!({ "output": archive, "inputs": [dir.path().join("a.txt")], "format": "bhive", "recovery_key": true }),
                Arc::clone(&gui) as Arc<dyn Interactor>,
                discard_events(),
            )
            .unwrap()
            .join()
            .unwrap();
        let key = made["recovery_key"].as_str().unwrap().to_string();

        let (tx, rx) = mpsc::channel();
        let sink: EventSink = Arc::new(move |event| {
            if let JobEvent::Prompt { id, prompt } = event {
                let _ = tx.send((id, prompt));
            }
        });
        let job = engine
            .invoke(
                "archive.list",
                json!({ "archive": archive, "flat": true }),
                Arc::clone(&gui) as Arc<dyn Interactor>,
                sink,
            )
            .unwrap();
        let wait = Duration::from_secs(30);
        let (id, prompt) = rx.recv_timeout(wait).unwrap();
        let Prompt::Unlock { ways, attempt, .. } = prompt else {
            panic!("expected the Unlock prompt, got {prompt:?}");
        };
        assert_eq!(attempt, 0);
        assert!(
            ways.iter().any(|w| w.kind == SlotKindName::RecoveryKey),
            "{ways:?}"
        );
        // Well formed, and wrong.
        let wrong = ["000000"; 8].join("-");
        let answer = |key: String| PromptReply::Unlock {
            answer: UnlockReply::RecoveryKey { key },
        };
        gui.respond(job.id(), id, answer(wrong)).unwrap();
        let (id, prompt) = rx.recv_timeout(wait).unwrap();
        assert!(
            matches!(prompt, Prompt::Unlock { attempt: 1, .. }),
            "{prompt:?}"
        );
        gui.respond(job.id(), id, answer(key)).unwrap();
        let listed = job.join().unwrap();
        assert!(listed.to_string().contains("a.txt"), "{listed}");
    }

    #[test]
    fn the_memory_question_is_no_until_the_app_can_ask_it() {
        let gui = GuiInteractor::new(|job| job == 9);
        assert!(!gui.spend_memory(1, 4096, 6144));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&asked);
        gui.ask_memory_with(move |job, need, total| {
            seen.lock().unwrap().push((job, need, total));
            need < 5000
        });
        assert!(gui.spend_memory(1, 4096, 6144));
        assert!(!gui.spend_memory(2, 6000, 8192));
        // A cancelled job isn't asked.
        assert!(!gui.spend_memory(9, 4096, 6144));
        assert_eq!(
            *asked.lock().unwrap(),
            vec![(1, 4096, 6144), (2, 6000, 8192)]
        );
    }

    #[test]
    fn the_memory_question_says_how_much_in_gib() {
        let q = memory_question(4096, 7782);
        assert!(q.starts_with("Opening this archive with its password needs 4 GiB of memory, more than half of this computer's 7.6 GiB."), "{q}");
        assert!(q.ends_with("\n\nUse that much memory?"));
        assert!(
            memory_question(2048, 3500)
                .contains("needs 2 GiB of memory, more than half of this computer's 3.4 GiB")
        );
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
