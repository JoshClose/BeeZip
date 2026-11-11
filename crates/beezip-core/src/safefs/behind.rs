//! Writing small files on other threads while the reader decodes the next (docs/M8.md §6.3).
//!
//! A reader that decodes on one thread (a cabinet's folders, an MSI's cabinets) spends as long
//! creating many small files as decoding them: each is a partial file, its data, a rename, its
//! time, its attributes and its Mark of the Web. With [`Behind`], [`super::FsSink`] still decides
//! everything on the job's thread, in archive order (the name made safe, its folders, the
//! overwrite policy and its prompts, the report), and reads each file's data through the
//! reader's checks there; only the writing of a small file, whole in memory, is handed to a
//! worker.
//!
//! - **Bounded:** at most [`IN_FLIGHT`] bytes wait or are being written; the job's thread waits
//!   for room.
//! - **In order where it matters:** the sink waits for every write before a hard link or a copy
//!   reads a file this job wrote, before a later entry writes to a file still being written, and
//!   before it finishes (symlinks, folder times).
//! - **Errors** a worker meets fail the next entry, or the finish, as the job's own would.
//!   Warnings (a time that couldn't be set) are passed on then too.
//! - **Cancel:** a dropped sink stops the workers; a file being written removes its partial
//!   file, as on the job's thread.

use std::{
    collections::HashSet,
    io::Write,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc},
    thread::JoinHandle,
    time::SystemTime,
};

use super::{FileJob, Partial};
use crate::{Error, Result, io::write_error};

/// The largest file handed to a worker.
pub const SMALL: u64 = 4 << 20;
/// The most bytes waiting for workers or being written by them.
pub const IN_FLIGHT: u64 = 64 << 20;

/// What a worker writes: a placed file, its data and what it gets afterwards.
pub struct Write1 {
    pub job: FileJob,
    pub data: Vec<u8>,
    pub meta: Meta,
}

/// What a file gets once it's written.
#[derive(Debug, Clone)]
pub struct Meta {
    pub modified: Option<SystemTime>,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub unix_mode: Option<u32>,
    pub readonly: bool,
}

#[derive(Default)]
struct State {
    /// Files queued or being written, and their bytes.
    jobs: usize,
    bytes: u64,
    /// Written since the job's thread last looked.
    files_done: u64,
    bytes_done: u64,
    error: Option<Error>,
    warnings: Vec<String>,
    stop: bool,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    zone: Option<Vec<u8>>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The workers and what the job's thread knows of them.
pub struct Behind {
    tx: Option<mpsc::Sender<Write1>>,
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
    /// The files queued since the last wait, for a later entry to the same file.
    pending: HashSet<PathBuf>,
}

/// What the job's thread is owed by the workers since it last looked.
#[derive(Debug, Default)]
pub struct Done {
    pub files: u64,
    pub bytes: u64,
    pub warnings: Vec<String>,
}

impl Behind {
    /// `workers` threads, writing the Mark of the Web `zone` to each file.
    pub fn new(workers: usize, zone: Option<Vec<u8>>) -> Self {
        let (tx, rx) = mpsc::channel::<Write1>();
        let rx = Arc::new(Mutex::new(rx));
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            zone,
        });
        let workers = (0..workers.max(1))
            .filter_map(|i| {
                let (rx, shared) = (Arc::clone(&rx), Arc::clone(&shared));
                std::thread::Builder::new()
                    .name(format!("beezip-write-{i}"))
                    .spawn(move || work(&rx, &shared))
                    .ok()
            })
            .collect();
        Self {
            tx: Some(tx),
            shared,
            workers,
            pending: HashSet::new(),
        }
    }

    /// Whether a write to `job`'s file is still queued since the last wait.
    pub fn touches(&self, job: &FileJob) -> bool {
        self.pending.contains(&job.target)
            || job
                .replaces
                .as_ref()
                .is_some_and(|r| self.pending.contains(r))
    }

    /// Queues a file, once there's room for it. A worker's error ends the queueing.
    pub fn send(&mut self, w: Write1) -> Result<()> {
        let len = w.data.len() as u64;
        {
            let mut s = self.shared.lock();
            while s.error.is_none() && s.jobs > 0 && s.bytes + len > IN_FLIGHT {
                s = self
                    .shared
                    .changed
                    .wait(s)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if let Some(e) = s.error.clone() {
                return Err(e);
            }
            s.jobs += 1;
            s.bytes += len;
        }
        self.pending.insert(w.job.target.clone());
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(w).is_ok());
        if !sent {
            let mut s = self.shared.lock();
            s.jobs -= 1;
            s.bytes -= len;
            return Err(Error::corrupt("the writing threads have stopped"));
        }
        Ok(())
    }

    /// What's been written so far, without waiting; a worker's error.
    pub fn poll(&mut self) -> Result<Done> {
        let mut s = self.shared.lock();
        Self::take(&mut s)
    }

    /// Waits until every queued file is written.
    pub fn wait(&mut self) -> Result<Done> {
        let mut s = self.shared.lock();
        while s.jobs > 0 && s.error.is_none() {
            s = self
                .shared
                .changed
                .wait(s)
                .unwrap_or_else(PoisonError::into_inner);
        }
        self.pending.clear();
        Self::take(&mut s)
    }

    fn take(s: &mut State) -> Result<Done> {
        if let Some(e) = s.error.clone() {
            return Err(e);
        }
        let done = Done {
            files: s.files_done,
            bytes: s.bytes_done,
            warnings: std::mem::take(&mut s.warnings),
        };
        s.files_done = 0;
        s.bytes_done = 0;
        Ok(done)
    }
}

impl Drop for Behind {
    fn drop(&mut self) {
        self.shared.lock().stop = true;
        self.tx = None;
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

/// A worker: writes queued files until the queue closes or the sink stops it.
fn work(rx: &Mutex<mpsc::Receiver<Write1>>, shared: &Shared) {
    loop {
        let next = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
        let Ok(w) = next else {
            return;
        };
        let len = w.data.len() as u64;
        let skip = {
            let s = shared.lock();
            s.stop || s.error.is_some()
        };
        let mut warnings = Vec::new();
        let result = if skip {
            Ok(())
        } else {
            write(&w, shared.zone.as_deref(), &mut warnings)
        };
        let mut s = shared.lock();
        s.jobs -= 1;
        s.bytes -= len;
        match result {
            Ok(()) if !skip => {
                s.files_done += 1;
                s.bytes_done += len;
                s.warnings.extend(warnings);
            }
            Ok(()) => {}
            Err(e) => {
                s.error.get_or_insert(e);
            }
        }
        drop(s);
        shared.changed.notify_all();
    }
}

/// Writes one file as `FsSink::write_job` does: the partial file, the rename, then its time,
/// attributes and mark.
fn write(w: &Write1, zone: Option<&[u8]>, warnings: &mut Vec<String>) -> Result<()> {
    let (dir, target) = (w.job.dir.as_path(), w.job.target.as_path());
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut tmp = Partial::create(dir, &name)?;
    tmp.file_mut()
        .write_all(&w.data)
        .map_err(|e| write_error(&e))?;
    super::sink::before_rename(target, w.job.replaces.as_deref())?;
    tmp.persist(target)?;
    super::sink::metadata(target, zone, &w.meta, &mut |m| warnings.push(m));
    Ok(())
}
