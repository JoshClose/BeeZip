//! Extracting a `.bhive` to disk on several threads (docs/M13.md §5), after zip's
//! (docs/M6.md §6.3, `zip_par.rs`).
//!
//! - **The job's thread decides everything first,** in archive order, through the sink's own
//!   rules ([`FsSink::plan`]): safe names, folders, collisions, the overwrite policy and its
//!   prompts, the report's skips, `max_entries`.
//! - **Workers then write the files,** cell by cell: the files are taken in the order of the
//!   cell their bytes start in, each worker a different cell's, so as many cells decode at once
//!   as there are workers, and a cell is decoded once for all its files. A worker whose cell is
//!   done takes files of the cells others are on. A file that reaches into other cells finds
//!   them in the shared cache, or decodes them.
//! - **A worker with no files left** decodes cells ahead for the others: one big file is read
//!   by one worker, and decoded by all.
//! - **A damaged cell** fails its files, and the rest are written; the job then fails.

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use super::read::{BhiveReader, CellIo, ExtentReader, KEEP, POLL, damaged, lock};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, OverwriteChoice, Progress, Result,
    format::EntryKind,
    io::{Counter, drain},
    limits::{Guarded, RatioGuard},
    safefs::{FileJob, FsSink},
};

/// How many workers extracting `selected` gets; 1 extracts on the job's thread. Workers pay
/// when there are many files to write, or more than one cell to decode.
pub(super) fn workers(r: &BhiveReader, selected: &[usize]) -> usize {
    let threads = r.threads();
    if threads < 2 {
        return 1;
    }
    let files = selected
        .iter()
        .filter(|&&id| r.entries[id].kind == EntryKind::File)
        .count();
    let mut cells: Vec<u32> = selected
        .iter()
        .flat_map(|&id| r.extents_of(id).iter().map(|x| x.cell))
        .collect();
    cells.sort_unstable();
    cells.dedup();
    if files >= r.source.min_parallel_files.max(1) || cells.len() > 1 {
        threads
    } else {
        1
    }
}

struct Job {
    /// The entry.
    id: usize,
    file: FileJob,
    /// A later entry goes to the same file: this one is read and checked, not written.
    superseded: bool,
}

/// Extracts the entries `selected` of `r` into `sink` with `workers` workers.
pub(super) fn extract(
    r: &mut BhiveReader,
    selected: &[usize],
    sink: &mut FsSink,
    cx: &mut dyn Ctx,
    workers: usize,
) -> Result<()> {
    let progress = Counter::new();
    let mut meter = Meter::new(progress.clone(), Some(r.source.size));
    meter.entries_total = Some(selected.len() as u64);

    // Every decision, in archive order.
    let mut jobs: Vec<Job> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    let ignores_case = sink.ignores_case();
    for &id in selected {
        cx.check()?;
        let entry = &r.entries[id];
        meter.current = Some(entry.path.clone());
        let Some(file) = sink.plan(entry, &mut MeteredCtx::new(cx, &meter))? else {
            continue;
        };
        // Two jobs for one file: the later one wins, as when they are written in turn.
        let key = file.target.to_string_lossy();
        let key = if ignores_case {
            key.to_lowercase()
        } else {
            key.into_owned()
        };
        if let Some(prev) = at.insert(key, jobs.len()) {
            jobs[prev].superseded = true;
        }
        jobs.push(Job {
            id,
            file,
            superseded: false,
        });
    }

    // The jobs by the cell their bytes start in, and in archive order within one: a group is one
    // worker's. Files without bytes come first.
    let home = |j: usize| r.extents_of(jobs[j].id).first().map(|x| x.cell);
    let mut order: Vec<usize> = (0..jobs.len()).collect();
    order.sort_by_key(|&j| home(j));
    let mut groups: Vec<(usize, usize)> = Vec::new();
    for (i, &j) in order.iter().enumerate() {
        match groups.last_mut() {
            Some((start, end)) if home(order[*start]) == home(j) => *end = i + 1,
            _ => groups.push((i, i + 1)),
        }
    }

    let bytes: Vec<AtomicU64> = jobs.iter().map(|_| AtomicU64::new(0)).collect();
    let shared = Shared {
        r: &*r,
        sink: &*sink,
        jobs: &jobs,
        order: &order,
        groups: &groups,
        bytes: &bytes,
        taken: groups.iter().map(|_| AtomicUsize::new(0)).collect(),
        next: AtomicUsize::new(0),
        done: AtomicUsize::new(0),
        stop: AtomicBool::new(false),
        warnings: Mutex::new(Vec::new()),
        unread: Mutex::new(Vec::new()),
        progress: &progress,
        ahead: workers,
        tick: (Mutex::new(()), Condvar::new()),
    };
    let failure: Mutex<Option<Error>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                if let Err(e) = shared.work() {
                    // The first failure is the job's; the others stopped because of it.
                    lock(&failure).get_or_insert(e);
                    shared.stop.store(true, Ordering::Relaxed);
                    shared.wake();
                }
            });
        }
        loop {
            let finished = shared.done.load(Ordering::Relaxed);
            if finished >= jobs.len() || shared.stop.load(Ordering::Relaxed) {
                break;
            }
            if cx.is_cancelled() {
                shared.stop.store(true, Ordering::Relaxed);
            }
            meter.entries_done = finished as u64;
            meter.current = None;
            cx.progress(&meter.snapshot());
            for w in lock(&shared.warnings).drain(..) {
                cx.warn(w);
            }
            // Until a worker finishes a file, or a moment has passed.
            let waiting = lock(&shared.tick.0);
            if shared.done.load(Ordering::Relaxed) < jobs.len()
                && !shared.stop.load(Ordering::Relaxed)
            {
                drop(shared.tick.1.wait_timeout(waiting, POLL));
            }
        }
        // Lets the workers that are waiting for cells to decode ahead go.
        shared.stop.store(true, Ordering::Relaxed);
        shared.r.cache.wake();
    });
    let Shared {
        warnings, unread, ..
    } = shared;
    r.cache.shrink(KEEP);
    for w in warnings
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    {
        cx.warn(w);
    }
    if let Some(e) = failure.into_inner().unwrap_or_else(PoisonError::into_inner) {
        return Err(e);
    }
    cx.check()?;
    let mut unread = unread.into_inner().unwrap_or_else(PoisonError::into_inner);
    unread.sort_by_key(|(j, _)| *j);
    for (j, n) in bytes.iter().enumerate() {
        if !unread.iter().any(|(u, _)| *u == j) {
            sink.wrote(n.load(Ordering::Relaxed));
        }
    }
    for (j, e) in &unread {
        let path = &r.entries[jobs[*j].id].path;
        cx.warn(format!("`{path}` can't be read: {}", e.message));
    }
    meter.entries_done = selected.len() as u64;
    meter.current = None;
    MeteredCtx::new(cx, &meter).report();
    match unread.first() {
        None => Ok(()),
        Some((_, e)) => Err(damaged(unread.len() as u64, e)),
    }
}

/// What the workers share. The sink only gets written through `write_job`, which changes
/// nothing in it.
struct Shared<'a> {
    r: &'a BhiveReader,
    sink: &'a FsSink,
    jobs: &'a [Job],
    /// The jobs in the order they are taken, and the runs of it that are one cell's.
    order: &'a [usize],
    groups: &'a [(usize, usize)],
    /// What each job wrote.
    bytes: &'a [AtomicU64],
    /// How many of each group's jobs are taken, and the next group without a worker.
    taken: Vec<AtomicUsize>,
    next: AtomicUsize,
    done: AtomicUsize,
    stop: AtomicBool,
    warnings: Mutex<Vec<String>>,
    /// The jobs whose file has bytes in a damaged cell.
    unread: Mutex<Vec<(usize, Error)>>,
    progress: &'a Counter,
    /// Cells a file asks for ahead of the one it reads.
    ahead: usize,
    /// The job's thread waits here between looks; a worker that finishes a file wakes it.
    tick: (Mutex<()>, Condvar),
}

impl Shared<'_> {
    /// Wakes the job's thread. Through the lock, so a wake can't fall between its look at the
    /// counts and its wait.
    fn wake(&self) {
        drop(lock(&self.tick.0));
        self.tick.1.notify_all();
    }

    /// The next file of group `g` that nobody has taken.
    fn take(&self, g: usize) -> Option<usize> {
        let (start, end) = self.groups[g];
        let i = start + self.taken[g].fetch_add(1, Ordering::Relaxed);
        (i < end).then(|| self.order[i])
    }

    /// One worker: a cell's files that nobody has started, until every cell has a worker; then
    /// files of the cells others are on, so a cell of many files isn't one worker's alone; then
    /// cells for the others, decoded ahead.
    fn work(&self) -> Result<()> {
        let source = &self.r.source;
        let mut input = source.input()?;
        // This worker's files alone, so each one's ratio is its own.
        let touched = Counter::new();
        let mut wcx = WorkerCtx {
            stop: &self.stop,
            warnings: Vec::new(),
        };
        let mut write = |j: usize| -> Result<()> {
            let job = &self.jobs[j];
            let entry = &self.r.entries[job.id];
            touched.set(0);
            let reader = ExtentReader::new(
                &self.r.cells,
                self.r.extents_of(job.id),
                &self.r.cache,
                CellIo {
                    input: &mut input,
                    limits: &source.limits,
                    progress: self.progress,
                },
                &touched,
                self.ahead,
            );
            let mut data = Guarded::new(
                reader,
                RatioGuard::new(&touched, &source.limits),
                source.budget.clone(),
            );
            let wrote = if job.superseded {
                drain(&mut data, &mut wcx)
            } else {
                self.sink.write_job(&job.file, entry, &mut data, &mut wcx)
            };
            drop(data);
            match wrote {
                Ok(n) => self.bytes[j].store(n, Ordering::Relaxed),
                Err(e) if e.kind == ErrorKind::Corrupt => lock(&self.unread).push((j, e)),
                Err(e) => return Err(e),
            }
            if !wcx.warnings.is_empty() {
                lock(&self.warnings).append(&mut wcx.warnings);
            }
            self.done.fetch_add(1, Ordering::Relaxed);
            self.wake();
            Ok(())
        };
        let stopped = || self.stop.load(Ordering::Relaxed);
        loop {
            let g = self.next.fetch_add(1, Ordering::Relaxed);
            if g >= self.groups.len() {
                break;
            }
            while let Some(j) = self.take(g) {
                if stopped() {
                    return Ok(());
                }
                write(j)?;
            }
        }
        for g in 0..self.groups.len() {
            while let Some(j) = self.take(g) {
                if stopped() {
                    return Ok(());
                }
                write(j)?;
            }
        }
        // Nothing left to write: decode ahead for the workers still writing.
        drop(write);
        while !stopped() && self.done.load(Ordering::Relaxed) < self.jobs.len() {
            let mut io = CellIo {
                input: &mut input,
                limits: &source.limits,
                progress: self.progress,
            };
            self.r.cache.help(&self.r.cells, &mut io);
        }
        Ok(())
    }
}

/// A worker's [`Ctx`]: the job's stop flag, and warnings for the job's thread to pass on.
/// Nothing a worker does asks anything.
struct WorkerCtx<'a> {
    stop: &'a AtomicBool,
    warnings: Vec<String>,
}

impl Ctx for WorkerCtx<'_> {
    fn is_cancelled(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn progress(&mut self, _: &Progress) {}

    fn warn(&mut self, message: String) {
        self.warnings.push(message);
    }

    fn password(&mut self, _: Option<&str>, _: u32) -> Result<String> {
        Err(Error::new(
            ErrorKind::PasswordRequired,
            "a worker has no password to give",
        ))
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        Err(Error::new(
            ErrorKind::Conflict,
            format!("`{}` already exists", existing.display()),
        ))
    }
}
