//! Extracting a zip to disk on several threads (docs/M6.md §6.3), and writing one (§6.2). A
//! child of `zip.rs`.
//!
//! Extracting:
//! - **The job's thread decides everything first,** in archive order, through the sink's own
//!   rules ([`FsSink::plan`]): names made safe, folders made and checked, collisions, the
//!   overwrite policy and its prompts, the report's skips and renames, `max_entries`.
//! - **Workers then write the files,** largest first. Each has its own handle on the archive:
//!   it reads an entry's data where the local header puts it, decodes it with BeeZip's codec,
//!   checks its size and CRC as the zip crate does, and writes it through the sink's partial
//!   file. The ratio limit counts each entry's own input; the total-bytes budget is shared.
//! - **The job's thread meanwhile** reports progress, passes on warnings and watches for
//!   cancel. It never shares the [`Ctx`] with the workers.
//! - **What workers can't do** is left to the job's thread, after them, in archive order:
//!   encrypted entries (the password and the zip crate's decryption are the job's) and methods
//!   BeeZip has no codec for (LZMA, PPMd, Deflate64, the legacy ones).
//! - **Two entries for one file:** only the last is written, as when they're written in turn.
//!   The earlier one is still decoded and checked, and counted, so the report is the same.

use std::{
    collections::HashMap,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{
        Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::{
    ZipMethod, ZipReader, ZipSpan, ZipWriteOptions, ZipWriter, add_to, entry_options,
    write_zip_error,
};
use crate::{
    CodecId, Ctx, Error, ErrorKind, Meter, MeteredCtx, OverwriteChoice, Progress, Result,
    codec::deflate_par::ParDeflate,
    format::{
        EntryKind, NewEntry, NewKind, Opener, Selection,
        zip_edit::{self, CentralRecord},
    },
    io::{BUF_SIZE, Counter, WriteSeek, copy, drain, read_error, write_error},
    limits::{Guarded, RatioGuard},
    safefs::{FileJob, FsSink, Partial},
};

/// How often the job's thread looks at the workers.
const POLL: Duration = Duration::from_millis(25);

/// Extractions run here, for [`super::parallel_extractions`].
pub(super) static RUNS: AtomicUsize = AtomicUsize::new(0);

/// The codec a worker decodes an entry's method with; `Some(None)` is stored.
fn worker_codec(method: Option<&str>) -> Option<Option<CodecId>> {
    match method? {
        "Store" => Some(None),
        "Deflate" => Some(Some(CodecId::Deflate)),
        "BZip2" => Some(Some(CodecId::Bzip2)),
        "Zstd" => Some(Some(CodecId::Zstd)),
        "XZ" => Some(Some(CodecId::Xz)),
        _ => None,
    }
}

/// How many workers extracting `sel` from `r` gets: 0 to extract on the job's thread. Only a
/// zip that is one plain file (not a set, not inside a codec), with enough files workers can
/// take (`min_parallel_files`).
pub(super) fn workers(r: &ZipReader, sel: &Selection) -> usize {
    let source = &r.source;
    let threads = crate::codec::resolve_threads(source.threads) as usize;
    if threads < 2 || !source.codecs.is_empty() || source.joined {
        return 0;
    }
    let files = r
        .entries
        .iter()
        .filter(|e| {
            e.kind == EntryKind::File
                && !e.encrypted
                && worker_codec(e.method).is_some()
                && sel.matches(e)
        })
        .count();
    if files < source.min_parallel_files.max(1) {
        0
    } else {
        threads.min(files)
    }
}

struct Job {
    /// The entry.
    id: usize,
    file: FileJob,
    /// Where a worker reads the data, and its codec. `None`: the job's thread extracts it.
    work: Option<(ZipSpan, Option<CodecId>)>,
    /// A later entry goes to the same file: this one is decoded and checked, not written.
    superseded: bool,
}

/// Extracts the selected entries of `r` into `sink` with `workers` workers.
pub(super) fn extract(
    r: &mut ZipReader,
    sel: &Selection,
    sink: &mut FsSink,
    cx: &mut dyn Ctx,
    workers: usize,
) -> Result<()> {
    RUNS.fetch_add(1, Ordering::Relaxed);
    // Progress has a count of its own: the source's follows the read position (a seek sets it),
    // and workers read all over the file. Workers add what they read; entries done on the job's
    // thread add their packed size.
    let progress = Counter::new();
    let mut meter = Meter::new(progress.clone(), Some(r.source.size));
    meter.entries_total = Some(r.entries.len() as u64);

    // Every decision, in archive order.
    let mut jobs: Vec<Job> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for i in 0..r.entries.len() {
        cx.check()?;
        let entry = &r.entries[i];
        if !sel.matches(entry) {
            continue;
        }
        // Planning names the entry but doesn't count it: entries are done when written.
        meter.current = Some(entry.path.clone());
        let planned = sink.plan(entry, &mut MeteredCtx::new(cx, &meter))?;
        let Some(file) = planned else {
            continue;
        };
        // The sink already folds case for collisions, so its targets differ in more than case,
        // or are the same file.
        if let Some(prev) = at.insert(file.target.to_string_lossy().to_lowercase(), jobs.len()) {
            jobs[prev].superseded = true;
        }
        let work = if entry.encrypted {
            None
        } else {
            worker_codec(entry.method).and_then(|codec| r.span(i).map(|span| (span, codec)))
        };
        jobs.push(Job {
            id: i,
            file,
            work,
            superseded: false,
        });
    }

    // The workers' share, largest first: a big entry that started last would finish alone.
    let mut order: Vec<usize> = (0..jobs.len())
        .filter(|&j| jobs[j].work.is_some())
        .collect();
    order.sort_by_key(|&j| std::cmp::Reverse(jobs[j].work.map_or(0, |(s, _)| s.data_end - s.data)));
    let bytes: Vec<AtomicU64> = jobs.iter().map(|_| AtomicU64::new(0)).collect();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let failure: Mutex<Option<Error>> = Mutex::new(None);
    let warnings: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let shared = Shared {
        r: &*r,
        sink: &*sink,
        jobs: &jobs,
        order: &order,
        bytes: &bytes,
        next: &next,
        done: &done,
        stop: &stop,
        warnings: &warnings,
        progress: &progress,
    };
    std::thread::scope(|s| {
        for _ in 0..workers.min(order.len()) {
            s.spawn(|| {
                if let Err(e) = shared.work() {
                    // The first failure is the job's; the others stopped because of it.
                    lock(&failure).get_or_insert(e);
                    stop.store(true, Ordering::Relaxed);
                }
            });
        }
        loop {
            let finished = done.load(Ordering::Relaxed);
            if finished >= order.len() || stop.load(Ordering::Relaxed) {
                break;
            }
            if cx.is_cancelled() {
                stop.store(true, Ordering::Relaxed);
            }
            meter.entries_done = finished as u64;
            meter.current = None;
            cx.progress(&meter.snapshot());
            for w in lock(&warnings).drain(..) {
                cx.warn(w);
            }
            std::thread::sleep(POLL);
        }
    });
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
    for (job, n) in jobs.iter().zip(&bytes) {
        if job.work.is_some() {
            sink.wrote(n.load(Ordering::Relaxed));
        }
    }

    // What the workers left, in archive order.
    meter.entries_done = order.len() as u64;
    for job in jobs.iter().filter(|j| j.work.is_none()) {
        cx.check()?;
        let entry = r.entries[job.id].clone();
        meter.current = Some(entry.path.clone());
        let mut data = r.open_data(job.id, cx)?;
        let mut mcx = MeteredCtx::new(cx, &meter);
        mcx.report();
        let n = if job.superseded {
            drain(&mut data, &mut mcx)?
        } else {
            sink.write_job(&job.file, &entry, &mut data, &mut mcx)?
        };
        drop(data);
        sink.wrote(n);
        progress.add(entry.packed_size.unwrap_or(0));
        meter.entries_done += 1;
    }
    meter.entries_done = r.entries.len() as u64;
    meter.current = None;
    MeteredCtx::new(cx, &meter).report();
    Ok(())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the workers share. The sink only gets written through `write_job`, which changes
/// nothing in it.
struct Shared<'a> {
    r: &'a ZipReader,
    sink: &'a FsSink,
    jobs: &'a [Job],
    order: &'a [usize],
    bytes: &'a [AtomicU64],
    next: &'a AtomicUsize,
    done: &'a AtomicUsize,
    stop: &'a AtomicBool,
    warnings: &'a Mutex<Vec<String>>,
    progress: &'a Counter,
}

impl Shared<'_> {
    /// One worker: takes the next job until there are none, or the job stops.
    fn work(&self) -> Result<()> {
        let source = &self.r.source;
        let mut input = source.input()?;
        // This worker's input alone, so each entry's ratio is its own.
        let own = Counter::new();
        let mut wcx = WorkerCtx {
            stop: self.stop,
            warnings: Vec::new(),
        };
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let k = self.next.fetch_add(1, Ordering::Relaxed);
            let Some(&j) = self.order.get(k) else {
                return Ok(());
            };
            let job = &self.jobs[j];
            let Some((span, codec)) = job.work else {
                continue;
            };
            let entry = &self.r.entries[job.id];
            input
                .seek(SeekFrom::Start(span.data))
                .map_err(|e| read_error(&e))?;
            let raw = BufReader::with_capacity(
                BUF_SIZE,
                Counted {
                    inner: (&mut input).take(span.data_end - span.data),
                    own: own.clone(),
                    progress: self.progress.clone(),
                },
            );
            let decoded: Box<dyn Read + Send + '_> = match codec {
                None => Box::new(raw),
                Some(c) => c.decoder(Box::new(raw), &source.limits)?,
            };
            let checked = Verify {
                inner: decoded,
                hasher: crc32fast::Hasher::new(),
                crc: entry.crc32.unwrap_or(0),
                size: entry.size.unwrap_or(0),
                read: 0,
            };
            let mut data = Guarded::new(
                checked,
                RatioGuard::new(&own, &source.limits),
                source.budget.clone(),
            );
            let n = if job.superseded {
                drain(&mut data, &mut wcx)?
            } else {
                self.sink.write_job(&job.file, entry, &mut data, &mut wcx)?
            };
            self.bytes[j].store(n, Ordering::Relaxed);
            if !wcx.warnings.is_empty() {
                lock(self.warnings).append(&mut wcx.warnings);
            }
            self.done.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Counts what a worker reads, for its own entries' ratio and for the job's progress.
struct Counted<R> {
    inner: R,
    own: Counter,
    progress: Counter,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.own.add(n as u64);
        self.progress.add(n as u64);
        Ok(n)
    }
}

/// Checks an entry's data as the zip crate does when the job's thread reads it, with the same
/// messages: no more than its size, and its CRC at the end.
struct Verify<R> {
    inner: R,
    hasher: crc32fast::Hasher,
    crc: u32,
    size: u64,
    read: u64,
}

impl<R: Read> Read for Verify<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() {
            if self.hasher.clone().finalize() != self.crc {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid checksum",
                ));
            }
            return Ok(0);
        }
        self.read += n as u64;
        if self.read > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File is larger than its declared uncompressed size",
            ));
        }
        self.hasher.update(&buf[..n]);
        Ok(n)
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

// Writing (docs/M6.md §6.2).

/// An entry bigger than this is made in a temporary file rather than in memory.
const MEM_CAP: u64 = 64 << 20;
/// Unencrypted Deflate entries at least this big are compressed by every worker at once, with
/// parallel deflate, rather than whole by one: a big file would otherwise finish alone.
const BIG: u64 = 16 << 20;
/// Bigger ones would need Zip64 sizes in a header the zip crate wrote without them, so they
/// stay on one worker.
const BIG_MAX: u64 = 0xF000_0000;

/// Whether `entry` is written with parallel deflate inside it.
fn big(opts: &ZipWriteOptions, entry: &NewEntry) -> bool {
    opts.method == ZipMethod::Deflate
        && opts.password.is_none()
        && entry.kind == NewKind::File
        && (BIG..BIG_MAX).contains(&entry.size)
}

/// The local header and central record the zip crate writes for `entry` with no data: the
/// parts that go around a parallel deflate stream, once its CRC and sizes are put in.
fn big_parts(
    opts: &ZipWriteOptions,
    level: Option<i64>,
    entry: &NewEntry,
) -> Result<(Vec<u8>, CentralRecord)> {
    let o = entry_options(opts, level, entry)?;
    let mut zip = zip::ZipWriter::new(io::Cursor::new(Vec::new())).set_auto_large_file();
    zip.start_file(&entry.path, o).map_err(write_zip_error)?;
    let mut c = zip.finish().map_err(write_zip_error)?;
    let (_, rec) = split(&mut c)?;
    let v = c.into_inner();
    let field = |at: usize| u16::from_le_bytes([v[at], v[at + 1]]);
    let len = 30 + usize::from(field(26)) + usize::from(field(28));
    // Deflate, sizes in the header (no data descriptor), and no Zip64 fields.
    if v.len() < len || field(8) != 8 || field(6) & 8 != 0 || len < 30 {
        return Err(Error::corrupt(
            "zip: an unexpected local header for a big entry",
        ));
    }
    Ok((v[..len].to_vec(), rec))
}

/// Writes `entry` at `pos` of `out`: the zip crate's header, then parallel deflate on `threads`
/// workers, then the CRC and sizes put in. Returns where it ends, and its central record.
#[allow(clippy::too_many_arguments)]
fn write_big(
    out: &mut dyn WriteSeek,
    pos: u64,
    opts: &ZipWriteOptions,
    level: Option<i64>,
    entry: &NewEntry,
    data: &mut dyn Read,
    threads: u32,
    cx: &mut dyn Ctx,
) -> Result<(u64, CentralRecord)> {
    let (head, mut rec) = big_parts(opts, level, entry)?;
    out.seek(SeekFrom::Start(pos))
        .and_then(|_| out.write_all(&head))
        .map_err(|e| write_error(&e))?;
    let level = level.and_then(|l| u32::try_from(l).ok()).unwrap_or(6);
    let mut enc = ParDeflate::new(&mut *out, level, threads);
    copy(data, &mut enc, cx)?;
    let (_, sum) = enc.finish().map_err(|e| write_error(&e))?;
    let (Ok(packed), Ok(size)) = (u32::try_from(sum.bytes_out), u32::try_from(sum.bytes_in)) else {
        return Err(Error::new(
            ErrorKind::Io,
            format!("`{}` grew past 4 GiB while it was being added", entry.path),
        ));
    };
    // CRC, compressed size, size: at 14 in the local header, at 16 in the central record.
    let mut fields = Vec::with_capacity(12);
    fields.extend_from_slice(&sum.crc32.to_le_bytes());
    fields.extend_from_slice(&packed.to_le_bytes());
    fields.extend_from_slice(&size.to_le_bytes());
    rec.0[16..28].copy_from_slice(&fields);
    let end = pos + head.len() as u64 + sum.bytes_out;
    out.seek(SeekFrom::Start(pos + 14))
        .and_then(|_| out.write_all(&fields))
        .and_then(|_| out.seek(SeekFrom::Start(end)))
        .map_err(|e| write_error(&e))?;
    Ok((end, rec))
}

/// [`write_big`] at the end of what `w` has written.
fn append_big(
    w: &mut ZipWriter,
    entry: &NewEntry,
    data: &mut dyn Read,
    threads: u32,
    cx: &mut dyn Ctx,
) -> Result<()> {
    let opts = w.opts.clone();
    let level = w.level;
    let (out, pos, recs): (&mut dyn WriteSeek, &mut u64, &mut Vec<CentralRecord>) = match &mut w.out
    {
        super::Out::Spans(s) => (&mut s.out, &mut s.pos, &mut s.recs),
        super::Out::Edit(ed) => (&mut ed.file, &mut ed.pos, &mut ed.kept),
        _ => return Err(Error::new(ErrorKind::Io, "zip: no place for a big entry")),
    };
    let (end, mut rec) = write_big(out, *pos, &opts, level, entry, data, threads, cx)?;
    rec.set_offset(*pos)?;
    *pos = end;
    recs.push(rec);
    Ok(())
}
/// Input bytes in flight at most; an entry bigger than this goes alone.
const IN_FLIGHT: u64 = 512 << 20;

/// The local part of a one-entry zip: its local header, data and data descriptor.
pub(super) enum Span {
    Mem(Vec<u8>),
    /// The first `len` bytes of a temporary file.
    Spool(Partial, u64),
}

impl Span {
    /// Writes the bytes to `w`, and says how many.
    pub(super) fn write_to(&self, w: &mut dyn Write) -> Result<u64> {
        match self {
            Span::Mem(v) => {
                w.write_all(v).map_err(|e| write_error(&e))?;
                Ok(v.len() as u64)
            }
            Span::Spool(tmp, len) => {
                let mut f = tmp.reopen()?;
                let n = io::copy(&mut (&mut f).take(*len), w).map_err(|e| write_error(&e))?;
                if n == *len {
                    Ok(n)
                } else {
                    Err(Error::new(
                        ErrorKind::Io,
                        "zip: an entry's temporary file is short",
                    ))
                }
            }
        }
    }
}

/// One entry, made as a one-entry zip by the zip crate with the writer's options, so its bytes
/// are what the zip crate writes in a whole zip: the local part, and the central record that
/// goes with it, to be moved to where the local part lands.
pub(super) struct Blob {
    pub(super) span: Span,
    pub(super) rec: CentralRecord,
}

/// Makes `entry` as a [`Blob`], in memory up to [`MEM_CAP`], else in a partial file in `spool`.
pub(super) fn one_entry(
    opts: &ZipWriteOptions,
    level: Option<i64>,
    entry: &NewEntry,
    data: &mut dyn Read,
    cx: &mut dyn Ctx,
    spool: &Path,
) -> Result<Blob> {
    let o = entry_options(opts, level, entry)?;
    if entry.kind == NewKind::File && entry.size > MEM_CAP {
        let tmp = Partial::create(spool, "beezip-entry.zip")?;
        let mut zip = zip::ZipWriter::new(tmp.try_clone()?).set_auto_large_file();
        add_to(&mut zip, o, entry, data, cx)?;
        let mut file = zip.finish().map_err(write_zip_error)?;
        let (at, rec) = split(&mut file)?;
        Ok(Blob {
            span: Span::Spool(tmp, at),
            rec,
        })
    } else {
        let cap = usize::try_from(entry.size / 2 + 4096).unwrap_or(4096);
        let mut zip =
            zip::ZipWriter::new(io::Cursor::new(Vec::with_capacity(cap))).set_auto_large_file();
        add_to(&mut zip, o, entry, data, cx)?;
        let mut c = zip.finish().map_err(write_zip_error)?;
        let (at, rec) = split(&mut c)?;
        let mut v = c.into_inner();
        v.truncate(usize::try_from(at).unwrap_or(v.len()));
        Ok(Blob {
            span: Span::Mem(v),
            rec,
        })
    }
}

/// A one-entry zip's central directory: where it starts, and its record.
fn split<R: Read + Seek>(r: &mut R) -> Result<(u64, CentralRecord)> {
    let len = r.seek(SeekFrom::End(0)).map_err(|e| write_error(&e))?;
    let (at, size) = zip_edit::find_directory(r, len)?;
    let size = usize::try_from(size).map_err(|_| Error::limit("zip: a directory too large"))?;
    let mut cd = vec![0u8; size];
    r.seek(SeekFrom::Start(at))
        .and_then(|_| r.read_exact(&mut cd))
        .map_err(|e| Error::io("reading an entry back", &e))?;
    let mut recs = zip_edit::records(&cd)?;
    match recs.len() {
        1 => Ok((at, recs.remove(0))),
        n => Err(Error::corrupt(format!("zip: {n} records for one entry"))),
    }
}

/// What the job's thread and the workers share while writing.
struct Window {
    /// The next entry a worker takes, and how many the job's thread has written.
    next: usize,
    written: usize,
    /// Input bytes taken and not written yet.
    in_flight: u64,
    done: HashMap<usize, Result<Blob>>,
}

/// Adds `entries` to `w` on `workers` workers, written in order. At most 8 entries per worker
/// and [`IN_FLIGHT`] bytes of input are in flight. Big entries ([`BIG`]) are the job thread's,
/// with every worker on them through parallel deflate. A worker's failure stops the job when the
/// job's thread reaches that entry, so the error is the first one in order, as on one thread.
pub(super) fn write(
    w: &mut ZipWriter,
    entries: &[NewEntry],
    open: &Opener<'_>,
    cx: &mut dyn Ctx,
    workers: usize,
) -> Result<()> {
    let opts = w.opts.clone();
    let level = w.level;
    let spool = w.spool.clone();
    // Big entries are the job thread's: workers skip them, and their size isn't in flight.
    let is_big = |k: usize| big(&opts, &entries[k]);
    let size = |k: usize| match entries[k].kind {
        NewKind::File if !is_big(k) => entries[k].size,
        _ => 0,
    };
    let ahead = 8 * workers;
    let window = Mutex::new(Window {
        next: 0,
        written: 0,
        in_flight: 0,
        done: HashMap::new(),
    });
    // Workers wait on `room` for the window to move; the job's thread waits on `ready`.
    let room = Condvar::new();
    let ready = Condvar::new();
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..workers.min(entries.len()) {
            s.spawn(|| {
                let mut wcx = WorkerCtx {
                    stop: &stop,
                    warnings: Vec::new(),
                };
                loop {
                    let k = {
                        let mut st = lock(&window);
                        loop {
                            while st.next < entries.len() && is_big(st.next) {
                                st.next += 1;
                            }
                            if stop.load(Ordering::Relaxed) || st.next >= entries.len() {
                                return;
                            }
                            let k = st.next;
                            let fits = k < st.written + ahead
                                && (st.in_flight + size(k) <= IN_FLIGHT || k == st.written);
                            if fits {
                                st.next += 1;
                                st.in_flight += size(k);
                                break k;
                            }
                            st = room.wait(st).unwrap_or_else(PoisonError::into_inner);
                        }
                    };
                    let made = (|| {
                        let mut data: Box<dyn Read + Send> = match entries[k].kind {
                            NewKind::File => open(k)?,
                            _ => Box::new(io::empty()),
                        };
                        one_entry(&opts, level, &entries[k], &mut data, &mut wcx, &spool)
                    })();
                    lock(&window).done.insert(k, made);
                    ready.notify_one();
                }
            });
        }
        let result = (|| -> Result<()> {
            for (k, entry) in entries.iter().enumerate() {
                if is_big(k) {
                    let mut data = open(k)?;
                    let threads = u32::try_from(workers).unwrap_or(u32::MAX);
                    append_big(w, entry, &mut data, threads, cx)?;
                    lock(&window).written += 1;
                    room.notify_one();
                    continue;
                }
                let made = loop {
                    let mut st = lock(&window);
                    if let Some(made) = st.done.remove(&k) {
                        st.written += 1;
                        st.in_flight -= size(k);
                        break made;
                    }
                    // Wakes a worker in case none is on the entry this one waits for.
                    room.notify_one();
                    drop(ready.wait_timeout(st, POLL));
                    cx.check()?;
                };
                room.notify_one();
                w.append(made?)?;
                cx.check()?;
            }
            Ok(())
        })();
        stop.store(true, Ordering::Relaxed);
        room.notify_all();
        result
    })
}
