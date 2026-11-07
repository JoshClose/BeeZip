//! The general path (docs/M5.md §3.6): entries a writer couldn't copy are decoded with the
//! reader's `extract`, in archive order so a solid source decodes once, and added through
//! `ArchiveWriter::add`. A writer that packs solid blocks pulls its entries, so for it the
//! reader runs on a helper thread and hands each entry over through a bounded pipe.

use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

use super::Skipped;
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, OverwriteChoice, Progress, Result,
    format::{
        ArchiveReader, ArchiveWriter, Entry, EntryKind, EntrySink, Keep, NewEntry, NewKind,
        Selection, link_target,
    },
    io::{BUF_SIZE, CountingReader, PipeReader, copy, pipe},
    safefs::Partial,
};

/// What [`decode_into`] wrote and left out.
#[derive(Debug, Default)]
pub struct Decoded {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub skipped: Vec<Skipped>,
}

/// The entry a source entry becomes, under `path`.
fn new_entry(e: &Entry, path: &str, kind: NewKind, size: u64) -> NewEntry {
    NewEntry {
        path: path.trim_end_matches('/').to_owned(),
        kind,
        size,
        modified: e.modified,
        unix_mode: e.unix_mode,
        dos_attrs: e.dos_attrs,
    }
}

/// A spooled entry's data, with the file kept alive while it's read.
struct Spooled {
    file: File,
    _partial: Partial,
}

impl Read for Spooled {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

/// `data` with its size: the entry's, or, when the source doesn't know it (a bare stream),
/// what spooling it to a temporary file measured.
fn sized<'a>(
    e: &Entry,
    data: &'a mut dyn Read,
    cx: &mut dyn Ctx,
) -> Result<(u64, Box<dyn Read + 'a>)> {
    if let Some(n) = e.size {
        return Ok((n, Box::new(data)));
    }
    let mut tmp = Partial::create_temp("beezip-spool")?;
    let n = copy(data, tmp.file_mut(), cx)?;
    let mut file = tmp.reopen()?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| Error::io("reading a spooled entry", &e))?;
    Ok((
        n,
        Box::new(Spooled {
            file,
            _partial: tmp,
        }),
    ))
}

/// Decodes `rest` from `source` and adds them to `writer`. Hard links become files (their
/// target's data, read again); devices and FIFOs are left out, as are symlinks the writer
/// can't hold, and reported.
pub fn decode_into(
    source: &mut dyn ArchiveReader,
    writer: &mut dyn ArchiveWriter,
    rest: &[Keep],
    meter: &mut Meter,
    cx: &mut dyn Ctx,
) -> Result<Decoded> {
    let entries = source.entries(cx)?.to_vec();
    let paths: HashMap<usize, String> = rest.iter().map(|k| (k.id, k.path.clone())).collect();
    let sel = Selection::ids(rest.iter().map(|k| k.id));
    let mut out = Decoded::default();
    let mut links = Vec::new();
    if writer.solid_block_limit().is_some() {
        bridge(
            source, writer, &entries, &paths, &sel, meter, cx, &mut out, &mut links,
        )?;
    } else {
        let mut sink = AddSink {
            writer: &mut *writer,
            paths: &paths,
            out: &mut out,
            links: &mut links,
        };
        let mut mcx = MeteredCtx::new(cx, meter);
        source.extract(&sel, &mut sink, &mut mcx)?;
    }
    // Hard links: the target's data, read again (a tar's links come after their targets).
    for id in links {
        cx.check()?;
        let (Some(e), Some(path)) = (entries.get(id), paths.get(&id)) else {
            continue;
        };
        let size = link_target(&entries, e).and_then(|t| t.size);
        let mut data = source.open_entry(id, cx)?;
        let e = Entry { size, ..e.clone() };
        let mut mcx = MeteredCtx::new(cx, meter);
        let (n, mut data) = sized(&e, &mut data, &mut mcx)?;
        writer.add(&new_entry(&e, path, NewKind::File, n), &mut data, &mut mcx)?;
        out.files += 1;
    }
    Ok(out)
}

/// Adds each entry the reader hands it, for writers that take entries one at a time.
struct AddSink<'a> {
    writer: &'a mut dyn ArchiveWriter,
    paths: &'a HashMap<usize, String>,
    out: &'a mut Decoded,
    links: &'a mut Vec<usize>,
}

impl EntrySink for AddSink<'_> {
    fn entry(&mut self, e: &Entry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let Some(path) = self.paths.get(&e.id) else {
            return Ok(());
        };
        add_one(self.writer, e, path, data, self.out, self.links, cx)
    }
}

/// Adds one decoded entry, or notes it as a link to do later or an entry left out.
fn add_one(
    writer: &mut dyn ArchiveWriter,
    e: &Entry,
    path: &str,
    data: &mut dyn Read,
    out: &mut Decoded,
    links: &mut Vec<usize>,
    cx: &mut dyn Ctx,
) -> Result<()> {
    match &e.kind {
        EntryKind::File => {
            let (n, mut data) = sized(e, data, cx)?;
            writer.add(&new_entry(e, path, NewKind::File, n), &mut data, cx)?;
            out.files += 1;
        }
        // A format without folders (ar, CAB) has them through its files' paths.
        EntryKind::Dir if !writer.holds(&NewKind::Dir) => {}
        EntryKind::Dir => {
            writer.add(&new_entry(e, path, NewKind::Dir, 0), &mut io::empty(), cx)?;
            out.dirs += 1;
        }
        EntryKind::Symlink { target } => {
            let kind = NewKind::Symlink {
                target: target.clone(),
            };
            if !writer.holds(&kind) {
                out.skipped.push(Skipped {
                    path: path.to_owned(),
                    reason: "a symbolic link, which the new archive can't hold".into(),
                });
                return Ok(());
            }
            writer.add(&new_entry(e, path, kind, 0), &mut io::empty(), cx)?;
            out.links += 1;
        }
        EntryKind::Hardlink { .. } => links.push(e.id),
        EntryKind::Other => out.skipped.push(Skipped {
            path: path.to_owned(),
            reason: "a device or FIFO, which the new archive can't hold".into(),
        }),
    }
    Ok(())
}

/// What the helper thread sends: each selected entry, in archive order, with a pipe for a
/// file's data; then how its pass ended.
enum Msg {
    Item(Box<Entry>, Option<PipeReader>),
    Done(Result<()>),
}

/// The helper thread's context: the password asked for before it started, a cancellation flag
/// the job's side sets, and its warnings, which the job reports afterwards.
struct HelperCtx {
    password: Option<String>,
    cancel: Arc<AtomicBool>,
    warnings: Arc<Mutex<Vec<String>>>,
}

impl Ctx for HelperCtx {
    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn progress(&mut self, _: &Progress) {}

    fn warn(&mut self, message: String) {
        if let Ok(mut w) = self.warnings.lock() {
            w.push(message);
        }
    }

    fn password(&mut self, _: Option<&str>, attempt: u32) -> Result<String> {
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
        Err(Error::new(
            ErrorKind::Conflict,
            format!("`{}` already exists", existing.display()),
        ))
    }
}

/// Sends every entry to the job's side, a file's data through a pipe.
struct PipeSink {
    tx: mpsc::SyncSender<Msg>,
}

impl EntrySink for PipeSink {
    fn entry(&mut self, e: &Entry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        if e.kind != EntryKind::File {
            return self
                .tx
                .send(Msg::Item(Box::new(e.clone()), None))
                .map_err(|_| Error::cancelled());
        }
        let (mut w, r) = pipe(4, BUF_SIZE);
        self.tx
            .send(Msg::Item(Box::new(e.clone()), Some(r)))
            .map_err(|_| Error::cancelled())?;
        let result = copy(data, &mut w, cx).map(|_| ());
        w.finish(result.clone());
        result
    }
}

/// The entries of one solid block, by id.
type Group = Vec<usize>;

/// The most data an entry outside a block may bring while a block is being written: those
/// are empty files, held until the block is done.
const MAX_SMALL: u64 = 64 * 1024;

/// Groups the files `rest` holds into blocks of up to `limit` bytes, in archive order, as
/// `ops::add_planned` does for new files. Empty files and everything else go one at a time.
fn groups(entries: &[Entry], paths: &HashMap<usize, String>, limit: u64) -> Vec<Group> {
    let mut out: Vec<Group> = Vec::new();
    let mut cur: Group = Vec::new();
    let mut bytes = 0u64;
    for e in entries.iter().filter(|e| paths.contains_key(&e.id)) {
        let size = e.size.unwrap_or(1);
        if e.kind != EntryKind::File || size == 0 {
            continue;
        }
        if !cur.is_empty() && bytes.saturating_add(size) > limit {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        cur.push(e.id);
        bytes = bytes.saturating_add(size);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Decodes on a helper thread and adds on the job's: the source pushes its entries, and a
/// solid writer pulls them.
#[allow(clippy::too_many_arguments)]
fn bridge(
    source: &mut dyn ArchiveReader,
    writer: &mut dyn ArchiveWriter,
    entries: &[Entry],
    paths: &HashMap<usize, String>,
    sel: &Selection,
    meter: &mut Meter,
    cx: &mut dyn Ctx,
    out: &mut Decoded,
    links: &mut Vec<usize>,
) -> Result<()> {
    let limit = writer.solid_block_limit().unwrap_or(u64::MAX);
    let groups = groups(entries, paths, limit);
    let first_of: HashMap<usize, usize> = groups
        .iter()
        .enumerate()
        .filter_map(|(g, ids)| ids.first().map(|&id| (id, g)))
        .collect();
    let in_group: std::collections::HashSet<usize> = groups.iter().flatten().copied().collect();
    // The helper can't ask anyone, so the password, if one is needed, is asked first.
    let password = if entries
        .iter()
        .any(|e| e.encrypted && paths.contains_key(&e.id))
    {
        Some(cx.password(None, 0)?)
    } else {
        None
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let counter = meter.bytes.clone();
    let result = std::thread::scope(|s| -> Result<()> {
        let (tx, rx) = mpsc::sync_channel::<Msg>(4);
        let helper_cancel = Arc::clone(&cancel);
        let helper_warnings = Arc::clone(&warnings);
        s.spawn(move || {
            let mut hcx = HelperCtx {
                password,
                cancel: helper_cancel,
                warnings: helper_warnings,
            };
            let mut sink = PipeSink { tx: tx.clone() };
            let done = source.extract(sel, &mut sink, &mut hcx);
            let _ = tx.send(Msg::Done(done));
        });
        let run = (|| -> Result<()> {
            loop {
                cx.check()?;
                let msg = rx
                    .recv()
                    .map_err(|_| Error::corrupt("the decoder stopped early"))?;
                let (entry, data) = match msg {
                    Msg::Done(r) => return r,
                    Msg::Item(e, d) => (*e, d),
                };
                let Some(path) = paths.get(&entry.id) else {
                    continue;
                };
                meter.current = Some(entry.path.clone());
                if let Some(&g) = first_of.get(&entry.id) {
                    let ids = &groups[g];
                    let mut news = Vec::with_capacity(ids.len());
                    for id in ids {
                        let e = &entries[*id];
                        let p = paths.get(id).map_or(e.path.as_str(), String::as_str);
                        news.push(new_entry(e, p, NewKind::File, e.size.unwrap_or(0)));
                    }
                    let mut first = data.map(|r| CountingReader::new(r, counter.clone()));
                    let mut deferred: Vec<(Entry, Vec<u8>)> = Vec::new();
                    let mut open = |k: usize| -> Result<Box<dyn Read>> {
                        if k == 0 {
                            return first
                                .take()
                                .map(|r| Box::new(r) as Box<dyn Read>)
                                .ok_or_else(|| Error::corrupt("an entry came without its data"));
                        }
                        // Between a block's files come only entries without data, and empty
                        // files: they are added after the block.
                        loop {
                            match rx.recv() {
                                Ok(Msg::Item(e, Some(r))) if e.id == ids[k] => {
                                    return Ok(Box::new(CountingReader::new(r, counter.clone())));
                                }
                                Ok(Msg::Item(e, Some(r))) if !in_group.contains(&e.id) => {
                                    let mut bytes = Vec::new();
                                    r.take(MAX_SMALL + 1)
                                        .read_to_end(&mut bytes)
                                        .map_err(|e| crate::io::read_error(&e))?;
                                    if bytes.len() as u64 > MAX_SMALL {
                                        return Err(Error::corrupt("an empty file has data"));
                                    }
                                    deferred.push((*e, bytes));
                                }
                                Ok(Msg::Item(e, None)) => deferred.push((*e, Vec::new())),
                                Ok(Msg::Item(..)) => {
                                    return Err(Error::corrupt("entries came out of order"));
                                }
                                Ok(Msg::Done(Err(e))) => return Err(e),
                                Ok(Msg::Done(Ok(()))) | Err(_) => {
                                    return Err(Error::corrupt("the decoder stopped early"));
                                }
                            }
                        }
                    };
                    let mut mcx = MeteredCtx::new(cx, meter);
                    writer.add_solid(&news, &mut open, &mut mcx)?;
                    out.files += ids.len() as u64;
                    for (e, bytes) in deferred {
                        if let Some(p) = paths.get(&e.id) {
                            let mut data = io::Cursor::new(bytes);
                            add_one(writer, &e, p, &mut data, out, links, &mut mcx)?;
                        }
                    }
                } else {
                    let mut mcx = MeteredCtx::new(cx, meter);
                    match data {
                        Some(r) => {
                            let mut r = CountingReader::new(r, counter.clone());
                            add_one(writer, &entry, path, &mut r, out, links, &mut mcx)?;
                        }
                        None => {
                            add_one(writer, &entry, path, &mut io::empty(), out, links, &mut mcx)?
                        }
                    }
                }
            }
        })();
        if run.is_err() {
            cancel.store(true, Ordering::Relaxed);
        }
        // Dropping the receiver here ends a helper still sending.
        drop(rx);
        run
    });
    if let Ok(w) = warnings.lock() {
        for m in w.iter() {
            cx.warn(m.clone());
        }
    }
    result
}
