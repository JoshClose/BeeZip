//! Writing a `.bhive` (docs/M13.md §3, §5; docs/bhive.md).
//!
//! - **The job's thread plans,** in the order the files are given: it looks each chunk up among
//!   those stored so far, copies the new ones into the cell being filled, and seals the cell
//!   when the next file doesn't fit. Every decision is made there, in order, so the same input
//!   gives the same archive however many threads work.
//! - **Workers compress** the sealed cells, as many at once as fit the memory budget, and the
//!   job's thread writes them in order, each behind its record.
//! - **Loaders** ([`ArchiveWriter::add_all`]) read the files ahead of the planner, cut them into
//!   chunks and hash those: for a folder of small files, reading is most of the work.
//! - **Nothing is seeked:** the index block and footer are written last.

use std::{
    collections::{HashMap, VecDeque},
    hash::{BuildHasherDefault, Hash, Hasher},
    io::{self, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use super::{
    chunk::{self, Chunk, MIN_SHARED, SEGMENT},
    coder::{self, Level},
    layout::{self, Cell, Extent, IndexHead, ItemRef, Kind, MAX_CELL, Record, checksum, stamp},
    mem,
};
use crate::{
    Ctx, Error, ErrorKind, Result,
    codec::resolve_threads,
    format::{ArchiveWriter, NewEntry, NewKind, Opener, normalize},
    io::{WriteSeek, read_error, write_error},
};

/// How often a waiting thread looks up, to notice a cancelled job.
const POLL: Duration = Duration::from_millis(25);
/// The chunks remembered at most: about 450 MiB of table, for the first 150 GiB or so of
/// distinct input. Past it, chunks are still stored, and no longer looked for.
const MAX_SEEN: usize = 8 << 20;
/// A journal this large seals its cell, whatever the cell holds: a tree of a million empty
/// files is otherwise one journal.
const MAX_JOURNAL: usize = 4 << 20;
/// Entries a loader may be ahead of the planner.
const AHEAD: usize = 4096;
/// Segments of one big file read ahead of the planner while their chunks are hashed.
const SEGMENTS_AHEAD: usize = 16;

/// How to write a `.bhive`.
#[derive(Debug, Clone, Default)]
pub struct BhiveWriteOptions {
    pub level: Level,
    /// Workers: `0` is one per logical core, `1` does everything on the job's thread.
    pub threads: u32,
    /// The memory the cells in flight may take, in bytes. `None` is a quarter of the machine's.
    /// One cell is always in flight, whatever this says.
    pub memory: Option<u64>,
    /// The most raw bytes of a cell, instead of the level's: for tests, which want many cells
    /// from little data. At most 256 MiB.
    pub cell_size: Option<u32>,
}

/// A chunk's BLAKE3, hashed for the table by its first eight bytes: it is a hash already.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Id([u8; 32]);

impl Hash for Id {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut first = [0u8; 8];
        first.copy_from_slice(&self.0[..8]);
        state.write_u64(u64::from_le_bytes(first));
    }
}

#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }

    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
}

/// A cell that is full, with the journal of the entries completed in it.
struct Sealed {
    number: u32,
    raw: Vec<u8>,
    journal: Vec<u8>,
    journal_items: u32,
    /// What it is charged against the memory budget while in flight.
    cost: u64,
}

/// A sealed cell as it goes into the file.
struct Packed {
    record: Record,
    journal: Vec<u8>,
    data: Vec<u8>,
    cost: u64,
}

/// Compresses a sealed cell and its journal, and makes its record.
fn pack(sealed: Sealed, level: Level, stop: &AtomicBool) -> Result<Packed> {
    let coded = coder::encode(&sealed.raw, level, stop)?;
    let sum = checksum(&sealed.raw);
    let raw_len = sealed.raw.len();
    let data = coded.data.unwrap_or(sealed.raw);
    let journal_raw = sealed.journal.len();
    let (journal, journal_zstd) = pack_small(sealed.journal, level)?;
    let len = |n: usize| u32::try_from(n).map_err(|_| Error::limit("bhive: a cell too large"));
    Ok(Packed {
        record: Record {
            number: sealed.number,
            raw: len(raw_len)?,
            stored: len(data.len())?,
            coder: coded.coder,
            param: coded.param,
            journal_zstd,
            journal_items: sealed.journal_items,
            journal_raw: len(journal_raw)?,
            journal_stored: len(journal.len())?,
            checksum: sum,
        },
        journal,
        data,
        cost: sealed.cost,
    })
}

/// A journal or the index as stored: one zstd frame when that is smaller, else as it is.
/// Returns the bytes and whether they are zstd.
fn pack_small(raw: Vec<u8>, level: Level) -> Result<(Vec<u8>, bool)> {
    if raw.is_empty() {
        return Ok((raw, false));
    }
    let packed = zstd::bulk::compress(&raw, level.index_level())
        .map_err(|e| Error::new(ErrorKind::Io, format!("bhive: zstd: {e}")))?;
    Ok(if packed.len() < raw.len() {
        (packed, true)
    } else {
        (raw, false)
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the job's thread and the compression workers share.
struct Shared {
    state: Mutex<PoolState>,
    /// Workers wait here for a cell.
    work: Condvar,
    /// The job's thread waits here for a packed one.
    done: Condvar,
    stop: AtomicBool,
    level: Level,
}

#[derive(Default)]
struct PoolState {
    queue: VecDeque<Sealed>,
    packed: HashMap<u32, Result<Packed>>,
}

/// The compression workers. Dropping it stops them: a worker notices between cells, and within
/// an LZMA2 cell every MiB.
struct Pool {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Pool {
    fn new(workers: usize, level: Level) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(PoolState::default()),
            work: Condvar::new(),
            done: Condvar::new(),
            stop: AtomicBool::new(false),
            level,
        });
        let threads = (0..workers)
            .map(|_| {
                let shared = shared.clone();
                std::thread::spawn(move || shared.work())
            })
            .collect();
        Self { shared, threads }
    }
}

impl Shared {
    fn work(&self) {
        loop {
            let sealed = {
                let mut st = lock(&self.state);
                loop {
                    if self.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(s) = st.queue.pop_front() {
                        break s;
                    }
                    st = self.work.wait(st).unwrap_or_else(PoisonError::into_inner);
                }
            };
            let number = sealed.number;
            // A panic in a coder must not leave the job waiting for this cell for ever.
            let packed = catch_unwind(AssertUnwindSafe(|| pack(sealed, self.level, &self.stop)))
                .unwrap_or_else(|_| {
                    Err(Error::new(
                        ErrorKind::Io,
                        format!("bhive: compressing cell {number} failed unexpectedly"),
                    ))
                });
            lock(&self.state).packed.insert(number, packed);
            self.done.notify_all();
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        {
            // Under the lock: a worker looks at `stop` and then waits with the lock held, so a
            // stop set without it could fall between the two.
            let _st = lock(&self.shared.state);
            self.shared.stop.store(true, Ordering::Relaxed);
        }
        self.shared.work.notify_all();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// Writes a `.bhive`. `finish` must be called.
pub struct BhiveWriter {
    out: Box<dyn WriteSeek>,
    /// Bytes written so far: the next block's offset.
    pos: u64,
    level: Level,
    cell_size: usize,
    workers: usize,
    budget: u64,
    /// The cell being filled, and the items of the entries completed in it.
    cell: Vec<u8>,
    journal: Vec<u8>,
    journal_items: u32,
    /// How many cells are sealed: the number of the one being filled.
    sealed: u32,
    /// Where each chunk stored so far is.
    seen: HashMap<Id, Extent, BuildHasherDefault<IdHasher>>,
    /// The cells written, in order: the index's table.
    cells: Vec<Cell>,
    /// Every entry's item, and how many.
    items: Vec<u8>,
    entries: u64,
    pool: Option<Pool>,
    /// Sealed cells not written yet, and what they are charged.
    pending: usize,
    in_flight: u64,
}

impl BhiveWriter {
    /// Writes the header to `out`.
    pub fn new(mut out: Box<dyn WriteSeek>, opts: &BhiveWriteOptions) -> Result<Self> {
        let cell_size = opts.cell_size.unwrap_or(opts.level.cell_size());
        if cell_size == 0 || cell_size > MAX_CELL {
            return Err(Error::invalid_args(format!(
                "bhive: a cell of {cell_size} bytes; cells hold 1 byte to 256 MiB"
            )));
        }
        let header = layout::header();
        out.write_all(&header).map_err(|e| write_error(&e))?;
        let workers = resolve_threads(opts.threads) as usize;
        Ok(Self {
            out,
            pos: header.len() as u64,
            level: opts.level,
            cell_size: cell_size as usize,
            workers,
            budget: opts.memory.unwrap_or_else(mem::budget),
            cell: Vec::new(),
            journal: Vec::new(),
            journal_items: 0,
            sealed: 0,
            seen: HashMap::default(),
            cells: Vec::new(),
            items: Vec::new(),
            entries: 0,
            pool: (workers > 1).then(|| Pool::new(workers, opts.level)),
            pending: 0,
            in_flight: 0,
        })
    }

    /// The most a loader reads of a file before the planner has it: a whole cell, to the next
    /// segment boundary, so what follows is chunked as if the file were read in one piece.
    fn load_cap(&self) -> usize {
        self.cell_size.next_multiple_of(SEGMENT)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes).map_err(|e| write_error(&e))?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    /// Writes a packed cell: its record, its journal, its data.
    fn write_packed(&mut self, p: Packed) -> Result<()> {
        debug_assert_eq!(p.record.number as usize, self.cells.len());
        let head = p.record.encode(&p.journal);
        self.write(&head)?;
        self.write(&p.journal)?;
        let offset = self.pos;
        self.write(&p.data)?;
        self.cells.push(p.record.cell(offset));
        Ok(())
    }

    /// Writes the cells the workers have packed, as far as they are next in order.
    fn write_ready(&mut self) -> Result<()> {
        loop {
            let next = self.cells.len() as u32;
            let Some(pool) = &self.pool else {
                return Ok(());
            };
            let Some(packed) = lock(&pool.shared.state).packed.remove(&next) else {
                return Ok(());
            };
            let packed = packed?;
            self.pending -= 1;
            self.in_flight -= packed.cost;
            self.write_packed(packed)?;
        }
    }

    /// Waits for a worker to pack something, or [`POLL`].
    fn wait_packed(&self) {
        if let Some(pool) = &self.pool {
            let st = lock(&pool.shared.state);
            let next = self.cells.len() as u32;
            if !st.packed.contains_key(&next) {
                drop(pool.shared.done.wait_timeout(st, POLL));
            }
        }
    }

    /// Seals the cell being filled and sends it to be compressed and written. With workers it
    /// waits here while the cells in flight are over the memory budget.
    fn seal(&mut self, cx: &mut dyn Ctx) -> Result<()> {
        let raw = std::mem::take(&mut self.cell);
        let journal = std::mem::take(&mut self.journal);
        let cost = self.level.memory(raw.len()) + journal.len() as u64;
        let sealed = Sealed {
            number: self.sealed,
            raw,
            journal,
            journal_items: std::mem::take(&mut self.journal_items),
            cost,
        };
        self.sealed = self
            .sealed
            .checked_add(1)
            .ok_or_else(|| Error::limit("bhive: more than 2^32 cells"))?;
        if self.pool.is_none() {
            static NEVER: AtomicBool = AtomicBool::new(false);
            cx.check()?;
            let packed = pack(sealed, self.level, &NEVER)?;
            return self.write_packed(packed);
        }
        loop {
            self.write_ready()?;
            if self.pending == 0 || self.in_flight + cost <= self.budget {
                break;
            }
            cx.check()?;
            self.wait_packed();
        }
        self.pending += 1;
        self.in_flight += cost;
        if let Some(pool) = &self.pool {
            lock(&pool.shared.state).queue.push_back(sealed);
            pool.shared.work.notify_one();
        }
        Ok(())
    }

    /// Appends new bytes to the cell being filled, sealing cells as they fill, and their
    /// extents to `extents`. Returns the extent when the bytes landed in one cell.
    fn store(
        &mut self,
        bytes: &[u8],
        extents: &mut Vec<Extent>,
        cx: &mut dyn Ctx,
    ) -> Result<Option<Extent>> {
        let mut rest = bytes;
        let mut whole = None;
        while !rest.is_empty() {
            if self.cell.len() >= self.cell_size {
                self.seal(cx)?;
            }
            if self.cell.capacity() == 0 {
                self.cell
                    .reserve_exact(self.cell_size.min(rest.len().max(1 << 20)));
            }
            let take = rest.len().min(self.cell_size - self.cell.len());
            // Both fit: a cell is at most 256 MiB.
            let e = Extent {
                cell: self.sealed,
                offset: self.cell.len() as u32,
                len: take as u32,
            };
            self.cell.extend_from_slice(&rest[..take]);
            push_extent(extents, e);
            if take == bytes.len() {
                whole = Some(e);
            }
            rest = &rest[take..];
        }
        Ok(whole)
    }

    /// Places a run of a file's bytes: each chunk seen before becomes an extent into the cell
    /// that holds it, and the rest is stored. Without `chunks` (level None) all of it is stored.
    fn place(
        &mut self,
        data: &[u8],
        chunks: &[Chunk],
        extents: &mut Vec<Extent>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        if !self.level.shares() {
            self.store(data, extents, cx)?;
            return Ok(());
        }
        let mut start = 0;
        for c in chunks {
            let bytes = &data[start..c.end];
            start = c.end;
            let shared = bytes.len() >= MIN_SHARED;
            if shared && let Some(&e) = self.seen.get(&Id(c.hash)) {
                push_extent(extents, e);
                continue;
            }
            if let Some(e) = self.store(bytes, extents, cx)?
                && shared
                && self.seen.len() < MAX_SEEN
            {
                self.seen.insert(Id(c.hash), e);
            }
        }
        Ok(())
    }

    /// A file that fits in a cell, all of it in `data`: never split across two cells. The cell
    /// being filled is sealed first when the file's new bytes don't fit in what is left of it.
    fn place_whole(
        &mut self,
        data: &[u8],
        chunks: &[Chunk],
        extents: &mut Vec<Extent>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let new = if self.level.shares() {
            let mut start = 0;
            let mut new = 0;
            for c in chunks {
                let len = c.end - start;
                start = c.end;
                if len < MIN_SHARED || !self.seen.contains_key(&Id(c.hash)) {
                    new += len;
                }
            }
            new
        } else {
            data.len()
        };
        if !self.cell.is_empty() && self.cell.len() + new > self.cell_size {
            self.seal(cx)?;
        }
        self.place(data, chunks, extents, cx)
    }

    /// The entry is complete: its item goes into the journal of the cell being filled, and
    /// into the index.
    fn complete(&mut self, entry: &NewEntry, extents: &[Extent], cx: &mut dyn Ctx) -> Result<()> {
        let path = normalize(&entry.path);
        let (kind, target) = match &entry.kind {
            NewKind::File => (Kind::File, ""),
            NewKind::Dir => (Kind::Folder, ""),
            NewKind::Symlink { target } => (Kind::Link, target.as_str()),
        };
        let item = ItemRef {
            kind,
            path: path.as_bytes(),
            modified: entry.modified.map(stamp),
            created: entry.created.map(stamp),
            mode: entry.unix_mode,
            attrs: entry.dos_attrs.map(|a| a & 0xFFFF),
            extents,
            target: target.as_bytes(),
        };
        let at = self.journal.len();
        layout::put_item(&mut self.journal, &item);
        self.items.extend_from_slice(&self.journal[at..]);
        self.journal_items += 1;
        self.entries += 1;
        if self.journal.len() >= MAX_JOURNAL {
            self.seal(cx)?;
        }
        Ok(())
    }

    /// A file's bytes from `data`, already begun with `head` (and its chunks, when a loader cut
    /// them): bigger than a cell, so it fills cells. `tasks` has loaders hash the segments read
    /// ahead; without it they are hashed here.
    fn stream(
        &mut self,
        entry: &NewEntry,
        head: Vec<u8>,
        head_chunks: Option<Vec<Chunk>>,
        data: Option<&mut dyn Read>,
        tasks: Option<&Tasks<'_>>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let shares = self.level.shares();
        let mut extents = Vec::new();
        let chunks = match head_chunks {
            Some(c) => c,
            None => cut(&head, shares),
        };
        self.place(&head, &chunks, &mut extents, cx)?;
        drop(head);
        if let Some(data) = data {
            let mut ahead: VecDeque<Arc<Segment>> = VecDeque::new();
            let mut eof = false;
            while !eof || !ahead.is_empty() {
                cx.check()?;
                if !eof && ahead.len() < SEGMENTS_AHEAD {
                    let mut block = Vec::with_capacity(SEGMENT);
                    eof = read_up_to(data, &mut block, SEGMENT).map_err(|e| read_error(&e))?;
                    if !block.is_empty() {
                        let segment = Arc::new(Segment {
                            data: block,
                            chunks: OnceLock::new(),
                        });
                        match tasks {
                            Some(t) if shares => t.hash(segment.clone()),
                            _ => {
                                let _ = segment.chunks.set(cut(&segment.data, shares));
                            }
                        }
                        ahead.push_back(segment);
                    }
                    // Keep reading while there is room ahead and the oldest isn't hashed yet.
                    if !eof
                        && ahead.len() < SEGMENTS_AHEAD
                        && ahead.front().is_some_and(|s| s.chunks.get().is_none())
                    {
                        continue;
                    }
                }
                let Some(segment) = ahead.pop_front() else {
                    continue;
                };
                let chunks = loop {
                    if let Some(c) = segment.chunks.get() {
                        break c;
                    }
                    cx.check()?;
                    if let Some(t) = tasks {
                        t.wait_hashed();
                    }
                };
                self.place(&segment.data, chunks, &mut extents, cx)?;
            }
        }
        self.complete(entry, &extents, cx)
    }

    /// A file from a reader, on this thread: all of it at once when it fits in a cell.
    fn add_file(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let cap = self.load_cap();
        let mut head = Vec::new();
        let mut eof = false;
        // In steps, so a cancelled job stops within one.
        while !eof && head.len() < cap {
            cx.check()?;
            let step = (head.len() + (1 << 20)).min(cap);
            eof = read_up_to(data, &mut head, step).map_err(|e| read_error(&e))?;
        }
        if eof && head.len() <= self.cell_size {
            let chunks = cut(&head, self.level.shares());
            let mut extents = Vec::new();
            self.place_whole(&head, &chunks, &mut extents, cx)?;
            return self.complete(entry, &extents, cx);
        }
        self.stream(entry, head, None, (!eof).then_some(data), None, cx)
    }

    /// The index block and the footer.
    fn write_index(&mut self) -> Result<()> {
        let raw = layout::encode_index(
            &self.cells,
            self.entries,
            &self.items,
            Some(self.level.number()),
        );
        let head = IndexHead {
            zstd: false,
            stored: 0,
            raw: raw.len() as u64,
            checksum: checksum(&raw),
        };
        let (stored, zstd) = pack_small(raw, self.level)?;
        let head = IndexHead {
            zstd,
            stored: stored.len() as u64,
            ..head
        };
        let offset = self.pos;
        self.write(&head.encode())?;
        self.write(&stored)?;
        self.write(&layout::footer(offset))
    }
}

/// The chunks of a file's bytes, when the level shares them.
fn cut(data: &[u8], shares: bool) -> Vec<Chunk> {
    let mut out = Vec::new();
    if shares {
        chunk::chunks(data, &mut out);
    }
    out
}

/// Adds an extent to a file's, joined to the last one when it goes on where that ends.
fn push_extent(extents: &mut Vec<Extent>, e: Extent) {
    match extents.last_mut() {
        Some(last) if last.cell == e.cell && last.offset + last.len == e.offset => {
            last.len += e.len;
        }
        _ => extents.push(e),
    }
}

/// Reads until `buf` holds `len` bytes or `r` ends, and says whether it ended.
fn read_up_to(r: &mut dyn Read, buf: &mut Vec<u8>, len: usize) -> io::Result<bool> {
    let want = len.saturating_sub(buf.len());
    let got = r.take(want as u64).read_to_end(buf)?;
    Ok(got < want)
}

/// A piece of a big file, read ahead of the planner, and its chunks once a loader has cut it.
struct Segment {
    data: Vec<u8>,
    chunks: OnceLock<Vec<Chunk>>,
}

/// A file a loader has read: all of it when `rest` is `None`.
struct Loaded<'a> {
    data: Vec<u8>,
    chunks: Vec<Chunk>,
    /// The file goes on: it grew since it was planned.
    rest: Option<Box<dyn Read + Send + 'a>>,
}

/// What the planner and the loaders share ([`ArchiveWriter::add_all`]).
struct Window<'a> {
    /// The next entry a loader takes, and the entry the planner is at.
    next: usize,
    at: usize,
    /// Bytes of files loaded or being loaded, not yet planned.
    in_flight: u64,
    loaded: HashMap<usize, Result<Loaded<'a>>>,
    /// Segments of a big file for a loader to hash.
    segments: VecDeque<Arc<Segment>>,
    stop: bool,
}

struct Tasks<'a> {
    window: Mutex<Window<'a>>,
    /// Loaders wait here for the window to move or a segment to hash.
    room: Condvar,
    /// The planner waits here for a file or a segment's chunks.
    ready: Condvar,
}

impl Tasks<'_> {
    fn hash(&self, segment: Arc<Segment>) {
        lock(&self.window).segments.push_back(segment);
        self.room.notify_all();
    }

    fn wait_hashed(&self) {
        let st = lock(&self.window);
        drop(self.ready.wait_timeout(st, POLL));
    }
}

impl ArchiveWriter for BhiveWriter {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        match entry.kind {
            NewKind::File => self.add_file(entry, data, cx),
            _ => self.complete(entry, &[], cx),
        }
    }

    fn workers(&self) -> usize {
        self.workers
    }

    /// Loaders read the files that fit in a cell ahead of the planner, whole, and cut and hash
    /// them; the planner takes them in order. A bigger file is read by the planner itself,
    /// which has the loaders hash its segments.
    fn add_all(&mut self, entries: &[NewEntry], open: &Opener<'_>, cx: &mut dyn Ctx) -> Result<()> {
        let cell_size = self.cell_size as u64;
        let cap = self.load_cap();
        let shares = self.level.shares();
        let small = |k: usize| entries[k].kind == NewKind::File && entries[k].size <= cell_size;
        // What a file is charged while loaded: at least a little, so empty files count too.
        let weight = |k: usize| entries[k].size.clamp(1024, cap as u64);
        let in_flight_max = (2 * cell_size).max(64 << 20);
        let tasks = Tasks {
            window: Mutex::new(Window {
                next: 0,
                at: 0,
                in_flight: 0,
                loaded: HashMap::new(),
                segments: VecDeque::new(),
                stop: false,
            }),
            room: Condvar::new(),
            ready: Condvar::new(),
        };
        let load = |k: usize| -> Result<Loaded<'_>> {
            let mut r = open(k)?;
            let mut data =
                Vec::with_capacity(usize::try_from(entries[k].size).unwrap_or(0).min(cap));
            let eof = read_up_to(&mut r, &mut data, cap).map_err(|e| read_error(&e))?;
            Ok(Loaded {
                chunks: cut(&data, shares),
                data,
                rest: (!eof).then_some(r),
            })
        };
        let loader = || {
            loop {
                enum Job {
                    File(usize),
                    Hash(Arc<Segment>),
                }
                let job = {
                    let mut st = lock(&tasks.window);
                    loop {
                        if st.stop {
                            return;
                        }
                        if let Some(s) = st.segments.pop_front() {
                            break Job::Hash(s);
                        }
                        while st.next < entries.len() && !small(st.next) {
                            st.next += 1;
                        }
                        let k = st.next;
                        if k < entries.len()
                            && k < st.at + AHEAD
                            && (st.in_flight + weight(k) <= in_flight_max || k <= st.at)
                        {
                            st.next += 1;
                            st.in_flight += weight(k);
                            break Job::File(k);
                        }
                        st = tasks.room.wait(st).unwrap_or_else(PoisonError::into_inner);
                    }
                };
                match job {
                    Job::File(k) => {
                        let loaded = load(k);
                        lock(&tasks.window).loaded.insert(k, loaded);
                    }
                    Job::Hash(s) => {
                        let _ = s.chunks.set(cut(&s.data, true));
                    }
                }
                tasks.ready.notify_all();
            }
        };
        std::thread::scope(|s| {
            // A big file is read here and hashed by the loaders, so one alone has them all.
            let big = (0..entries.len()).any(|k| entries[k].kind == NewKind::File && !small(k));
            let loaders = if big {
                self.workers
            } else {
                self.workers.min(entries.len())
            };
            for _ in 0..loaders {
                s.spawn(loader);
            }
            let result = (|| -> Result<()> {
                for (k, entry) in entries.iter().enumerate() {
                    cx.check()?;
                    {
                        let mut st = lock(&tasks.window);
                        st.at = k;
                    }
                    tasks.room.notify_all();
                    if entry.kind != NewKind::File {
                        self.complete(entry, &[], cx)?;
                        continue;
                    }
                    if !small(k) {
                        let mut data = open(k)?;
                        let mut head = Vec::with_capacity(SEGMENT);
                        let eof = read_up_to(&mut data, &mut head, SEGMENT)
                            .map_err(|e| read_error(&e))?;
                        let rest = (!eof).then_some(&mut data as &mut dyn Read);
                        self.stream(entry, head, None, rest, Some(&tasks), cx)?;
                        continue;
                    }
                    let loaded = loop {
                        let mut st = lock(&tasks.window);
                        if let Some(l) = st.loaded.remove(&k) {
                            st.in_flight -= weight(k);
                            break l;
                        }
                        drop(tasks.ready.wait_timeout(st, POLL));
                        cx.check()?;
                    }?;
                    tasks.room.notify_all();
                    match loaded.rest {
                        None if loaded.data.len() <= self.cell_size => {
                            let mut extents = Vec::new();
                            self.place_whole(&loaded.data, &loaded.chunks, &mut extents, cx)?;
                            self.complete(entry, &extents, cx)?;
                        }
                        mut rest => {
                            let rest = rest.as_mut().map(|r| r as &mut dyn Read);
                            let chunks = Some(loaded.chunks);
                            self.stream(entry, loaded.data, chunks, rest, Some(&tasks), cx)?;
                        }
                    }
                }
                Ok(())
            })();
            {
                let mut st = lock(&tasks.window);
                st.stop = true;
            }
            tasks.room.notify_all();
            result
        })
    }

    /// The last cell, the cells still with the workers, then the index block and footer.
    fn finish(mut self: Box<Self>, cx: &mut dyn Ctx) -> Result<()> {
        if !self.cell.is_empty() || !self.journal.is_empty() {
            self.seal(cx)?;
        }
        loop {
            self.write_ready()?;
            if self.pending == 0 {
                break;
            }
            cx.check()?;
            self.wait_packed();
        }
        self.pool = None;
        self.write_index()?;
        self.out.flush().map_err(|e| write_error(&e))
    }
}
