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
    crypt::{Protection, envelope::Envelope},
    layout::{
        self, Cell, Extent, IndexHead, ItemRef, Kind, MAX_CELL, Record, SECTION_DIGESTS,
        SECTION_LEVEL, SECTION_SIGNATURES, SECTION_SLOTS, checksum, stamp,
    },
    mem,
    read::BhiveReader,
    sign::{self, Signing},
};
use crate::{
    Ctx, Error, ErrorKind, Result,
    codec::resolve_threads,
    format::{
        ArchiveReader, ArchiveWriter, Copied, EntryKind, Keep, NewEntry, NewKind, Opener, normalize,
    },
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
    /// In an edit, write at the level the archive was made at, when it says, instead of
    /// `level`: nobody chose one, and an archive keeps its own.
    pub inherit: bool,
    /// Encrypt the archive for these ways in, or keep an edited archive's (docs/bhive.md §12).
    pub protection: Option<Protection>,
    /// Sign it (docs/bhive.md §13). An edit that isn't signed again drops the signatures.
    pub signing: Option<Signing>,
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
    /// The cell's bytes in the file: as stored, or sealed in an encrypted archive.
    data: Vec<u8>,
    cost: u64,
    /// The SHA-256 of the stored bytes, when the archive is signed (docs/bhive.md §13.2).
    digest: Option<[u8; 32]>,
    /// The cell's id, when the archive is encrypted (docs/bhive.md §12.2).
    id: Option<[u8; 32]>,
}

/// A cell's bytes in the file, its stored bytes' digest, and its id.
type Finished = (Vec<u8>, Option<[u8; 32]>, Option<[u8; 32]>);

/// What every cell goes through after it is compressed: a digest, then the seal.
#[derive(Default)]
struct Finish {
    digests: bool,
    envelope: Option<Arc<Envelope>>,
}

impl Finish {
    /// The stored bytes' digest, when signing, then the bytes sealed under a new id, when
    /// encrypting: in that order, since a signature covers what is stored, not how it is sealed.
    fn apply(&self, stored: Vec<u8>) -> Result<Finished> {
        let digest = match self.digests {
            true => Some(sign::cell_digest(&stored)?),
            false => None,
        };
        match &self.envelope {
            Some(env) => {
                let id = env.new_cell_id()?;
                let sealed = env.seal_cell(&id, &stored)?;
                Ok((sealed, digest, Some(id)))
            }
            None => Ok((stored, digest, None)),
        }
    }
}

/// Compresses a sealed cell and its journal, and makes its record.
fn pack(sealed: Sealed, level: Level, finish: &Finish, stop: &AtomicBool) -> Result<Packed> {
    let coded = coder::encode(&sealed.raw, level, stop)?;
    let sum = checksum(&sealed.raw);
    let raw_len = sealed.raw.len();
    let data = coded.data.unwrap_or(sealed.raw);
    let stored_len = data.len();
    let (data, digest, id) = finish.apply(data)?;
    let journal_raw = sealed.journal.len();
    let (journal, journal_zstd) = pack_small(sealed.journal, level)?;
    let len = |n: usize| u32::try_from(n).map_err(|_| Error::limit("bhive: a cell too large"));
    Ok(Packed {
        record: Record {
            number: sealed.number,
            raw: len(raw_len)?,
            stored: len(stored_len)?,
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
        digest,
        id,
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
    finish: Arc<Finish>,
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
    fn new(workers: usize, level: Level, finish: Arc<Finish>) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(PoolState::default()),
            work: Condvar::new(),
            done: Condvar::new(),
            stop: AtomicBool::new(false),
            level,
            finish,
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
            let packed = catch_unwind(AssertUnwindSafe(|| {
                pack(sealed, self.level, &self.finish, &self.stop)
            }))
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
    /// The digest and seal every cell gets, and what they gave, by cell.
    finish: Arc<Finish>,
    digests: Vec<[u8; 32]>,
    ids: Vec<[u8; 32]>,
    signing: Option<Signing>,
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
        let signing = opts.signing.clone().filter(|s| !s.is_empty());
        if let Some(signing) = &signing {
            sign::ready(signing)?;
        }
        let envelope = match &opts.protection {
            Some(p) => Some(Arc::new(Envelope::new(p)?)),
            None => None,
        };
        let mut start = match envelope {
            Some(_) => layout::header_encrypted().to_vec(),
            None => layout::header().to_vec(),
        };
        if let Some(env) = &envelope {
            start.extend_from_slice(env.key_block());
        }
        out.write_all(&start).map_err(|e| write_error(&e))?;
        let finish = Arc::new(Finish {
            digests: signing.is_some(),
            envelope,
        });
        let workers = resolve_threads(opts.threads) as usize;
        Ok(Self {
            out,
            pos: start.len() as u64,
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
            pool: (workers > 1).then(|| Pool::new(workers, opts.level, finish.clone())),
            pending: 0,
            in_flight: 0,
            finish,
            digests: Vec::new(),
            ids: Vec::new(),
            signing,
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

    /// Writes a packed cell: its record, its journal, its data; in an encrypted archive, a
    /// `BHCE` block with the record sealed, then the sealed cell (docs/bhive.md §12.6).
    fn write_packed(&mut self, p: Packed) -> Result<()> {
        debug_assert_eq!(p.record.number as usize, self.cells.len());
        let head = p.record.encode(&p.journal);
        match (&self.finish.envelope, p.id) {
            (Some(env), Some(id)) => {
                let sealed_len = u32::try_from(p.data.len())
                    .map_err(|_| Error::limit("bhive: a sealed cell too large"))?;
                let block = env.record_block(self.pos, &id, &head, &p.journal, sealed_len)?;
                self.write(&block)?;
                self.ids.push(id);
            }
            (Some(_), None) => {
                return Err(Error::new(ErrorKind::Io, "bhive: a cell wasn't sealed"));
            }
            (None, _) => {
                self.write(&head)?;
                self.write(&p.journal)?;
            }
        }
        if let Some(digest) = p.digest {
            self.digests.push(digest);
        }
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
            let packed = pack(sealed, self.level, &self.finish, &NEVER)?;
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
        self.journal_item(
            &ItemRef {
                kind,
                path: path.as_bytes(),
                modified: entry.modified.map(stamp),
                created: entry.created.map(stamp),
                mode: entry.unix_mode,
                attrs: entry.dos_attrs.map(|a| a & 0xFFFF),
                extents,
                target: target.as_bytes(),
            },
            cx,
        )
    }

    /// An item into the journal of the cell being filled, and into the index.
    fn journal_item(&mut self, item: &ItemRef<'_>, cx: &mut dyn Ctx) -> Result<()> {
        let at = self.journal.len();
        layout::put_item(&mut self.journal, item);
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

    /// The index block and the footer. A signed archive's index gets the cells' digests and
    /// the signatures; an encrypted one's has its cell ids and slot descriptions, and is sealed
    /// (docs/bhive.md §12.7, §13).
    fn write_index(&mut self) -> Result<()> {
        let level = [self.level.number()];
        let mut sections: Vec<(u64, Vec<u8>)> = vec![(SECTION_LEVEL, level.to_vec())];
        if let Some(signing) = &self.signing {
            if self.digests.len() != self.cells.len() {
                return Err(Error::new(ErrorKind::Io, "bhive: a cell has no digest"));
            }
            sections.push((SECTION_DIGESTS, self.digests.concat()));
            let covered: Vec<(u64, &[u8])> = sections
                .iter()
                .filter(|(id, _)| id % 2 == 0)
                .map(|(id, b)| (*id, b.as_slice()))
                .collect();
            let features = if self.finish.envelope.is_some() {
                layout::FEATURE_ENCRYPTED
            } else {
                0
            };
            let manifest = sign::manifest_of(
                layout::VERSION,
                features,
                &self.cells,
                self.entries,
                &self.items,
                &covered,
            )?;
            sections.push((SECTION_SIGNATURES, sign::section(signing, &manifest)?));
        }
        let envelope = self.finish.envelope.clone();
        if let Some(descriptions) = envelope.as_ref().and_then(|e| e.descriptions.clone()) {
            sections.push((SECTION_SLOTS, descriptions));
        }
        let sections: Vec<(u64, &[u8])> =
            sections.iter().map(|(id, b)| (*id, b.as_slice())).collect();
        let ids = envelope.as_ref().map(|_| self.ids.as_slice());
        let raw = layout::encode_index_with(&self.cells, ids, self.entries, &self.items, &sections);
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
        match envelope {
            Some(env) => {
                let mut inner = head.encode().to_vec();
                inner.extend_from_slice(&stored);
                let block = env.index_block(&inner)?;
                self.write(&block)?;
            }
            None => {
                self.write(&head.encode())?;
                self.write(&stored)?;
            }
        }
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

/// What becomes of a cell of the archive entries are kept from.
enum Fate {
    /// No kept entry has bytes in it.
    Gone,
    /// Copied as it is stored, under this number.
    Copy(u32),
    /// Decoded, and its runs that are still used stored again: each run's start and end in the
    /// old cell, and where it went.
    Repack(Vec<(u32, u32, Vec<Extent>)>),
}

/// Whether any of `extents` is in a cell that is stored again.
fn repacked(fates: &[Fate], extents: &[Extent]) -> bool {
    extents
        .iter()
        .any(|x| matches!(fates[x.cell as usize], Fate::Repack(_)))
}

/// Where an extent of the old archive is in the new one, added to `out`.
fn moved(fates: &[Fate], x: &Extent, out: &mut Vec<Extent>) -> Result<()> {
    match &fates[x.cell as usize] {
        Fate::Copy(number) => push_extent(
            out,
            Extent {
                cell: *number,
                ..*x
            },
        ),
        Fate::Repack(runs) => {
            // The run that holds it: runs are whole extents joined, so one does.
            let i = runs.partition_point(|(_, end, _)| *end <= x.offset);
            let Some((start, _, to)) = runs.get(i).filter(|(start, _, _)| *start <= x.offset)
            else {
                return Err(Error::new(ErrorKind::Io, "bhive: an extent lost its cell"));
            };
            let (mut skip, mut left) = (x.offset - start, x.len);
            for e in to {
                if skip >= e.len {
                    skip -= e.len;
                    continue;
                }
                let take = (e.len - skip).min(left);
                push_extent(
                    out,
                    Extent {
                        cell: e.cell,
                        offset: e.offset + skip,
                        len: take,
                    },
                );
                left -= take;
                skip = 0;
                if left == 0 {
                    break;
                }
            }
        }
        Fate::Gone => return Err(Error::new(ErrorKind::Io, "bhive: an extent lost its cell")),
    }
    Ok(())
}

/// The item of a kept entry: as it was, under the path it is kept as, with its new extents.
fn kept<'a>(r: &'a BhiveReader, k: &'a Keep, extents: &'a [Extent]) -> ItemRef<'a> {
    let e = &r.entries[k.id];
    let (kind, target) = match &e.kind {
        EntryKind::Dir => (Kind::Folder, ""),
        EntryKind::Symlink { target } => (Kind::Link, target.as_str()),
        _ => (Kind::File, ""),
    };
    let (modified, created) = r.stamps[k.id];
    ItemRef {
        kind,
        path: k.path.trim_end_matches('/').as_bytes(),
        modified,
        created,
        mode: e.unix_mode,
        attrs: e.dos_attrs,
        extents,
        target: target.as_bytes(),
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

    /// Keeps entries of another `.bhive` without decoding them (docs/M13.md §5): the cells
    /// they have bytes in are copied as they are stored, under new numbers, each behind a new
    /// record; a cell that has lost more than half its bytes is decoded, and what is left of
    /// it stored again. Only into an archive that holds nothing yet, and from an archive that
    /// has its index.
    fn copy_from(
        &mut self,
        source: &mut dyn ArchiveReader,
        keep: &[Keep],
        cx: &mut dyn Ctx,
    ) -> Result<Copied> {
        let empty = self.sealed == 0 && self.cell.is_empty() && self.entries == 0;
        let Some(r) = source.as_any_mut().downcast_mut::<BhiveReader>() else {
            return Ok(Copied::nothing(keep));
        };
        // Cells that need a digest are copied by PR H (docs/M14.md §10); until then their
        // entries are decoded and stored again.
        if self.finish.digests {
            return Ok(Copied::nothing(keep));
        }
        if !empty || r.recovered().is_some() || keep.iter().any(|k| k.id >= r.entries.len()) {
            return Ok(Copied::nothing(keep));
        }
        // How a copied cell is sealed (docs/bhive.md §12.2): under the same file key it goes as
        // it is, id and all; otherwise its stored bytes are opened from the old key, if any,
        // and sealed under a new id with the new one. Protect and New key keep every cell that
        // is still used, never storing one again, so its stored bytes and their signatures
        // stand (docs/M14.md §3).
        let as_is = match (r.unlocked(), &self.finish.envelope) {
            (None, None) => true,
            (Some(u), Some(env)) => env.same_key(u),
            _ => false,
        };

        // What is left of each cell: the bytes the kept entries have, as runs in order.
        let mut live: Vec<Vec<(u32, u32)>> = vec![Vec::new(); r.cells.len()];
        for k in keep {
            for x in r.extents_of(k.id) {
                live[x.cell as usize].push((x.offset, x.offset + x.len));
            }
        }
        for runs in &mut live {
            runs.sort_unstable();
            let mut joined: Vec<(u32, u32)> = Vec::with_capacity(runs.len());
            for &(start, end) in runs.iter() {
                match joined.last_mut() {
                    Some(last) if start <= last.1 => last.1 = last.1.max(end),
                    _ => joined.push((start, end)),
                }
            }
            *runs = joined;
        }
        // A cell goes as it is, under a new number, while at least half of it is still used.
        let mut fates = Vec::with_capacity(r.cells.len());
        let mut copies = 0u32;
        for (cell, runs) in r.cells.iter().zip(&live) {
            let left: u64 = runs.iter().map(|(a, b)| u64::from(b - a)).sum();
            fates.push(if left == 0 {
                Fate::Gone
            } else if left * 2 >= u64::from(cell.raw) || !as_is {
                copies += 1;
                Fate::Copy(copies - 1)
            } else {
                Fate::Repack(Vec::new())
            });
        }

        // An entry whose cells are all copied goes into the journal of the last of them, or of
        // the last cell an entry before it went into: journals list entries in order. From the
        // first entry with bytes in a cell that is stored again, entries wait for that.
        let early = match copies {
            0 => 0,
            _ => keep
                .iter()
                .position(|k| repacked(&fates, r.extents_of(k.id)))
                .unwrap_or(keep.len()),
        };
        let mut journals: Vec<(Vec<u8>, u32)> = vec![(Vec::new(), 0); copies as usize];
        let mut at = 0u32;
        let mut extents = Vec::new();
        for k in &keep[..early] {
            extents.clear();
            for x in r.extents_of(k.id) {
                moved(&fates, x, &mut extents)?;
            }
            at = extents.iter().map(|x| x.cell).fold(at, u32::max);
            let (journal, count) = &mut journals[at as usize];
            let from = journal.len();
            layout::put_item(journal, &kept(r, k, &extents));
            self.items.extend_from_slice(&journal[from..]);
            *count += 1;
            self.entries += 1;
        }

        // The cells that go as they are, in the order they were in.
        for (n, fate) in fates.iter().enumerate() {
            let Fate::Copy(number) = *fate else {
                continue;
            };
            cx.check()?;
            let cell = r.cells[n];
            let (data, id) = match &self.finish.envelope {
                Some(_) if as_is => (r.in_file(n)?, r.cell_ids().get(n).copied()),
                Some(env) => {
                    let id = env.new_cell_id()?;
                    (env.seal_cell(&id, &r.stored(n)?)?, Some(id))
                }
                None if as_is => (r.in_file(n)?, None),
                None => (r.stored(n)?, None),
            };
            let (journal, journal_items) = std::mem::take(&mut journals[number as usize]);
            let journal_raw = journal.len();
            let (journal, journal_zstd) = pack_small(journal, self.level)?;
            let len =
                |n: usize| u32::try_from(n).map_err(|_| Error::limit("bhive: a journal too large"));
            self.write_packed(Packed {
                record: Record {
                    number,
                    raw: cell.raw,
                    stored: cell.stored,
                    coder: cell.coder,
                    param: cell.param,
                    journal_zstd,
                    journal_items,
                    journal_raw: len(journal_raw)?,
                    journal_stored: len(journal.len())?,
                    checksum: cell.checksum,
                },
                journal,
                data,
                cost: 0,
                digest: None,
                id,
            })?;
        }
        self.sealed = copies;

        // What is left of the others, stored again in cells of this writer's.
        for (n, fate) in fates.iter_mut().enumerate() {
            if !matches!(fate, Fate::Repack(_)) {
                continue;
            }
            cx.check()?;
            let raw = r.raw(n as u32)?;
            let mut runs = Vec::with_capacity(live[n].len());
            for &(start, end) in &live[n] {
                let mut to = Vec::new();
                self.store(&raw[start as usize..end as usize], &mut to, cx)?;
                runs.push((start, end, to));
            }
            *fate = Fate::Repack(runs);
        }
        let mut recompressed = 0;
        for k in &keep[early..] {
            extents.clear();
            for x in r.extents_of(k.id) {
                moved(&fates, x, &mut extents)?;
            }
            recompressed += u64::from(repacked(&fates, r.extents_of(k.id)));
            let item = kept(r, k, &extents);
            self.journal_item(&item, cx)?;
        }
        Ok(Copied {
            rest: Vec::new(),
            copied: keep.len() as u64 - recompressed,
            recompressed,
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
