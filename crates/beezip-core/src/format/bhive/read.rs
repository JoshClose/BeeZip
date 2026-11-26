//! Reading a `.bhive` (docs/M13.md §5, §7; docs/bhive.md).
//!
//! - **Opening** reads the footer, the index block and nothing else: every cell and entry is in
//!   the index, and everything docs/bhive.md §9 asks is checked before an entry is listed.
//! - **A file's bytes** come from its extents, each a run of one cell. Cells are decoded whole,
//!   checked against their checksum, and kept in a [`Cache`] while there is room, so the files
//!   of one cell cost one decode.
//! - **Extracting to disk** runs on every core (`par.rs`); so does testing, cell by cell.
//! - **A damaged cell** fails the files with bytes in it, and the rest of the archive is read.
//! - **A missing or damaged index** is `Corrupt`, unless the archive is opened to recover
//!   ([`crate::OpenOptions::recover`]): then the entries come from the records before each cell.

use std::{
    any::Any,
    borrow::Cow,
    collections::{HashMap, VecDeque},
    io::{self, Read, Seek, SeekFrom},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::{
    coder,
    crypt::{
        TAG_LEN,
        envelope::{KeyBlock, Unlocked},
    },
    layout::{
        self, CELL_TAG, Cell, Coder, Extent, FOOTER_LEN, HEADER_LEN, INDEX_HEAD_LEN, INDEX_TAG,
        Index, IndexHead, Items, Kind, RECORD_LEN, Record, SEALED_CELL_HEAD_LEN, SEALED_CELL_TAG,
        SEALED_INDEX_HEAD_LEN, SEALED_INDEX_TAG, Stamp, TableForm, bad, checksum, sums,
    },
    mem, par, sign,
};
use crate::{
    Ctx, Error, ErrorKind, Limits, Meter, MeteredCtx, Result, TestReport,
    backend::{ExternalInfo, LevelProperty},
    codec::resolve_threads,
    format::{
        ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
    },
    io::{Counter, read_error},
    limits::{Guarded, RatioGuard},
    source::{Input, Source},
    time::from_unix,
};

/// How often a waiting thread looks up.
pub(super) const POLL: Duration = Duration::from_millis(25);
/// The decoded cells an open archive keeps between jobs: the last one read, so a preview or a
/// file opened from the list is immediate, and no more than this.
pub(super) const KEEP: u64 = 64 << 20;

pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `len` bytes of the input at `offset`.
fn read_at(input: &mut Input, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    input
        .seek(SeekFrom::Start(offset))
        .and_then(|_| input.read_exact(&mut buf))
        .map_err(|e| read_error(&e))?;
    Ok(buf)
}

fn memory_limit(what: &str, need: u64, limits: &Limits) -> Result<()> {
    if need > limits.decoder_memory {
        return Err(Error::limit(format!(
            "bhive: {what} needs {} MiB (limit `decoder_memory`)",
            need.div_ceil(1 << 20)
        )));
    }
    Ok(())
}

/// The index, found from the footer and checked, and its signatures checked against it.
fn read_index(
    input: &mut Input,
    header: &[u8; HEADER_LEN],
    limits: &Limits,
    unlocked: Option<&Unlocked>,
    key_block_len: u64,
) -> Result<(Index, sign::Checked)> {
    if let Some(unlocked) = unlocked {
        return read_sealed_index(input, header, limits, unlocked, key_block_len);
    }
    let len = input.len();
    let least = (HEADER_LEN + INDEX_HEAD_LEN + FOOTER_LEN) as u64;
    if len < least {
        return Err(bad("the file is too short to hold an index"));
    }
    let footer = read_at(input, len - FOOTER_LEN as u64, FOOTER_LEN)?;
    let Some(offset) = layout::parse_footer(&footer) else {
        return Err(bad("the file doesn't end with a .bhive footer"));
    };
    if offset < HEADER_LEN as u64 || offset > len - (INDEX_HEAD_LEN + FOOTER_LEN) as u64 {
        return Err(bad("the footer points outside the file"));
    }
    let head = IndexHead::parse(&read_at(input, offset, INDEX_HEAD_LEN)?)?;
    // The index block and the footer end the file, exactly.
    let ends = offset
        .checked_add(INDEX_HEAD_LEN as u64)
        .and_then(|n| n.checked_add(head.stored))
        .and_then(|n| n.checked_add(FOOTER_LEN as u64));
    if ends != Some(len) {
        return Err(bad("the index and the footer don't end the file"));
    }
    memory_limit("the index", head.raw.max(head.stored), limits)?;
    let stored = read_at(input, offset + INDEX_HEAD_LEN as u64, head.stored as usize)?;
    let raw = index_raw(&head, stored)?;
    let index = layout::parse_index(&raw, offset, limits.max_entries)?;
    let report = sign::checked(header, &raw, &index);
    Ok((index, report))
}

/// An index's raw bytes from its stored ones, checked.
fn index_raw(head: &IndexHead, stored: Vec<u8>) -> Result<Vec<u8>> {
    let raw = if head.zstd {
        coder::unzstd(&stored, head.raw as usize, "the index")?
    } else {
        stored
    };
    if !sums(checksum(&raw), head.checksum) {
        return Err(bad("the index fails its checksum"));
    }
    Ok(raw)
}

fn u64_of(b: &[u8]) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[..8]);
    u64::from_le_bytes(w)
}

/// An encrypted archive's index (docs/bhive.md §12.7): the `BHIE` block the footer points to,
/// opened, then read as §5's index block with a sealed table.
fn read_sealed_index(
    input: &mut Input,
    header: &[u8; HEADER_LEN],
    limits: &Limits,
    unlocked: &Unlocked,
    key_block_len: u64,
) -> Result<(Index, sign::Checked)> {
    let len = input.len();
    let start = HEADER_LEN as u64 + key_block_len;
    let least = start + (SEALED_INDEX_HEAD_LEN + TAG_LEN + INDEX_HEAD_LEN + FOOTER_LEN) as u64;
    if len < least {
        return Err(bad("the file is too short to hold a sealed index"));
    }
    let footer = read_at(input, len - FOOTER_LEN as u64, FOOTER_LEN)?;
    let Some(offset) = layout::parse_footer(&footer) else {
        return Err(bad("the file doesn't end with a .bhive footer"));
    };
    if offset < start || offset > len - (SEALED_INDEX_HEAD_LEN + FOOTER_LEN) as u64 {
        return Err(bad("the footer points outside the file"));
    }
    let head = read_at(input, offset, SEALED_INDEX_HEAD_LEN)?;
    if head[..4] != SEALED_INDEX_TAG {
        return Err(bad("the footer doesn't point at a sealed index"));
    }
    let sealed = u64_of(&head[8..16]);
    // A sealed length larger than the file is refused before anything is added to it.
    let ends = (sealed <= len)
        .then(|| offset + (SEALED_INDEX_HEAD_LEN + FOOTER_LEN) as u64)
        .and_then(|n| n.checked_add(sealed));
    if ends != Some(len) {
        return Err(bad("the sealed index and the footer don't end the file"));
    }
    memory_limit("the index", sealed, limits)?;
    let block = read_at(input, offset, SEALED_INDEX_HEAD_LEN + sealed as usize)?;
    let inner = unlocked.open_index(&block)?;
    let head = IndexHead::parse(&inner)?;
    memory_limit("the index", head.raw.max(head.stored), limits)?;
    let raw = index_raw(&head, inner[INDEX_HEAD_LEN..].to_vec())?;
    let form = TableForm {
        sealed: true,
        start,
    };
    let index = layout::parse_index_with(&raw, offset, limits.max_entries, form)?;
    if let Some(body) = index.section(layout::SECTION_SLOTS) {
        unlocked.set_descriptions(body);
    }
    let report = sign::checked(header, &raw, &index);
    Ok((index, report))
}

/// What the records before the cells still list (docs/bhive.md §8): the cells that are whole,
/// in order from the start of the file, and the entries completed in them.
fn recover(
    input: &mut Input,
    limits: &Limits,
    sealed: Option<(&Unlocked, u64)>,
    cx: &mut dyn Ctx,
) -> Result<(Vec<Cell>, Items, Vec<[u8; 32]>)> {
    if let Some((unlocked, key_block_len)) = sealed {
        return recover_sealed(input, limits, unlocked, key_block_len, cx);
    }
    let len = input.len();
    let mut cells: Vec<Cell> = Vec::new();
    let mut items = Items::default();
    let mut pos = HEADER_LEN as u64;
    // A step that fails ends the scan: what was taken before it stands.
    let mut step = |pos: u64, cells: &mut Vec<Cell>, items: &mut Items| -> Result<Option<u64>> {
        if pos.checked_add(4).is_none_or(|end| end > len) {
            return Ok(None);
        }
        let tag = read_at(input, pos, 4)?;
        if tag == INDEX_TAG {
            // An index block in the middle: the file was added to in place.
            if pos + (INDEX_HEAD_LEN + FOOTER_LEN) as u64 > len {
                return Ok(None);
            }
            let head = IndexHead::parse(&read_at(input, pos, INDEX_HEAD_LEN)?)?;
            let end = pos
                .checked_add((INDEX_HEAD_LEN + FOOTER_LEN) as u64)
                .and_then(|n| n.checked_add(head.stored));
            return Ok(end.filter(|&end| end <= len));
        }
        if tag != CELL_TAG || pos + RECORD_LEN as u64 > len {
            return Ok(None);
        }
        let mut head = [0u8; RECORD_LEN];
        head.copy_from_slice(&read_at(input, pos, RECORD_LEN)?);
        let (record, sum) = Record::parse(&head)?;
        if record.number as usize != cells.len() {
            return Err(bad("a record out of order"));
        }
        let journal_at = pos + RECORD_LEN as u64;
        let cell = record.cell(journal_at + u64::from(record.journal_stored));
        cell.check()?;
        if cell.end() > len {
            return Ok(None);
        }
        memory_limit(
            "a journal",
            u64::from(record.journal_raw.max(record.journal_stored)),
            limits,
        )?;
        let stored = read_at(input, journal_at, record.journal_stored as usize)?;
        if !sums(layout::record_checksum(&head, &stored), sum) {
            return Err(bad("a record fails its checksum"));
        }
        let raw = if record.journal_zstd {
            coder::unzstd(&stored, record.journal_raw as usize, "a journal")?
        } else {
            stored
        };
        cells.push(cell);
        let (had_items, had_extents) = (items.items.len(), items.extents.len());
        if let Err(e) = layout::parse_journal(&raw, record.journal_items, cells, items) {
            cells.pop();
            items.items.truncate(had_items);
            items.extents.truncate(had_extents);
            return Err(e);
        }
        Ok(Some(cell.end()))
    };
    loop {
        cx.check()?;
        match step(pos, &mut cells, &mut items) {
            Ok(Some(next)) => pos = next,
            Ok(None) => break,
            Err(e) if e.kind == ErrorKind::Corrupt => break,
            Err(e) => return Err(e),
        }
        limits.check_entries(items.items.len() as u64)?;
    }
    Ok((cells, items, Vec::new()))
}

/// [`recover`] for an encrypted archive (docs/bhive.md §12.10): from the end of the key block,
/// each `BHCE` block's record opened with its nonce and offset, which gives the cell's id,
/// record head and journal; a `BHIE` block skipped by its sealed length.
fn recover_sealed(
    input: &mut Input,
    limits: &Limits,
    unlocked: &Unlocked,
    key_block_len: u64,
    cx: &mut dyn Ctx,
) -> Result<(Vec<Cell>, Items, Vec<[u8; 32]>)> {
    let len = input.len();
    let mut cells: Vec<Cell> = Vec::new();
    let mut ids = Vec::new();
    let mut items = Items::default();
    let mut pos = HEADER_LEN as u64 + key_block_len;
    let mut step = |pos: u64,
                    cells: &mut Vec<Cell>,
                    ids: &mut Vec<[u8; 32]>,
                    items: &mut Items|
     -> Result<Option<u64>> {
        if pos.checked_add(4).is_none_or(|end| end > len) {
            return Ok(None);
        }
        let tag = read_at(input, pos, 4)?;
        if tag == SEALED_INDEX_TAG {
            // An index block in the middle: the file was added to in place.
            if pos + (SEALED_INDEX_HEAD_LEN + FOOTER_LEN) as u64 > len {
                return Ok(None);
            }
            let head = read_at(input, pos, SEALED_INDEX_HEAD_LEN)?;
            let end = pos
                .checked_add((SEALED_INDEX_HEAD_LEN + FOOTER_LEN) as u64)
                .and_then(|n| n.checked_add(u64_of(&head[8..16])));
            return Ok(end.filter(|&end| end <= len));
        }
        if tag != SEALED_CELL_TAG || pos + SEALED_CELL_HEAD_LEN as u64 > len {
            return Ok(None);
        }
        let head = read_at(input, pos, SEALED_CELL_HEAD_LEN)?;
        let r = u64::from(u32::from_le_bytes([head[4], head[5], head[6], head[7]]));
        let c = u64::from(u32::from_le_bytes([head[8], head[9], head[10], head[11]]));
        let cell_at = pos + SEALED_CELL_HEAD_LEN as u64 + r;
        if cell_at.checked_add(c).is_none_or(|end| end > len) {
            return Ok(None);
        }
        memory_limit("a journal", r, limits)?;
        let block = read_at(input, pos, SEALED_CELL_HEAD_LEN + r as usize)?;
        let (id, record_head, stored) = unlocked.open_record(pos, &block)?;
        if record_head[..4] != CELL_TAG {
            return Err(bad("a sealed record without its record head"));
        }
        let (record, sum) = Record::parse(&record_head)?;
        if record.number as usize != cells.len() {
            return Err(bad("a record out of order"));
        }
        if record.journal_stored as usize != stored.len() {
            return Err(bad(
                "a sealed record's journal isn't the length its head says",
            ));
        }
        let cell = record.cell(cell_at);
        cell.check()?;
        memory_limit("a journal", u64::from(record.journal_raw), limits)?;
        if !sums(layout::record_checksum(&record_head, &stored), sum) {
            return Err(bad("a record fails its checksum"));
        }
        let raw = if record.journal_zstd {
            coder::unzstd(&stored, record.journal_raw as usize, "a journal")?
        } else {
            stored
        };
        cells.push(cell);
        let (had_items, had_extents) = (items.items.len(), items.extents.len());
        if let Err(e) = layout::parse_journal(&raw, record.journal_items, cells, items) {
            cells.pop();
            items.items.truncate(had_items);
            items.extents.truncate(had_extents);
            return Err(e);
        }
        ids.push(id);
        Ok(Some(cell_at + c))
    };
    loop {
        cx.check()?;
        match step(pos, &mut cells, &mut ids, &mut items) {
            Ok(Some(next)) => pos = next,
            Ok(None) => break,
            Err(e) if e.kind == ErrorKind::Corrupt => break,
            Err(e) => return Err(e),
        }
        limits.check_entries(items.items.len() as u64)?;
    }
    Ok((cells, items, ids))
}

/// One decoded cell, or what it is on the way to being.
enum Slot {
    /// Asked for ahead of its use, and not yet taken by a helper.
    Wanted,
    Decoding,
    Ready {
        data: Arc<Vec<u8>>,
        used: u64,
    },
    /// It doesn't decode: every file in it fails the same way, without decoding it again.
    Failed(Error),
}

#[derive(Default)]
struct CacheState {
    slots: HashMap<u32, Slot>,
    /// Bytes of the `Ready` cells.
    bytes: u64,
    tick: u64,
    wanted: VecDeque<u32>,
}

/// Decoded cells, shared by every thread that reads the archive: a cell is decoded once however
/// many ask for it at the same time, and kept while the budget has room, the least recently
/// used going first. A cell someone is reading is never dropped, so the budget is a target: the
/// cells in use come on top of it.
pub(super) struct Cache {
    state: Mutex<CacheState>,
    changed: Condvar,
    budget: u64,
}

/// What decoding a cell needs from the thread that does it.
pub(super) struct CellIo<'a> {
    pub input: &'a mut Input,
    pub limits: &'a Limits,
    /// Counts the stored bytes read, for progress.
    pub progress: &'a Counter,
    /// How a cell's bytes in the file become its stored bytes.
    pub crypt: &'a CellCrypt,
}

/// What lies between a cell's bytes in the file and its stored bytes (docs/bhive.md §12.8,
/// §13.2): the segments of an encrypted archive, and the digests of a signed one. Nothing for
/// an archive that has neither.
#[derive(Debug, Default)]
pub(super) struct CellCrypt {
    pub unlocked: Option<Arc<Unlocked>>,
    /// An encrypted archive's cell ids, by number.
    pub ids: Vec<[u8; 32]>,
    /// Section 2, by number, when the archive has it.
    pub digests: Option<Vec<[u8; 32]>>,
}

impl CellCrypt {
    /// The bytes cell `cell` takes in the file.
    pub fn len_in_file(&self, cell: &Cell) -> u64 {
        if self.unlocked.is_some() {
            layout::sealed_len(u64::from(cell.stored))
        } else {
            u64::from(cell.stored)
        }
    }

    /// Cell `n`'s stored bytes from its bytes in the file: each segment opened, then checked
    /// against its digest. The bytes as they are when there is nothing to do.
    pub fn open(&self, n: u32, in_file: Vec<u8>) -> Result<Vec<u8>> {
        let stored = match &self.unlocked {
            Some(u) => {
                let id = self
                    .ids
                    .get(n as usize)
                    .ok_or_else(|| bad(format!("cell {n} has no id")))?;
                u.open_cell(id, &in_file)?
            }
            None => in_file,
        };
        if let Some(digests) = &self.digests {
            let want = digests
                .get(n as usize)
                .ok_or_else(|| bad(format!("cell {n} has no digest")))?;
            if sign::cell_digest(&stored)? != *want {
                return Err(bad(format!(
                    "cell {n} isn't what was signed: it changed after the archive was signed"
                )));
            }
        }
        Ok(stored)
    }
}

impl Cache {
    pub(super) fn new(budget: u64) -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
            changed: Condvar::new(),
            budget,
        }
    }

    /// Reads and decodes cell `n`, checked.
    fn decode(cells: &[Cell], n: u32, io: &mut CellIo<'_>) -> Result<Vec<u8>> {
        let cell = &cells[n as usize];
        memory_limit(&format!("cell {n}"), cell.memory(), io.limits)?;
        let len = io.crypt.len_in_file(cell);
        let in_file = read_at(io.input, cell.offset, len as usize)?;
        io.progress.add(len);
        let stored = io.crypt.open(n, in_file)?;
        coder::decode(cell, n, stored, io.limits)
    }

    /// Drops cells nobody is reading, least recently used first, until `need` more bytes fit.
    fn make_room(st: &mut CacheState, need: u64, budget: u64) {
        while st.bytes + need > budget {
            let victim = st
                .slots
                .iter()
                .filter_map(|(&n, s)| match s {
                    Slot::Ready { data, used } if Arc::strong_count(data) == 1 => Some((*used, n)),
                    _ => None,
                })
                .min();
            let Some((_, n)) = victim else {
                return;
            };
            if let Some(Slot::Ready { data, .. }) = st.slots.remove(&n) {
                st.bytes -= data.len() as u64;
            }
        }
    }

    /// Decodes cell `n`, whose slot the caller has set to `Decoding`, and files the result.
    fn fill(&self, cells: &[Cell], n: u32, io: &mut CellIo<'_>) -> Result<Arc<Vec<u8>>> {
        // A panic in a decoder must not leave the threads waiting for this cell waiting for ever.
        let decoded = catch_unwind(AssertUnwindSafe(|| Self::decode(cells, n, io)))
            .unwrap_or_else(|_| Err(bad(format!("cell {n} doesn't decode"))));
        let mut st = lock(&self.state);
        let result = match decoded {
            Ok(raw) => {
                let data = Arc::new(raw);
                Self::make_room(&mut st, data.len() as u64, self.budget);
                st.bytes += data.len() as u64;
                st.tick += 1;
                let used = st.tick;
                st.slots.insert(
                    n,
                    Slot::Ready {
                        data: data.clone(),
                        used,
                    },
                );
                Ok(data)
            }
            Err(e) => {
                // Damage is the cell's for good; a limit or an I/O error may not come again.
                if e.kind == ErrorKind::Corrupt {
                    st.slots.insert(n, Slot::Failed(e.clone()));
                } else {
                    st.slots.remove(&n);
                }
                Err(e)
            }
        };
        drop(st);
        self.changed.notify_all();
        result
    }

    /// Cell `n`'s raw bytes: from the cache, from whoever is decoding it now, or decoded here.
    pub(super) fn get(&self, cells: &[Cell], n: u32, io: &mut CellIo<'_>) -> Result<Arc<Vec<u8>>> {
        {
            let mut st = lock(&self.state);
            loop {
                st.tick += 1;
                let tick = st.tick;
                match st.slots.get_mut(&n) {
                    Some(Slot::Ready { data, used }) => {
                        *used = tick;
                        return Ok(data.clone());
                    }
                    Some(Slot::Failed(e)) => return Err(e.clone()),
                    Some(Slot::Decoding) => {
                        st = self
                            .changed
                            .wait(st)
                            .unwrap_or_else(PoisonError::into_inner);
                    }
                    Some(Slot::Wanted) | None => {
                        st.slots.insert(n, Slot::Decoding);
                        break;
                    }
                }
            }
        }
        self.fill(cells, n, io)
    }

    /// Drops cells nobody is reading until at most `keep` bytes are left: after a job, an open
    /// archive holds a cell or two, not the job's worth.
    pub(super) fn shrink(&self, keep: u64) {
        let mut st = lock(&self.state);
        st.wanted.clear();
        st.slots.retain(|_, s| !matches!(s, Slot::Wanted));
        Self::make_room(&mut st, 0, keep);
    }

    /// Wakes the threads waiting in [`Cache::help`], to look at whether they are still needed.
    pub(super) fn wake(&self) {
        drop(lock(&self.state));
        self.changed.notify_all();
    }

    /// Asks for cell `n` ahead of its use, when the cache has room for it: a thread with nothing
    /// else to do decodes it ([`Cache::help`]).
    pub(super) fn hint(&self, cells: &[Cell], n: u32) {
        let mut st = lock(&self.state);
        let waiting = st.wanted.len() as u64 * u64::from(cells[n as usize].raw);
        if st.slots.contains_key(&n)
            || st.bytes + waiting + u64::from(cells[n as usize].raw) > self.budget / 2
        {
            return;
        }
        st.slots.insert(n, Slot::Wanted);
        st.wanted.push_back(n);
        drop(st);
        self.changed.notify_all();
    }

    /// Decodes one cell that was asked for ahead, if there is one. Otherwise waits a moment for
    /// one to be asked for, and says there was none.
    pub(super) fn help(&self, cells: &[Cell], io: &mut CellIo<'_>) -> bool {
        let n = {
            let mut st = lock(&self.state);
            loop {
                let Some(n) = st.wanted.pop_front() else {
                    drop(self.changed.wait_timeout(st, POLL));
                    return false;
                };
                // Its reader may have got there first.
                if matches!(st.slots.get(&n), Some(Slot::Wanted)) {
                    st.slots.insert(n, Slot::Decoding);
                    break n;
                }
            }
        };
        let _ = self.fill(cells, n, io);
        true
    }
}

/// A file's bytes: its extents, one after another, each from its cell.
pub(super) struct ExtentReader<'a> {
    cells: &'a [Cell],
    extents: &'a [Extent],
    cache: &'a Cache,
    io: CellIo<'a>,
    /// Counts the stored bytes of the cells this file touches, decoded for it or not: what its
    /// ratio is measured against.
    touched: &'a Counter,
    /// Cells to ask for ahead; 0 asks for none.
    ahead: usize,
    /// Not part of a job ([`ArchiveReader::open_entry`]): the cache is shrunk when it is done.
    alone: bool,
    next: usize,
    hinted: usize,
    cell: Option<(u32, Arc<Vec<u8>>)>,
    at: usize,
    left: usize,
}

impl<'a> ExtentReader<'a> {
    pub(super) fn new(
        cells: &'a [Cell],
        extents: &'a [Extent],
        cache: &'a Cache,
        io: CellIo<'a>,
        touched: &'a Counter,
        ahead: usize,
    ) -> Self {
        Self {
            cells,
            extents,
            cache,
            io,
            touched,
            ahead,
            alone: false,
            next: 0,
            hinted: 0,
            cell: None,
            at: 0,
            left: 0,
        }
    }

    /// A reader that is no job's: when it is dropped, the cache keeps only [`KEEP`].
    fn alone(mut self) -> Self {
        self.alone = true;
        self
    }

    /// Asks for the cells of the extents to come, a few ahead of the one being read.
    fn hint(&mut self) {
        let mut cells = 0;
        let mut last = self.cell.as_ref().map(|(n, _)| *n);
        let mut i = self.next;
        while i < self.extents.len() && cells < self.ahead {
            let n = self.extents[i].cell;
            if Some(n) != last {
                cells += 1;
                last = Some(n);
                if i >= self.hinted {
                    self.cache.hint(self.cells, n);
                }
            }
            i += 1;
        }
        self.hinted = self.hinted.max(i);
    }
}

impl Drop for ExtentReader<'_> {
    fn drop(&mut self) {
        if self.alone {
            self.cell = None;
            self.cache.shrink(KEEP);
        }
    }
}

impl Read for ExtentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.left == 0 {
            let Some(e) = self.extents.get(self.next) else {
                return Ok(0);
            };
            self.next += 1;
            if self.cell.as_ref().map(|(n, _)| *n) != Some(e.cell) {
                // Let go of the last cell before asking for the next: one a reader at a time.
                self.cell = None;
                if self.ahead > 0 {
                    self.hint();
                }
                self.touched
                    .add(u64::from(self.cells[e.cell as usize].stored));
                let data = self
                    .cache
                    .get(self.cells, e.cell, &mut self.io)
                    .map_err(Error::into_io)?;
                self.cell = Some((e.cell, data));
            }
            self.at = e.offset as usize;
            self.left = e.len as usize;
        }
        let Some((_, data)) = &self.cell else {
            return Ok(0);
        };
        let n = buf.len().min(self.left);
        buf[..n].copy_from_slice(&data[self.at..self.at + n]);
        self.at += n;
        self.left -= n;
        Ok(n)
    }
}

/// An open `.bhive`.
pub struct BhiveReader {
    pub(super) source: Source,
    pub(super) cells: Vec<Cell>,
    pub(super) entries: Vec<Entry>,
    /// Each entry's extents: `extents[first..first + count]`.
    pub(super) spans: Vec<(usize, usize)>,
    pub(super) extents: Vec<Extent>,
    level: Option<u8>,
    /// Why the entries come from the records, when they do.
    recovered: Option<String>,
    /// An encrypted archive's keys and cell ids, and a signed one's digests.
    pub(super) crypt: CellCrypt,
    /// The signatures, as the index has them, checked (docs/bhive.md §13).
    signatures: sign::Report,
    /// Section 3 and the manifest, for a rewrite that keeps the contents to carry over.
    carried: Option<sign::Carried>,
    pub(super) cache: Cache,
    input: Option<Input>,
    /// For the reads of [`ArchiveReader::open_entry`].
    touched: Counter,
    /// Each entry's times as its item has them: a system's own time can't hold every one
    /// (Windows keeps 100 ns, and nothing before 1601), and an edit must keep them all.
    pub(super) stamps: Vec<(Option<Stamp>, Option<Stamp>)>,
}

impl BhiveReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let mut input = source.input()?;
        if input.len() < HEADER_LEN as u64 {
            return Err(bad("the file is too short to be a .bhive"));
        }
        let mut head = [0u8; HEADER_LEN];
        head.copy_from_slice(&read_at(&mut input, 0, HEADER_LEN)?);
        let features = layout::check_header(&head)?;
        // An encrypted archive: its key block, and a way in before anything else is read.
        let (unlocked, key_block_len) = if features & layout::FEATURE_ENCRYPTED != 0 {
            input
                .seek(SeekFrom::Start(HEADER_LEN as u64))
                .map_err(|e| read_error(&e))?;
            let block = KeyBlock::read(&head, &mut input)?;
            let unlocked = Unlocked::open(&block, cx)?;
            (Some(Arc::new(unlocked)), block.len() as u64)
        } else {
            (None, 0)
        };
        let (index, recovered, checked) = match read_index(
            &mut input,
            &head,
            &source.limits,
            unlocked.as_deref(),
            key_block_len,
        ) {
            Ok((index, checked)) => (index, None, checked),
            Err(e) if e.kind == ErrorKind::Corrupt && source.recover => {
                let sealed = unlocked.as_deref().map(|u| (u, key_block_len));
                let (cells, items, ids) = recover(&mut input, &source.limits, sealed, cx)?;
                cx.warn(format!(
                    "the archive is incomplete ({}): listing the {} entries its first {} cells hold",
                    e.message,
                    items.items.len(),
                    cells.len()
                ));
                let index = Index {
                    cells,
                    items,
                    ids,
                    ..Index::default()
                };
                (index, Some(e.message), sign::Checked::default())
            }
            Err(e) if e.kind == ErrorKind::Corrupt => {
                return Err(Error::corrupt(format!(
                    "{}: the archive is incomplete or damaged. Opened with `recover`, it lists \
                     what is left of it.",
                    e.message
                )));
            }
            Err(e) => return Err(e),
        };
        let (entries, spans) = entries_of(&index.items, &index.cells);
        let stamps = index
            .items
            .items
            .iter()
            .map(|i| (i.modified, i.created))
            .collect();
        // Half the memory a job's cells may take, within reason: the rest is for the cells
        // being decoded.
        let budget = (mem::budget() / 2).clamp(128 << 20, 2 << 30);
        let crypt = CellCrypt {
            unlocked,
            ids: index.ids,
            digests: checked.report.digests.clone(),
        };
        Ok(Self {
            source,
            cells: index.cells,
            entries,
            spans,
            extents: index.items.extents,
            level: index.level,
            recovered,
            crypt,
            signatures: checked.report,
            carried: checked.carried,
            cache: Cache::new(budget),
            input: Some(input),
            touched: Counter::new(),
            stamps,
        })
    }

    /// The archive's signatures, checked when it was opened (docs/bhive.md §13). Whether to
    /// trust a signer is the caller's question.
    pub fn signatures(&self) -> &sign::Report {
        &self.signatures
    }

    /// Section 3 as it is and the manifest it was made over, when the archive is signed: a
    /// writer that copies the archive keeps them while its contents stay (docs/M14.md §11).
    pub(super) fn carried(&self) -> Option<&sign::Carried> {
        self.carried.as_ref()
    }

    /// Whether the archive is encrypted, and so how it was opened.
    pub fn unlocked(&self) -> Option<&Arc<Unlocked>> {
        self.crypt.unlocked.as_ref()
    }

    /// Why the entries were recovered from the records: the index is missing or damaged.
    pub fn recovered(&self) -> Option<&str> {
        self.recovered.as_deref()
    }

    /// The level the archive was made at, when it says.
    pub fn level(&self) -> Option<super::Level> {
        self.level
            .and_then(|l| super::Level::from_number(i64::from(l)))
    }

    /// The cells, as the index lists them.
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// What `archive.info` says of the archive (docs/M13.md §5): the level it was made at, its
    /// cells, and what storing repeated content once saved.
    fn properties(&self) -> ExternalInfo {
        let property = |name: &str, value: String| LevelProperty {
            level: "bhive".to_owned(),
            name: name.to_owned(),
            value,
        };
        let mut properties = Vec::new();
        if let Some(level) = self.level() {
            properties.push(property("Level", level.name().to_owned()));
        }
        properties.push(property("Cells", self.cells.len().to_string()));
        let largest = self.cells.iter().map(|c| c.raw).max().unwrap_or(0);
        properties.push(property("Cell Size", largest.to_string()));
        // The entries' bytes, and the bytes of the cells they use, each counted once.
        let total = self
            .entries
            .iter()
            .fold(0u64, |n, e| n.saturating_add(e.size.unwrap_or(0)));
        let mut runs: Vec<(u32, u32, u32)> = self
            .extents
            .iter()
            .map(|x| (x.cell, x.offset, x.offset + x.len))
            .collect();
        runs.sort_unstable();
        let mut used = 0u64;
        let mut last: Option<(u32, u32)> = None;
        for (cell, start, end) in runs {
            let from = match last {
                Some((c, e)) if c == cell => start.max(e),
                _ => start,
            };
            used += u64::from(end.saturating_sub(from));
            last = Some((cell, end.max(from)));
        }
        properties.push(property(
            "Stored Once",
            total.saturating_sub(used).to_string(),
        ));
        let notes = match &self.recovered {
            Some(why) => vec![format!(
                "The archive is incomplete ({why}): these are the entries the records before \
                 its cells still list."
            )],
            None => Vec::new(),
        };
        ExternalInfo {
            levels: vec!["bhive".to_owned()],
            properties,
            notes,
        }
    }

    /// Cell `n`'s bytes as they are in the file (sealed, in an encrypted archive), for a writer
    /// that copies the cell as it is.
    pub(super) fn in_file(&mut self, n: usize) -> Result<Vec<u8>> {
        let cell = self.cells[n];
        let len = self.crypt.len_in_file(&cell);
        read_at(self.input()?, cell.offset, len as usize)
    }

    /// Cell `n`'s bytes as they are stored, opened and checked, for a writer that copies the
    /// cell without decoding it.
    pub(super) fn stored(&mut self, n: usize) -> Result<Vec<u8>> {
        let in_file = self.in_file(n)?;
        self.crypt.open(n as u32, in_file)
    }

    /// An encrypted archive's cell ids, by number.
    pub(super) fn cell_ids(&self) -> &[[u8; 32]] {
        &self.crypt.ids
    }

    /// Cell `n`'s raw bytes, decoded and checked.
    pub(super) fn raw(&mut self, n: u32) -> Result<Arc<Vec<u8>>> {
        self.input()?;
        let Some(input) = self.input.as_mut() else {
            return Err(Error::new(ErrorKind::Io, "bhive: no input"));
        };
        let mut io = CellIo {
            input,
            limits: &self.source.limits,
            progress: &self.source.counter,
            crypt: &self.crypt,
        };
        self.cache.get(&self.cells, n, &mut io)
    }

    pub(super) fn extents_of(&self, id: usize) -> &[Extent] {
        let (first, count) = self.spans[id];
        &self.extents[first..first + count]
    }

    /// Refuses a job whose files are more than `max_ratio` times the archive's size. Extents may
    /// share bytes, so a small archive can describe a very large tree; a file's own ratio is
    /// measured against the cells it touches, and this bounds all of them together.
    pub(super) fn check_expansion(&self, total: u64) -> Result<()> {
        let limits = &self.source.limits;
        match limits.max_ratio {
            Some(max) if total > limits.ratio_grace && total / self.source.size.max(1) > max => {
                Err(Error::limit(format!(
                    "the archive's files are {total} bytes, more than {max} times its own {} (limit `max_ratio`)",
                    self.source.size
                )))
            }
            _ => Ok(()),
        }
    }

    /// How many threads decode cells at once: as the settings say, but no more than the memory
    /// the largest cell takes allows.
    pub(super) fn threads(&self) -> usize {
        let threads = resolve_threads(self.source.threads) as usize;
        let largest = self
            .cells
            .iter()
            .map(Cell::memory)
            .max()
            .unwrap_or(0)
            .max(1);
        let fit = usize::try_from(mem::budget() / largest).unwrap_or(usize::MAX);
        threads.min(fit).max(1)
    }

    fn input(&mut self) -> Result<&mut Input> {
        if self.input.is_none() {
            self.input = Some(self.source.input()?);
        }
        self.input
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Io, "bhive: no input"))
    }

    /// Decodes every cell on `threads` threads and says which fail. Nothing is kept.
    fn test_cells(&mut self, cx: &mut dyn Ctx) -> Result<Vec<Option<Error>>> {
        let threads = self.threads().min(self.cells.len()).max(1);
        let progress = Counter::new();
        let meter = Meter::new(progress.clone(), Some(self.source.size));
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let failure: Mutex<Option<Error>> = Mutex::new(None);
        let results: Mutex<Vec<Option<Error>>> = Mutex::new(vec![None; self.cells.len()]);
        // The job's thread waits here between looks; a worker that finishes a cell wakes it.
        let tick = (Mutex::new(()), Condvar::new());
        let (source, cells, crypt) = (&self.source, &self.cells[..], &self.crypt);
        let work = || -> Result<()> {
            let mut input = source.input()?;
            loop {
                let n = next.fetch_add(1, Ordering::Relaxed);
                if n >= cells.len() || stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let mut io = CellIo {
                    input: &mut input,
                    limits: &source.limits,
                    progress: &progress,
                    crypt,
                };
                match Cache::decode(cells, n as u32, &mut io) {
                    Ok(raw) => source.budget.add(raw.len() as u64)?,
                    Err(e) if e.kind == ErrorKind::Corrupt => lock(&results)[n] = Some(e),
                    Err(e) => return Err(e),
                }
                done.fetch_add(1, Ordering::Relaxed);
                drop(lock(&tick.0));
                tick.1.notify_all();
            }
        };
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    if let Err(e) = work() {
                        lock(&failure).get_or_insert(e);
                        stop.store(true, Ordering::Relaxed);
                        drop(lock(&tick.0));
                        tick.1.notify_all();
                    }
                });
            }
            while done.load(Ordering::Relaxed) < cells.len() && !stop.load(Ordering::Relaxed) {
                if cx.is_cancelled() {
                    stop.store(true, Ordering::Relaxed);
                }
                cx.progress(&meter.snapshot());
                let waiting = lock(&tick.0);
                if done.load(Ordering::Relaxed) < cells.len() && !stop.load(Ordering::Relaxed) {
                    drop(tick.1.wait_timeout(waiting, POLL));
                }
            }
        });
        if let Some(e) = failure.into_inner().unwrap_or_else(PoisonError::into_inner) {
            return Err(e);
        }
        cx.check()?;
        Ok(results.into_inner().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The entries of `items`, and each one's span of the extents.
fn entries_of(items: &Items, cells: &[Cell]) -> (Vec<Entry>, Vec<(usize, usize)>) {
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let time = |t: Option<(i64, u32)>| t.and_then(|(secs, nanos)| from_unix(secs, nanos));
    let mut entries = Vec::with_capacity(items.items.len());
    let mut spans = Vec::with_capacity(items.items.len());
    for (id, item) in items.items.iter().enumerate() {
        let kind = match item.kind {
            Kind::File => EntryKind::File,
            Kind::Folder => EntryKind::Dir,
            Kind::Link => EntryKind::Symlink {
                target: text(&item.target),
            },
        };
        let mut e = Entry::new(id, text(&item.path), kind);
        e.raw_path = item.path.clone();
        e.modified = time(item.modified);
        e.created = time(item.created);
        e.unix_mode = item.mode;
        e.dos_attrs = item.attrs;
        if item.kind == Kind::File {
            e.size = Some(item.size);
            // What its first bytes are stored with; the rest of a file is usually the same.
            e.method = items
                .extents_of(item)
                .first()
                .map(|x| Cow::Borrowed(cells[x.cell as usize].coder.name()));
        }
        entries.push(e);
        spans.push((item.first, item.count));
    }
    (entries, spans)
}

impl ArchiveReader for BhiveReader {
    fn format(&self) -> FormatId {
        FormatId::Bhive
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        // An encrypted archive seals everything, its names too (docs/bhive.md §12).
        let sealed = self.crypt.unlocked.is_some();
        let methods = [Coder::Stored, Coder::Zstd, Coder::Lzma2]
            .into_iter()
            .filter(|c| {
                self.cells
                    .iter()
                    .any(|cell| cell.coder == *c && cell.raw > 0)
            })
            .map(|c| Cow::Borrowed(c.name()))
            .collect();
        Ok(ArchiveInfo {
            format: FormatId::Bhive,
            codecs: Vec::new(),
            methods,
            comment: None,
            encryption: if sealed {
                Encryption::All
            } else {
                Encryption::None
            },
            solid: false,
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: sealed,
            locked: false,
            recovery_record: false,
            external: Some(self.properties()),
        })
    }

    /// To disk, on every core when there is enough to do (`par.rs`). Otherwise in archive order
    /// on the job's thread. A file with bytes in a damaged cell fails, the rest are extracted,
    /// and the job then fails as `Corrupt`.
    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let selected: Vec<usize> = (0..self.entries.len())
            .filter(|&id| sel.matches(&self.entries[id]))
            .collect();
        let total = selected.iter().fold(0u64, |n, &id| {
            n.saturating_add(self.entries[id].size.unwrap_or(0))
        });
        self.check_expansion(total)?;
        if let Some(fs) = sink.as_fs_sink() {
            let workers = par::workers(self, &selected);
            if workers > 1 {
                return par::extract(self, &selected, fs, cx, workers);
            }
        }

        let progress = Counter::new();
        let mut meter = Meter::new(progress.clone(), Some(self.source.size));
        meter.entries_total = Some(selected.len() as u64);
        let mut failed: Option<Error> = None;
        let mut failures = 0u64;
        self.input()?;
        for (done, &id) in selected.iter().enumerate() {
            cx.check()?;
            meter.entries_done = done as u64;
            meter.current = Some(self.entries[id].path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            let entry = &self.entries[id];
            let touched = Counter::new();
            let Some(input) = self.input.as_mut() else {
                return Err(Error::new(ErrorKind::Io, "bhive: no input"));
            };
            let (first, count) = self.spans[id];
            let reader = ExtentReader::new(
                &self.cells,
                &self.extents[first..first + count],
                &self.cache,
                CellIo {
                    input,
                    limits: &self.source.limits,
                    progress: &progress,
                    crypt: &self.crypt,
                },
                &touched,
                0,
            );
            let mut data = Guarded::new(
                reader,
                RatioGuard::new(&touched, &self.source.limits),
                self.source.budget.clone(),
            );
            match sink.entry(entry, &mut data, &mut mcx) {
                Ok(()) => {}
                Err(e) if e.kind == ErrorKind::Corrupt && entry.kind == EntryKind::File => {
                    failures += 1;
                    mcx.warn(format!("`{}` can't be read: {}", entry.path, e.message));
                    failed.get_or_insert(e);
                }
                Err(e) => return Err(e),
            }
        }
        self.cache.shrink(KEEP);
        meter.entries_done = selected.len() as u64;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        match failed {
            None => Ok(()),
            Some(e) => Err(damaged(failures, &e)),
        }
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        if id >= self.entries.len() {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        }
        self.check_expansion(self.entries[id].size.unwrap_or(0))?;
        self.input()?;
        self.touched.set(0);
        let Some(input) = self.input.as_mut() else {
            return Err(Error::new(ErrorKind::Io, "bhive: no input"));
        };
        let (first, count) = self.spans[id];
        let reader = ExtentReader::new(
            &self.cells,
            &self.extents[first..first + count],
            &self.cache,
            CellIo {
                input,
                limits: &self.source.limits,
                progress: &self.source.counter,
                crypt: &self.crypt,
            },
            &self.touched,
            0,
        )
        .alone();
        Ok(Box::new(Guarded::new(
            reader,
            RatioGuard::new(&self.touched, &self.source.limits),
            self.source.budget.clone(),
        )))
    }

    /// Every cell decoded once and checked, on every core; a file fails with the first of its
    /// cells that does. An archive listed from its records fails as a whole too: its index is
    /// missing.
    fn test(&mut self, cx: &mut dyn Ctx) -> Option<Result<TestReport>> {
        let cells = match self.test_cells(cx) {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };
        let mut report = TestReport::default();
        if let Some(why) = &self.recovered {
            report.record(
                "",
                &Error::corrupt(format!("{why}: the archive is incomplete")),
            );
        }
        for (id, entry) in self.entries.iter().enumerate() {
            report.entries += 1;
            report.bytes = report.bytes.saturating_add(entry.size.unwrap_or(0));
            let bad = self
                .extents_of(id)
                .iter()
                .find_map(|x| cells[x.cell as usize].as_ref());
            if let Some(e) = bad {
                report.record(&entry.path, e);
            }
        }
        // A damaged cell no file uses is damage all the same.
        for (n, e) in cells.iter().enumerate() {
            if let Some(e) = e
                && !self.extents.iter().any(|x| x.cell as usize == n)
            {
                report.record("", e);
            }
        }
        Some(Ok(report))
    }
}

/// The error of a job that left files out for damaged cells.
pub(super) fn damaged(files: u64, first: &Error) -> Error {
    let files = match files {
        1 => "1 file".to_owned(),
        n => format!("{n} files"),
    };
    Error::corrupt(format!(
        "{files} couldn't be read, the rest were: {}",
        first.message
    ))
}
