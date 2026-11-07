//! Multithreaded xz decoding (docs/M6.md §6.4), on lzma-rust2's public `Lzma2Reader`.
//!
//! - **The scan** reads each stream's footer and index and each block's header from the end,
//!   as `xz --list` does, every CRC checked, and takes each block's LZMA2 dictionary.
//! - **The reader thread** reads the blocks in order, while fewer than `DEPTH` per worker
//!   are in flight, and runs the workers as scoped threads.
//! - **The workers** decode whole blocks and verify each one's check and sizes.
//! - **The job thread** hands the blocks out in order, and counts the input as it does, so
//!   progress and the ratio limit see what has been handed out.
//!
//! A file it doesn't take is decoded on one thread by `XzReader`, which also reports what is
//! wrong with it. lzma-rust2's `XzReaderMt` isn't used: it takes no memory limit and doesn't
//! verify block checks.

use std::{
    any::Any,
    collections::{BTreeMap, VecDeque},
    io::{self, Read, Seek, SeekFrom},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

use lzma_rust2::{Lzma2Reader, lzma2_get_memory_usage};
use sha2::Digest;

use super::{resolve_threads, xz::MAGIC};
use crate::{
    Error, Limits,
    io::{Counter, LatchReader},
};

/// Blocks in flight per worker: read, being decoded, decoded, or being handed out.
const DEPTH: usize = 2;
/// The scan reads every block's header and keeps a row for each; a file with more blocks is
/// decoded on one thread.
const MAX_BLOCKS: u64 = 1 << 20;
/// A worker looks at the stop flag after each step.
const STEP: usize = 64 * 1024;
/// The LZMA2 filter id.
const LZMA2: u64 = 0x21;

/// A decoder for the xz file `input` on up to `threads` workers (`0` is one per core), or
/// `None` when it is decoded on one thread instead: fewer than two blocks, filters other than
/// LZMA2 alone (BCJ), an index or a block header that doesn't read, or a `decoder_memory` too
/// small for two workers. `counter` starts again at zero and reaches the file's size once
/// everything has been read.
pub fn decoder<R>(
    mut input: R,
    limits: &Limits,
    threads: u32,
    counter: &Counter,
) -> Option<Box<dyn Read + Send>>
where
    R: Read + Seek + Send + 'static,
{
    let reader = XzMtReader::new(&mut input, limits, threads, counter)?.start(input)?;
    Some(Box::new(LatchReader::new(reader)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    None,
    Crc32,
    Crc64,
    Sha256,
}

impl Check {
    /// The check types XZ Utils writes. The others are reserved: those files go to `XzReader`.
    fn from_id(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Crc32),
            0x04 => Some(Self::Crc64),
            0x0A => Some(Self::Sha256),
            _ => None,
        }
    }

    fn len(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Crc32 => 4,
            Self::Crc64 => 8,
            Self::Sha256 => 32,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::None => "no",
            Self::Crc32 => "CRC-32",
            Self::Crc64 => "CRC-64",
            Self::Sha256 => "SHA-256",
        }
    }
}

/// One block, as the index and its header give it.
#[derive(Debug, Clone)]
struct Block {
    /// Where its header starts in the file.
    start: u64,
    /// The header's size.
    header: u64,
    /// The header, the compressed data and the check: the block without its padding.
    unpadded: u64,
    uncompressed: u64,
    /// The LZMA2 dictionary.
    dict: u32,
    check: Check,
}

impl Block {
    /// The block with its padding, as it is in the file.
    fn padded(&self) -> u64 {
        self.unpadded.next_multiple_of(4)
    }

    fn end(&self) -> u64 {
        self.start + self.padded()
    }
}

/// Every block of every stream, first to last.
#[derive(Debug)]
struct Scan {
    blocks: Vec<Block>,
    /// The file's size.
    len: u64,
    /// The largest dictionary.
    dict: u32,
    /// The largest block, packed and unpacked.
    block: u64,
}

/// Reads `buf.len()` bytes at `at`.
fn read_at<R: Read + Seek>(r: &mut R, at: u64, buf: &mut [u8]) -> Option<()> {
    r.seek(SeekFrom::Start(at)).ok()?;
    r.read_exact(buf).ok()
}

/// An xz multibyte integer: at most nine bytes, seven bits each.
fn varint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let byte = *b.get(*at)?;
        *at += 1;
        v |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The dictionary an LZMA2 property byte gives.
fn dict_size(prop: u8) -> Option<u32> {
    match prop {
        0..=39 => Some((2 | u32::from(prop & 1)) << (prop / 2 + 11)),
        40 => Some(u32::MAX),
        _ => None,
    }
}

/// Every stream, read from the end of the file backwards. `None` if anything doesn't read
/// or a block uses a filter other than LZMA2 alone.
fn scan<R: Read + Seek>(r: &mut R) -> Option<Scan> {
    let len = r.seek(SeekFrom::End(0)).ok()?;
    // Last block first, until the end.
    let mut blocks = Vec::new();
    // Blocks, and streams without any, so a file of empty streams has a limit too.
    let mut rows = 0;
    let mut end = len;
    loop {
        end = skip_padding(r, end)?;
        let (start, stream) = scan_stream(r, end, MAX_BLOCKS.checked_sub(rows)?)?;
        rows += (stream.len() as u64).max(1);
        blocks.extend(stream.into_iter().rev());
        // The first stream starts the file: padding before it isn't allowed.
        if start == 0 {
            break;
        }
        end = start;
    }
    blocks.reverse();
    let dict = blocks.iter().map(|b| b.dict).max().unwrap_or(0);
    let block = blocks
        .iter()
        .map(|b| b.padded().saturating_add(b.uncompressed))
        .max()
        .unwrap_or(0);
    Some(Scan {
        blocks,
        len,
        dict,
        block,
    })
}

/// Moves `end` back over stream padding: zero bytes, four at a time.
fn skip_padding<R: Read + Seek>(r: &mut R, mut end: u64) -> Option<u64> {
    let mut buf = [0u8; 4096];
    loop {
        let n = end.min(buf.len() as u64) / 4 * 4;
        if n == 0 {
            return Some(end);
        }
        let chunk = &mut buf[..n as usize];
        read_at(r, end - n, chunk)?;
        let zeros = chunk
            .rchunks_exact(4)
            .take_while(|w| w.iter().all(|&b| b == 0))
            .count() as u64
            * 4;
        end -= zeros;
        if zeros < n {
            return Some(end);
        }
    }
}

/// The stream that ends at `end`, with at most `room` blocks: where it starts, and its blocks.
fn scan_stream<R: Read + Seek>(r: &mut R, end: u64, room: u64) -> Option<(u64, Vec<Block>)> {
    // The header, the smallest index and the footer.
    if end < 32 {
        return None;
    }
    let mut footer = [0u8; 12];
    read_at(r, end - 12, &mut footer)?;
    if footer[10..] != *b"YZ" || crc32fast::hash(&footer[4..10]).to_le_bytes() != footer[..4] {
        return None;
    }
    let flags = [footer[8], footer[9]];
    if flags[0] != 0 || flags[1] & 0xF0 != 0 {
        return None;
    }
    let check = Check::from_id(flags[1])?;
    let backward = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
    let index_size = (u64::from(backward) + 1) * 4;
    // An index is at least the indicator, the count, padding and its CRC: 8 bytes. Each
    // record is two integers of at most nine bytes.
    if index_size < 8 || index_size > 16 + room * 18 {
        return None;
    }
    let index_start = (end - 12).checked_sub(index_size).filter(|&s| s >= 12)?;
    let mut index = vec![0u8; usize::try_from(index_size).ok()?];
    read_at(r, index_start, &mut index)?;
    let (body, crc) = index.split_at(index.len() - 4);
    if body[0] != 0 || crc32fast::hash(body).to_le_bytes() != crc {
        return None;
    }
    let mut at = 1;
    let records = varint(body, &mut at)?;
    // Each record takes at least two bytes.
    if records > room || records > body.len() as u64 / 2 {
        return None;
    }
    let mut sizes = Vec::with_capacity(usize::try_from(records).ok()?);
    let mut blocks_size = 0u64;
    for _ in 0..records {
        let unpadded = varint(body, &mut at)?;
        let uncompressed = varint(body, &mut at)?;
        if unpadded == 0 {
            return None;
        }
        blocks_size = blocks_size.checked_add(unpadded.next_multiple_of(4))?;
        sizes.push((unpadded, uncompressed));
    }
    // Zero padding to a multiple of four, then the CRC.
    if at.next_multiple_of(4) != body.len() || body[at..].iter().any(|&b| b != 0) {
        return None;
    }
    let start = index_start.checked_sub(blocks_size)?.checked_sub(12)?;
    let mut header = [0u8; 12];
    read_at(r, start, &mut header)?;
    if header[..6] != MAGIC
        || header[6..8] != flags
        || crc32fast::hash(&header[6..8]).to_le_bytes() != header[8..]
    {
        return None;
    }
    let mut pos = start + 12;
    let mut blocks = Vec::with_capacity(sizes.len());
    for (unpadded, uncompressed) in sizes {
        let block = block_header(r, pos, unpadded, uncompressed, check)?;
        pos = block.end();
        blocks.push(block);
    }
    Some((start, blocks))
}

/// The block whose header is at `pos`: one LZMA2 filter, and sizes, where the header has
/// them, that match the index's.
fn block_header<R: Read + Seek>(
    r: &mut R,
    pos: u64,
    unpadded: u64,
    uncompressed: u64,
    check: Check,
) -> Option<Block> {
    let mut first = [0u8; 1];
    read_at(r, pos, &mut first)?;
    // Zero is the index indicator, not a header.
    if first[0] == 0 {
        return None;
    }
    let size = (usize::from(first[0]) + 1) * 4;
    let mut buf = [0u8; 1024];
    let h = &mut buf[..size];
    read_at(r, pos, h)?;
    let (body, crc) = h.split_at(size - 4);
    if crc32fast::hash(body).to_le_bytes() != crc {
        return None;
    }
    let header = size as u64;
    // At least one byte of LZMA2: its end marker.
    let compressed = unpadded
        .checked_sub(header + check.len())
        .filter(|&c| c > 0)?;
    let flags = body[1];
    // Reserved bits, or more than one filter.
    if flags & 0x3F != 0 {
        return None;
    }
    let mut at = 2;
    if flags & 0x40 != 0 && varint(body, &mut at)? != compressed {
        return None;
    }
    if flags & 0x80 != 0 && varint(body, &mut at)? != uncompressed {
        return None;
    }
    if varint(body, &mut at)? != LZMA2 || varint(body, &mut at)? != 1 {
        return None;
    }
    let dict = dict_size(*body.get(at)?)?;
    // Zero padding up to the CRC.
    if body[at + 1..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(Block {
        start: pos,
        header,
        unpadded,
        uncompressed,
        dict,
        check,
    })
}

/// What decoding on `workers` workers can hold at once: each worker's LZMA2 decoder for the
/// largest dictionary, the largest block packed and unpacked for each block in flight, and
/// the scan's rows.
fn bound(scan: &Scan, workers: usize) -> u64 {
    let n = scan.blocks.len();
    let decoder = u64::from(lzma2_get_memory_usage(scan.dict)) * 1024;
    let window = (DEPTH * workers).min(n) as u64;
    let rows = (n * size_of::<Block>()) as u64;
    decoder
        .saturating_mul(workers as u64)
        .saturating_add(window.saturating_mul(scan.block))
        .saturating_add(rows)
}

/// The most workers, two at least and at most `threads` (and one per block), whose
/// [`bound`] fits `decoder_memory`.
fn workers(scan: &Scan, limits: &Limits, threads: u32) -> Option<usize> {
    let most = usize::try_from(resolve_threads(threads))
        .unwrap_or(usize::MAX)
        .min(scan.blocks.len());
    (2..=most)
        .rev()
        .find(|&w| bound(scan, w) <= limits.decoder_memory)
}

/// CRC-64/XZ, eight bytes at a time. lzma-rust2's is private, and goes a byte at a time.
static CRC64: [[u64; 256]; 8] = crc64_tables();

const fn crc64_tables() -> [[u64; 256]; 8] {
    let mut t = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xC96C_5795_D787_0F42
            } else {
                c >> 1
            };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

/// Adds `data` to a CRC-64 register (`!0` to start; the CRC is its complement).
fn crc64(mut crc: u64, data: &[u8]) -> u64 {
    let (words, rest) = data.as_chunks::<8>();
    for &w in words {
        let v = crc ^ u64::from_le_bytes(w);
        let byte = |k: u32| ((v >> (8 * k)) & 0xFF) as usize;
        crc = CRC64[7][byte(0)]
            ^ CRC64[6][byte(1)]
            ^ CRC64[5][byte(2)]
            ^ CRC64[4][byte(3)]
            ^ CRC64[3][byte(4)]
            ^ CRC64[2][byte(5)]
            ^ CRC64[1][byte(6)]
            ^ CRC64[0][byte(7)];
    }
    for &b in rest {
        crc = CRC64[0][((crc ^ u64::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// A block's check, as its data is decoded.
enum Hasher {
    None,
    Crc32(crc32fast::Hasher),
    Crc64(u64),
    Sha256(sha2::Sha256),
}

impl Hasher {
    fn new(check: Check) -> Self {
        match check {
            Check::None => Self::None,
            Check::Crc32 => Self::Crc32(crc32fast::Hasher::new()),
            Check::Crc64 => Self::Crc64(!0),
            Check::Sha256 => Self::Sha256(sha2::Sha256::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::None => {}
            Self::Crc32(h) => h.update(data),
            Self::Crc64(c) => *c = crc64(*c, data),
            Self::Sha256(h) => h.update(data),
        }
    }

    fn matches(self, stored: &[u8]) -> bool {
        match self {
            Self::None => true,
            Self::Crc32(h) => h.finalize().to_le_bytes()[..] == *stored,
            Self::Crc64(c) => (!c).to_le_bytes()[..] == *stored,
            Self::Sha256(h) => h.finalize()[..] == *stored,
        }
    }
}

/// Decodes block `i` (`packed` is all of it, padding included) into `out`, whose memory is
/// reused. Stops early when `stop` is set.
fn decode(
    i: usize,
    b: &Block,
    packed: &[u8],
    mut out: Vec<u8>,
    stop: &AtomicBool,
) -> io::Result<Vec<u8>> {
    let n = i + 1;
    let corrupt = |what: String| Error::corrupt(format!("xz: block {n} {what}")).into_io();
    let failed = |e: io::Error| {
        crate::io::read_error(&e)
            .context(format!("xz: block {n}"))
            .into_io()
    };
    // The scan checked that the header and check fit in the block, with data between them.
    let (body, check) = packed.split_at(packed.len() - b.check.len() as usize);
    let (header, data_end) = (b.header as usize, (b.unpadded - b.check.len()) as usize);
    if body[data_end..].iter().any(|&x| x != 0) {
        return Err(corrupt("has padding that isn't zero".into()));
    }
    let mut lzma = Lzma2Reader::new(&body[header..data_end], b.dict, None);
    let mut hash = Hasher::new(b.check);
    let want = b.uncompressed as usize;
    out.clear();
    out.try_reserve_exact(want).map_err(|_| out_of_memory(n))?;
    while out.len() < want {
        if stop.load(Ordering::Relaxed) {
            return Err(Error::cancelled().into_io());
        }
        let at = out.len();
        out.resize(at + STEP.min(want - at), 0);
        let got = lzma.read(&mut out[at..]).map_err(failed)?;
        out.truncate(at + got);
        if got == 0 {
            return Err(corrupt("decodes to fewer bytes than the index says".into()));
        }
        hash.update(&out[at..]);
    }
    if lzma.read(&mut [0u8; 1]).map_err(failed)? != 0 {
        return Err(corrupt("decodes to more bytes than the index says".into()));
    }
    if !lzma.into_inner().is_empty() {
        return Err(corrupt("is shorter than the index says".into()));
    }
    if !hash.matches(check) {
        return Err(corrupt(format!("fails its {} check", b.check.name())));
    }
    Ok(out)
}

/// The blocks fit `decoder_memory`, which can be set past what the system has.
fn out_of_memory(n: usize) -> io::Error {
    Error::limit(format!("xz: block {n} doesn't fit in memory")).into_io()
}

/// A block's outcome, waiting for the job thread.
enum Done {
    Data(Vec<u8>),
    Failed(io::Error),
    /// The decoder panicked: the job thread panics with it, as it would decoding on one thread.
    Panicked(Box<dyn Any + Send>),
}

#[derive(Default)]
struct State {
    /// Blocks read and not yet taken by a worker.
    packed: VecDeque<(usize, Vec<u8>)>,
    /// Decoded blocks and failures, by block.
    done: BTreeMap<usize, Done>,
    /// The blocks before this one are handed out: blocks from here to `DEPTH` per worker on
    /// may be in flight.
    released: usize,
    /// A block failed: nothing more is read.
    failed: bool,
    /// The reader thread has read everything it will.
    read_all: bool,
    /// Every thread has finished.
    finished: bool,
    /// Buffers of blocks that are done with, for the next ones: fresh ones would be faulted in
    /// page by page for every block.
    spare_packed: Vec<Vec<u8>>,
    spare_unpacked: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    /// The reader thread waits here for room in the window.
    room: Condvar,
    /// Workers wait here for blocks to decode.
    work: Condvar,
    /// The job thread waits here for the next block.
    ready: Condvar,
    /// The job thread is gone, or a block failed and has been handed out.
    stop: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, cv: &Condvar, st: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        cv.wait(st).unwrap_or_else(PoisonError::into_inner)
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Stops every thread: workers within a step, the reader thread before its next block.
    fn halt(&self) {
        self.stop.store(true, Ordering::Relaxed);
        // Under the lock, so a thread that has just found nothing to do is already waiting.
        let _st = self.lock();
        self.room.notify_all();
        self.work.notify_all();
        self.ready.notify_all();
    }
}

/// Marks the threads finished when the reader thread ends, however it ends.
struct Finish<'a>(&'a Shared);

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        self.0.lock().finished = true;
        self.0.ready.notify_all();
    }
}

/// The reader thread: starts the workers, then reads the blocks in order while there is room.
fn run<R: Read + Seek>(shared: &Shared, scan: &Scan, mut input: R, workers: usize, window: usize) {
    let _finish = Finish(shared);
    std::thread::scope(|s| {
        for k in 0..workers {
            let spawned = std::thread::Builder::new()
                .name(format!("beezip-xz-{k}"))
                .spawn_scoped(s, move || work(shared, scan));
            if let Err(e) = spawned {
                if k > 0 {
                    break;
                }
                let e = Error::io("starting the xz decoder", &e).into_io();
                shared.lock().done.insert(0, Done::Failed(e));
                return;
            }
        }
        read_blocks(shared, scan, &mut input, window);
    });
}

fn read_blocks<R: Read + Seek>(shared: &Shared, scan: &Scan, input: &mut R, window: usize) {
    for (i, b) in scan.blocks.iter().enumerate() {
        let mut buf = {
            let mut st = shared.lock();
            while !st.failed && !shared.stopped() && i >= st.released + window {
                st = shared.wait(&shared.room, st);
            }
            if st.failed || shared.stopped() {
                break;
            }
            st.spare_packed.pop().unwrap_or_default()
        };
        let len = b.padded() as usize;
        buf.clear();
        let read = match buf.try_reserve_exact(len) {
            Ok(()) => {
                buf.resize(len, 0);
                input
                    .seek(SeekFrom::Start(b.start))
                    .and_then(|_| input.read_exact(&mut buf))
                    .map_err(|e| Error::io(format!("reading xz block {}", i + 1), &e).into_io())
            }
            Err(_) => Err(out_of_memory(i + 1)),
        };
        let mut st = shared.lock();
        match read {
            Ok(()) => {
                st.packed.push_back((i, buf));
                shared.work.notify_one();
            }
            Err(e) => {
                st.done.insert(i, Done::Failed(e));
                st.failed = true;
                shared.ready.notify_all();
                break;
            }
        }
    }
    shared.lock().read_all = true;
    shared.work.notify_all();
}

/// A worker: decodes blocks until there are no more, or it's told to stop.
fn work(shared: &Shared, scan: &Scan) {
    loop {
        let (i, packed, out) = {
            let mut st = shared.lock();
            loop {
                if shared.stopped() {
                    return;
                }
                if let Some((i, packed)) = st.packed.pop_front() {
                    break (i, packed, st.spare_unpacked.pop().unwrap_or_default());
                }
                if st.read_all {
                    return;
                }
                st = shared.wait(&shared.work, st);
            }
        };
        let block = &scan.blocks[i];
        let decoded = catch_unwind(AssertUnwindSafe(|| {
            decode(i, block, &packed, out, &shared.stop)
        }));
        let done = match decoded {
            Ok(Ok(data)) => Done::Data(data),
            Ok(Err(e)) => Done::Failed(e),
            Err(panic) => Done::Panicked(panic),
        };
        let mut st = shared.lock();
        if !matches!(done, Done::Data(_)) {
            st.failed = true;
            shared.room.notify_all();
        }
        st.spare_packed.push(packed);
        st.done.insert(i, done);
        shared.ready.notify_all();
    }
}

/// The job thread's end: hands the blocks out in order.
struct XzMtReader {
    shared: Arc<Shared>,
    scan: Arc<Scan>,
    workers: usize,
    /// The next block to hand out.
    next: usize,
    /// The block being handed out.
    cur: Vec<u8>,
    pos: usize,
    counter: Counter,
    /// The end of the file after the last block (its index and footer) has been counted.
    counted_tail: bool,
    thread: Option<JoinHandle<()>>,
}

impl XzMtReader {
    /// Scans `input` and picks the workers; `None` when one thread should decode it.
    fn new<R: Read + Seek>(
        input: &mut R,
        limits: &Limits,
        threads: u32,
        counter: &Counter,
    ) -> Option<Self> {
        let scan = scan(input)?;
        let workers = workers(&scan, limits, threads)?;
        Some(Self {
            shared: Arc::default(),
            scan: Arc::new(scan),
            workers,
            next: 0,
            cur: Vec::new(),
            pos: 0,
            counter: counter.clone(),
            counted_tail: false,
            thread: None,
        })
    }

    /// Starts the reader thread on `input`.
    fn start<R: Read + Seek + Send + 'static>(mut self, input: R) -> Option<Self> {
        let (shared, scan) = (Arc::clone(&self.shared), Arc::clone(&self.scan));
        let workers = self.workers;
        let window = (DEPTH * workers).min(scan.blocks.len());
        let thread = std::thread::Builder::new()
            .name("beezip-xz".into())
            .spawn(move || run(&shared, &scan, input, workers, window))
            .ok()?;
        self.thread = Some(thread);
        self.counter.set(0);
        Some(self)
    }

    /// Lets go of the block handed out, and waits for the next.
    fn take_next(&mut self) -> io::Result<()> {
        let i = self.next;
        let old = std::mem::take(&mut self.cur);
        self.pos = 0;
        let mut st = self.shared.lock();
        if old.capacity() > 0 {
            st.spare_unpacked.push(old);
        }
        st.released = i;
        self.shared.room.notify_all();
        let done = loop {
            if let Some(done) = st.done.remove(&i) {
                break Some(done);
            }
            if st.finished {
                break None;
            }
            st = self.shared.wait(&self.shared.ready, st);
        };
        drop(st);
        match done {
            Some(Done::Data(data)) => {
                let blocks = &self.scan.blocks;
                let from = i.checked_sub(1).map_or(0, |p| blocks[p].end());
                self.counter.add(blocks[i].end() - from);
                self.cur = data;
                self.next += 1;
                Ok(())
            }
            Some(Done::Failed(e)) => {
                self.shared.halt();
                Err(e)
            }
            Some(Done::Panicked(panic)) => {
                self.shared.halt();
                resume_unwind(panic)
            }
            None => Err(Error::corrupt("xz: the decoder stopped early").into_io()),
        }
    }
}

impl Read for XzMtReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos == self.cur.len() {
            if self.next == self.scan.blocks.len() {
                if !self.counted_tail {
                    self.counted_tail = true;
                    let last = self.scan.blocks.last().map_or(0, Block::end);
                    self.counter.add(self.scan.len - last);
                }
                return Ok(0);
            }
            self.take_next()?;
        }
        let n = buf.len().min(self.cur.len() - self.pos);
        buf[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Drop for XzMtReader {
    /// Stops the threads and waits for them, so nothing goes on decoding after a cancel.
    fn drop(&mut self) {
        self.shared.halt();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Write},
        path::{Path, PathBuf},
        time::Instant,
    };

    use super::*;
    use crate::{CodecId, EncodeOpts, ErrorKind, OpenOptions, source::Source};

    fn fixture(name: &str) -> Vec<u8> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty/xz");
        std::fs::read(dir.join(name)).unwrap()
    }

    /// xorshift64*, enough for test data.
    fn data(len: usize, seed: u64) -> Vec<u8> {
        const WORDS: [&str; 8] = ["bee", "zip ", "hive\n", "honey ", "é", "wax ", "the ", "a "];
        let mut s = seed | 1;
        let mut next = move || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            // Text, with a random byte now and then so blocks compress unevenly.
            match next() % 16 {
                0 => out.push((next() >> 24) as u8),
                k => out.extend_from_slice(WORDS[(k % 8) as usize].as_bytes()),
            }
        }
        out.truncate(len);
        out
    }

    /// BeeZip's own threaded writer, with `block` bytes a block.
    fn encode_mt(data: &[u8], level: i32, block: u64) -> Vec<u8> {
        let opts = EncodeOpts {
            level: Some(level),
            threads: 4,
            block_size: Some(block),
            size_hint: Some(block),
            ..EncodeOpts::default()
        };
        let mut out = Vec::new();
        let mut enc = CodecId::Xz
            .codec()
            .encoder(Box::new(&mut out), &opts)
            .unwrap();
        enc.write_all(data).unwrap();
        enc.finish().unwrap();
        out
    }

    /// What `XzReader` makes of `xz`.
    fn one_thread(xz: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut dec =
            CodecId::Xz.decoder(Box::new(Cursor::new(xz.to_vec())), &Limits::default())?;
        dec.read_to_end(&mut out)
            .map_err(|e| crate::io::read_error(&e))?;
        Ok(out)
    }

    /// What the multithreaded decoder makes of `xz`, or `None` if it leaves it to one thread.
    fn threaded(xz: &[u8], threads: u32, limits: &Limits) -> Option<Result<Vec<u8>, Error>> {
        let mut dec = decoder(Cursor::new(xz.to_vec()), limits, threads, &Counter::new())?;
        let mut out = Vec::new();
        Some(
            dec.read_to_end(&mut out)
                .map(|_| out)
                .map_err(|e| crate::io::read_error(&e)),
        )
    }

    fn workers_for(xz: &[u8], threads: u32, limits: &Limits) -> Option<usize> {
        let r = XzMtReader::new(&mut Cursor::new(xz), limits, threads, &Counter::new())?;
        Some(r.workers)
    }

    fn scan_of(xz: &[u8]) -> Option<Scan> {
        scan(&mut Cursor::new(xz))
    }

    /// Each block's padding, 0 to 3 bytes.
    fn paddings(s: &Scan) -> Vec<u64> {
        s.blocks.iter().map(|b| b.padded() - b.unpadded).collect()
    }

    /// The bytes of block `i`'s check, and of its data's middle.
    fn check_at(s: &Scan, i: usize) -> usize {
        (s.blocks[i].end() - s.blocks[i].check.len()) as usize
    }

    fn data_at(s: &Scan, i: usize) -> usize {
        let b = &s.blocks[i];
        (b.start + b.header + (b.unpadded - b.header - b.check.len()) / 2) as usize
    }

    #[test]
    fn crc64_is_xz_utils_crc64() {
        assert_eq!(!crc64(!0, b"123456789"), 0x995D_C9BB_DF19_39FA);
        assert_eq!(!crc64(!0, b""), 0);
        // In pieces, of every length around the eight-byte step.
        let d = data(1000, 5);
        let whole = crc64(!0, &d);
        for cut in 0..20 {
            assert_eq!(crc64(crc64(!0, &d[..cut]), &d[cut..]), whole);
        }
    }

    #[test]
    fn xz_utils_files_decode_as_on_one_thread() {
        // seq 1 50000, by `xz -T0 --block-size=8KiB` with each check (README.md).
        for (name, check) in [
            ("seq-T0.xz", Check::Crc64),
            ("seq-T0-crc32.xz", Check::Crc32),
            ("seq-T0-sha256.xz", Check::Sha256),
            ("seq-T0-none.xz", Check::None),
        ] {
            let xz = fixture(name);
            let s = scan_of(&xz).unwrap();
            assert_eq!(s.blocks.len(), 36, "{name}");
            assert!(
                s.blocks
                    .iter()
                    .all(|b| b.check == check && b.dict == 8 << 20)
            );
            // Every padding length, which the spike's first decoder got wrong.
            let pads = paddings(&s);
            assert!((0..4).all(|p| pads.contains(&p)), "{name}: {pads:?}");
            let want = one_thread(&xz).unwrap();
            assert_eq!(want.len(), 288_894);
            for threads in [2, 3, 4, 36, 64] {
                let got = threaded(&xz, threads, &Limits::default()).unwrap().unwrap();
                assert!(got == want, "{name} at {threads} threads");
            }
        }
    }

    #[test]
    fn beezip_threaded_writer_files_decode() {
        let input = data(1_500_000, 1);
        for level in [0, 6, 9] {
            let xz = encode_mt(&input, level, 64 * 1024);
            let s = scan_of(&xz).unwrap();
            assert_eq!(
                s.blocks.len(),
                input.len().div_ceil(64 * 1024),
                "level {level}"
            );
            let pads = paddings(&s);
            assert!((0..4).all(|p| pads.contains(&p)), "level {level}: {pads:?}");
            let got = threaded(&xz, 4, &Limits::default()).unwrap().unwrap();
            assert!(got == input, "level {level}");
        }
    }

    #[test]
    fn concatenated_streams_and_their_padding() {
        let a = fixture("seq-T0.xz");
        let b = fixture("seq-T0-crc32.xz");
        let one = fixture("seq-T1.xz");
        let empty = encode_mt(b"", 6, 64 * 1024);
        let mut xz = a.clone();
        xz.extend([0; 4]);
        xz.extend(&empty);
        xz.extend(&b);
        xz.extend([0; 8]);
        xz.extend(&one);
        xz.extend([0; 12]);
        let s = scan_of(&xz).unwrap();
        assert_eq!(s.blocks.len(), 36 + 36 + 1);
        let want = one_thread(&xz).unwrap();
        assert_eq!(want.len(), 3 * 288_894);
        assert!(threaded(&xz, 4, &Limits::default()).unwrap().unwrap() == want);

        // Two one-block streams are two blocks, decoded side by side.
        let mut two = one.clone();
        two.extend(&one);
        assert_eq!(workers_for(&two, 8, &Limits::default()), Some(2));
        assert!(
            threaded(&two, 8, &Limits::default()).unwrap().unwrap() == one_thread(&two).unwrap()
        );

        // Padding that isn't whole words, or comes before the first stream, is left to
        // XzReader, which refuses it.
        for bad in [
            [a.as_slice(), &[0u8; 2][..]].concat(),
            [&[0u8; 4][..], a.as_slice()].concat(),
            [a.as_slice(), &[0u8; 3][..], b.as_slice()].concat(),
        ] {
            assert!(scan_of(&bad).is_none());
            assert!(one_thread(&bad).is_err());
        }
    }

    #[test]
    fn one_block_and_bcj_use_one_thread() {
        let limits = Limits::default();
        for name in ["seq-T1.xz", "seq-T0-x86.xz"] {
            let xz = fixture(name);
            assert!(workers_for(&xz, 4, &limits).is_none(), "{name}");
            // Through a source, which falls back to XzReader.
            let (_dir, path) = temp_file(&xz);
            let opts = OpenOptions::new(limits.clone()).with_threads(4);
            let source = Source::new(&path, vec![CodecId::Xz], &opts).unwrap();
            let mut out = Vec::new();
            source.open_stream().unwrap().read_to_end(&mut out).unwrap();
            assert_eq!(out, one_thread(&xz).unwrap(), "{name}");
            assert_eq!(source.counter.get(), xz.len() as u64);
        }
        // Not without threads to give; `0` is one per core.
        let xz = fixture("seq-T0.xz");
        assert!(workers_for(&xz, 1, &limits).is_none());
        let cores = resolve_threads(0) as usize;
        assert_eq!(
            workers_for(&xz, 0, &limits),
            Some(cores.min(36)).filter(|&c| c > 1)
        );
    }

    fn temp_file(data: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.xz");
        std::fs::write(&path, data).unwrap();
        (dir, path)
    }

    #[test]
    fn a_damaged_middle_block_fails() {
        let mine = encode_mt(&data(600_000, 2), 6, 64 * 1024);
        for xz in [
            fixture("seq-T0.xz"),
            fixture("seq-T0-crc32.xz"),
            fixture("seq-T0-sha256.xz"),
            mine,
        ] {
            let s = scan_of(&xz).unwrap();
            let mid = s.blocks.len() / 2;
            let name = s.blocks[mid].check.name();
            let mut bad = xz.clone();
            bad[check_at(&s, mid)] ^= 0x01;
            let err = threaded(&bad, 4, &Limits::default()).unwrap().unwrap_err();
            assert_eq!(err.kind, ErrorKind::Corrupt);
            assert_eq!(
                err.message,
                format!("xz: block {} fails its {name} check", mid + 1)
            );
            // A data byte: the LZMA2 data fails, or the check does.
            let mut bad = xz.clone();
            bad[data_at(&s, mid)] ^= 0x10;
            let err = threaded(&bad, 4, &Limits::default()).unwrap().unwrap_err();
            assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
            assert!(
                err.message.starts_with(&format!("xz: block {}", mid + 1)),
                "{err}"
            );
        }
    }

    #[test]
    fn too_little_memory_for_two_workers_is_one_thread() {
        let xz = encode_mt(&data(1_000_000, 3), 6, 128 * 1024);
        let s = scan_of(&xz).unwrap();
        let two = bound(&s, 2);
        let fits = |m| Limits {
            decoder_memory: m,
            ..Limits::default()
        };
        assert_eq!(workers_for(&xz, 4, &fits(two)), Some(2));
        assert_eq!(workers_for(&xz, 4, &fits(bound(&s, 3))), Some(3));
        assert_eq!(workers_for(&xz, 4, &fits(two - 1)), None);
        // One thread still decodes it: its dictionary fits.
        let (_dir, path) = temp_file(&xz);
        let opts = OpenOptions::new(fits(two - 1)).with_threads(4);
        let source = Source::new(&path, vec![CodecId::Xz], &opts).unwrap();
        let mut out = Vec::new();
        source.open_stream().unwrap().read_to_end(&mut out).unwrap();
        assert!(out == one_thread(&xz).unwrap());
    }

    #[test]
    fn the_whole_file_is_counted_as_it_is_handed_out() {
        let input = data(1_000_000, 4);
        let mut xz = encode_mt(&input, 1, 64 * 1024);
        xz.extend([0; 8]);
        xz.extend(fixture("seq-T0.xz"));
        let counter = Counter::new();
        counter.set(123);
        let mut dec = decoder(Cursor::new(xz.clone()), &Limits::default(), 4, &counter).unwrap();
        assert_eq!(counter.get(), 0);
        let mut buf = vec![0u8; 100_000];
        let mut last = 0;
        let mut out = Vec::new();
        loop {
            let n = dec.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            assert!(counter.get() >= last && counter.get() <= xz.len() as u64);
            last = counter.get();
        }
        assert!(out[..input.len()] == input[..]);
        assert_eq!(counter.get(), xz.len() as u64);
        // Reading on at the end adds nothing.
        assert_eq!(dec.read(&mut buf).unwrap(), 0);
        assert_eq!(counter.get(), xz.len() as u64);

        // Through a source, as progress and the ratio limit see it.
        let (_dir, path) = temp_file(&xz);
        let opts = OpenOptions::new(Limits::default()).with_threads(4);
        let source = Source::new(&path, vec![CodecId::Xz], &opts).unwrap();
        let mut stream = source.open_stream().unwrap();
        stream.read_to_end(&mut Vec::new()).unwrap();
        assert_eq!(source.counter.get(), xz.len() as u64);
    }

    #[test]
    fn a_stopped_worker_stops_before_decoding() {
        let xz = fixture("seq-T0.xz");
        let s = scan_of(&xz).unwrap();
        let b = &s.blocks[1];
        let packed = &xz[b.start as usize..b.end() as usize];
        let out = decode(1, b, packed, Vec::new(), &AtomicBool::new(false)).unwrap();
        assert_eq!(out.len(), 8192);
        let err = decode(1, b, packed, out, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(crate::io::read_error(&err).kind, ErrorKind::Cancelled);
    }

    #[test]
    fn dropping_it_part_way_stops_the_workers() {
        // Three 8 MiB blocks on two workers: the third starts once the first two are done, so
        // it has only just started when the first is handed out.
        let input = data(24 << 20, 6);
        let xz = encode_mt(&input, 0, 8 << 20);
        let t = Instant::now();
        let mut dec = decoder(Cursor::new(xz), &Limits::default(), 2, &Counter::new()).unwrap();
        let mut buf = vec![0u8; 1000];
        dec.read_exact(&mut buf).unwrap();
        let first = t.elapsed();
        assert!(buf == input[..buf.len()]);
        let t = Instant::now();
        drop(dec);
        // Within a step, not a block.
        assert!(
            t.elapsed() < first / 4,
            "{:?} against {first:?}",
            t.elapsed()
        );
    }

    /// Every byte of a small file flipped in turn: the scan never panics, and whatever the
    /// threaded decoder accepts, `XzReader` gives the same bytes for.
    #[test]
    fn flipped_bytes_never_decode_differently() {
        let input = data(12_000, 7);
        let xz = encode_mt(&input, 6, 4096);
        assert_eq!(scan_of(&xz).unwrap().blocks.len(), 3);
        let limits = Limits::default();
        let (mut taken, mut refused) = (0, 0);
        for at in 0..xz.len() {
            let mut bad = xz.clone();
            bad[at] ^= if at % 2 == 0 { 0x01 } else { 0x80 };
            match threaded(&bad, 2, &limits) {
                None => {}
                Some(Ok(out)) => {
                    taken += 1;
                    assert!(one_thread(&bad).is_ok_and(|v| v == out), "byte {at}");
                }
                Some(Err(e)) => {
                    refused += 1;
                    assert_eq!(e.kind, ErrorKind::Corrupt, "byte {at}: {e}");
                }
            }
        }
        // Only a block's data, padding or check gets past the scan, and every change there
        // fails.
        assert_eq!(taken, 0);
        assert!(refused > 0);
    }
}
