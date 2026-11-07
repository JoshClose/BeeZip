//! Parallel deflate (docs/M6.md §6.1): gzip, zlib and raw deflate with more than one thread, and
//! the zip writer's big entries.
//!
//! The input is cut into 128 KiB blocks by offset, never by `write` call, so the output depends
//! only on the level: not on the thread count, and not on the sizes of the writes. Each block is
//! deflated by a fresh raw `Compress`, primed with the 32 KiB before it and ended with a sync
//! flush, which leaves it on a byte boundary; the last block ends the stream. The workers also
//! take each block's CRC-32 (Adler-32 for zlib), and the writer combines them in order.
//!
//! One thread stays on flate2's own encoders, which are faster there; the codecs choose.

use std::{
    collections::BTreeMap,
    io::{self, Write},
    mem,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
};

use flate2::{Compress, Compression, FlushCompress, Status};

/// Input per block. In the spike's sweep at level 6, 64 KiB was 7 % slower, and bigger blocks
/// at most 6 % faster with more memory in flight.
const BLOCK: usize = 128 * 1024;
/// Deflate's window: each block is primed with this much of the input before it.
const DICT: usize = 32 * 1024;
/// Blocks handed out and not yet written, per worker. One more than a worker holds lets the
/// others go on while the writer waits for the oldest block; three was no faster.
const IN_FLIGHT_PER_WORKER: usize = 2;

/// The checksum the workers take of each block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Crc32,
    Adler32,
}

impl Check {
    /// The checksum of no input.
    fn empty(self) -> u32 {
        match self {
            Self::Crc32 => 0,
            Self::Adler32 => 1,
        }
    }

    fn of(self, data: &[u8]) -> u32 {
        match self {
            Self::Crc32 => crc32fast::hash(data),
            Self::Adler32 => zlib_rs::adler32::adler32(1, data),
        }
    }

    /// The checksum of `a`'s input followed by `b`'s, which is `len_b` bytes.
    fn combine(self, a: u32, b: u32, len_b: u64) -> u32 {
        match self {
            Self::Crc32 => {
                let mut sum = crc32fast::Hasher::new_with_initial(a);
                sum.combine(&crc32fast::Hasher::new_with_initial_len(b, len_b));
                sum.finalize()
            }
            Self::Adler32 => zlib_rs::adler32::adler32_combine(a, b, len_b),
        }
    }
}

/// What a finished raw deflate stream was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Summary {
    /// The CRC-32 of the input.
    pub crc32: u32,
    /// Bytes given to the encoder.
    pub bytes_in: u64,
    /// Bytes of deflate it wrote.
    pub bytes_out: u64,
}

/// A raw deflate writer that compresses on `threads` workers.
///
/// The stream is the same at any thread count (1 included) and for any sizes of writes, and is
/// exactly what the gzip writer puts between its header and its trailer at the same level. It
/// is not flate2's single-threaded stream: blocks are cut every 128 KiB.
///
/// `finish` writes the end of the stream and reports what a worker hit. Dropped without it, the
/// writer stops its workers (each finishes the block it holds) and the stream is incomplete.
pub(crate) struct ParDeflate<W: Write> {
    w: W,
    level: u32,
    check: Check,
    threads: usize,
    /// Written before the first block: the gzip or zlib header.
    head: Vec<u8>,
    /// The block being filled.
    cur: Vec<u8>,
    /// The last full block, whose end primes the next.
    prev: Option<Arc<Vec<u8>>>,
    /// Started at the first full block, so a stream of one block starts no thread.
    pool: Option<Pool>,
    /// Blocks handed out, and the next one to write.
    sent: u64,
    next: u64,
    /// Blocks done ahead of `next`.
    ready: BTreeMap<u64, Done>,
    /// The checksum of the blocks written so far.
    sum: u32,
    bytes_in: u64,
    bytes_out: u64,
    /// A call failed part-way, so the stream is broken and must not be finished.
    failed: bool,
}

impl<W: Write> ParDeflate<W> {
    /// Raw deflate at `level` (0–9) on `threads` workers; 1 (or 0) compresses on the caller's
    /// thread, and is still this stream rather than flate2's.
    pub(crate) fn new(w: W, level: u32, threads: u32) -> Self {
        Self::with(w, level, threads, Check::Crc32, Vec::new())
    }

    /// gzip's deflate, after `header`; [`Self::finish_gzip`] writes the trailer.
    pub(super) fn gzip(w: W, level: u32, threads: u32, header: Vec<u8>) -> Self {
        Self::with(w, level, threads, Check::Crc32, header)
    }

    /// A zlib stream: the header zlib-rs writes for `level`, then deflate; [`Self::finish_zlib`]
    /// writes the Adler-32.
    pub(super) fn zlib(w: W, level: u32, threads: u32) -> Self {
        Self::with(
            w,
            level,
            threads,
            Check::Adler32,
            zlib_header(level).to_vec(),
        )
    }

    fn with(w: W, level: u32, threads: u32, check: Check, head: Vec<u8>) -> Self {
        Self {
            w,
            level,
            check,
            threads: usize::try_from(threads).unwrap_or(usize::MAX).max(1),
            head,
            cur: Vec::with_capacity(BLOCK),
            prev: None,
            pool: None,
            sent: 0,
            next: 0,
            ready: BTreeMap::new(),
            sum: check.empty(),
            bytes_in: 0,
            bytes_out: 0,
            failed: false,
        }
    }

    /// Ends the stream and returns the writer, unflushed.
    pub(crate) fn finish(self) -> io::Result<(W, Summary)> {
        debug_assert_eq!(
            self.check,
            Check::Crc32,
            "a zlib writer ends with finish_zlib"
        );
        let (w, sum, bytes_in, bytes_out) = self.end()?;
        let summary = Summary {
            crc32: sum,
            bytes_in,
            bytes_out,
        };
        Ok((w, summary))
    }

    /// Ends the stream and writes gzip's trailer: the CRC-32 and the size mod 2³².
    pub(super) fn finish_gzip(self) -> io::Result<W> {
        let (mut w, crc, bytes_in, _) = self.end()?;
        w.write_all(&crc.to_le_bytes())?;
        w.write_all(&(bytes_in as u32).to_le_bytes())?;
        Ok(w)
    }

    /// Ends the stream and writes zlib's trailer: the Adler-32, big-endian.
    pub(super) fn finish_zlib(self) -> io::Result<W> {
        let (mut w, adler, ..) = self.end()?;
        w.write_all(&adler.to_be_bytes())?;
        Ok(w)
    }

    fn end(mut self) -> io::Result<(W, u32, u64, u64)> {
        if self.failed {
            return Err(broken());
        }
        self.dispatch(true)?;
        self.drain()?;
        if let Some(mut pool) = self.pool.take() {
            pool.stop()?;
        }
        Ok((self.w, self.sum, self.bytes_in, self.bytes_out))
    }

    /// Hands out the current block: to a worker, or compressed here with one thread, or when
    /// it is the whole stream.
    fn dispatch(&mut self, last: bool) -> io::Result<()> {
        let next_cur = if last {
            Vec::new()
        } else {
            Vec::with_capacity(BLOCK)
        };
        let data = Arc::new(mem::replace(&mut self.cur, next_cur));
        self.bytes_in += data.len() as u64;
        let prev = if last {
            self.prev.take()
        } else {
            self.prev.replace(Arc::clone(&data))
        };
        let job = Job {
            seq: self.sent,
            data,
            prev,
            last,
        };
        self.sent += 1;
        if self.threads == 1 || (last && self.pool.is_none()) {
            let done = job.run(self.level, self.check);
            return self.write_block(done);
        }
        let limit = self.threads.saturating_mul(IN_FLIGHT_PER_WORKER) as u64;
        while self.sent - self.next > limit {
            self.receive(true)?;
        }
        let in_flight = usize::try_from(self.sent - self.next).unwrap_or(usize::MAX);
        let pool = self
            .pool
            .get_or_insert_with(|| Pool::new(self.level, self.check, self.threads));
        pool.send(job, in_flight)?;
        while self.receive(false)? {}
        Ok(())
    }

    /// Takes one finished block from the workers, waiting for it if `wait`, and writes every
    /// block that is now next in order. False if none was ready.
    fn receive(&mut self, wait: bool) -> io::Result<bool> {
        let Some(pool) = &self.pool else {
            return Ok(false);
        };
        let done = if wait {
            pool.done.recv().map_err(|_| stopped())?
        } else {
            match pool.done.try_recv() {
                Ok(done) => done,
                Err(_) => return Ok(false),
            }
        };
        self.ready.insert(done.seq, done);
        while let Some(done) = self.ready.remove(&self.next) {
            self.write_block(done)?;
        }
        Ok(true)
    }

    /// Writes every block handed out.
    fn drain(&mut self) -> io::Result<()> {
        while self.next < self.sent {
            self.receive(true)?;
        }
        Ok(())
    }

    fn write_block(&mut self, done: Done) -> io::Result<()> {
        let out = done.out?;
        if !self.head.is_empty() {
            self.w.write_all(&mem::take(&mut self.head))?;
        }
        self.w.write_all(&out)?;
        self.bytes_out += out.len() as u64;
        self.sum = self.check.combine(self.sum, done.sum, done.len);
        self.next += 1;
        Ok(())
    }

    fn guard<T>(&mut self, r: io::Result<T>) -> io::Result<T> {
        self.failed |= r.is_err();
        r
    }
}

impl<W: Write> Write for ParDeflate<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(broken());
        }
        let mut rest = buf;
        while !rest.is_empty() {
            let take = (BLOCK - self.cur.len()).min(rest.len());
            self.cur.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.cur.len() == BLOCK {
                let r = self.dispatch(false);
                self.guard(r)?;
            }
        }
        Ok(buf.len())
    }

    /// Writes the blocks handed out, then flushes the writer. The block being filled stays:
    /// cutting it here would make the bytes depend on when flushes come.
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(broken());
        }
        let r = self.drain().and_then(|()| self.w.flush());
        self.guard(r)
    }
}

/// The header zlib-rs writes: a 32 KiB window, FLEVEL from the level, no dictionary.
fn zlib_header(level: u32) -> [u8; 2] {
    let flevel: u16 = match level {
        0 | 1 => 0,
        2..=5 => 1,
        6 => 2,
        _ => 3,
    };
    let mut h = 0x7800 | flevel << 6;
    h += 31 - h % 31;
    h.to_be_bytes()
}

fn broken() -> io::Error {
    io::Error::other("the deflate stream failed earlier")
}

fn stopped() -> io::Error {
    io::Error::other("the deflate workers stopped")
}

/// A block to compress.
struct Job {
    seq: u64,
    data: Arc<Vec<u8>>,
    /// The full block before this one, whose last 32 KiB prime it.
    prev: Option<Arc<Vec<u8>>>,
    last: bool,
}

/// A compressed block.
struct Done {
    seq: u64,
    out: io::Result<Vec<u8>>,
    /// The block's checksum, and its input's length.
    sum: u32,
    len: u64,
}

impl Job {
    /// Compresses the block. A panic becomes an error, so the writer never waits for a block
    /// that won't come.
    fn run(&self, level: u32, check: Check) -> Done {
        let dict = self.prev.as_deref().map(|p| &p[p.len() - DICT..]);
        let out = panic::catch_unwind(AssertUnwindSafe(|| {
            deflate_block(level, &self.data, dict, self.last)
        }))
        .unwrap_or_else(|_| Err(io::Error::other("a deflate worker panicked")));
        Done {
            seq: self.seq,
            out,
            sum: check.of(&self.data),
            len: self.data.len() as u64,
        }
    }
}

/// Deflates one block: primed with `dict`, then a sync flush, or the end of the stream if
/// `last`.
///
/// A fresh `Compress` each time: on zlib-rs 0.6.8, `reset()` and then `set_dictionary` gives
/// different bytes from a new one at levels 1–8 (an upstream bug), and the bytes must not depend
/// on which worker had which block before.
fn deflate_block(level: u32, data: &[u8], dict: Option<&[u8]>, last: bool) -> io::Result<Vec<u8>> {
    let mut c = Compress::new(Compression::new(level), false);
    if let Some(dict) = dict {
        c.set_dictionary(dict).map_err(io::Error::other)?;
    }
    let flush = if last {
        FlushCompress::Finish
    } else {
        FlushCompress::Sync
    };
    let mut out = Vec::with_capacity(data.len() / 2 + 4096);
    loop {
        if out.capacity() - out.len() < 4096 {
            out.reserve(out.capacity().max(64 * 1024));
        }
        let (before_in, before_out) = (c.total_in(), c.total_out());
        let used = usize::try_from(before_in).unwrap_or(usize::MAX);
        let status = c
            .compress_vec(&data[used..], &mut out, flush)
            .map_err(io::Error::other)?;
        let used = usize::try_from(c.total_in()).unwrap_or(usize::MAX);
        match status {
            Status::StreamEnd => return Ok(out),
            // A sync flush is complete once deflate returns with output space left.
            _ if !last && used == data.len() && out.len() < out.capacity() => return Ok(out),
            Status::BufError if c.total_in() == before_in && c.total_out() == before_out => {
                return Err(io::Error::other("deflate made no progress"));
            }
            _ => {}
        }
    }
}

/// The workers, started as blocks need them. Dropping it stops them.
struct Pool {
    level: u32,
    check: Check,
    max: usize,
    jobs: Option<mpsc::Sender<Job>>,
    /// One queue for all the workers, so a slow block holds up only its own worker.
    queue: Arc<Mutex<mpsc::Receiver<Job>>>,
    done_tx: mpsc::Sender<Done>,
    done: mpsc::Receiver<Done>,
    workers: Vec<JoinHandle<()>>,
}

impl Pool {
    fn new(level: u32, check: Check, max: usize) -> Self {
        let (jobs, queue) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        Self {
            level,
            check,
            max,
            jobs: Some(jobs),
            queue: Arc::new(Mutex::new(queue)),
            done_tx,
            done,
            workers: Vec::new(),
        }
    }

    /// Queues `job`, starting a worker if fewer are running than blocks are in flight.
    fn send(&mut self, job: Job, in_flight: usize) -> io::Result<()> {
        if self.workers.len() < self.max.min(in_flight) {
            let queue = Arc::clone(&self.queue);
            let done = self.done_tx.clone();
            let (level, check) = (self.level, self.check);
            let worker = thread::Builder::new()
                .name("beezip-deflate".into())
                .spawn(move || work(&queue, &done, level, check));
            match worker {
                Ok(worker) => self.workers.push(worker),
                // Fewer workers than asked for still finish the stream.
                Err(_) if !self.workers.is_empty() => self.max = self.workers.len(),
                Err(e) => return Err(e),
            }
        }
        self.jobs
            .as_ref()
            .ok_or_else(stopped)?
            .send(job)
            .map_err(|_| stopped())
    }

    /// Stops the workers once they finish what they hold, and waits for them.
    fn stop(&mut self) -> io::Result<()> {
        self.jobs = None;
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            panicked |= worker.join().is_err();
        }
        if panicked {
            return Err(io::Error::other("a deflate worker panicked"));
        }
        Ok(())
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn work(queue: &Mutex<mpsc::Receiver<Job>>, done: &mpsc::Sender<Done>, level: u32, check: Check) {
    loop {
        // The lock is held while waiting for a job, never while compressing one.
        let job = match queue.lock() {
            Ok(queue) => queue.recv(),
            Err(_) => return,
        };
        // The writer finished or was dropped.
        let Ok(job) = job else { return };
        if done.send(job.run(level, check)).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use flate2::read::{DeflateDecoder, ZlibDecoder};

    use super::*;

    /// Text, then random bytes, then text again.
    fn mixed(len: usize) -> Vec<u8> {
        let mut s = 0x9E37_79B9_7F4A_7C15_u64;
        let mut out = Vec::with_capacity(len);
        const WORDS: [&[u8]; 6] = [b"bee ", b"zip ", b"hive\n", b"honey ", b"wax ", b"the "];
        while out.len() < len {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let third = out.len() * 3 / len;
            if third == 1 {
                out.push((s >> 32) as u8);
            } else {
                out.extend_from_slice(WORDS[(s % 6) as usize]);
            }
        }
        out.truncate(len);
        out
    }

    fn raw(data: &[u8], level: u32, threads: u32) -> (Vec<u8>, Summary) {
        let mut enc = ParDeflate::new(Vec::new(), level, threads);
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn the_bytes_depend_only_on_the_level() {
        let data = mixed(9 * BLOCK + 1000);
        for level in 0..=9 {
            let (one, _) = raw(&data, level, 1);
            for threads in [2, 4, 32] {
                let (out, _) = raw(&data, level, threads);
                assert!(out == one, "level {level}, {threads} threads");
            }
        }
    }

    #[test]
    fn reports_the_crc_and_sizes() {
        for len in [0, 1, BLOCK, BLOCK + 1, 5 * BLOCK + 7] {
            let data = mixed(len);
            let (out, s) = raw(&data, 6, 4);
            assert_eq!(s.crc32, crc32fast::hash(&data), "{len} bytes");
            assert_eq!(s.bytes_in, len as u64);
            assert_eq!(s.bytes_out, out.len() as u64);
            let mut back = Vec::new();
            DeflateDecoder::new(&out[..])
                .read_to_end(&mut back)
                .unwrap();
            assert!(back == data, "{len} bytes");
        }
    }

    /// The zip writer's big entries are the same deflate as a parallel gzip's.
    #[test]
    fn raw_deflate_is_what_gzip_wraps() {
        let data = mixed(3 * BLOCK + 99);
        let (out, s) = raw(&data, 6, 4);
        let mut gz = ParDeflate::gzip(Vec::new(), 6, 4, b"HEADER".to_vec());
        gz.write_all(&data).unwrap();
        let gz = gz.finish_gzip().unwrap();
        assert_eq!(&gz[..6], b"HEADER");
        assert_eq!(&gz[6..gz.len() - 8], &out[..]);
        assert_eq!(gz[gz.len() - 8..gz.len() - 4], s.crc32.to_le_bytes());
        assert_eq!(gz[gz.len() - 4..], (data.len() as u32).to_le_bytes());
    }

    #[test]
    fn zlib_streams_carry_the_adler32() {
        let data = mixed(4 * BLOCK + 3);
        let mut enc = ParDeflate::zlib(Vec::new(), 9, 3);
        enc.write_all(&data).unwrap();
        let out = enc.finish_zlib().unwrap();
        let want = zlib_rs::adler32::adler32(1, &data);
        assert_eq!(out[out.len() - 4..], want.to_be_bytes());
        let mut back = Vec::new();
        ZlibDecoder::new(&out[..]).read_to_end(&mut back).unwrap();
        assert!(back == data);
    }

    #[test]
    fn checksums_combine_in_order() {
        let data = mixed(70_001);
        let (a, b) = data.split_at(12_345);
        for check in [Check::Crc32, Check::Adler32] {
            let whole = check.of(&data);
            let joined = check.combine(check.of(a), check.of(b), b.len() as u64);
            assert_eq!(joined, whole, "{check:?}");
            assert_eq!(
                check.combine(check.empty(), whole, data.len() as u64),
                whole
            );
            assert_eq!(check.of(&[]), check.empty());
        }
    }

    /// Dropping the writer part-way stops its workers instead of hanging.
    #[test]
    fn dropping_without_finish_stops_the_workers() {
        let data = mixed(40 * BLOCK);
        let mut enc = ParDeflate::new(Vec::new(), 9, 8);
        enc.write_all(&data).unwrap();
        drop(enc);
    }

    /// A writer that fails once its budget is spent.
    struct Budget(usize);

    impl Write for Budget {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.len() > self.0 {
                return Err(io::Error::other("full"));
            }
            self.0 -= buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Once the writer under it fails, the stream stays failed, so a broken one never finishes.
    #[test]
    fn a_failed_write_is_never_finished() {
        let data = mixed(20 * BLOCK);
        let mut enc = ParDeflate::new(Budget(50_000), 1, 4);
        assert!(enc.write_all(&data).is_err());
        assert!(enc.write_all(b"more").is_err());
        assert!(enc.finish().is_err());
    }

    #[test]
    fn zlib_headers_match_zlib_rs() {
        for level in 0..=9 {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Compression::new(level));
            z.write_all(b"x").unwrap();
            let z = z.finish().unwrap();
            assert_eq!(z[..2], zlib_header(level), "level {level}");
        }
    }
}
