//! The benchmark behind `bench.run` (docs/M6.md §7): each codec compresses and decompresses a
//! sample in memory, at the levels and thread counts asked for.
//!
//! - **The sample** is a file, read as 16 slices spread across it so a big file isn't judged
//!   by its start, or BeeZip's built-in one: seeded text, JSON and code, binary tables and
//!   random bytes.
//! - **Each cell** reports the packed size, the time each way and the memory each way: the
//!   growth of the process's private bytes, sampled every millisecond on a helper thread, so
//!   allocations in C code count too.
//! - **Each round trip is checked** against the sample, byte for byte; a mismatch fails the
//!   cell, not the run.
//! - **Cancel** is checked every 256 KiB. A cancelled run keeps the cells it finished.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    panic::{self, AssertUnwindSafe},
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use crate::{
    CodecId, Ctx, EncodeOpts, Error, ErrorKind, Limits, Progress, Result,
    codec::resolve_threads,
    io::{read_error, write_error},
    limits::MIB,
};

/// The built-in sample's size, and how much of a file is read, unless asked otherwise.
pub const DEFAULT_BYTES: u64 = 8 * MIB;
/// The `threads` grid's sample. Threads only pay once the sample holds several of a codec's
/// jobs or blocks: on 8 MiB, xz at -6 fits in one block.
pub const THREADS_BYTES: u64 = 64 * MIB;
/// The largest sample: it is held in memory along with its packed copy.
pub const MAX_BYTES: u64 = 1024 * MIB;
/// How many slices a file sample is read as.
pub const SLICES: u64 = 16;
/// Input between cancel checks.
const CHUNK: usize = 256 * 1024;

/// One codec at one level and thread count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub codec: CodecId,
    /// `None` for codecs without levels.
    pub level: Option<i32>,
    /// Resolved: never 0. Always 1 for codecs without threads.
    pub threads: u32,
}

impl Cell {
    /// A cell as asked for: no level is the codec's default, `threads` 0 is one per core.
    /// A level out of range, or given to a codec without levels, is `InvalidArgs`.
    pub fn new(codec: CodecId, level: Option<i32>, threads: u32) -> Result<Self> {
        let levels = codec.codec().levels();
        let resolved = EncodeOpts {
            level,
            ..EncodeOpts::default()
        }
        .resolve_level(codec, levels)?;
        Ok(Self::fixed(
            codec,
            levels.map(|_| resolved),
            threads,
            resolve_threads(0),
        ))
    }

    /// A grid's cell. A level the codec doesn't have is dropped or brought into range, so a
    /// grid stays valid when a codec gains or changes its levels.
    fn fixed(codec: CodecId, level: Option<i32>, threads: u32, cpus: u32) -> Self {
        let level = codec
            .codec()
            .levels()
            .map(|l| level.unwrap_or(l.default).clamp(l.min, l.max));
        let threads = match (codec.codec().threads(), threads) {
            (false, _) => 1,
            (true, 0) => cpus,
            (true, n) => n,
        };
        Self {
            codec,
            level,
            threads,
        }
    }

    /// For people: `xz -6, all threads`, `zstd -3, 1 thread`, `lz4`.
    pub fn label(&self, cpus: u32) -> String {
        let mut s = self.codec.name().to_owned();
        if let Some(l) = self.level {
            s.push_str(&format!(" -{l}"));
        }
        if self.codec.codec().threads() {
            s.push_str(&match self.threads {
                1 => ", 1 thread".to_owned(),
                t if t == cpus => ", all threads".to_owned(),
                t => format!(", {t} threads"),
            });
        }
        s
    }
}

/// The named grids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grid {
    /// The levels people pick, one thread each: about 10 seconds on 8 MiB.
    Default,
    /// Every codec at every level on one thread, and the threaded codecs at their default
    /// level on 4 threads and on all of them.
    Full,
    /// zstd -3 and -9, xz -1 and -6, on 1, 4 and all threads, on a 64 MiB sample.
    Threads,
}

impl Grid {
    pub fn cells(self) -> Vec<Cell> {
        use CodecId::*;
        let cpus = resolve_threads(0);
        let cell = |codec, level, threads| Cell::fixed(codec, level, threads, cpus);
        let mut cells: Vec<Cell> = match self {
            Self::Default => [
                (Gzip, Some(1)),
                (Gzip, Some(6)),
                (Gzip, Some(9)),
                (Bzip2, Some(9)),
                (Xz, Some(1)),
                (Xz, Some(6)),
                (Xz, Some(9)),
                (Zstd, Some(1)),
                (Zstd, Some(3)),
                (Zstd, Some(9)),
                (Zstd, Some(19)),
                (Lz4, None),
                (Brotli, Some(5)),
                (Brotli, Some(9)),
                (Snappy, None),
                (Lzop, None),
            ]
            .into_iter()
            .map(|(codec, level)| cell(codec, level, 1))
            .collect(),
            Self::Full => {
                let mut v = Vec::new();
                for id in CodecId::ALL {
                    let c = id.codec();
                    match c.levels() {
                        Some(l) => v.extend((l.min..=l.max).map(|lv| cell(id, Some(lv), 1))),
                        None => v.push(cell(id, None, 1)),
                    }
                    if c.threads() {
                        v.extend([4, 0].map(|t| cell(id, None, t)));
                    }
                }
                v
            }
            Self::Threads => [(Zstd, 3), (Zstd, 9), (Xz, 1), (Xz, 6)]
                .into_iter()
                .flat_map(|(codec, level)| [1, 4, 0].map(|t| cell(codec, Some(level), t)))
                .collect(),
        };
        // On four cores, "4" and "all" are the same cell; on one, "all" and "1".
        let mut seen = Vec::with_capacity(cells.len());
        cells.retain(|c| {
            let new = !seen.contains(c);
            seen.push(*c);
            new
        });
        cells
    }

    /// The sample size this grid runs on unless asked otherwise.
    pub fn sample_bytes(self) -> u64 {
        match self {
            Self::Threads => THREADS_BYTES,
            Self::Default | Self::Full => DEFAULT_BYTES,
        }
    }
}

/// BeeZip's built-in sample: `bytes` of seeded data, the same on every machine. It cycles
/// through 256 KiB segments of English-like text (4 in 10), JSON records and code-like lines
/// (3 in 10), tables of slowly changing little-endian numbers (2 in 10) and random bytes
/// (1 in 10).
pub fn builtin_sample(bytes: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "of",
        "and",
        "to",
        "a",
        "in",
        "is",
        "it",
        "you",
        "that",
        "he",
        "was",
        "for",
        "on",
        "are",
        "with",
        "as",
        "I",
        "his",
        "they",
        "be",
        "at",
        "one",
        "have",
        "this",
        "from",
        "or",
        "had",
        "by",
        "word",
        "but",
        "what",
        "some",
        "we",
        "can",
        "out",
        "other",
        "were",
        "all",
        "there",
        "when",
        "up",
        "use",
        "your",
        "how",
        "said",
        "an",
        "each",
        "she",
        "which",
        "do",
        "their",
        "time",
        "if",
        "will",
        "way",
        "about",
        "many",
        "then",
        "them",
        "write",
        "would",
        "like",
        "so",
        "these",
        "her",
        "long",
        "make",
        "thing",
        "see",
        "him",
        "two",
        "has",
        "look",
        "more",
        "day",
        "could",
        "go",
        "come",
        "did",
        "number",
        "sound",
        "no",
        "most",
        "people",
        "my",
        "over",
        "know",
        "water",
        "than",
        "call",
        "first",
        "who",
        "may",
        "down",
        "side",
        "been",
        "now",
        "find",
        "archive",
        "compression",
        "ratio",
        "stream",
        "block",
        "window",
        "dictionary",
        "entropy",
        "Huffman",
        "literal",
        "match",
        "length",
        "distance",
        "offset",
    ];
    let word = |r: u64| WORDS[(r % WORDS.len() as u64) as usize];
    // xorshift64: small, fast, and the same everywhere.
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut rnd = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::with_capacity(bytes + 256);
    let segment = 256 * 1024;
    let mut kind = 0u32;
    while out.len() < bytes {
        let end = (out.len() + segment).min(bytes);
        match kind % 10 {
            0 | 3 | 6 | 8 => {
                while out.len() < end {
                    let r = rnd();
                    // The product skews the choice towards the first words, as in prose.
                    out.extend_from_slice(word((r % 97) * (r % 89) / 89).as_bytes());
                    out.push(match r >> 60 {
                        0 => b'.',
                        1 => b',',
                        2 if r & 0xF00 == 0 => b'\n',
                        _ => b' ',
                    });
                }
            }
            1 | 4 | 7 => {
                let mut id = rnd() % 100_000;
                while out.len() < end {
                    id += 1 + rnd() % 7;
                    let r = rnd();
                    let line = if r & 1 == 0 {
                        format!(
                            "{{\"id\": {id}, \"name\": \"{} {}\", \"tags\": [\"{}\", \"{}\"], \"value\": {}.{:03}}},\n",
                            word(r >> 8),
                            word(r >> 16),
                            word(r >> 24),
                            word(r >> 32),
                            (r >> 40) % 1000,
                            (r >> 50) % 1000
                        )
                    } else {
                        format!(
                            "    let {}_{} = self.{}({}, \"{}\")?;\n",
                            word(r >> 8),
                            (r >> 16) % 64,
                            word(r >> 24),
                            (r >> 32) % 4096,
                            word(r >> 40)
                        )
                    };
                    out.extend_from_slice(line.as_bytes());
                }
            }
            2 | 5 => {
                let mut v = [0u32; 4];
                while out.len() < end {
                    let r = rnd();
                    v[0] = v[0].wrapping_add(1);
                    v[1] = v[1].wrapping_add((r % 16) as u32);
                    v[2] = (r >> 32) as u32 & 0xFFFF;
                    if r & 7 == 0 {
                        v[3] = (r >> 8) as u32;
                    }
                    for x in v {
                        out.extend_from_slice(&x.to_le_bytes());
                    }
                }
            }
            _ => {
                while out.len() < end {
                    out.extend_from_slice(&rnd().to_le_bytes());
                }
            }
        }
        out.truncate(end);
        kind += 1;
    }
    out
}

/// `bytes` of `path`, as [`SLICES`] slices, one at the start of each sixteenth of the file;
/// the whole file if it is no bigger.
pub fn file_sample(path: &Path, bytes: u64) -> Result<Vec<u8>> {
    let reading = || format!("reading {}", path.display());
    let mut file = File::open(path).map_err(|e| Error::io(reading(), &e))?;
    let len = file.metadata().map_err(|e| Error::io(reading(), &e))?.len();
    let cap = usize::try_from(bytes.min(len)).map_err(|_| Error::limit("the sample is too big"))?;
    let mut out = Vec::with_capacity(cap);
    if len <= bytes {
        file.read_to_end(&mut out)
            .map_err(|e| Error::io(reading(), &e))?;
        return Ok(out);
    }
    let share = |n: u64, i: u64| (u128::from(n) * u128::from(i) / u128::from(SLICES)) as u64;
    for i in 0..SLICES {
        let n = share(bytes, i + 1) - share(bytes, i);
        // Slices may touch when the file is barely bigger than the sample; they never run
        // past its end.
        let at = share(len, i).min(len - n);
        file.seek(SeekFrom::Start(at))
            .map_err(|e| Error::io(reading(), &e))?;
        let before = out.len();
        (&mut file)
            .take(n)
            .read_to_end(&mut out)
            .map_err(|e| Error::io(reading(), &e))?;
        if (out.len() - before) as u64 != n {
            return Err(Error::new(
                ErrorKind::Io,
                format!("{}: the file got shorter while it was read", reading()),
            ));
        }
    }
    Ok(out)
}

/// What one cell measured. A failed cell keeps what it measured before it failed.
#[derive(Debug, Clone, PartialEq)]
pub struct CellReport {
    pub cell: Cell,
    /// 0 unless compressing finished.
    pub packed_bytes: u64,
    /// `None` when that way didn't finish.
    pub compress_time: Option<Duration>,
    pub decompress_time: Option<Duration>,
    /// Growth of the process's private bytes during each way, in bytes. 0 where the
    /// platform gives no figure.
    pub compress_mem: u64,
    pub decompress_mem: u64,
    /// The whole cell.
    pub elapsed: Duration,
    /// The codec's error, or a round trip that didn't match the sample.
    pub error: Option<Error>,
}

impl CellReport {
    /// Decimal megabytes of the sample per second, or 0 when that way didn't finish.
    pub fn mbps(sample_bytes: u64, time: Option<Duration>) -> f64 {
        match time {
            Some(t) if !t.is_zero() => sample_bytes as f64 / 1e6 / t.as_secs_f64(),
            _ => 0.0,
        }
    }
}

/// Runs a list of cells on one sample, one cell per [`Bench::next_cell`], so the caller can
/// send each result on as it comes.
pub struct Bench<'a> {
    sample: &'a [u8],
    cells: Vec<Cell>,
    limits: Limits,
    cpus: u32,
    next: usize,
    cancelled: bool,
    /// The encoders' output and the decoders' buffer, set aside before any cell starts so
    /// they aren't in its memory figure (unless a codec outgrows the first).
    packed: Vec<u8>,
    buf: Vec<u8>,
    /// Makes a cell go wrong, for the tests.
    #[cfg(test)]
    fault: Option<(usize, Fault)>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// A byte of the decompressed output flipped.
    Mismatch,
    /// The encoder panics.
    Panic,
}

impl<'a> Bench<'a> {
    pub fn new(sample: &'a [u8], cells: Vec<Cell>, limits: Limits) -> Self {
        let cap = sample.len() + sample.len() / 8 + 64 * 1024;
        // Filled, not only reserved (as zeros would be), so the pages are resident on Linux
        // too before the first cell's reading.
        let mut packed = vec![1u8; cap];
        packed.clear();
        Self {
            sample,
            cells,
            limits,
            cpus: resolve_threads(0),
            next: 0,
            cancelled: false,
            packed,
            buf: vec![1u8; CHUNK],
            #[cfg(test)]
            fault: None,
        }
    }

    #[cfg(test)]
    fn faulty(&self, index: usize, fault: Fault) -> bool {
        self.fault == Some((index, fault))
    }

    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// Logical CPUs: what "all threads" means.
    pub fn cpus(&self) -> u32 {
        self.cpus
    }

    /// Whether the job was cancelled before every cell ran.
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Runs the next cell. `None` once every cell has run, or once the job is cancelled; the
    /// cell running then is dropped.
    pub fn next_cell(&mut self, cx: &mut dyn Ctx) -> Option<CellReport> {
        if self.cancelled || self.next >= self.cells.len() {
            return None;
        }
        if cx.is_cancelled() {
            self.cancelled = true;
            return None;
        }
        let index = self.next;
        self.next += 1;
        let started = Instant::now();
        let mut report = CellReport {
            cell: self.cells[index],
            packed_bytes: 0,
            compress_time: None,
            decompress_time: None,
            compress_mem: 0,
            decompress_mem: 0,
            elapsed: Duration::ZERO,
            error: None,
        };
        // A codec that panics fails its cell, not the cells already measured. The buffers
        // are only reused after `clear`, so they are sound after a panic.
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            self.compress(index, &mut report, cx)
                .and_then(|()| self.decompress(index, &mut report, cx))
        }))
        .unwrap_or_else(|payload| {
            let why = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic payload");
            Err(Error::new(
                ErrorKind::Corrupt,
                format!("the codec panicked: {why}"),
            ))
        });
        report.elapsed = started.elapsed();
        match result {
            Ok(()) => Some(report),
            Err(e) if e.kind == ErrorKind::Cancelled => {
                self.cancelled = true;
                None
            }
            Err(e) => {
                report.error = Some(e);
                Some(report)
            }
        }
    }

    fn meter(&self, index: usize) -> Meter {
        Meter {
            index: index as u64,
            cells: self.cells.len() as u64,
            len: self.sample.len() as u64,
            label: self.cells[index].label(self.cpus),
        }
    }

    fn compress(&mut self, index: usize, report: &mut CellReport, cx: &mut dyn Ctx) -> Result<()> {
        let cell = self.cells[index];
        let meter = self.meter(index);
        let opts = EncodeOpts {
            level: cell.level,
            threads: cell.threads,
            size_hint: Some(self.sample.len() as u64),
            size_exact: true,
            ..EncodeOpts::default()
        };
        let sample = self.sample;
        #[cfg(test)]
        let panics = self.faulty(index, Fault::Panic);
        let packed = &mut self.packed;
        packed.clear();
        let (result, time, mem) = measure(|peak| {
            let mut enc = cell.codec.codec().encoder(Box::new(&mut *packed), &opts)?;
            let mut done = 0;
            for chunk in sample.chunks(CHUNK) {
                #[cfg(test)]
                assert!(!panics, "a test's panic");
                enc.write_all(chunk).map_err(|e| write_error(&e))?;
                done += chunk.len();
                meter.report(cx, 0, done);
                cx.check()?;
            }
            // What the encoder holds at its fullest, in case the sampler missed it.
            peak.note();
            enc.finish().map_err(|e| write_error(&e))
        });
        report.compress_mem = mem;
        result?;
        report.compress_time = Some(time);
        report.packed_bytes = self.packed.len() as u64;
        Ok(())
    }

    fn decompress(
        &mut self,
        index: usize,
        report: &mut CellReport,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let cell = self.cells[index];
        let meter = self.meter(index);
        let sample = self.sample;
        #[cfg(test)]
        let tamper = self.faulty(index, Fault::Mismatch);
        let packed = &self.packed[..];
        let buf = &mut self.buf;
        let limits = &self.limits;
        let (result, time, mem) = measure(|peak| {
            let mut dec = cell.codec.decoder(Box::new(packed), limits)?;
            let mut pos = 0;
            loop {
                let n = dec.read(buf).map_err(|e| read_error(&e))?;
                if n == 0 {
                    break;
                }
                #[cfg(test)]
                if tamper {
                    buf[0] ^= 1;
                }
                let got = &buf[..n];
                let want = sample.get(pos..pos + n);
                if want != Some(got) {
                    let at = want
                        .and_then(|w| w.iter().zip(got).position(|(a, b)| a != b))
                        .map_or(sample.len(), |i| pos + i);
                    return Err(Error::corrupt(format!(
                        "the round trip doesn't match the sample from byte {at}"
                    )));
                }
                pos += n;
                meter.report(cx, 1, pos);
                cx.check()?;
            }
            peak.note();
            if pos == sample.len() {
                Ok(())
            } else {
                Err(Error::corrupt(format!(
                    "the round trip gave {pos} bytes of the sample's {}",
                    sample.len()
                )))
            }
        });
        report.decompress_mem = mem;
        result?;
        report.decompress_time = Some(time);
        Ok(())
    }
}

/// Progress for one cell: the cells done of the total, and bytes through both ways of every
/// cell, which grow steadily for a progress bar.
struct Meter {
    index: u64,
    cells: u64,
    len: u64,
    label: String,
}

impl Meter {
    /// `way` is 0 compressing, 1 decompressing; `done` is the sample bytes through it.
    fn report(&self, cx: &mut dyn Ctx, way: u64, done: usize) {
        cx.progress(&Progress {
            bytes_done: (self.index * 2 + way) * self.len + done as u64,
            bytes_total: Some(self.cells * 2 * self.len),
            entries_done: self.index,
            entries_total: Some(self.cells),
            current: Some(format!(
                "{}, {}",
                self.label,
                if way == 0 {
                    "compressing"
                } else {
                    "decompressing"
                }
            )),
        });
    }
}

/// The highest private-bytes reading while one way of a cell runs.
struct Peak {
    max: AtomicU64,
    stop: AtomicBool,
}

impl Peak {
    fn note(&self) {
        self.max.fetch_max(private_bytes(), Ordering::Relaxed);
    }

    fn watch(&self) {
        while !self.stop.load(Ordering::Relaxed) {
            self.note();
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Runs `f`, timing it, while a helper thread samples the private bytes every millisecond.
/// The memory is the highest reading over the one taken before.
fn measure<T>(f: impl FnOnce(&Peak) -> T) -> (T, Duration, u64) {
    let base = private_bytes();
    let peak = Peak {
        max: AtomicU64::new(base),
        stop: AtomicBool::new(false),
    };
    /// Stops the sampler however `f` ends: the scope waits for it, so a panic in `f` would
    /// otherwise wait forever.
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    thread::scope(|s| {
        let _stop = Stop(&peak.stop);
        // Without a thread, the readings `f` takes itself still count.
        let _sampler = thread::Builder::new()
            .name("beezip-bench-memory".to_owned())
            .spawn_scoped(s, || peak.watch());
        let started = Instant::now();
        let out = f(&peak);
        let time = started.elapsed();
        peak.note();
        (
            out,
            time,
            peak.max.load(Ordering::Relaxed).saturating_sub(base),
        )
    })
}

/// The process's private bytes: memory committed to it alone, C allocations included.
#[cfg(windows)]
#[allow(unsafe_code)]
fn private_bytes() -> u64 {
    use windows_sys::Win32::System::{
        ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
        },
        Threading::GetCurrentProcess,
    };
    let mut counters = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..PROCESS_MEMORY_COUNTERS_EX::default()
    };
    // SAFETY: the counters are ours and `cb` is their size; the EX struct starts with the
    // plain one, as the call expects. The current-process handle needs no closing.
    let ok = unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&raw mut counters).cast::<PROCESS_MEMORY_COUNTERS>(),
            counters.cb,
        )
    };
    if ok == 0 {
        0
    } else {
        counters.PrivateUsage as u64
    }
}

/// Linux: anonymous resident memory (`RssAnon`), the nearest to Windows' private bytes.
#[cfg(target_os = "linux")]
fn private_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("RssAnon:"))
                .and_then(|v| v.trim().strip_suffix("kB"))
                .and_then(|v| v.trim().parse::<u64>().ok())
        })
        .map_or(0, |kib| kib * 1024)
}

/// Elsewhere there's no figure yet.
#[cfg(not(any(windows, target_os = "linux")))]
fn private_bytes() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use super::*;
    use crate::SimpleCtx;

    const SMALL: usize = 64 * 1024;

    fn run_all(bench: &mut Bench<'_>, cx: &mut dyn Ctx) -> Vec<CellReport> {
        std::iter::from_fn(|| bench.next_cell(cx)).collect()
    }

    #[test]
    fn the_builtin_sample_is_deterministic() {
        let a = builtin_sample(1 << 20);
        assert_eq!(a.len(), 1 << 20);
        assert_eq!(a, builtin_sample(1 << 20));
        // The same bytes on every machine and in every version, or results don't compare.
        assert_eq!(crc32fast::hash(&a), 0xF34B_DA42);
        // A shorter sample is the start of a longer one.
        assert_eq!(builtin_sample(1000)[..], a[..1000]);
    }

    #[test]
    fn every_grid_runs_on_a_small_sample() {
        let sample = builtin_sample(16 * 1024);
        for grid in [Grid::Default, Grid::Full, Grid::Threads] {
            let cells = grid.cells();
            assert!(!cells.is_empty());
            let mut bench = Bench::new(&sample, cells.clone(), Limits::default());
            let reports = run_all(&mut bench, &mut SimpleCtx::new());
            assert_eq!(reports.len(), cells.len(), "{grid:?}");
            assert!(!bench.cancelled());
            for r in &reports {
                assert_eq!(r.error, None, "{grid:?} {:?}", r.cell);
                assert!(r.packed_bytes > 0, "{:?}", r.cell);
                assert!(r.compress_time.is_some() && r.decompress_time.is_some());
            }
        }
    }

    #[test]
    fn grids_hold_what_the_plan_says() {
        let cpus = resolve_threads(0);
        let default = Grid::Default.cells();
        assert_eq!(default.len(), 16);
        assert!(default.iter().all(|c| c.threads == 1));
        let full = Grid::Full.cells();
        let levels: usize = CodecId::ALL
            .iter()
            .map(|c| {
                c.codec()
                    .levels()
                    .map_or(1, |l| (l.max - l.min + 1) as usize)
            })
            .sum();
        let threaded = CodecId::ALL.iter().filter(|c| c.codec().threads()).count();
        let extra = if cpus == 1 || cpus == 4 { 1 } else { 2 };
        assert_eq!(full.len(), levels + threaded * extra);
        let threads = Grid::Threads.cells();
        assert_eq!(threads.len(), if cpus == 1 || cpus == 4 { 8 } else { 12 });
        assert!(threads.iter().any(|c| c.threads == cpus));
        assert_eq!(Grid::Threads.sample_bytes(), 64 * MIB);
    }

    #[test]
    fn cells_are_checked_and_labelled() {
        let cpus = resolve_threads(0);
        let zstd = Cell::new(CodecId::Zstd, None, 0).unwrap();
        assert_eq!(zstd.level, Some(3));
        assert_eq!(zstd.threads, cpus);
        assert_eq!(zstd.label(cpus), "zstd -3, all threads");
        let xz = Cell::new(CodecId::Xz, Some(6), 1).unwrap();
        assert_eq!(xz.label(cpus), "xz -6, 1 thread");
        // No threads, no level: neither is shown.
        let lz4 = Cell::new(CodecId::Lz4, None, 8).unwrap();
        assert_eq!((lz4.level, lz4.threads), (None, 1));
        assert_eq!(lz4.label(cpus), "lz4");
        assert_eq!(
            Cell::new(CodecId::Gzip, Some(12), 1).unwrap_err().kind,
            ErrorKind::InvalidArgs
        );
        assert_eq!(
            Cell::new(CodecId::Lz4, Some(1), 1).unwrap_err().kind,
            ErrorKind::InvalidArgs
        );
    }

    #[test]
    fn a_round_trip_that_does_not_match_fails_its_cell() {
        let sample = builtin_sample(SMALL);
        let cells = vec![
            Cell::new(CodecId::Gzip, Some(1), 1).unwrap(),
            Cell::new(CodecId::Lz4, None, 1).unwrap(),
        ];
        let mut bench = Bench::new(&sample, cells, Limits::default());
        bench.fault = Some((0, Fault::Mismatch));
        let reports = run_all(&mut bench, &mut SimpleCtx::new());
        assert_eq!(reports.len(), 2);
        let failed = reports[0].error.as_ref().expect("the first cell fails");
        assert_eq!(failed.kind, ErrorKind::Corrupt);
        assert!(failed.message.contains("from byte 0"), "{}", failed.message);
        // Compressing finished, so its figures stay; decompressing didn't.
        assert!(reports[0].packed_bytes > 0);
        assert!(reports[0].compress_time.is_some());
        assert_eq!(reports[0].decompress_time, None);
        assert_eq!(
            CellReport::mbps(SMALL as u64, reports[0].decompress_time),
            0.0
        );
        // The run goes on.
        assert_eq!(reports[1].error, None);
    }

    #[test]
    fn a_codec_that_panics_fails_its_cell() {
        let sample = builtin_sample(SMALL);
        let cells = vec![Cell::new(CodecId::Lz4, None, 1).unwrap(); 2];
        let mut bench = Bench::new(&sample, cells, Limits::default());
        bench.fault = Some((0, Fault::Panic));
        // Returning at all shows the memory sampler stopped.
        let reports = run_all(&mut bench, &mut SimpleCtx::new());
        let failed = reports[0].error.as_ref().expect("the first cell fails");
        assert!(
            failed.message.contains("a test's panic"),
            "{}",
            failed.message
        );
        assert_eq!(reports[0].compress_time, None);
        assert_eq!(reports[1].error, None);
    }

    /// Cancels the job once the cell numbered `cell` (from 0) reports decompressing.
    struct CancelAt {
        cell: u64,
        flag: Arc<AtomicBool>,
    }

    impl Ctx for CancelAt {
        fn is_cancelled(&self) -> bool {
            self.flag.load(Ordering::Relaxed)
        }
        fn progress(&mut self, p: &Progress) {
            let decompressing = p
                .current
                .as_deref()
                .is_some_and(|c| c.ends_with("decompressing"));
            if p.entries_done == self.cell && decompressing {
                self.flag.store(true, Ordering::Relaxed);
            }
        }
        fn warn(&mut self, _message: String) {}
        fn password(&mut self, _entry: Option<&str>, _attempt: u32) -> Result<String> {
            Err(Error::cancelled())
        }
        fn overwrite(&mut self, _existing: &Path) -> Result<crate::OverwriteChoice> {
            Err(Error::cancelled())
        }
    }

    #[test]
    fn a_cancelled_run_keeps_the_cells_it_finished() {
        // Two chunks, so decompressing checks at least twice.
        let sample = builtin_sample(2 * CHUNK);
        let cells: Vec<Cell> = [CodecId::Lz4, CodecId::Snappy, CodecId::Gzip, CodecId::Zstd]
            .into_iter()
            .map(|c| Cell::new(c, None, 1).unwrap())
            .collect();
        let mut bench = Bench::new(&sample, cells, Limits::default());
        // Cancelled while the second cell decompresses.
        let mut cx = CancelAt {
            cell: 1,
            flag: Arc::default(),
        };
        let reports = run_all(&mut bench, &mut cx);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].cell.codec, CodecId::Lz4);
        assert_eq!(reports[0].error, None);
        assert!(bench.cancelled());
        assert_eq!(bench.next_cell(&mut cx), None);

        // Cancelled between cells: nothing more runs.
        let flag = Arc::new(AtomicBool::new(false));
        let mut cx = SimpleCtx::new().with_cancel(Arc::clone(&flag));
        let cells = vec![Cell::new(CodecId::Lz4, None, 1).unwrap(); 3];
        let mut bench = Bench::new(&sample, cells, Limits::default());
        assert!(bench.next_cell(&mut cx).is_some());
        flag.store(true, Ordering::Relaxed);
        assert_eq!(bench.next_cell(&mut cx), None);
        assert!(bench.cancelled());
    }

    #[test]
    fn progress_counts_cells_and_names_the_current_one() {
        let sample = builtin_sample(SMALL);
        let cells = vec![Cell::new(CodecId::Xz, Some(6), 1).unwrap()];
        let mut bench = Bench::new(&sample, cells, Limits::default());
        let mut cx = SimpleCtx::new();
        bench.next_cell(&mut cx).unwrap();
        let p = cx.last_progress.unwrap();
        assert_eq!(p.entries_total, Some(1));
        assert_eq!(p.bytes_done, p.bytes_total.unwrap());
        assert_eq!(p.current.as_deref(), Some("xz -6, 1 thread, decompressing"));
    }

    #[test]
    fn a_file_is_read_as_slices_across_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data: Vec<u8> = (0..1600u32).map(|i| (i / 100) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        // 16 slices of 10 bytes, one from each hundred.
        let s = file_sample(&path, 160).unwrap();
        assert_eq!(s.len(), 160);
        for (i, slice) in s.chunks(10).enumerate() {
            assert!(slice.iter().all(|&b| b as usize == i), "{i}: {slice:?}");
        }
        // A sample bigger than the file is the file.
        assert_eq!(file_sample(&path, 1 << 20).unwrap(), data);
        // Barely bigger than the sample: still in bounds, and the right size.
        assert_eq!(file_sample(&path, 1599).unwrap().len(), 1599);
        assert_eq!(
            file_sample(&dir.path().join("none"), 10).unwrap_err().kind,
            ErrorKind::NotFound
        );
    }

    #[test]
    fn memory_is_read() {
        #[cfg(any(windows, target_os = "linux"))]
        assert!(private_bytes() > 0);
        // 64 MiB touched while measuring shows.
        let (_, _, mem) = measure(|_| {
            let v = vec![1u8; 64 << 20];
            std::hint::black_box(&v);
            thread::sleep(Duration::from_millis(5));
        });
        // Loosely: other tests in this process allocate and free meanwhile.
        #[cfg(any(windows, target_os = "linux"))]
        assert!(mem >= 32 << 20, "{mem}");
        let _ = mem;
    }
}
