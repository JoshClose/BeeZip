//! Reading many blobs at once, in the order their data lies in the file (docs/M8.md §5.4).
//!
//! - **The plan** ([`Plan::new`]) groups the blobs asked for by where they are: a blob of its
//!   own resource is a run of that resource's chunks; the blobs of a solid resource are cut from
//!   runs of its chunks, one run as long as the blobs follow each other without a whole chunk
//!   between them. Runs are in file order. A blob whose range overlaps another's, which no
//!   image's writer makes, is `Corrupt`: decoding it again for each would let a small file
//!   claim any amount of work.
//! - **Decoding:** each chunk decodes alone, so `threads` workers decode them in any order and
//!   the job's thread takes them back in order ([`Threaded`]), at most `window` chunks ahead of
//!   it: `decoder_memory` over the largest chunk. With one thread they decode on the job's
//!   thread ([`Inline`]).
//! - **The blobs** are read from the chunks as they come ([`Cursor`]), each through a
//!   [`CutReader`] that checks its size and SHA-1 at its end. A chunk that doesn't decode fails
//!   the blobs in it; the rest go on.

use std::{
    collections::{BTreeMap, HashMap},
    io::{self, Read},
    sync::{Arc, Condvar, Mutex},
};

use sha1::{Digest, Sha1};

use super::container::{
    Chunk, ChunkIter, Container, Hash, Loc, Method, SolidCursor, ZERO, bad, hex,
};
use crate::{
    Error, Result,
    format::{lzx::Lzx, xpress},
};

/// A blob to read: the caller's key for it, its hash, where it is and its size.
#[derive(Debug, Clone, Copy)]
pub struct Want {
    pub key: usize,
    pub hash: Hash,
    pub loc: Loc,
    pub size: u64,
}

/// Where a run's chunks come from.
#[derive(Debug, Clone, Copy)]
enum Src {
    Res {
        part: usize,
        res: super::container::Res,
    },
    /// Chunks `first..end` of solid resource `s`.
    Solid { s: usize, first: u64, end: u64 },
}

/// A blob cut from a run's data.
#[derive(Debug, Clone, Copy)]
struct Cut {
    key: usize,
    /// From the run's first byte.
    start: u64,
    size: u64,
    hash: Hash,
}

struct Run {
    src: Src,
    /// Where the run's first chunk starts in its resource's data.
    start: u64,
    cuts: Vec<Cut>,
}

/// What's read, in what order (see the module's notes).
pub struct Plan {
    runs: Vec<Run>,
    /// Blobs that can't be read, and why; and blobs of no bytes.
    early: Vec<(usize, Option<Error>, Hash)>,
    /// The largest chunk decoded.
    max_chunk: u64,
}

impl Plan {
    pub fn new(c: &Container, wants: &[Want]) -> Self {
        let mut early: Vec<(usize, Option<Error>, Hash)> = Vec::new();
        let mut plain: Vec<(usize, u64, Want)> = Vec::new();
        let mut solid: BTreeMap<usize, Vec<Cut>> = BTreeMap::new();
        let mut max_chunk = 0u64;
        for w in wants {
            if w.size == 0 {
                early.push((w.key, None, w.hash));
                continue;
            }
            match w.loc {
                Loc::Res { part, res } => plain.push((part, res.offset, *w)),
                Loc::Solid { offset, size } => {
                    let Some(s) = c.solid_at(offset) else {
                        early.push((
                            w.key,
                            Some(bad(format!(
                                "blob {} lies outside every solid resource",
                                hex(&w.hash)
                            ))),
                            w.hash,
                        ));
                        continue;
                    };
                    let sol = &c.solids[s];
                    let rel = offset - sol.base;
                    if rel.checked_add(size).is_none_or(|e| e > sol.size) || size != w.size {
                        early.push((
                            w.key,
                            Some(bad(format!(
                                "blob {} runs past its solid resource",
                                hex(&w.hash)
                            ))),
                            w.hash,
                        ));
                        continue;
                    }
                    solid.entry(s).or_default().push(Cut {
                        key: w.key,
                        start: rel,
                        size,
                        hash: w.hash,
                    });
                }
            }
        }
        let overlap = |hash: &Hash| {
            bad(format!(
                "blob {}'s data overlaps another blob's, which no WIM's writer does",
                hex(hash)
            ))
        };
        // Sorted, so (part, offset) runs are in file order, and so overlaps are found.
        let mut runs: Vec<(usize, u64, Run)> = Vec::new();
        plain.sort_by_key(|(p, o, w)| (*p, *o, w.key));
        let mut end: Option<(usize, u64)> = None;
        for (part, offset, w) in plain {
            let Loc::Res { res, .. } = w.loc else {
                continue;
            };
            if let Some((p, e)) = end
                && p == part
                && offset < e
            {
                early.push((w.key, Some(overlap(&w.hash)), w.hash));
                continue;
            }
            end = Some((part, offset.saturating_add(res.size.max(1))));
            if let Ok(it) = c.chunks(part, &res) {
                max_chunk = max_chunk.max(it.max_chunk());
            }
            runs.push((
                part,
                offset,
                Run {
                    src: Src::Res { part, res },
                    start: 0,
                    cuts: vec![Cut {
                        key: w.key,
                        start: 0,
                        size: w.size,
                        hash: w.hash,
                    }],
                },
            ));
        }
        for (s, mut cuts) in solid {
            let sol = &c.solids[s];
            max_chunk = max_chunk.max(sol.chunk.min(sol.size));
            cuts.sort_by_key(|c| (c.start, c.key));
            let mut run: Option<(u64, u64, Vec<Cut>)> = None;
            let mut last_end = 0u64;
            let push = |runs: &mut Vec<(usize, u64, Run)>, (f, e, v): (u64, u64, Vec<Cut>)| {
                runs.push((
                    sol.part,
                    sol.res.offset.saturating_add(f),
                    Run {
                        src: Src::Solid {
                            s,
                            first: f,
                            end: e,
                        },
                        start: f * sol.chunk,
                        cuts: v,
                    },
                ));
            };
            for cut in cuts {
                if cut.start < last_end {
                    early.push((cut.key, Some(overlap(&cut.hash)), cut.hash));
                    continue;
                }
                last_end = cut.start + cut.size;
                let (a, b) = (
                    cut.start / sol.chunk,
                    (cut.start + cut.size - 1) / sol.chunk + 1,
                );
                match &mut run {
                    Some((_, e, v)) if a < *e => {
                        *e = (*e).max(b);
                        v.push(cut);
                    }
                    _ => {
                        if let Some(r) = run.take() {
                            push(&mut runs, r);
                        }
                        run = Some((a, b, vec![cut]));
                    }
                }
            }
            if let Some(r) = run.take() {
                push(&mut runs, r);
            }
        }
        runs.sort_by_key(|(p, o, _)| (*p, *o));
        let runs = runs
            .into_iter()
            .map(|(_, _, mut r)| {
                // Cuts are from the run's first byte.
                for cut in &mut r.cuts {
                    cut.start -= r.start;
                }
                r
            })
            .collect();
        Self {
            runs,
            early,
            max_chunk,
        }
    }
}

/// Decodes chunks: one set per worker, kept between chunks.
#[derive(Default)]
pub struct Decoders {
    xpress: xpress::Decoder,
    /// LZX's decoder and its window's bits.
    lzx: Option<(u32, Box<Lzx>)>,
    #[cfg(windows)]
    lzms: Option<super::lzms_win::LzmsDecoder>,
}

impl Decoders {
    /// Reads chunk `ch` and decodes it; a chunk as long as its output is stored.
    pub fn decode(&mut self, c: &Container, ch: &Chunk) -> Result<Vec<u8>> {
        let (packed, size) = (
            usize::try_from(ch.packed).map_err(|_| bad("a chunk too large"))?,
            usize::try_from(ch.size).map_err(|_| bad("a chunk too large"))?,
        );
        let mut input = vec![0u8; packed];
        c.read_at(ch.part, ch.offset, &mut input)?;
        if packed == size {
            return Ok(input);
        }
        let damaged = |e: &dyn std::fmt::Display| {
            bad(format!(
                "the {} chunk at {}{} is damaged: {e}",
                ch.method.name(),
                ch.offset,
                if c.parts.len() > 1 {
                    format!(" of part {}", ch.part + 1)
                } else {
                    String::new()
                }
            ))
        };
        match ch.method {
            Method::None => Err(bad(format!(
                "a stored chunk at {} of {packed} bytes that claims {size}",
                ch.offset
            ))),
            Method::Xpress => {
                let mut out = vec![0u8; size];
                self.xpress
                    .decode(&input, &mut out)
                    .map_err(|e| damaged(&e))?;
                Ok(out)
            }
            Method::Lzx => {
                let bits = ch.chunk.max(32_768).ilog2();
                let lzx = match &mut self.lzx {
                    Some((b, l)) if *b == bits => {
                        l.reset();
                        l
                    }
                    slot => {
                        let l = Lzx::new_wim(bits).map_err(|e| damaged(&e))?;
                        &mut slot.insert((bits, Box::new(l))).1
                    }
                };
                let mut out = Vec::with_capacity(size);
                if let Err(e) = lzx.decode_frame(&input, size, &mut out) {
                    // Its state is unknown now: a fresh one for the next chunk.
                    self.lzx = None;
                    return Err(damaged(&e));
                }
                if out.len() != size {
                    return Err(damaged(&"it decodes to the wrong size"));
                }
                Ok(out)
            }
            #[cfg(windows)]
            Method::Lzms => {
                let lzms = match &mut self.lzms {
                    Some(d) => d,
                    slot => slot.insert(super::lzms_win::LzmsDecoder::new()?),
                };
                let mut out = vec![0u8; size];
                lzms.decode(&input, &mut out).map_err(|e| {
                    if e.kind == crate::ErrorKind::Corrupt {
                        damaged(&e.message.trim_start_matches("wim: "))
                    } else {
                        e
                    }
                })?;
                Ok(out)
            }
            #[cfg(not(windows))]
            Method::Lzms => Err(super::container::unsupported(
                "LZMS, which BeeZip decodes only on Windows (through its Compression API)",
            )),
        }
    }
}

/// The chunks of a plan's runs, in order, each with its run's number.
struct Producer<'a> {
    c: &'a Container,
    plan: &'a Plan,
    k: usize,
    cur: Option<RunIter>,
    solid: HashMap<usize, SolidCursor>,
}

enum RunIter {
    Res(ChunkIter),
    Solid { s: usize, next: u64, end: u64 },
    Failed,
}

impl<'a> Producer<'a> {
    fn new(c: &'a Container, plan: &'a Plan) -> Self {
        Self {
            c,
            plan,
            k: 0,
            cur: None,
            solid: HashMap::new(),
        }
    }

    fn next(&mut self) -> Option<(usize, Result<Chunk>)> {
        loop {
            let run = self.plan.runs.get(self.k)?;
            let cur = match &mut self.cur {
                Some(it) => it,
                slot => slot.insert(match run.src {
                    Src::Res { part, res } => match self.c.chunks(part, &res) {
                        Ok(it) => RunIter::Res(it),
                        Err(e) => {
                            self.cur = Some(RunIter::Failed);
                            return Some((self.k, Err(e)));
                        }
                    },
                    Src::Solid { s, first, end } => RunIter::Solid {
                        s,
                        next: first,
                        end,
                    },
                }),
            };
            let got = match cur {
                RunIter::Res(it) => it.next(self.c),
                RunIter::Solid { s, next, end } if *next < *end => {
                    let i = *next;
                    *next += 1;
                    let s = *s;
                    let cursor = self.solid.entry(s).or_insert_with(|| SolidCursor::new(s));
                    let r = cursor.chunk(self.c, i);
                    if r.is_err() {
                        *next = *end;
                    }
                    Some(r)
                }
                RunIter::Solid { .. } | RunIter::Failed => None,
            };
            match got {
                Some(r) => return Some((self.k, r)),
                None => {
                    self.k += 1;
                    self.cur = None;
                }
            }
        }
    }
}

/// A decoded chunk, or why it isn't, for run `run`; `len` is how far it reaches (all the rest of
/// the run for a chunk that couldn't be found).
pub struct Item {
    run: usize,
    data: Result<Arc<Vec<u8>>>,
    len: u64,
}

impl Item {
    fn of(
        run: usize,
        ch: Result<Chunk>,
        decoded: impl FnOnce(&Chunk) -> Result<Arc<Vec<u8>>>,
    ) -> Self {
        match ch {
            Ok(ch) => Self {
                run,
                data: decoded(&ch),
                len: ch.size,
            },
            Err(e) => Self {
                run,
                data: Err(e),
                len: u64::MAX,
            },
        }
    }
}

/// Decoded chunks, in order.
pub trait Pipe {
    fn next_item(&mut self) -> Option<Item>;
}

/// The last chunk decoded, or why it couldn't be, by where it is: what `open_entry` keeps
/// (docs/M8.md §5.4). Without it each small file of a solid ESD would decode its 64 MiB chunk
/// again, even one that failed (the spike's `repro/own/hang-05.img`).
#[derive(Default)]
pub struct ChunkCache(Option<(ChunkKey, Result<Arc<Vec<u8>>>)>);

/// A chunk, by its part and its offset there.
type ChunkKey = (usize, u64);

/// Chunks decoded on the job's thread.
pub struct Inline<'a> {
    producer: Producer<'a>,
    dec: &'a mut Decoders,
    cache: &'a mut ChunkCache,
}

impl<'a> Inline<'a> {
    pub fn new(
        c: &'a Container,
        plan: &'a Plan,
        dec: &'a mut Decoders,
        cache: &'a mut ChunkCache,
    ) -> Self {
        Self {
            producer: Producer::new(c, plan),
            dec,
            cache,
        }
    }
}

impl Pipe for Inline<'_> {
    fn next_item(&mut self) -> Option<Item> {
        let (run, ch) = self.producer.next()?;
        let (c, dec, cache) = (self.producer.c, &mut *self.dec, &mut *self.cache);
        Some(Item::of(run, ch, |ch| {
            let key = (ch.part, ch.offset);
            if let Some((k, r)) = &cache.0
                && *k == key
            {
                return r.clone();
            }
            let r = dec.decode(c, ch).map(Arc::new);
            cache.0 = Some((key, r.clone()));
            r
        }))
    }
}

/// What the workers share.
struct Shared<'a> {
    jobs: Mutex<(Producer<'a>, usize)>,
    out: Mutex<Out>,
    cv: Condvar,
    window: usize,
}

#[derive(Default)]
struct Out {
    ready: BTreeMap<usize, Item>,
    /// The next sequence number the consumer takes.
    taken: usize,
    /// How many there are, once the producer is done.
    total: Option<usize>,
    stop: bool,
}

/// Chunks decoded by workers, taken back in order.
pub struct Threaded<'s, 'a> {
    shared: &'s Shared<'a>,
}

impl Pipe for Threaded<'_, '_> {
    fn next_item(&mut self) -> Option<Item> {
        let mut g = self.shared.out.lock().ok()?;
        loop {
            let at = g.taken;
            if let Some(item) = g.ready.remove(&at) {
                g.taken += 1;
                self.shared.cv.notify_all();
                return Some(item);
            }
            if g.total.is_some_and(|t| at >= t) || g.stop {
                return None;
            }
            g = self.shared.cv.wait(g).ok()?;
        }
    }
}

impl Drop for Threaded<'_, '_> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.shared.out.lock() {
            g.stop = true;
            g.ready.clear();
        }
        self.shared.cv.notify_all();
    }
}

fn worker(c: &Container, shared: &Shared<'_>) {
    let mut dec = Decoders::default();
    loop {
        let (seq, run, ch) = {
            let Ok(mut g) = shared.jobs.lock() else {
                return;
            };
            match g.0.next() {
                Some((run, ch)) => {
                    let seq = g.1;
                    g.1 += 1;
                    (seq, run, ch)
                }
                None => {
                    let seq = g.1;
                    drop(g);
                    if let Ok(mut o) = shared.out.lock() {
                        o.total = Some(seq);
                    }
                    shared.cv.notify_all();
                    return;
                }
            }
        };
        // Not too far ahead of the consumer.
        {
            let Ok(mut g) = shared.out.lock() else { return };
            while seq >= g.taken + shared.window && !g.stop {
                let Ok(next) = shared.cv.wait(g) else { return };
                g = next;
            }
            if g.stop {
                return;
            }
        }
        let item = Item::of(run, ch, |ch| dec.decode(c, ch).map(Arc::new));
        let Ok(mut g) = shared.out.lock() else { return };
        if g.stop {
            return;
        }
        g.ready.insert(seq, item);
        drop(g);
        shared.cv.notify_all();
    }
}

/// Reads the blobs of `plan` in data order, handing each to `each` with its key, as a reader of
/// its bytes ([`CutReader`]). Blobs that can't be planned, and blobs of no bytes, come first.
/// `threads` workers decode, at most `memory` bytes of chunks ahead; `each`'s error stops it.
pub fn run(
    c: &Container,
    plan: &Plan,
    threads: usize,
    memory: u64,
    each: &mut dyn FnMut(usize, &mut CutReader<'_, '_>) -> Result<()>,
) -> Result<()> {
    for (key, err, hash) in &plan.early {
        let mut r = CutReader::early(*hash, err.clone());
        each(*key, &mut r)?;
    }
    if plan.runs.is_empty() {
        return Ok(());
    }
    let max = plan.max_chunk.max(1);
    if max > memory {
        return Err(Error::limit(format!(
            "wim: its chunks of {max} bytes need more memory than `decoder_memory` allows \
             ({memory})"
        )));
    }
    if threads <= 1 {
        let mut dec = Decoders::default();
        let mut cache = ChunkCache::default();
        let mut pipe = Inline::new(c, plan, &mut dec, &mut cache);
        return read_runs(plan, &mut pipe, each);
    }
    let window = usize::try_from(memory / max)
        .unwrap_or(usize::MAX)
        .clamp(1, 4 * threads + 4);
    let shared = Shared {
        jobs: Mutex::new((Producer::new(c, plan), 0)),
        out: Mutex::new(Out::default()),
        cv: Condvar::new(),
        window,
    };
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| worker(c, &shared));
        }
        let mut pipe = Threaded { shared: &shared };
        read_runs(plan, &mut pipe, each)
        // Dropping the pipe stops the workers.
    })
}

fn read_runs(
    plan: &Plan,
    pipe: &mut dyn Pipe,
    each: &mut dyn FnMut(usize, &mut CutReader<'_, '_>) -> Result<()>,
) -> Result<()> {
    let mut cursor = Cursor::new(pipe);
    for (k, run) in plan.runs.iter().enumerate() {
        cursor.start_run(k);
        for cut in &run.cuts {
            let mut r = CutReader::new(&mut cursor, cut);
            each(cut.key, &mut r)?;
        }
    }
    Ok(())
}

/// One run's data, a chunk at a time, read forward.
pub struct Cursor<'p> {
    pipe: &'p mut dyn Pipe,
    peeked: Option<Item>,
    run: usize,
    /// Where the current chunk starts in the run's data, and the chunk.
    pos: u64,
    cur: Option<(Result<Arc<Vec<u8>>>, u64)>,
}

impl<'p> Cursor<'p> {
    pub fn new(pipe: &'p mut dyn Pipe) -> Self {
        Self {
            pipe,
            peeked: None,
            run: 0,
            pos: 0,
            cur: None,
        }
    }

    pub fn start_run(&mut self, k: usize) {
        self.run = k;
        self.pos = 0;
        self.cur = None;
    }

    /// Up to `buf.len()` bytes at `at` in the run's data, which never goes back.
    fn read_at(&mut self, at: u64, buf: &mut [u8]) -> Result<usize> {
        loop {
            if let Some((data, len)) = &self.cur {
                let end = self.pos.saturating_add(*len);
                if at < end {
                    let data = data.as_ref().map_err(Clone::clone)?;
                    let from = usize::try_from(at - self.pos).unwrap_or(usize::MAX);
                    let have = data.get(from..).unwrap_or_default();
                    let n = have.len().min(buf.len());
                    buf[..n].copy_from_slice(&have[..n]);
                    return Ok(n);
                }
                self.pos = end;
                self.cur = None;
            }
            // The next chunk of this run: earlier runs' leftovers are passed over.
            let item = loop {
                match self.peeked.take().or_else(|| self.pipe.next_item()) {
                    Some(i) if i.run < self.run => {}
                    other => break other,
                }
            };
            match item {
                Some(i) if i.run == self.run => {
                    let len = match &i.data {
                        Ok(d) if i.len != u64::MAX => d.len() as u64,
                        _ => i.len,
                    };
                    self.cur = Some((i.data, len));
                }
                other => {
                    self.peeked = other;
                    return Err(bad("the data ends before a blob in it does"));
                }
            }
        }
    }
}

/// One blob's bytes, checked: exactly its size, then its SHA-1 (unless it has none to check).
pub struct CutReader<'c, 'p> {
    cursor: Option<&'c mut Cursor<'p>>,
    start: u64,
    size: u64,
    done: u64,
    hash: Hash,
    sha: Sha1,
    outcome: Option<Result<()>>,
}

impl<'c, 'p> CutReader<'c, 'p> {
    fn new(cursor: &'c mut Cursor<'p>, cut: &Cut) -> Self {
        Self {
            cursor: Some(cursor),
            start: cut.start,
            size: cut.size,
            done: 0,
            hash: cut.hash,
            sha: Sha1::new(),
            outcome: None,
        }
    }

    /// A blob of no bytes, or one that can't be read.
    fn early(hash: Hash, err: Option<Error>) -> Self {
        Self {
            cursor: None,
            start: 0,
            size: 0,
            done: 0,
            hash,
            sha: Sha1::new(),
            outcome: err.map(Err),
        }
    }

    /// Its size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Reads the rest, if a sink stopped before the end, to learn the outcome.
    pub fn finish(&mut self, mut keep: Option<&mut Vec<u8>>) -> Result<()> {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match self.read_checked(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    if let Some(k) = keep.as_deref_mut() {
                        k.extend_from_slice(&buf[..n]);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn read_checked(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(r) = &self.outcome {
            return r.clone().map(|()| 0);
        }
        if self.done == self.size {
            let got: Hash = std::mem::take(&mut self.sha).finalize().into();
            let r = if self.hash == ZERO || got == self.hash {
                Ok(())
            } else {
                Err(bad(format!(
                    "a blob's data doesn't match its SHA-1 ({}, not {})",
                    hex(&got),
                    hex(&self.hash)
                )))
            };
            self.outcome = Some(r.clone());
            return r.map(|()| 0);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.size - self.done)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let Some(cursor) = self.cursor.as_mut() else {
            return Ok(0);
        };
        match cursor.read_at(self.start + self.done, &mut buf[..want]) {
            Ok(n) => {
                self.sha.update(&buf[..n]);
                self.done += n as u64;
                Ok(n)
            }
            Err(e) => {
                self.outcome = Some(Err(e.clone()));
                Err(e)
            }
        }
    }
}

impl Read for CutReader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_checked(buf).map_err(Error::into_io)
    }
}

/// One blob read on the job's thread, a chunk at a time, keeping the last chunk decoded in
/// `cache` for the next blob read (`open_entry`, docs/M8.md §5.4); its size and SHA-1 checked at
/// its end.
pub struct BlobReader<'a> {
    c: &'a Container,
    dec: &'a mut Decoders,
    cache: &'a mut ChunkCache,
    src: BlobSrc,
    /// The blob's range in its resource's data, and how much of it is read.
    start: u64,
    size: u64,
    done: u64,
    /// The chunk held, and where it starts in the data.
    cur: Option<(Arc<Vec<u8>>, u64)>,
    hash: Hash,
    sha: Sha1,
    outcome: Option<Result<()>>,
}

enum BlobSrc {
    /// A resource's chunks, and where the next starts.
    Res(ChunkIter, u64),
    Solid {
        cursor: SolidCursor,
        next: u64,
        end: u64,
        chunk: u64,
    },
}

impl<'a> BlobReader<'a> {
    pub fn new(
        c: &'a Container,
        dec: &'a mut Decoders,
        cache: &'a mut ChunkCache,
        hash: Hash,
    ) -> Result<Self> {
        let blob = *c
            .blobs
            .get(&hash)
            .ok_or_else(|| bad(format!("blob {} isn't in the lookup table", hex(&hash))))?;
        let (src, start) = match blob.loc {
            Loc::Res { part, res } => (BlobSrc::Res(c.chunks(part, &res)?, 0), 0),
            Loc::Solid { offset, size } => {
                let s = c.solid_at(offset).ok_or_else(|| {
                    bad(format!(
                        "blob {} lies outside every solid resource",
                        hex(&hash)
                    ))
                })?;
                let sol = &c.solids[s];
                let rel = offset - sol.base;
                if rel.checked_add(size).is_none_or(|e| e > sol.size) {
                    return Err(bad(format!(
                        "blob {} runs past its solid resource",
                        hex(&hash)
                    )));
                }
                let first = rel / sol.chunk;
                let end = if size == 0 {
                    first
                } else {
                    (rel + size - 1) / sol.chunk + 1
                };
                (
                    BlobSrc::Solid {
                        cursor: SolidCursor::new(s),
                        next: first,
                        end,
                        chunk: sol.chunk,
                    },
                    rel,
                )
            }
        };
        Ok(Self {
            c,
            dec,
            cache,
            src,
            start,
            size: blob.size,
            done: 0,
            cur: None,
            hash,
            sha: Sha1::new(),
            outcome: None,
        })
    }

    /// The next chunk, and where it starts in the data.
    fn next_chunk(&mut self) -> Option<Result<(Arc<Vec<u8>>, u64)>> {
        let (ch, at) = match &mut self.src {
            BlobSrc::Res(it, at) => {
                let ch = it.next(self.c)?;
                let pos = *at;
                if let Ok(ch) = &ch {
                    *at += ch.size;
                }
                (ch, pos)
            }
            BlobSrc::Solid {
                cursor,
                next,
                end,
                chunk,
            } => {
                if *next >= *end {
                    return None;
                }
                let i = *next;
                *next += 1;
                (cursor.chunk(self.c, i), i * *chunk)
            }
        };
        let ch = match ch {
            Ok(ch) => ch,
            Err(e) => return Some(Err(e)),
        };
        let key = (ch.part, ch.offset);
        if let Some((k, r)) = &self.cache.0
            && *k == key
        {
            return Some(r.clone().map(|d| (d, at)));
        }
        let r = self.dec.decode(self.c, &ch).map(Arc::new);
        self.cache.0 = Some((key, r.clone()));
        Some(r.map(|d| (d, at)))
    }

    fn read_checked(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(r) = &self.outcome {
            return r.clone().map(|()| 0);
        }
        if self.done == self.size {
            let got: Hash = std::mem::take(&mut self.sha).finalize().into();
            let r = if got == self.hash {
                Ok(())
            } else {
                Err(bad(format!(
                    "a blob's data doesn't match its SHA-1 ({}, not {})",
                    hex(&got),
                    hex(&self.hash)
                )))
            };
            self.outcome = Some(r.clone());
            return r.map(|()| 0);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let at = self.start + self.done;
        loop {
            if let Some((data, pos)) = &self.cur
                && at >= *pos
                && at < pos + data.len() as u64
            {
                let from = usize::try_from(at - pos).unwrap_or(usize::MAX);
                let want = usize::try_from(self.size - self.done)
                    .unwrap_or(usize::MAX)
                    .min(buf.len());
                let have = data.get(from..).unwrap_or_default();
                let n = have.len().min(want);
                buf[..n].copy_from_slice(&have[..n]);
                self.sha.update(&buf[..n]);
                self.done += n as u64;
                return Ok(n);
            }
            match self.next_chunk() {
                Some(Ok(c)) => self.cur = Some(c),
                Some(Err(e)) => {
                    self.outcome = Some(Err(e.clone()));
                    return Err(e);
                }
                None => {
                    let e = bad(format!(
                        "blob {} ends {} bytes short",
                        hex(&self.hash),
                        self.size - self.done
                    ));
                    self.outcome = Some(Err(e.clone()));
                    return Err(e);
                }
            }
        }
    }
}

impl Read for BlobReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_checked(buf).map_err(Error::into_io)
    }
}
