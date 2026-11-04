//! Byte counting and the copy loop every reader, writer and sink uses.

use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{Ctx, Error, ErrorKind, Result};

/// Buffer size for copies: large enough for the codecs to work in big steps, small enough that
/// cancellation is noticed quickly.
pub const BUF_SIZE: usize = 256 * 1024;

/// A shared byte count. Clones share the count.
#[derive(Debug, Clone, Default)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn set(&self, n: u64) {
        self.0.store(n, Ordering::Relaxed);
    }
}

/// Counts the bytes read through it. On the archive file it measures compressed input, which is
/// what progress and the ratio limit are based on.
#[derive(Debug)]
pub struct CountingReader<R> {
    inner: R,
    counter: Counter,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R, counter: Counter) -> Self {
        Self { inner, counter }
    }

    pub fn counter(&self) -> &Counter {
        &self.counter
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.counter.add(n as u64);
        Ok(n)
    }
}

impl<R: Seek> Seek for CountingReader<R> {
    /// Seeking sets the count to the new position, so on a file the count is the position.
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let at = self.inner.seek(pos)?;
        self.counter.set(at);
        Ok(at)
    }
}

/// Where archive writers write: a file, or a volume set (`volume::VolumeWriter`).
pub trait WriteSeek: Write + Seek + Send {}

impl<T: Write + Seek + Send> WriteSeek for T {}

/// Counts the bytes written through it.
#[derive(Debug)]
pub struct CountingWriter<W> {
    inner: W,
    counter: Counter,
}

impl<W> CountingWriter<W> {
    pub fn new(inner: W, counter: Counter) -> Self {
        Self { inner, counter }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.counter.add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for CountingWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Copies `r` to `w` in [`BUF_SIZE`] steps, calling [`Ctx::check`] before each one, so a
/// cancelled job stops within one buffer. Read errors keep their kind (a damaged stream is
/// `Corrupt`, a smuggled limit is `LimitExceeded`); write errors are `Io`.
pub fn copy(r: &mut dyn Read, w: &mut dyn Write, cx: &mut dyn Ctx) -> Result<u64> {
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total = 0u64;
    loop {
        cx.check()?;
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(read_error(&e)),
        };
        w.write_all(&buf[..n]).map_err(|e| write_error(&e))?;
        total += n as u64;
    }
}

/// Reads and discards everything, with the same checks as [`copy`].
pub fn drain(r: &mut dyn Read, cx: &mut dyn Ctx) -> Result<u64> {
    copy(r, &mut io::sink(), cx)
}

/// A read error as a core error. Smuggled core errors come back as they were; anything else
/// that isn't plainly an I/O failure means the data is damaged.
pub fn read_error(e: &io::Error) -> Error {
    if let Some(inner) = e.get_ref().and_then(|x| x.downcast_ref::<Error>()) {
        return inner.clone();
    }
    let err = Error::from_io(e);
    match err.kind {
        ErrorKind::Io if !is_os_error(e) => Error::corrupt(err.message),
        _ => err,
    }
}

/// A write error as a core error.
pub fn write_error(e: &io::Error) -> Error {
    let err = Error::from_io(e);
    match err.kind {
        ErrorKind::Corrupt => Error::new(ErrorKind::Io, err.message),
        _ => err,
    }
}

fn is_os_error(e: &io::Error) -> bool {
    e.raw_os_error().is_some()
        || matches!(
            e.kind(),
            io::ErrorKind::PermissionDenied
                | io::ErrorKind::StorageFull
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotFound
        )
}

/// Reads up to `max` bytes, stopping early at EOF or at the first error. Used by probes, which
/// look at whatever a possibly damaged or truncated stream gives them.
pub fn read_prefix(r: &mut dyn Read, max: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(max.min(64 * 1024));
    let mut buf = [0u8; 8192];
    while out.len() < max {
        let want = (max - out.len()).min(buf.len());
        match r.read(&mut buf[..want]) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

/// Yields exactly `len` bytes of `inner`: tar needs the size up front, so a file that shrank
/// while being archived must fail rather than corrupt the archive. Extra bytes are ignored.
pub struct ExactReader<R> {
    inner: R,
    left: u64,
}

impl<R: Read> ExactReader<R> {
    pub fn new(inner: R, len: u64) -> Self {
        Self { inner, left: len }
    }
}

impl<R: Read> Read for ExactReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the file got shorter while it was being read",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Calls [`Ctx::check`] before every read, for data handed to code with its own copy loop
/// (the tar and zip writers), so those loops stop on cancel and report progress too.
pub struct Checked<'a, R> {
    inner: R,
    cx: &'a mut dyn Ctx,
}

impl<'a, R: Read> Checked<'a, R> {
    pub fn new(inner: R, cx: &'a mut dyn Ctx) -> Self {
        Self { inner, cx }
    }
}

impl<R: Read> Read for Checked<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.cx.check().map_err(Error::into_io)?;
        self.inner.read(buf)
    }
}

enum PipeMsg {
    Data(Vec<u8>),
    Fail(Error),
    End,
}

/// A bounded push-to-pull adapter (docs/M3.md §3.3): a decoder that only calls back (7z's block
/// decoder, UnRAR) writes on its own thread, and the job reads. At most `chunks` chunks of
/// `chunk` bytes are in flight. Dropping the reader makes the writer's next write fail, and
/// sets [`PipeWriter::stopped`].
pub fn pipe(chunks: usize, chunk: usize) -> (PipeWriter, PipeReader) {
    let (tx, rx) = std::sync::mpsc::sync_channel(chunks.max(1));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        PipeWriter {
            tx,
            buf: Vec::with_capacity(chunk),
            chunk: chunk.max(1),
            stop: stop.clone(),
        },
        PipeReader {
            rx,
            cur: Vec::new(),
            pos: 0,
            done: false,
            failed: None,
            stop,
        },
    )
}

pub struct PipeWriter {
    tx: std::sync::mpsc::SyncSender<PipeMsg>,
    buf: Vec<u8>,
    chunk: usize,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl PipeWriter {
    /// The reader is gone: stop producing.
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn send_buf(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(self.chunk));
        self.tx
            .send(PipeMsg::Data(data))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the reader is gone"))
    }

    /// Ends the stream: what is buffered, then the end or the error.
    pub fn finish(mut self, result: Result<()>) {
        let flushed = self.send_buf();
        let msg = match (result, flushed) {
            (Err(e), _) => PipeMsg::Fail(e),
            (Ok(()), Err(_)) => return,
            (Ok(()), Ok(())) => PipeMsg::End,
        };
        let _ = self.tx.send(msg);
    }
}

impl Write for PipeWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.stopped() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the reader is gone",
            ));
        }
        let n = data.len().min(self.chunk - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() >= self.chunk {
            self.send_buf()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buf()
    }
}

pub struct PipeReader {
    rx: std::sync::mpsc::Receiver<PipeMsg>,
    cur: Vec<u8>,
    pos: usize,
    done: bool,
    failed: Option<Error>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl PipeReader {
    /// Waits for the first data, the end, or a failure, and returns the failure if that came
    /// first: a wrong password usually shows before any data does.
    pub fn first_error(&mut self) -> Option<Error> {
        if self.cur.is_empty() && !self.done && self.failed.is_none() {
            self.next();
        }
        self.failed.clone()
    }

    fn next(&mut self) {
        match self.rx.recv() {
            Ok(PipeMsg::Data(d)) => {
                self.cur = d;
                self.pos = 0;
            }
            Ok(PipeMsg::End) => self.done = true,
            Ok(PipeMsg::Fail(e)) => self.failed = Some(e),
            Err(_) => self.failed = Some(Error::corrupt("the decoder stopped unexpectedly")),
        }
    }
}

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.cur.len() {
                let n = buf.len().min(self.cur.len() - self.pos);
                buf[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if let Some(e) = &self.failed {
                return Err(e.clone().into_io());
            }
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            self.next();
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Remembers the first write error, for encoders (brotli) whose `finish` swallows them.
pub struct LatchWriter<W> {
    inner: W,
    pub error: Option<io::Error>,
}

impl<W: Write> LatchWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, error: None }
    }

    pub fn into_parts(self) -> (W, Option<io::Error>) {
        (self.inner, self.error)
    }
}

impl<W: Write> Write for LatchWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(e) = &self.error {
            return Err(io::Error::new(e.kind(), e.to_string()));
        }
        self.inner.write(buf).inspect_err(|e| {
            self.error = Some(io::Error::new(e.kind(), e.to_string()));
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().inspect_err(|e| {
            self.error = Some(io::Error::new(e.kind(), e.to_string()));
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;
    use crate::SimpleCtx;

    #[test]
    fn counting_reader_counts() {
        let c = Counter::new();
        let mut r = CountingReader::new(&b"hello world"[..], c.clone());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(c.get(), 11);
    }

    #[test]
    fn copy_stops_when_cancelled() {
        let flag = Arc::new(AtomicBool::new(true));
        let mut cx = SimpleCtx::new().with_cancel(flag);
        let err = copy(&mut &b"abc"[..], &mut Vec::new(), &mut cx).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }

    #[test]
    fn exact_reader_rejects_short_input() {
        let mut out = Vec::new();
        let err = ExactReader::new(&b"abc"[..], 5)
            .read_to_end(&mut out)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let mut out = Vec::new();
        ExactReader::new(&b"abcdef"[..], 4)
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn read_errors_keep_core_kinds() {
        let smuggled = Error::limit("ratio").into_io();
        assert_eq!(read_error(&smuggled).kind, ErrorKind::LimitExceeded);
        let bad = io::Error::other("bad block");
        assert_eq!(read_error(&bad).kind, ErrorKind::Corrupt);
    }
}
