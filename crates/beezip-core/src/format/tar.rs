//! TAR, through the `tar` crate (0.4.46). This is the only file that names `tar::`.
//!
//! - Names in pax records are UTF-8; the others (ustar and GNU long names) are bytes, read
//!   through the source's `NameDecoding` with the system's ANSI code page (docs/M5.md §6).
//! - Reading is one pass over `tar::Archive`; the crate handles pax and GNU long names. A plain
//!   `.tar` is seekable, so listing skips the data and `open_entry` seeks straight to an
//!   entry. A compressed tar is decoded from the start each time.
//! - Regular and contiguous files are `File`, as are GNU sparse files (read expanded);
//!   directories, symlinks and hardlinks keep their kinds; devices and FIFOs are `Other`.
//! - Writing uses GNU headers, so long names get `././@LongLink` entries. Modes are real on
//!   Unix and 0o644/0o755 on Windows, which has no exec bit.

use std::{
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    time::SystemTime,
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Copied, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, Keep, NewEntry, NewKind, Selection, normalize,
};
use crate::{
    Ctx, Error, Meter, MeteredCtx, Result,
    codec::FinishWrite,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, Checked, CountingReader, ExactReader, read_error, write_error},
    names::{NameDecoding, SystemPage},
    source::{Input, Source},
    time::{from_unix, to_unix},
};

pub struct Tar;

impl ArchiveFormat for Tar {
    fn id(&self) -> FormatId {
        FormatId::Tar
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".tar"]
    }

    /// `ustar` at offset 257 with a valid header checksum is certain; the magic alone, or a
    /// valid checksum on a v7 header without it, is likely.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let header = probe.head.get(..512)?;
        let magic = header[257..262] == *b"ustar";
        let checksum = checksum_ok(header);
        match (magic, checksum) {
            (true, true) => Some(Confidence::Certain),
            (true, false) => Some(Confidence::Likely),
            (false, true) if v7_plausible(header) => Some(Confidence::Likely),
            _ => None,
        }
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            append: true,
            delete: true,
            rename: true,
            random_access: true,
            ..FormatCaps::default()
        }
    }
}

/// The header checksum: the byte sum with the checksum field read as spaces. Some old tars
/// summed signed bytes, so both sums are accepted.
fn checksum_ok(header: &[u8]) -> bool {
    let Some(stored) = octal(&header[148..156]) else {
        return false;
    };
    let field = 148..156;
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in header.iter().enumerate() {
        let b = if field.contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b.cast_signed());
    }
    // An all-zero block sums to 256 (the spaces); that is an end marker, not a header.
    unsigned != 256 && (stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed))
}

/// A v7 header has a name and octal mode, size and mtime fields.
fn v7_plausible(header: &[u8]) -> bool {
    header[0] != 0
        && octal(&header[100..108]).is_some()
        && octal(&header[124..136]).is_some()
        && octal(&header[136..148]).is_some()
}

/// An octal field: optional leading spaces, digits, then NUL or space padding.
fn octal(field: &[u8]) -> Option<u64> {
    let s = field
        .iter()
        .skip_while(|&&b| b == b' ')
        .take_while(|&&b| b != 0 && b != b' ')
        .copied()
        .collect::<Vec<_>>();
    if s.is_empty() || !s.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return None;
    }
    s.iter().try_fold(0u64, |acc, &d| {
        acc.checked_mul(8)?.checked_add(u64::from(d - b'0'))
    })
}

fn tar_error(e: &io::Error) -> Error {
    read_error(e).context("tar")
}

/// Headers the crate yields but that aren't entries.
fn is_meta(t: tar::EntryType) -> bool {
    t.is_pax_global_extensions()
        || t.is_pax_local_extensions()
        || t.is_gnu_longname()
        || t.is_gnu_longlink()
}

/// Where a plain tar keeps a contiguous file's bytes: (offset, size).
type Span = Option<(u64, u64)>;

/// A GNU sparse file stored the pax way (`tar --sparse --format=pax`), which the tar crate
/// doesn't decode: the header names a placeholder (`GNUSparseFile.<pid>/name`), and pax records
/// give the real name and size. Versions 0.0 and 0.1 put the map of data regions in pax
/// records; 1.0 puts it at the start of the entry's data.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PaxSparse {
    name: Option<String>,
    size: u64,
    /// `(offset, length)` of each stored region; `None` for 1.0, whose map is in the data.
    map: Option<Vec<(u64, u64)>>,
}

fn pax_sparse<R: Read>(e: &mut tar::Entry<'_, R>) -> Option<PaxSparse> {
    let exts = e.pax_extensions().ok()??;
    let (mut major, mut name, mut size, mut map01) = (None, None, None, None);
    let (mut offsets, mut lengths) = (Vec::new(), Vec::new());
    let mut any = false;
    for ext in exts.flatten() {
        let (Ok(key), Ok(value)) = (ext.key(), ext.value()) else {
            continue;
        };
        let Some(field) = key.strip_prefix("GNU.sparse.") else {
            continue;
        };
        any = true;
        match field {
            "major" => major = value.parse::<u32>().ok(),
            "name" => name = Some(value.to_owned()),
            "realsize" | "size" => size = value.parse::<u64>().ok(),
            "map" => map01 = Some(value.to_owned()),
            "offset" => offsets.extend(value.parse::<u64>().ok()),
            "numbytes" => lengths.extend(value.parse::<u64>().ok()),
            _ => {}
        }
    }
    if !any {
        return None;
    }
    let map = if major == Some(1) {
        None
    } else if let Some(m) = map01 {
        let nums: Vec<u64> = m.split(',').filter_map(|n| n.trim().parse().ok()).collect();
        Some(
            nums.as_chunks::<2>()
                .0
                .iter()
                .map(|&[o, l]| (o, l))
                .collect(),
        )
    } else {
        Some(offsets.into_iter().zip(lengths).collect())
    };
    Some(PaxSparse {
        name,
        size: size.unwrap_or_else(|| e.size()),
        map,
    })
}

/// Expands a pax sparse file: stored regions from `inner`, zeros in between and after.
struct SparseData<R> {
    inner: R,
    /// Regions not yet passed, in order. `None` until a 1.0 map has been read from the data.
    map: Option<std::collections::VecDeque<(u64, u64)>>,
    size: u64,
    pos: u64,
}

impl<R: Read> SparseData<R> {
    fn new(inner: R, s: &PaxSparse) -> Self {
        Self {
            inner,
            map: s.map.clone().map(Into::into),
            size: s.size,
            pos: 0,
        }
    }

    /// The 1.0 map: decimal lines (a count, then offset and length pairs), padded to 512 bytes.
    fn read_map(&mut self) -> io::Result<std::collections::VecDeque<(u64, u64)>> {
        let mut consumed = 0u64;
        let mut line = || -> io::Result<u64> {
            let mut digits = Vec::new();
            loop {
                let mut b = [0u8; 1];
                self.inner.read_exact(&mut b)?;
                consumed += 1;
                match b[0] {
                    b'\n' => break,
                    d @ b'0'..=b'9' if digits.len() < 20 => digits.push(d),
                    _ => return Err(bad_map()),
                }
            }
            std::str::from_utf8(&digits)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(bad_map)
        };
        let count = line()?;
        if count > 1 << 20 {
            return Err(bad_map());
        }
        let mut map = std::collections::VecDeque::new();
        for _ in 0..count {
            let off = line()?;
            let len = line()?;
            map.push_back((off, len));
        }
        let pad = (512 - consumed % 512) % 512;
        io::copy(&mut (&mut self.inner).take(pad), &mut io::sink())?;
        Ok(map)
    }
}

fn bad_map() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "a damaged sparse-file map")
}

impl<R: Read> Read for SparseData<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.map.is_none() {
            let map = self.read_map()?;
            self.map = Some(map);
        }
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        let Some(map) = self.map.as_mut() else {
            return Ok(0);
        };
        while map
            .front()
            .is_some_and(|&(off, len)| self.pos >= off.saturating_add(len))
        {
            map.pop_front();
        }
        let want = buf
            .len()
            .min(usize::try_from(self.size - self.pos).unwrap_or(usize::MAX));
        let n = match map.front().copied() {
            Some((off, len)) if self.pos >= off => {
                if off.saturating_add(len) > self.size {
                    return Err(bad_map());
                }
                let n = want.min(usize::try_from(off + len - self.pos).unwrap_or(usize::MAX));
                let got = self.inner.read(&mut buf[..n])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "a sparse file's data ends early",
                    ));
                }
                got
            }
            Some((off, _)) => {
                let n = want.min(usize::try_from(off - self.pos).unwrap_or(usize::MAX));
                buf[..n].fill(0);
                n
            }
            None => {
                buf[..want].fill(0);
                want
            }
        };
        self.pos += n as u64;
        Ok(n)
    }
}

/// Which of the entry's names came from pax records, which are UTF-8: `(path, linkpath)`. A
/// header with `hdrcharset=BINARY` says its records aren't.
fn pax_names<R: Read>(e: &mut tar::Entry<'_, R>) -> (bool, bool) {
    let Ok(Some(exts)) = e.pax_extensions() else {
        return (false, false);
    };
    let (mut path, mut link, mut binary) = (false, false, false);
    for ext in exts.flatten() {
        match ext.key() {
            Ok("path") => path = true,
            Ok("linkpath") => link = true,
            Ok("hdrcharset") => binary = ext.value_bytes() == b"BINARY",
            _ => {}
        }
    }
    (path && !binary, link && !binary)
}

fn convert<R: Read>(
    id: usize,
    e: &mut tar::Entry<'_, R>,
    names: &NameDecoding,
) -> (Entry, Option<PaxSparse>) {
    let sparse = pax_sparse(e);
    let (pax_path, pax_link) = pax_names(e);
    let (raw, utf8) = match sparse.as_ref().and_then(|s| s.name.clone()) {
        Some(name) => (name.into_bytes(), true),
        None => (e.path_bytes().into_owned(), pax_path),
    };
    let path = names.decode(&raw, utf8, SystemPage::Ansi);
    let link = e
        .link_name_bytes()
        .map(|b| names.decode(&b, pax_link, SystemPage::Ansi))
        .unwrap_or_default();
    let t = e.header().entry_type();
    let kind = if t.is_dir() || (t.is_file() && path.ends_with('/')) {
        EntryKind::Dir
    } else if t.is_symlink() {
        EntryKind::Symlink { target: link }
    } else if t.is_hard_link() {
        EntryKind::Hardlink { target: link }
    } else if t.is_file() || t.is_contiguous() || t.is_gnu_sparse() {
        EntryKind::File
    } else {
        EntryKind::Other
    };
    let modified = pax_mtime(e).or_else(|| {
        e.header()
            .mtime()
            .ok()
            .and_then(|s| from_unix(i64::try_from(s).ok()?, 0))
    });
    let is_file = kind == EntryKind::File;
    let size = sparse.as_ref().map_or_else(|| e.size(), |s| s.size);
    let entry = Entry {
        id,
        path,
        raw_path: raw,
        size: is_file.then_some(size),
        packed_size: is_file.then(|| e.header().entry_size().ok()).flatten(),
        modified,
        crc32: None,
        method: None,
        encrypted: false,
        unix_mode: e.header().mode().ok(),
        dos_attrs: None,
        kind,
    };
    (entry, sparse.filter(|_| is_file))
}

/// An entry's data, expanded if it is a pax sparse file.
fn entry_data<'a, R: Read + 'a>(data: R, sparse: Option<&PaxSparse>) -> Box<dyn Read + 'a> {
    match sparse {
        Some(s) => Box::new(SparseData::new(data, s)),
        None => Box::new(data),
    }
}

/// The pax `mtime` record, which may have a fraction: `1700000000.25`.
fn pax_mtime<R: Read>(e: &mut tar::Entry<'_, R>) -> Option<SystemTime> {
    let exts = e.pax_extensions().ok()??;
    for ext in exts.flatten() {
        if ext.key() == Ok("mtime") {
            let v = ext.value().ok()?;
            let (secs, frac) = v.split_once('.').unwrap_or((v, ""));
            let secs: i64 = secs.parse().ok()?;
            let nanos: u32 = format!("{frac:0<9}").get(..9)?.parse().ok()?;
            return from_unix(secs, if secs < 0 { 0 } else { nanos });
        }
    }
    None
}

pub struct TarReader {
    source: Source,
    index: Option<Vec<Entry>>,
    spans: Vec<Span>,
    /// The archive behind the reader `open_entry` returns, when it had to rescan.
    scan: Option<tar::Archive<Box<dyn Read + Send>>>,
    file: Option<BufReader<CountingReader<Input>>>,
}

impl TarReader {
    pub fn new(source: Source) -> Self {
        Self {
            source,
            index: None,
            spans: Vec::new(),
            scan: None,
            file: None,
        }
    }

    fn plain(&self) -> bool {
        self.source.codecs.is_empty()
    }

    /// One pass over the archive: builds the index if there is none yet, and hands selected
    /// entries to `visit`'s sink on the way.
    fn pass(
        &mut self,
        mut visit: Option<(&Selection, &mut dyn EntrySink)>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
        meter.entries_total = self.index.as_ref().map(|i| i.len() as u64);
        let mut index = Vec::new();
        let mut spans = Vec::new();
        if self.plain() {
            let file = BufReader::with_capacity(BUF_SIZE, self.source.open_file()?);
            let mut ar = tar::Archive::new(file);
            let entries = ar.entries_with_seek().map_err(|e| tar_error(&e))?;
            walk_entries(
                entries,
                &self.source,
                &mut meter,
                &mut visit,
                &mut index,
                &mut spans,
                cx,
            )?;
        } else {
            let mut ar = tar::Archive::new(self.source.open_stream()?);
            let entries = ar.entries().map_err(|e| tar_error(&e))?;
            walk_entries(
                entries,
                &self.source,
                &mut meter,
                &mut visit,
                &mut index,
                &mut spans,
                cx,
            )?;
        }
        if self.index.is_none() {
            self.index = Some(index);
            self.spans = spans;
        }
        Ok(())
    }

    fn index(&mut self, cx: &mut dyn Ctx) -> Result<&[Entry]> {
        if self.index.is_none() {
            self.pass(None, cx)?;
        }
        Ok(self.index.as_deref().unwrap_or_default())
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_entries<R: Read>(
    entries: tar::Entries<'_, R>,
    source: &Source,
    meter: &mut Meter,
    visit: &mut Option<(&Selection, &mut dyn EntrySink)>,
    index: &mut Vec<Entry>,
    spans: &mut Vec<Span>,
    cx: &mut dyn Ctx,
) -> Result<()> {
    let mut id = 0usize;
    for item in entries {
        cx.check()?;
        let mut e = item.map_err(|e| tar_error(&e))?;
        if is_meta(e.header().entry_type()) {
            continue;
        }
        source.limits.check_entries(id as u64 + 1)?;
        let (entry, sparse) = convert(id, &mut e, &source.names);
        let contiguous = entry.kind == EntryKind::File
            && !e.header().entry_type().is_gnu_sparse()
            && sparse.is_none();
        spans.push(contiguous.then(|| (e.raw_file_position(), e.size())));
        if let Some((sel, sink)) = visit.as_mut()
            && sel.matches(&entry)
        {
            meter.entries_done = id as u64;
            meter.current = Some(entry.path.clone());
            let mut mcx = MeteredCtx::new(cx, meter);
            mcx.report();
            if entry.kind == EntryKind::File {
                let mut data = source.guard(entry_data(&mut e, sparse.as_ref()));
                sink.entry(&entry, &mut data, &mut mcx)?;
            } else {
                sink.entry(&entry, &mut io::empty(), &mut mcx)?;
            }
        }
        index.push(entry);
        id += 1;
    }
    meter.entries_done = id as u64;
    MeteredCtx::new(cx, meter).report();
    Ok(())
}

impl ArchiveReader for TarReader {
    fn format(&self) -> FormatId {
        FormatId::Tar
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, cx: &mut dyn Ctx) -> Result<&[Entry]> {
        self.index(cx)
    }

    fn info(&mut self, cx: &mut dyn Ctx) -> Result<ArchiveInfo> {
        self.index(cx)?;
        Ok(ArchiveInfo {
            format: FormatId::Tar,
            codecs: self.source.codecs.clone(),
            methods: Vec::new(),
            comment: None,
            encryption: Encryption::None,
            // A compressed tar is one stream: entries can't be decoded on their own.
            solid: !self.plain(),
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        self.pass(Some((sel, sink)), cx)
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let index = self.index(cx)?;
        let entry = index
            .get(id)
            .ok_or_else(|| Error::new(crate::ErrorKind::NotFound, format!("no entry {id}")))?;
        // A hardlink reads as the last earlier entry with its target's path.
        let id = match &entry.kind {
            EntryKind::Hardlink { target } => {
                let target = normalize(target);
                index[..id]
                    .iter()
                    .rev()
                    .find(|e| normalize(&e.path) == target && e.kind == EntryKind::File)
                    .map(|e| e.id)
                    .ok_or_else(|| {
                        Error::corrupt(format!("hard link target `{target}` is missing"))
                    })?
            }
            EntryKind::File => id,
            _ => return Ok(Box::new(io::empty())),
        };
        if self.plain()
            && let Some(Some((offset, size))) = self.spans.get(id).copied()
        {
            let mut file = BufReader::with_capacity(BUF_SIZE, self.source.open_file()?);
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| Error::io("seeking in the tar", &e))?;
            let file = self.file.insert(file);
            return Ok(Box::new(self.source.guard(file.take(size))));
        }
        self.scan = Some(tar::Archive::new(self.source.open_stream()?));
        let Some(ar) = self.scan.as_mut() else {
            return Err(Error::corrupt("tar"));
        };
        let mut n = 0usize;
        for item in ar.entries().map_err(|e| tar_error(&e))? {
            cx.check()?;
            let mut e = item.map_err(|e| tar_error(&e))?;
            if is_meta(e.header().entry_type()) {
                continue;
            }
            if n == id {
                let (_, sparse) = convert(n, &mut e, &self.source.names);
                return Ok(Box::new(self.source.guard(entry_data(e, sparse.as_ref()))));
            }
            n += 1;
        }
        Err(Error::corrupt(format!(
            "entry {id} vanished on a second pass"
        )))
    }
}

/// One item of a tar as it is stored (docs/M5.md §3.5): an entry's header blocks with the
/// extension records before it (pax `x`, GNU `L` and `K`) and any GNU sparse extension blocks
/// after it, or a global pax header (`g`), which isn't an entry.
#[derive(Debug, Clone)]
struct RawItem {
    /// The extension records before the main header, each with its data: (type, bytes).
    exts: Vec<(u8, Vec<u8>)>,
    /// The main header.
    main: [u8; 512],
    /// GNU sparse extension blocks after the main header.
    after: Vec<u8>,
    /// The pax records that apply to the entry, in order.
    pax: Vec<(Vec<u8>, Vec<u8>)>,
    global: bool,
    /// The data after the headers, padded to 512 bytes.
    data: u64,
}

impl RawItem {
    fn write_headers(&self, out: &mut dyn Write) -> io::Result<()> {
        for (_, b) in &self.exts {
            out.write_all(b)?;
        }
        // A global header is all in `exts`: a zero block after it would end the archive.
        if !self.global {
            out.write_all(&self.main)?;
            out.write_all(&self.after)?;
        }
        Ok(())
    }
}

/// The most extension data one entry may have: its pax records and long names.
const MAX_EXT: u64 = 16 << 20;

fn padded(n: u64) -> Option<u64> {
    n.checked_add(511).map(|n| n & !511)
}

/// A header's numeric field: octal, or GNU's base-256 when the high bit is set.
fn numeric(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = u64::from(field[0] & 0x7F);
        for &b in &field[1..] {
            v = v.checked_mul(256)?.checked_add(u64::from(b))?;
        }
        return Some(v);
    }
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ' || b == 0)
        .take_while(|&b| b != 0 && b != b' ')
        .collect();
    if digits.is_empty() {
        return Some(0);
    }
    octal(&digits)
}

/// Parses pax records (`LEN key=value\n`), skipping any it can't read.
fn pax_records(mut data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let Some(sp) = data.iter().position(|&b| b == b' ') else {
            break;
        };
        let Some(len) = std::str::from_utf8(&data[..sp])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&l| l > sp + 1 && l <= data.len())
        else {
            break;
        };
        let rec = &data[sp + 1..len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            out.push((rec[..eq].to_vec(), rec[eq + 1..].to_vec()));
        }
        data = &data[len..];
    }
    out
}

/// One pax record, with its length counting itself.
fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let base = key.len() + value.len() + 3;
    let mut len = base + base.to_string().len();
    if len.to_string().len() + base != len {
        len = base + len.to_string().len();
    }
    let mut r = format!("{len} ").into_bytes();
    r.extend_from_slice(key);
    r.push(b'=');
    r.extend_from_slice(value);
    r.push(b'\n');
    r
}

/// Reads exactly `buf.len()` bytes, or none at the end of the input.
fn read_block<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) if n == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the tar ends inside a header",
                ));
            }
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// The next item, or `None` at the end-of-archive block (or the end of the input), as the tar
/// crate reads them.
fn next_item<R: Read + ?Sized>(r: &mut R) -> Result<Option<RawItem>> {
    let mut exts = Vec::new();
    let mut pax = Vec::new();
    let mut ext_bytes = 0u64;
    loop {
        let mut h = [0u8; 512];
        if !read_block(r, &mut h).map_err(|e| tar_error(&e))? {
            return if exts.is_empty() {
                Ok(None)
            } else {
                Err(Error::corrupt(
                    "tar: extension records with no entry after them",
                ))
            };
        }
        if h.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        if !checksum_ok(&h) {
            return Err(Error::corrupt("tar: archive header checksum mismatch"));
        }
        let kind = h[156];
        let mut size = numeric(&h[124..136])
            .ok_or_else(|| Error::corrupt("tar: a header's size is damaged"))?;
        if matches!(kind, b'x' | b'g' | b'L' | b'K') {
            ext_bytes = ext_bytes.saturating_add(size);
            if ext_bytes > MAX_EXT {
                return Err(Error::limit(
                    "tar: an entry's extension records are over 16 MiB",
                ));
            }
            let len = padded(size).ok_or_else(|| Error::corrupt("tar: a size overflows"))?;
            let mut data = vec![0u8; usize::try_from(len).unwrap_or(0)];
            if !read_block(r, &mut data).map_err(|e| tar_error(&e))? && len > 0 {
                return Err(Error::corrupt("tar: an extension record is cut short"));
            }
            let body = &data[..usize::try_from(size).unwrap_or(0)];
            if kind == b'g' {
                let mut bytes = h.to_vec();
                bytes.extend_from_slice(&data);
                return Ok(Some(RawItem {
                    exts: vec![(kind, bytes)],
                    main: [0; 512],
                    after: Vec::new(),
                    pax: Vec::new(),
                    global: true,
                    data: 0,
                }));
            }
            if kind == b'x' {
                pax.extend(pax_records(body));
            }
            let mut bytes = h.to_vec();
            bytes.extend_from_slice(&data);
            exts.push((kind, bytes));
            continue;
        }
        if let Some((_, v)) = pax.iter().rev().find(|(k, _)| k == b"size")
            && let Some(n) = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok())
        {
            size = n;
        }
        let mut after = Vec::new();
        // GNU sparse files: extension blocks follow while the header says there are more.
        if kind == b'S' && h[482] != 0 {
            loop {
                let mut ext = [0u8; 512];
                if !read_block(r, &mut ext).map_err(|e| tar_error(&e))? {
                    return Err(Error::corrupt("tar: a sparse file's map is cut short"));
                }
                after.extend_from_slice(&ext);
                if after.len() as u64 > MAX_EXT {
                    return Err(Error::limit("tar: a sparse file's map is over 16 MiB"));
                }
                if ext[504] == 0 {
                    break;
                }
            }
        }
        return Ok(Some(RawItem {
            exts,
            main: h,
            after,
            pax,
            global: false,
            data: padded(size).ok_or_else(|| Error::corrupt("tar: a size overflows"))?,
        }));
    }
}

/// `s` with every byte outside printable ASCII made `_`, for the name fields of a header whose
/// real name is in a pax record, and cut to `max` bytes (keeping the end).
fn ascii_stand_in(s: &str, max: usize) -> Vec<u8> {
    let b: Vec<u8> = s
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c as u8
            } else {
                b'_'
            }
        })
        .collect();
    b[b.len().saturating_sub(max)..].to_vec()
}

fn set_checksum(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let field = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(field.as_bytes());
}

/// The headers of `item` under a new name and link target (docs/M5.md §3.5): a pax header of
/// BeeZip's with `path` and `linkpath` and the entry's other records, its GNU long-name records
/// dropped, and the main header's name fields set to ASCII stand-ins.
fn renamed_headers(item: &RawItem, path: Option<&str>, link: Option<&str>) -> Vec<u8> {
    let mut records: Vec<(Vec<u8>, Vec<u8>)> = item
        .pax
        .iter()
        .filter(|(k, _)| !(path.is_some() && k == b"path") && !(link.is_some() && k == b"linkpath"))
        .cloned()
        .collect();
    if let Some(p) = path {
        for (k, v) in &mut records {
            if k == b"GNU.sparse.name" {
                *v = p.as_bytes().to_vec();
            }
        }
        records.push((b"path".to_vec(), p.as_bytes().to_vec()));
    }
    if let Some(l) = link {
        records.push((b"linkpath".to_vec(), l.as_bytes().to_vec()));
    }
    let body: Vec<u8> = records.iter().flat_map(|(k, v)| pax_record(k, v)).collect();

    let mut main = item.main;
    if let Some(p) = path {
        main[..100].fill(0);
        let name = ascii_stand_in(p, 100);
        main[..name.len()].copy_from_slice(&name);
        // ustar's prefix field; GNU headers keep other fields there.
        if &main[257..263] == b"ustar\0" {
            main[345..500].fill(0);
        }
    }
    if let Some(l) = link {
        main[157..257].fill(0);
        let name = ascii_stand_in(l, 100);
        main[157..157 + name.len()].copy_from_slice(&name);
    }
    set_checksum(&mut main);

    let mut x = [0u8; 512];
    let name = ascii_stand_in(&format!("PaxHeaders/{}", path.unwrap_or_default()), 100);
    x[..name.len()].copy_from_slice(&name);
    x[100..108].copy_from_slice(b"0000644\0");
    x[108..116].copy_from_slice(b"0000000\0");
    x[116..124].copy_from_slice(b"0000000\0");
    x[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
    x[136..148].copy_from_slice(&item.main[136..148]);
    x[156] = b'x';
    x[257..263].copy_from_slice(b"ustar\0");
    x[263..265].copy_from_slice(b"00");
    set_checksum(&mut x);

    let mut out = x.to_vec();
    out.extend_from_slice(&body);
    out.resize(out.len().div_ceil(512) * 512, 0);
    for (kind, bytes) in &item.exts {
        let dropped =
            *kind == b'x' || (path.is_some() && *kind == b'L') || (link.is_some() && *kind == b'K');
        if !dropped {
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&main);
    out.extend_from_slice(&item.after);
    out
}

impl TarReader {
    /// Writes `keep` to `out` as they are stored (docs/M5.md §3.5), from one pass over the tar:
    /// kept entries byte for byte, renamed ones and links whose target moved with new headers,
    /// global pax headers where they were. The new entries and the end blocks come after.
    fn copy_into(&mut self, out: &mut dyn Write, keep: &[Keep], cx: &mut dyn Ctx) -> Result<u64> {
        let index = self.index(cx)?.to_vec();
        let mut paths: Vec<Option<String>> = vec![None; index.len()];
        for k in keep {
            if let Some(p) = paths.get_mut(k.id) {
                *p = Some(k.path.clone());
            }
        }
        // A hard link names an earlier entry by path; when that one moves, so does the link.
        let mut links: Vec<Option<String>> = vec![None; index.len()];
        for (id, e) in index.iter().enumerate() {
            let (EntryKind::Hardlink { target }, Some(_)) = (&e.kind, &paths[id]) else {
                continue;
            };
            let t = normalize(target);
            if let Some(to) = index[..id]
                .iter()
                .rposition(|x| normalize(&x.path) == t)
                .and_then(|i| paths[i].as_ref().filter(|p| normalize(p) != t))
            {
                links[id] = Some(normalize(to));
            }
        }
        let mut stream: Box<dyn Read> = if self.plain() {
            Box::new(BufReader::with_capacity(BUF_SIZE, self.source.open_file()?))
        } else {
            Box::new(self.source.open_stream()?)
        };
        let werr = |e: io::Error| write_error(&e);
        let mut id = 0usize;
        let mut copied = 0u64;
        while let Some(item) = next_item(&mut stream)? {
            cx.check()?;
            if item.global {
                item.write_headers(out).map_err(werr)?;
                continue;
            }
            let entry = index
                .get(id)
                .ok_or_else(|| Error::corrupt("tar: more entries than the listing has"))?;
            let mut data = (&mut stream).take(item.data);
            match &paths[id] {
                None => {
                    crate::io::drain(&mut data, cx)?;
                }
                Some(p) => {
                    let renamed = (*p != entry.path).then_some(p.as_str());
                    let link = links[id].as_deref();
                    if renamed.is_none() && link.is_none() {
                        item.write_headers(out).map_err(werr)?;
                    } else {
                        out.write_all(&renamed_headers(&item, renamed, link))
                            .map_err(werr)?;
                    }
                    let n = crate::io::copy(&mut data, out, cx)?;
                    if n != item.data {
                        return Err(Error::corrupt("tar: an entry's data is cut short"));
                    }
                    copied += 1;
                }
            }
            id += 1;
        }
        if id != index.len() {
            return Err(Error::corrupt("tar: fewer entries than the listing has"));
        }
        Ok(copied)
    }
}

/// Writes a tar to `out`, which a codec encoder may wrap.
pub struct TarWriter<'a> {
    builder: tar::Builder<Box<dyn FinishWrite + 'a>>,
    /// `out` is a codec's encoder, so kept entries are encoded again.
    compressed: bool,
}

impl<'a> TarWriter<'a> {
    pub fn new(out: Box<dyn FinishWrite + 'a>) -> Self {
        let mut builder = tar::Builder::new(out);
        builder.mode(tar::HeaderMode::Complete);
        Self {
            builder,
            compressed: false,
        }
    }

    /// The same, writing through a codec's encoder.
    pub fn compressed(out: Box<dyn FinishWrite + 'a>) -> Self {
        Self {
            compressed: true,
            ..Self::new(out)
        }
    }
}

fn mode_for(entry: &NewEntry) -> u32 {
    let default = match entry.kind {
        NewKind::Dir => 0o755,
        NewKind::Symlink { .. } => 0o777,
        NewKind::File => 0o644,
    };
    match entry.unix_mode {
        Some(m) if cfg!(unix) => m & 0o7777,
        _ => default,
    }
}

impl ArchiveWriter for TarWriter<'_> {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let mut h = tar::Header::new_gnu();
        let mtime = entry.modified.map(to_unix).unwrap_or(0).max(0);
        h.set_mtime(mtime.unsigned_abs());
        h.set_mode(mode_for(entry));
        h.set_uid(0);
        h.set_gid(0);
        let err = |e: io::Error| {
            let err = write_error(&e);
            match err.kind {
                crate::ErrorKind::Io if e.raw_os_error().is_none() => {
                    Error::invalid_args(format!("cannot store `{}` in a tar: {e}", entry.path))
                }
                _ => err,
            }
        };
        match &entry.kind {
            NewKind::File => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(entry.size);
                let exact = ExactReader::new(data, entry.size);
                self.builder
                    .append_data(&mut h, &entry.path, Checked::new(exact, cx))
                    .map_err(err)
            }
            NewKind::Dir => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                self.builder
                    .append_data(&mut h, format!("{}/", entry.path), io::empty())
                    .map_err(err)
            }
            NewKind::Symlink { target } => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                self.builder
                    .append_link(&mut h, &entry.path, target)
                    .map_err(err)
            }
        }
    }

    fn copy_from(
        &mut self,
        source: &mut dyn ArchiveReader,
        keep: &[Keep],
        cx: &mut dyn Ctx,
    ) -> Result<Copied> {
        let Some(r) = source.as_any_mut().downcast_mut::<TarReader>() else {
            return Ok(Copied::nothing(keep));
        };
        let n = r.copy_into(self.builder.get_mut(), keep, cx)?;
        Ok(if self.compressed {
            Copied {
                recompressed: n,
                ..Copied::default()
            }
        } else {
            Copied {
                copied: n,
                ..Copied::default()
            }
        })
    }

    fn finish(self: Box<Self>, _: &mut dyn Ctx) -> Result<()> {
        let out = self.builder.into_inner().map_err(|e| write_error(&e))?;
        out.finish().map_err(|e| write_error(&e))
    }
}

/// What [`walk_nested`] calls with each entry, its data and the context.
pub(crate) type EachEntry<'a> = dyn FnMut(Entry, &mut dyn Read, &mut dyn Ctx) -> Result<()> + 'a;

/// Walks the tar in `r` from the start, as [`TarReader`] lists one, for a tar inside another
/// format (a Debian package's), which names its entries in its own way. `each` gets every
/// entry, with ids counted from 0, and its data (empty for anything but a file).
pub(crate) fn walk_nested(
    r: Box<dyn Read + Send + '_>,
    names: &NameDecoding,
    each: &mut EachEntry<'_>,
    cx: &mut dyn Ctx,
) -> Result<()> {
    let mut ar = tar::Archive::new(r);
    let mut n = 0usize;
    for item in ar.entries().map_err(|e| tar_error(&e))? {
        cx.check()?;
        let mut e = item.map_err(|e| tar_error(&e))?;
        if is_meta(e.header().entry_type()) {
            continue;
        }
        let (entry, sparse) = convert(n, &mut e, names);
        if entry.kind == EntryKind::File {
            let mut data = entry_data(&mut e, sparse.as_ref());
            each(entry, &mut data, cx)?;
        } else {
            each(entry, &mut io::empty(), cx)?;
        }
        n += 1;
    }
    Ok(())
}

/// A tar inside another format, kept open so one of its entries can be read
/// ([`ArchiveReader::open_entry`]).
pub(crate) struct Nested {
    archive: tar::Archive<Box<dyn Read + Send>>,
}

impl Nested {
    pub(crate) fn new(r: Box<dyn Read + Send>) -> Self {
        Self {
            archive: tar::Archive::new(r),
        }
    }

    /// The data of the `n`th entry, counted as [`walk_nested`] counts them.
    pub(crate) fn open(
        &mut self,
        n: usize,
        names: &NameDecoding,
        cx: &mut dyn Ctx,
    ) -> Result<Box<dyn Read + '_>> {
        let mut i = 0usize;
        for item in self.archive.entries().map_err(|e| tar_error(&e))? {
            cx.check()?;
            let mut e = item.map_err(|e| tar_error(&e))?;
            if is_meta(e.header().entry_type()) {
                continue;
            }
            if i == n {
                let (_, sparse) = convert(n, &mut e, names);
                return Ok(entry_data(e, sparse.as_ref()));
            }
            i += 1;
        }
        Err(Error::corrupt(format!(
            "tar: entry {n} vanished on a second pass"
        )))
    }
}
