//! TAR, through the `tar` crate (0.4.46). This is the only file that names `tar::`.
//!
//! - Reading is one pass over `tar::Archive`; the crate handles pax and GNU long names. A plain
//!   `.tar` is seekable, so listing skips the data and `open_entry` seeks straight to an
//!   entry. A compressed tar is decoded from the start each time.
//! - Regular and contiguous files are `File`, as are GNU sparse files (read expanded);
//!   directories, symlinks and hardlinks keep their kinds; devices and FIFOs are `Other`.
//! - Writing uses GNU headers, so long names get `././@LongLink` entries. Modes are real on
//!   Unix and 0o644/0o755 on Windows, which has no exec bit.

use std::{
    io::{self, BufReader, Read, Seek, SeekFrom},
    time::SystemTime,
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, NewEntry, NewKind, Selection, normalize,
};
use crate::{
    Ctx, Error, Meter, MeteredCtx, Result,
    codec::FinishWrite,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, Checked, CountingReader, ExactReader, read_error, write_error},
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

fn convert<R: Read>(id: usize, e: &mut tar::Entry<'_, R>) -> (Entry, Option<PaxSparse>) {
    let sparse = pax_sparse(e);
    let raw = match sparse.as_ref().and_then(|s| s.name.clone()) {
        Some(name) => name.into_bytes(),
        None => e.path_bytes().into_owned(),
    };
    let path = String::from_utf8_lossy(&raw).into_owned();
    let link = e
        .link_name_bytes()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
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
        let (entry, sparse) = convert(id, &mut e);
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
                let (_, sparse) = convert(n, &mut e);
                return Ok(Box::new(self.source.guard(entry_data(e, sparse.as_ref()))));
            }
            n += 1;
        }
        Err(Error::corrupt(format!(
            "entry {id} vanished on a second pass"
        )))
    }
}

/// Writes a tar to `out`, which a codec encoder may wrap.
pub struct TarWriter<'a> {
    builder: tar::Builder<Box<dyn FinishWrite + 'a>>,
}

impl<'a> TarWriter<'a> {
    pub fn new(out: Box<dyn FinishWrite + 'a>) -> Self {
        let mut builder = tar::Builder::new(out);
        builder.mode(tar::HeaderMode::Complete);
        Self { builder }
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

    fn finish(self: Box<Self>) -> Result<()> {
        let out = self.builder.into_inner().map_err(|e| write_error(&e))?;
        out.finish().map_err(|e| write_error(&e))
    }
}
