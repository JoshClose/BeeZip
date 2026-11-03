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
    fs::File,
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
    source::Source,
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

fn convert<R: Read>(id: usize, e: &mut tar::Entry<'_, R>) -> Entry {
    let raw = e.path_bytes().into_owned();
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
    Entry {
        id,
        path,
        raw_path: raw,
        size: is_file.then(|| e.size()),
        packed_size: is_file.then(|| e.header().entry_size().ok()).flatten(),
        modified,
        crc32: None,
        method: None,
        encrypted: false,
        unix_mode: e.header().mode().ok(),
        dos_attrs: None,
        kind,
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
    scan: Option<tar::Archive<Box<dyn Read>>>,
    file: Option<BufReader<CountingReader<File>>>,
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
        let entry = convert(id, &mut e);
        let contiguous = entry.kind == EntryKind::File && !e.header().entry_type().is_gnu_sparse();
        spans.push(contiguous.then(|| (e.raw_file_position(), e.size())));
        if let Some((sel, sink)) = visit.as_mut()
            && sel.matches(&entry)
        {
            meter.entries_done = id as u64;
            meter.current = Some(entry.path.clone());
            let mut mcx = MeteredCtx::new(cx, meter);
            mcx.report();
            if entry.kind == EntryKind::File {
                let mut data = source.guard(&mut e);
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
            let e = item.map_err(|e| tar_error(&e))?;
            if is_meta(e.header().entry_type()) {
                continue;
            }
            if n == id {
                return Ok(Box::new(self.source.guard(e)));
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
