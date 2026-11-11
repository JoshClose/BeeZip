//! WIM, ESD and SWM images, BeeZip's own reader (docs/M8.md §5), read only.
//!
//! - **What's read:** WIM 1.13 and ESD 0.14; resources stored, or in chunks of XPRESS, LZX (up
//!   to 2 MiB) or LZMS (on Windows, through its Compression API: [`lzms_win`]); solid resources
//!   of each method, laid end to end in table order; chunks up to 64 MiB; several images; split
//!   sets (`.swm`, opened from any part, by name and else by GUID); files over 4 GiB; empty
//!   images, and none. The container is [`container`]; each image's tree, [`meta`].
//! - **Refused** as `UnsupportedOperation`, so that 7-Zip may read it when it's installed: other
//!   versions, unknown compression flags or solid methods, chunks that really hold more than
//!   64 MiB, resources spanning a split set's parts, wimlib's pipable WIMs, encrypted ESDs, and
//!   LZMS on Linux and macOS or where `cabinet.dll` can't be loaded. Damage is `Corrupt`.
//! - **The listing** ([`listing`]): a folder per image when there are several (`1/`, `2/`…, as
//!   7-Zip names them), straight at the top when there's one, the images' names in Info; no
//!   `[1].xml` or `[DELETED]/` (Info counts the blobs no image refers to); alternate streams as
//!   `file:stream`; further names of a hard link group as hard links; reparse points decoded as
//!   NTFS's are, a target DISM or wimlib fixed at capture made relative inside the image; WOF,
//!   deduplicated and EFS files listed, and reading them `UnsupportedOperation`; DOS attributes
//!   and the modified time to 100 ns.
//! - **Integrity:** every blob's SHA-1 is checked when it's read, and each image's metadata when
//!   the image opens. The integrity table, which means reading the whole file, is checked by
//!   `archive.test` only (decision 8).
//! - **Speed** ([`pipe`]): chunks decode on `[extract] threads` workers, at most
//!   `decoder_memory` of them ahead; extraction goes in the data's order, and one decode serves
//!   every file that shares a blob (the sink copies the first, or a copy kept in memory up to
//!   [`KEEP`] is handed over); `open_entry` keeps the last chunk decoded.
//! - **Limits:** the lookup table and a metadata resource are read whole up to 256 MiB, all
//!   images' metadata up to [`MAX_METADATA_TOTAL`], the XML up to 16 MiB (past it, it's skipped
//!   with a warning). The lookup table and the XML must be stored, as every writer stores them
//!   (a compressed lookup table is `UnsupportedOperation`, a compressed XML skipped), so they
//!   hold no more than the file's bytes. Before extracting, each selected file's size is held to the ratio limit
//!   against its share of its resource's bytes, and their total to `max_total_bytes`; while it's
//!   read, its share is what the ratio counts as its input.

mod container;
mod listing;
#[cfg(windows)]
mod lzms_win;
mod meta;
mod pipe;
#[cfg(test)]
mod tests;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read},
    sync::{Arc, Mutex},
};

use self::{
    container::{Container, FileAt, Hash, Loc, Locked, Method, Part, ReadAt, ZERO, bad},
    listing::{Image, Item},
    meta::Dentry,
    pipe::{BlobReader, ChunkCache, Decoders, Plan, Want},
};
use super::{
    ArchiveInfo, ArchiveReader, Encryption, Entry, EntrySink, FormatId, Selection,
    reparse::MAX_DATA,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result, TestReport, TestSink,
    backend::{External, ExternalInfo, LevelProperty},
    io::{Counter, copy},
    limits::{Guarded, RatioGuard},
    safefs::Partial,
    source::Source,
};

/// A metadata resource, read whole.
const MAX_METADATA: u64 = 256 << 20;
/// All images' metadata together (install.esd's seven are 220 MB).
pub const MAX_METADATA_TOTAL: u64 = 2 << 30;
/// The bytes of an image's paths.
const MAX_PATH_BYTES: u64 = 256 << 20;
/// A blob shared by several selected files is kept in memory up to this, for a sink that can't
/// copy the first file written.
pub const KEEP: u64 = 64 << 20;
/// Warnings opening gives, each different; the rest are counted.
const MAX_WARNINGS: usize = 50;

/// Opens a WIM, ESD or split set (see the module's notes).
pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Box<dyn ArchiveReader>> {
    Ok(Box::new(WimReader::open(source, cx)?))
}

fn lzms_available() -> bool {
    #[cfg(windows)]
    {
        lzms_win::available()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Errors that stop a whole job rather than one entry.
fn fatal(e: &Error) -> bool {
    matches!(
        e.kind,
        ErrorKind::Cancelled | ErrorKind::LimitExceeded | ErrorKind::Io
    )
}

pub struct WimReader {
    source: Source,
    c: Container,
    entries: Vec<Entry>,
    items: Vec<Item>,
    methods: Vec<Cow<'static, str>>,
    properties: Vec<LevelProperty>,
    notes: Vec<String>,
    /// For `open_entry`: its decoders, and the last chunk decoded.
    dec: Decoders,
    cache: ChunkCache,
    /// Keeps an image spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl WimReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (first, spool) = first_part(&source, cx)?;
        let mut warnings = Vec::new();
        let mut c = Container::open(first, &mut |w| warnings.push(w))?;
        c.read_xml()?;
        warnings.append(&mut c.warnings);
        if c.uses_lzms() && !lzms_available() {
            return Err(container::unsupported(if cfg!(windows) {
                "it's compressed with LZMS, which BeeZip reads through Windows' Compression API, \
                 and cabinet.dll can't be loaded"
            } else {
                "it's compressed with LZMS, which BeeZip reads only on Windows"
            }));
        }
        let threads = crate::codec::resolve_threads(source.threads) as usize;
        let limits = source.limits.clone();
        // Kept up to a point: a damaged image can have a warning for each of millions of names.
        let mut dropped = 0usize;
        let mut warn = |w: String| {
            if warnings.len() < 20 * MAX_WARNINGS {
                warnings.push(w);
            } else {
                dropped += 1;
            }
        };
        let images = load_images(&c, &limits, threads, cx, &mut warn)?;
        cx.check()?;
        let reparse = read_reparse(&c, &images, threads, limits.decoder_memory, cx, &mut warn)?;
        let listing = listing::list(&c, &images, &reparse, &limits, &mut warn)?;
        drop(images);
        let name = source.file_name();
        // Once each (several blobs of one damaged chunk fail alike), and not without end.
        let mut said = HashSet::new();
        let mut more = dropped;
        for w in warnings {
            if said.contains(&w) {
                continue;
            }
            if said.len() >= MAX_WARNINGS {
                more += 1;
                continue;
            }
            cx.warn(format!("{name}: {w}"));
            said.insert(w);
        }
        if more > 0 {
            cx.warn(format!("{name}: and {more} more warnings like these"));
        }
        let mut r = Self {
            source,
            methods: c
                .methods()
                .into_iter()
                .map(|m| Cow::Borrowed(m.name()))
                .collect(),
            properties: Vec::new(),
            notes: Vec::new(),
            entries: listing.entries,
            items: listing.items,
            c,
            dec: Decoders::default(),
            cache: ChunkCache::default(),
            _spool: spool,
        };
        r.describe(listing.unreferenced, listing.fixed);
        Ok(r)
    }

    /// What Info shows (decision 8).
    fn describe(&mut self, unreferenced: usize, fixed: usize) {
        let c = &self.c;
        let mut props = vec![("Version", c.header.version_name())];
        props.push(("Method", self.methods.join(", ")));
        if c.method != Method::None {
            props.push(("Chunk Size", c.chunk.to_string()));
        }
        props.push(("Images", c.images.len().to_string()));
        if c.header.boot_index > 0 {
            props.push(("Boot Image", c.header.boot_index.to_string()));
        }
        if c.parts.len() > 1 {
            props.push(("Parts", c.parts.len().to_string()));
        }
        if c.parts
            .iter()
            .flatten()
            .any(|p| p.header.integrity.size > 0)
        {
            props.push(("Integrity Table", "yes".to_owned()));
        }
        self.properties = props
            .into_iter()
            .map(|(n, v)| LevelProperty {
                level: "wim".to_owned(),
                name: n.to_owned(),
                value: v,
            })
            .collect();
        for img in &c.images {
            if let Some(n) = &img.name {
                self.properties.push(LevelProperty {
                    level: "wim".to_owned(),
                    name: format!("Image {}", img.index),
                    value: n.clone(),
                });
            }
        }
        if c.images.len() > 1 {
            self.notes.push(
                "Each image is a folder named by its number, as 7-Zip names them; their names \
                 are above."
                    .to_owned(),
            );
        }
        match unreferenced {
            0 => {}
            1 => self.notes.push(
                "1 blob no image refers to isn't listed (7-Zip lists it under [DELETED])."
                    .to_owned(),
            ),
            n => self.notes.push(format!(
                "{n} blobs no image refers to aren't listed (7-Zip lists them under [DELETED])."
            )),
        }
        match fixed {
            0 => {}
            1 => self.notes.push(
                "1 link was fixed at capture to point inside the image; it's listed relative to \
                 where it is."
                    .to_owned(),
            ),
            n => self.notes.push(format!(
                "{n} links were fixed at capture to point inside the image; they're listed \
                 relative to where they are."
            )),
        }
    }

    /// The limits against what the selected files claim, before anything is read.
    fn check_limits(&self, selected: &[bool]) -> Result<()> {
        let limits = &self.source.limits;
        let mut total = 0u64;
        for (id, (e, item)) in self.entries.iter().zip(&self.items).enumerate() {
            if !selected[id] {
                continue;
            }
            match item {
                Item::Blob(h) => {
                    let size = e.size.unwrap_or(0);
                    total = total.saturating_add(size);
                    let packed = self.c.blobs.get(h).map_or(0, |b| self.c.packed(b));
                    if let Some(max) = limits.max_ratio
                        && size > limits.ratio_grace
                        && size / packed.max(1) > max
                    {
                        return Err(Error::limit(format!(
                            "`{}` claims {size} bytes from {packed} in the image, more than \
                             {max}:1 (limit `max_ratio`)",
                            e.path
                        )));
                    }
                }
                // Written as a copy of its file.
                Item::Link(f) => {
                    total = total
                        .saturating_add(self.entries.get(*f).and_then(|e| e.size).unwrap_or(0));
                }
                _ => {}
            }
        }
        if let Some(max) = limits.max_total_bytes
            && total > max
        {
            return Err(Error::limit(format!(
                "the selected entries claim {total} bytes, more than {max} (limit \
                 `max_total_bytes`)"
            )));
        }
        Ok(())
    }

    fn threads(&self) -> usize {
        crate::codec::resolve_threads(self.source.threads) as usize
    }

    fn test_all(&mut self, cx: &mut dyn Ctx) -> Result<TestReport> {
        let mut sink = TestSink::default();
        match self.extract(&Selection::all(), &mut sink, cx) {
            Ok(()) => {}
            Err(e) if e.kind == ErrorKind::Corrupt => sink.report.record("", &e),
            Err(e) => return Err(e),
        }
        for e in self.c.check_integrity(self.threads(), cx)? {
            sink.report.record("", &e);
        }
        Ok(sink.report)
    }
}

/// The WIM's first input: the file, a numbered set or the file seen from an offset (read one
/// thread at a time), or, behind a codec, the decoded image spooled to a temporary file.
fn first_part(source: &Source, cx: &mut dyn Ctx) -> Result<(Part, Option<Partial>)> {
    let (input, len, path, spool): (Arc<dyn ReadAt>, u64, _, _) = if !source.codecs.is_empty() {
        let mut tmp = Partial::create_temp("beezip-spool.wim")?;
        let mut stream = source.guard(source.open_stream()?);
        copy(&mut stream, tmp.file_mut(), cx)?;
        tmp.close();
        let f = tmp.reopen()?;
        let len = f
            .metadata()
            .map_err(|e| Error::io("reading the spooled image", &e))?
            .len();
        (Arc::new(FileAt(f)), len, None, Some(tmp))
    } else if source.joined || source.offset > 0 {
        let input = source.input()?;
        let len = input.len();
        (Arc::new(Locked(Mutex::new(input))), len, None, None)
    } else {
        let f = File::open(&source.path)
            .map_err(|e| Error::io(format!("opening {}", source.path.display()), &e))?;
        let len = f
            .metadata()
            .map_err(|e| Error::io(format!("reading {}", source.path.display()), &e))?
            .len();
        (Arc::new(FileAt(f)), len, Some(source.path.clone()), None)
    };
    let header = container::header_of(&*input)?;
    Ok((
        Part {
            input,
            header,
            len,
            path,
        },
        spool,
    ))
}

/// Every image's metadata, read (in parallel), its SHA-1 checked, and walked.
fn load_images(
    c: &Container,
    limits: &crate::Limits,
    threads: usize,
    cx: &mut dyn Ctx,
    warn: &mut dyn FnMut(String),
) -> Result<Vec<Image>> {
    let mut wants: Vec<Want> = Vec::new();
    // The images each metadata resource is, by hash: an image appended twice is read once.
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut by_hash: HashMap<Hash, usize> = HashMap::new();
    let mut total = 0u64;
    for (i, img) in c.images.iter().enumerate() {
        if img.meta.original > MAX_METADATA {
            return Err(Error::limit(format!(
                "wim: image {}'s metadata is {} bytes, more than BeeZip reads ({MAX_METADATA})",
                img.index, img.meta.original
            )));
        }
        if img.hash != ZERO
            && let Some(&k) = by_hash.get(&img.hash)
        {
            groups[k].push(i);
            continue;
        }
        total = total.saturating_add(img.meta.original);
        if total > MAX_METADATA_TOTAL {
            return Err(Error::limit(format!(
                "wim: its images' metadata is more than BeeZip reads ({MAX_METADATA_TOTAL} bytes)"
            )));
        }
        by_hash.insert(img.hash, wants.len());
        wants.push(Want {
            key: wants.len(),
            hash: img.hash,
            loc: Loc::Res {
                part: img.part,
                res: img.meta,
            },
            size: img.meta.original,
        });
        groups.push(vec![i]);
    }
    let plan = Plan::new(c, &wants);
    let caps = meta::Caps {
        entries: limits.max_entries.unwrap_or(u64::MAX),
        path_bytes: MAX_PATH_BYTES,
    };
    let mut walked: Vec<Option<Vec<Dentry>>> = vec![None; c.images.len()];
    pipe::run(c, &plan, threads, limits.decoder_memory, &mut |k, cut| {
        cx.check()?;
        let index = groups[k].first().map_or(0, |&i| c.images[i].index);
        let mut data = Vec::with_capacity(usize::try_from(cut.size().min(1 << 20)).unwrap_or(0));
        cut.finish(Some(&mut data)).map_err(|e| {
            if fatal(&e) {
                e
            } else {
                Error::new(
                    e.kind,
                    format!(
                        "wim: image {index}'s metadata can't be read: {}",
                        e.message.trim_start_matches("wim: ")
                    ),
                )
            }
        })?;
        let mut w = |m: String| warn(format!("image {index}: {m}"));
        let ds = meta::walk(&data, caps, &mut w)?;
        for &i in &groups[k] {
            walked[i] = Some(ds.clone());
        }
        Ok(())
    })?;
    Ok(c.images
        .iter()
        .zip(walked)
        .map(|(img, ds)| Image {
            index: img.index,
            dentries: ds.unwrap_or_default(),
        })
        .collect())
}

/// The data of the reparse points whose tags need it (links, WOF), read together, so a solid
/// chunk holding several is decoded once.
fn read_reparse(
    c: &Container,
    images: &[Image],
    threads: usize,
    memory: u64,
    cx: &mut dyn Ctx,
    warn: &mut dyn FnMut(String),
) -> Result<HashMap<Hash, Vec<u8>>> {
    let mut want: HashSet<Hash> = HashSet::new();
    for d in images.iter().flat_map(|i| &i.dentries) {
        if d.is_reparse()
            && listing::wants_data(d.reparse_tag)
            && let (Some(h), _) = d.data()
            && h != ZERO
        {
            want.insert(h);
        }
    }
    let mut hashes: Vec<Hash> = want.into_iter().collect();
    hashes.sort_unstable();
    let mut wants = Vec::new();
    for h in &hashes {
        match c.blobs.get(h) {
            Some(b) if b.size <= MAX_DATA => wants.push(Want {
                key: wants.len(),
                hash: *h,
                loc: b.loc,
                size: b.size,
            }),
            Some(b) => warn(format!(
                "a reparse point's data of {} bytes, more than Windows allows; its link can't be \
                 read",
                b.size
            )),
            None => {}
        }
    }
    let mut out = HashMap::new();
    let plan = Plan::new(c, &wants);
    pipe::run(c, &plan, threads, memory, &mut |k, cut| {
        cx.check()?;
        let mut v = Vec::new();
        match cut.finish(Some(&mut v)) {
            Ok(()) => {
                out.insert(wants[k].hash, v);
            }
            Err(e) if fatal(&e) => return Err(e),
            Err(e) => warn(format!(
                "a reparse point's data can't be read: {}",
                e.message.trim_start_matches("wim: ")
            )),
        }
        Ok(())
    })?;
    Ok(out)
}

/// An entry's data, its errors naming it.
struct Named<R> {
    inner: R,
    path: String,
}

impl<R: Read> Read for Named<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            let err = Error::from_io(&e);
            if fatal(&err) || err.message.contains(&format!("`{}`", self.path)) {
                return e;
            }
            Error::new(
                err.kind,
                format!(
                    "wim: `{}`: {}",
                    self.path,
                    err.message.trim_start_matches("wim: ")
                ),
            )
            .into_io()
        })
    }
}

/// A blob's bytes, counted as its share of its resource's bytes on the input's counter as they
/// come, which is what the ratio limit and progress read; and kept, when they're to be handed
/// over again.
struct Counted<R> {
    inner: R,
    counter: Counter,
    share: u64,
    size: u64,
    delivered: u64,
    counted: u64,
    keep: Option<Vec<u8>>,
}

impl<R: Read> Counted<R> {
    fn new(inner: R, counter: Counter, share: u64, size: u64, keep: bool) -> Self {
        Self {
            inner,
            counter,
            share,
            size,
            delivered: 0,
            counted: 0,
            keep: keep.then(Vec::new),
        }
    }

    /// The rest, read and dropped (or kept): whether the whole blob was right.
    fn finish(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match self.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(Error::from_io(&e)),
            }
        }
    }
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(k) = &mut self.keep {
            k.extend_from_slice(&buf[..n]);
        }
        self.delivered += n as u64;
        let now = u64::try_from(
            u128::from(self.delivered) * u128::from(self.share) / u128::from(self.size.max(1)),
        )
        .unwrap_or(u64::MAX);
        self.counter.add(now.saturating_sub(self.counted));
        self.counted = now;
        Ok(n)
    }
}

/// A file whose data can't be read: its error, at the first read.
struct Failing(Error);

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self.0.clone().into_io())
    }
}

/// Hands a file BeeZip doesn't read, or can't find, to the sink: `FsSink` skips one it doesn't
/// read (WOF, EFS) and goes on; a missing or damaged one fails at its first read.
fn hand_refused(
    e: &Error,
    entry: &Entry,
    sink: &mut dyn EntrySink,
    cx: &mut dyn Ctx,
) -> Result<()> {
    if e.kind == ErrorKind::UnsupportedOperation {
        return match super::volume::unreadable(e.clone(), entry, sink, cx)? {
            Some(mut r) => sink.entry(entry, &mut r, cx),
            None => Ok(()),
        };
    }
    sink.entry(entry, &mut Failing(e.clone()), cx)
}

impl ArchiveReader for WimReader {
    fn format(&self) -> FormatId {
        FormatId::External(External::Wim)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::External(External::Wim),
            codecs: self.source.codecs.clone(),
            methods: self.methods.clone(),
            comment: None,
            encryption: Encryption::None,
            solid: !self.c.solids.is_empty(),
            sfx: false,
            volumes: self.c.parts.len().max(self.source.volumes.len()),
            solid_blocks: Some(self.c.solids.len() as u64),
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: Some(ExternalInfo {
                backend: None,
                levels: vec!["wim".to_owned()],
                properties: self.properties.clone(),
                notes: self.notes.clone(),
            }),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let selected: Vec<bool> = self.entries.iter().map(|e| sel.matches(e)).collect();
        self.check_limits(&selected)?;
        // Many small files: written on other threads while the chunks decode.
        if let Some(fs) = sink.as_fs_sink() {
            fs.write_behind(self.source.threads);
        }
        let threads = self.threads();
        let (c, entries, items, source) = (&self.c, &self.entries, &self.items, &self.source);
        // Each blob with the selected entries that take it, in listing order.
        let mut groups: Vec<(Hash, Vec<usize>)> = Vec::new();
        let mut at: HashMap<Hash, usize> = HashMap::new();
        let mut bytes_total = 0u64;
        for (id, item) in items.iter().enumerate() {
            if let (true, Item::Blob(h)) = (selected[id], item) {
                match at.get(h) {
                    Some(&g) => groups[g].1.push(id),
                    None => {
                        at.insert(*h, groups.len());
                        groups.push((*h, vec![id]));
                        bytes_total += c.blobs.get(h).map_or(0, |b| c.packed(b));
                    }
                }
            }
        }
        let counter = source.counter.clone();
        counter.set(0);
        let mut meter = Meter::new(counter.clone(), Some(bytes_total));
        meter.entries_total = Some(selected.iter().filter(|s| **s).count() as u64);
        // Copies made from memory produce bytes without reading any: held to the ratio limit
        // against the whole job's input, as FsSink's copies are.
        let mut copy_guard = Some(RatioGuard::new(&counter, &source.limits));
        let mut done = 0u64;

        // What has no data first: folders, links, empty files, and what can't be read.
        for (id, item) in items.iter().enumerate() {
            if !selected[id] || matches!(item, Item::Blob(_) | Item::Link(_)) {
                continue;
            }
            cx.check()?;
            let entry = &entries[id];
            meter.entries_done = done;
            meter.current = Some(entry.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            match item {
                Item::Refused(e) => hand_refused(e, entry, sink, &mut mcx)?,
                _ => sink.entry(entry, &mut io::empty(), &mut mcx)?,
            }
            done += 1;
        }

        // The blobs, in their data's order.
        let wants: Vec<Want> = groups
            .iter()
            .enumerate()
            .filter_map(|(k, (h, _))| {
                let b = c.blobs.get(h)?;
                Some(Want {
                    key: k,
                    hash: *h,
                    loc: b.loc,
                    size: b.size,
                })
            })
            .collect();
        let plan = Plan::new(c, &wants);
        pipe::run(
            c,
            &plan,
            threads,
            source.limits.decoder_memory,
            &mut |k, cut| {
                let (h, targets) = &groups[k];
                let Some(&first) = targets.first() else {
                    return Ok(());
                };
                let share = c.blobs.get(h).map_or(0, |b| c.packed(b));
                let size = cut.size();
                let again = targets.len() > 1;
                let mut data =
                    Counted::new(cut, counter.clone(), share, size, again && size <= KEEP);
                {
                    let entry = &entries[first];
                    meter.entries_done = done;
                    meter.current = Some(entry.path.clone());
                    let mut mcx = MeteredCtx::new(cx, &meter);
                    mcx.report();
                    let mut named = Named {
                        inner: source.guard(&mut data),
                        path: entry.path.clone(),
                    };
                    sink.entry(entry, &mut named, &mut mcx)?;
                }
                done += 1;
                if !again {
                    return Ok(());
                }
                let whole = data.finish();
                for &t in &targets[1..] {
                    let entry = &entries[t];
                    meter.entries_done = done;
                    meter.current = Some(entry.path.clone());
                    let mut mcx = MeteredCtx::new(cx, &meter);
                    mcx.report();
                    done += 1;
                    if sink.same_as(entry, &entries[first], &mut mcx)? {
                        continue;
                    }
                    let path = entry.path.clone();
                    match (&whole, &data.keep) {
                        (Err(e), _) => {
                            sink.entry(entry, &mut Failing(e.clone()), &mut mcx)?;
                        }
                        (Ok(()), Some(kept)) => {
                            let guard = copy_guard
                                .take()
                                .unwrap_or_else(|| RatioGuard::new(&counter, &source.limits));
                            let mut g = Guarded::new(
                                io::Cursor::new(kept.as_slice()),
                                guard,
                                source.budget.clone(),
                            );
                            let r = sink.entry(
                                entry,
                                &mut Named {
                                    inner: &mut g,
                                    path,
                                },
                                &mut mcx,
                            );
                            copy_guard = Some(g.into_parts().1);
                            r?;
                        }
                        // Too large to keep, and the sink can't copy it: read again.
                        (Ok(()), None) => {
                            let mut dec = Decoders::default();
                            let mut cache = ChunkCache::default();
                            let r = BlobReader::new(c, &mut dec, &mut cache, *h)?;
                            let counted = Counted::new(r, counter.clone(), share, size, false);
                            let mut named = Named {
                                inner: source.guard(counted),
                                path,
                            };
                            sink.entry(entry, &mut named, &mut mcx)?;
                        }
                    }
                }
                Ok(())
            },
        )?;

        // Hard links last, once their files are written.
        for (id, item) in items.iter().enumerate() {
            if !selected[id] || !matches!(item, Item::Link(_)) {
                continue;
            }
            cx.check()?;
            let entry = &entries[id];
            meter.entries_done = done;
            meter.current = Some(entry.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            sink.entry(entry, &mut io::empty(), &mut mcx)?;
            done += 1;
        }
        meter.entries_done = done;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let mut at = id;
        if let Some(Item::Link(f)) = self.items.get(id) {
            at = *f;
        }
        let (Some(entry), Some(item)) = (self.entries.get(at), self.items.get(at)) else {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        };
        match item {
            Item::None | Item::Empty => Ok(Box::new(io::empty())),
            Item::Refused(e) => Err(e.clone()),
            Item::Link(_) => Err(bad("a hard link to a hard link")),
            Item::Blob(h) => {
                let blob = *self
                    .c
                    .blobs
                    .get(h)
                    .ok_or_else(|| bad("a blob that isn't in the lookup table"))?;
                let share = self.c.packed(&blob);
                self.source.counter.set(0);
                let path = entry.path.clone();
                let r = BlobReader::new(&self.c, &mut self.dec, &mut self.cache, *h)
                    .map_err(|e| Error::new(e.kind, format!("wim: `{path}`: {}", e.message)))?;
                let counted = Counted::new(r, self.source.counter.clone(), share, blob.size, false);
                Ok(Box::new(Named {
                    inner: self.source.guard(counted),
                    path,
                }))
            }
        }
    }

    /// Every blob of every image (each SHA-1 checked), then the integrity table, if the image
    /// has one (decision 8).
    fn test(&mut self, cx: &mut dyn Ctx) -> Option<Result<TestReport>> {
        Some(self.test_all(cx))
    }
}
