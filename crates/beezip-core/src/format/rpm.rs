//! RPM packages (docs/M5.md §5.4), read only.
//!
//! - **The lead and the signature header** are skipped: their sizes are read and checked;
//!   signatures aren't verified.
//! - **The header** gives the listing without touching the payload: names (`BASENAMES`,
//!   `DIRNAMES`, `DIRINDEXES`, or the old `OLDFILENAMES`), sizes, modes, times and link targets.
//!   Every index entry's offset, count and type is checked against the data before it's used.
//!   Ghost files aren't in the payload, so they aren't listed. Files that share an inode are
//!   hard links to the last of them, which carries the data in the payload.
//! - **The payload** is a cpio (newc, or the stripped `07070X` headers of packages with large
//!   files) under gzip, bzip2, xz, lzma or zstd, streamed through the codecs. Extracting decodes
//!   it once; RPM has no random access.

use std::{
    collections::HashMap,
    io::{self, BufReader, Read, Seek, SeekFrom},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
    cpio::{self, Members},
    normalize,
};
use crate::{
    CodecId, Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, read_error},
    names::SystemPage,
    source::Source,
    time::from_unix,
};

pub struct Rpm;

const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
const LEAD_LEN: usize = 96;
const HEADER_MAGIC: [u8; 4] = [0x8E, 0xAD, 0xE8, 0x01];
/// rpm's own limits on a header: index entries and data bytes.
const MAX_INDEX: u64 = 0x1_0000;
const MAX_DATA: u64 = 256 << 20;

impl ArchiveFormat for Rpm {
    fn id(&self) -> FormatId {
        FormatId::Rpm
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".rpm"]
    }

    /// The lead's magic, and the signature header's right after it.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        if !probe.head.starts_with(&LEAD_MAGIC) {
            return None;
        }
        match probe.head.get(LEAD_LEN..LEAD_LEN + 4) {
            Some(m) if m == HEADER_MAGIC => Some(Confidence::Certain),
            _ => Some(Confidence::Likely),
        }
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::corrupt(format!("rpm: {}", msg.into()))
}

mod tag {
    pub const PAYLOADCOMPRESSOR: u32 = 1125;
    pub const PAYLOADFORMAT: u32 = 1124;
    pub const OLDFILENAMES: u32 = 1027;
    pub const FILESIZES: u32 = 1028;
    pub const FILEMODES: u32 = 1030;
    pub const FILEMTIMES: u32 = 1034;
    pub const FILELINKTOS: u32 = 1036;
    pub const FILEFLAGS: u32 = 1037;
    pub const FILEDEVICES: u32 = 1095;
    pub const FILEINODES: u32 = 1096;
    pub const DIRINDEXES: u32 = 1116;
    pub const BASENAMES: u32 = 1117;
    pub const DIRNAMES: u32 = 1118;
    pub const LONGFILESIZES: u32 = 5008;
}

/// `%ghost`: listed in the header, not in the payload.
const GHOST: u64 = 0x40;

/// One header structure: its index, as (tag, type, offset, count), and its data.
struct Header {
    index: Vec<(u32, u32, u32, u32)>,
    store: Vec<u8>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Reads `n` bytes, growing the buffer as they arrive rather than trusting `n`.
fn read_n<R: Read + ?Sized>(r: &mut R, n: u64) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    let got = r
        .take(n)
        .read_to_end(&mut v)
        .map_err(|e| read_error(&e).context("rpm"))?;
    if got as u64 != n {
        return Err(corrupt("the package is cut short"));
    }
    Ok(v)
}

/// One header structure, at most `room` bytes long. The signature header is padded to 8 bytes;
/// the main one isn't.
fn read_header<R: Read + ?Sized>(r: &mut R, room: u64, pad8: bool) -> Result<(Header, u64)> {
    let mut h = [0u8; 16];
    r.read_exact(&mut h)
        .map_err(|_| corrupt("the package is cut short"))?;
    if h[..4] != HEADER_MAGIC {
        return Err(corrupt("a header without its magic"));
    }
    let (n, size) = (u64::from(be32(&h[8..])), u64::from(be32(&h[12..])));
    let len = 16 + n * 16 + size;
    if n == 0 || n > MAX_INDEX || size > MAX_DATA || len > room {
        return Err(corrupt(format!(
            "a header of {n} entries and {size} bytes, which the package can't hold"
        )));
    }
    let raw = read_n(r, n * 16)?;
    let store = read_n(r, size)?;
    let index = raw
        .as_chunks::<16>()
        .0
        .iter()
        .map(|e| (be32(e), be32(&e[4..]), be32(&e[8..]), be32(&e[12..])))
        .collect();
    let mut used = len;
    if pad8 {
        let pad = (8 - size % 8) % 8;
        read_n(r, pad)?;
        used += pad;
    }
    Ok((Header { index, store }, used))
}

impl Header {
    fn find(&self, tag: u32) -> Option<(u32, usize, usize)> {
        let &(_, ty, off, count) = self.index.iter().find(|e| e.0 == tag)?;
        Some((ty, off as usize, count as usize))
    }

    /// A STRING, STRING_ARRAY or I18NSTRING tag's values.
    fn strings(&self, tag: u32) -> Result<Option<Vec<&[u8]>>> {
        let Some((ty, off, count)) = self.find(tag) else {
            return Ok(None);
        };
        if !matches!(ty, 6 | 8 | 9) {
            return Err(corrupt(format!("tag {tag} isn't a string")));
        }
        let mut rest = self
            .store
            .get(off..)
            .ok_or_else(|| corrupt(format!("tag {tag} points past the header")))?;
        // Every string takes a byte at least.
        if count > rest.len() {
            return Err(corrupt(format!("tag {tag} has too many strings")));
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let end = rest
                .iter()
                .position(|&c| c == 0)
                .ok_or_else(|| corrupt(format!("tag {tag} has a string without its end")))?;
            out.push(&rest[..end]);
            rest = &rest[end + 1..];
        }
        Ok(Some(out))
    }

    fn string(&self, tag: u32) -> Result<Option<&[u8]>> {
        Ok(self.strings(tag)?.and_then(|v| v.into_iter().next()))
    }

    /// An integer tag's values, widened.
    fn ints(&self, tag: u32) -> Result<Option<Vec<u64>>> {
        let Some((ty, off, count)) = self.find(tag) else {
            return Ok(None);
        };
        let w = match ty {
            1 | 2 => 1,
            3 => 2,
            4 => 4,
            5 => 8,
            _ => return Err(corrupt(format!("tag {tag} isn't an integer"))),
        };
        let data = count
            .checked_mul(w)
            .and_then(|n| off.checked_add(n))
            .and_then(|end| self.store.get(off..end))
            .ok_or_else(|| corrupt(format!("tag {tag} points past the header")))?;
        Ok(Some(
            data.chunks_exact(w)
                .map(|c| c.iter().fold(0u64, |a, &b| a << 8 | u64::from(b)))
                .collect(),
        ))
    }
}

/// A file as the header lists it.
struct HeaderFile {
    path: Vec<u8>,
    size: u64,
    mode: u64,
    mtime: u64,
    link: Vec<u8>,
    ghost: bool,
    key: (u64, u64),
}

/// The header's file list, in header order.
fn files(h: &Header, max: u64) -> Result<Vec<HeaderFile>> {
    use tag::*;
    let paths: Vec<Vec<u8>> = if let Some(base) = h.strings(BASENAMES)? {
        let dirs = h.strings(DIRNAMES)?.ok_or_else(|| corrupt("no DIRNAMES"))?;
        let idx = h
            .ints(DIRINDEXES)?
            .ok_or_else(|| corrupt("no DIRINDEXES"))?;
        if idx.len() != base.len() {
            return Err(corrupt("DIRINDEXES doesn't match BASENAMES"));
        }
        base.iter()
            .zip(&idx)
            .map(|(b, &i)| {
                let d = usize::try_from(i)
                    .ok()
                    .and_then(|i| dirs.get(i))
                    .ok_or_else(|| corrupt("a directory index past DIRNAMES"))?;
                Ok([*d, *b].concat())
            })
            .collect::<Result<_>>()?
    } else if let Some(old) = h.strings(OLDFILENAMES)? {
        old.iter().map(|p| p.to_vec()).collect()
    } else {
        return Ok(Vec::new());
    };
    let n = paths.len();
    if n as u64 > max {
        return Err(Error::limit(format!(
            "the package has more than {max} files (limit `max_entries`)"
        )));
    }
    let col = |v: Option<Vec<u64>>, what: &str| -> Result<Vec<u64>> {
        match v {
            Some(v) if v.len() == n => Ok(v),
            Some(_) => Err(corrupt(format!("{what} doesn't have one value per file"))),
            None => Ok(vec![0; n]),
        }
    };
    let sizes = col(
        match h.ints(LONGFILESIZES)? {
            Some(v) => Some(v),
            None => h.ints(FILESIZES)?,
        },
        "the file sizes",
    )?;
    let modes = col(h.ints(FILEMODES)?, "FILEMODES")?;
    let mtimes = col(h.ints(FILEMTIMES)?, "FILEMTIMES")?;
    let flags = col(h.ints(FILEFLAGS)?, "FILEFLAGS")?;
    let inodes = col(h.ints(FILEINODES)?, "FILEINODES")?;
    let devices = col(h.ints(FILEDEVICES)?, "FILEDEVICES")?;
    let links = h.strings(FILELINKTOS)?.unwrap_or_default();
    if !links.is_empty() && links.len() != n {
        return Err(corrupt("FILELINKTOS doesn't have one value per file"));
    }
    Ok(paths
        .into_iter()
        .enumerate()
        .map(|(i, path)| HeaderFile {
            path,
            size: sizes[i],
            mode: modes[i],
            mtime: mtimes[i],
            link: links.get(i).map(|l| l.to_vec()).unwrap_or_default(),
            ghost: flags[i] & GHOST != 0,
            key: (devices[i], inodes[i]),
        })
        .collect())
}

/// The payload's codec: what its first bytes say, else what the header says.
fn payload_codec(head: &[u8], named: Option<&[u8]>) -> Result<Option<CodecId>> {
    Ok(Some(match head {
        [0x1F, 0x8B, ..] => CodecId::Gzip,
        [b'B', b'Z', b'h', ..] => CodecId::Bzip2,
        [0xFD, b'7', b'z', b'X', b'Z', 0, ..] => CodecId::Xz,
        [0x28, 0xB5, 0x2F, 0xFD, ..] => CodecId::Zstd,
        [b'0', b'7', b'0', b'7', b'0', ..] => return Ok(None),
        _ => match named {
            Some(b"lzma") => CodecId::Lzma,
            Some(other) => {
                return Err(Error::unsupported_format(format!(
                    "an RPM payload compressed with {}",
                    String::from_utf8_lossy(other)
                )));
            }
            None => return Err(corrupt("the payload isn't a known compressed cpio")),
        },
    }))
}

pub struct RpmReader {
    source: Source,
    entries: Vec<Entry>,
    /// The entry each header file is, by header index (ghosts have none).
    by_index: Vec<Option<usize>>,
    /// Every header file's size, for stripped payload headers.
    sizes: Vec<u64>,
    /// The entry with a hard link's data, by entry.
    link_to: Vec<Option<usize>>,
    by_path: HashMap<String, usize>,
    payload_at: u64,
    codec: Option<CodecId>,
    scan: Option<Members<Box<dyn Read + Send>>>,
}

const S_IFMT: u64 = 0o170_000;

impl RpmReader {
    /// Reads the lead and both headers.
    pub fn open(source: Source, _: &mut dyn Ctx) -> Result<Self> {
        let mut file = BufReader::with_capacity(BUF_SIZE, source.open_file()?);
        let mut lead = [0u8; LEAD_LEN];
        file.read_exact(&mut lead)
            .map_err(|_| corrupt("the package is cut short"))?;
        if lead[..4] != LEAD_MAGIC {
            return Err(corrupt("not an RPM package"));
        }
        let room = source.size.saturating_sub(LEAD_LEN as u64);
        let (_, sig) = read_header(&mut file, room, true)?;
        let (h, main) = read_header(&mut file, room.saturating_sub(sig), false)?;
        let payload_at = LEAD_LEN as u64 + sig + main;
        if let Some(f) = h.string(tag::PAYLOADFORMAT)?
            && f != b"cpio"
        {
            return Err(Error::unsupported_format(format!(
                "an RPM payload in {} format",
                String::from_utf8_lossy(f)
            )));
        }
        let mut head = [0u8; 8];
        let n = file
            .read(&mut head)
            .map_err(|e| read_error(&e).context("rpm"))?;
        let codec = payload_codec(&head[..n], h.string(tag::PAYLOADCOMPRESSOR)?)?;
        let max = source.limits.max_entries.unwrap_or(u64::MAX);
        let files = files(&h, max)?;

        let mut entries: Vec<Entry> = Vec::new();
        let mut by_index = Vec::with_capacity(files.len());
        let mut by_path = HashMap::new();
        // The last regular file of each inode group, which carries the group's data.
        let mut last: HashMap<(u64, u64), usize> = HashMap::new();
        for (i, f) in files.iter().enumerate() {
            if f.ghost {
                by_index.push(None);
                continue;
            }
            if f.mode & S_IFMT == 0o100_000 && f.key != (0, 0) {
                last.insert(f.key, i);
            }
        }
        for (i, f) in files.iter().enumerate() {
            if f.ghost {
                continue;
            }
            let id = entries.len();
            let raw = normalize(&String::from_utf8_lossy(&f.path)).into_bytes();
            let path = source.names.decode(&f.path, false, SystemPage::Ansi);
            let path = normalize(&path);
            let kind = match f.mode & S_IFMT {
                0o040_000 => EntryKind::Dir,
                0o120_000 => EntryKind::Symlink {
                    target: source.names.decode(&f.link, false, SystemPage::Ansi),
                },
                0o100_000 | 0 => EntryKind::File,
                _ => EntryKind::Other,
            };
            let is_file = kind == EntryKind::File;
            let mut e = Entry {
                id,
                path: if kind == EntryKind::Dir {
                    format!("{path}/")
                } else {
                    path.clone()
                },
                raw_path: raw,
                size: is_file.then_some(f.size),
                packed_size: None,
                modified: i64::try_from(f.mtime).ok().and_then(|s| from_unix(s, 0)),
                crc32: None,
                method: None,
                encrypted: false,
                unix_mode: u32::try_from(f.mode).ok(),
                dos_attrs: None,
                kind,
            };
            if is_file
                && let Some(&l) = last.get(&f.key)
                && l != i
            {
                e.kind = EntryKind::Hardlink {
                    target: normalize(&source.names.decode(
                        &files[l].path,
                        false,
                        SystemPage::Ansi,
                    )),
                };
                e.size = None;
            }
            by_index.push(Some(id));
            by_path.insert(fold(&path), id);
            entries.push(e);
        }
        // Each link's data: the entry its group's last file became.
        let link_to = files
            .iter()
            .filter(|f| !f.ghost)
            .zip(&entries)
            .map(|(f, e)| match e.kind {
                EntryKind::Hardlink { .. } => last
                    .get(&f.key)
                    .and_then(|&l| by_index.get(l).copied().flatten()),
                _ => None,
            })
            .collect();
        Ok(Self {
            sizes: files.iter().map(|f| f.size).collect(),
            source,
            entries,
            by_index,
            link_to,
            by_path,
            payload_at,
            codec,
            scan: None,
        })
    }

    /// The payload's cpio, from its start.
    fn payload(&self) -> Result<Members<Box<dyn Read + Send>>> {
        let mut file = self.source.open_file()?;
        file.seek(SeekFrom::Start(self.payload_at))
            .map_err(|e| Error::io("seeking in the package", &e))?;
        let mut r: Box<dyn Read + Send> = Box::new(BufReader::with_capacity(BUF_SIZE, file));
        if let Some(c) = self.codec {
            r = c.decoder(r, &self.source.limits)?;
        }
        Ok(Members::new(r))
    }

    /// The entry a payload member is: by its stripped header's index, or by its name.
    fn entry_of(&self, h: &cpio::Header) -> Result<usize> {
        match h.index {
            Some(i) => usize::try_from(i)
                .ok()
                .and_then(|i| self.by_index.get(i).copied().flatten())
                .ok_or_else(|| corrupt(format!("the payload has file {i}, which isn't listed"))),
            None => {
                let name = self.source.names.decode(&h.name, false, SystemPage::Ansi);
                self.by_path
                    .get(&fold(&normalize(&name)))
                    .copied()
                    .ok_or_else(|| {
                        corrupt(format!(
                            "the payload has `{name}`, which the header doesn't list"
                        ))
                    })
            }
        }
    }
}

/// A path as the payload and the header are matched: case matters, as in rpm.
fn fold(p: &str) -> String {
    p.to_owned()
}

impl ArchiveReader for RpmReader {
    fn format(&self) -> FormatId {
        FormatId::Rpm
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Rpm,
            codecs: self.source.codecs.clone(),
            methods: self
                .codec
                .map(|c| CodecId::name(c).into())
                .into_iter()
                .collect(),
            comment: None,
            encryption: Encryption::None,
            solid: self.codec.is_some(),
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: None,
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
        meter.entries_total = Some(self.entries.len() as u64);
        let sizes = &self.sizes;
        let stripped = |i: u32| sizes.get(i as usize).copied();
        let mut m = self.payload()?;
        let mut seen = vec![false; self.entries.len()];
        // Links waiting for their data, by the entry with it.
        let mut waiting: HashMap<usize, Vec<usize>> = HashMap::new();
        let emit = |e: &Entry,
                    data: &mut dyn Read,
                    meter: &mut Meter,
                    sink: &mut dyn EntrySink,
                    cx: &mut dyn Ctx|
         -> Result<()> {
            if !sel.matches(e) {
                return Ok(());
            }
            meter.entries_done = e.id as u64;
            meter.current = Some(e.path.clone());
            let mut mcx = MeteredCtx::new(cx, meter);
            mcx.report();
            sink.entry(e, data, &mut mcx)
        };
        while let Some(h) = m.next(&stripped)? {
            cx.check()?;
            if h.is_trailer() {
                break;
            }
            let id = self.entry_of(&h)?;
            seen[id] = true;
            let e = &self.entries[id];
            match &e.kind {
                EntryKind::File => {
                    if Some(h.size) != e.size {
                        return Err(corrupt(format!(
                            "`{}` has {} bytes in the payload and {} in the header",
                            e.path,
                            h.size,
                            e.size.unwrap_or(0)
                        )));
                    }
                    {
                        let mut data = self.source.guard(m.data());
                        emit(e, &mut data, &mut meter, sink, cx)?;
                    }
                    for l in waiting.remove(&id).unwrap_or_default() {
                        emit(&self.entries[l], &mut io::empty(), &mut meter, sink, cx)?;
                    }
                }
                EntryKind::Hardlink { .. } => match self.link_to[id] {
                    Some(t) if seen[t] => emit(e, &mut io::empty(), &mut meter, sink, cx)?,
                    Some(t) => waiting.entry(t).or_default().push(id),
                    None => emit(e, &mut io::empty(), &mut meter, sink, cx)?,
                },
                _ => emit(e, &mut io::empty(), &mut meter, sink, cx)?,
            }
        }
        if !m.ended {
            return Err(corrupt("the payload ends without its trailer"));
        }
        if let Some(e) = self
            .entries
            .iter()
            .find(|e| !seen[e.id] && e.kind == EntryKind::File && sel.matches(e))
        {
            return Err(corrupt(format!("the payload doesn't have `{}`", e.path)));
        }
        // Links whose data never came: the sink says what it does with them.
        let mut rest: Vec<usize> = waiting.into_values().flatten().collect();
        rest.sort_unstable();
        for l in rest {
            emit(&self.entries[l], &mut io::empty(), &mut meter, sink, cx)?;
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        let id = match &entry.kind {
            EntryKind::File => id,
            EntryKind::Hardlink { target } => self.link_to[id]
                .ok_or_else(|| corrupt(format!("hard link target `{target}` is missing")))?,
            _ => return Ok(Box::new(io::empty())),
        };
        let mut m = self.payload()?;
        let sizes = self.sizes.clone();
        let stripped = move |i: u32| sizes.get(i as usize).copied();
        loop {
            cx.check()?;
            let h = m
                .next(&stripped)?
                .filter(|h| !h.is_trailer())
                .ok_or_else(|| corrupt("the payload doesn't have the file"))?;
            if self.entry_of(&h)? == id {
                break;
            }
        }
        let m = self.scan.insert(m);
        Ok(Box::new(self.source.guard(m.data())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header structure from (tag, type, count, data) entries.
    fn header(tags: &[(u32, u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut store = Vec::new();
        for (tag, ty, count, data) in tags {
            for v in [*tag, *ty, store.len() as u32, *count] {
                index.extend_from_slice(&v.to_be_bytes());
            }
            store.extend_from_slice(data);
        }
        let mut out = HEADER_MAGIC.to_vec();
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        out.extend_from_slice(&(store.len() as u32).to_be_bytes());
        out.extend(index);
        out.extend(store);
        out
    }

    #[test]
    fn index_entries_are_checked_against_the_data() {
        let bytes = header(&[(1000, 6, 1, b"name\0".to_vec())]);
        let room = bytes.len() as u64;
        let (h, _) = read_header(&mut &bytes[..], room, false).unwrap();
        assert_eq!(h.string(1000).unwrap(), Some(&b"name"[..]));
        // Past the data, unterminated, too many, the wrong type.
        let mut bad = bytes.clone();
        bad[16 + 8..16 + 12].copy_from_slice(&100u32.to_be_bytes());
        let (h, _) = read_header(&mut &bad[..], room, false).unwrap();
        assert!(h.string(1000).is_err());
        let bytes = header(&[(1000, 6, 1, b"name".to_vec())]);
        let (h, _) = read_header(&mut &bytes[..], 999, false).unwrap();
        assert!(h.string(1000).is_err());
        let bytes = header(&[(1000, 8, u32::MAX, b"a\0".to_vec())]);
        let (h, _) = read_header(&mut &bytes[..], 999, false).unwrap();
        assert!(h.strings(1000).is_err());
        let bytes = header(&[(1028, 4, 0x4000_0000, vec![0; 4])]);
        let (h, _) = read_header(&mut &bytes[..], 999, false).unwrap();
        assert!(h.ints(1028).is_err());
        assert!(h.strings(1028).is_err());
    }

    #[test]
    fn headers_bigger_than_the_file_are_refused() {
        let mut bytes = header(&[(1000, 6, 1, b"x\0".to_vec())]);
        bytes[12..16].copy_from_slice(&(200u32 << 20).to_be_bytes());
        assert!(read_header(&mut &bytes[..], bytes.len() as u64, false).is_err());
        bytes[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(read_header(&mut &bytes[..], u64::MAX, false).is_err());
    }

    #[test]
    fn payload_codecs_come_from_the_bytes() {
        assert_eq!(
            payload_codec(&[0x28, 0xB5, 0x2F, 0xFD], Some(b"xz")).unwrap(),
            Some(CodecId::Zstd)
        );
        assert_eq!(payload_codec(b"070701xx", None).unwrap(), None);
        assert_eq!(
            payload_codec(&[0x5D, 0, 0], Some(b"lzma")).unwrap(),
            Some(CodecId::Lzma)
        );
        assert!(payload_codec(&[0, 0], Some(b"lz4")).is_err());
    }
}
