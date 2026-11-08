//! ARJ (docs/M6.md §4), read only. Taken in from unarc-rs 0.8.1's `arj` module, © Mike Krüger,
//! MIT, and rewritten to BeeZip's conventions. GOST40 is left out (docs/M6.md §14).
//!
//! - **The layout:** each part of a set starts with a main header, then a local header before
//!   each entry's packed data, and a header of size 0 ends it ([`header`]). Every header field is
//!   checked against the header's size, and every packed size against the file, before it's used.
//! - **Methods** 0 (stored), 1–3 (LZH, through delharc) and 4 (ARJ's own), decoded into the sink
//!   as it reads, in fixed memory, and each piece's CRC-32 checked at its end ([`decode`]).
//!   unarc-rs decoded every entry into a `Vec` first.
//! - **Volume sets** (`x.arj`, `x.a01`…, found as old RAR sets are): every part is listed, and a
//!   file split between parts (the volume and ext-file flags) is one entry, its pieces decoded one
//!   after another. unarc-rs compared the joined size with a field ARJ 3.10 leaves 0, and refused
//!   ARJ 3.10's sets though their data decodes.
//! - **Names** are bytes through `NameDecoding`, with the OEM code page as zip's DOS-era names
//!   have; `\` becomes `/`.
//! - **Times:** an entry made on Unix (or NeXT) has a Unix time, the rest a DOS local time.
//!   unarc-rs and 7-Zip 26.00 read both as DOS times, and show 2033 for a Unix file of 2026.
//! - **Garble** is ARJ's XOR with the password. It has no password check, so a garbled entry
//!   that doesn't decode or match its CRC is "wrong password or damaged data", and the reader
//!   asks again (at most [`MAX_PASSWORD_TRIES`] times), trying the last password that worked
//!   first. ARJ's GOST encryption isn't read: its entries list, and fail when read.

mod decode;
mod header;

use std::{
    borrow::Cow,
    io::{self, Read},
    sync::Arc,
};

use decode::{EntryData, Parts, Piece, Set};
use header::{Local, Main};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    ctx::MAX_PASSWORD_TRIES,
    detect::{Confidence, Probe},
    names::{NameDecoding, SystemPage},
    source::Source,
    time::{DosClock, DosTime, from_unix},
};

pub struct Arj;

impl ArchiveFormat for Arj {
    fn id(&self) -> FormatId {
        FormatId::Arj
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".arj"]
    }

    /// A main header at the start, its CRC-32 matching: never the two magic bytes alone.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        header::main_at(probe.head).then_some(Confidence::Certain)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            volumes: true,
            ..FormatCaps::default()
        }
    }
}

fn corrupt(what: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("arj: {what}"))
}

/// The method's name, for the listing.
fn method_name(m: u8) -> Cow<'static, str> {
    match m {
        0 => "Store".into(),
        1 => "ARJ 1".into(),
        2 => "ARJ 2".into(),
        3 => "ARJ 3".into(),
        4 => "ARJ 4".into(),
        _ => format!("ARJ method {m}").into(),
    }
}

/// What reading an entry's data needs beyond its pieces.
#[derive(Debug, Clone, Default)]
struct Item {
    pieces: Vec<Piece>,
    /// The entry starts or goes on in a part that isn't there.
    missing: Option<String>,
}

pub struct ArjReader {
    set: Arc<Set>,
    entries: Vec<Entry>,
    items: Vec<Item>,
    comment: Option<String>,
    /// The main header's encryption version: garble below 2, GOST from 2 up.
    encryption: u8,
    /// The parts the archive takes up.
    parts: usize,
    /// The last password that worked.
    password: Option<String>,
}

impl ArjReader {
    /// Reads every header of every part.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let mut r = Self {
            set: Arc::new(Set::new(source)?),
            entries: Vec::new(),
            items: Vec::new(),
            comment: None,
            encryption: 0,
            parts: 0,
            password: None,
        };
        r.list(cx)?;
        Ok(r)
    }

    fn list(&mut self, cx: &mut dyn Ctx) -> Result<()> {
        let mut parts = Parts::new(&self.set);
        let mut clock = DosClock::default();
        let names = self.set.source.names;
        let count = self.set.source.volumes.len();
        // The entry whose last piece says it goes on in the next part.
        let mut pending: Option<usize> = None;
        // The last part read says another follows.
        let mut more = false;
        for k in 0..count {
            cx.check()?;
            let part = self.set.part_name(k);
            parts.goto(k, 0)?;
            let main = match header::read(&mut parts) {
                Ok(Some(b)) => Main::parse(&b),
                Ok(None) => Err(corrupt("no main header")),
                Err(e) => Err(e),
            }
            .map_err(|e| if k == 0 { e } else { e.context(&part) })?;
            if k == 0 {
                self.encryption = main.encryption;
                if !main.comment.is_empty() {
                    self.comment = Some(names.decode(&main.comment, false, SystemPage::Oem));
                }
            }
            let carried = pending.take();
            let mut first = true;
            loop {
                cx.check()?;
                let Some(b) = header::read(&mut parts)? else {
                    break;
                };
                let h = Local::parse(&b)?;
                let data = parts.pos();
                let packed = u64::from(h.packed);
                if let Some(Some(len)) = self.set.lens.get(k)
                    && data.saturating_add(packed) > *len
                {
                    return Err(corrupt(format!(
                        "an entry of {packed} bytes runs past the end of {part}"
                    )));
                }
                let piece = Piece {
                    part: k,
                    data,
                    packed,
                    size: u64::from(h.size),
                    crc: h.crc,
                    method: h.method,
                    garbled: h.flags & header::GARBLED != 0,
                    modifier: h.modifier,
                };
                let continued = h.flags & header::EXT_FILE != 0;
                let id = match (first.then_some(carried).flatten(), continued) {
                    (Some(id), true) => {
                        self.add_piece(id, &h, piece, &part)?;
                        id
                    }
                    (Some(id), false) => {
                        return Err(corrupt(format!(
                            "`{}` goes on in {part}, which doesn't continue it",
                            self.entries[id].path
                        )));
                    }
                    (None, _) => {
                        if pending.is_some() {
                            return Err(corrupt(format!(
                                "an entry in {part} goes on in the next part, but more follow it"
                            )));
                        }
                        let id = self.entries.len();
                        self.set.source.limits.check_entries(id as u64 + 1)?;
                        let mut item = Item {
                            pieces: vec![piece],
                            missing: None,
                        };
                        let entry = entry_for(id, &h, &names, &mut clock);
                        if continued {
                            item.missing = Some(format!(
                                "`{}` starts in a part before {part}, which isn't here",
                                entry.path
                            ));
                        }
                        self.entries.push(entry);
                        self.items.push(item);
                        id
                    }
                };
                if h.flags & header::VOLUME != 0 && self.entries[id].kind == EntryKind::File {
                    pending = Some(id);
                }
                first = false;
                parts.goto(k, data.saturating_add(packed))?;
            }
            if first && let Some(id) = carried {
                return Err(corrupt(format!(
                    "`{}` goes on in {part}, which doesn't continue it",
                    self.entries[id].path
                )));
            }
            self.parts = k + 1;
            more = main.flags & header::VOLUME != 0;
            if !more && pending.is_none() {
                break;
            }
        }
        let last = self.set.part_name(self.parts.saturating_sub(1));
        if more && pending.is_none() && self.parts == count {
            cx.warn(format!(
                "{last} says the set goes on, but its next part isn't here"
            ));
        }
        if let Some(id) = pending {
            self.items[id].missing.get_or_insert(format!(
                "`{}` goes on in the part after {last}, which isn't here",
                self.entries[id].path
            ));
        }
        Ok(())
    }

    /// Adds a piece continued from the previous part to entry `id`: the same name, starting
    /// where the pieces before it end.
    fn add_piece(&mut self, id: usize, h: &Local, piece: Piece, part: &str) -> Result<()> {
        let e = &mut self.entries[id];
        let item = &mut self.items[id];
        let so_far: u64 = item.pieces.iter().map(|p| p.size).sum();
        if h.name != e.raw_path || u64::from(h.ext_pos) != so_far {
            return Err(corrupt(format!(
                "{part} doesn't go on with `{}` where the part before it stops",
                e.path
            )));
        }
        e.size = Some(so_far.saturating_add(piece.size));
        e.packed_size = Some(e.packed_size.unwrap_or(0).saturating_add(piece.packed));
        e.crc32 = None;
        item.pieces.push(piece);
        Ok(())
    }

    /// Why entry `id` can't be read, if it can't.
    fn trouble(&self, id: usize) -> Option<Error> {
        let (e, item) = (&self.entries[id], &self.items[id]);
        if let Some(m) = &item.missing {
            return Some(Error::new(ErrorKind::NotFound, m.clone()));
        }
        if let Some(p) = item
            .pieces
            .iter()
            .find(|p| p.size > 0 && !decode::decodes(p.method))
        {
            return Some(Error::unsupported_format(format!(
                "`{}` is compressed with ARJ method {}, which BeeZip can't decode",
                e.path, p.method
            )));
        }
        if self.encryption >= 2 && item.pieces.iter().any(|p| p.garbled) {
            return Some(Error::unsupported(format!(
                "`{}` is encrypted with ARJ's GOST encryption (version {}), which BeeZip doesn't read",
                e.path, self.encryption
            )));
        }
        None
    }

    /// Whether entry `id` needs the garble password: data to ungarble, and nothing else wrong.
    fn needs_password(&self, id: usize) -> bool {
        self.items[id]
            .pieces
            .iter()
            .any(|p| p.garbled && p.size > 0)
            && self.trouble(id).is_none()
    }

    /// Entry `id`'s data, `parts` moved to its first piece; `trouble` is given on the first read.
    fn data<'a>(
        &'a self,
        mut parts: Parts,
        id: usize,
        key: Option<Vec<u8>>,
    ) -> Result<EntryData<'a>> {
        let item = &self.items[id];
        let trouble = self.trouble(id);
        if trouble.is_none()
            && let Some(p) = item.pieces.iter().find(|p| p.size > 0)
        {
            // Here, so the ratio check starts from the entry's own bytes.
            parts.goto(p.part, p.data)?;
        }
        Ok(EntryData::new(
            parts,
            &item.pieces,
            &self.entries[id].path,
            key,
            trouble,
        ))
    }

    /// Finds the password for entry `id` by reading it through: the last one that worked, then
    /// what the context gives, until one matches the CRCs.
    fn unlock(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Vec<u8>> {
        let mut failed = 0u32;
        loop {
            let pw = ask(&self.password, &self.entries[id].path, failed, cx)?;
            let read = {
                let parts = Parts::new(&self.set);
                let mut data = self.data(parts, id, Some(pw.as_bytes().to_vec()))?;
                crate::io::drain(&mut self.set.source.guard(&mut data), cx)
            };
            match read {
                Ok(_) => {
                    self.password = Some(pw.clone());
                    return Ok(pw.into_bytes());
                }
                Err(e) if e.kind == ErrorKind::WrongPassword => {
                    self.password = None;
                    failed += 1;
                    if failed >= MAX_PASSWORD_TRIES {
                        return Err(decode::wrong_password());
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// The password to try after `failed` wrong ones: the remembered one first.
fn ask(remembered: &Option<String>, path: &str, failed: u32, cx: &mut dyn Ctx) -> Result<String> {
    if failed == 0
        && let Some(pw) = remembered
    {
        return Ok(pw.clone());
    }
    cx.password(Some(path), failed).map_err(|e| {
        if e.kind == ErrorKind::WrongPassword {
            decode::wrong_password()
        } else {
            e
        }
    })
}

fn entry_for(id: usize, h: &Local, names: &NameDecoding, clock: &mut DosClock) -> Entry {
    let kind = match h.file_type {
        header::BINARY | header::TEXT => EntryKind::File,
        header::DIR => EntryKind::Dir,
        // Volume and chapter labels, and anything newer.
        _ => EntryKind::Other,
    };
    let mut path = names
        .decode(&h.name, false, SystemPage::Oem)
        .replace('\\', "/");
    if kind == EntryKind::Dir && !path.ends_with('/') {
        path.push('/');
    }
    let unix = header::unix_host(h.host_os);
    let modified = if unix {
        from_unix(i64::from(h.time), 0)
    } else {
        clock.read(DosTime {
            date: (h.time >> 16) as u16,
            time: h.time as u16,
        })
    };
    let is_file = kind == EntryKind::File;
    let (unix_mode, dos_attrs) = if unix {
        // ARJ's own type bits over the permissions: give the POSIX ones.
        let ftype = if kind == EntryKind::Dir {
            0o040_000
        } else {
            0o100_000
        };
        (Some(ftype | u32::from(h.mode & 0o7777)), None)
    } else {
        (None, Some(u32::from(h.mode)))
    };
    Entry {
        id,
        path,
        raw_path: h.name.clone(),
        size: is_file.then_some(u64::from(h.size)),
        packed_size: is_file.then_some(u64::from(h.packed)),
        modified,
        crc32: is_file.then_some(h.crc),
        method: is_file.then(|| method_name(h.method)),
        encrypted: h.flags & header::GARBLED != 0,
        unix_mode,
        dos_attrs,
        kind,
    }
}

impl ArchiveReader for ArjReader {
    fn format(&self) -> FormatId {
        FormatId::Arj
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let files = self.entries.iter().filter(|e| e.kind == EntryKind::File);
        let mut methods: Vec<Cow<'static, str>> = Vec::new();
        for m in files.clone().filter_map(|e| e.method.as_ref()) {
            if !methods.contains(m) {
                methods.push(m.clone());
            }
        }
        let encrypted = files.clone().filter(|e| e.encrypted).count();
        let encryption = match encrypted {
            0 => Encryption::None,
            n if n == files.count() => Encryption::All,
            _ => Encryption::Some,
        };
        Ok(ArchiveInfo {
            format: FormatId::Arj,
            codecs: self.set.source.codecs.clone(),
            methods,
            comment: self.comment.clone(),
            encryption,
            solid: false,
            sfx: false,
            volumes: self.parts.max(1),
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
        let mut meter = Meter::new(self.set.source.counter.clone(), Some(self.set.total));
        meter.entries_total = Some(self.entries.len() as u64);
        // One pass over the parts: each entry moves on from where the one before stopped.
        let mut parts = Parts::new(&self.set);
        for id in 0..self.entries.len() {
            cx.check()?;
            if !sel.matches(&self.entries[id]) {
                continue;
            }
            meter.entries_done = id as u64;
            meter.current = Some(self.entries[id].path.clone());
            if self.entries[id].kind != EntryKind::File {
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.report();
                sink.entry(&self.entries[id], &mut io::empty(), &mut mcx)?;
                continue;
            }
            let locked = self.needs_password(id);
            let mut failed = 0u32;
            loop {
                let pw = if locked {
                    Some(ask(&self.password, &self.entries[id].path, failed, cx)?)
                } else {
                    None
                };
                let key = pw.as_ref().map(|p| p.as_bytes().to_vec());
                let mut data = self.data(parts, id, key)?;
                let sent = {
                    let mut guarded = self.set.source.guard(&mut data);
                    let mut mcx = MeteredCtx::new(cx, &meter);
                    mcx.report();
                    sink.entry(&self.entries[id], &mut guarded, &mut mcx)
                };
                parts = data.into_parts();
                match sent {
                    Ok(()) => {
                        if pw.is_some() {
                            self.password = pw;
                        }
                        break;
                    }
                    Err(e) if e.kind == ErrorKind::WrongPassword && locked => {
                        self.password = None;
                        failed += 1;
                        if failed >= MAX_PASSWORD_TRIES {
                            return Err(decode::wrong_password());
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let e = self
            .entries
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        if e.kind != EntryKind::File {
            return Ok(Box::new(io::empty()));
        }
        if let Some(t) = self.trouble(id) {
            return Err(t);
        }
        let key = if self.needs_password(id) {
            Some(self.unlock(id, cx)?)
        } else {
            None
        };
        let data = self.data(Parts::new(&self.set), id, key)?;
        Ok(Box::new(self.set.source.guard(data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names() {
        assert_eq!(method_name(0), "Store");
        assert_eq!(method_name(4), "ARJ 4");
        assert_eq!(method_name(9), "ARJ method 9");
    }
}
