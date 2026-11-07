//! ar (docs/M5.md §5.3): BeeZip's own reader and GNU writer.
//!
//! - **Reading:** GNU archives (`//` name table, `/` and `/SYM64/` symbol tables, `name/`
//!   names) and BSD ones (`#1/<len>` names stored before the data, `__.SYMDEF` symbol tables),
//!   and Windows' `.lib` (whose long names end with NUL). Symbol tables are skipped, not listed.
//!   Thin archives (`!<thin>`) are refused: their members are other files.
//! - **Names** are bytes, read through the source's `NameDecoding` (docs/M5.md §6).
//! - **Writing** is GNU's form. Names over 15 bytes, or with a `/` in them, go in a `//` table at
//!   the start, which is possible because the writer is told every name first
//!   ([`ArchiveWriter::expect`]). Sizes are 10 decimal digits, so a file of 10¹⁰ bytes or more
//!   fails with `InvalidArgs` before anything is written. ar holds files only.
//! - **Editing** copies members' data as it is. Every kept member gets a new header, since a long
//!   name's place in the table moves, with its time, owner and mode. A symbol table is left out:
//!   it would point at the old offsets.

use std::{
    collections::HashMap,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Copied, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, Keep, NewEntry, NewKind, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    codec::FinishWrite,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, CountingReader, ExactReader, read_error, write_error},
    names::SystemPage,
    source::{Input, Source},
    time::{from_unix, to_unix},
};

pub struct Ar;

pub const MAGIC: &[u8; 8] = b"!<arch>\n";
const THIN: &[u8; 8] = b"!<thin>\n";
const HEADER_LEN: usize = 60;
/// The most a `//` name table or a BSD name may hold.
const MAX_NAMES: u64 = 16 * 1024 * 1024;
const MAX_BSD_NAME: u64 = 64 * 1024;
/// ar's size field holds 10 decimal digits.
const MAX_SIZE: u64 = 9_999_999_999;

impl ArchiveFormat for Ar {
    fn id(&self) -> FormatId {
        FormatId::Ar
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".ar"]
    }

    /// The magic with a plausible first header is certain, unless that member is a Debian
    /// package's `debian-binary`, when deb is. A thin archive is likely, so it opens to be refused.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        if probe.head.starts_with(THIN) {
            return Some(Confidence::Likely);
        }
        if !probe.head.starts_with(MAGIC) {
            return None;
        }
        match probe.head.get(8..8 + HEADER_LEN) {
            None if probe.head.len() == 8 => Some(Confidence::Certain),
            Some(h) if h[58..60] == *b"`\n" && !is_deb_binary(&h[..16]) => {
                Some(Confidence::Certain)
            }
            _ => Some(Confidence::Likely),
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

/// A member name field that says `debian-binary`, with or without GNU's `/`.
pub(crate) fn is_deb_binary(field: &[u8]) -> bool {
    let name = trim_name(field);
    name == b"debian-binary"
}

fn trim_name(field: &[u8]) -> &[u8] {
    let end = field.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    let name = &field[..end];
    name.strip_suffix(b"/").unwrap_or(name)
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::corrupt(format!("ar: {}", msg.into()))
}

/// A decimal or octal field: spaces around digits; blank is 0.
fn number(field: &[u8], radix: u32) -> Option<u64> {
    let s = std::str::from_utf8(field).ok()?.trim_matches([' ', '\0']);
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, radix).ok()
}

/// One member: its header's fields, the name resolved.
#[derive(Debug, Clone)]
pub(crate) struct Member {
    /// The name as stored (GNU's `/` taken off).
    pub name: Vec<u8>,
    pub mtime: u64,
    pub uid: u64,
    pub gid: u64,
    pub mode: u64,
    /// The data's size, without a BSD name before it.
    pub size: u64,
    /// Where the data starts, from the archive's start.
    pub data_at: u64,
}

/// Walks an ar's members in order, from a plain `Read`.
pub(crate) struct Members<R> {
    r: R,
    pos: u64,
    /// The current member's data still unread, and the padding after it.
    left: u64,
    pad: u64,
    /// GNU's `//` table, once read.
    names: Vec<u8>,
    /// The archive had a symbol table.
    pub symbols: bool,
}

impl<R: Read> Members<R> {
    /// Reads the magic.
    pub fn new(mut r: R) -> Result<Self> {
        let mut m = [0u8; 8];
        r.read_exact(&mut m)
            .map_err(|_| corrupt("the archive is cut short"))?;
        if m == *THIN {
            return Err(Error::unsupported_format(
                "a thin ar archive, whose members are other files, isn't supported",
            ));
        }
        if m != *MAGIC {
            return Err(corrupt("not an ar archive"));
        }
        Ok(Self {
            r,
            pos: 8,
            left: 0,
            pad: 0,
            names: Vec::new(),
            symbols: false,
        })
    }

    fn io(e: &io::Error) -> Error {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            corrupt("the archive is cut short")
        } else {
            read_error(e).context("ar")
        }
    }

    fn skip(&mut self, n: u64) -> Result<()> {
        let got =
            io::copy(&mut (&mut self.r).take(n), &mut io::sink()).map_err(|e| Self::io(&e))?;
        self.pos += got;
        if got != n {
            return Err(corrupt("the archive is cut short"));
        }
        Ok(())
    }

    fn read_vec(&mut self, n: u64) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        let got = (&mut self.r)
            .take(n)
            .read_to_end(&mut v)
            .map_err(|e| Self::io(&e))?;
        self.pos += got as u64;
        if got as u64 != n {
            return Err(corrupt("the archive is cut short"));
        }
        Ok(v)
    }

    /// The current member's data.
    pub fn data(&mut self) -> MemberData<'_, R> {
        MemberData { m: self }
    }

    /// The current member's data, owning the walk.
    pub fn into_data(self) -> IntoData<R> {
        IntoData { m: self }
    }

    /// The next member that is an entry, or `None` at the end. Name and symbol tables are read
    /// or skipped on the way.
    pub fn next(&mut self) -> Result<Option<Member>> {
        loop {
            let n = self.left + self.pad;
            self.left = 0;
            self.pad = 0;
            self.skip(n)?;
            let mut h = [0u8; HEADER_LEN];
            let mut got = 0;
            while got < HEADER_LEN {
                match self.r.read(&mut h[got..]) {
                    Ok(0) => break,
                    Ok(k) => got += k,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(Self::io(&e)),
                }
            }
            if got == 0 {
                return Ok(None);
            }
            // Some writers end with a newline of padding the size didn't count.
            if got == 1 && h[0] == b'\n' {
                return Ok(None);
            }
            if got < HEADER_LEN {
                return Err(corrupt("the archive is cut short"));
            }
            let at = self.pos;
            self.pos += HEADER_LEN as u64;
            if h[58..60] != *b"`\n" {
                return Err(corrupt(format!("a damaged header at byte {at}")));
            }
            let bad = || corrupt(format!("a damaged header at byte {at}"));
            let field = &h[..16];
            let mut size = number(&h[48..58], 10).ok_or_else(bad)?;
            let mut m = Member {
                name: Vec::new(),
                mtime: number(&h[16..28], 10).unwrap_or(0),
                uid: number(&h[28..34], 10).unwrap_or(0),
                gid: number(&h[34..40], 10).unwrap_or(0),
                mode: number(&h[40..48], 8).unwrap_or(0o644),
                size,
                data_at: 0,
            };
            let trimmed = trim_name(field);
            if field.starts_with(b"// ") || field == b"//              " {
                if size > MAX_NAMES {
                    return Err(corrupt(format!("a name table of {size} bytes")));
                }
                self.names = self.read_vec(size)?;
                self.pad = size % 2;
                continue;
            }
            // GNU's `/` and `/SYM64/`, Windows' `/<ECSYMBOLS>/`, BSD's `__.SYMDEF`.
            if (trimmed.is_empty() && field.starts_with(b"/"))
                || field.starts_with(b"/SYM64/")
                || field.starts_with(b"/<")
                || trimmed.starts_with(b"__.SYMDEF")
            {
                self.symbols = true;
                self.left = size;
                self.pad = size % 2;
                continue;
            }
            if let Some(len) = field.strip_prefix(b"#1/") {
                // BSD: the name is the start of the data.
                let len = number(len, 10).ok_or_else(bad)?;
                if len > MAX_BSD_NAME || len > size {
                    return Err(corrupt(format!("a name of {len} bytes at byte {at}")));
                }
                let mut name = self.read_vec(len)?;
                if let Some(end) = name.iter().position(|&b| b == 0) {
                    name.truncate(end);
                }
                size -= len;
                if name.starts_with(b"__.SYMDEF") {
                    self.symbols = true;
                    self.left = size;
                    self.pad = (size + len) % 2;
                    continue;
                }
                m.name = name;
                m.size = size;
                self.pad = (size + len) % 2;
            } else if let Some(off) = field
                .strip_prefix(b"/")
                .and_then(|r| number(r, 10))
                .filter(|_| field[1].is_ascii_digit())
            {
                // GNU: an offset into the `//` table.
                let start = usize::try_from(off)
                    .ok()
                    .filter(|&o| o < self.names.len())
                    .ok_or_else(|| corrupt(format!("a long name past the table at byte {at}")))?;
                let rest = &self.names[start..];
                let end = rest
                    .windows(2)
                    .position(|w| w == b"/\n")
                    .or_else(|| rest.iter().position(|&b| b == b'\n' || b == 0))
                    .unwrap_or(rest.len());
                m.name = rest[..end].to_vec();
                self.pad = size % 2;
            } else {
                // GNU's `name/`, or BSD's and System V's space-padded name.
                let end = field.iter().position(|&b| b == b'/').unwrap_or(16);
                let name = if end == 0 { trimmed } else { &field[..end] };
                m.name = trim_name(name).to_vec();
                self.pad = size % 2;
            }
            m.data_at = self.pos;
            self.left = m.size;
            return Ok(Some(m));
        }
    }
}

/// One member's data, from [`Members::into_data`].
pub(crate) struct IntoData<R> {
    m: Members<R>,
}

impl<R: Read> Read for IntoData<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        MemberData { m: &mut self.m }.read(buf)
    }
}

/// One member's data, from [`Members::data`].
pub(crate) struct MemberData<'a, R> {
    m: &'a mut Members<R>,
}

impl<R: Read> Read for MemberData<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.m.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.m.left).unwrap_or(usize::MAX));
        let n = self.m.r.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ar: a member's data is cut short",
            ));
        }
        self.m.left -= n as u64;
        self.m.pos += n as u64;
        Ok(n)
    }
}

pub struct ArReader {
    source: Source,
    entries: Vec<Entry>,
    members: Vec<Member>,
    symbols: bool,
    file: Option<BufReader<CountingReader<Input>>>,
    scan: Option<Members<Box<dyn Read + Send>>>,
}

impl ArReader {
    /// Reads the member headers, skipping the data where the file can seek.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let mut r = Self {
            source,
            entries: Vec::new(),
            members: Vec::new(),
            symbols: false,
            file: None,
            scan: None,
        };
        r.list(cx)?;
        Ok(r)
    }

    fn stream(&self) -> Result<Box<dyn Read + Send>> {
        if self.source.codecs.is_empty() {
            Ok(Box::new(BufReader::with_capacity(
                BUF_SIZE,
                self.source.open_file()?,
            )))
        } else {
            self.source.open_stream()
        }
    }

    fn list(&mut self, cx: &mut dyn Ctx) -> Result<()> {
        let mut m = Members::new(self.stream()?)?;
        let names = self.source.names;
        while let Some(member) = m.next()? {
            cx.check()?;
            let id = self.entries.len();
            self.source.limits.check_entries(id as u64 + 1)?;
            if self.source.codecs.is_empty()
                && member.data_at.saturating_add(member.size) > self.source.size
            {
                return Err(corrupt("a member runs past the end of the file"));
            }
            self.entries.push(entry_for(id, &member, &names));
            self.members.push(member);
        }
        self.symbols = m.symbols;
        Ok(())
    }

    /// Writes the `keep` members to `w` with new headers and their data as it is.
    fn copy_into(&mut self, w: &mut ArWriter<'_>, keep: &[Keep], cx: &mut dyn Ctx) -> Result<u64> {
        let mut paths: Vec<Option<&str>> = vec![None; self.entries.len()];
        for k in keep {
            if let Some(p) = paths.get_mut(k.id) {
                *p = Some(k.path.as_str());
            }
        }
        if self.symbols {
            cx.warn(
                "the archive's symbol table was left out, since it would point at the old \
                 places; `ranlib` makes it again"
                    .into(),
            );
        }
        let mut m = Members::new(self.stream()?)?;
        let mut id = 0usize;
        let mut copied = 0u64;
        while let Some(member) = m.next()? {
            cx.check()?;
            if let Some(Some(path)) = paths.get(id) {
                w.header(
                    path,
                    member.mtime,
                    member.uid,
                    member.gid,
                    member.mode,
                    member.size,
                )?;
                let n = crate::io::copy(&mut m.data(), &mut w.out, cx)?;
                if n != member.size {
                    return Err(corrupt("a member's data is cut short"));
                }
                w.pad(member.size)?;
                copied += 1;
            }
            id += 1;
        }
        if id != self.entries.len() {
            return Err(corrupt("the members changed on a second pass"));
        }
        Ok(copied)
    }
}

pub(crate) fn entry_for(id: usize, m: &Member, names: &crate::NameDecoding) -> Entry {
    Entry {
        id,
        path: names.decode(&m.name, false, SystemPage::Ansi),
        raw_path: m.name.clone(),
        kind: EntryKind::File,
        size: Some(m.size),
        packed_size: Some(m.size),
        modified: i64::try_from(m.mtime).ok().and_then(|s| from_unix(s, 0)),
        crc32: None,
        method: None,
        encrypted: false,
        unix_mode: u32::try_from(m.mode).ok(),
        dos_attrs: None,
    }
}

impl ArchiveReader for ArReader {
    fn format(&self) -> FormatId {
        FormatId::Ar
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Ar,
            codecs: self.source.codecs.clone(),
            methods: Vec::new(),
            comment: None,
            encryption: Encryption::None,
            solid: false,
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
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
        meter.entries_total = Some(self.entries.len() as u64);
        let mut m = Members::new(self.stream()?)?;
        let mut id = 0usize;
        while let Some(_member) = m.next()? {
            cx.check()?;
            let Some(e) = self.entries.get(id) else {
                return Err(corrupt("the members changed on a second pass"));
            };
            if sel.matches(e) {
                meter.entries_done = id as u64;
                meter.current = Some(e.path.clone());
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.report();
                let mut data = self.source.guard(m.data());
                sink.entry(e, &mut data, &mut mcx)?;
            }
            id += 1;
        }
        meter.entries_done = id as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let member = self
            .members
            .get(id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        if self.source.codecs.is_empty() {
            let mut file = BufReader::with_capacity(BUF_SIZE, self.source.open_file()?);
            file.seek(SeekFrom::Start(member.data_at))
                .map_err(|e| Error::io("seeking in the ar", &e))?;
            let file = self.file.insert(file);
            return Ok(Box::new(self.source.guard(file.take(member.size))));
        }
        let mut m = Members::new(self.source.open_stream()?)?;
        for _ in 0..=id {
            cx.check()?;
            m.next()?
                .ok_or_else(|| corrupt("a member vanished on a second pass"))?;
        }
        let m = self.scan.insert(m);
        Ok(Box::new(self.source.guard(m.data())))
    }
}

/// Writes a GNU ar to `out`.
pub struct ArWriter<'a> {
    out: Box<dyn FinishWrite + 'a>,
    started: bool,
    /// Long names' places in the `//` table, by path.
    long: HashMap<String, usize>,
}

impl<'a> ArWriter<'a> {
    pub fn new(out: Box<dyn FinishWrite + 'a>) -> Self {
        Self {
            out,
            started: false,
            long: HashMap::new(),
        }
    }

    fn w(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes).map_err(|e| write_error(&e))
    }

    /// A name that must go in the table: too long for the field, or holding a `/`.
    fn needs_table(name: &str) -> bool {
        name.len() > 15 || name.contains('/') || name.ends_with(' ') || name.is_empty()
    }

    fn header(
        &mut self,
        path: &str,
        mtime: u64,
        uid: u64,
        gid: u64,
        mode: u64,
        size: u64,
    ) -> Result<()> {
        if size > MAX_SIZE {
            return Err(too_big(path));
        }
        let name = path.trim_end_matches('/');
        let field = match self.long.get(name) {
            Some(off) => format!("/{off}"),
            None if Self::needs_table(name) => {
                return Err(Error::invalid_args(format!(
                    "the ar writer wasn't told of `{name}` before it was added"
                )));
            }
            None => format!("{name}/"),
        };
        let h = format!(
            "{field:<16}{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
            mtime.min(999_999_999_999),
            uid.min(999_999),
            gid.min(999_999),
            mode & 0o777_777,
            size
        );
        if h.len() != HEADER_LEN {
            return Err(Error::invalid_args(format!(
                "`{name}` can't be stored in an ar header"
            )));
        }
        self.w(h.as_bytes())
    }

    fn pad(&mut self, size: u64) -> Result<()> {
        if size % 2 == 1 {
            self.w(b"\n")?;
        }
        Ok(())
    }

    /// The magic and the name table, once.
    fn start(&mut self, names: &[&str]) -> Result<()> {
        if self.started {
            return Ok(());
        }
        self.started = true;
        self.w(MAGIC)?;
        let mut table = Vec::new();
        for name in names {
            if Self::needs_table(name) && !self.long.contains_key(*name) {
                self.long.insert((*name).to_owned(), table.len());
                table.extend_from_slice(name.as_bytes());
                table.extend_from_slice(b"/\n");
            }
        }
        if !table.is_empty() {
            let h = format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "//",
                "",
                "",
                "",
                "",
                table.len()
            );
            self.w(h.as_bytes())?;
            self.w(&table)?;
            self.pad(table.len() as u64)?;
        }
        Ok(())
    }
}

fn too_big(path: &str) -> Error {
    Error::invalid_args(format!(
        "`{path}` is 10 GB or more, which an ar can't hold; use tar, zip or 7z"
    ))
}

impl ArchiveWriter for ArWriter<'_> {
    fn expect(&mut self, entries: &[NewEntry]) -> Result<()> {
        if let Some(e) = entries.iter().find(|e| e.size > MAX_SIZE) {
            return Err(too_big(&e.path));
        }
        let names: Vec<&str> = entries
            .iter()
            .filter(|e| e.kind == NewKind::File)
            .map(|e| e.path.trim_end_matches('/'))
            .collect();
        self.start(&names)
    }

    fn holds(&self, kind: &NewKind) -> bool {
        *kind == NewKind::File
    }

    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        if entry.kind != NewKind::File {
            return Ok(());
        }
        self.start(&[])?;
        let mtime = entry
            .modified
            .map(to_unix)
            .unwrap_or(0)
            .max(0)
            .unsigned_abs();
        let mode = u64::from(0o100_000 | entry.unix_mode.map_or(0o644, |m| m & 0o7777));
        self.header(&entry.path, mtime, 0, 0, mode, entry.size)?;
        crate::io::copy(&mut ExactReader::new(data, entry.size), &mut self.out, cx)?;
        self.pad(entry.size)
    }

    fn copy_from(
        &mut self,
        source: &mut dyn ArchiveReader,
        keep: &[Keep],
        cx: &mut dyn Ctx,
    ) -> Result<Copied> {
        let Some(r) = source.as_any_mut().downcast_mut::<ArReader>() else {
            return Ok(Copied::nothing(keep));
        };
        self.start(&[])?;
        let n = r.copy_into(self, keep, cx)?;
        Ok(Copied {
            copied: n,
            ..Copied::default()
        })
    }

    fn finish(mut self: Box<Self>) -> Result<()> {
        self.start(&[])?;
        let out = self.out;
        out.finish().map_err(|e| write_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimpleCtx, codec::finisher};

    fn header(name: &str, size: usize) -> Vec<u8> {
        format!(
            "{name:<16}{:<12}{:<6}{:<6}{:<8}{size:<10}`\n",
            1_700_000_000, 0, 0, 100_644
        )
        .into_bytes()
    }

    fn member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = header(name, data.len());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    fn list(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        let mut m = Members::new(bytes)?;
        let mut out = Vec::new();
        while let Some(member) = m.next()? {
            let mut data = Vec::new();
            m.data()
                .read_to_end(&mut data)
                .map_err(|e| read_error(&e))?;
            out.push((String::from_utf8_lossy(&member.name).into_owned(), data));
        }
        Ok(out)
    }

    #[test]
    fn reads_gnu_names_and_skips_symbols() {
        let table = b"a-rather-long-name.o/\nsub/dir/x.o/\n";
        let mut ar = MAGIC.to_vec();
        ar.extend(member("/", b"\0\0\0\0"));
        ar.extend(member("//", table));
        ar.extend(member("short.o/", b"abc"));
        ar.extend(member("/0", b"long"));
        ar.extend(member("/22", b"x"));
        let got = list(&ar).unwrap();
        assert_eq!(
            got,
            [
                ("short.o".into(), b"abc".to_vec()),
                ("a-rather-long-name.o".into(), b"long".to_vec()),
                ("sub/dir/x.o".into(), b"x".to_vec()),
            ]
        );
    }

    #[test]
    fn reads_bsd_names() {
        let mut ar = MAGIC.to_vec();
        let mut symdef = b"__.SYMDEF SORTED\0\0\0\0".to_vec();
        symdef.extend_from_slice(&[0; 8]);
        ar.extend(member("#1/20", &symdef));
        let mut data = b"a-long-bsd-name.txt\0".to_vec();
        data.extend_from_slice(b"hello");
        ar.extend(member("#1/20", &data));
        ar.extend(member("plain.txt", b"hi"));
        let got = list(&ar).unwrap();
        assert_eq!(
            got,
            [
                ("a-long-bsd-name.txt".into(), b"hello".to_vec()),
                ("plain.txt".into(), b"hi".to_vec()),
            ]
        );
    }

    #[test]
    fn bad_archives_are_refused() {
        assert_eq!(
            Members::new(&b"!<thin>\n"[..]).err().map(|e| e.kind),
            Some(ErrorKind::UnsupportedFormat)
        );
        let mut ar = MAGIC.to_vec();
        ar.extend(member("a/", b"hello"));
        for cut in [20, 8 + 59, ar.len() - 3] {
            assert_eq!(
                list(&ar[..cut]).unwrap_err().kind,
                ErrorKind::Corrupt,
                "{cut}"
            );
        }
        let mut long = MAGIC.to_vec();
        long.extend(member("/99", b"x"));
        assert_eq!(list(&long).unwrap_err().kind, ErrorKind::Corrupt);
        let mut huge = MAGIC.to_vec();
        huge.extend(header("//", 999_999_999));
        assert_eq!(list(&huge).unwrap_err().kind, ErrorKind::Corrupt);
        let mut bsd = MAGIC.to_vec();
        bsd.extend(header("#1/99999", 4));
        bsd.extend_from_slice(b"abcd");
        assert_eq!(list(&bsd).unwrap_err().kind, ErrorKind::Corrupt);
    }

    #[test]
    fn writes_gnu_with_a_name_table() {
        let mut buf = Vec::new();
        {
            let out = finisher(&mut buf, |w: &mut Vec<u8>| w.flush());
            let mut w = Box::new(ArWriter::new(out));
            let file = |path: &str, size| NewEntry {
                path: path.into(),
                kind: NewKind::File,
                size,
                modified: None,
                unix_mode: None,
                dos_attrs: None,
            };
            let entries = [
                file("a.txt", 5),
                file("a-name-over-fifteen.txt", 2),
                file("d/b", 1),
            ];
            assert_eq!(
                w.expect(&[file("huge", 10_000_000_000)]).unwrap_err().kind,
                ErrorKind::InvalidArgs
            );
            w.expect(&entries).unwrap();
            let mut cx = SimpleCtx::new();
            w.add(&entries[0], &mut &b"hello"[..], &mut cx).unwrap();
            w.add(&entries[1], &mut &b"hi"[..], &mut cx).unwrap();
            w.add(&entries[2], &mut &b"x"[..], &mut cx).unwrap();
            w.finish().unwrap();
        }
        let got = list(&buf).unwrap();
        assert_eq!(
            got,
            [
                ("a.txt".into(), b"hello".to_vec()),
                ("a-name-over-fifteen.txt".into(), b"hi".to_vec()),
                ("d/b".into(), b"x".to_vec()),
            ]
        );
        assert!(buf.windows(4).any(|w| w == b"//  "));
    }
}
