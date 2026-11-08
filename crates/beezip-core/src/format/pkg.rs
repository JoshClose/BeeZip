//! macOS flat packages (docs/M6.md §5), read only: a XAR (xar.rs), listed as
//! `pkgutil --expand-full` unpacks it.
//!
//! - **A component package** holds `Bom`, `PackageInfo`, `Payload` and maybe `Scripts`.
//!   `Payload` and `Scripts` become folders of their cpio's contents: each member under the
//!   folder without its leading `./`, the cpio's own `.` being the folder itself (its mode and
//!   time). Everything else stays a file at its XAR path. `pkgbuild --large-payload` (macOS 12
//!   and up) names the payload `LargeSegmentedPayload`, a pbzx'd odc cpio as `--compression
//!   latest` makes, and `pkgutil --expand-full` expands it the same way under that name.
//! - **A product archive** holds `Distribution`, maybe `Resources/…`, and a `name.pkg/` folder
//!   per component, whose `Payload` and `Scripts` are expanded the same way inside it.
//! - **Payloads** are cpio (odc from Apple's tools, newc from others, whose hard links are
//!   resolved as cpio.rs resolves them), plain, gzip'd or in pbzx (pbzx.rs). An Apple Archive
//!   payload (Apple Archive's own `pbz?` streams, or `AA01` inside pbzx; macOS 26's pkgbuild
//!   writes none, with any option) is listed as one file with a warning, and `Apple Archive`
//!   among the archive's methods; so is anything else that isn't a cpio, without the method.
//! - **Reading** decodes each expanded payload once for the listing, and once per extraction or
//!   test, in the XAR's order, then reads it to its end so the XAR checks its checksums; opening
//!   one of its members decodes the payload again from its start, as deb.rs does.
//! - **Signatures** aren't checked.

use std::{
    borrow::Cow,
    collections::HashMap,
    io::{self, BufReader, Cursor, Read},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
    cpio::{self, Members},
    link_target, normalize,
    pbzx::{self, Pbzx},
    xar::{self, Archive, Failing, Header, Rec, RecKind},
};
use crate::{
    CodecId, Ctx, Error, ErrorKind, Limits, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, read_error},
    names::NameDecoding,
    source::Source,
};

pub struct Pkg;

/// The most of the table of contents inflated for sniffing.
const SNIFF_XML: usize = 1 << 20;
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

impl ArchiveFormat for Pkg {
    fn id(&self) -> FormatId {
        FormatId::Pkg
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".pkg", ".mpkg"]
    }

    /// A XAR whose table of contents, as far as the probe holds it, names a package: a
    /// `Distribution` or `PackageInfo` at the top, or a `name.pkg` folder holding a
    /// `PackageInfo`.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let h = Header::parse(probe.head, probe.len).ok()?;
        let start = usize::from(h.size);
        let end = usize::try_from(h.toc_packed)
            .ok()?
            .saturating_add(start)
            .min(probe.head.len());
        let xml = xar::toc_prefix(probe.head.get(start..end)?, SNIFF_XML);
        let toc = xar::parse_toc(&xml[..], true, &mut || Ok(())).ok()?;
        is_package(&toc.recs).then_some(Confidence::Certain)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}

fn is_package(recs: &[Rec]) -> bool {
    fn name(r: &Rec) -> Option<&[u8]> {
        r.name.as_deref()
    }
    recs.iter().any(|r| match r.parent {
        None => matches!(name(r), Some(b"Distribution" | b"PackageInfo")),
        Some(p) => {
            name(r) == Some(b"PackageInfo")
                && recs.get(p).is_some_and(|d| {
                    d.parent.is_none()
                        && d.kind == Some(RecKind::Dir)
                        && name(d).is_some_and(|n| n.ends_with(b".pkg"))
                })
        }
    })
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::corrupt(format!("pkg: {}", msg.into()))
}

/// What holds a payload's cpio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    Gzip,
    Pbzx,
    /// Nothing: the cpio as it is.
    Plain,
}

impl Container {
    fn method(self) -> Option<&'static str> {
        match self {
            Self::Gzip => Some("gzip"),
            Self::Pbzx => Some("pbzx"),
            Self::Plain => None,
        }
    }
}

/// What a XAR entry is in the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// Itself.
    Plain,
    /// A folder of its cpio's members.
    Expanded(Container),
}

/// Where a listed entry comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// A XAR entry, by its id there.
    Xar(usize),
    /// An expanded payload's folder.
    Folder,
    /// Member `nth` (counting from 0, the `.` too) of the cpio in XAR entry `xar`.
    Member { xar: usize, nth: usize },
}

/// What a payload turned out to be.
enum Found {
    Cpio(Container),
    AppleArchive,
    Unknown,
}

/// A `Payload`, `LargeSegmentedPayload` or `Scripts` file where `pkgutil --expand-full`
/// expands one: at the top (a component package) or in a top-level `name.pkg` folder (a product
/// archive's component).
fn expandable(e: &Entry) -> bool {
    if e.kind != EntryKind::File {
        return false;
    }
    let (dir, name) = match e.path.rsplit_once('/') {
        Some((d, n)) => (Some(d), n),
        None => (None, e.path.as_str()),
    };
    matches!(name, "Payload" | "LargeSegmentedPayload" | "Scripts")
        && dir.is_none_or(|d| !d.contains('/') && d.ends_with(".pkg"))
}

/// Reads up to `buf.len()` bytes, fewer only at the end.
fn read_up_to(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn is_cpio(head: &[u8]) -> bool {
    matches!(head.get(..6), Some(b"070707" | b"070701" | b"070702"))
        || matches!(head.get(..2), Some([0xC7, 0x71] | [0x71, 0xC7]))
}

fn is_apple_archive(head: &[u8]) -> bool {
    head.starts_with(b"AA01") || head.starts_with(b"YAA1")
}

/// A payload's decoded stream: its container undone. The XAR's reader of a stored payload
/// reads the file directly, and cpio's headers and xz come in small reads: buffered here.
fn open_container<'a>(
    r: Box<dyn Read + Send + 'a>,
    c: Container,
    limits: &Limits,
) -> Result<Box<dyn Read + Send + 'a>> {
    let r = Box::new(BufReader::with_capacity(BUF_SIZE, r));
    match c {
        Container::Gzip => CodecId::Gzip.decoder(r, limits),
        Container::Pbzx => Ok(Box::new(
            Pbzx::new(r, limits.decoder_memory_kib()).map_err(|e| read_error(&e))?,
        )),
        Container::Plain => Ok(r),
    }
}

/// Looks at the start of XAR entry `x`'s data, and inside its container.
fn payload_kind(xar: &mut Archive, x: usize, limits: &Limits) -> Result<Found> {
    let mut r = xar.reader(x)?;
    let mut magic = [0u8; 8];
    let n = read_up_to(&mut r, &mut magic).map_err(|e| read_error(&e))?;
    let head = &magic[..n];
    let container = if head.starts_with(&[0x1F, 0x8B]) {
        Container::Gzip
    } else if head.starts_with(pbzx::MAGIC) {
        Container::Pbzx
    } else if head.starts_with(b"pbz") || is_apple_archive(head) {
        // Apple Archive's own compressed streams: pbze (LZFSE), pbz4, pbzz, pbzb.
        return Ok(Found::AppleArchive);
    } else {
        Container::Plain
    };
    let whole: Box<dyn Read + Send + '_> = Box::new(Cursor::new(head.to_vec()).chain(r));
    let mut inner = open_container(whole, container, limits)?;
    let mut first = [0u8; 6];
    let n = read_up_to(&mut inner, &mut first).map_err(|e| read_error(&e))?;
    let first = &first[..n];
    Ok(if is_cpio(first) {
        Found::Cpio(container)
    } else if is_apple_archive(first) {
        Found::AppleArchive
    } else {
        Found::Unknown
    })
}

/// One pass over the package in listing order: `each` gets every entry (its id counted here),
/// where it comes from, and its data. Plain XAR entries' data is read only with `data`;
/// expanded payloads are always decoded, and with `data` read to their end, which checks the
/// XAR's checksums of them.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn walk(
    xar: &mut Archive,
    parts: &[Part],
    names: NameDecoding,
    limits: &Limits,
    data: bool,
    each: &mut dyn FnMut(&Entry, Origin, &mut dyn Read, &mut dyn Ctx) -> Result<()>,
    cx: &mut dyn Ctx,
) -> Result<()> {
    let mut id = 0usize;
    let next_id = |id: &mut usize| -> Result<usize> {
        let this = *id;
        *id += 1;
        limits.check_entries(*id as u64)?;
        Ok(this)
    };
    for x in 0..xar.entries.len() {
        cx.check()?;
        let Some(Part::Expanded(c)) = parts.get(x).copied() else {
            let mut e = xar.entries[x].clone();
            e.id = next_id(&mut id)?;
            let mut r: Box<dyn Read + '_> = if data && e.kind == EntryKind::File {
                match xar.reader(x) {
                    Ok(r) => r,
                    Err(err) => Box::new(Failing(err)),
                }
            } else {
                Box::new(io::empty())
            };
            each(&e, Origin::Xar(x), &mut r, cx)?;
            continue;
        };
        let file = xar.entries[x].clone();
        let base = file.path.clone();
        let mut folder = Entry::new(0, format!("{base}/"), EntryKind::Dir);
        folder.raw_path = file.raw_path.clone();
        folder.modified = file.modified;
        let mut have_folder = false;
        let mut links: HashMap<(u64, u64, u64), String> = HashMap::new();
        let mut waiting: HashMap<(u64, u64, u64), Vec<(Entry, Origin)>> = HashMap::new();
        let mut m = Members::new(open_container(xar.reader(x)?, c, limits)?);
        let mut nth = 0usize;
        while let Some(h) = m.next(&|_| None)? {
            cx.check()?;
            if h.is_trailer() {
                break;
            }
            let this = nth;
            nth += 1;
            if h.kind == cpio::Kind::Stripped {
                return Err(corrupt(format!("`{base}` has a stripped cpio header")));
            }
            let target = if h.mode & S_IFMT == S_IFLNK {
                cpio::read_target(&mut m.data(), h.size, &names)?
            } else {
                String::new()
            };
            let mut e = cpio::entry_for(0, &h, &names, target);
            let rel = normalize(&e.path);
            if rel.is_empty() || rel == "." {
                // The payload's root: the folder itself. A second one is left out.
                if !have_folder {
                    have_folder = true;
                    folder.id = next_id(&mut id)?;
                    folder.modified = e.modified;
                    folder.unix_mode = e.unix_mode;
                    each(&folder, Origin::Folder, &mut io::empty(), cx)?;
                }
                continue;
            }
            if !have_folder {
                have_folder = true;
                folder.id = next_id(&mut id)?;
                each(&folder, Origin::Folder, &mut io::empty(), cx)?;
            }
            e.path = format!("{base}/{rel}");
            e.raw_path = e.path.as_bytes().to_vec();
            if e.kind == EntryKind::Dir {
                e.path.push('/');
            }
            if c != Container::Plain {
                e.packed_size = None;
            }
            let origin = Origin::Member { xar: x, nth: this };
            // newc's hard links: the group's data is in its last member, and the others are
            // links to it, each handed out once the data has been (as cpio.rs does).
            match h.link_key() {
                Some(key) if h.size == 0 => match links.get(&key) {
                    Some(target) => {
                        e.kind = EntryKind::Hardlink {
                            target: target.clone(),
                        };
                        e.size = None;
                        e.packed_size = None;
                        e.id = next_id(&mut id)?;
                        each(&e, origin, &mut io::empty(), cx)?;
                    }
                    None => waiting.entry(key).or_default().push((e, origin)),
                },
                Some(key) => {
                    e.id = next_id(&mut id)?;
                    each(&e, origin, &mut m.data(), cx)?;
                    for (mut link, origin) in waiting.remove(&key).unwrap_or_default() {
                        link.kind = EntryKind::Hardlink {
                            target: e.path.clone(),
                        };
                        link.size = None;
                        link.packed_size = None;
                        link.id = next_id(&mut id)?;
                        each(&link, origin, &mut io::empty(), cx)?;
                    }
                    links.insert(key, e.path);
                }
                None => {
                    e.id = next_id(&mut id)?;
                    each(&e, origin, &mut m.data(), cx)?;
                }
            }
        }
        if !m.ended {
            return Err(corrupt(format!("`{base}`'s cpio ends without its trailer")));
        }
        // Links whose group never had data: empty files.
        let mut rest: Vec<(Entry, Origin)> = waiting.into_values().flatten().collect();
        rest.sort_by_key(|(_, o)| match o {
            Origin::Member { nth, .. } => *nth,
            _ => 0,
        });
        for (mut e, origin) in rest {
            e.id = next_id(&mut id)?;
            each(&e, origin, &mut io::empty(), cx)?;
        }
        if !have_folder {
            folder.id = next_id(&mut id)?;
            each(&folder, Origin::Folder, &mut io::empty(), cx)?;
        }
        if data {
            // The payload's end, so the XAR checks its size and checksums.
            io::copy(&mut m.into_inner(), &mut io::sink()).map_err(|e| read_error(&e))?;
        }
    }
    Ok(())
}

/// One member's data, by itself.
struct MemberReader<R>(Members<R>);

impl<R: Read> Read for MemberReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.data().read(buf)
    }
}

pub struct PkgReader {
    source: Source,
    xar: Archive,
    /// What each XAR entry is, by its id there.
    parts: Vec<Part>,
    entries: Vec<Entry>,
    from: Vec<Origin>,
    methods: Vec<Cow<'static, str>>,
}

impl PkgReader {
    /// Reads the table of contents, then each payload once, for the listing.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let mut xar = Archive::open(&source, cx)?;
        let limits = source.limits.clone();
        let mut parts = vec![Part::Plain; xar.entries.len()];
        let mut methods = xar.methods();
        fn add(m: &'static str, methods: &mut Vec<Cow<'static, str>>) {
            if !methods.iter().any(|x| x == m) {
                methods.push(m.into());
            }
        }
        // Each payload's data is expanded once: copies of it (xar's `--link-same`, or a
        // crafted table naming one stream many times) stay files, so listing decodes it once.
        let mut expanded: HashMap<(u64, u64), String> = HashMap::new();
        for (x, part) in parts.iter_mut().enumerate() {
            if !expandable(&xar.entries[x]) || xar.bad_toc.is_some() {
                continue;
            }
            let path = xar.entries[x].path.clone();
            let range = xar.data_range(x);
            if let Some(first) = range.and_then(|r| expanded.get(&r)) {
                cx.warn(format!(
                    "pkg: `{path}` is the same data as `{first}`: it's listed as one file"
                ));
                continue;
            }
            match payload_kind(&mut xar, x, &limits) {
                Ok(Found::Cpio(c)) => {
                    *part = Part::Expanded(c);
                    if let Some(r) = range {
                        expanded.insert(r, path);
                    }
                    if let Some(m) = c.method() {
                        add(m, &mut methods);
                    }
                }
                Ok(Found::AppleArchive) => {
                    cx.warn(format!(
                        "pkg: `{path}` is an Apple Archive, which BeeZip doesn't expand: it's listed as one file"
                    ));
                    add("Apple Archive", &mut methods);
                }
                Ok(Found::Unknown) => cx.warn(format!(
                    "pkg: `{path}` isn't a cpio BeeZip reads: it's listed as one file"
                )),
                Err(e) if e.kind == ErrorKind::Cancelled => return Err(e),
                Err(e) => cx.warn(format!(
                    "pkg: `{path}` can't be expanded ({e}): it's listed as one file"
                )),
            }
        }
        let mut entries = Vec::new();
        let mut from = Vec::new();
        walk(
            &mut xar,
            &parts,
            source.names,
            &limits,
            false,
            &mut |e, f, _, _| {
                entries.push(e.clone());
                from.push(f);
                Ok(())
            },
            cx,
        )?;
        Ok(Self {
            source,
            xar,
            parts,
            entries,
            from,
            methods,
        })
    }
}

impl ArchiveReader for PkgReader {
    fn format(&self) -> FormatId {
        FormatId::Pkg
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Pkg,
            codecs: self.source.codecs.clone(),
            methods: self.methods.clone(),
            comment: None,
            encryption: Encryption::None,
            solid: self.parts.iter().any(|p| *p != Part::Plain),
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
        if let Some(e) = &self.xar.bad_toc {
            return Err(e.clone());
        }
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.xar.len));
        let total = self.entries.len();
        meter.entries_total = Some(total as u64);
        self.source.counter.set(self.xar.heap);
        let source = &self.source;
        walk(
            &mut self.xar,
            &self.parts,
            source.names,
            &source.limits,
            true,
            &mut |e, _, data, cx| {
                if e.id >= total {
                    return Err(corrupt("the package changed since it was opened"));
                }
                if !sel.matches(e) {
                    return Ok(());
                }
                meter.entries_done = e.id as u64;
                meter.current = Some(e.path.clone());
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.report();
                let mut data = source.guard(data);
                sink.entry(e, &mut data, &mut mcx)
            },
            cx,
        )?;
        meter.entries_done = total as u64;
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
            EntryKind::Hardlink { target } => link_target(&self.entries, entry)
                .map(|t| t.id)
                .ok_or_else(|| corrupt(format!("hard link target `{target}` is missing")))?,
            _ => return Ok(Box::new(io::empty())),
        };
        match self.from[id] {
            Origin::Xar(x) => Ok(Box::new(self.source.guard(self.xar.reader(x)?))),
            Origin::Folder => Ok(Box::new(io::empty())),
            Origin::Member { xar: x, nth } => {
                let Some(Part::Expanded(c)) = self.parts.get(x).copied() else {
                    return Err(corrupt("a member of a payload that isn't expanded"));
                };
                let stream = open_container(self.xar.reader(x)?, c, &self.source.limits)?;
                let mut m = Members::new(stream);
                let vanished = || corrupt("a payload's member vanished on a second pass");
                for _ in 0..nth {
                    cx.check()?;
                    m.next(&|_| None)?.ok_or_else(vanished)?;
                }
                m.next(&|_| None)?.ok_or_else(vanished)?;
                Ok(Box::new(self.source.guard(MemberReader(m))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_expand_where_pkgutil_expands_them() {
        let f = |p: &str| expandable(&Entry::new(0, p.into(), EntryKind::File));
        assert!(f("Payload"));
        assert!(f("Scripts"));
        assert!(f("foo.pkg/Payload"));
        assert!(f("foo.pkg/Scripts"));
        assert!(f("LargeSegmentedPayload"));
        assert!(f("foo.pkg/LargeSegmentedPayload"));
        assert!(!f("Bom"));
        assert!(!f("Resources/Payload"));
        assert!(!f("a/foo.pkg/Payload"));
        assert!(!expandable(&Entry::new(
            0,
            "Payload/".into(),
            EntryKind::Dir
        )));
    }

    #[test]
    fn packages_are_named_by_their_table() {
        let rec = |name: &str, parent: Option<usize>, kind: RecKind| Rec {
            parent,
            name: Some(name.as_bytes().to_vec()),
            kind: Some(kind),
            ..Rec::default()
        };
        assert!(is_package(&[rec("Distribution", None, RecKind::File)]));
        assert!(is_package(&[
            rec("Bom", None, RecKind::File),
            rec("PackageInfo", None, RecKind::File)
        ]));
        assert!(is_package(&[
            rec("x.pkg", None, RecKind::Dir),
            rec("PackageInfo", Some(0), RecKind::File)
        ]));
        assert!(!is_package(&[
            rec("x", None, RecKind::Dir),
            rec("PackageInfo", Some(0), RecKind::File)
        ]));
        assert!(!is_package(&[rec("hello.txt", None, RecKind::File)]));
    }
}
