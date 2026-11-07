//! ISO 9660 with Joliet and Rock Ridge, and UDF (docs/M5.md §5.9), through hadris-iso and
//! hadris-udf 3.0 (rc.3, the newest published; hadris-iso is BeeZip's patched copy in
//! vendor/hadris-iso, whose name de-duplication no longer retries every suffix).
//!
//! - **Reading:** the tree comes from Rock Ridge, else Joliet, else the primary names (hadris's
//!   `Namespace::Preferred`). hadris puts Rock Ridge's relocated folders back, joins multi-extent
//!   files and hides the `;1` versions. When the volume also has UDF's NSR descriptors and the UDF
//!   tree has more entries, it is listed instead: Windows' ISOs have an empty ISO 9660 tree. A
//!   folder already visited is skipped, since a crafted image can make a cycle. zisofs files
//!   (Rock Ridge `ZF`) are listed with their real size, and extracting one is
//!   `UnsupportedOperation`. El Torito boot images aren't listed.
//! - **Names:** Rock Ridge and primary names are bytes, read through the source's `NameDecoding`
//!   (docs/M5.md §6); Joliet and UDF names are Unicode.
//! - **Writing:** ISO 9660 level 3 (files of 4 GiB and more in several extents) with Joliet and
//!   Rock Ridge. hadris reads every file by its host path when the image is written, so the
//!   writer takes files by path ([`NewEntry::source`]) and spools entries with no file behind them
//!   (a convert) to temporary files beside the output. hadris's warnings (names cut for Joliet,
//!   folders relocated) become the job's.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use hadris_fs::{
    DateTime, DirCursor, FileType, MountOptions, Node, NodeId, OpenMode, Permissions, SetAttr,
    Tree, WarningKind, sync::FileSystem,
};
use hadris_io::StdIo;
use hadris_iso::{IsoId, IsoLevel, IsoOptions, Namespace, sync::IsoFs};
use hadris_storage::{BlockSize, ReadOnly, sync::StreamDevice};
use hadris_udf::sync::UdfFs;

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, NewEntry, NewKind, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Progress, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, CountingReader, WriteSeek, copy},
    names::{NameDecoding, SystemPage},
    safefs::Partial,
    source::{Input, Source},
    time::{from_unix, to_unix},
};

pub struct Iso;

/// Volume descriptors start at sector 16 of 2 048 bytes.
const SECTOR: usize = 2048;
const DESCRIPTORS: usize = 16 * SECTOR;
/// How many descriptors are looked at for UDF's NSR.
const MAX_DESCRIPTORS: usize = 64;
/// Folders deeper than this are refused: a crafted image could nest them without end.
const MAX_DEPTH: usize = 1024;
/// The most of one folder's records read to find zisofs files.
const MAX_DIR_RECORDS: u64 = 16 * 1024 * 1024;
/// A symlink target is at most this long.
const MAX_LINK: usize = 64 * 1024;

impl ArchiveFormat for Iso {
    fn id(&self) -> FormatId {
        FormatId::Iso
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".iso"]
    }

    /// `CD001` (ISO 9660) or UDF's `BEA01`, `NSR02` or `NSR03` in one of the first three volume
    /// descriptors, with version 1, is certain.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        for i in 0..3 {
            let at = DESCRIPTORS + i * SECTOR;
            let Some(d) = probe.head.get(at..at + 7) else {
                break;
            };
            let id = &d[1..6];
            if d[6] == 1 && matches!(id, b"CD001" | b"BEA01" | b"NSR02" | b"NSR03") {
                return Some(Confidence::Certain);
            }
        }
        None
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

/// ISO 9660's and UDF's 2 048-byte sectors.
const BLOCK: BlockSize = match BlockSize::new(SECTOR as u32) {
    Some(b) => b,
    None => panic!("2 048 is a block size"),
};

type Device = StreamDevice<ReadOnly<StdIo<BufReader<CountingReader<Input>>>>>;
type FsError = hadris_fs::Error<io::Error>;

fn corrupt(msg: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("ISO: {msg}"))
}

/// A hadris error as BeeZip's: damage is `Corrupt`, a device error `Io`.
fn fs_error(e: &FsError, what: &str) -> Error {
    match e.kind() {
        hadris_fs::ErrorKind::Io => Error::new(ErrorKind::Io, format!("{what}: {e}")),
        hadris_fs::ErrorKind::Unsupported => Error::unsupported_format(format!("ISO: {what}: {e}")),
        _ => corrupt(format!("{what}: {e}")),
    }
}

/// The tree an image is read through.
enum Mounted {
    Iso(Box<IsoFs<Device>>),
    Udf(Box<UdfFs<Device>>),
}

/// Calls `$body` with `$fs` bound to whichever filesystem is mounted.
macro_rules! with_fs {
    ($m:expr, $fs:ident => $body:expr) => {
        match $m {
            Mounted::Iso($fs) => $body,
            Mounted::Udf($fs) => $body,
        }
    };
}

impl Mounted {
    fn root(&self) -> NodeId {
        with_fs!(self, fs => fs.root())
    }

    fn readdir(
        &mut self,
        dir: NodeId,
        at: DirCursor,
    ) -> std::result::Result<Option<hadris_fs::DirEntry>, FsError> {
        with_fs!(self, fs => fs.readdir(dir, at))
    }

    fn readlink(&mut self, node: NodeId) -> std::result::Result<Vec<u8>, FsError> {
        let mut buf = vec![0u8; MAX_LINK];
        with_fs!(self, fs => fs.readlink(node, &mut buf).map(<[u8]>::to_vec))
    }

    fn open(&mut self, node: NodeId) -> std::result::Result<(), FsError> {
        with_fs!(self, fs => fs.open(node, OpenMode::Read))
    }

    fn close(&mut self, node: NodeId) {
        let _ = with_fs!(self, fs => fs.close(node));
    }

    fn read(
        &mut self,
        node: NodeId,
        at: u64,
        buf: &mut [u8],
    ) -> std::result::Result<usize, FsError> {
        with_fs!(self, fs => fs.read(node, at, buf))
    }

    /// The zisofs files of folder `dir`: their first records' offsets (their node ids) and real
    /// sizes, from the Rock Ridge `ZF` entries in the folder's records. hadris doesn't read
    /// `ZF`, so its sizes are the compressed ones.
    fn zisofs(&mut self, dir: NodeId) -> HashMap<u64, u64> {
        let Mounted::Iso(fs) = self else {
            return HashMap::new();
        };
        if fs.namespace() != Namespace::RockRidge {
            return HashMap::new();
        }
        let mut extents = [hadris_fs::Extent::new(0, 0); 8];
        let Ok(n) = fs.extents(dir, 0, &mut extents) else {
            return HashMap::new();
        };
        let mut found = HashMap::new();
        let mut budget = MAX_DIR_RECORDS;
        for x in &extents[..n] {
            let len = x.len().min(budget);
            budget -= len;
            let Ok(size) = usize::try_from(len) else {
                continue;
            };
            let mut buf = vec![0u8; size];
            if fs.read_raw(x.offset(), &mut buf).is_err() {
                continue;
            }
            for (at, real) in zf_records(&buf) {
                found.insert(x.offset() + at as u64, real);
            }
        }
        found
    }
}

/// The records in `buf` (a folder's records, sector after sector) with a Rock Ridge `ZF` entry of
/// zisofs (`pz`): each record's offset in `buf` and the file's uncompressed size.
fn zf_records(buf: &[u8]) -> Vec<(usize, u64)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < buf.len() {
        let len = usize::from(buf[at]);
        if len == 0 {
            // Records don't cross sectors: the rest of this one is padding.
            at = (at / SECTOR + 1) * SECTOR;
            continue;
        }
        let Some(rec) = buf.get(at..at + len) else {
            break;
        };
        if len >= 34 {
            let name = usize::from(rec[32]);
            let mut susp = 33 + name + usize::from(name % 2 == 0);
            while susp + 4 <= rec.len() {
                let e_len = usize::from(rec[susp + 2]);
                if e_len < 4 || susp + e_len > rec.len() {
                    break;
                }
                let e = &rec[susp..susp + e_len];
                if &e[..2] == b"ZF" && e_len >= 16 && &e[4..6] == b"pz" {
                    let real = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
                    out.push((at, u64::from(real)));
                }
                susp += e_len;
            }
        }
        at += len;
    }
    out
}

/// Whether the descriptors after sector 16 include UDF's NSR02 or NSR03.
fn has_udf(input: &mut (impl Read + Seek)) -> bool {
    if input.seek(SeekFrom::Start(DESCRIPTORS as u64)).is_err() {
        return false;
    }
    let mut d = [0u8; 7];
    for i in 0..MAX_DESCRIPTORS {
        let at = (DESCRIPTORS + i * SECTOR) as u64;
        if input.seek(SeekFrom::Start(at)).is_err() || input.read_exact(&mut d).is_err() {
            return false;
        }
        match &d[1..6] {
            b"NSR02" | b"NSR03" => return true,
            b"CD001" | b"BEA01" | b"BOOT2" | b"CDW02" => {}
            // TEA01 ends UDF's extended area; anything else is past the descriptors.
            _ => return false,
        }
    }
    false
}

/// How a tree's names are stored.
#[derive(Clone, Copy)]
enum Names {
    /// Rock Ridge and primary names: bytes in some code page.
    Bytes(NameDecoding),
    /// Joliet and UDF: Unicode, which hadris gives as UTF-8.
    Unicode,
}

impl Names {
    fn decode(self, raw: &[u8]) -> String {
        match self {
            Self::Bytes(n) => n.decode(raw, false, SystemPage::Ansi),
            Self::Unicode => String::from_utf8_lossy(raw).into_owned(),
        }
    }
}

/// A listed tree: the entries, each one's node, and the zisofs files.
#[derive(Default)]
struct Listing {
    entries: Vec<Entry>,
    nodes: Vec<NodeId>,
    zisofs: HashSet<usize>,
    /// Folders skipped because they had been visited already.
    cycles: u64,
}

/// One folder being listed.
struct Frame {
    dir: NodeId,
    at: DirCursor,
    prefix: String,
    raw: Vec<u8>,
    zisofs: HashMap<u64, u64>,
}

/// Lists `fs` in pre-order (a folder before its contents), names in directory order.
fn list(
    fs: &mut Mounted,
    names: Names,
    source: &Source,
    posix: bool,
    cx: &mut dyn Ctx,
) -> Result<Listing> {
    let mut out = Listing::default();
    let root = fs.root();
    let mut visited = HashSet::from([root.get()]);
    let mut stack = vec![Frame {
        dir: root,
        at: DirCursor::START,
        prefix: String::new(),
        raw: Vec::new(),
        zisofs: fs.zisofs(root),
    }];
    while let Some(top) = stack.last_mut() {
        cx.check()?;
        let shown = if top.prefix.is_empty() {
            "the top folder".to_owned()
        } else {
            format!("`{}`", top.prefix)
        };
        let Some(e) = fs
            .readdir(top.dir, top.at)
            .map_err(|e| fs_error(&e, &format!("reading {shown}")))?
        else {
            stack.pop();
            continue;
        };
        top.at = e.next_cursor();
        let raw_name = e.name().as_bytes().to_vec();
        let name = names.decode(&raw_name);
        let (path, raw) = if top.prefix.is_empty() {
            (name, raw_name)
        } else {
            let mut raw = top.raw.clone();
            raw.push(b'/');
            raw.extend_from_slice(&raw_name);
            (format!("{}/{name}", top.prefix), raw)
        };
        let id = out.entries.len();
        source.limits.check_entries(id as u64 + 1)?;
        let m = e.metadata();
        let node = e.node();
        let mut size = m.len();
        let mut method = None;
        if let Some(&real) = top.zisofs.get(&node.get()) {
            out.zisofs.insert(id);
            method = Some("zisofs");
            size = real;
        }
        let kind = match e.file_type() {
            FileType::Dir => EntryKind::Dir,
            FileType::File => EntryKind::File,
            FileType::Symlink => {
                let target = fs
                    .readlink(node)
                    .map_err(|err| fs_error(&err, &format!("reading the link `{path}`")))?;
                EntryKind::Symlink {
                    target: names.decode(&target),
                }
            }
            _ => EntryKind::Other,
        };
        let is_dir = kind == EntryKind::Dir;
        let file_type = match kind {
            EntryKind::Dir => 0o040_000,
            EntryKind::Symlink { .. } => 0o120_000,
            EntryKind::File => 0o100_000,
            _ => 0,
        };
        out.entries.push(Entry {
            id,
            path: path.clone(),
            raw_path: raw.clone(),
            size: (kind == EntryKind::File).then_some(size),
            packed_size: (kind == EntryKind::File).then_some(m.len()),
            modified: m
                .modified()
                .and_then(|t| from_unix(t.unix_seconds(), t.nanoseconds())),
            crc32: None,
            method,
            encrypted: false,
            unix_mode: posix.then(|| file_type | (m.permissions().bits() & 0o7777)),
            dos_attrs: None,
            kind,
        });
        out.nodes.push(node);
        if is_dir {
            if !visited.insert(node.get()) {
                out.cycles += 1;
                continue;
            }
            if stack.len() >= MAX_DEPTH {
                return Err(corrupt(format!(
                    "folders are nested more than {MAX_DEPTH} deep at `{path}`"
                )));
            }
            let zisofs = fs.zisofs(node);
            stack.push(Frame {
                dir: node,
                at: DirCursor::START,
                prefix: path,
                raw,
                zisofs,
            });
        }
    }
    Ok(out)
}

pub struct IsoReader {
    source: Source,
    fs: Mounted,
    tree: &'static str,
    entries: Vec<Entry>,
    nodes: Vec<NodeId>,
    zisofs: HashSet<usize>,
    /// Keeps an image spooled out of a codec alive.
    spool: Option<Partial>,
}

impl IsoReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let spool = if source.codecs.is_empty() {
            None
        } else {
            // hadris reads by offset: spool the decoded stream, under the usual limits.
            let mut tmp = Partial::create_temp("beezip-spool.iso")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            Some(tmp)
        };
        let input = |counted: bool| -> Result<CountingReader<Input>> {
            let input = match &spool {
                None => source.input()?,
                Some(tmp) => Input::file(tmp.reopen()?)?,
            };
            if counted {
                source.counter.set(0);
            }
            let counter = if counted {
                source.counter.clone()
            } else {
                crate::io::Counter::new()
            };
            Ok(CountingReader::new(input, counter))
        };
        let device = |r: CountingReader<Input>| -> Result<Device> {
            StreamDevice::new(
                ReadOnly::new(StdIo::new(BufReader::with_capacity(BUF_SIZE, r))),
                BLOCK,
            )
            .map_err(|e| Error::new(ErrorKind::Io, format!("reading the image: {e}")))
        };
        let udf = has_udf(&mut input(false)?);
        let names = source.names;

        // The ISO 9660 tree, unless the image has none.
        let iso: Candidate = match IsoFs::mount_namespace(
            device(input(true)?)?,
            MountOptions::new(),
            Namespace::Preferred,
        ) {
            Ok(fs) => {
                let ns = fs.namespace();
                let mut m = Mounted::Iso(Box::new(fs));
                let names = match ns {
                    Namespace::Joliet => Names::Unicode,
                    _ => Names::Bytes(names),
                };
                let tree = match ns {
                    Namespace::RockRidge => "Rock Ridge",
                    Namespace::Joliet => "Joliet",
                    _ => "ISO 9660",
                };
                let listed = list(&mut m, names, &source, ns == Namespace::RockRidge, cx);
                Some((tree, listed.map(|l| (m, l))))
            }
            // A UDF image whose ISO 9660 part is missing or damaged: UDF decides.
            Err(_) if udf => None,
            Err(e) => {
                return Err(match e.kind() {
                    hadris_fs::ErrorKind::NotRecognized => {
                        corrupt("there's no ISO 9660 or UDF volume descriptor")
                    }
                    _ => fs_error(e.error(), "opening the image"),
                });
            }
        };
        let udf: Candidate = if udf {
            // Counted too: if this tree is listed, its reads are the ones progress and the ratio
            // limit see.
            let listed = match UdfFs::mount(device(input(true)?)?, MountOptions::new()) {
                Ok(fs) => {
                    let mut m = Mounted::Udf(Box::new(fs));
                    list(&mut m, Names::Unicode, &source, true, cx).map(|l| (m, l))
                }
                Err(e) => Err(fs_error(e.error(), "opening the UDF volume")),
            };
            Some(("UDF", listed))
        } else {
            None
        };
        let (tree, fs, listing) = choose(iso, udf, cx)?;
        match listing.cycles {
            0 => {}
            1 => cx.warn(
                "a folder of the image appears more than once (a cycle) and was listed once".into(),
            ),
            n => cx.warn(format!(
                "{n} folders of the image appear more than once (a cycle) and were listed once"
            )),
        }
        Ok(Self {
            source,
            fs,
            tree,
            entries: listing.entries,
            nodes: listing.nodes,
            zisofs: listing.zisofs,
            spool,
        })
    }
}

/// The data of entry `e`, whose node is `node`, checked for length.
fn data<'a>(fs: &'a mut Mounted, e: &Entry, node: NodeId, zisofs: bool) -> Result<NodeReader<'a>> {
    if zisofs {
        return Err(Error::unsupported(format!(
            "`{}` is compressed with zisofs, which BeeZip doesn't decompress",
            e.path
        )));
    }
    let len = if e.kind == EntryKind::File {
        e.size.unwrap_or(0)
    } else {
        0
    };
    if e.kind == EntryKind::File {
        // Even an empty file is opened: hadris lists an entry whose Rock Ridge entries loop
        // (libarchive's rockridge_ce_loop), and only opening it finds the damage.
        fs.open(node)
            .map_err(|err| fs_error(&err, &format!("opening `{}`", e.path)))?;
        if len == 0 {
            fs.close(node);
        }
    }
    Ok(NodeReader {
        fs,
        node,
        at: 0,
        len,
        path: e.path.clone(),
    })
}

/// A tree that was mounted, by name, with its listing or why it failed.
type Candidate = Option<(&'static str, Result<(Mounted, Listing)>)>;

/// The tree to list: UDF when it has more entries than the ISO 9660 tree (Windows' images), the
/// ISO tree otherwise. A tree that failed to list loses to one that didn't, with a warning.
fn choose(
    iso: Candidate,
    udf: Candidate,
    cx: &mut dyn Ctx,
) -> Result<(&'static str, Mounted, Listing)> {
    match (iso, udf) {
        (Some((t, Ok((m, l)))), None) | (None, Some((t, Ok((m, l))))) => Ok((t, m, l)),
        (Some((_, Err(e))), None) | (None, Some((_, Err(e)))) => Err(e),
        (Some((it, Ok((im, il)))), Some((ut, Ok((um, ul))))) => {
            if ul.entries.len() > il.entries.len() {
                Ok((ut, um, ul))
            } else {
                Ok((it, im, il))
            }
        }
        (Some((it, Ok((im, il)))), Some((_, Err(e)))) => {
            cx.warn(format!(
                "the image's UDF volume couldn't be read, so its ISO 9660 tree is listed: {}",
                e.message
            ));
            Ok((it, im, il))
        }
        (Some((_, Err(e))), Some((ut, Ok((um, ul))))) => {
            cx.warn(format!(
                "the image's ISO 9660 tree couldn't be read, so its UDF volume is listed: {}",
                e.message
            ));
            Ok((ut, um, ul))
        }
        (Some((_, Err(e))), Some((_, Err(_)))) => Err(e),
        (None, None) => Err(corrupt("there's no ISO 9660 or UDF volume descriptor")),
    }
}

/// One file's data from the mounted tree.
struct NodeReader<'a> {
    fs: &'a mut Mounted,
    node: NodeId,
    at: u64,
    len: u64,
    path: String,
}

impl Read for NodeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.at >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.len - self.at).unwrap_or(usize::MAX));
        let n = self
            .fs
            .read(self.node, self.at, &mut buf[..want])
            .map_err(|e| fs_error(&e, &format!("reading `{}`", self.path)).into_io())?;
        if n == 0 {
            return Err(Error::corrupt(format!("ISO: `{}` is cut short", self.path)).into_io());
        }
        self.at += n as u64;
        if self.at >= self.len {
            self.fs.close(self.node);
        }
        Ok(n)
    }
}

impl ArchiveReader for IsoReader {
    fn format(&self) -> FormatId {
        FormatId::Iso
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods = vec![self.tree];
        if !self.zisofs.is_empty() {
            methods.push("zisofs");
        }
        Ok(ArchiveInfo {
            format: FormatId::Iso,
            codecs: self.source.codecs.clone(),
            methods,
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
        let size = match &self.spool {
            Some(tmp) => std::fs::metadata(tmp.path()).map_or(self.source.size, |m| m.len()),
            None => self.source.size,
        };
        let mut meter = Meter::new(self.source.counter.clone(), Some(size));
        meter.entries_total = Some(self.entries.len() as u64);
        for id in 0..self.entries.len() {
            cx.check()?;
            let e = self.entries[id].clone();
            if !sel.matches(&e) {
                continue;
            }
            meter.entries_done = id as u64;
            meter.current = Some(e.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.report();
            let zisofs = self.zisofs.contains(&id);
            let reader = data(&mut self.fs, &e, self.nodes[id], zisofs)?;
            let mut reader = self.source.guard(reader);
            sink.entry(&e, &mut reader, &mut mcx)?;
        }
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        if id >= self.entries.len() {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        }
        let zisofs = self.zisofs.contains(&id);
        let reader = data(&mut self.fs, &self.entries[id], self.nodes[id], zisofs)?;
        Ok(Box::new(self.source.guard(reader)))
    }
}

/// How to write an ISO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IsoWriteOptions {
    /// The volume's creation time; now when `None`. A fixed one makes the same files give the
    /// same bytes (the malicious corpus is made this way).
    pub time: Option<SystemTime>,
}

/// Writes an ISO 9660 level 3 image with Joliet and Rock Ridge.
pub struct IsoWriter {
    out: Box<dyn WriteSeek>,
    /// Where entries with no file behind them are spooled.
    dir: PathBuf,
    /// The output's name, for the spools' names.
    name: String,
    label: String,
    time: Option<SystemTime>,
    tree: Tree,
    spools: Vec<Partial>,
    files: u64,
}

impl IsoWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: IsoWriteOptions, output: &Path) -> Result<Self> {
        let dir = match output.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let name = output
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(Self {
            out,
            dir,
            label: volume_label(output),
            name,
            time: opts.time,
            tree: Tree::new(),
            spools: Vec::new(),
            files: 0,
        })
    }

    fn insert(&mut self, path: &str, node: Node) -> Result<()> {
        match self.tree.insert(path, node.clone()) {
            Ok(()) => Ok(()),
            // A folder made earlier for a file inside it, or a name given twice (the later wins,
            // as extracting would leave it).
            Err(e) if e.kind() == hadris_fs::ErrorKind::AlreadyExists => self
                .tree
                .replace(path, node)
                .map_err(|e| path_error(&e, path)),
            Err(e) => Err(path_error(&e, path)),
        }
    }
}

/// The volume identifier: the output's name without its extension, in ISO 9660's d-characters
/// (A–Z, 0–9, `_`), at most 32 of them.
fn volume_label(output: &Path) -> String {
    let stem = output
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let label: String = stem
        .chars()
        .map(|c| match c.to_ascii_uppercase() {
            c @ ('A'..='Z' | '0'..='9' | '_') => c,
            _ => '_',
        })
        .take(32)
        .collect();
    if label.trim_matches('_').is_empty() {
        "CDROM".into()
    } else {
        label
    }
}

fn path_error(e: &hadris_fs::PathError, path: &str) -> Error {
    let kind = match e.kind() {
        hadris_fs::ErrorKind::Io => ErrorKind::Io,
        hadris_fs::ErrorKind::Corrupt => ErrorKind::Corrupt,
        hadris_fs::ErrorKind::NotFound => ErrorKind::NotFound,
        _ => ErrorKind::InvalidArgs,
    };
    Error::new(kind, format!("`{path}` can't be written to the ISO: {e}"))
}

fn date(t: SystemTime) -> Option<DateTime> {
    let nanos = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    DateTime::new(to_unix(t), nanos).ok()
}

fn attrs(entry: &NewEntry, default_mode: u32) -> SetAttr {
    let mut a = SetAttr::new().with_permissions(Permissions::new(
        entry.unix_mode.map_or(default_mode, |m| m & 0o7777),
    ));
    if let Some(t) = entry.modified.and_then(date) {
        a = a.with_modified(t);
    }
    a
}

impl ArchiveWriter for IsoWriter {
    fn reads_sources(&self) -> bool {
        true
    }

    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let path = entry.path.trim_end_matches('/');
        match &entry.kind {
            NewKind::Dir => self.insert(path, Node::dir().with_attrs(attrs(entry, 0o755))),
            NewKind::Symlink { target } => self.insert(
                path,
                Node::symlink(target.as_bytes()).with_attrs(attrs(entry, 0o777)),
            ),
            NewKind::File => {
                let host = match &entry.source {
                    Some(p) => p.clone(),
                    None => {
                        // hadris reads files by path when the image is written.
                        let mut tmp = Partial::create(&self.dir, &format!(".{}", self.name))?;
                        copy(data, tmp.file_mut(), cx)?;
                        tmp.close();
                        let p = tmp.path().to_path_buf();
                        self.spools.push(tmp);
                        p
                    }
                };
                let content = hadris_fs::host::file(&host).map_err(|e| path_error(&e, path))?;
                self.files += 1;
                self.insert(path, Node::file(content).with_attrs(attrs(entry, 0o644)))
            }
        }
    }

    fn finish(self: Box<Self>, cx: &mut dyn Ctx) -> Result<()> {
        let this = *self;
        let now = date(this.time.unwrap_or_else(SystemTime::now)).unwrap_or_else(|| {
            DateTime::new(0, 0).unwrap_or_else(|_| unreachable!("the epoch is a date"))
        });
        let opts = IsoOptions::new()
            .with_id(IsoId::Volume, &this.label)
            .with_id(IsoId::Application, "BEEZIP")
            .with_level(IsoLevel::L3)
            .with_joliet()
            .with_rock_ridge()
            .with_time(now);
        let plan =
            hadris_iso::plan(&this.tree, &opts).map_err(|e| path_error(&e, &plan_path(&e)))?;
        for w in warnings(plan.warnings()) {
            cx.warn(w);
        }
        let total = plan.size();
        let out = Progressed {
            out: BufWriter::with_capacity(BUF_SIZE, this.out),
            cx: &mut *cx,
            done: 0,
            total,
            last: 0,
            files: this.files,
        };
        let dev = StreamDevice::new_growable(StdIo::new(out), BLOCK)
            .map_err(|e| Error::new(ErrorKind::Io, format!("writing the image: {e}")))?;
        let written = hadris_iso::sync::write(dev, &this.tree, &opts);
        if cx.is_cancelled() {
            return Err(Error::cancelled());
        }
        let report = written.map_err(|e| path_error(&e, &plan_path(&e)))?;
        cx.progress(&Progress {
            bytes_done: report.size(),
            bytes_total: Some(total),
            entries_done: this.files,
            entries_total: Some(this.files),
            current: None,
        });
        drop(this.spools);
        Ok(())
    }
}

fn plan_path(e: &hadris_fs::PathError) -> String {
    e.path()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default()
}

/// hadris's warnings, grouped: one line per kind of change, with a few of the paths. Renamed
/// primary (ISO 9660) names aren't reported: Joliet and Rock Ridge keep the real ones.
fn warnings(all: &[hadris_fs::Warning]) -> Vec<String> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for w in all {
        // hadris says what it did in its message: "the Joliet name is cut to 64 characters",
        // "characters outside the Basic Multilingual Plane become _ in the Joliet name".
        let msg = w.message().to_ascii_lowercase();
        let joliet = msg.contains("joliet");
        let what = match w.kind() {
            WarningKind::Renamed | WarningKind::Truncated if joliet && msg.contains("cut") => {
                "names were cut to 64 characters in the Joliet tree, which Windows reads; \
                 Rock Ridge keeps them whole"
            }
            WarningKind::Renamed if joliet => {
                "names have characters Joliet can't hold (shown as `_` on Windows); Rock Ridge \
                 keeps them"
            }
            WarningKind::Relocated => {
                "folders more than 8 deep were relocated, as Rock Ridge does; readers that know \
                 Rock Ridge put them back"
            }
            WarningKind::Dropped(_) | WarningKind::Skipped => w.message(),
            // The primary tree's names: Joliet and Rock Ridge keep the real ones.
            _ => continue,
        };
        let path = w
            .path()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .unwrap_or_default();
        groups.entry(what.to_owned()).or_default().push(path);
    }
    groups
        .into_iter()
        .map(|(what, paths)| {
            let shown: Vec<&str> = paths
                .iter()
                .filter(|p| !p.is_empty())
                .take(3)
                .map(String::as_str)
                .collect();
            let more = paths.len().saturating_sub(shown.len());
            let mut line = format!("{} {what}", paths.len());
            if !shown.is_empty() {
                line.push_str(&format!(": `{}`", shown.join("`, `")));
                if more > 0 {
                    line.push_str(&format!(" and {more} more"));
                }
            }
            line
        })
        .collect()
}

/// The output, reporting progress and checking for cancellation as hadris writes.
struct Progressed<'a> {
    out: BufWriter<Box<dyn WriteSeek>>,
    cx: &'a mut dyn Ctx,
    done: u64,
    total: u64,
    last: u64,
    files: u64,
}

impl Write for Progressed<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.done - self.last >= 1 << 20 || self.last == 0 {
            if self.cx.is_cancelled() {
                return Err(Error::cancelled().into_io());
            }
            self.last = self.done.max(1);
            self.cx.progress(&Progress {
                bytes_done: self.done,
                bytes_total: Some(self.total),
                entries_done: 0,
                entries_total: Some(self.files),
                current: None,
            });
        }
        let n = self.out.write(buf)?;
        self.done += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

impl Seek for Progressed<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.out.seek(pos)
    }
}

impl Read for Progressed<'_> {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("the ISO writer doesn't read its output"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_d_characters() {
        assert_eq!(volume_label(Path::new("C:/x/my disc.iso")), "MY_DISC");
        assert_eq!(volume_label(Path::new("ünï.iso")), "_N_");
        assert_eq!(volume_label(Path::new("....iso")), "CDROM");
        assert_eq!(
            volume_label(Path::new(&format!("{}.iso", "a".repeat(40)))).len(),
            32
        );
    }

    /// The vendored hadris-iso's fix: 20 000 names sharing a long prefix collide in the primary
    /// tree, and published rc.3 took 80 s (release) to give them suffixes.
    #[test]
    fn colliding_names_plan_quickly() {
        use hadris_fs::Content;
        let mut tree = Tree::new();
        for i in 0..20_000 {
            let name = format!("d/file-with-a-longer-name-{i:07}.txt");
            tree.insert(&name, Node::file(Content::bytes(b"x".to_vec())))
                .unwrap();
        }
        let opts = IsoOptions::new()
            .with_level(IsoLevel::L3)
            .with_joliet()
            .with_rock_ridge();
        let t = std::time::Instant::now();
        hadris_iso::plan(&tree, &opts).unwrap();
        let took = t.elapsed();
        eprintln!("planned 20 000 colliding names in {took:?}");
        assert!(took.as_secs() < 10, "{took:?}");
    }

    #[test]
    fn zf_entries_are_found() {
        // One record: 33 bytes of header, a 1-byte name (so a padding byte isn't needed), then
        // a ZF entry of 16 bytes.
        let mut rec = vec![0u8; 34];
        rec[32] = 1;
        rec[33] = b'A';
        rec.extend_from_slice(b"ZF");
        rec.push(16);
        rec.push(1);
        rec.extend_from_slice(b"pz");
        rec.push(4);
        rec.push(15);
        rec.extend_from_slice(&123_456u32.to_le_bytes());
        rec.extend_from_slice(&123_456u32.to_be_bytes());
        rec[0] = rec.len() as u8;
        let mut sector = rec.clone();
        sector.resize(SECTOR, 0);
        sector.extend_from_slice(&rec);
        let found = zf_records(&sector);
        assert_eq!(found, vec![(0, 123_456), (SECTOR, 123_456)]);
        assert!(zf_records(&[200, 1, 2]).is_empty());
    }
}
