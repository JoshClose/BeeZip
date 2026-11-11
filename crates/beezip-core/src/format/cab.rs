//! CAB (Microsoft Cabinet), BeeZip's own reader and writer (docs/M5.md §5.5).
//!
//! - **The layout:** a header (`CFHEADER`), the folders (`CFFOLDER`), the files (`CFFILE`), then
//!   each folder's data blocks (`CFDATA`). A folder is one compressed stream of its files laid
//!   end to end, cut into blocks of at most 32 KiB uncompressed.
//! - **Reading:** none, MSZIP (flate2, each block a raw deflate stream whose dictionary is the
//!   folder's last 32 KiB) and LZX (BeeZip's own, [`lzx`], one frame per block). Quantum is listed, and
//!   refused when an entry of its folder is extracted. Blocks' checksums are checked when set.
//!   Every count and size is checked against the file before anything is allocated for it, and a
//!   folder whose files claim more than its blocks can hold is `Corrupt` when it opens.
//! - **Cabinet sets:** the previous and next cabinets are found by name in the opened one's folder
//!   (ignoring case if the exact name isn't there), the set is read from its first cabinet, and a
//!   folder that continues into the next cabinet reads on there, a block split between the two
//!   joined. A file listed in both cabinets is listed once.
//! - **A cabinet inside another file** (an MSI's embedded one, docs/M7.md §8.3) is read through a
//!   [`CabStream`], which opens its bytes afresh for each pass. No set is followed from one.
//! - **Names** are UTF-8 when `_A_NAME_IS_UTF` is set, otherwise bytes in the ANSI code page
//!   (docs/M5.md §6); `\` becomes `/`. Times are DOS local times. Entries are files only.
//! - **Extracting** decodes each folder once, handing its files to the sink in the order of their
//!   offsets. The last 32 decoded blocks are kept, so a file that repeats or overlaps the one
//!   before it is read from them; one further back decodes its folder again from the start.
//! - **Writing:** none and MSZIP, every block compressed on its own. The writer hears of every file
//!   first ([`ArchiveWriter::expect`]), so it reserves the header and the folder and file tables
//!   up front, writes the data, and fills the tables in at the end, in the order the files came.

mod lzx;

use std::{
    borrow::BorrowMut,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs::File,
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind,
    EntrySink, FormatCaps, FormatId, NewEntry, NewKind, Selection,
};
use crate::{
    Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::{BUF_SIZE, ExactReader, WriteSeek, copy, read_error, write_error},
    limits::Limits,
    names::{NameDecoding, SystemPage},
    safefs::Partial,
    source::Source,
    time::{DosClock, DosTime, to_dos},
};

const SIGNATURE: &[u8; 4] = b"MSCF";
const HEADER_LEN: usize = 36;

/// `CFHEADER.flags`: the cabinet has a previous one, a next one, reserved areas.
const FLAG_PREV: u16 = 0x0001;
const FLAG_NEXT: u16 = 0x0002;
const FLAG_RESERVE: u16 = 0x0004;

/// `CFFILE.iFolder` for files split between cabinets: continued from the previous one (in this
/// cabinet's first folder), continued in the next one (in its last), or both.
const FROM_PREV: u16 = 0xFFFD;
const TO_NEXT: u16 = 0xFFFE;
const PREV_AND_NEXT: u16 = 0xFFFF;

const ATTR_RDONLY: u16 = 0x01;
const ATTR_HIDDEN: u16 = 0x02;
const ATTR_SYSTEM: u16 = 0x04;
const ATTR_ARCH: u16 = 0x20;
/// `_A_NAME_IS_UTF`: the name is UTF-8.
const ATTR_NAME_IS_UTF: u16 = 0x80;
/// The attributes entries carry.
const ATTR_KEPT: u16 = ATTR_RDONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_ARCH;

/// The most a data block holds uncompressed, and compressed (MS-CAB's limit, as libmspack's).
const BLOCK: usize = 32 * 1024;
const MAX_PACKED: usize = BLOCK + 6144;
/// Names, without their NUL.
const MAX_NAME: usize = 255;

const METHOD_NONE: u16 = 0;
const METHOD_MSZIP: u16 = 1;
const METHOD_QUANTUM: u16 = 2;
const METHOD_LZX: u16 = 3;

/// Decoded blocks a folder reader keeps, for files that repeat or overlap.
const RING_BLOCKS: usize = 32;
/// A folder never reaches 65 535 blocks: the writer starts another before.
const MAX_FOLDER_BLOCKS: u32 = 65_534;
/// The largest cabinet BeeZip writes, measured by its files before compression.
const MAX_CABINET: u64 = 2 << 30;
/// 1980-01-01 00:00, for files without a time DOS can hold.
const DOS_EPOCH: u16 = (1 << 5) | 1;

pub struct Cab;

impl ArchiveFormat for Cab {
    fn id(&self) -> FormatId {
        FormatId::Cab
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".cab"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        header_at(probe.head, probe.len)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            create: true,
            ..FormatCaps::default()
        }
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("cab: {message}"))
}

/// A cabinet's first bytes, `MSCF` with a plausible header: the reserved fields zero, version
/// 1.3, a folder, and the file list after the folder table and inside the cabinet. `Certain`
/// when the cabinet also fits in `len`; `Likely` when it's cut short, so that it opens as a
/// damaged cabinet rather than as nothing.
pub fn header_at(head: &[u8], len: Option<u64>) -> Option<Confidence> {
    let h = head.get(..HEADER_LEN)?;
    if !h.starts_with(SIGNATURE) || le32(h, 4) != 0 || le32(h, 12) != 0 || le32(h, 20) != 0 {
        return None;
    }
    if (le16(h, 24) != 0x0103) || le16(h, 26) == 0 {
        return None;
    }
    let cabinet = u64::from(le32(h, 8));
    let files = u64::from(le32(h, 16));
    let reserve = if le16(h, 30) & FLAG_RESERVE != 0 {
        4
    } else {
        0
    };
    let first = HEADER_LEN as u64 + reserve + 8 * u64::from(le16(h, 26));
    if files < first || files > cabinet {
        return None;
    }
    match len {
        Some(len) if cabinet > len => Some(Confidence::Likely),
        _ => Some(Confidence::Certain),
    }
}

/// The checksum MS-CAB gives data blocks: the XOR of the bytes as little-endian words, with the
/// last one to three bytes taken most significant first, as Microsoft's code does.
fn checksum(data: &[u8], seed: u32) -> u32 {
    let (words, tail) = data.as_chunks::<4>();
    let sum = words.iter().fold(seed, |s, w| s ^ u32::from_le_bytes(*w));
    let last = match *tail {
        [a, b, c] => (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c),
        [a, b] => (u32::from(a) << 8) | u32::from(b),
        [a] => u32::from(a),
        _ => 0,
    };
    sum ^ last
}

/// A block's checksum: its data, then its header from `cbData` on.
fn block_checksum(header: &[u8], data: &[u8]) -> u32 {
    checksum(header, checksum(data, 0))
}

/// Whether `sum` is the block's. `header` runs from `cbData` to the end of the block's reserved
/// area: Microsoft's code sums the reserved bytes, libmspack's doesn't, so either is accepted.
fn checksum_ok(sum: u32, header: &[u8], data: &[u8]) -> bool {
    sum == block_checksum(header, data)
        || sum == block_checksum(header.get(..4).unwrap_or(header), data)
}

/// What a cabinet's bytes are read from.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// Opens a cabinet's bytes, and gives their length, each time they're read.
type OpenCab = dyn Fn() -> Result<(Box<dyn ReadSeek>, u64)> + Send + Sync;

/// A cabinet held inside another file, such as an MSI's embedded one (docs/M7.md §8.3): it's
/// opened again from its start for each pass, as a cabinet file is.
#[derive(Clone)]
pub struct CabStream {
    /// What messages call it: `cab1.cab in setup.msi`.
    pub name: String,
    open: std::sync::Arc<OpenCab>,
}

impl CabStream {
    /// `open` gives the cabinet's bytes from their start, and their length.
    pub fn new(
        name: impl Into<String>,
        open: impl Fn() -> Result<(Box<dyn ReadSeek>, u64)> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            open: std::sync::Arc::new(open),
        }
    }
}

impl std::fmt::Debug for CabStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CabStream")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

fn read_exact_or<R: Read + ?Sized>(r: &mut R, buf: &mut [u8], what: &str) -> Result<()> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            bad(format!("the cabinet ends inside {what}"))
        } else {
            read_error(&e)
        }
    })
}

fn skip<R: Read + ?Sized>(r: &mut R, n: u64, what: &str) -> Result<()> {
    let got = io::copy(&mut r.take(n), &mut io::sink()).map_err(|e| read_error(&e))?;
    if got == n {
        Ok(())
    } else {
        Err(bad(format!("the cabinet ends inside {what}")))
    }
}

/// A NUL-terminated name of at most 255 bytes.
fn read_name<R: Read + ?Sized>(r: &mut R, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        read_exact_or(r, &mut b, what)?;
        match b {
            [0] => return Ok(out),
            [c] if out.len() < MAX_NAME => out.push(c),
            _ => return Err(bad(format!("{what} is longer than 255 bytes"))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RawFolder {
    /// Where its first data block is.
    coff: u32,
    blocks: u16,
    /// `typeCompress`: the method in the low nibble, LZX's window bits in the high byte.
    kind: u16,
}

#[derive(Debug, Clone)]
struct RawFile {
    size: u32,
    /// Where it starts in its folder's uncompressed stream.
    offset: u32,
    folder: u16,
    date: u16,
    time: u16,
    attrs: u16,
    name: Vec<u8>,
}

/// One cabinet's header and tables.
#[derive(Debug)]
struct Cabinet {
    flags: u16,
    set_id: u16,
    index: u16,
    /// Reserved bytes in each data block's header.
    data_reserve: u8,
    folders: Vec<RawFolder>,
    files: Vec<RawFile>,
    prev: Option<Vec<u8>>,
    next: Option<Vec<u8>>,
}

impl Cabinet {
    fn continues_from_prev(&self) -> bool {
        self.files
            .iter()
            .any(|f| matches!(f.folder, FROM_PREV | PREV_AND_NEXT))
    }

    fn continues_to_next(&self) -> bool {
        self.files
            .iter()
            .any(|f| matches!(f.folder, TO_NEXT | PREV_AND_NEXT))
    }
}

/// Reads a cabinet's header, folders and files from `r`, `len` bytes long.
fn read_cabinet(r: &mut dyn ReadSeek, len: u64) -> Result<Cabinet> {
    r.seek(SeekFrom::Start(0))
        .map_err(|e| Error::io("seeking in the cabinet", &e))?;
    let mut r = BufReader::with_capacity(64 * 1024, r);
    let mut h = [0u8; HEADER_LEN];
    read_exact_or(&mut r, &mut h, "its header")?;
    if !h.starts_with(SIGNATURE) {
        return Err(bad("not a cabinet (no MSCF signature)"));
    }
    if le32(&h, 4) != 0 || le32(&h, 12) != 0 || le32(&h, 20) != 0 {
        return Err(bad("the header is damaged"));
    }
    let (minor, major) = (h[24], h[25]);
    if major != 1 {
        return Err(Error::unsupported_format(format!(
            "cabinet version {major}.{minor} isn't supported"
        )));
    }
    let cabinet = u64::from(le32(&h, 8));
    let coff_files = u64::from(le32(&h, 16));
    let n_folders = le16(&h, 26);
    let n_files = le16(&h, 28);
    let flags = le16(&h, 30);
    if cabinet > len {
        return Err(bad(format!(
            "the cabinet is cut short: it should be {cabinet} bytes, and is {len}"
        )));
    }
    if n_folders == 0 {
        return Err(bad("the cabinet has no folders"));
    }
    let (mut folder_reserve, mut data_reserve) = (0u8, 0u8);
    if flags & FLAG_RESERVE != 0 {
        let mut b = [0u8; 4];
        read_exact_or(&mut r, &mut b, "its header")?;
        let [_, _, f, d] = b;
        (folder_reserve, data_reserve) = (f, d);
        skip(&mut r, u64::from(le16(&b, 0)), "its reserved area")?;
    }
    let mut names = |present: bool, what: &str| -> Result<Option<Vec<u8>>> {
        if !present {
            return Ok(None);
        }
        let cabinet = read_name(&mut r, what)?;
        read_name(&mut r, "a disk name")?;
        Ok(Some(cabinet))
    };
    let prev = names(flags & FLAG_PREV != 0, "the previous cabinet's name")?;
    let next = names(flags & FLAG_NEXT != 0, "the next cabinet's name")?;

    let block_header = 8 + u64::from(data_reserve);
    let mut folders = Vec::with_capacity(usize::from(n_folders));
    for _ in 0..n_folders {
        let mut b = [0u8; 8];
        read_exact_or(&mut r, &mut b, "its folder list")?;
        skip(&mut r, u64::from(folder_reserve), "its folder list")?;
        let f = RawFolder {
            coff: le32(&b, 0),
            blocks: le16(&b, 4),
            kind: le16(&b, 6),
        };
        let end = u64::from(f.coff) + u64::from(f.blocks) * block_header;
        if f.blocks > 0 && (u64::from(f.coff) < HEADER_LEN as u64 || end > len) {
            return Err(bad(format!(
                "a folder's {} data blocks can't fit between offset {} and the end at {len}",
                f.blocks, f.coff
            )));
        }
        folders.push(f);
    }

    if coff_files > len {
        return Err(bad(format!(
            "the file list is at {coff_files}, past the end at {len}"
        )));
    }
    r.seek(SeekFrom::Start(coff_files))
        .map_err(|e| Error::io("seeking in the cabinet", &e))?;
    // Each file takes at least 17 bytes, which bounds what a crafted count can reserve.
    let room = usize::try_from((len - coff_files) / 17).unwrap_or(usize::MAX);
    let mut files = Vec::with_capacity(usize::from(n_files).min(room));
    for _ in 0..n_files {
        let mut b = [0u8; 16];
        read_exact_or(&mut r, &mut b, "its file list")?;
        let name = read_name(&mut r, "a file name")?;
        let folder = le16(&b, 8);
        if folder >= n_folders && !matches!(folder, FROM_PREV | TO_NEXT | PREV_AND_NEXT) {
            return Err(bad(format!(
                "a file is in folder {folder}, and the cabinet has {n_folders}"
            )));
        }
        files.push(RawFile {
            size: le32(&b, 0),
            offset: le32(&b, 4),
            folder,
            date: le16(&b, 10),
            time: le16(&b, 12),
            attrs: le16(&b, 14),
            name,
        });
    }
    Ok(Cabinet {
        flags,
        set_id: le16(&h, 32),
        index: le16(&h, 34),
        data_reserve,
        folders,
        files,
        prev,
        next,
    })
}

/// Where a cabinet of the set is read from.
#[derive(Debug, Clone)]
enum Loc {
    /// The source's own input: the file, or the cabinet inside an SFX.
    Input,
    /// Another file: a cabinet beside it in the set, or the cabinet spooled out of a codec.
    Path(PathBuf),
    /// A cabinet inside another file.
    Stream(CabStream),
}

fn open_loc(source: &Source, loc: &Loc) -> Result<(Box<dyn ReadSeek>, u64)> {
    match loc {
        Loc::Stream(s) => (s.open)(),
        Loc::Input => {
            let input = source.input()?;
            let len = input.len();
            Ok((Box::new(input), len))
        }
        Loc::Path(p) => {
            let file =
                File::open(p).map_err(|e| Error::io(format!("opening {}", p.display()), &e))?;
            let len = file
                .metadata()
                .map_err(|e| Error::io(format!("reading {}", p.display()), &e))?
                .len();
            Ok((Box::new(file), len))
        }
    }
}

#[derive(Debug)]
struct CabMeta {
    loc: Loc,
    data_reserve: u8,
}

/// A run of a folder's blocks in one cabinet.
#[derive(Debug, Clone, Copy)]
struct Segment {
    cab: usize,
    coff: u32,
    blocks: u16,
}

/// A folder of the set: its blocks in each cabinet it spans.
#[derive(Debug)]
struct Folder {
    kind: u16,
    segments: Vec<Segment>,
    /// All its blocks: a bound on what it holds.
    blocks: u64,
    /// It starts in a cabinet that isn't there, named.
    missing_prev: Option<String>,
    /// It continues in a cabinet that isn't there, named.
    missing_next: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct FileAt {
    folder: usize,
    offset: u32,
    size: u32,
}

/// The cabinets of a set and their folders, and where each entry is.
#[derive(Debug)]
struct CabSet {
    cabs: Vec<CabMeta>,
    folders: Vec<Folder>,
    /// By entry id.
    files: Vec<FileAt>,
}

fn method_name(kind: u16) -> &'static str {
    match kind & 0x000F {
        METHOD_NONE => "Store",
        METHOD_MSZIP => "MSZIP",
        METHOD_QUANTUM => "Quantum",
        METHOD_LZX => "LZX",
        _ => "Unknown",
    }
}

/// Builds the set's folders and entries from its cabinets, in order. The first folder of a
/// cabinet that continues the one before (it has files continued from there, or the one before
/// has files continued in it) is the last folder of that one. A file listed in both is kept once.
fn build(
    cabs: Vec<(Loc, u64, Cabinet)>,
    missing_prev: Option<String>,
    missing_next: Option<String>,
    names: &NameDecoding,
    limits: &Limits,
) -> Result<(CabSet, Vec<Entry>)> {
    let mut folders: Vec<Folder> = Vec::new();
    let mut files = Vec::new();
    let mut entries = Vec::new();
    let mut clock = DosClock::default();
    // The previous cabinet's files that continue into this one.
    let mut carried: HashSet<(usize, u32, u32, Vec<u8>)> = HashSet::new();
    let mut before_continues = false;
    let mut metas = Vec::with_capacity(cabs.len());
    for (k, (loc, _, cab)) in cabs.into_iter().enumerate() {
        let continues = k > 0 && (before_continues || cab.continues_from_prev());
        before_continues = cab.continues_to_next();
        let base = if continues {
            folders.len().saturating_sub(1)
        } else {
            folders.len()
        };
        for (j, f) in cab.folders.iter().enumerate() {
            let seg = Segment {
                cab: k,
                coff: f.coff,
                blocks: f.blocks,
            };
            match folders.last_mut() {
                Some(last) if j == 0 && continues => {
                    if last.kind != f.kind {
                        return Err(bad(
                            "a folder continues in the next cabinet with another compression",
                        ));
                    }
                    last.segments.push(seg);
                    last.blocks += u64::from(f.blocks);
                }
                _ => folders.push(Folder {
                    kind: f.kind,
                    segments: vec![seg],
                    blocks: u64::from(f.blocks),
                    missing_prev: None,
                    missing_next: None,
                }),
            }
        }
        if k == 0
            && cab.continues_from_prev()
            && let Some(first) = folders.first_mut()
        {
            first.missing_prev = Some(
                missing_prev
                    .clone()
                    .unwrap_or_else(|| "the cabinet before it".to_owned()),
            );
        }
        let mut next_carried = HashSet::new();
        for f in &cab.files {
            let local = match f.folder {
                FROM_PREV | PREV_AND_NEXT => 0,
                TO_NEXT => cab.folders.len().saturating_sub(1),
                n => usize::from(n),
            };
            let folder = base + local;
            let key = (folder, f.offset, f.size, f.name.clone());
            let from_prev = matches!(f.folder, FROM_PREV | PREV_AND_NEXT);
            if matches!(f.folder, TO_NEXT | PREV_AND_NEXT) {
                next_carried.insert(key.clone());
            }
            if continues && from_prev && carried.contains(&key) {
                continue;
            }
            let id = entries.len();
            limits.check_entries(id as u64 + 1)?;
            let kind = folders.get(folder).map_or(0, |f| f.kind);
            let utf8 = f.attrs & ATTR_NAME_IS_UTF != 0;
            let path = names
                .decode(&f.name, utf8, SystemPage::Ansi)
                .replace('\\', "/");
            let mut e = Entry::new(id, path, EntryKind::File);
            e.raw_path.clone_from(&f.name);
            e.size = Some(u64::from(f.size));
            e.modified = clock.read(DosTime {
                date: f.date,
                time: f.time,
            });
            e.method = Some(method_name(kind).into());
            e.dos_attrs = Some(u32::from(f.attrs & ATTR_KEPT));
            entries.push(e);
            files.push(FileAt {
                folder,
                offset: f.offset,
                size: f.size,
            });
        }
        carried = next_carried;
        metas.push(CabMeta {
            loc,
            data_reserve: cab.data_reserve,
        });
    }
    if missing_next.is_some()
        && let Some(last) = folders.last_mut()
    {
        last.missing_next = missing_next;
    }
    // A folder holds at most 32 KiB a block: files claiming more are refused now, before
    // anything decodes for them.
    for (id, f) in files.iter().enumerate() {
        let Some(folder) = folders.get(f.folder) else {
            return Err(bad("a file is in a folder that isn't there"));
        };
        let end = u64::from(f.offset) + u64::from(f.size);
        let room = folder.blocks * BLOCK as u64;
        if folder.missing_prev.is_none() && folder.missing_next.is_none() && end > room {
            let path = entries.get(id).map_or("", |e: &Entry| e.path.as_str());
            return Err(bad(format!(
                "`{path}` ends at byte {end} of its folder, whose {} blocks hold at most {room}",
                folder.blocks
            )));
        }
    }
    Ok((
        CabSet {
            cabs: metas,
            folders,
            files,
        },
        entries,
    ))
}

/// The cabinet called `name` in `dir`: the exact name, else one that differs only in case.
/// `name` is a file name alone ([`sibling_name`]), so a set can't reach outside the folder.
pub(crate) fn find_sibling(dir: &Path, name: &str) -> Option<PathBuf> {
    let exact = dir.join(name);
    if exact.is_file() {
        return Some(exact);
    }
    let lower = name.to_lowercase();
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .find(|e| e.file_name().to_string_lossy().to_lowercase() == lower)
        .map(|e| e.path())
        .filter(|p| p.is_file())
}

/// A set member's name as stored, reduced to a file name.
fn sibling_name(raw: Option<&[u8]>, names: &NameDecoding) -> String {
    let name = names.decode(raw.unwrap_or_default(), false, SystemPage::Ansi);
    name.rsplit(['\\', '/', ':'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn lower_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// A set's cabinet held in the same file, by the name a cabinet gives it.
pub type StreamFinder = std::sync::Arc<dyn Fn(&str) -> Option<CabStream> + Send + Sync>;

/// Where a set's other cabinets are found, by the names a cabinet gives them.
#[derive(Clone)]
pub enum Siblings {
    /// Nowhere: an SFX's or a spooled cabinet's set isn't known.
    None,
    /// Files in this folder.
    Dir(PathBuf),
    /// Cabinets held in the same file as this one: a name to its stream (an MSI's embedded
    /// cabinets), or `None`.
    Streams(StreamFinder),
}

/// Opens the set member `name`, or says why it can't be; with the name it's known by in `seen`.
fn load_sibling(
    siblings: &Siblings,
    name: &str,
    seen: &[String],
) -> std::result::Result<(Loc, String, u64, Cabinet), String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err("its name is empty".to_owned());
    }
    match siblings {
        Siblings::None => Err("a set is only followed from a cabinet file".to_owned()),
        Siblings::Dir(dir) => {
            let path =
                find_sibling(dir, name).ok_or_else(|| "it isn't in the same folder".to_owned())?;
            if seen.contains(&lower_name(&path)) {
                return Err("the set names it twice".to_owned());
            }
            let mut file = File::open(&path).map_err(|e| e.to_string())?;
            let len = file.metadata().map_err(|e| e.to_string())?.len();
            let cab = read_cabinet(&mut file, len).map_err(|e| e.message)?;
            Ok((Loc::Path(path.clone()), lower_name(&path), len, cab))
        }
        Siblings::Streams(find) => {
            let stream = find(name).ok_or_else(|| "the package doesn't hold it".to_owned())?;
            let key = name.to_lowercase();
            if seen.contains(&key) {
                return Err("the set names it twice".to_owned());
            }
            let (mut r, len) = (stream.open)().map_err(|e| e.message)?;
            let cab = read_cabinet(&mut *r, len).map_err(|e| e.message)?;
            Ok((Loc::Stream(stream), key, len, cab))
        }
    }
}

pub struct CabReader {
    source: Source,
    /// The set's cabinets, by the names they're known by (lower case).
    members: Vec<String>,
    set: CabSet,
    entries: Vec<Entry>,
    /// The size of every cabinet of the set.
    total: u64,
    /// Keeps a cabinet spooled out of a codec alive.
    _spool: Option<Partial>,
}

impl CabReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let (loc, spool) = if source.codecs.is_empty() {
            (Loc::Input, None)
        } else {
            // Blocks are read by offset: spool the decoded stream, under the usual limits.
            let mut tmp = Partial::create_temp("beezip-spool.cab")?;
            let mut stream = source.guard(source.open_stream()?);
            copy(&mut stream, tmp.file_mut(), cx)?;
            tmp.close();
            (Loc::Path(tmp.path().to_path_buf()), Some(tmp))
        };
        // A set is followed only from a plain file: siblings of an SFX or a spool aren't known.
        let siblings = if source.codecs.is_empty() && !source.joined && source.offset == 0 {
            Siblings::Dir(source.path.parent().unwrap_or(Path::new("")).to_path_buf())
        } else {
            Siblings::None
        };
        let this = source.file_name();
        let key = lower_name(&source.path);
        Self::open_at(source, loc, spool, siblings, this, key, cx)
    }

    /// Opens `stream`, a cabinet held inside another file (an MSI's embedded cabinet,
    /// docs/M7.md §8.3). `source` is that file: it gives the limits, the name decoding, the byte
    /// counter and the budget, and isn't read itself. No set is followed from the cabinet.
    /// `name` is what the set's other cabinets call it, and `siblings` finds them.
    pub fn open_stream(
        source: Source,
        stream: CabStream,
        name: &str,
        siblings: Siblings,
        cx: &mut dyn Ctx,
    ) -> Result<Self> {
        let this = stream.name.clone();
        let key = name.to_lowercase();
        Self::open_at(source, Loc::Stream(stream), None, siblings, this, key, cx)
    }

    /// Opens the cabinet at `loc`, called `this` in messages, and, when `follow`, the rest of
    /// its set beside `source`.
    fn open_at(
        source: Source,
        loc: Loc,
        spool: Option<Partial>,
        siblings: Siblings,
        this: String,
        key: String,
        cx: &mut dyn Ctx,
    ) -> Result<Self> {
        let (mut input, len) = open_loc(&source, &loc)?;
        let opened = read_cabinet(&mut *input, len)?;
        drop(input);

        let names = source.names;
        let mut seen = vec![key];
        let mut chain: VecDeque<(Loc, u64, Cabinet)> = VecDeque::from([(loc, len, opened)]);
        let mut missing_prev = None;
        let mut missing_next = None;

        // Back to the first cabinet of the set.
        while let Some((_, _, head)) = chain.front()
            && head.flags & FLAG_PREV != 0
        {
            let name = sibling_name(head.prev.as_deref(), &names);
            let why = match load_sibling(&siblings, &name, &seen) {
                Ok((loc, key, len, cab))
                    if cab.set_id == head.set_id
                        && u32::from(cab.index) + 1 == u32::from(head.index) =>
                {
                    seen.push(key);
                    chain.push_front((loc, len, cab));
                    continue;
                }
                Ok(_) => "it isn't the cabinet before in this set".to_owned(),
                Err(why) => why,
            };
            if head.continues_from_prev() {
                cx.warn(format!(
                    "{this}: the set's previous cabinet, {name}, can't be read ({why}); the \
                     files that start there can't be extracted"
                ));
            }
            missing_prev = Some(name);
            break;
        }
        // On to its last.
        while let Some((_, _, tail)) = chain.back()
            && tail.flags & FLAG_NEXT != 0
        {
            let name = sibling_name(tail.next.as_deref(), &names);
            let why = match load_sibling(&siblings, &name, &seen) {
                Ok((loc, key, len, cab))
                    if cab.set_id == tail.set_id
                        && u32::from(tail.index) + 1 == u32::from(cab.index) =>
                {
                    seen.push(key);
                    chain.push_back((loc, len, cab));
                    continue;
                }
                Ok(_) => "it isn't the next cabinet in this set".to_owned(),
                Err(why) => why,
            };
            cx.warn(format!(
                "{this}: the set's next cabinet, {name}, can't be read ({why}); the files in it \
                 aren't listed"
            ));
            missing_next = Some(name);
            break;
        }

        let total = chain.iter().map(|(_, len, _)| *len).sum();
        let (set, entries) = build(
            chain.into(),
            missing_prev,
            missing_next,
            &names,
            &source.limits,
        )?;
        Ok(Self {
            source,
            members: seen,
            set,
            entries,
            total,
            _spool: spool,
        })
    }

    fn pass_meter(&self) -> Meter {
        self.source.counter.set(0);
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.total));
        meter.entries_total = Some(self.entries.len() as u64);
        meter
    }

    /// The entries' ids in the order [`ArchiveReader::extract`] hands them to the sink: by
    /// folder, then by where each starts in it.
    pub fn data_order(&self) -> Vec<usize> {
        let mut order: Vec<(usize, u32, usize)> = self
            .set
            .files
            .iter()
            .enumerate()
            .map(|(id, f)| (f.folder, f.offset, id))
            .collect();
        order.sort_unstable();
        order.into_iter().map(|(_, _, id)| id).collect()
    }

    /// The set's cabinets, by the names they're known by (lower case): what else this reader
    /// reads, so a package naming them too opens them once.
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// The size of every cabinet read: the progress a full pass makes.
    pub fn total_size(&self) -> u64 {
        self.total
    }
}

impl ArchiveReader for CabReader {
    fn format(&self) -> FormatId {
        FormatId::Cab
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods = Vec::new();
        for f in &self.set.folders {
            let m = method_name(f.kind);
            if !methods.contains(&m) {
                methods.push(m);
            }
        }
        let methods = methods.into_iter().map(Into::into).collect();
        // A compressed folder of several files is solid: one stream for all of them.
        let mut per_folder = vec![0u64; self.set.folders.len()];
        for f in self.set.files.iter().filter(|f| f.size > 0) {
            if let Some(n) = per_folder.get_mut(f.folder) {
                *n += 1;
            }
        }
        let solid_blocks = per_folder
            .iter()
            .zip(&self.set.folders)
            .filter(|(n, f)| **n > 1 && f.kind & 0x000F != METHOD_NONE)
            .count() as u64;
        Ok(ArchiveInfo {
            format: FormatId::Cab,
            codecs: self.source.codecs.clone(),
            methods,
            comment: None,
            encryption: Encryption::None,
            solid: solid_blocks > 0,
            sfx: self.source.offset > 0,
            volumes: self.set.cabs.len(),
            solid_blocks: Some(solid_blocks),
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
        if let Some(fs) = sink.as_fs_sink() {
            fs.write_behind(self.source.threads);
        }
        let mut meter = self.pass_meter();
        let mut by_folder: BTreeMap<usize, Vec<(u32, usize)>> = BTreeMap::new();
        for (e, at) in self.entries.iter().zip(&self.set.files) {
            if sel.matches(e) {
                by_folder
                    .entry(at.folder)
                    .or_default()
                    .push((at.offset, e.id));
            }
        }
        let mut done = 0u64;
        // Files handed over in full, by where their data is: a later one with the same data is
        // offered to the sink as a copy first, instead of decoding its folder again.
        let mut served: HashMap<(u32, u32), usize> = HashMap::new();
        for (folder, mut ids) in by_folder {
            served.clear();
            ids.sort_unstable();
            let mut reader: Option<FolderReader<'_>> = None;
            for (_, id) in ids {
                cx.check()?;
                let (Some(entry), Some(at)) = (self.entries.get(id), self.set.files.get(id)) else {
                    continue;
                };
                meter.entries_done = done;
                meter.current = Some(entry.path.clone());
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.report();
                if at.size == 0 {
                    sink.entry(entry, &mut io::empty(), &mut mcx)?;
                } else if let Some(earlier) = served
                    .get(&(at.offset, at.size))
                    .and_then(|&e| self.entries.get(e))
                    && sink.same_as(
                        entry,
                        earlier,
                        reader
                            .as_ref()
                            .is_some_and(|r| r.holds(u64::from(at.offset), u64::from(at.size))),
                        &mut mcx,
                    )?
                {
                } else {
                    if reader.is_none() {
                        reader = Some(FolderReader::new(&self.source, &self.set, folder)?);
                    }
                    let Some(fr) = reader.as_mut() else {
                        continue;
                    };
                    fr.seek(u64::from(at.offset), &mut mcx)?;
                    let mut data = self.source.guard(EntryData {
                        fr,
                        left: u64::from(at.size),
                    });
                    sink.entry(entry, &mut data, &mut mcx)?;
                    served.entry((at.offset, at.size)).or_insert(id);
                }
                done += 1;
            }
        }
        meter.entries_done = done;
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let at = *self
            .set
            .files
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        if at.size == 0 {
            return Ok(Box::new(io::empty()));
        }
        self.source.counter.set(0);
        let mut fr = FolderReader::new(&self.source, &self.set, at.folder)?;
        fr.seek(u64::from(at.offset), cx)?;
        Ok(Box::new(self.source.guard(EntryData {
            fr,
            left: u64::from(at.size),
        })))
    }
}

/// Decodes one folder's blocks.
enum Decoder {
    Store,
    Mszip {
        inflate: Box<Decompress>,
        /// The folder's last 32 KiB: the next block's dictionary.
        history: Vec<u8>,
    },
    Lzx(Box<lzx::Lzx>),
}

impl Decoder {
    fn new(folder: &Folder) -> Result<Self> {
        if let Some(name) = &folder.missing_prev {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("cab: the file's folder starts in {name}, which is missing"),
            ));
        }
        Ok(match folder.kind & 0x000F {
            METHOD_NONE => Self::Store,
            METHOD_MSZIP => Self::Mszip {
                inflate: Box::new(Decompress::new(false)),
                history: Vec::with_capacity(BLOCK),
            },
            METHOD_QUANTUM => {
                return Err(Error::unsupported_format(
                    "Quantum compression isn't supported",
                ));
            }
            METHOD_LZX => {
                let bits = (folder.kind >> 8) & 0x1F;
                Self::Lzx(Box::new(lzx::Lzx::new(u32::from(bits)).map_err(|_| {
                    bad(format!("an LZX window of {bits} bits (15–21 are valid)"))
                })?))
            }
            n => {
                return Err(Error::unsupported_format(format!(
                    "cab: compression type {n} isn't supported"
                )));
            }
        })
    }

    /// Decodes one block of `packed` bytes into `out`, which must come to `unpacked` bytes.
    fn decode(&mut self, packed: &[u8], unpacked: usize, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        match self {
            Self::Store => {
                if packed.len() != unpacked {
                    return Err(bad(format!(
                        "a stored block has {} bytes and says {unpacked}",
                        packed.len()
                    )));
                }
                out.extend_from_slice(packed);
            }
            Self::Mszip { inflate, history } => {
                mszip_block(inflate, history, packed, unpacked, out)?;
                if out.len() >= BLOCK {
                    history.clear();
                    history.extend_from_slice(out.get(out.len() - BLOCK..).unwrap_or_default());
                } else {
                    history.extend_from_slice(out);
                    let over = history.len().saturating_sub(BLOCK);
                    history.drain(..over);
                }
            }
            Self::Lzx(lzx) => {
                lzx.decode_frame(packed, unpacked, out)
                    .map_err(|e| bad(format!("an LZX block is damaged: {e}")))?;
            }
        }
        Ok(())
    }
}

/// One MSZIP block: `CK`, then raw deflate whose dictionary is `history`.
fn mszip_block(
    inflate: &mut Decompress,
    history: &[u8],
    packed: &[u8],
    unpacked: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    let body = packed
        .strip_prefix(b"CK")
        .ok_or_else(|| bad("an MSZIP block doesn't start with CK"))?;
    inflate.reset(false);
    if !history.is_empty() {
        inflate
            .set_dictionary(history)
            .map_err(|e| bad(format!("an MSZIP block's dictionary: {e}")))?;
    }
    // One byte more than the block should make, to see one that makes more.
    out.resize(unpacked + 1, 0);
    let (mut read, mut made) = (0usize, 0usize);
    loop {
        let (in0, out0) = (inflate.total_in(), inflate.total_out());
        let status = inflate
            .decompress(
                body.get(read..).unwrap_or_default(),
                out.get_mut(made..).unwrap_or_default(),
                FlushDecompress::Finish,
            )
            .map_err(|e| bad(format!("an MSZIP block is damaged: {e}")))?;
        let used = usize::try_from(inflate.total_in() - in0).unwrap_or(usize::MAX);
        let produced = usize::try_from(inflate.total_out() - out0).unwrap_or(usize::MAX);
        read = read.saturating_add(used);
        made = made.saturating_add(produced);
        if status == Status::StreamEnd || (used == 0 && produced == 0) || made > unpacked {
            break;
        }
    }
    if made != unpacked {
        return Err(bad(format!(
            "an MSZIP block decodes to {}{made} bytes, not {unpacked}",
            if made > unpacked { "more than " } else { "" }
        )));
    }
    out.truncate(unpacked);
    Ok(())
}

/// A folder's uncompressed stream, read from its blocks in each cabinet in turn. The last
/// [`RING_BLOCKS`] decoded blocks are kept, so it can go back within them; further back, it
/// starts over.
struct FolderReader<'a> {
    source: &'a Source,
    set: &'a CabSet,
    folder: &'a Folder,
    decoder: Decoder,
    /// The next segment to open, the blocks left in the open one, and that one's file.
    seg: usize,
    left: u16,
    reserve: u8,
    file: Option<BufReader<Box<dyn ReadSeek>>>,
    /// The block being decoded, joined if it was split between cabinets.
    packed: Vec<u8>,
    /// Recent blocks with where they start in the folder.
    ring: VecDeque<(u64, Vec<u8>)>,
    spare: Vec<Vec<u8>>,
    /// Where the newest block ends, and where reading is.
    end: u64,
    pos: u64,
    /// The first error, given back from then on: the decoder can't go on after one.
    failed: Option<Error>,
}

impl<'a> FolderReader<'a> {
    fn new(source: &'a Source, set: &'a CabSet, index: usize) -> Result<Self> {
        let folder = set
            .folders
            .get(index)
            .ok_or_else(|| bad("a file is in a folder that isn't there"))?;
        Ok(Self {
            source,
            set,
            folder,
            decoder: Decoder::new(folder)?,
            seg: 0,
            left: 0,
            reserve: 0,
            file: None,
            packed: Vec::with_capacity(MAX_PACKED),
            ring: VecDeque::with_capacity(RING_BLOCKS + 1),
            spare: Vec::new(),
            end: 0,
            pos: 0,
            failed: None,
        })
    }

    /// Why the folder's data ended before a file did.
    fn short(&self) -> Error {
        match &self.folder.missing_next {
            Some(name) => Error::new(
                ErrorKind::NotFound,
                format!("cab: the file continues in {name}, which is missing"),
            ),
            None => bad("a folder's data ends before its files do"),
        }
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e.clone());
        e
    }

    fn restart(&mut self) -> Result<()> {
        self.decoder = Decoder::new(self.folder)?;
        self.seg = 0;
        self.left = 0;
        self.file = None;
        while let Some((_, b)) = self.ring.pop_front() {
            self.spare.push(b);
        }
        self.end = 0;
        self.pos = 0;
        Ok(())
    }

    /// The next block's packed bytes into `self.packed`, joining a block split between cabinets,
    /// and how many bytes it decodes to; `None` at the folder's end.
    fn next_block(&mut self) -> Result<Option<usize>> {
        self.packed.clear();
        let mut split = false;
        loop {
            while self.left == 0 {
                let Some(seg) = self.folder.segments.get(self.seg).copied() else {
                    return if split { Err(self.short()) } else { Ok(None) };
                };
                self.seg += 1;
                self.file = None;
                self.left = seg.blocks;
                if seg.blocks == 0 {
                    continue;
                }
                let meta = self
                    .set
                    .cabs
                    .get(seg.cab)
                    .ok_or_else(|| bad("a folder is in a cabinet that isn't there"))?;
                let (mut f, _) = open_loc(self.source, &meta.loc)?;
                f.seek(SeekFrom::Start(u64::from(seg.coff)))
                    .map_err(|e| Error::io("seeking in the cabinet", &e))?;
                self.reserve = meta.data_reserve;
                self.file = Some(BufReader::with_capacity(64 * 1024, f));
            }
            self.left -= 1;
            let Some(file) = self.file.as_mut() else {
                return Err(bad("a folder's blocks can't be read"));
            };
            let mut header = [0u8; 8 + 255];
            let hlen = 8 + usize::from(self.reserve);
            let header = header.get_mut(..hlen).unwrap_or_default();
            read_exact_or(file, header, "a data block")?;
            let sum = le32(header, 0);
            let packed = usize::from(le16(header, 4));
            let unpacked = usize::from(le16(header, 6));
            if packed > MAX_PACKED || unpacked > BLOCK {
                return Err(bad(format!(
                    "a data block of {packed} bytes says it holds {unpacked}; blocks hold at \
                     most {MAX_PACKED} and {BLOCK}"
                )));
            }
            let start = self.packed.len();
            if start + packed > MAX_PACKED {
                return Err(bad("a data block split between cabinets is too large"));
            }
            self.packed.resize(start + packed, 0);
            let data = self.packed.get_mut(start..).unwrap_or_default();
            read_exact_or(file, data, "a data block")?;
            self.source.counter.add((hlen + packed) as u64);
            if sum != 0 && !checksum_ok(sum, header.get(4..).unwrap_or_default(), data) {
                return Err(bad("a data block's checksum doesn't match"));
            }
            // An uncompressed size of 0: the block goes on in the next cabinet.
            if unpacked != 0 {
                return Ok(Some(unpacked));
            }
            split = true;
        }
    }

    /// Decodes one more block onto the ring; `false` at the folder's end.
    fn fill(&mut self) -> Result<bool> {
        let Some(unpacked) = self.next_block()? else {
            return Ok(false);
        };
        let mut out = self.spare.pop().unwrap_or_default();
        self.decoder.decode(&self.packed, unpacked, &mut out)?;
        let start = self.end;
        self.end += out.len() as u64;
        self.ring.push_back((start, out));
        while self.ring.len() > RING_BLOCKS {
            if let Some((_, b)) = self.ring.pop_front() {
                self.spare.push(b);
            }
        }
        Ok(true)
    }

    /// Whether `len` bytes at `from` are in the blocks kept, decoded.
    fn holds(&self, from: u64, len: u64) -> bool {
        let oldest = self.ring.front().map_or(self.end, |(s, _)| *s);
        from >= oldest && from.saturating_add(len) <= self.end
    }

    /// Moves to `to` in the folder, decoding up to it, from the start again if it's behind the
    /// blocks kept.
    fn seek(&mut self, to: u64, cx: &mut dyn Ctx) -> Result<()> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let oldest = self.ring.front().map_or(self.end, |(s, _)| *s);
        if to < oldest {
            self.restart().map_err(|e| self.fail(e))?;
        }
        while self.end < to {
            cx.check()?;
            match self.fill() {
                Ok(true) => {}
                Ok(false) => return Err(self.fail(self.short())),
                Err(e) => return Err(self.fail(e)),
            }
        }
        self.pos = to;
        Ok(())
    }
}

impl Read for FolderReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.failed {
            return Err(e.clone().into_io());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.end {
            match self.fill() {
                Ok(true) => {}
                Ok(false) => return Ok(0),
                Err(e) => return Err(self.fail(e).into_io()),
            }
        }
        let pos = self.pos;
        let Some((start, data)) = self.ring.iter().rev().find(|(s, _)| *s <= pos) else {
            return Ok(0);
        };
        let off = usize::try_from(pos - start).unwrap_or(usize::MAX);
        let avail = data.get(off..).unwrap_or_default();
        let n = avail.len().min(buf.len());
        if let (Some(to), Some(from)) = (buf.get_mut(..n), avail.get(..n)) {
            to.copy_from_slice(from);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// One file's bytes from its folder: exactly its size, or an error.
struct EntryData<F> {
    fr: F,
    left: u64,
}

impl<'a, F: BorrowMut<FolderReader<'a>>> Read for EntryData<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let fr = self.fr.borrow_mut();
        let n = fr.read(buf.get_mut(..want).unwrap_or_default())?;
        if n == 0 {
            let e = fr.short();
            return Err(fr.fail(e).into_io());
        }
        self.left -= n as u64;
        Ok(n)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CabMethod {
    Store,
    #[default]
    Mszip,
}

impl CabMethod {
    pub const ALL: [CabMethod; 2] = [Self::Store, Self::Mszip];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Mszip => "mszip",
        }
    }

    const fn kind(self) -> u16 {
        match self {
            Self::Store => METHOD_NONE,
            Self::Mszip => METHOD_MSZIP,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CabWriteOptions {
    pub method: CabMethod,
}

/// A path as a cabinet stores it: `\`-separated, and whether it's beyond ASCII (so UTF-8, flagged).
fn encode_name(path: &str) -> Result<(Vec<u8>, bool)> {
    let name = path.replace('/', "\\").into_bytes();
    if name.is_empty() || name.contains(&0) {
        return Err(Error::invalid_args(format!(
            "`{path}` can't be stored in a cabinet"
        )));
    }
    if name.len() > MAX_NAME {
        return Err(Error::invalid_args(format!(
            "`{path}` is too long for a cabinet, whose names are at most {MAX_NAME} bytes"
        )));
    }
    let utf8 = !name.is_ascii();
    Ok((name, utf8))
}

/// What [`CabWriter::expect`] reserved.
#[derive(Debug)]
struct Plan {
    /// The files still to come, by path.
    names: HashMap<String, usize>,
    /// Bytes of the file list, and the folder slots before it.
    table_len: u64,
    slots: usize,
    coff_files: u32,
}

/// A file written, for the file list.
#[derive(Debug)]
struct Written {
    name: Vec<u8>,
    size: u32,
    offset: u32,
    folder: u16,
    date: u16,
    time: u16,
    attrs: u16,
}

#[derive(Debug, Clone, Copy)]
struct FolderOut {
    coff: u32,
    blocks: u16,
}

/// Writes a cabinet: the header and tables are reserved when [`ArchiveWriter::expect`] hears of
/// every file, and filled in by `finish`.
pub struct CabWriter {
    out: BufWriter<Box<dyn WriteSeek>>,
    method: CabMethod,
    /// The most blocks a folder gets before another starts.
    folder_blocks: u32,
    plan: Option<Plan>,
    /// Bytes written so far.
    pos: u64,
    files: Vec<Written>,
    folders: Vec<FolderOut>,
    /// The open folder's bytes, before compression, and every folder's.
    folder_bytes: u64,
    total: u64,
    /// The block being filled: its first `filled` bytes.
    block: Vec<u8>,
    filled: usize,
    deflate: Option<Compress>,
    packed: Vec<u8>,
    /// An add failed: the cabinet can't be finished.
    broken: bool,
}

/// How many folders files of `sizes` take, in that order, a new one starting when a file
/// doesn't fit in what's left of the one before.
fn folders_for(sizes: impl Iterator<Item = u64>, room: u64) -> usize {
    let (mut n, mut used) = (1usize, 0u64);
    for s in sizes {
        if used > 0 && used.saturating_add(s) > room {
            n += 1;
            used = 0;
        }
        used = used.saturating_add(s);
    }
    n
}

fn too_big(total: u64) -> Error {
    Error::invalid_args(format!(
        "a cabinet can't be over 2 GiB, and these files come to {total} bytes before compression \
         (BeeZip measures them uncompressed, to refuse before writing)"
    ))
}

impl CabWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: CabWriteOptions) -> Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(BUF_SIZE, out),
            method: opts.method,
            folder_blocks: MAX_FOLDER_BLOCKS,
            plan: None,
            pos: 0,
            files: Vec::new(),
            folders: Vec::new(),
            folder_bytes: 0,
            total: 0,
            block: vec![0; BLOCK],
            filled: 0,
            deflate: None,
            packed: Vec::with_capacity(MAX_PACKED),
            broken: false,
        })
    }

    /// The same, with folders of at most `blocks` blocks, so tests can make several.
    #[cfg(test)]
    fn with_folder_blocks(mut self, blocks: u32) -> Self {
        self.folder_blocks = blocks.clamp(1, MAX_FOLDER_BLOCKS);
        self
    }

    fn folder_room(&self) -> u64 {
        u64::from(self.folder_blocks) * BLOCK as u64
    }

    /// Compresses and writes the block being filled.
    fn emit_block(&mut self) -> Result<()> {
        if self.filled == 0 {
            return Ok(());
        }
        let raw = self.block.get(..self.filled).unwrap_or_default();
        let unpacked = u16::try_from(raw.len()).map_err(|_| bad("a block over 32 KiB"))?;
        self.packed.clear();
        match self.method {
            CabMethod::Store => self.packed.extend_from_slice(raw),
            CabMethod::Mszip => {
                self.packed.extend_from_slice(b"CK");
                let deflate = self
                    .deflate
                    .get_or_insert_with(|| Compress::new(Compression::new(6), false));
                deflate.reset();
                self.packed.reserve(BLOCK + 1024);
                let status = deflate.compress_vec(raw, &mut self.packed, FlushCompress::Finish);
                let whole = deflate.total_in() == raw.len() as u64;
                // Deflate falls back to stored blocks on data it can't compress, a few of them,
                // with their headers. One stored block is the least that can be written.
                if !(matches!(status, Ok(Status::StreamEnd)) && whole)
                    || self.packed.len() > raw.len() + 7
                {
                    self.packed.clear();
                    self.packed.extend_from_slice(b"CK");
                    // A final stored block: BFINAL set, type 00, then LEN and its complement.
                    self.packed.push(0x01);
                    self.packed.extend_from_slice(&unpacked.to_le_bytes());
                    self.packed.extend_from_slice(&(!unpacked).to_le_bytes());
                    self.packed.extend_from_slice(raw);
                }
            }
        }
        let packed = u16::try_from(self.packed.len())
            .ok()
            .filter(|&n| usize::from(n) <= MAX_PACKED)
            .ok_or_else(|| bad("a compressed block over its limit"))?;
        let mut header = [0u8; 8];
        header[4..6].copy_from_slice(&packed.to_le_bytes());
        header[6..8].copy_from_slice(&unpacked.to_le_bytes());
        let sum = block_checksum(&header[4..], &self.packed);
        header[..4].copy_from_slice(&sum.to_le_bytes());
        self.out.write_all(&header).map_err(|e| write_error(&e))?;
        self.out
            .write_all(&self.packed)
            .map_err(|e| write_error(&e))?;
        self.pos += 8 + self.packed.len() as u64;
        if self.pos > u64::from(u32::MAX) {
            return Err(too_big(self.total));
        }
        let folder = self
            .folders
            .last_mut()
            .ok_or_else(|| bad("a block outside a folder"))?;
        folder.blocks = folder
            .blocks
            .checked_add(1)
            .ok_or_else(|| bad("a folder of 65 536 blocks"))?;
        self.filled = 0;
        Ok(())
    }

    fn add_file(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        let room = self.folder_room();
        let plan = self.plan.as_mut().ok_or_else(|| {
            Error::invalid_args("a cabinet needs to hear of every file before the first is added")
        })?;
        let left = plan
            .names
            .get_mut(&entry.path)
            .filter(|n| **n > 0)
            .ok_or_else(|| {
                Error::invalid_args(format!(
                    "`{}` wasn't among the files announced for the cabinet",
                    entry.path
                ))
            })?;
        *left -= 1;
        let slots = plan.slots;
        let (name, utf8) = encode_name(&entry.path)?;
        if entry.size > room {
            return Err(Error::invalid_args(format!(
                "`{}` is {} bytes, more than a cabinet's folder holds ({room})",
                entry.path, entry.size
            )));
        }
        let total = self.total.saturating_add(entry.size);
        if total > MAX_CABINET {
            return Err(too_big(total));
        }
        let size = u32::try_from(entry.size).map_err(|_| too_big(total))?;
        if self.folders.is_empty()
            || (self.folder_bytes > 0 && self.folder_bytes + entry.size > room)
        {
            self.emit_block()?;
            if self.folders.len() >= slots {
                return Err(Error::invalid_args(
                    "the files came in another order than announced, and no longer fit the \
                     cabinet's folders",
                ));
            }
            let coff = u32::try_from(self.pos).map_err(|_| too_big(total))?;
            self.folders.push(FolderOut { coff, blocks: 0 });
            self.folder_bytes = 0;
        }
        let offset = u32::try_from(self.folder_bytes).map_err(|_| too_big(total))?;
        let folder = u16::try_from(self.folders.len() - 1).map_err(|_| too_big(total))?;

        let mut src = ExactReader::new(data, entry.size);
        loop {
            cx.check()?;
            // The block is never left full, so there's always room to read into.
            let room = self.block.get_mut(self.filled..).unwrap_or_default();
            let n = match src.read(room) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(read_error(&e)),
            };
            self.filled += n;
            if self.filled >= BLOCK {
                self.emit_block()?;
            }
        }
        self.folder_bytes += entry.size;
        self.total = total;
        let (date, time) = entry
            .modified
            .and_then(to_dos)
            .map_or((DOS_EPOCH, 0), |d| (d.date, d.time));
        let attrs = entry.dos_attrs.map_or(ATTR_ARCH, |a| {
            u16::try_from(a & u32::from(ATTR_KEPT)).unwrap_or(0)
        });
        self.files.push(Written {
            name,
            size,
            offset,
            folder,
            date,
            time,
            attrs: attrs | if utf8 { ATTR_NAME_IS_UTF } else { 0 },
        });
        Ok(())
    }

    fn finish_tables(&mut self) -> Result<()> {
        if self.plan.is_none() {
            ArchiveWriter::expect(self, &[])?;
        }
        self.emit_block()?;
        if self.folders.is_empty() {
            let coff = u32::try_from(self.pos).map_err(|_| too_big(self.total))?;
            self.folders.push(FolderOut { coff, blocks: 0 });
        }
        let Some(plan) = &self.plan else {
            return Err(bad("the writer lost its plan"));
        };
        let mut table = Vec::with_capacity(usize::try_from(plan.table_len).unwrap_or(0));
        for f in &self.files {
            table.extend_from_slice(&f.size.to_le_bytes());
            table.extend_from_slice(&f.offset.to_le_bytes());
            table.extend_from_slice(&f.folder.to_le_bytes());
            table.extend_from_slice(&f.date.to_le_bytes());
            table.extend_from_slice(&f.time.to_le_bytes());
            table.extend_from_slice(&f.attrs.to_le_bytes());
            table.extend_from_slice(&f.name);
            table.push(0);
        }
        if table.len() as u64 > plan.table_len {
            return Err(bad("the file list outgrew its room"));
        }
        // Announced files that never came leave their room empty.
        table.resize(usize::try_from(plan.table_len).unwrap_or(table.len()), 0);
        let cabinet = u32::try_from(self.pos).map_err(|_| too_big(self.total))?;
        let n_folders = u16::try_from(self.folders.len()).map_err(|_| too_big(self.total))?;
        let n_files = u16::try_from(self.files.len())
            .map_err(|_| Error::invalid_args("a cabinet holds at most 65 535 files"))?;

        let mut head = Vec::with_capacity(HEADER_LEN + 8 * self.folders.len());
        head.extend_from_slice(SIGNATURE);
        head.extend_from_slice(&0u32.to_le_bytes());
        head.extend_from_slice(&cabinet.to_le_bytes());
        head.extend_from_slice(&0u32.to_le_bytes());
        head.extend_from_slice(&plan.coff_files.to_le_bytes());
        head.extend_from_slice(&0u32.to_le_bytes());
        head.extend_from_slice(&[3, 1]);
        head.extend_from_slice(&n_folders.to_le_bytes());
        head.extend_from_slice(&n_files.to_le_bytes());
        head.extend_from_slice(&0u16.to_le_bytes()); // flags
        head.extend_from_slice(&0u16.to_le_bytes()); // setID
        head.extend_from_slice(&0u16.to_le_bytes()); // iCabinet
        let kind = self.method.kind();
        for f in &self.folders {
            head.extend_from_slice(&f.coff.to_le_bytes());
            head.extend_from_slice(&f.blocks.to_le_bytes());
            head.extend_from_slice(&kind.to_le_bytes());
        }
        let coff_files = u64::from(plan.coff_files);
        let seek = |out: &mut BufWriter<Box<dyn WriteSeek>>, to: u64| {
            out.seek(SeekFrom::Start(to))
                .map(|_| ())
                .map_err(|e| write_error(&e))
        };
        seek(&mut self.out, 0)?;
        self.out.write_all(&head).map_err(|e| write_error(&e))?;
        seek(&mut self.out, coff_files)?;
        self.out.write_all(&table).map_err(|e| write_error(&e))?;
        seek(&mut self.out, self.pos)?;
        self.out.flush().map_err(|e| write_error(&e))
    }
}

impl ArchiveWriter for CabWriter {
    /// Reserves the header and the folder and file tables, after refusing what a cabinet can't
    /// hold: names over 255 bytes, more than 65 535 files, more than 2 GiB of them.
    fn expect(&mut self, entries: &[NewEntry]) -> Result<()> {
        if self.plan.is_some() || self.pos > 0 {
            return Err(Error::invalid_args(
                "a cabinet's files can only be announced once",
            ));
        }
        let room = self.folder_room();
        let files: Vec<&NewEntry> = entries.iter().filter(|e| e.kind == NewKind::File).collect();
        if files.len() > usize::from(u16::MAX) {
            return Err(Error::invalid_args(format!(
                "a cabinet holds at most 65 535 files, and there are {}",
                files.len()
            )));
        }
        let mut names: HashMap<String, usize> = HashMap::new();
        let (mut table_len, mut total) = (0u64, 0u64);
        for e in &files {
            let (name, _) = encode_name(&e.path)?;
            if e.size > room {
                return Err(Error::invalid_args(format!(
                    "`{}` is {} bytes, more than a cabinet's folder holds ({room})",
                    e.path, e.size
                )));
            }
            total = total.saturating_add(e.size);
            table_len += 16 + name.len() as u64 + 1;
            *names.entry(e.path.clone()).or_default() += 1;
        }
        if total > MAX_CABINET {
            return Err(too_big(total));
        }
        let slots = folders_for(files.iter().map(|e| e.size), room);
        let coff_files = HEADER_LEN as u64 + 8 * slots as u64;
        let start = coff_files + table_len;
        let coff_files = u32::try_from(coff_files).map_err(|_| too_big(total))?;
        let mut zeros = io::repeat(0).take(start);
        io::copy(&mut zeros, &mut self.out).map_err(|e| write_error(&e))?;
        self.pos = start;
        self.plan = Some(Plan {
            names,
            table_len,
            slots,
            coff_files,
        });
        Ok(())
    }

    /// Files only: folders come from the files' paths, and links can't be stored.
    fn holds(&self, kind: &NewKind) -> bool {
        *kind == NewKind::File
    }

    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        match entry.kind {
            NewKind::Dir => return Ok(()),
            NewKind::Symlink { .. } => {
                return Err(Error::unsupported(format!(
                    "`{}` is a symbolic link, which a cabinet can't hold",
                    entry.path
                )));
            }
            NewKind::File => {}
        }
        if self.broken {
            return Err(Error::invalid_args(
                "the cabinet can't take more files after one failed",
            ));
        }
        let added = self.add_file(entry, data, cx);
        if added.is_err() {
            self.broken = true;
        }
        added
    }

    fn finish(mut self: Box<Self>, _: &mut dyn Ctx) -> Result<()> {
        if self.broken {
            return Err(Error::invalid_args(
                "the cabinet can't be finished after a file failed",
            ));
        }
        self.finish_tables()
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::{SimpleCtx, source::OpenOptions, time::from_unix};

    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i % 251) as u8 ^ (i / 1000) as u8)
            .collect()
    }

    fn when() -> SystemTime {
        from_unix(1_700_000_001, 0).unwrap()
    }

    fn new_entry(path: &str, size: usize) -> NewEntry {
        NewEntry {
            path: path.to_owned(),
            kind: NewKind::File,
            size: size as u64,
            modified: Some(when()),
            unix_mode: None,
            dos_attrs: None,
            source: None,
        }
    }

    fn writer(path: &Path, method: CabMethod, blocks: Option<u32>) -> CabWriter {
        let out = File::create(path).unwrap();
        let w = CabWriter::new(Box::new(out), CabWriteOptions { method }).unwrap();
        match blocks {
            Some(b) => w.with_folder_blocks(b),
            None => w,
        }
    }

    fn write_cab(path: &Path, method: CabMethod, files: &[(&str, Vec<u8>)], blocks: Option<u32>) {
        let mut w = writer(path, method, blocks);
        let entries: Vec<NewEntry> = files.iter().map(|(p, d)| new_entry(p, d.len())).collect();
        w.expect(&entries).unwrap();
        let mut cx = SimpleCtx::new();
        for (e, (_, d)) in entries.iter().zip(files) {
            w.add(e, &mut &d[..], &mut cx).unwrap();
        }
        Box::new(w).finish(&mut SimpleCtx::new()).unwrap();
    }

    fn open(path: &Path) -> Result<CabReader> {
        let source = Source::new(path, Vec::new(), &OpenOptions::default())?;
        CabReader::open(source, &mut SimpleCtx::new())
    }

    struct Collect(Vec<(Entry, Vec<u8>)>);

    impl EntrySink for Collect {
        fn entry(&mut self, e: &Entry, data: &mut dyn Read, _: &mut dyn Ctx) -> Result<()> {
            let mut v = Vec::new();
            data.read_to_end(&mut v).map_err(|e| read_error(&e))?;
            self.0.push((e.clone(), v));
            Ok(())
        }
    }

    fn extract_all(r: &mut CabReader) -> Result<Vec<(Entry, Vec<u8>)>> {
        let mut sink = Collect(Vec::new());
        r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())?;
        Ok(sink.0)
    }

    fn read_entry(r: &mut CabReader, id: usize) -> Result<Vec<u8>> {
        let mut data = r.open_entry(id, &mut SimpleCtx::new())?;
        let mut v = Vec::new();
        data.read_to_end(&mut v).map_err(|e| read_error(&e))?;
        Ok(v)
    }

    /// Checks a cabinet holds `files`, by listing, extracting and opening each entry.
    fn check(path: &Path, files: &[(&str, Vec<u8>)]) {
        let mut r = open(path).unwrap();
        let listed: Vec<(String, u64)> = r
            .entries(&mut SimpleCtx::new())
            .unwrap()
            .iter()
            .map(|e| (e.path.clone(), e.size.unwrap()))
            .collect();
        let want: Vec<(String, u64)> = files
            .iter()
            .map(|(p, d)| ((*p).to_owned(), d.len() as u64))
            .collect();
        assert_eq!(listed, want);
        let mut got = extract_all(&mut r).unwrap();
        got.sort_by_key(|(e, _)| e.id);
        assert_eq!(got.len(), files.len());
        for ((e, data), (p, d)) in got.iter().zip(files) {
            assert_eq!(e.path, *p);
            assert!(data == d, "{p} differs");
            assert_eq!(e.modified.and_then(to_dos), to_dos(when()), "{p}");
            assert_eq!(e.kind, EntryKind::File);
        }
        for (id, (p, d)) in files.iter().enumerate() {
            assert!(read_entry(&mut r, id).unwrap() == *d, "open_entry {p}");
        }
    }

    fn sample() -> Vec<(&'static str, Vec<u8>)> {
        let mut files = vec![
            ("empty.txt", Vec::new()),
            ("hello.txt", b"Hello, cabinet!\n".to_vec()),
            ("dir/sub/pattern.bin", pattern(100_000)),
            ("noise.bin", noise(70_000, 7)),
            ("ünïcödé/名前.txt", "non-ASCII\n".repeat(50).into_bytes()),
            ("exact.bin", pattern(BLOCK)),
            ("empty2.txt", Vec::new()),
        ];
        for i in 0..300 {
            let name: &'static str = Box::leak(format!("many/f{i:03}.txt").into_boxed_str());
            files.push((name, format!("file {i}\n").repeat(i % 7).into_bytes()));
        }
        files
    }

    #[test]
    fn round_trips_with_both_methods() {
        let dir = tempfile::tempdir().unwrap();
        let files = sample();
        for method in CabMethod::ALL {
            let path = dir.path().join(format!("{}.cab", method.name()));
            write_cab(&path, method, &files, None);
            check(&path, &files);
            let mut r = open(&path).unwrap();
            let info = r.info(&mut SimpleCtx::new()).unwrap();
            assert_eq!(info.volumes, 1);
            assert_eq!(
                info.methods,
                [match method {
                    CabMethod::Store => "Store",
                    CabMethod::Mszip => "MSZIP",
                }]
            );
            assert_eq!(info.solid, method == CabMethod::Mszip);
            let head = std::fs::read(&path).unwrap();
            let len = head.len() as u64;
            assert_eq!(header_at(&head, Some(len)), Some(Confidence::Certain));
            // Non-ASCII names are flagged UTF-8; attributes default to the archive bit.
            let e = &r.entries(&mut SimpleCtx::new()).unwrap()[4];
            assert_eq!(e.dos_attrs, Some(u32::from(ATTR_ARCH)));
            assert_eq!(e.raw_path, "ünïcödé\\名前.txt".as_bytes());
        }
        // MSZIP compresses the pattern; noise stays about its size.
        let store = std::fs::metadata(dir.path().join("store.cab"))
            .unwrap()
            .len();
        let mszip = std::fs::metadata(dir.path().join("mszip.cab"))
            .unwrap()
            .len();
        assert!(mszip < store - 100_000, "{mszip} vs {store}");
    }

    #[test]
    fn incompressible_blocks_stay_within_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("n.cab");
        let files = vec![("n.bin", noise(5 * BLOCK + 17, 3))];
        write_cab(&path, CabMethod::Mszip, &files, None);
        check(&path, &files);
        // Each block: 8 header bytes, CK, one stored block's 5 and the data.
        let len = std::fs::metadata(&path).unwrap().len();
        let tables = (HEADER_LEN + 8 + 16 + 6) as u64;
        assert!(
            len <= tables + 6 * (8 + 2 + 5) + files[0].1.len() as u64,
            "{len}"
        );
    }

    #[test]
    fn several_folders() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.cab");
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("a", pattern(40_000)),
            ("b", noise(40_000, 1)),
            ("c", pattern(10_000)),
            ("d", Vec::new()),
            ("e", noise(65_536, 2)),
            ("f", pattern(1)),
        ];
        for method in CabMethod::ALL {
            write_cab(&path, method, &files, Some(2));
            check(&path, &files);
            let r = open(&path).unwrap();
            assert_eq!(r.set.folders.len(), 4, "{method:?}");
            assert!(r.set.folders.iter().all(|f| f.blocks <= 2));
        }
    }

    #[test]
    fn files_may_come_in_another_order_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("o.cab");
        let mut w = writer(&path, CabMethod::Mszip, None);
        let announced = [new_entry("a", 10), new_entry("b", 0), new_entry("c", 5)];
        w.expect(&announced).unwrap();
        let mut cx = SimpleCtx::new();
        // A stream's size isn't known when it's announced.
        let b = new_entry("b", 70_000);
        w.add(&announced[2], &mut &b"ccccc"[..], &mut cx).unwrap();
        w.add(&b, &mut &pattern(70_000)[..], &mut cx).unwrap();
        w.add(&announced[0], &mut &b"aaaaaaaaaa"[..], &mut cx)
            .unwrap();
        // Unannounced, or announced fewer times.
        let err = w
            .add(&new_entry("a", 1), &mut &b"a"[..], &mut cx)
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgs);
        let err = Box::new(w).finish(&mut SimpleCtx::new()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgs);

        let mut w = writer(&path, CabMethod::Mszip, None);
        w.expect(&announced).unwrap();
        w.add(&announced[2], &mut &b"ccccc"[..], &mut cx).unwrap();
        w.add(&b, &mut &pattern(70_000)[..], &mut cx).unwrap();
        Box::new(w).finish(&mut SimpleCtx::new()).unwrap();
        // The list is in the order the data is, and `a` never came.
        check(&path, &[("c", b"ccccc".to_vec()), ("b", pattern(70_000))]);
    }

    #[test]
    fn short_data_fails_the_add() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = writer(&dir.path().join("s.cab"), CabMethod::Store, None);
        let e = new_entry("a", 10);
        w.expect(std::slice::from_ref(&e)).unwrap();
        let err = w
            .add(&e, &mut &b"abc"[..], &mut SimpleCtx::new())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Corrupt);
        assert!(Box::new(w).finish(&mut SimpleCtx::new()).is_err());
    }

    #[test]
    fn the_writer_refuses_what_a_cabinet_cant_hold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.cab");
        let refuse = |entries: &[NewEntry]| {
            let mut w = writer(&path, CabMethod::Mszip, None);
            let err = w.expect(entries).unwrap_err();
            assert_eq!(err.kind, ErrorKind::InvalidArgs, "{err}");
            drop(w);
            // Nothing was written.
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
            err
        };
        refuse(&[new_entry(&"x".repeat(256), 1)]);
        let err = refuse(&[
            new_entry("a", 1 << 30),
            new_entry("b", 1 << 30),
            new_entry("c", 1),
        ]);
        assert!(err.message.contains("2 GiB"), "{err}");
        refuse(&[new_entry("big", 1 << 32)]);
        let many: Vec<NewEntry> = (0..65_536).map(|i| new_entry(&format!("{i}"), 0)).collect();
        refuse(&many);

        let mut w = writer(&path, CabMethod::Mszip, None);
        assert!(w.holds(&NewKind::File));
        assert!(!w.holds(&NewKind::Dir));
        assert!(!w.holds(&NewKind::Symlink { target: "x".into() }));
        let link = NewEntry {
            kind: NewKind::Symlink { target: "x".into() },
            ..new_entry("l", 0)
        };
        w.expect(&[]).unwrap();
        let err = w
            .add(&link, &mut io::empty(), &mut SimpleCtx::new())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
        // Adding before announcing.
        let mut w = writer(&path, CabMethod::Mszip, None);
        let err = w
            .add(&new_entry("a", 0), &mut io::empty(), &mut SimpleCtx::new())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgs);
    }

    #[test]
    fn an_empty_cabinet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.cab");
        let w = writer(&path, CabMethod::Mszip, None);
        Box::new(w).finish(&mut SimpleCtx::new()).unwrap();
        let head = std::fs::read(&path).unwrap();
        assert_eq!(head.len(), HEADER_LEN + 8);
        assert_eq!(
            header_at(&head, Some(head.len() as u64)),
            Some(Confidence::Certain)
        );
        let mut r = open(&path).unwrap();
        assert!(r.entries(&mut SimpleCtx::new()).unwrap().is_empty());
        assert!(extract_all(&mut r).unwrap().is_empty());
    }

    #[test]
    fn checksums_and_tails() {
        assert_eq!(checksum(&[1, 2, 3, 4], 0), 0x0403_0201);
        assert_eq!(
            checksum(&[1, 2, 3, 4, 5, 6, 7], 0),
            0x0403_0201 ^ 0x0005_0607
        );
        assert_eq!(checksum(&[9, 8], 0), 0x0908);
        assert_eq!(checksum(&[9], 0xFF00), 0xFF09);
        assert_eq!(checksum(&[], 5), 5);
    }

    /// A data block by hand: packed bytes, unpacked size, a checksum to write instead of its own.
    type RawBlock = (Vec<u8>, u16, Option<u32>);

    /// A cabinet put together by hand: its folders' blocks and its files (name, folder, offset,
    /// size).
    #[derive(Clone)]
    struct Raw {
        kind: u16,
        folders: Vec<Vec<RawBlock>>,
        files: Vec<(String, u16, u32, u32)>,
        prev: Option<&'static str>,
        next: Option<&'static str>,
        set_id: u16,
        index: u16,
        reserve: Option<(u16, u8, u8)>,
    }

    impl Raw {
        fn stored(data: &[u8], files: &[(&str, u32, u32)]) -> Self {
            let blocks = data
                .chunks(BLOCK)
                .map(|c| (c.to_vec(), c.len() as u16, None))
                .collect();
            Self {
                kind: METHOD_NONE,
                folders: vec![blocks],
                files: files
                    .iter()
                    .map(|(n, o, s)| ((*n).to_owned(), 0, *o, *s))
                    .collect(),
                prev: None,
                next: None,
                set_id: 7,
                index: 0,
                reserve: None,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let (hres, fres, dres) = self.reserve.unwrap_or((0, 0, 0));
            let mut flags = 0;
            let mut names = Vec::new();
            if let Some(p) = self.prev {
                flags |= FLAG_PREV;
                names.extend_from_slice(p.as_bytes());
                names.extend_from_slice(b"\0disk\0");
            }
            if let Some(n) = self.next {
                flags |= FLAG_NEXT;
                names.extend_from_slice(n.as_bytes());
                names.extend_from_slice(b"\0disk\0");
            }
            let mut head_len = HEADER_LEN + names.len();
            if self.reserve.is_some() {
                flags |= FLAG_RESERVE;
                head_len += 4 + usize::from(hres);
            }
            let coff_files = head_len + self.folders.len() * (8 + usize::from(fres));
            let mut table = Vec::new();
            for (name, folder, offset, size) in &self.files {
                table.extend_from_slice(&size.to_le_bytes());
                table.extend_from_slice(&offset.to_le_bytes());
                table.extend_from_slice(&folder.to_le_bytes());
                table.extend_from_slice(&0x5A21u16.to_le_bytes());
                table.extend_from_slice(&0x6000u16.to_le_bytes());
                let utf8 = if name.is_ascii() { 0 } else { ATTR_NAME_IS_UTF };
                table.extend_from_slice(&(ATTR_ARCH | utf8).to_le_bytes());
                table.extend_from_slice(name.as_bytes());
                table.push(0);
            }
            let mut data = Vec::new();
            let mut coffs = Vec::new();
            let start = coff_files + table.len();
            for blocks in &self.folders {
                coffs.push((start + data.len()) as u32);
                for (packed, unpacked, sum) in blocks {
                    let mut h = vec![0u8; 8 + usize::from(dres)];
                    h[4..6].copy_from_slice(&(packed.len() as u16).to_le_bytes());
                    h[6..8].copy_from_slice(&unpacked.to_le_bytes());
                    let s = sum.unwrap_or_else(|| block_checksum(&h[4..], packed));
                    h[..4].copy_from_slice(&s.to_le_bytes());
                    data.extend_from_slice(&h);
                    data.extend_from_slice(packed);
                }
            }
            let total = start + data.len();
            let mut out = Vec::new();
            out.extend_from_slice(SIGNATURE);
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(total as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(coff_files as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&[3, 1]);
            out.extend_from_slice(&(self.folders.len() as u16).to_le_bytes());
            out.extend_from_slice(&(self.files.len() as u16).to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&self.set_id.to_le_bytes());
            out.extend_from_slice(&self.index.to_le_bytes());
            if self.reserve.is_some() {
                out.extend_from_slice(&hres.to_le_bytes());
                out.extend_from_slice(&[fres, dres]);
                out.resize(out.len() + usize::from(hres), 0xAB);
            }
            out.extend_from_slice(&names);
            for (blocks, coff) in self.folders.iter().zip(coffs) {
                out.extend_from_slice(&coff.to_le_bytes());
                out.extend_from_slice(&(blocks.len() as u16).to_le_bytes());
                out.extend_from_slice(&self.kind.to_le_bytes());
                out.resize(out.len() + usize::from(fres), 0xCD);
            }
            assert_eq!(out.len(), coff_files);
            out.extend_from_slice(&table);
            out.extend_from_slice(&data);
            out
        }

        fn write(&self, dir: &Path, name: &str) -> PathBuf {
            let p = dir.join(name);
            std::fs::write(&p, self.bytes()).unwrap();
            p
        }
    }

    fn kind_of<T>(r: Result<T>) -> ErrorKind {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.kind,
        }
    }

    #[test]
    fn overlapping_and_repeated_files_come_out_right() {
        let dir = tempfile::tempdir().unwrap();
        // 40 blocks, more than the 32 kept, so going back to the start decodes again.
        let data = pattern(40 * BLOCK);
        let whole = data.len() as u32;
        let ranges = [
            ("whole", 0, whole),
            ("head", 100, 200),
            ("again", 100, 200),
            ("overlap", 150, 70_000),
            ("tail", whole - 10, 10),
            ("near-tail", whole - 40_000, 30_000),
            ("empty", 5, 0),
        ];
        let p = Raw::stored(&data, &ranges).write(dir.path(), "o.cab");
        let mut r = open(&p).unwrap();
        let got = extract_all(&mut r).unwrap();
        assert_eq!(got.len(), ranges.len());
        for (e, bytes) in &got {
            let (_, o, s) = ranges.iter().find(|(n, _, _)| *n == e.path).unwrap();
            assert!(
                *bytes == data[*o as usize..(*o + *s) as usize],
                "{}",
                e.path
            );
        }
        // Handed over in the order of their offsets.
        let order: Vec<&str> = got.iter().map(|(e, _)| e.path.as_str()).collect();
        assert_eq!(
            order,
            [
                "whole",
                "empty",
                "head",
                "again",
                "overlap",
                "near-tail",
                "tail"
            ]
        );
        for (id, (_, o, s)) in ranges.iter().enumerate() {
            let bytes = read_entry(&mut r, id).unwrap();
            assert!(bytes == data[*o as usize..(*o + *s) as usize]);
        }
    }

    #[test]
    fn checksums_are_checked_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(50_000);
        let mut raw = Raw::stored(&data, &[("a", 0, 50_000)]);
        let p = raw.write(dir.path(), "ok.cab");
        assert!(extract_all(&mut open(&p).unwrap()).unwrap()[0].1 == data);
        raw.folders[0][1].2 = Some(0);
        let p = raw.write(dir.path(), "zero.cab");
        assert!(extract_all(&mut open(&p).unwrap()).unwrap()[0].1 == data);
        raw.folders[0][1].2 = Some(0x1234_5678);
        let p = raw.write(dir.path(), "bad.cab");
        let mut r = open(&p).unwrap();
        assert_eq!(kind_of(extract_all(&mut r)), ErrorKind::Corrupt);
        assert_eq!(kind_of(read_entry(&mut r, 0)), ErrorKind::Corrupt);
    }

    #[test]
    fn reserved_areas_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(70_000);
        let mut raw = Raw::stored(&data, &[("a", 0, 70_000), ("b", 10, 5)]);
        raw.reserve = Some((20, 3, 5));
        let p = raw.write(dir.path(), "r.cab");
        let got = extract_all(&mut open(&p).unwrap()).unwrap();
        assert!(got[0].1 == data);
        assert_eq!(got[1].1, data[10..15]);
        // A checksum over the block's header without its reserved bytes is accepted too.
        let mut bytes = raw.bytes();
        let first = le32(&bytes, HEADER_LEN + 4 + 20) as usize;
        let packed = le16(&bytes, first + 4) as usize;
        let block = bytes[first + 8 + 5..first + 8 + 5 + packed].to_vec();
        let sum = block_checksum(&bytes[first + 4..first + 8], &block);
        bytes[first..first + 4].copy_from_slice(&sum.to_le_bytes());
        std::fs::write(&p, &bytes).unwrap();
        let got = extract_all(&mut open(&p).unwrap()).unwrap();
        assert!(got[0].1 == data);
    }

    #[test]
    fn mszip_blocks_use_the_folder_so_far_as_dictionary() {
        let dir = tempfile::tempdir().unwrap();
        let data = [pattern(BLOCK), pattern(BLOCK), pattern(1000)].concat();
        let mut blocks = Vec::new();
        let mut prev: &[u8] = &[];
        for chunk in data.chunks(BLOCK) {
            let mut c = Compress::new(Compression::new(9), false);
            if !prev.is_empty() {
                c.set_dictionary(prev).unwrap();
            }
            let mut out = b"CK".to_vec();
            out.reserve(2 * BLOCK);
            c.compress_vec(chunk, &mut out, FlushCompress::Finish)
                .unwrap();
            blocks.push((out, chunk.len() as u16, None));
            prev = chunk;
        }
        // The second block refers back into the first, so it's small.
        assert!(blocks[1].0.len() < 1000, "{}", blocks[1].0.len());
        let mut raw = Raw::stored(&[], &[("a", 0, data.len() as u32), ("b", 40_000, 10)]);
        raw.kind = METHOD_MSZIP;
        raw.folders = vec![blocks];
        let p = raw.write(dir.path(), "d.cab");
        let mut r = open(&p).unwrap();
        let got = extract_all(&mut r).unwrap();
        assert!(got[0].1 == data);
        assert_eq!(read_entry(&mut r, 1).unwrap(), data[40_000..40_010]);
        // A block without its CK, or one that decodes to another size.
        let mut bad = raw.clone();
        bad.folders[0][1].0[0] = b'X';
        let mut r = open(&bad.write(dir.path(), "ck.cab")).unwrap();
        assert_eq!(kind_of(extract_all(&mut r)), ErrorKind::Corrupt);
        let mut bad = raw.clone();
        bad.folders[0][2].1 = 999;
        bad.files[0].3 -= 1;
        let mut r = open(&bad.write(dir.path(), "size.cab")).unwrap();
        assert_eq!(kind_of(extract_all(&mut r)), ErrorKind::Corrupt);
    }

    #[test]
    fn quantum_lists_and_refuses_to_extract() {
        let dir = tempfile::tempdir().unwrap();
        let mut raw = Raw::stored(&[1, 2, 3], &[("q", 0, 3), ("e", 0, 0)]);
        raw.kind = METHOD_QUANTUM | (21 << 8);
        let mut r = open(&raw.write(dir.path(), "q.cab")).unwrap();
        let entries = r.entries(&mut SimpleCtx::new()).unwrap();
        assert_eq!(entries[0].method.as_deref(), Some("Quantum"));
        let err = r.open_entry(0, &mut SimpleCtx::new()).err().unwrap();
        assert_eq!(err.kind, ErrorKind::UnsupportedFormat);
        assert_eq!(err.message, "Quantum compression isn't supported");
        assert_eq!(read_entry(&mut r, 1).unwrap(), b"");
        let mut sink = Collect(Vec::new());
        let sel = Selection::ids([1]);
        r.extract(&sel, &mut sink, &mut SimpleCtx::new()).unwrap();
        assert_eq!(kind_of(extract_all(&mut r)), ErrorKind::UnsupportedFormat);
    }

    #[test]
    fn damaged_lzx_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        for (kind, data) in [
            (METHOD_LZX | (21 << 8), noise(3000, 5)),
            (METHOD_LZX | (16 << 8), vec![0xFF; 64]),
            (METHOD_LZX | (16 << 8), vec![0; 64]),
            (METHOD_LZX | (22 << 8), vec![0; 64]),
            (9, vec![0; 64]),
        ] {
            let mut raw = Raw::stored(&[], &[("x", 0, BLOCK as u32)]);
            raw.kind = kind;
            raw.folders = vec![vec![(data, BLOCK as u16, None)]];
            let mut r = open(&raw.write(dir.path(), "x.cab")).unwrap();
            let k = kind_of(extract_all(&mut r));
            assert!(
                matches!(k, ErrorKind::Corrupt | ErrorKind::UnsupportedFormat),
                "{kind:#x}: {k:?}"
            );
        }
    }

    #[test]
    fn crafted_tables_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let good = Raw::stored(&pattern(1000), &[("a", 0, 1000)]);
        let refused = |bytes: Vec<u8>, what: &str| {
            let p = dir.path().join("c.cab");
            std::fs::write(&p, bytes).unwrap();
            let k = open(&p).map(|mut r| extract_all(&mut r).map(|_| ()));
            let k = match k {
                Ok(Ok(())) => panic!("{what}: accepted"),
                Ok(Err(e)) | Err(e) => e.kind,
            };
            assert_eq!(k, ErrorKind::Corrupt, "{what}");
        };
        let set = |mut b: Vec<u8>, at: usize, v: &[u8]| {
            b[at..at + v.len()].copy_from_slice(v);
            b
        };
        let b = good.bytes();
        refused(set(b.clone(), 28, &u16::MAX.to_le_bytes()), "65 535 files");
        refused(
            set(b.clone(), 26, &u16::MAX.to_le_bytes()),
            "65 535 folders",
        );
        refused(set(b.clone(), 26, &0u16.to_le_bytes()), "no folders");
        refused(
            set(b.clone(), 16, &u32::MAX.to_le_bytes()),
            "the file list past the end",
        );
        refused(
            set(b.clone(), 8, &u32::MAX.to_le_bytes()),
            "the cabinet past the end",
        );
        refused(
            set(b.clone(), 36, &u32::MAX.to_le_bytes()),
            "a folder past the end",
        );
        refused(set(b.clone(), 40, &u16::MAX.to_le_bytes()), "65 535 blocks");
        refused(
            set(b.clone(), 44, &5000u32.to_le_bytes()),
            "a file over its folder",
        );
        refused(
            set(b.clone(), 48, &u32::MAX.to_le_bytes()),
            "a file past its folder",
        );
        refused(
            set(b.clone(), 52, &7u16.to_le_bytes()),
            "a folder that isn't there",
        );
        refused(set(b.clone(), 4, &[1]), "a reserved field");

        // Files claiming 4 GiB of a folder of two blocks: refused at once, nothing allocated.
        let started = std::time::Instant::now();
        let mut raw = Raw::stored(&pattern(40_000), &[("a", 0, u32::MAX)]);
        refused(raw.bytes(), "the over-claiming folder");
        raw.files = vec![("a".into(), 0, 0, 40_000), ("b".into(), 0, 65_000, 1000)];
        refused(raw.bytes(), "a file just past what the blocks hold");
        assert!(started.elapsed().as_secs() < 5);

        // A name of 300 bytes.
        let raw = Raw::stored(&pattern(10), &[(&"n".repeat(300), 0, 10)]);
        refused(raw.bytes(), "a long name");
        // Blocks that hold less than the files say.
        let mut raw = Raw::stored(&pattern(40_000), &[("a", 0, 40_000)]);
        raw.folders[0][1].1 = 100;
        refused(raw.bytes(), "a short block");
        // A block bigger than blocks can be, or a split block at the folder's end.
        let mut raw = Raw::stored(&[], &[("a", 0, 30_000)]);
        raw.folders = vec![vec![(vec![0; MAX_PACKED + 1], 30_000, None)]];
        refused(raw.bytes(), "a huge block");
        let mut raw = Raw::stored(&[], &[("a", 0, 100)]);
        raw.folders = vec![vec![(vec![0; 100], 0, None)]];
        refused(raw.bytes(), "a split block at the end");
    }

    #[test]
    fn truncated_cabinets_are_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.cab");
        let files = vec![
            ("a.txt", b"some text\n".repeat(20)),
            ("b.bin", noise(40_000, 9)),
        ];
        write_cab(&path, CabMethod::Mszip, &files, None);
        let bytes = std::fs::read(&path).unwrap();
        let cut = dir.path().join("cut.cab");
        for len in (0..bytes.len()).step_by(97).chain([bytes.len() - 1]) {
            std::fs::write(&cut, &bytes[..len]).unwrap();
            let e = open(&cut).err().unwrap_or_else(|| panic!("{len}: opened"));
            assert_eq!(e.kind, ErrorKind::Corrupt, "{len}: {e}");
            if len >= HEADER_LEN {
                assert_eq!(
                    header_at(&bytes[..len], Some(len as u64)),
                    Some(Confidence::Likely)
                );
            }
        }
    }

    #[test]
    fn mutations_never_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.cab");
        let files = vec![
            ("a.txt", b"Hello\n".repeat(10)),
            ("b.bin", pattern(40_000)),
            ("c", Vec::new()),
        ];
        write_cab(&path, CabMethod::Mszip, &files, None);
        let bytes = std::fs::read(&path).unwrap();
        let m = dir.path().join("mut.cab");
        let mut x = 0x1234_5678u32;
        for i in 0..400 {
            let mut b = bytes.clone();
            for _ in 0..1 + i % 3 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                // Half of them in the tables and the first block's header.
                let at = (x as usize) % if i % 2 == 0 { 200 } else { b.len() };
                b[at] ^= (x >> 8) as u8 | 1;
            }
            std::fs::write(&m, &b).unwrap();
            if let Ok(mut r) = open(&m) {
                let _ = extract_all(&mut r);
                for id in 0..r.entries.len() {
                    let _ = read_entry(&mut r, id);
                }
            }
        }
    }

    #[test]
    fn detection() {
        let good = Raw::stored(&pattern(100), &[("a", 0, 100)]).bytes();
        let len = Some(good.len() as u64);
        assert_eq!(header_at(&good, len), Some(Confidence::Certain));
        assert_eq!(header_at(&good, None), Some(Confidence::Certain));
        assert_eq!(header_at(&good, Some(50)), Some(Confidence::Likely));
        assert_eq!(header_at(&good[..35], len), None);
        let mut b = good.clone();
        b[24] = 2;
        assert_eq!(header_at(&b, len), None);
        let mut b = good.clone();
        b[13] = 1;
        assert_eq!(header_at(&b, len), None);
        let mut b = good.clone();
        b[16..20].copy_from_slice(&20u32.to_le_bytes());
        assert_eq!(header_at(&b, len), None);
        assert_eq!(
            header_at(b"MSCF\0\0\0\0garbage that isn't a cabinet", None),
            None
        );
        let probe = Probe {
            head: &good,
            tail: &[],
            len,
            name: None,
        };
        assert_eq!(Cab.sniff(&probe), Some(Confidence::Certain));
        let caps = Cab.caps();
        assert!(caps.list && caps.extract && caps.create);
        assert!(!caps.append && !caps.delete && !caps.rename && !caps.random_access);
    }

    /// Two cabinets: a folder split between them, a block split with it, and a file in each.
    fn two_cabinets(dir: &Path) -> (Vec<u8>, Vec<u8>) {
        let a = pattern(2 * BLOCK);
        let b = noise(3000, 11);
        let first = a[..BLOCK].to_vec();
        let (part1, part2) = a[BLOCK..].split_at(10_000);
        let one = Raw {
            kind: METHOD_NONE,
            folders: vec![
                vec![(pattern(500), 500, None)],
                vec![(first, BLOCK as u16, None), (part1.to_vec(), 0, None)],
            ],
            files: vec![
                ("own.txt".into(), 0, 0, 500),
                ("split.bin".into(), TO_NEXT, 0, a.len() as u32),
            ],
            prev: None,
            next: Some("SET2.CAB"),
            set_id: 42,
            index: 0,
            reserve: None,
        };
        let two = Raw {
            kind: METHOD_NONE,
            folders: vec![
                vec![(part2.to_vec(), BLOCK as u16, None)],
                vec![(b.clone(), b.len() as u16, None)],
            ],
            files: vec![
                ("split.bin".into(), FROM_PREV, 0, a.len() as u32),
                ("after.bin".into(), 1, 0, b.len() as u32),
            ],
            prev: Some("set1.cab"),
            next: None,
            set_id: 42,
            index: 1,
            reserve: None,
        };
        one.write(dir, "set1.cab");
        two.write(dir, "set2.cab");
        (a, b)
    }

    #[test]
    fn a_set_reads_whole_from_any_cabinet() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = two_cabinets(dir.path());
        for name in ["set1.cab", "set2.cab"] {
            let mut r = open(&dir.path().join(name)).unwrap();
            let got = extract_all(&mut r).unwrap();
            let names: Vec<&str> = got.iter().map(|(e, _)| e.path.as_str()).collect();
            assert_eq!(names, ["own.txt", "split.bin", "after.bin"], "{name}");
            assert!(got[0].1 == pattern(500));
            assert!(got[1].1 == a, "{name}");
            assert!(got[2].1 == b);
            assert_eq!(r.info(&mut SimpleCtx::new()).unwrap().volumes, 2);
            assert!(read_entry(&mut r, 1).unwrap() == a);
        }
    }

    #[test]
    fn a_set_with_a_cabinet_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (_, b) = two_cabinets(dir.path());
        std::fs::rename(dir.path().join("set2.cab"), dir.path().join("x.cab")).unwrap();
        let mut cx = SimpleCtx::new();
        let first = dir.path().join("set1.cab");
        let source = Source::new(&first, Vec::new(), &OpenOptions::default()).unwrap();
        let mut r = CabReader::open(source, &mut cx).unwrap();
        assert!(cx.warnings[0].contains("SET2.CAB"), "{:?}", cx.warnings);
        assert_eq!(r.entries.len(), 2);
        assert!(read_entry(&mut r, 0).unwrap() == pattern(500));
        assert_eq!(kind_of(read_entry(&mut r, 1)), ErrorKind::NotFound);

        std::fs::rename(dir.path().join("x.cab"), dir.path().join("set2.cab")).unwrap();
        std::fs::rename(dir.path().join("set1.cab"), dir.path().join("x.cab")).unwrap();
        let mut r = open(&dir.path().join("set2.cab")).unwrap();
        let names: Vec<&str> = r.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, ["split.bin", "after.bin"]);
        assert_eq!(kind_of(read_entry(&mut r, 0)), ErrorKind::NotFound);
        assert!(read_entry(&mut r, 1).unwrap() == b);
    }

    #[test]
    fn a_set_cant_name_a_file_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        two_cabinets(&sub);
        std::fs::rename(sub.join("set2.cab"), dir.path().join("set2.cab")).unwrap();
        let mut raw = Raw::stored(&pattern(10), &[("a", 0, 10)]);
        raw.next = Some("..\\set2.cab");
        let p = raw.write(&sub, "evil.cab");
        let mut cx = SimpleCtx::new();
        let source = Source::new(&p, Vec::new(), &OpenOptions::default()).unwrap();
        let r = CabReader::open(source, &mut cx).unwrap();
        assert_eq!(r.set.cabs.len(), 1);
        assert_eq!(cx.warnings.len(), 1);
        // A cabinet naming itself as the next.
        let mut raw = Raw::stored(&pattern(10), &[("a", 0, 10)]);
        raw.next = Some("SELF.cab");
        let p = raw.write(&sub, "self.cab");
        assert_eq!(open(&p).unwrap().set.cabs.len(), 1);
    }

    /// A cabinet in memory, read as an MSI's embedded one is: the same entries and bytes as
    /// the file, in the order `data_order` says, and its bytes counted on the source's counter.
    #[test]
    fn a_cabinet_inside_another_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("in.cab");
        let mut files = sample();
        files.truncate(20);
        write_cab(&path, CabMethod::Mszip, &files, Some(4));
        let bytes = std::sync::Arc::new(std::fs::read(&path).unwrap());
        // Any file stands for the outer one: only its limits and counter are used.
        let outer = dir.path().join("outer.bin");
        std::fs::write(&outer, b"not a cabinet").unwrap();
        let source = Source::new(&outer, Vec::new(), &OpenOptions::default()).unwrap();
        let counter = source.counter.clone();
        let opens = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stream = {
            let (bytes, opens) = (bytes.clone(), opens.clone());
            CabStream::new("in.cab in outer.bin", move || {
                opens.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let len = bytes.len() as u64;
                let r: Box<dyn ReadSeek> = Box::new(io::Cursor::new(bytes.to_vec()));
                Ok((r, len))
            })
        };
        let mut cx = SimpleCtx::new();
        let mut r =
            CabReader::open_stream(source, stream, "in.cab", Siblings::None, &mut cx).unwrap();
        assert!(cx.warnings.is_empty(), "{:?}", cx.warnings);
        assert_eq!(r.total_size(), bytes.len() as u64);
        let got = extract_all(&mut r).unwrap();
        let ids: Vec<usize> = got.iter().map(|(e, _)| e.id).collect();
        assert_eq!(ids, r.data_order());
        assert_eq!(got.len(), files.len());
        for (e, data) in &got {
            assert!(*data == files[e.id].1, "{}", e.path);
        }
        assert!(counter.get() > 0, "the packed bytes are counted");
        assert!(opens.load(std::sync::atomic::Ordering::Relaxed) >= 2);
        for id in [3, 0, 19] {
            assert!(read_entry(&mut r, id).unwrap() == files[id].1);
        }

        // A damaged one fails as a damaged file does, naming nothing outside it.
        let cut = std::sync::Arc::new(bytes[..bytes.len() / 2].to_vec());
        let stream = CabStream::new("cut.cab", move || {
            let r: Box<dyn ReadSeek> = Box::new(io::Cursor::new(cut.to_vec()));
            Ok((r, cut.len() as u64))
        });
        let source = Source::new(&outer, Vec::new(), &OpenOptions::default()).unwrap();
        assert_eq!(
            kind_of(CabReader::open_stream(
                source,
                stream,
                "cut.cab",
                Siblings::None,
                &mut SimpleCtx::new()
            )),
            ErrorKind::Corrupt
        );
    }

    #[test]
    fn cancelling_stops_reading_and_writing() {
        use std::sync::{Arc, atomic::AtomicBool};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.cab");
        let files = vec![("a", pattern(10 * BLOCK)), ("b", pattern(100))];
        write_cab(&path, CabMethod::Mszip, &files, None);
        let cancelled = || SimpleCtx::new().with_cancel(Arc::new(AtomicBool::new(true)));
        let mut r = open(&path).unwrap();
        let mut sink = Collect(Vec::new());
        let err = r
            .extract(&Selection::all(), &mut sink, &mut cancelled())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
        // Reaching `b` decodes the blocks before it, checking between them.
        let err = r.open_entry(1, &mut cancelled()).err().unwrap();
        assert_eq!(err.kind, ErrorKind::Cancelled);

        let mut w = writer(&dir.path().join("w.cab"), CabMethod::Mszip, None);
        let e = new_entry("a", 100);
        w.expect(std::slice::from_ref(&e)).unwrap();
        let err = w
            .add(&e, &mut &pattern(100)[..], &mut cancelled())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }

    /// LZX's bits: 16-bit little-endian words, each read from its top bit down.
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        word: u16,
        used: u8,
    }

    impl Bits {
        fn put(&mut self, value: u32, bits: u8) {
            for i in (0..bits).rev() {
                self.word = (self.word << 1) | ((value >> i) & 1) as u16;
                self.used += 1;
                if self.used == 16 {
                    self.out.extend_from_slice(&self.word.to_le_bytes());
                    (self.word, self.used) = (0, 0);
                }
            }
        }

        fn align(&mut self) {
            while self.used != 0 {
                self.put(0, 1);
            }
        }

        fn bytes(&mut self, b: &[u8]) {
            self.align();
            self.out.extend_from_slice(b);
        }
    }

    /// An LZX frame of 32 KiB windows: an uncompressed block of one byte that sets the repeated
    /// offsets to `r0`, then a verbatim block whose only element is a two-byte match at R0.
    fn lzx_repeat(r0: u32) -> Vec<u8> {
        let mut b = Bits::default();
        b.put(0, 1); // no E8 translation
        b.put(3, 3); // an uncompressed block
        b.put(0, 16);
        b.put(1, 8);
        b.align();
        for r in [r0, 1, 1] {
            b.bytes(&r.to_le_bytes());
        }
        b.bytes(b"A\0"); // the byte, and the pad after an odd block
        b.put(1, 3); // a verbatim block
        b.put(0, 16);
        b.put(2, 8);
        // Each tree's pretree: symbols 0, 16, 17 and 18 of 2 bits (codes 00, 01, 10, 11), so
        // 16 sets a length of 1 and 18 is a run of 20 + 5 bits of zeros.
        let pretree = |b: &mut Bits| {
            for sym in 0..20 {
                b.put(
                    if matches!(sym, 0 | 16 | 17 | 18) {
                        2
                    } else {
                        0
                    },
                    4,
                );
            }
        };
        let zeros = |b: &mut Bits, mut n: u32| {
            while n > 0 {
                let run = n.min(51);
                b.put(3, 2);
                b.put(run - 20, 5);
                n -= run;
            }
        };
        // The main tree: the literal 0 and element 256 (a two-byte match at R0), one bit each.
        pretree(&mut b);
        b.put(1, 2);
        zeros(&mut b, 255);
        pretree(&mut b);
        b.put(1, 2);
        zeros(&mut b, 8 * 30 - 1);
        // An empty length tree.
        pretree(&mut b);
        zeros(&mut b, 249);
        b.put(1, 1); // element 256
        b.align();
        b.out
    }

    #[test]
    fn a_repeated_offset_past_the_window_is_caught() {
        // A sane offset decodes: "A", then "A" again from one back... at offset 1, twice.
        let mut lzx = lzx::Lzx::new(15).unwrap();
        let mut out = Vec::new();
        lzx.decode_frame(&lzx_repeat(1), 3, &mut out).unwrap();
        assert_eq!(out, b"AAA");
        // An offset beyond the window: lzxd 0.2.7 subtracted it from the window position, which
        // overflows (a panic with overflow checks, as in debug builds and fuzzing).
        let dir = tempfile::tempdir().unwrap();
        let mut raw = Raw::stored(&[], &[("x", 0, 3)]);
        raw.kind = METHOD_LZX | (15 << 8);
        raw.folders = vec![vec![(lzx_repeat(u32::MAX), 3, None)]];
        let mut r = open(&raw.write(dir.path(), "r.cab")).unwrap();
        match read_entry(&mut r, 0) {
            Ok(data) => assert_eq!(data.len(), 3),
            Err(e) => assert_eq!(e.kind, ErrorKind::Corrupt),
        }
    }
}
