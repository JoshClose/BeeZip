//! NTFS (docs/M7.md §6): fstool's ntfs module behind BeeZip's checks, with BeeZip's own folder
//! walk, records, times, links and reparse points around it.
//!
//! - **Before fstool opens the volume**, BeeZip checks the boot sector. Clusters over 64 KiB, or
//!   written in NTFS's negative form (which fstool doesn't read), are `UnsupportedOperation`, so
//!   that 7-Zip can read the volume instead. It checks `$MFT`'s first record too, which fstool
//!   reads to find `$MFT` itself: when its data has no runs and its attribute list names another
//!   record, fstool recurses until its stack overflows, which aborts the process (fstool 0.5.2,
//!   `mod.rs:281` and `:390`). The records that list holds for `$MFT`'s data are checked as well.
//! - **Every record is checked before fstool walks its attributes** ([`check_attrs`]): a resident
//!   attribute too short for its own header at a record's end makes fstool's `AttributeIter`
//!   index past the record and panic (`attribute.rs:170`). A file's records are its base record
//!   and the extension records its attribute list names, read as fstool reads them, and each
//!   must point back at the base, since fstool would take another file's attributes as its own.
//! - **Folders are walked here**, through `$INDEX_ROOT` and `$INDEX_ALLOCATION` with fstool's
//!   index decoding, in name order: fstool's `read_directory` keeps one name per file in a
//!   folder, so a hard link beside its file would go missing. The walk keeps a visited set of
//!   folder records, goes at most [`MAX_DEPTH`] folders deep, and checks for cancellation between
//!   folders. It reads at most a few times the records in `$MFT` and the index bytes in the
//!   volume, so a damaged volume whose folders share their records can't keep it going.
//! - **What's listed** (decision 3): the metadata files under `[SYSTEM]/` as 7-Zip names them
//!   (`[SYSTEM]/$MFT`, `[SYSTEM]/$Extend/$Quota`), without `$BadClus:$Bad`, a sparse stream as
//!   long as the volume; every folder; alternate data streams as `file:stream` after their file;
//!   a further name of a file as a hard link to the first name met, its streams likewise; DOS 8.3
//!   names not at all. Symlinks, junctions and WSL symlinks become symlinks to their targets as
//!   stored, `\` made `/` (a junction's `\??\C:\…` stays recognisable, as `/??/C:/…`), and
//!   FsSink judges them like any other link; so do ntfs-3g's Interix links. WSL's and Interix's
//!   devices, FIFOs and sockets are special files.
//! - **Each stream's size** is the one fstool will read (a resident value, else the first piece's
//!   size), and its `packed_size` is the clusters its runs allocate, at most the volume, so the
//!   disk reader's ratio check refuses a sparse file of 100 GB before any byte is read. A stream
//!   whose pieces or runs don't add up is listed, and reading it is `Corrupt`.
//! - **Data** comes through fstool's stream reader, which decodes LZNT1 and reads holes as
//!   zeros. Files encrypted with EFS, compressed by Windows (WOF) or deduplicated by Windows
//!   Server are listed; reading them is `UnsupportedOperation`.
//! - Names are UTF-16, an unpaired surrogate read as U+FFFD; a name holding `/` or NUL is left
//!   out with a warning. Times are `$STANDARD_INFORMATION`'s, to 100 ns.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io::{self, Read},
};

use fstool::fs::ntfs::{
    Ntfs,
    attribute::{
        AttributeIter, AttributeKind, FileName, StandardInformation, TYPE_ATTRIBUTE_LIST,
        TYPE_DATA, TYPE_FILE_NAME, TYPE_INDEX_ALLOCATION, TYPE_INDEX_ROOT, TYPE_REPARSE_POINT,
        TYPE_STANDARD_INFORMATION, TYPE_VOLUME_NAME, decode_utf16le,
    },
    attribute_list,
    index::{self, IndexEntry},
    mft,
    run_list::{Extent, RunMap},
};

use super::{Device, FileSystem, VolumeOptions};
use crate::{
    Ctx, Error, ErrorKind, Result,
    backend::External,
    format::{Entry, EntryKind},
    io::read_error,
    limits::Limits,
    time::from_ntfs,
};

/// The deepest folder listed, as for a DMG's volume.
pub const MAX_DEPTH: usize = 256;
/// The largest cluster read; larger ones go to 7-Zip.
pub const MAX_CLUSTER: u64 = 64 * 1024;
/// The largest attribute list read: tens of thousands of extension records.
pub const MAX_ATTR_LIST: u64 = 1 << 20;
/// The most bytes one file's records may take together.
const MAX_RECORD_SET: u64 = 64 << 20;
/// A reparse point's most data, as Windows bounds it (`MAXIMUM_REPARSE_DATA_BUFFER_SIZE`).
const MAX_REPARSE: u64 = 16 * 1024;
/// The largest LZNT1 compression unit read: Windows writes 64 KiB ones.
const MAX_COMPRESSION_UNIT: u64 = 1 << 20;
/// The most bytes of paths listed together; past it the listing is refused.
const MAX_PATH_BYTES: u64 = 256 << 20;
/// The most bytes of an Interix file's data read to tell what it is: a magic and a target.
const INTERIX_HEAD: u64 = 8 + 2 * 4096;

const ROOT: u64 = 5;
const BAD_CLUS: u64 = 8;
const VOLUME: u64 = 3;
/// Records below this, named in the root folder with a `$`, are the volume's metadata.
const FIRST_USER: u64 = 16;
const SYSTEM_DIR: &str = "[SYSTEM]";
const REF_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

const TYPE_VOLUME_INFORMATION: u32 = 0x70;
const ATTR_COMPRESSED: u16 = 0x0001;
const ATTR_ENCRYPTED: u16 = 0x4000;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
/// NTFS's own bits in `$STANDARD_INFORMATION`, not Windows' attributes.
const NTFS_INTERNAL: u32 = 0x3000_0000;

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn le64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("ntfs: {message}"))
}

/// An fstool error as BeeZip's: errors of the image come back as they were.
fn fs_error(e: fstool::Error) -> Error {
    match e {
        fstool::Error::Io(e) => read_error(&e),
        fstool::Error::Unsupported(m) => {
            Error::unsupported(format!("ntfs: {}", m.trim_start_matches("ntfs: ")))
        }
        fstool::Error::InvalidImage(m) => bad(m.trim_start_matches("ntfs: ")),
        e => bad(e),
    }
}

/// Whether an error ends the listing instead of leaving one file or folder out: cancelling, a
/// limit, or the image itself failing to read.
fn fatal(e: &Error) -> bool {
    matches!(
        e.kind,
        ErrorKind::Cancelled | ErrorKind::LimitExceeded | ErrorKind::Io
    )
}

/// An error's message without the `ntfs: ` it starts with, to say inside another.
fn why(e: &Error) -> &str {
    e.message.trim_start_matches("ntfs: ")
}

/// An fstool error's message, to say inside another.
fn fs_why(e: fstool::Error) -> String {
    why(&fs_error(e)).to_owned()
}

/// The volume's layout, from its boot sector.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    sector: u32,
    cluster: u64,
    record: usize,
    mft_lcn: u64,
    /// The volume's bytes, by its boot sector.
    len: u64,
    clusters: u64,
    serial: u64,
}

/// The boot sector, checked as far as fstool doesn't, and for what it doesn't read.
fn geometry(dev: &mut Device) -> Result<Geometry> {
    if dev.len() < 512 {
        return Err(bad("the volume is too small to hold a boot sector"));
    }
    let mut b = [0u8; 512];
    dev.read_exact_at(0, &mut b)?;
    if &b[3..11] != b"NTFS    " {
        return Err(bad("the volume has no NTFS boot sector"));
    }
    let bps = le16(&b, 11);
    if !(256..=4096).contains(&bps) || !bps.is_power_of_two() {
        return Err(bad(format!("the boot sector says sectors are {bps} bytes")));
    }
    let spc = b[13];
    if spc > 0x80 {
        // 2^(256 - spc) sectors: how NTFS writes clusters of 128 KiB and more.
        let shift = 256 - u32::from(spc);
        let kib = 1u128
            .checked_shl(shift)
            .and_then(|s| s.checked_mul(u128::from(bps)))
            .map(|b| b / 1024);
        return Err(Error::unsupported(match kib {
            Some(k) if k > 64 => format!(
                "ntfs: the volume's clusters are {k} KiB; BeeZip reads NTFS clusters up to 64 KiB"
            ),
            _ => "ntfs: the volume's cluster size is written in NTFS's negative form, which \
                  BeeZip doesn't read"
                .to_owned(),
        }));
    }
    if spc == 0 || !spc.is_power_of_two() {
        return Err(bad(format!(
            "the boot sector says clusters are {spc} sectors"
        )));
    }
    let cluster = u64::from(bps) * u64::from(spc);
    if cluster > MAX_CLUSTER {
        return Err(Error::unsupported(format!(
            "ntfs: the volume's clusters are {} KiB; BeeZip reads NTFS clusters up to 64 KiB",
            cluster / 1024
        )));
    }
    let per_record = b[0x40] as i8;
    let record = match per_record {
        n if n > 0 => u64::from(n.unsigned_abs()) * cluster,
        n if n < 0 && n > -32 => 1u64 << n.unsigned_abs(),
        n => {
            return Err(bad(format!(
                "the boot sector's record size ({n}) isn't one"
            )));
        }
    };
    if !(512..=1 << 20).contains(&record) {
        return Err(bad(format!(
            "the boot sector says records are {record} bytes"
        )));
    }
    if record > 64 * 1024 {
        return Err(Error::unsupported(format!(
            "ntfs: the volume's records are {record} bytes; BeeZip reads records up to 64 KiB"
        )));
    }
    let len = le64(&b, 0x28)
        .checked_mul(u64::from(bps))
        .ok_or_else(|| bad("the boot sector's sector count overflows"))?;
    let mft_lcn = le64(&b, 0x30);
    if mft_lcn
        .checked_mul(cluster)
        .and_then(|at| at.checked_add(record))
        .is_none_or(|end| end > len.min(dev.len()))
    {
        return Err(bad("$MFT starts past the end of the volume"));
    }
    Ok(Geometry {
        sector: u32::from(bps),
        cluster,
        record: usize::try_from(record).map_err(|_| bad("records too large"))?,
        mft_lcn,
        len,
        clusters: len / cluster,
        serial: le64(&b, 0x48),
    })
}

/// Refuses a record that would make fstool's `AttributeIter` index past it: a resident
/// attribute too short for its own header, at the record's end (fstool 0.5.2,
/// `attribute.rs:170`). Anything else malformed is refused too, which fstool would only report.
fn check_attrs(rec: &[u8]) -> std::result::Result<(), String> {
    let hdr = mft::RecordHeader::parse(rec).map_err(fs_why)?;
    let mut at = usize::from(hdr.first_attribute_offset);
    loop {
        let Some(t) = rec.get(at..at + 4) else {
            return Ok(());
        };
        if t == [0xFF; 4] {
            return Ok(());
        }
        let Some(h) = rec.get(at..at + 16) else {
            return Err("an attribute's header runs past its record".into());
        };
        let len = le32(h, 4) as usize;
        if len < 16 || at + len > rec.len() {
            return Err(format!("an attribute of {len} bytes runs past its record"));
        }
        let resident = h[8] == 0;
        if resident && len < 0x18 || !resident && len < 0x40 {
            return Err(format!(
                "an attribute of {len} bytes is too short for its own header"
            ));
        }
        at += len;
    }
}

/// A record read and fixed up, and checked for fstool ([`check_attrs`]).
fn checked_record(mut buf: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    mft::apply_fixup(&mut buf, mft::NTFS_BLOCK_SIZE).map_err(fs_why)?;
    check_attrs(&buf)?;
    Ok(buf)
}

/// One instance of a non-resident attribute: a piece of its runs.
#[derive(Debug, Clone)]
struct Piece {
    first_vcn: u64,
    last_vcn: u64,
    size: u64,
    unit: u8,
    runs: Vec<Extent>,
}

/// `pieces`' runs, sorted by where each starts, as fstool joins `$MFT`'s: the first of two
/// pieces that start at the same cluster wins.
fn join_like_fstool(pieces: &mut [(u64, Vec<Extent>)]) -> Vec<Extent> {
    pieces.sort_by_key(|p| p.0);
    let mut out = Vec::new();
    let mut last = None;
    for (vcn, runs) in pieces.iter() {
        if last == Some(*vcn) {
            continue;
        }
        last = Some(*vcn);
        out.extend_from_slice(runs);
    }
    out
}

/// `pieces` joined into one run list after checking that they follow each other from cluster 0
/// and that every run is real and inside the volume.
fn join_checked(g: &Geometry, pieces: &mut [Piece]) -> std::result::Result<RunMap, String> {
    pieces.sort_by_key(|p| p.first_vcn);
    let mut next = 0u64;
    let mut runs = Vec::new();
    for p in pieces.iter() {
        if p.first_vcn != next {
            return Err("its pieces don't follow each other".into());
        }
        next = p.last_vcn.checked_add(1).ok_or("its pieces overflow")?;
        for r in &p.runs {
            if r.length == 0 {
                return Err("it has a run of no clusters".into());
            }
            if let Some(lcn) = r.lcn
                && lcn.checked_add(r.length).is_none_or(|end| end > g.clusters)
            {
                return Err("its data lies past the volume's end".into());
            }
        }
        runs.extend_from_slice(&p.runs);
    }
    RunMap::new(runs).map_err(fs_why)
}

/// `buf.len()` bytes from `offset` of a non-resident value whose runs are `runs`. A hole reads
/// as zeros where `holes` allows it.
fn read_runs(
    dev: &mut Device,
    g: &Geometry,
    runs: &RunMap,
    offset: u64,
    buf: &mut [u8],
    holes: bool,
) -> Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let at = offset
            .checked_add(done as u64)
            .ok_or_else(|| bad("an offset overflows"))?;
        let (vcn, within) = (at / g.cluster, at % g.cluster);
        let (ext, local) = runs
            .lookup(vcn)
            .ok_or_else(|| bad("a value's runs end before it does"))?;
        let span = (ext.length - local)
            .saturating_mul(g.cluster)
            .saturating_sub(within);
        let n = usize::try_from(span)
            .unwrap_or(usize::MAX)
            .min(buf.len() - done);
        let part = &mut buf[done..done + n];
        match ext.lcn {
            Some(lcn) => {
                let phys = lcn
                    .checked_add(local)
                    .and_then(|c| c.checked_mul(g.cluster))
                    .and_then(|b| b.checked_add(within))
                    .ok_or_else(|| bad("a run's offset overflows"))?;
                dev.read_exact_at(phys, part)?;
            }
            None if holes => part.fill(0),
            None => return Err(bad("an index lies in a hole")),
        }
        done += n;
    }
    Ok(())
}

/// The value of the first `$ATTRIBUTE_LIST` in `rec`, read as fstool reads it.
fn attribute_list(dev: &mut Device, g: &Geometry, rec: &[u8]) -> Result<Option<Vec<u8>>> {
    let hdr = mft::RecordHeader::parse(rec).map_err(fs_error)?;
    for a in AttributeIter::new(rec, usize::from(hdr.first_attribute_offset)) {
        let a = a.map_err(fs_error)?;
        if a.type_code != TYPE_ATTRIBUTE_LIST {
            continue;
        }
        return match a.kind {
            AttributeKind::Resident { value, .. } => Ok(Some(value.to_vec())),
            AttributeKind::NonResident {
                real_size, runs, ..
            } => {
                if real_size > MAX_ATTR_LIST {
                    return Err(bad(format!(
                        "an attribute list of {real_size} bytes is past BeeZip's limit of \
                         {MAX_ATTR_LIST}"
                    )));
                }
                let map = RunMap::new(runs).map_err(fs_error)?;
                let mut buf = vec![0u8; real_size as usize];
                read_runs(dev, g, &map, 0, &mut buf, true)?;
                Ok(Some(buf))
            }
        };
    }
    Ok(None)
}

/// Checks `$MFT`'s first record and the records that hold the rest of `$MFT`'s runs, exactly as
/// fstool reads them when it first finds `$MFT` (`bootstrap_mft_runs`), so that fstool neither
/// recurses without end nor walks a record [`check_attrs`] would refuse. Returns how many
/// records `$MFT` holds, by its size.
fn check_mft(dev: &mut Device, g: &Geometry) -> Result<u64> {
    let damaged = |why: String| bad(format!("$MFT's first record is damaged: {why}"));
    let mut rec0 = vec![0u8; g.record];
    dev.read_exact_at(g.mft_lcn * g.cluster, &mut rec0)?;
    let rec0 = checked_record(rec0).map_err(damaged)?;
    let hdr = mft::RecordHeader::parse(&rec0).map_err(fs_error)?;
    let mut pieces = Vec::new();
    let mut size = 0;
    for a in AttributeIter::new(&rec0, usize::from(hdr.first_attribute_offset)) {
        let a = a.map_err(|e| damaged(fs_why(e)))?;
        if a.type_code != TYPE_DATA || !a.name.is_empty() {
            continue;
        }
        match a.kind {
            AttributeKind::Resident { .. } => return Err(damaged("its data is resident".into())),
            AttributeKind::NonResident {
                starting_vcn,
                real_size,
                runs,
                ..
            } => {
                if starting_vcn == 0 {
                    size = real_size;
                }
                pieces.push((starting_vcn, runs));
            }
        }
    }
    let runs = join_like_fstool(&mut pieces);
    // With no runs here, fstool maps the records below through an empty list, which sends it
    // back here: the stack overflow.
    if runs.is_empty() {
        return Err(damaged("its data has no runs".into()));
    }
    if runs.iter().any(|r| r.length == 0) {
        return Err(damaged("its data has a run of no clusters".into()));
    }
    let map = RunMap::new(runs).map_err(fs_error)?;
    if let Some(list) = attribute_list(dev, g, &rec0).map_err(|e| damaged(why(&e).to_owned()))? {
        let mut seen = HashSet::from([0u64]);
        for e in attribute_list::decode(&list).map_err(|e| damaged(fs_why(e)))? {
            if e.type_code != TYPE_DATA || !e.name.is_empty() || !seen.insert(e.record_number()) {
                continue;
            }
            let rec = e.record_number();
            let at = rec
                .checked_mul(g.record as u64)
                .ok_or_else(|| damaged("a record number overflows".into()))?;
            let (ext, local) = map
                .lookup(at / g.cluster)
                .ok_or_else(|| damaged(format!("record {rec} lies past $MFT's runs")))?;
            let lcn = ext
                .lcn
                .ok_or_else(|| damaged(format!("record {rec} lies in a hole")))?;
            let phys = lcn
                .checked_add(local)
                .and_then(|c| c.checked_mul(g.cluster))
                .and_then(|b| b.checked_add(at % g.cluster))
                .ok_or_else(|| damaged(format!("record {rec}'s offset overflows")))?;
            let mut buf = vec![0u8; g.record];
            dev.read_exact_at(phys, &mut buf)?;
            checked_record(buf).map_err(|why| damaged(format!("record {rec}: {why}")))?;
        }
    }
    Ok((size / g.record as u64).clamp(16, g.len / g.record as u64 + 16))
}

/// What a reparse point makes of its file (docs/M7.md §6).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reparse {
    /// A symlink, junction or WSL symlink, with its target as stored, `\` made `/`.
    Link(String),
    /// WSL's FIFOs, devices and sockets.
    Special,
    /// Compressed by Windows (WOF), with the method's name.
    Wof(&'static str),
    /// Deduplicated by Windows Server: the data is in a chunk store elsewhere.
    Dedup,
    /// A link whose target can't be read.
    Bad,
    /// A tag BeeZip leaves alone: the file reads as stored.
    Other,
}

const TAG_MOUNT_POINT: u32 = 0xA000_0003;
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_DEDUP: u32 = 0x8000_0013;
const TAG_WOF: u32 = 0x8000_0017;
const TAG_LX_SYMLINK: u32 = 0xA000_001D;
const TAG_AF_UNIX: u32 = 0x8000_0023;
const TAG_LX_FIFO: u32 = 0x8000_0024;
const TAG_LX_CHR: u32 = 0x8000_0025;
const TAG_LX_BLK: u32 = 0x8000_0026;

/// A link target as stored: UTF-16 or UTF-8, `\` made `/`. Empty or holding NUL is no target.
fn target(t: String) -> Reparse {
    if t.is_empty() || t.contains('\0') {
        Reparse::Bad
    } else {
        Reparse::Link(t.replace('\\', "/"))
    }
}

/// A `$REPARSE_POINT` value: its tag, the length of its data, then the data.
fn decode_reparse(v: &[u8]) -> Reparse {
    let tag = le32(v, 0);
    let len = usize::from(le16(v, 4));
    let data = v.get(8..).map_or(&[][..], |d| &d[..len.min(d.len())]);
    // Substitute and print names, as offsets and lengths into the path buffer at `buf`.
    let names = |buf: usize| -> Option<String> {
        let path = data.get(buf..)?;
        let name = |off: usize, n: usize| -> Option<String> {
            path.get(usize::from(le16(data, off))..)?
                .get(..usize::from(le16(data, n)))
                .map(decode_utf16le)
        };
        let subst = name(0, 2).unwrap_or_default();
        Some(if subst.is_empty() { name(4, 6)? } else { subst })
    };
    match tag {
        TAG_SYMLINK if data.len() >= 12 => names(12).map_or(Reparse::Bad, target),
        TAG_MOUNT_POINT if data.len() >= 8 => names(8).map_or(Reparse::Bad, target),
        // A version (2), then the target in UTF-8.
        TAG_LX_SYMLINK if data.len() > 4 => {
            target(String::from_utf8_lossy(&data[4..]).into_owned())
        }
        TAG_SYMLINK | TAG_MOUNT_POINT | TAG_LX_SYMLINK => Reparse::Bad,
        TAG_AF_UNIX | TAG_LX_FIFO | TAG_LX_CHR | TAG_LX_BLK => Reparse::Special,
        // WOF's version and provider; the file provider's version and algorithm.
        TAG_WOF => Reparse::Wof(match (le32(data, 4), le32(data, 12)) {
            (1, _) => "WIM",
            (2, 0) => "XPRESS4K",
            (2, 1) => "LZX",
            (2, 2) => "XPRESS8K",
            (2, 3) => "XPRESS16K",
            _ => "WOF",
        }),
        TAG_DEDUP => Reparse::Dedup,
        _ => Reparse::Other,
    }
}

/// What ntfs-3g's Interix special files are, by their data's start: a symlink with its target,
/// or a device. ntfs-3g's FIFOs are empty system files, so they can't be told from one.
fn interix(head: &[u8]) -> Option<Reparse> {
    if let Some(rest) = head.strip_prefix(b"IntxLNK\x01") {
        return Some(target(
            decode_utf16le(rest).trim_end_matches('\0').to_owned(),
        ));
    }
    (head.starts_with(b"IntxCHR\0") || head.starts_with(b"IntxBLK\0")).then_some(Reparse::Special)
}

/// One data stream of a file, as listed.
#[derive(Debug, Clone)]
struct Stream {
    name: String,
    size: u64,
    /// The bytes its runs allocate, at most the volume.
    packed: u64,
    lznt1: bool,
    encrypted: bool,
    /// Why it can't be read, if it can't: damaged, or unsupported.
    refused: Option<(ErrorKind, String)>,
    /// The start of a small system file's data, to tell an Interix file.
    head: Option<Vec<u8>>,
}

impl Stream {
    /// What reading `path`, this stream, gives instead of its data, if anything.
    fn refusal(&self, path: &str) -> Option<Error> {
        if self.encrypted {
            return Some(Error::unsupported(format!(
                "ntfs: `{path}` is encrypted with EFS, which BeeZip doesn't read"
            )));
        }
        let (kind, why) = self.refused.as_ref()?;
        Some(Error::new(*kind, format!("ntfs: `{path}`: {why}")))
    }
}

/// One file's records, read.
#[derive(Debug, Default)]
struct Record {
    dir: bool,
    in_use: bool,
    /// Not a base record: an extension record of another file.
    extension: bool,
    sequence: u16,
    /// `$FILE_NAME`s other than DOS ones: more than one is a hard link.
    names: usize,
    modified: Option<u64>,
    attrs: u32,
    streams: Vec<Stream>,
    reparse: Option<Vec<u8>>,
    index_root: Option<Vec<u8>>,
    index_alloc: Vec<Piece>,
    label: Option<String>,
    version: Option<(u8, u8)>,
}

/// One stream's attributes, gathered across a file's records.
#[derive(Default)]
struct Parts {
    residents: usize,
    resident_len: u64,
    head: Vec<u8>,
    pieces: Vec<Piece>,
    flags: u16,
}

/// A file's records ([`Volume::record_set`]) made sense of.
fn parse(dev: &mut Device, g: &Geometry, set: &[Vec<u8>]) -> Result<Record> {
    let base = mft::RecordHeader::parse(&set[0]).map_err(fs_error)?;
    let mut r = Record {
        dir: base.is_directory(),
        in_use: base.is_in_use(),
        extension: base.base_record_ref & REF_MASK != 0,
        sequence: le16(&set[0], 0x10),
        ..Record::default()
    };
    // In the order first met, and by name, since a set may hold a great many.
    let mut streams: Vec<(String, Parts)> = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for rec in set {
        let hdr = mft::RecordHeader::parse(rec).map_err(fs_error)?;
        for a in AttributeIter::new(rec, usize::from(hdr.first_attribute_offset)) {
            let a = a.map_err(fs_error)?;
            match (a.type_code, a.kind) {
                (TYPE_STANDARD_INFORMATION, AttributeKind::Resident { value, .. }) => {
                    if r.modified.is_none()
                        && let Ok(si) = StandardInformation::parse(value)
                    {
                        r.modified = Some(si.modified_time);
                        r.attrs = si.file_attributes;
                    }
                }
                (TYPE_FILE_NAME, AttributeKind::Resident { value, .. }) => {
                    if FileName::parse(value).is_ok_and(|f| f.namespace != FileName::NAMESPACE_DOS)
                    {
                        r.names += 1;
                    }
                }
                (TYPE_DATA, kind) => {
                    let i = *by_name.entry(a.name.clone()).or_insert_with(|| {
                        streams.push((a.name.clone(), Parts::default()));
                        streams.len() - 1
                    });
                    let p = &mut streams[i].1;
                    p.flags |= a.flags;
                    match kind {
                        AttributeKind::Resident { value, .. } => {
                            p.residents += 1;
                            p.resident_len = value.len() as u64;
                            p.head = value[..value.len().min(INTERIX_HEAD as usize)].to_vec();
                        }
                        AttributeKind::NonResident {
                            starting_vcn,
                            last_vcn,
                            real_size,
                            compression_unit,
                            runs,
                            ..
                        } => p.pieces.push(Piece {
                            first_vcn: starting_vcn,
                            last_vcn,
                            size: real_size,
                            unit: compression_unit,
                            runs,
                        }),
                    }
                }
                (TYPE_INDEX_ROOT, AttributeKind::Resident { value, .. }) if a.name == "$I30" => {
                    r.index_root.get_or_insert_with(|| value.to_vec());
                }
                (
                    TYPE_INDEX_ALLOCATION,
                    AttributeKind::NonResident {
                        starting_vcn,
                        last_vcn,
                        real_size,
                        runs,
                        ..
                    },
                ) if a.name == "$I30" => r.index_alloc.push(Piece {
                    first_vcn: starting_vcn,
                    last_vcn,
                    size: real_size,
                    unit: 0,
                    runs,
                }),
                (TYPE_REPARSE_POINT, kind) if r.reparse.is_none() => {
                    r.reparse = Some(match kind {
                        AttributeKind::Resident { value, .. } => {
                            value[..value.len().min(MAX_REPARSE as usize)].to_vec()
                        }
                        AttributeKind::NonResident {
                            real_size, runs, ..
                        } => {
                            let map = RunMap::new(runs).map_err(fs_error)?;
                            let mut buf = vec![0u8; real_size.min(MAX_REPARSE) as usize];
                            read_runs(dev, g, &map, 0, &mut buf, true)?;
                            buf
                        }
                    });
                }
                (TYPE_VOLUME_NAME, AttributeKind::Resident { value, .. }) => {
                    r.label = Some(decode_utf16le(value));
                }
                (TYPE_VOLUME_INFORMATION, AttributeKind::Resident { value, .. }) => {
                    if let Some(&[major, minor]) = value.get(8..10) {
                        r.version = Some((major, minor));
                    }
                }
                _ => {}
            }
        }
    }
    // Only a system file's data may be an Interix link or device.
    let interix = r.attrs & FILE_ATTRIBUTE_SYSTEM != 0 && !r.dir && r.reparse.is_none();
    for (name, p) in streams {
        let head = interix && name.is_empty();
        let s = stream(dev, g, name, p, head)?;
        r.streams.push(s);
    }
    Ok(r)
}

/// A stream from its attributes: the size fstool will read, the bytes it allocates, whether its
/// pieces add up, and with `head`, the start of its data when it's small.
fn stream(
    dev: &mut Device,
    g: &Geometry,
    name: String,
    mut p: Parts,
    head: bool,
) -> Result<Stream> {
    let mut s = Stream {
        name,
        size: 0,
        packed: 0,
        lznt1: false,
        encrypted: p.flags & ATTR_ENCRYPTED != 0,
        refused: None,
        head: None,
    };
    let damaged = |why: &str| Some((ErrorKind::Corrupt, format!("it's damaged: {why}")));
    if p.residents > 0 {
        // fstool reads the last resident value, whatever else there is.
        s.size = p.resident_len;
        s.packed = p.resident_len;
        if head {
            s.head = Some(std::mem::take(&mut p.head));
        }
        if p.residents > 1 || !p.pieces.is_empty() {
            s.refused = damaged("its data is stored twice");
        }
        return Ok(s);
    }
    p.pieces.sort_by_key(|p| p.first_vcn);
    let Some(first) = p.pieces.first().cloned() else {
        return Ok(s);
    };
    s.size = first.size;
    s.packed = p
        .pieces
        .iter()
        .flat_map(|p| &p.runs)
        .filter(|r| r.lcn.is_some())
        .fold(0u64, |n, r| {
            n.saturating_add(r.length.saturating_mul(g.cluster))
        })
        .min(g.len);
    let compressed = p.flags & ATTR_COMPRESSED != 0 && first.unit > 0;
    s.lznt1 = compressed;
    match join_checked(g, &mut p.pieces) {
        Err(why) => s.refused = damaged(&why),
        Ok(map) => {
            if map.total_clusters().saturating_mul(g.cluster) < s.size {
                s.refused = damaged("its runs end before its data does");
            } else if compressed
                && 1u64
                    .checked_shl(u32::from(first.unit))
                    .and_then(|n| n.checked_mul(g.cluster))
                    .is_none_or(|unit| unit > MAX_COMPRESSION_UNIT)
            {
                s.refused = Some((
                    ErrorKind::UnsupportedOperation,
                    format!(
                        "its LZNT1 compression units are 2^{} clusters; BeeZip reads them up to \
                         {} KiB",
                        first.unit,
                        MAX_COMPRESSION_UNIT / 1024
                    ),
                ));
            } else if head && !compressed && s.size <= INTERIX_HEAD && !s.encrypted {
                let mut head = vec![0u8; s.size as usize];
                if read_runs(dev, g, &map, 0, &mut head, true).is_ok() {
                    s.head = Some(head);
                }
            }
        }
    }
    Ok(s)
}

/// What open gives for an entry.
#[derive(Debug, Clone)]
enum Data {
    /// Folders, links and special files: nothing.
    None,
    /// A file with no such stream: no bytes.
    Empty,
    /// The stream `name` (`""`: the file's data) of record `rec`, through fstool.
    Stream { rec: u64, name: String },
    /// Can't be read, for this reason.
    Refused(Error),
}

/// A file listed under its first name, for its further names.
struct First {
    id: usize,
    streams: Vec<(String, usize)>,
}

/// A folder to list.
struct Folder {
    rec: u64,
    /// From the volume's root; empty for the root.
    path: String,
    depth: usize,
}

/// An NTFS volume, listed when it opens.
pub struct Volume {
    ntfs: Ntfs,
    dev: Device,
    g: Geometry,
    entries: Vec<Entry>,
    data: Vec<Data>,
    label: Option<String>,
    version: Option<(u8, u8)>,
    methods: Vec<Cow<'static, str>>,
    /// Records the walk may still read.
    records_left: u64,
    /// Index bytes the walk may still read.
    index_left: u64,
}

impl std::fmt::Debug for Volume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume")
            .field("dev", &self.dev)
            .field("g", &self.g)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// The volume on `dev`, with every entry listed.
pub fn open(dev: Device, opts: &VolumeOptions, cx: &mut dyn Ctx) -> Result<Box<dyn FileSystem>> {
    Ok(Box::new(Volume::open(dev, &opts.limits, cx)?))
}

impl Volume {
    /// Opens and lists the volume on `dev` (see the module's notes).
    pub fn open(dev: Device, limits: &Limits, cx: &mut dyn Ctx) -> Result<Self> {
        let mut dev = dev;
        let g = geometry(&mut dev)?;
        let mut dev = dev.with_sector(g.sector);
        if g.len > dev.len() {
            cx.warn(format!(
                "ntfs: the image holds {} bytes of a volume of {}; what lies past its end can't \
                 be read",
                dev.len(),
                g.len
            ));
        }
        let records = check_mft(&mut dev, &g)?;
        let ntfs = Ntfs::open(&mut dev).map_err(fs_error)?;
        let mut v = Self {
            ntfs,
            dev,
            g,
            entries: Vec::new(),
            data: Vec::new(),
            label: None,
            version: None,
            methods: Vec::new(),
            records_left: records.saturating_mul(3).saturating_add(4096),
            index_left: g.len.saturating_mul(2).saturating_add(16 << 20),
        };
        if let Ok(set) = v.record_set(VOLUME)
            && let Ok(r) = parse(&mut v.dev, &v.g, &set)
        {
            v.label = r.label;
            v.version = r.version;
        }
        v.walk(limits, cx)?;
        Ok(v)
    }

    /// Record `rec`, read through fstool and checked.
    fn record(&mut self, rec: u64) -> Result<Vec<u8>> {
        if self.records_left == 0 {
            return Err(bad(
                "the folders name records over and over; the volume is damaged",
            ));
        }
        self.records_left -= 1;
        let mut buf = vec![0u8; self.g.record];
        self.ntfs
            .read_mft_record(&mut self.dev, rec, &mut buf)
            .map_err(fs_error)?;
        check_attrs(&buf).map_err(|why| bad(format!("record {rec}: {why}")))?;
        Ok(buf)
    }

    /// File `rec`'s records: its base record, then the extension records its attribute list
    /// names, as fstool reads them for its data (`load_record_set`). Each must belong to `rec`.
    fn record_set(&mut self, rec: u64) -> Result<Vec<Vec<u8>>> {
        let base = self.record(rec)?;
        let Some(list) = attribute_list(&mut self.dev, &self.g, &base)? else {
            return Ok(vec![base]);
        };
        let mut set = vec![base];
        let mut seen = HashSet::from([rec]);
        for e in attribute_list::decode(&list).map_err(fs_error)? {
            let other = e.record_number();
            if !seen.insert(other) {
                continue;
            }
            if (set.len() as u64 + 1).saturating_mul(self.g.record as u64) > MAX_RECORD_SET {
                return Err(bad(format!(
                    "record {rec}'s attribute list names more records than BeeZip reads"
                )));
            }
            let buf = self.record(other)?;
            let owner = mft::RecordHeader::parse(&buf)
                .map_err(fs_error)?
                .base_record_ref
                & REF_MASK;
            if owner != rec {
                return Err(bad(format!(
                    "record {rec}'s attribute list names record {other}, which isn't its own"
                )));
            }
            set.push(buf);
        }
        Ok(set)
    }

    /// The names in folder `rec`'s index, in its order (collation order), without DOS names.
    fn folder(
        &mut self,
        set: &[Vec<u8>],
        limits: &Limits,
        listed: usize,
    ) -> Result<Vec<(u64, String)>> {
        let mut r = parse(&mut self.dev, &self.g, set)?;
        let root = r
            .index_root
            .take()
            .ok_or_else(|| bad("the folder has no index of names"))?;
        let h = index::IndexRootHeader::parse(&root).map_err(fs_error)?;
        if h.indexed_attr_type != TYPE_FILE_NAME {
            return Err(bad("the folder's index isn't of names"));
        }
        let start = 16 + h.first_entry_offset as usize;
        let end = 16 + h.bytes_in_use as usize;
        if h.first_entry_offset < 16 || start > end || end > root.len() {
            return Err(bad("the folder's index root is damaged"));
        }
        let mut stack = Vec::new();
        push_node(&root, start, end - start, &mut stack)?;
        let mut alloc: Option<RunMap> = None;
        let block = h.index_block_size as usize;
        let mut blocks = HashSet::new();
        let mut out = Vec::new();
        let mut names = HashSet::new();
        while let Some(step) = stack.pop() {
            match step {
                Step::Name(e) => {
                    let Some(f) = e.file_name else { continue };
                    if f.namespace == FileName::NAMESPACE_DOS {
                        continue;
                    }
                    // The same name twice is one name.
                    if !names.insert(f.name.clone()) {
                        continue;
                    }
                    out.push((e.file_ref, f.name));
                    if out.len() % 4096 == 0 {
                        limits.check_entries((listed + out.len()) as u64)?;
                    }
                }
                Step::Node(vcn) => {
                    if alloc.is_none() {
                        if !(512..=64 * 1024).contains(&block) || !block.is_power_of_two() {
                            return Err(bad(format!(
                                "the folder's index blocks are {block} bytes"
                            )));
                        }
                        let map = join_checked(&self.g, &mut r.index_alloc)
                            .map_err(|why| bad(format!("the folder's index: {why}")))?;
                        if map.runs().is_empty() {
                            return Err(bad("the folder's index has blocks but no runs"));
                        }
                        alloc = Some(map);
                    }
                    let Some(map) = alloc.as_ref() else { continue };
                    if !blocks.insert(vcn) {
                        return Err(bad("the folder's index loops"));
                    }
                    self.index_left =
                        self.index_left.checked_sub(block as u64).ok_or_else(|| {
                            bad(
                                "the folders read the same index over and over; the volume is \
                                 damaged",
                            )
                        })?;
                    let unit = index::vcn_unit_bytes(self.g.cluster, block as u64);
                    let at = vcn
                        .checked_mul(unit)
                        .ok_or_else(|| bad("an index block's offset overflows"))?;
                    let mut buf = vec![0u8; block];
                    read_runs(&mut self.dev, &self.g, map, at, &mut buf, false)?;
                    mft::apply_fixup(&mut buf, mft::NTFS_BLOCK_SIZE).map_err(fs_error)?;
                    let bh = index::IndexBlockHeader::parse(&buf).map_err(fs_error)?;
                    let start = 0x18 + bh.first_entry_offset as usize;
                    let end = 0x18 + bh.bytes_in_use as usize;
                    if bh.first_entry_offset < 16 || start > end || end > buf.len() {
                        return Err(bad("an index block of the folder is damaged"));
                    }
                    push_node(&buf, start, end - start, &mut stack)?;
                }
            }
        }
        Ok(out)
    }

    /// Lists the volume: every folder from the root, depth first, parents before their contents.
    fn walk(&mut self, limits: &Limits, cx: &mut dyn Ctx) -> Result<()> {
        let mut w = Walk {
            limits,
            first: HashMap::new(),
            visited: HashSet::from([ROOT]),
            path_bytes: 0,
            system_dir: false,
        };
        let mut pending = vec![Folder {
            rec: ROOT,
            path: String::new(),
            depth: 0,
        }];
        while let Some(dir) = pending.pop() {
            cx.check()?;
            let names = match self
                .record_set(dir.rec)
                .and_then(|set| self.folder(&set, limits, self.entries.len()))
            {
                Ok(n) => n,
                Err(e) if fatal(&e) => return Err(e),
                Err(e) if dir.rec == ROOT => {
                    return Err(Error::new(
                        e.kind,
                        format!("ntfs: the root folder can't be listed: {}", why(&e)),
                    ));
                }
                Err(e) => {
                    cx.warn(format!("ntfs: `{}` can't be listed: {}", dir.path, why(&e)));
                    continue;
                }
            };
            let mut subdirs = Vec::new();
            for (file_ref, name) in names {
                self.child(&mut w, &dir, file_ref, name, &mut subdirs, cx)?;
            }
            pending.extend(subdirs.into_iter().rev());
        }
        let mut methods = Vec::new();
        for (e, d) in self.entries.iter().zip(&self.data) {
            if let (Some(m), Data::Stream { .. } | Data::Refused(_)) = (&e.method, d)
                && !methods.contains(m)
            {
                methods.push(m.clone());
            }
        }
        methods.sort();
        self.methods = methods;
        Ok(())
    }

    /// Adds an entry.
    fn push(
        &mut self,
        w: &mut Walk<'_>,
        path: String,
        kind: EntryKind,
        data: Data,
    ) -> Result<usize> {
        w.limits.check_entries(self.entries.len() as u64 + 1)?;
        w.path_bytes += path.len() as u64;
        if w.path_bytes > MAX_PATH_BYTES {
            return Err(Error::limit(format!(
                "ntfs: the volume's paths take more than {} MiB together",
                MAX_PATH_BYTES >> 20
            )));
        }
        let id = self.entries.len();
        self.entries.push(Entry::new(id, path, kind));
        self.data.push(data);
        Ok(id)
    }

    /// Lists `name` of folder `dir`: a file, folder or link with its streams, or a further name
    /// of a file listed already. A folder to walk goes on `subdirs`.
    fn child(
        &mut self,
        w: &mut Walk<'_>,
        dir: &Folder,
        file_ref: u64,
        name: String,
        subdirs: &mut Vec<Folder>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let rec = file_ref & REF_MASK;
        if dir.rec == ROOT && rec == ROOT && name == "." {
            return Ok(());
        }
        let shown = |dir: &Folder| {
            if dir.path.is_empty() {
                "the root folder".to_owned()
            } else {
                format!("`{}`", dir.path)
            }
        };
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            cx.warn(format!(
                "ntfs: {} holds a name no file can have, {name:?}; it's left out",
                shown(dir)
            ));
            return Ok(());
        }
        let system = dir.rec == ROOT && rec < FIRST_USER && name.starts_with('$');
        let path = if system {
            if !w.system_dir {
                w.system_dir = true;
                self.push(w, SYSTEM_DIR.to_owned(), EntryKind::Dir, Data::None)?;
            }
            format!("{SYSTEM_DIR}/{name}")
        } else if dir.path.is_empty() {
            name
        } else {
            format!("{}/{name}", dir.path)
        };
        if let Some((id, streams)) = w.first.get(&rec).map(|f| (f.id, f.streams.clone())) {
            return self.further_name(w, path, id, streams);
        }
        let r = match self
            .record_set(rec)
            .and_then(|set| parse(&mut self.dev, &self.g, &set))
        {
            Ok(r) => r,
            Err(e) if fatal(&e) => return Err(e),
            Err(e) => {
                cx.warn(format!("ntfs: `{path}` can't be read: {}", why(&e)));
                return Ok(());
            }
        };
        let seq = (file_ref >> 48) as u16;
        if !r.in_use || r.extension || seq != 0 && r.sequence != 0 && seq != r.sequence {
            cx.warn(format!(
                "ntfs: `{path}` names a record that's no longer the file's; it's left out"
            ));
            return Ok(());
        }
        let reparse = r.reparse.as_deref().map(decode_reparse);
        let unnamed = r.streams.iter().find(|s| s.name.is_empty());
        let mut refused: Option<Error> = None;
        let mut method = None;
        let kind = match &reparse {
            Some(Reparse::Link(t)) => EntryKind::Symlink { target: t.clone() },
            Some(Reparse::Special) => EntryKind::Other,
            Some(Reparse::Bad) => {
                cx.warn(format!("ntfs: `{path}`'s link can't be read"));
                EntryKind::Other
            }
            Some(Reparse::Wof(m)) if !r.dir => {
                method = Some(Cow::Borrowed(*m));
                refused = Some(Error::unsupported(format!(
                    "ntfs: `{path}` is compressed by Windows ({m}), which BeeZip doesn't read"
                )));
                EntryKind::File
            }
            Some(Reparse::Dedup) if !r.dir => {
                refused = Some(Error::unsupported(format!(
                    "ntfs: `{path}` is deduplicated by Windows Server; its data isn't in the \
                     volume's file"
                )));
                EntryKind::File
            }
            _ if r.dir => EntryKind::Dir,
            _ => match unnamed
                .filter(|_| !system && r.attrs & FILE_ATTRIBUTE_SYSTEM != 0)
                .and_then(|s| s.head.as_deref())
                .and_then(interix)
            {
                Some(Reparse::Link(t)) => EntryKind::Symlink { target: t },
                Some(Reparse::Special) => EntryKind::Other,
                _ => EntryKind::File,
            },
        };
        let encrypted = kind == EntryKind::File
            && (r.attrs & FILE_ATTRIBUTE_ENCRYPTED != 0 || unnamed.is_some_and(|s| s.encrypted));
        let data = match (&kind, unnamed) {
            (EntryKind::File, _) if encrypted => Data::Refused(Error::unsupported(format!(
                "ntfs: `{path}` is encrypted with EFS, which BeeZip doesn't read"
            ))),
            (EntryKind::File, _) if refused.is_some() => {
                Data::Refused(refused.take().unwrap_or_else(|| bad("refused")))
            }
            (EntryKind::File, Some(s)) => match s.refusal(&path) {
                Some(e) => Data::Refused(e),
                None => Data::Stream {
                    rec,
                    name: String::new(),
                },
            },
            (EntryKind::File, None) => Data::Empty,
            _ => Data::None,
        };
        let id = self.push(w, path.clone(), kind.clone(), data)?;
        let attrs = (r.attrs & !NTFS_INTERNAL)
            | if r.dir && !matches!(kind, EntryKind::File) {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                0
            };
        let modified = r.modified.filter(|&t| t > 0).and_then(from_ntfs);
        {
            let e = &mut self.entries[id];
            e.modified = modified;
            e.dos_attrs = Some(attrs);
            e.encrypted = encrypted;
            if kind == EntryKind::File {
                // A WOF file's bytes on the volume are its compressed stream's.
                let wof = r
                    .streams
                    .iter()
                    .filter(|s| method.is_some() && s.name == "WofCompressedData")
                    .map(|s| s.packed)
                    .sum::<u64>();
                e.size = Some(unnamed.map_or(0, |s| s.size));
                e.packed_size = Some(unnamed.map_or(0, |s| s.packed).saturating_add(wof));
                e.method =
                    method.or_else(|| unnamed.filter(|s| s.lznt1).map(|_| Cow::Borrowed("LZNT1")));
            }
        }
        let mut streams = Vec::new();
        for s in r.streams.iter().filter(|s| !s.name.is_empty()) {
            // `$BadClus:$Bad` is a hole as long as the volume (decision 3).
            if rec == BAD_CLUS && system && s.name == "$Bad" {
                continue;
            }
            let spath = format!("{path}:{}", s.name);
            let data = match s.refusal(&spath) {
                _ if encrypted => Data::Refused(Error::unsupported(format!(
                    "ntfs: `{spath}` is encrypted with EFS, which BeeZip doesn't read"
                ))),
                Some(e) => Data::Refused(e),
                None => Data::Stream {
                    rec,
                    name: s.name.clone(),
                },
            };
            let sid = self.push(w, spath, EntryKind::File, data)?;
            let e = &mut self.entries[sid];
            e.size = Some(s.size);
            e.packed_size = Some(s.packed);
            e.modified = modified;
            e.dos_attrs = Some(attrs & !FILE_ATTRIBUTE_DIRECTORY);
            e.encrypted = s.encrypted || encrypted;
            e.method = s.lznt1.then_some(Cow::Borrowed("LZNT1"));
            streams.push((s.name.clone(), sid));
        }
        if r.dir && kind == EntryKind::Dir {
            if dir.depth + 1 >= MAX_DEPTH {
                cx.warn(format!(
                    "ntfs: `{path}` is more than {MAX_DEPTH} folders deep; what's in it isn't \
                     listed"
                ));
            } else if w.visited.insert(rec) {
                subdirs.push(Folder {
                    rec,
                    path,
                    depth: dir.depth + 1,
                });
            } else {
                cx.warn(format!(
                    "ntfs: `{path}` is a folder already listed; what's in it isn't listed again"
                ));
            }
        } else if !r.dir && r.names > 1 {
            w.first.insert(rec, First { id, streams });
        }
        Ok(())
    }

    /// A further name of the file listed as entry `first`, with its streams: hard links to it,
    /// or the same link or special file again.
    fn further_name(
        &mut self,
        w: &mut Walk<'_>,
        path: String,
        first: usize,
        streams: Vec<(String, usize)>,
    ) -> Result<()> {
        let f = &self.entries[first];
        let kind = match &f.kind {
            EntryKind::File => EntryKind::Hardlink {
                target: f.path.clone(),
            },
            k => k.clone(),
        };
        let (modified, attrs) = (f.modified, f.dos_attrs);
        let id = self.push(w, path.clone(), kind, Data::None)?;
        self.entries[id].modified = modified;
        self.entries[id].dos_attrs = attrs;
        for (name, sid) in streams {
            let target = self.entries[sid].path.clone();
            let (modified, attrs) = (self.entries[sid].modified, self.entries[sid].dos_attrs);
            let id = self.push(
                w,
                format!("{path}:{name}"),
                EntryKind::Hardlink { target },
                Data::None,
            )?;
            self.entries[id].modified = modified;
            self.entries[id].dos_attrs = attrs;
        }
        Ok(())
    }
}

/// What the walk keeps between folders.
struct Walk<'a> {
    limits: &'a Limits,
    /// Files with several names, by record: the entry of the first name met.
    first: HashMap<u64, First>,
    /// Folder records listed or to be listed.
    visited: HashSet<u64>,
    path_bytes: u64,
    /// Whether `[SYSTEM]` is listed yet.
    system_dir: bool,
}

/// One step of an in-order walk of a folder's index: a block to read, or a name to give.
enum Step {
    Node(u64),
    Name(IndexEntry),
}

/// Pushes the steps for one index node so that, popped, they give each entry's subtree (smaller
/// names), then the entry, then after the last the end marker's subtree.
fn push_node(buf: &[u8], start: usize, len: usize, stack: &mut Vec<Step>) -> Result<()> {
    let mut list = Vec::new();
    let children =
        index::walk_index_node(buf, start, len, |e| list.push(e.clone())).map_err(fs_error)?;
    let with_child = list.iter().filter(|e| e.child_vcn.is_some()).count();
    if children.len() > with_child
        && let Some(&last) = children.last()
    {
        stack.push(Step::Node(last));
    }
    for e in list.into_iter().rev() {
        let child = e.child_vcn;
        stack.push(Step::Name(e));
        if let Some(c) = child {
            stack.push(Step::Node(c));
        }
    }
    Ok(())
}

/// A stream from fstool, its errors made BeeZip's: the image's own come back as they were, the
/// rest are `Corrupt`.
struct Reader<R>(R);

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(|e| {
            let err = if e.get_ref().is_some_and(|i| i.is::<fstool::Error>()) {
                match e.into_inner().map(|i| i.downcast::<fstool::Error>()) {
                    Some(Ok(f)) => fs_error(*f),
                    _ => bad("a read failed"),
                }
            } else {
                let err = read_error(&e);
                Error::new(err.kind, format!("ntfs: {}", why(&err)))
            };
            err.into_io()
        })
    }
}

impl FileSystem for Volume {
    fn kind(&self) -> External {
        External::Ntfs
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<Vec<Entry>> {
        Ok(std::mem::take(&mut self.entries))
    }

    fn open(&mut self, id: usize) -> Result<Box<dyn Read + '_>> {
        match self.data.get(id) {
            Some(Data::Stream { rec, name }) => {
                let (rec, name) = (*rec, name.clone());
                let r = self
                    .ntfs
                    .open_stream_by_record(&mut self.dev, rec, &name)
                    .map_err(fs_error)?;
                Ok(Box::new(Reader(r)))
            }
            Some(Data::Refused(e)) => Err(e.clone()),
            Some(Data::Empty | Data::None) => Ok(Box::new(io::empty())),
            None => Err(Error::new(ErrorKind::NotFound, format!("no entry {id}"))),
        }
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut p = Vec::new();
        if let Some(l) = &self.label {
            p.push(("Label", l.clone()));
        }
        if let Some((major, minor)) = self.version {
            p.push(("File System", format!("NTFS {major}.{minor}")));
        }
        p.push(("Cluster Size", self.g.cluster.to_string()));
        p.push(("Sector Size", self.g.sector.to_string()));
        p.push(("MFT Record Size", self.g.record.to_string()));
        p.push(("ID", self.g.serial.to_string()));
        p
    }

    fn methods(&self) -> Vec<Cow<'static, str>> {
        self.methods.clone()
    }
}

#[cfg(test)]
mod tests;
