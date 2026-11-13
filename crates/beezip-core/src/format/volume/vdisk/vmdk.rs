//! VMDK, from VMware's Virtual Disk Format 5.0 (docs/M8.md §3.3): a descriptor, embedded in a
//! hosted sparse extent or a text file of its own, naming the disk's extents in order.
//!
//! - **Read:** hosted sparse extents (`KDMV`, versions 1 to 3: monolithicSparse,
//!   twoGbMaxExtentSparse's pieces, zeroed-grain entries); stream-optimized ones, whose grains are
//!   deflate behind markers, VMware's (the grain directory in a footer) and qemu-img's (at the
//!   start, no footer); FLAT and VMFS extents (monolithicFlat, twoGbMaxExtentFlat, a `vmfs`
//!   descriptor with its `-flat.vmdk`), and ESXi's VMFSRAW read as FLAT, as 7-Zip reads it
//!   (docs/M11.md §6.1); ZERO and NOACCESS extents, which read as zeros; a bare
//!   sparse extent opened alone; child disks, whose parent (`parentFileNameHint`) must have the
//!   CID the child records as `parentCID`.
//! - **Descriptors** are UTF-8, or Latin-1 when they declare a `windows-125x` or ISO-8859
//!   encoding. A line that isn't either is skipped, unless it's one BeeZip needs (an extent, the
//!   CIDs, the parent's name): then it's `Corrupt`.
//! - **Grains** of up to 1 GiB, as 7-Zip reads them (VMware and qemu-img write 64 KiB): a
//!   stored grain is read where it is; a compressed one, decoded whole, must fit `decoder_memory`
//!   (`LimitExceeded`), and a grain whose compressed bytes couldn't hold it is `Corrupt` before
//!   anything is allocated for it.
//! - **Refused** (`UnsupportedOperation`): ESXi's vmfsSparse (`COWD`) and seSparse extents, raw
//!   device maps (VMFSRDM, VMFSRDMP), grains compressed without markers or other than with
//!   deflate, grain tables of other than 512 entries. An extent named by a device
//!   (`\\.\PhysicalDrive0`, `/dev/sda`) is `Unsafe` ([`Files`]).
//! - **The redundant grain directory** isn't used: a damaged primary one is `Corrupt`.
//! - **Memory:** the grain directory is read only when the file holds it (and at most
//!   [`MAX_GD`]); grain tables (2 KiB) and decoded grains are cached a few at a time.

use std::{borrow::Cow, cell::RefCell, collections::HashMap};

use super::{Cache, Decoders, Files, Got, Handle, Layer, Origin, files, le32, le64};
use crate::{Error, ErrorKind, Result, backend::External};

/// The largest descriptor read, embedded or in a file of its own.
const MAX_DESCRIPTOR: u64 = 1 << 20;
/// The largest grain directory read: 64 MiB maps 512 TiB of 64 KiB grains.
const MAX_GD: u64 = 64 << 20;
/// The largest grain read: VMware and qemu-img write 64 KiB; 7-Zip reads them up to 1 GiB.
const MAX_GRAIN: u64 = 1 << 30;
/// What the decoded grains kept may take together (at least one grain).
const GRAIN_BYTES: u64 = 16 << 20;
/// Deflate's most: a stream decodes to at most about 1,032 times its length.
const DEFLATE_RATIO: u64 = 1032;
/// Entries in a grain table, as every VMware disk has them.
const GTES: u64 = 512;
/// Grain tables kept in memory, 2 KiB each.
const GT_CACHE: usize = 256;
/// Decoded grains kept in memory.
const GRAIN_CACHE: usize = 4;
/// A grain directory "at the end": a stream-optimized extent VMware wrote, whose footer has it.
const GD_AT_END: u64 = u64::MAX;
/// A grain table entry of 1 means a zeroed grain (with [`ZEROED`]).
const ZEROED: u32 = 1 << 2;
const COMPRESSED: u32 = 1 << 16;
const MARKERS: u32 = 1 << 17;

/// A hosted sparse extent's header (`SparseExtentHeader`).
#[derive(Debug, Clone)]
struct Header {
    version: u32,
    flags: u32,
    /// Sectors.
    capacity: u64,
    /// Sectors.
    grain: u64,
    desc_off: u64,
    desc_size: u64,
    gtes: u32,
    gd: u64,
    unclean: bool,
    compress: u16,
}

fn header(b: &[u8; 512]) -> Option<Header> {
    b.starts_with(b"KDMV").then(|| Header {
        version: le32(b, 4),
        flags: le32(b, 8),
        capacity: le64(b, 12),
        grain: le64(b, 20),
        desc_off: le64(b, 28),
        desc_size: le64(b, 36),
        gtes: le32(b, 44),
        gd: le64(b, 56),
        unclean: b[72] != 0,
        compress: u16::from_le_bytes([b[77], b[78]]),
    })
}

/// A hosted sparse extent (`KDMV`): a grain directory of grain tables of grains.
struct Sparse {
    file: Handle,
    /// Its name, for messages.
    name: String,
    /// Bytes it holds: its capacity.
    len: u64,
    /// Bytes a grain.
    grain: u64,
    gd: Vec<u32>,
    zeroed: bool,
    compressed: bool,
    version: u32,
    unclean: bool,
    /// Grain tables, by their sector.
    tables: Cache,
    /// Decoded grains, by their sector.
    grains: Cache,
    dec: Decoders,
    src: Vec<u8>,
}

/// What a grain table entry says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grain {
    Hole,
    Zero,
    At(u32),
}

impl Sparse {
    /// The extent in `file` (`name`), and its header (for its embedded descriptor); a
    /// compressed grain may take `memory` bytes decoded.
    fn open(mut file: Handle, name: &str, memory: u64) -> Result<(Self, Header)> {
        let mut b = [0u8; 512];
        file.read_exact_at(0, &mut b, &format!("vmdk: {name}'s header"))?;
        let mut h = header(&b)
            .ok_or_else(|| Error::corrupt(format!("vmdk: {name} isn't a sparse extent")))?;
        if !(1..=3).contains(&h.version) {
            return Err(Error::unsupported(format!(
                "vmdk: {name} is a sparse extent of version {}; BeeZip reads 1 to 3",
                h.version
            )));
        }
        if h.gd == GD_AT_END {
            // VMware's stream-optimized layout: the footer, a copy of the header with the grain
            // directory's place, is the second-to-last sector, before the end-of-stream marker.
            let at = file
                .len
                .checked_sub(1024)
                .filter(|&at| at >= 512)
                .ok_or_else(|| {
                    Error::corrupt(format!(
                        "vmdk: {name} keeps its grain directory in a footer, and has none"
                    ))
                })?;
            let mut f = [0u8; 512];
            file.read_exact_at(at, &mut f, &format!("vmdk: {name}'s footer"))?;
            let foot = header(&f).ok_or_else(|| {
                Error::corrupt(format!(
                    "vmdk: {name} keeps its grain directory in a footer, and its end isn't one \
                     (was it cut short?)"
                ))
            })?;
            if foot.gd == GD_AT_END {
                return Err(Error::corrupt(format!(
                    "vmdk: {name}'s footer doesn't say where its grain directory is"
                )));
            }
            h.gd = foot.gd;
        }
        let compressed = h.flags & COMPRESSED != 0;
        if compressed != (h.flags & MARKERS != 0) {
            return Err(Error::unsupported(format!(
                "vmdk: {name}'s grains are {}",
                if compressed {
                    "compressed without markers"
                } else {
                    "behind markers, not compressed"
                }
            )));
        }
        if compressed && h.compress != 1 {
            return Err(Error::unsupported(format!(
                "vmdk: {name}'s grains are compressed with method {}; BeeZip reads deflate",
                h.compress
            )));
        }
        if h.grain == 0 || !h.grain.is_power_of_two() {
            return Err(Error::corrupt(format!(
                "vmdk: {name} has grains of {} sectors",
                h.grain
            )));
        }
        let grain = h.grain.saturating_mul(512);
        if grain > MAX_GRAIN {
            return Err(Error::unsupported(format!(
                "vmdk: {name} has grains of {grain} bytes; BeeZip reads them up to {MAX_GRAIN}"
            )));
        }
        if compressed && grain > memory {
            return Err(Error::limit(format!(
                "vmdk: {name}'s compressed grains of {grain} bytes need more memory than \
                 `decoder_memory` allows ({memory})"
            )));
        }
        if u64::from(h.gtes) != GTES {
            return Err(Error::unsupported(format!(
                "vmdk: {name} has grain tables of {} entries; BeeZip reads VMware's {GTES}",
                h.gtes
            )));
        }
        let len = h
            .capacity
            .checked_mul(512)
            .filter(|&l| l > 0)
            .ok_or_else(|| {
                Error::corrupt(format!(
                    "vmdk: {name} has a capacity of {} sectors",
                    h.capacity
                ))
            })?;
        let tables = h.capacity.div_ceil(h.grain).div_ceil(GTES);
        let at = h.gd.checked_mul(512).filter(|&at| at > 0).ok_or_else(|| {
            Error::corrupt(format!(
                "vmdk: {name}'s grain directory is at sector {}",
                h.gd
            ))
        })?;
        let raw = file.read_vec(
            at,
            tables.saturating_mul(4),
            MAX_GD,
            &format!("vmdk: {name}'s grain directory"),
        )?;
        let gd = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        Ok((
            Self {
                file,
                name: name.to_owned(),
                len,
                grain,
                gd,
                zeroed: h.flags & ZEROED != 0,
                compressed,
                version: h.version,
                unclean: h.unclean,
                tables: Cache::new(GT_CACHE),
                grains: Cache::new(
                    usize::try_from(GRAIN_BYTES / grain)
                        .unwrap_or(GRAIN_CACHE)
                        .clamp(1, GRAIN_CACHE),
                ),
                dec: Decoders::default(),
                src: Vec::new(),
            },
            h,
        ))
    }

    /// The grain table at sector `gde`, from the cache or the file.
    fn table<'a>(
        tables: &'a mut Cache,
        file: &mut Handle,
        name: &str,
        gde: u32,
    ) -> Result<&'a [u8]> {
        let key = u64::from(gde);
        if tables.get(key).is_none() {
            tables.fill(key, (GTES * 4) as usize, |out| {
                file.read_exact_at(
                    key * 512,
                    out,
                    &format!("vmdk: {name}'s grain table at sector {gde}"),
                )
            })?;
        }
        tables
            .get(key)
            .ok_or_else(|| Error::corrupt("vmdk: a grain table"))
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)> {
        let want = buf.len() as u64;
        let g = off / self.grain;
        let within = off % self.grain;
        let t = g / GTES;
        let first = g % GTES;
        let gde = *self
            .gd
            .get(usize::try_from(t).unwrap_or(usize::MAX))
            .ok_or_else(|| {
                Error::corrupt(format!("vmdk: {} past its grain directory", self.name))
            })?;
        if gde == 0 {
            let left = (GTES - first) * self.grain - within;
            return Ok((n(want.min(left)), Got::Hole));
        }
        let (zeroed, grain, sectors) = (self.zeroed, self.grain, self.grain / 512);
        let gt = Self::table(&mut self.tables, &mut self.file, &self.name, gde)?;
        let entry = |i: u64| le32(gt, (4 * i) as usize);
        let state = |e: u32| match e {
            0 => Grain::Hole,
            1 if zeroed => Grain::Zero,
            s => Grain::At(s),
        };
        // The grains of this table the read reaches.
        let last = GTES.min(first + (within + want).div_ceil(grain));
        let start = state(entry(first));
        let mut i = first + 1;
        match start {
            Grain::Hole | Grain::Zero => {
                while i < last && state(entry(i)) == start {
                    i += 1;
                }
                let got = if start == Grain::Hole {
                    Got::Hole
                } else {
                    Got::Zero
                };
                Ok((n(want.min((i - first) * grain - within)), got))
            }
            Grain::At(s) if !self.compressed => {
                // Grains stored one after another read in one go.
                while i < last && u64::from(entry(i)) == u64::from(s) + (i - first) * sectors {
                    i += 1;
                }
                let k = n(want.min((i - first) * grain - within));
                let at = u64::from(s) * 512 + within;
                self.file.read_exact_at(
                    at,
                    &mut buf[..k],
                    &format!("vmdk: {}'s grain", self.name),
                )?;
                Ok((k, Got::Data))
            }
            Grain::At(s) => {
                let k = n(want.min(grain - within));
                let data = self.inflated(g, s)?;
                let w = n(within);
                buf[..k].copy_from_slice(&data[w..w + k]);
                Ok((k, Got::Data))
            }
        }
    }

    /// Grain `g` of a stream-optimized extent, stored at sector `s` behind its marker, decoded.
    fn inflated(&mut self, g: u64, s: u32) -> Result<&[u8]> {
        let key = u64::from(s);
        if self.grains.get(key).is_none() {
            let what = format!("vmdk: {}'s grain at sector {s}", self.name);
            let mut m = [0u8; 12];
            self.file.read_exact_at(key * 512, &mut m, &what)?;
            let lba = le64(&m, 0);
            let size = u64::from(le32(&m, 8));
            if lba != g * (self.grain / 512) {
                return Err(Error::corrupt(format!(
                    "{what}: its marker says it's the grain at sector {lba}, not {}",
                    g * (self.grain / 512)
                )));
            }
            // The last grain may reach past the extent's end: only its bytes in it are kept.
            let full = n(self.grain.min(self.len - g * self.grain));
            if size == 0
                || size > 2 * self.grain + 512
                || key * 512 + 12 + size > self.file.len
                || (full as u64) > size.saturating_mul(DEFLATE_RATIO) + 1024
            {
                return Err(Error::corrupt(format!(
                    "{what}: a compressed grain of {size} bytes, for {full}"
                )));
            }
            self.src.resize(n(size), 0);
            self.file
                .read_exact_at(key * 512 + 12, &mut self.src, &what)?;
            let (src, dec) = (&self.src, &mut self.dec);
            // Only what's in the extent is kept: a read never goes past its end.
            self.grains
                .fill(key, full, |out| dec.inflate(src, out, true, &what))?;
        }
        self.grains
            .get(key)
            .ok_or_else(|| Error::corrupt("vmdk: a grain"))
    }

    /// Bytes of `start..start + len` in grains the extent holds (compressed ones too): the
    /// grain tables are read as needed. One that can't be read counts as held.
    fn held(&mut self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len).min(self.len);
        if start >= end {
            return 0;
        }
        let span = GTES * self.grain;
        let overlap = |a: u64, b: u64| b.min(end).saturating_sub(a.max(start));
        let mut held = 0u64;
        let mut t = start / span;
        while t * span < end {
            let Some(&gde) = self.gd.get(usize::try_from(t).unwrap_or(usize::MAX)) else {
                break;
            };
            if gde != 0 {
                let base = t * span;
                match Self::table(&mut self.tables, &mut self.file, &self.name, gde) {
                    Err(_) => held += overlap(base, base + span),
                    Ok(gt) => {
                        let from = (start.max(base) - base) / self.grain;
                        for i in from..GTES {
                            let a = base + i * self.grain;
                            if a >= end {
                                break;
                            }
                            let e = le32(gt, (4 * i) as usize);
                            if e != 0 && !(e == 1 && self.zeroed) {
                                held += overlap(a, a + self.grain);
                            }
                        }
                    }
                }
            }
            t += 1;
        }
        held
    }
}

/// `x` as a buffer length: every caller has bounded it by one.
fn n(x: u64) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

/// How an extent may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    ReadWrite,
    ReadOnly,
    None,
}

/// One extent line of a descriptor.
#[derive(Debug, Clone)]
struct Line {
    access: Access,
    sectors: u64,
    kind: String,
    name: Option<String>,
    /// Sectors into a FLAT extent's file.
    offset: u64,
}

/// What BeeZip reads of a descriptor.
#[derive(Debug, Default, Clone)]
struct Desc {
    cid: Option<u32>,
    /// `None` when it's `ffffffff`: no parent.
    parent_cid: Option<u32>,
    create_type: Option<String>,
    parent_hint: Option<String>,
    extents: Vec<Line>,
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
}

/// Whether a descriptor declares an encoding whose bytes are Latin-1's (as near as matters for
/// file names): `windows-1252` and its kin, ISO-8859.
fn latin1(raw: &[u8]) -> bool {
    raw.split(|&c| c == b'\n').any(|line| {
        let l = String::from_utf8_lossy(line);
        let Some((k, v)) = l.split_once('=') else {
            return false;
        };
        let v = unquote(v).to_ascii_lowercase();
        k.trim().eq_ignore_ascii_case("encoding")
            && (v.starts_with("windows-125") || v.starts_with("iso-8859") || v == "latin1")
    })
}

/// The descriptor in `raw` (see the module's notes).
fn parse(raw: &[u8]) -> Result<Desc> {
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    let raw = &raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())];
    let latin1 = latin1(raw);
    let bad = |what: &str| Error::corrupt(format!("vmdk: the descriptor's {what}"));
    let mut d = Desc::default();
    for line in raw.split(|&c| c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text: Cow<'_, str> = if latin1 {
            Cow::Owned(line.iter().map(|&c| char::from(c)).collect())
        } else {
            String::from_utf8_lossy(line)
        };
        // Replacement characters: a line that isn't UTF-8.
        let garbled = !latin1 && matches!(text, Cow::Owned(_));
        let t = text.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let first = t.split_whitespace().next().unwrap_or("");
        let access = match first.to_ascii_uppercase().as_str() {
            "RW" => Some(Access::ReadWrite),
            "RDONLY" => Some(Access::ReadOnly),
            "NOACCESS" => Some(Access::None),
            _ => None,
        };
        if let Some(access) = access {
            if garbled {
                return Err(bad("extent line that isn't UTF-8"));
            }
            d.extents.push(extent_line(t, first.len(), access)?);
            if d.extents.len() > files::MAX_FILES {
                return Err(Error::limit(format!(
                    "vmdk: a descriptor of more than {} extents",
                    files::MAX_FILES
                )));
            }
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), unquote(v));
        let hex = |v: &str, what: &str| {
            u32::from_str_radix(v, 16).map_err(|_| bad(&format!("{what} `{v}`")))
        };
        if garbled && matches!(k, "CID" | "parentCID" | "parentFileNameHint" | "createType") {
            return Err(bad(&format!("{k} that isn't UTF-8")));
        }
        match k {
            "CID" => d.cid = Some(hex(v, "CID")?),
            "parentCID" => d.parent_cid = Some(hex(v, "parentCID")?).filter(|&c| c != u32::MAX),
            "createType" => d.create_type = Some(v.to_owned()),
            "parentFileNameHint" => d.parent_hint = Some(v.to_owned()).filter(|v| !v.is_empty()),
            _ => {}
        }
    }
    if d.extents.is_empty() {
        return Err(bad("extents: there are none"));
    }
    Ok(d)
}

/// An extent line, `ACCESS SECTORS TYPE ["NAME" [OFFSET]]`, whose access word is `skip` bytes.
fn extent_line(t: &str, skip: usize, access: Access) -> Result<Line> {
    let bad = || Error::corrupt(format!("vmdk: the descriptor's extent line `{t}`"));
    let rest = t[skip..].trim_start();
    let (sectors, rest) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let sectors: u64 = sectors.parse().map_err(|_| bad())?;
    let rest = rest.trim_start();
    let (kind, rest) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    if kind.is_empty() {
        return Err(bad());
    }
    let rest = rest.trim();
    let (name, offset) = match rest.strip_prefix('"') {
        Some(r) => {
            let q = r.find('"').ok_or_else(bad)?;
            let off = r[q + 1..].trim();
            let off = if off.is_empty() {
                0
            } else {
                off.parse().map_err(|_| bad())?
            };
            (Some(r[..q].to_owned()), off)
        }
        None if rest.is_empty() => (None, 0),
        None => return Err(bad()),
    };
    Ok(Line {
        access,
        sectors,
        kind: kind.to_ascii_uppercase(),
        name,
        offset,
    })
}

/// Why an extent of type `kind` isn't read.
fn refused(kind: &str) -> Error {
    Error::unsupported(match kind {
        "VMFSSPARSE" => {
            "vmdk: an ESXi vmfsSparse (COWD) snapshot extent; BeeZip doesn't read them".to_owned()
        }
        "SESPARSE" => "vmdk: an ESXi seSparse snapshot extent; BeeZip doesn't read them".to_owned(),
        "VMFSRDM" | "VMFSRDMP" => {
            "vmdk: a raw device map, whose data is a physical drive's".to_owned()
        }
        k => format!("vmdk: an extent of type {k}, which BeeZip doesn't read"),
    })
}

/// What an extent reads from.
enum Data {
    /// A file at a byte offset, by index into [`Vmdk::flats`].
    Flat { file: usize, offset: u64 },
    /// Zeros: a ZERO or NOACCESS extent.
    Zero,
    /// A hosted sparse extent, read when its holdings are asked for too.
    Sparse(Box<RefCell<Sparse>>),
}

struct Extent {
    start: u64,
    len: u64,
    data: Data,
}

/// One VMDK: its descriptor's extents, read as one level.
pub struct Vmdk {
    len: u64,
    extents: Vec<Extent>,
    flats: Vec<Handle>,
    create_type: String,
    cid: Option<u32>,
    parent_cid: Option<u32>,
    /// Bytes a grain, of the first sparse extent.
    grain: Option<u64>,
    version: Option<u32>,
    stream: bool,
    unclean: bool,
    file_bytes: u64,
}

/// The descriptor in `file`, a VMDK: embedded in its sparse header `h`, or the file itself. A
/// bare sparse extent has none.
fn descriptor(file: &mut Handle, h: Option<&Header>) -> Result<Option<Desc>> {
    match h {
        Some(h) if h.desc_off == 0 || h.desc_size == 0 => Ok(None),
        Some(h) => {
            let at = h.desc_off.checked_mul(512);
            let len = h.desc_size.checked_mul(512);
            let (Some(at), Some(len)) = (at, len) else {
                return Err(Error::corrupt("vmdk: the embedded descriptor's place"));
            };
            let raw = file.read_vec(at, len, MAX_DESCRIPTOR, "vmdk: the embedded descriptor")?;
            parse(&raw).map(Some)
        }
        None => {
            let raw = file.read_vec(0, file.len, MAX_DESCRIPTOR, "vmdk: the descriptor")?;
            parse(&raw).map(Some)
        }
    }
}

impl Vmdk {
    /// The VMDK in `file` (at `origin`), its extents found by `files`; and its parent's CID and
    /// name when it's a child disk.
    fn open(
        mut file: Handle,
        origin: &Origin,
        files: &mut Files,
    ) -> Result<(Self, Option<(u32, String)>)> {
        let mut head = [0u8; 4];
        file.read_exact_at(0, &mut head, "vmdk: the header")?;
        let mut v = Vmdk {
            len: 0,
            extents: Vec::new(),
            flats: Vec::new(),
            create_type: String::new(),
            cid: None,
            parent_cid: None,
            grain: None,
            version: None,
            stream: false,
            unclean: false,
            file_bytes: file.len,
        };
        let (desc, own) = match &head {
            b"KDMV" => {
                let (mut sp, h) = Sparse::open(file, &origin.name, files.memory)?;
                let desc = descriptor(&mut sp.file, Some(&h))?;
                (desc, Some(sp))
            }
            b"COWD" => return Err(refused("VMFSSPARSE")),
            _ => (descriptor(&mut file, None)?, None),
        };
        let Some(desc) = desc else {
            // A bare sparse extent: no descriptor, no parent.
            let sp = own.ok_or_else(|| Error::corrupt("vmdk: no descriptor"))?;
            v.create_type = "sparse extent".into();
            v.len = sp.len;
            v.note_sparse(&sp);
            v.extents.push(Extent {
                start: 0,
                len: sp.len,
                data: Data::Sparse(Box::new(RefCell::new(sp))),
            });
            return Ok((v, None));
        };
        v.cid = desc.cid;
        v.parent_cid = desc.parent_cid;
        v.create_type = desc.create_type.clone().unwrap_or_default();
        let parent = match (desc.parent_cid, &desc.parent_hint) {
            (Some(pc), Some(hint)) => Some((pc, hint.clone())),
            (Some(pc), None) => {
                return Err(Error::corrupt(format!(
                    "vmdk: a child disk (its parent's CID is {pc:08x}) that doesn't name its \
                     parent"
                )));
            }
            (None, _) => None,
        };
        let mut own = own;
        if own.is_some() && (desc.extents.len() != 1 || desc.extents[0].kind != "SPARSE") {
            return Err(Error::unsupported(
                "vmdk: a sparse extent whose embedded descriptor names other extents",
            ));
        }
        let mut flat_names: HashMap<String, usize> = HashMap::new();
        let mut start = 0u64;
        for line in &desc.extents {
            let len = line
                .sectors
                .checked_mul(512)
                .filter(|&l| l > 0)
                .ok_or_else(|| {
                    Error::corrupt(format!("vmdk: an extent of {} sectors", line.sectors))
                })?;
            let data = v.extent(line, len, &mut own, &mut flat_names, origin, files)?;
            v.extents.push(Extent { start, len, data });
            start = start
                .checked_add(len)
                .ok_or_else(|| Error::corrupt("vmdk: extents adding up past 2^64 bytes"))?;
        }
        v.len = start;
        Ok((v, parent))
    }

    /// What extent `line`, `len` bytes, reads from: the opened file's own sparse extent
    /// (`own`), or a file `files` finds.
    fn extent(
        &mut self,
        line: &Line,
        len: u64,
        own: &mut Option<Sparse>,
        flat_names: &mut HashMap<String, usize>,
        origin: &Origin,
        files: &mut Files,
    ) -> Result<Data> {
        if line.access == Access::None || line.kind == "ZERO" {
            return Ok(Data::Zero);
        }
        if let Some(sp) = own.take() {
            if len > sp.len {
                return Err(Error::corrupt(format!(
                    "vmdk: an extent of {len} bytes in a sparse extent of {}",
                    sp.len
                )));
            }
            self.note_sparse(&sp);
            return Ok(Data::Sparse(Box::new(RefCell::new(sp))));
        }
        let name = line
            .name
            .as_deref()
            .ok_or_else(|| Error::corrupt(format!("vmdk: a {} extent with no file", line.kind)))?;
        if let Some(why) = files::never(name) {
            return Err(Error::new(
                ErrorKind::Unsafe,
                format!(
                    "vmdk: the extent `{name}` named by {} is never opened: {why}",
                    origin.name
                ),
            ));
        }
        let what = format!("the extent `{name}`");
        match line.kind.as_str() {
            "SPARSE" => {
                let memory = files.memory;
                let (sp, _) = files.find(origin, &[name], false, false, &what, |_, h, o| {
                    Sparse::open(h, &o.name, memory).map(Ok)
                })?;
                if len > sp.len {
                    return Err(Error::corrupt(format!(
                        "vmdk: an extent of {len} bytes in {name}, a sparse extent of {}",
                        sp.len
                    )));
                }
                self.file_bytes = self.file_bytes.saturating_add(sp.file.len);
                self.note_sparse(&sp);
                Ok(Data::Sparse(Box::new(RefCell::new(sp))))
            }
            // ESXi's VMFSRAW is a flat file of the disk, as 7-Zip reads it.
            "FLAT" | "VMFS" | "VMFSRAW" => {
                let offset = line
                    .offset
                    .checked_mul(512)
                    .ok_or_else(|| Error::corrupt(format!("vmdk: the offset of `{name}`")))?;
                let file = match flat_names.get(name) {
                    Some(&i) => i,
                    None => {
                        let h = files
                            .find(origin, &[name], false, false, &what, |_, h, _| Ok(Ok(h)))?;
                        self.file_bytes = self.file_bytes.saturating_add(h.len);
                        self.flats.push(h);
                        flat_names.insert(name.to_owned(), self.flats.len() - 1);
                        self.flats.len() - 1
                    }
                };
                Ok(Data::Flat { file, offset })
            }
            k => Err(refused(k)),
        }
    }

    /// Records what Info shows of a sparse extent: the first one's grain and version.
    fn note_sparse(&mut self, sp: &Sparse) {
        if self.grain.is_none() {
            self.grain = Some(sp.grain);
            self.version = Some(sp.version);
        }
        self.stream |= sp.compressed;
        self.unclean |= sp.unclean;
    }
}

impl Layer for Vmdk {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)> {
        let i = self.extents.partition_point(|e| e.start + e.len <= off);
        let e = self
            .extents
            .get_mut(i)
            .ok_or_else(|| Error::corrupt("vmdk: a read past the last extent"))?;
        let rel = off - e.start;
        let k = buf.len().min(n(e.len - rel));
        match &mut e.data {
            Data::Zero => Ok((k, Got::Zero)),
            Data::Flat { file, offset } => {
                let f = self
                    .flats
                    .get_mut(*file)
                    .ok_or_else(|| Error::corrupt("vmdk: a flat extent"))?;
                let at = offset
                    .checked_add(rel)
                    .ok_or_else(|| Error::corrupt("vmdk: a flat extent's offset"))?;
                f.read_exact_at(at, &mut buf[..k], "vmdk: a flat extent")?;
                Ok((k, Got::Data))
            }
            Data::Sparse(s) => s.get_mut().read_at(rel, &mut buf[..k]),
        }
    }

    fn held_in(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len).min(self.len);
        let mut held = 0u64;
        for e in &self.extents {
            let (a, b) = (start.max(e.start), end.min(e.start + e.len));
            if a >= b {
                continue;
            }
            let (rel, span) = (a - e.start, b - a);
            held = held.saturating_add(match &e.data {
                Data::Zero => 0,
                Data::Flat { file, offset } => {
                    let have = self.flats.get(*file).map_or(0, |f| f.len);
                    have.saturating_sub(offset.saturating_add(rel)).min(span)
                }
                Data::Sparse(s) => match s.try_borrow_mut() {
                    Ok(mut s) => s.held(rel, span),
                    Err(_) => span,
                },
            });
        }
        held
    }

    fn file_bytes(&self) -> u64 {
        self.file_bytes
    }

    fn properties(&self, out: &mut Vec<(&'static str, String)>) {
        out.push(("Method", self.create_type.clone()));
        if let Some(g) = self.grain {
            out.push(("Cluster Size", g.to_string()));
        }
        if let Some(c) = self.cid {
            out.push(("ID", format!("{c:08x}")));
        }
        if let Some(c) = self.parent_cid {
            out.push(("Parent ID", format!("{c:08x}")));
        }
        if self.extents.len() > 1 {
            out.push(("Extents", self.extents.len().to_string()));
        }
        if let Some(v) = self.version {
            out.push(("Version", v.to_string()));
        }
        if self.stream {
            out.push(("Compression", "deflate".into()));
        }
    }

    fn notes(&self, out: &mut Vec<String>) {
        if self.unclean {
            out.push(
                "the VMDK wasn't closed cleanly (its unclean-shutdown flag is set); it's read as \
                 it is"
                    .into(),
            );
        }
    }
}

/// The CID a candidate parent records, or why it isn't one.
fn cid_of(h: &mut Handle) -> std::result::Result<u32, String> {
    let mut head = vec![0u8; n(h.len.min(512))];
    h.read_exact_at(0, &mut head, "vmdk: a parent's header")
        .map_err(|e| e.message)?;
    if super::sniff(&head) != Some(External::Vmdk) {
        return Err("it isn't a VMDK".into());
    }
    let sparse = match head.get(..512).and_then(|b| <&[u8; 512]>::try_from(b).ok()) {
        Some(b) if b.starts_with(b"KDMV") => header(b),
        _ => None,
    };
    let desc = descriptor(h, sparse.as_ref())
        .map_err(|e| format!("its descriptor can't be read ({})", e.message))?;
    desc.and_then(|d| d.cid)
        .ok_or_else(|| "it records no CID".to_owned())
}

/// The levels of the VMDK `file` is, its parents' below it.
pub fn layers(file: Handle, origin: Origin, files: &mut Files) -> Result<Vec<Box<dyn Layer>>> {
    let (v, parent) = Vmdk::open(file, &origin, files)?;
    let mut out: Vec<Box<dyn Layer>> = vec![Box::new(v)];
    if let Some((pcid, hint)) = parent {
        let below = files.find(
            &origin,
            &[hint.as_str()],
            true,
            true,
            "the parent disk",
            |files, mut h, o| {
                match cid_of(&mut h) {
                    Err(why) => return Ok(Err(why)),
                    Ok(cid) if cid != pcid => {
                        return Ok(Err(format!(
                            "its CID is {cid:08x}, not {pcid:08x}: it changed after this disk \
                             was made"
                        )));
                    }
                    Ok(_) => {}
                }
                super::layers(Some(External::Vmdk), h, o, files).map(Ok)
            },
        )?;
        out.extend(below);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::testing::{self, copy_into, digest, digest_of, dir, error_of, open_path};
    use super::{le64, parse};
    use crate::{ErrorKind, backend::External};

    /// Sets `key` in the descriptor of the VMDK at `path`, embedded in its sparse header or not.
    fn set_key(path: &Path, key: &str, value: &str) {
        let mut data = std::fs::read(path).unwrap();
        let sparse = data.starts_with(b"KDMV");
        let (a, b) = if sparse {
            let at = le64(&data, 28) as usize * 512;
            (at, at + le64(&data, 36) as usize * 512)
        } else {
            (0, data.len())
        };
        let text: Vec<u8> = data[a..b].iter().copied().take_while(|&c| c != 0).collect();
        let text = String::from_utf8(text).unwrap();
        let mut found = false;
        let lines: Vec<String> = text
            .lines()
            .map(|l| {
                if l.starts_with(&format!("{key}=")) {
                    found = true;
                    format!("{key}={value}")
                } else {
                    l.to_owned()
                }
            })
            .collect();
        assert!(found, "no {key} in {}", path.display());
        let new = lines.join("\n") + "\n";
        if sparse {
            assert!(new.len() <= b - a);
            data[a..b].fill(0);
            data[a..a + new.len()].copy_from_slice(new.as_bytes());
        } else {
            data = new.into_bytes();
        }
        std::fs::write(path, data).unwrap();
    }

    #[test]
    fn every_vmdk_fixture_reads_as_expected() {
        testing::check_all(&[".vmdk"]);
    }

    #[test]
    fn a_parent_is_found_at_its_absolute_path_or_by_its_name_beside() {
        let tmp = tempfile::tempdir().unwrap();
        copy_into(
            tmp.path(),
            &[
                ("v-sparse.vmdk", "base/v-sparse.vmdk"),
                ("v-child.vmdk", "kids/v-child.vmdk"),
            ],
        );
        let base = tmp.path().join("base").join("v-sparse.vmdk");
        let child = tmp.path().join("kids").join("v-child.vmdk");
        let reads = |hint: &str| {
            set_key(&child, "parentFileNameHint", &format!("\"{hint}\""));
            let mut d = open_path(External::Vmdk, &child).unwrap();
            assert_eq!(d.depth(), 2, "{hint}");
            assert_eq!(digest(&mut d).unwrap(), digest_of("v-child.vmdk"), "{hint}");
        };
        // The absolute path as recorded, on a local drive (rule 3).
        reads(&base.display().to_string());
        // A relative path up and across (rule 1).
        reads("../base/v-sparse.vmdk");
        // Paths from other machines, by their names beside the child (rule 2).
        std::fs::rename(&base, tmp.path().join("kids").join("v-sparse.vmdk")).unwrap();
        reads("/vmfs/volumes/datastore1/vm/v-sparse.vmdk");
        reads(r"Q:\VMs\vm\v-sparse.vmdk");
    }

    #[test]
    fn a_changed_parent_is_not_found_and_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        copy_into(
            tmp.path(),
            &[
                ("v-sparse.vmdk", "v-sparse.vmdk"),
                ("v-child.vmdk", "v-child.vmdk"),
            ],
        );
        set_key(&tmp.path().join("v-sparse.vmdk"), "CID", "1a2b3c4d");
        let e = error_of(External::Vmdk, &tmp.path().join("v-child.vmdk"));
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(
            e.message
                .contains("its CID is 1a2b3c4d, not 6d7a0001: it changed after this disk was made"),
            "{e}"
        );
    }

    #[test]
    fn a_missing_parent_or_extent_names_where_it_was_looked_for() {
        let tmp = tempfile::tempdir().unwrap();
        copy_into(
            tmp.path(),
            &[
                ("v-child.vmdk", "v-child.vmdk"),
                ("v-2gs.vmdk", "v-2gs.vmdk"),
            ],
        );
        let e = error_of(External::Vmdk, &tmp.path().join("v-child.vmdk"));
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        let beside = tmp.path().join("v-sparse.vmdk");
        assert!(
            e.message
                .contains("the parent disk named by v-child.vmdk isn't found")
                && e.message
                    .contains(&format!("{} (its relative path", beside.display())),
            "{e}"
        );
        let e = error_of(External::Vmdk, &tmp.path().join("v-2gs.vmdk"));
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(
            e.message
                .contains("the extent `v-2gs-s001.vmdk` named by v-2gs.vmdk"),
            "{e}"
        );
    }

    #[test]
    fn devices_and_other_machines_are_never_opened() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("d.vmdk");
        for name in [
            r"\\.\PhysicalDrive0",
            "/dev/sda",
            r"\\server\share\d-flat.vmdk",
            "//server/share/d-flat.vmdk",
            "nbd://localhost:10809/d",
        ] {
            std::fs::write(
                &path,
                format!(
                    "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\n\
                     createType=\"fullDevice\"\nRW 4096 FLAT \"{name}\" 0\n"
                ),
            )
            .unwrap();
            let e = error_of(External::Vmdk, &path);
            assert_eq!(e.kind, ErrorKind::Unsafe, "{name}: {e}");
        }
    }

    #[test]
    fn descriptors_in_latin1_and_their_damage() {
        let d = parse(
            b"# Disk DescriptorFile\nencoding=\"windows-1252\"\nCID=00000001\n\
              parentCID=ffffffff\nRW 8 FLAT \"caf\xE9-flat.vmdk\" 0\n",
        )
        .unwrap();
        assert_eq!(d.extents[0].name.as_deref(), Some("caf\u{e9}-flat.vmdk"));
        assert_eq!(d.parent_cid, None);
        // Not UTF-8, with no encoding saying so: an extent line can't be read.
        let e = parse(b"CID=00000001\nRW 8 FLAT \"caf\xE9.vmdk\" 0\n").unwrap_err();
        assert_eq!(e.kind, ErrorKind::Corrupt);
        // A comment that isn't UTF-8 doesn't matter.
        assert!(parse(b"# caf\xE9\nRW 8 ZERO\n").is_ok());
        for bad in [
            &b"RW eight FLAT \"x\" 0\n"[..],
            b"RW 8 FLAT \"x 0\n",
            b"CID=xyz\nRW 8 ZERO\n",
            b"CID=00000001\n",
        ] {
            assert_eq!(parse(bad).unwrap_err().kind, ErrorKind::Corrupt);
        }
    }

    #[test]
    fn holdings_are_exact() {
        let d = open_path(External::Vmdk, &dir().join("v-sparse.vmdk")).unwrap();
        // disk.img's 64 KiB grains 0, 1 and 3 hold something; grain 2 is zeros.
        assert_eq!(d.held_in(0, d.len()), 3 << 16);
        assert_eq!(d.held_in(2 << 16, 1 << 16), 0);
        assert_eq!(
            d.held_in(100_000, 100_000),
            (128 << 10) - 100_000 + 200_000 - (192 << 10)
        );
        // A zeroed grain isn't held.
        let d = open_path(External::Vmdk, &dir().join("v-zg.vmdk")).unwrap();
        assert_eq!(d.held_in(2 << 16, 1 << 16), 0);
        // Compressed grains are, whole; ZERO and NOACCESS extents aren't.
        let d = open_path(External::Vmdk, &dir().join("v-stream.vmdk")).unwrap();
        assert_eq!(d.held_in(0, d.len()), 3 << 16);
        let d = open_path(External::Vmdk, &dir().join("v-multi.vmdk")).unwrap();
        assert_eq!(d.held_in(3 * 512, 60 * 512), 0);
        assert_eq!(d.held_in(63 * 512, 193 * 512), 193 * 512);
        testing::holdings_never_low(&[".vmdk"]);
    }

    #[test]
    fn info_gives_its_type_cid_and_parents() {
        let props = |f: &str| {
            open_path(External::Vmdk, &dir().join(f))
                .unwrap()
                .properties()
        };
        let has = |p: &[(&str, String)], k: &str, v: &str| {
            assert!(
                p.iter().any(|(a, b)| *a == k && b == v),
                "{k} = {v} in {p:?}"
            );
        };
        let p = props("v-stream.vmdk");
        has(&p, "Method", "streamOptimized");
        has(&p, "Compression", "deflate");
        has(&p, "Cluster Size", "65536");
        has(&p, "ID", "6d7a0007");
        let p = props("v-vmware.vmdk");
        has(&p, "Version", "3");
        has(&p, "Compression", "deflate");
        let p = props("v-gchild.vmdk");
        has(&p, "Parent ID", "6d7a0008");
        has(&p, "Parent", "v-child.vmdk > v-sparse.vmdk");
        let p = props("v-multi.vmdk");
        has(&p, "Method", "custom");
        has(&p, "Extents", "6");
        let p = props("v-bare.vmdk");
        has(&p, "Method", "sparse extent");
        has(&p, "Cluster Size", "4096");
        // Every file read counts, extents included, each once.
        let sizes = |fs: &[&str]| -> u64 {
            fs.iter()
                .map(|f| std::fs::metadata(dir().join(f)).unwrap().len())
                .sum()
        };
        let bytes = |f: &str| {
            open_path(External::Vmdk, &dir().join(f))
                .unwrap()
                .file_bytes()
        };
        assert_eq!(
            bytes("v-2gs.vmdk"),
            sizes(&["v-2gs.vmdk", "v-2gs-s001.vmdk"])
        );
        assert_eq!(
            bytes("v-multi.vmdk"),
            sizes(&[
                "v-multi.vmdk",
                "v-multi-a.bin",
                "v-multi-b.bin",
                "v-multi-c.vmdk"
            ])
        );
        assert_eq!(
            bytes("v-child.vmdk"),
            sizes(&["v-child.vmdk", "v-sparse.vmdk"])
        );
    }

    #[test]
    fn mutated_vmdks_never_panic() {
        testing::mutations(&[".vmdk"], 24, 0x5EED_0001);
    }
}
