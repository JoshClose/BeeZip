//! QCOW2, versions 2 and 3, from qemu's format description (`docs/interop/qcow2.txt`,
//! docs/M8.md §3.4): an L1 table of L2 tables mapping the disk's clusters; and QCOW version 1
//! (qemu's `block/qcow.c`, docs/M11.md §6.1), whose tables map clusters the same way.
//!
//! - **Read:** the active L1 table (internal snapshots are counted in Info, not read); clusters
//!   of 512 bytes to 2 MiB, any refcount width (refcounts aren't needed to read); standard, zero
//!   and unallocated clusters, the zero ones never read at the offset they may keep; clusters
//!   compressed with deflate or zstd; extended L2 entries (32 subclusters each allocated, zero,
//!   or the backing file's); an external data file; the dirty and corrupt bits, which Info notes.
//! - **Backing files** of QCOW2, raw, VMDK, VDI, VHD or VHDX: the format the header's extension
//!   records, else the one the file's extension says, else what its first bytes are. One shorter
//!   than the disk reads zeros past its end. QCOW2 records no identity for it, so it's looked for
//!   by its relative path and by its name beside the image only ([`Files`]), never at an absolute
//!   path; a name that isn't a file (`json:{…}`, `nbd://`, a UNC path) is `Unsafe`.
//! - **Version 1:** a 48-byte header, L2 tables of `2^l2_bits` entries, a compressed cluster
//!   marked by bit 63 with its length in the bits above `63 - cluster_bits`, and a backing file
//!   by name, plain, compressed or a child alike.
//! - **Refused** (`UnsupportedOperation`): encryption, AES or LUKS ("BeeZip doesn't decrypt disk
//!   images"); incompatible feature bits or compression types BeeZip doesn't know.
//! - **Memory:** the L1 table is read only when the file holds it (at most [`MAX_L1`], as qemu
//!   caps it); L2 tables and decoded clusters are cached a few at a time.

use std::cell::RefCell;

use super::{Cache, Decoders, Files, Got, Handle, Layer, Origin, be32, be64};
use crate::{Error, ErrorKind, Result, backend::External};

/// The largest L1 table read, qemu's own cap.
const MAX_L1: u64 = 32 << 20;
/// L2 tables kept in memory, in bytes (at least [`MIN_L2S`] tables).
const L2_CACHE: u64 = 16 << 20;
const MIN_L2S: u64 = 8;
/// Decoded clusters kept in memory.
const CLUSTER_CACHE: usize = 4;
/// Bits 9 to 55 of a table entry: a host offset.
const OFFSET: u64 = 0x00FF_FFFF_FFFF_FE00;
const COPIED: u64 = 1 << 63;
const COMPRESSED: u64 = 1 << 62;
/// A standard cluster descriptor's "reads as zeros" bit (version 3).
const ZERO: u64 = 1;
/// Incompatible feature bits.
const DIRTY: u64 = 1 << 0;
const CORRUPT: u64 = 1 << 1;
const DATA_FILE: u64 = 1 << 2;
const COMPRESSION_TYPE: u64 = 1 << 3;
const EXTENDED_L2: u64 = 1 << 4;
const KNOWN: u64 = 0b1_1111;
/// Autoclear bit: the data file is a raw image of the disk.
const DATA_FILE_RAW: u64 = 1 << 1;
/// Header extension types.
const EXT_END: u32 = 0;
const EXT_BACKING_FORMAT: u32 = 0xE279_2ACA;
const EXT_DATA_FILE: u32 = 0x4441_5441;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Codec {
    Deflate,
    Zstd,
}

/// What reads the image's files: kept apart so that [`Layer::held_in`] can read L2 tables too.
struct Io {
    file: Handle,
    /// The external data file: standard clusters' offsets are into it.
    data: Option<Handle>,
    /// L2 tables, by their offset.
    tables: Cache,
    /// Decoded clusters, by their offset.
    clusters: Cache,
    dec: Decoders,
    src: Vec<u8>,
}

/// One QCOW2 image.
pub struct Qcow2 {
    len: u64,
    bits: u32,
    cluster: u64,
    /// Entries in an L2 table.
    l2_entries: u64,
    extended: bool,
    l1: Vec<u64>,
    codec: Codec,
    v3: bool,
    io: RefCell<Io>,
    version: u32,
    backing: Option<String>,
    backing_format: Option<String>,
    data_name: Option<String>,
    data_raw: bool,
    snapshots: u32,
    refcount_bits: u32,
    dirty: bool,
    corrupt: bool,
    file_bytes: u64,
    /// A QCOW version 1 image (qemu's `block/qcow.c`, docs/M11.md §6.1).
    v1: bool,
    /// An L2 table's bytes: a cluster in QCOW2, `2^l2_bits` entries in version 1.
    l2_bytes: u64,
}

/// What an L2 entry maps a cluster (or subcluster) to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Map {
    /// Not in this image: the backing file's, or zeros.
    Hole,
    Zero,
    /// At this offset of the image's file, or its data file.
    At(u64),
    /// A compressed cluster: its L2 entry.
    Packed(u64),
}

fn n(x: u64) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

impl Qcow2 {
    /// The image in `file` (at `origin`), its data file found by `files`.
    fn open(mut file: Handle, origin: &Origin, files: &mut Files) -> Result<Self> {
        let mut h = [0u8; 112];
        let got = file.read_upto(0, &mut h, "qcow2: the header")?;
        if got < 72 || !h.starts_with(b"QFI\xFB") {
            return Err(Error::corrupt("qcow2: no QCOW2 header"));
        }
        let version = be32(&h, 4);
        match version {
            1 => return Self::open_v1(file, &h, got),
            2 | 3 => {}
            v => {
                return Err(Error::unsupported(format!(
                    "qcow2: version {v}; BeeZip reads 2 and 3"
                )));
            }
        }
        let bits = be32(&h, 20);
        if !(9..=21).contains(&bits) {
            return Err(Error::corrupt(format!(
                "qcow2: clusters of 2^{bits} bytes (2^9 to 2^21 are valid)"
            )));
        }
        let cluster = 1u64 << bits;
        match be32(&h, 32) {
            0 => {}
            1 => {
                return Err(Error::unsupported(
                    "qcow2: encrypted with AES; BeeZip doesn't decrypt disk images",
                ));
            }
            2 => {
                return Err(Error::unsupported(
                    "qcow2: encrypted with LUKS; BeeZip doesn't decrypt disk images",
                ));
            }
            m => {
                return Err(Error::unsupported(format!(
                    "qcow2: encrypted (method {m}); BeeZip doesn't decrypt disk images"
                )));
            }
        }
        // The header's cluster: its extensions and the backing file's name are in it.
        let head = file.read_vec(0, cluster.min(file.len), cluster, "qcow2: the header")?;
        let (mut incompat, mut autoclear, mut header_len, mut ctype) = (0u64, 0u64, 72u64, 0u8);
        let mut refcount_bits = 16;
        if version == 3 {
            if got < 104 {
                return Err(Error::corrupt("qcow2: the file is shorter than its header"));
            }
            incompat = be64(&h, 72);
            autoclear = be64(&h, 88);
            let order = be32(&h, 96);
            if order > 6 {
                return Err(Error::corrupt(format!(
                    "qcow2: refcounts of 2^{order} bits"
                )));
            }
            refcount_bits = 1 << order;
            header_len = u64::from(be32(&h, 100));
            if header_len < 104 || header_len > head.len() as u64 {
                return Err(Error::corrupt(format!(
                    "qcow2: a header of {header_len} bytes"
                )));
            }
            if header_len > 104 {
                ctype = h[104];
            }
        }
        if incompat & !KNOWN != 0 {
            return Err(Error::unsupported(format!(
                "qcow2: incompatible features BeeZip doesn't know ({:#x})",
                incompat & !KNOWN
            )));
        }
        let codec = match (incompat & COMPRESSION_TYPE != 0, ctype) {
            (false, _) | (true, 0) => Codec::Deflate,
            (true, 1) => Codec::Zstd,
            (true, t) => {
                return Err(Error::unsupported(format!(
                    "qcow2: compression type {t}; BeeZip reads deflate and zstd"
                )));
            }
        };
        let extended = incompat & EXTENDED_L2 != 0;
        if extended && bits < 14 {
            return Err(Error::corrupt(
                "qcow2: extended L2 entries in clusters under 16 KiB",
            ));
        }
        let entry = if extended { 16 } else { 8 };
        let l2_entries = cluster / entry;
        let size = be64(&h, 24);
        let per_l1 = cluster * l2_entries;
        let needed = size.div_ceil(per_l1);
        let l1_size = u64::from(be32(&h, 36));
        let l1_off = be64(&h, 40);
        if l1_size < needed {
            return Err(Error::corrupt(format!(
                "qcow2: an L1 table of {l1_size} entries can't map {size} bytes"
            )));
        }
        if needed > 0 && (l1_off == 0 || !l1_off.is_multiple_of(cluster)) {
            return Err(Error::corrupt(format!(
                "qcow2: an L1 table at {l1_off}, not on a cluster"
            )));
        }
        let raw = file.read_vec(l1_off, needed * 8, MAX_L1, "qcow2: the L1 table")?;
        let l1 = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .collect();
        // The header extensions, up to the end one, before the backing file's name.
        let back_off = be64(&h, 8);
        let back_len = u64::from(be32(&h, 16));
        let (mut backing_format, mut data_name) = (None, None);
        let mut at = header_len;
        loop {
            if at + 8 > head.len() as u64 {
                break;
            }
            let a = n(at);
            let (t, l) = (be32(&head, a), u64::from(be32(&head, a + 4)));
            if t == EXT_END {
                break;
            }
            let body = at + 8;
            if body + l > head.len() as u64 {
                return Err(Error::corrupt(
                    "qcow2: a header extension runs past the header's cluster",
                ));
            }
            let b = &head[n(body)..n(body + l)];
            let text = |what: &str| {
                String::from_utf8(b.to_vec())
                    .map_err(|_| Error::corrupt(format!("qcow2: the {what} isn't UTF-8")))
            };
            match t {
                EXT_BACKING_FORMAT => backing_format = Some(text("backing file's format")?),
                EXT_DATA_FILE => data_name = Some(text("data file's name")?),
                _ => {}
            }
            at = body + l.div_ceil(8) * 8;
        }
        let backing = if back_off != 0 && back_len != 0 {
            if back_len > 1023
                || back_off
                    .checked_add(back_len)
                    .is_none_or(|e| e > head.len() as u64)
            {
                return Err(Error::corrupt(
                    "qcow2: the backing file's name isn't in the header's cluster",
                ));
            }
            let b = &head[n(back_off)..n(back_off + back_len)];
            Some(
                String::from_utf8(b.to_vec())
                    .map_err(|_| Error::corrupt("qcow2: the backing file's name isn't UTF-8"))?,
            )
        } else {
            None
        };
        let mut file_bytes = file.len;
        let data = if incompat & DATA_FILE != 0 {
            let Some(name) = &data_name else {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "qcow2: {} keeps its data in a file it doesn't name",
                        origin.name
                    ),
                ));
            };
            let d = files.find(
                origin,
                &[name.as_str()],
                false,
                false,
                "the data file",
                |_, h, _| Ok(Ok(h)),
            )?;
            file_bytes = file_bytes.saturating_add(d.len);
            Some(d)
        } else {
            None
        };
        let tables = (L2_CACHE / cluster).max(MIN_L2S);
        Ok(Self {
            len: size,
            bits,
            cluster,
            l2_entries,
            extended,
            l1,
            codec,
            v3: version >= 3,
            io: RefCell::new(Io {
                file,
                data,
                tables: Cache::new(n(tables)),
                clusters: Cache::new(CLUSTER_CACHE),
                dec: Decoders::default(),
                src: Vec::new(),
            }),
            version,
            backing,
            backing_format,
            data_name,
            data_raw: autoclear & DATA_FILE_RAW != 0,
            snapshots: be32(&h, 60),
            refcount_bits,
            dirty: incompat & DIRTY != 0,
            corrupt: incompat & CORRUPT != 0,
            file_bytes,
            v1: false,
            l2_bytes: cluster,
        })
    }

    /// A QCOW version 1 image, as qemu-img still writes it (`-O qcow`). Its 48-byte header: the
    /// backing file's name (offset, length), a time, the disk's size, cluster and L2 bits,
    /// encryption, the L1 table's offset.
    /// Entries are offsets; bit 63 marks a compressed cluster (raw deflate), its length in the
    /// bits above `63 - cluster_bits`.
    fn open_v1(file: Handle, h: &[u8], got: usize) -> Result<Self> {
        if got < 48 {
            return Err(Error::corrupt("qcow2: the file is shorter than its header"));
        }
        let (bits, l2_bits) = (u32::from(h[32]), u32::from(h[33]));
        // qemu's limits.
        if !(9..=16).contains(&bits) || !(6..=13).contains(&l2_bits) {
            return Err(Error::corrupt(format!(
                "qcow: clusters of 2^{bits} bytes and L2 tables of 2^{l2_bits} entries"
            )));
        }
        if be32(h, 36) != 0 {
            return Err(Error::corrupt(
                "qcow: encrypted with AES; BeeZip doesn't decrypt disk images",
            ));
        }
        let cluster = 1u64 << bits;
        let l2_entries = 1u64 << l2_bits;
        let size = be64(h, 24);
        let needed = size.div_ceil(cluster * l2_entries);
        let l1_off = be64(h, 40);
        let mut file = file;
        let raw = file.read_vec(l1_off, needed * 8, MAX_L1, "qcow: the L1 table")?;
        let l1 = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .collect();
        let back_off = be64(h, 8);
        let back_len = u64::from(be32(h, 16));
        let backing = if back_off != 0 && back_len != 0 {
            if back_len > 1023 {
                return Err(Error::corrupt("qcow: the backing file's name is too long"));
            }
            let b = file.read_vec(back_off, back_len, 1023, "qcow: the backing file's name")?;
            Some(
                String::from_utf8(b)
                    .map_err(|_| Error::corrupt("qcow: the backing file's name isn't UTF-8"))?,
            )
        } else {
            None
        };
        let file_bytes = file.len;
        let l2_bytes = l2_entries * 8;
        Ok(Self {
            len: size,
            bits,
            cluster,
            l2_entries,
            extended: false,
            l1,
            codec: Codec::Deflate,
            v3: false,
            io: RefCell::new(Io {
                file,
                data: None,
                tables: Cache::new(n((L2_CACHE / l2_bytes).max(MIN_L2S))),
                clusters: Cache::new(CLUSTER_CACHE),
                dec: Decoders::default(),
                src: Vec::new(),
            }),
            version: 1,
            backing,
            backing_format: None,
            data_name: None,
            data_raw: false,
            snapshots: 0,
            refcount_bits: 16,
            dirty: false,
            corrupt: false,
            file_bytes,
            v1: true,
            l2_bytes,
        })
    }

    /// Where L1 entry `l1e` puts its L2 table (0: none).
    fn l2_at(&self, l1e: u64) -> u64 {
        if self.v1 { l1e & !COPIED } else { l1e & OFFSET }
    }

    /// The L2 table at `off`, from the cache or the file.
    fn table<'a>(
        tables: &'a mut Cache,
        file: &mut Handle,
        cluster: u64,
        size: u64,
        off: u64,
    ) -> Result<&'a [u8]> {
        if !off.is_multiple_of(cluster) {
            return Err(Error::corrupt(format!(
                "qcow2: an L2 table at {off}, not on a cluster"
            )));
        }
        if tables.get(off).is_none() {
            tables.fill(off, n(size), |out| {
                file.read_exact_at(off, out, "qcow2: an L2 table")
            })?;
        }
        tables
            .get(off)
            .ok_or_else(|| Error::corrupt("qcow2: an L2 table"))
    }

    /// What entry `e` of an L2 table maps its cluster to (not extended).
    fn map(&self, e: u64, has_data: bool) -> Map {
        if self.v1 {
            // Version 1: bit 63 marks a compressed cluster; otherwise an offset or 0.
            return match e {
                0 => Map::Hole,
                e if e & COPIED != 0 => Map::Packed(e),
                e => Map::At(e),
            };
        }
        if e & COMPRESSED != 0 {
            return Map::Packed(e);
        }
        if self.v3 && e & ZERO != 0 {
            return Map::Zero;
        }
        let host = e & OFFSET;
        if host == 0 && !(has_data && e & COPIED != 0) {
            return Map::Hole;
        }
        Map::At(host)
    }

    /// Subcluster `i`'s state in an extended L2 entry's bitmap: allocated, zero, or neither.
    fn sub(bitmap: u64, i: u64) -> Result<Got> {
        match (bitmap >> i & 1 != 0, bitmap >> (32 + i) & 1 != 0) {
            (true, true) => Err(Error::corrupt(
                "qcow2: a subcluster both allocated and reading as zeros",
            )),
            (true, false) => Ok(Got::Data),
            (false, true) => Ok(Got::Zero),
            (false, false) => Ok(Got::Hole),
        }
    }

    /// Copies `buf.len()` bytes at `within` of the compressed cluster whose L2 entry is `e`,
    /// cluster `ci` of the disk, into `buf`.
    fn packed(&self, io: &mut Io, e: u64, ci: u64, within: u64, buf: &mut [u8]) -> Result<()> {
        if io.data.is_some() {
            return Err(Error::corrupt(
                "qcow2: a compressed cluster in an image with a data file",
            ));
        }
        let (off, len) = if self.v1 {
            // Version 1: the offset below bit 63 - cluster_bits, the length in bytes above it.
            let x = 63 - self.bits;
            (e & ((1u64 << x) - 1), (e >> x) & (self.cluster - 1))
        } else {
            let x = 62 - (self.bits - 8);
            let off = e & ((1u64 << x) - 1);
            let sectors = (e >> x) & ((1u64 << (self.bits - 8)) - 1);
            (off, (sectors + 1) * 512 - (off & 511))
        };
        if io.clusters.get(off).is_none() {
            if off >= io.file.len {
                return Err(Error::corrupt(format!(
                    "qcow2: a compressed cluster at {off}, past the file's end"
                )));
            }
            let what = format!("qcow2: the compressed cluster at {off}");
            // The last compressed cluster may end before its last sector: the file's end.
            io.src.resize(n(len.min(io.file.len - off)), 0);
            io.file.read_exact_at(off, &mut io.src, &what)?;
            // The disk's last cluster keeps only its bytes in the disk.
            let full = n(self.cluster.min(self.len - ci * self.cluster));
            let (src, dec, codec) = (&io.src, &mut io.dec, self.codec);
            io.clusters.fill(off, n(self.cluster), |out| {
                match codec {
                    Codec::Deflate => dec.inflate(src, &mut out[..full], false, &what)?,
                    Codec::Zstd => dec.unzstd(src, &mut out[..full], &what)?,
                }
                out[full..].fill(0);
                Ok(())
            })?;
        }
        let c = io
            .clusters
            .get(off)
            .ok_or_else(|| Error::corrupt("qcow2: a compressed cluster"))?;
        let w = n(within);
        buf.copy_from_slice(&c[w..w + buf.len()]);
        Ok(())
    }
}

impl Layer for Qcow2 {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)> {
        let want = buf.len() as u64;
        let cs = self.cluster;
        let ci = off >> self.bits;
        let within = off & (cs - 1);
        let (l1i, first) = (ci / self.l2_entries, ci % self.l2_entries);
        let l1e = *self
            .l1
            .get(n(l1i))
            .ok_or_else(|| Error::corrupt("qcow2: a read past the L1 table"))?;
        let l2 = self.l2_at(l1e);
        if l2 == 0 {
            let left = (self.l2_entries - first) * cs - within;
            return Ok((n(want.min(left)), Got::Hole));
        }
        let mut io = self
            .io
            .try_borrow_mut()
            .map_err(|_| Error::corrupt("qcow2: a read while another is under way"))?;
        self.read_in(&mut io, l2, ci, first, within, buf)
    }

    fn held_in(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len).min(self.len);
        if start >= end {
            return 0;
        }
        let Ok(mut io) = self.io.try_borrow_mut() else {
            return end - start;
        };
        let io = &mut *io;
        let cs = self.cluster;
        let span = self.l2_entries * cs;
        let overlap = |a: u64, b: u64| b.min(end).saturating_sub(a.max(start));
        let has_data = io.data.is_some();
        let mut held = 0u64;
        let mut t = start / span;
        while t * span < end {
            let Some(&l1e) = self.l1.get(n(t)) else {
                break;
            };
            let base = t * span;
            let l2 = self.l2_at(l1e);
            if l2 != 0 {
                match Self::table(&mut io.tables, &mut io.file, cs, self.l2_bytes, l2) {
                    Err(_) => held += overlap(base, base + span),
                    Ok(table) => {
                        for i in (start.max(base) - base) / cs..self.l2_entries {
                            let a = base + i * cs;
                            if a >= end {
                                break;
                            }
                            let at = n(i * if self.extended { 16 } else { 8 });
                            let e = be64(table, at);
                            if self.extended && e & COMPRESSED == 0 {
                                let bitmap = be64(table, at + 8);
                                let sub = cs / 32;
                                for s in 0..32 {
                                    if bitmap >> s & 1 != 0 {
                                        let b = a + s * sub;
                                        held += overlap(b, b + sub);
                                    }
                                }
                            } else if matches!(self.map(e, has_data), Map::At(_) | Map::Packed(_)) {
                                held += overlap(a, a + cs);
                            }
                        }
                    }
                }
            }
            t += 1;
        }
        held
    }

    fn file_bytes(&self) -> u64 {
        self.file_bytes
    }

    fn properties(&self, out: &mut Vec<(&'static str, String)>) {
        out.push(("Version", self.version.to_string()));
        out.push(("Cluster Size", self.cluster.to_string()));
        if let Some(b) = &self.backing {
            out.push(("Backing File", b.clone()));
        }
        if let Some(f) = &self.backing_format {
            out.push(("Backing Format", f.clone()));
        }
        if let Some(d) = &self.data_name {
            let raw = if self.data_raw { " (raw)" } else { "" };
            out.push(("Data File", format!("{d}{raw}")));
        }
        if self.codec == Codec::Zstd {
            out.push(("Compression", "zstd".into()));
        }
        if self.extended {
            out.push(("Subclusters", "32".into()));
        }
        if self.refcount_bits != 16 {
            out.push(("Refcount Bits", self.refcount_bits.to_string()));
        }
        if self.snapshots > 0 {
            out.push(("Snapshots", self.snapshots.to_string()));
        }
    }

    fn notes(&self, out: &mut Vec<String>) {
        if self.dirty {
            out.push(
                "the QCOW2 is marked dirty: qemu didn't close it cleanly, so its reference counts \
                 may be stale (reading doesn't use them)"
                    .into(),
            );
        }
        if self.corrupt {
            out.push(
                "qemu marked the QCOW2 corrupt: its tables may be damaged; it's read as it is"
                    .into(),
            );
        }
        if self.snapshots > 0 {
            out.push(format!(
                "the QCOW2 has {} internal snapshot{}; its current state is what's read",
                self.snapshots,
                if self.snapshots == 1 { "" } else { "s" }
            ));
        }
    }
}

impl Qcow2 {
    /// [`Layer::read_at`] once the L2 table at `l2` is known to map cluster `ci`, entry `first`
    /// of it.
    fn read_in(
        &self,
        io: &mut Io,
        l2: u64,
        ci: u64,
        first: u64,
        within: u64,
        buf: &mut [u8],
    ) -> Result<(usize, Got)> {
        let want = buf.len() as u64;
        let cs = self.cluster;
        let has_data = io.data.is_some();
        let table = Self::table(&mut io.tables, &mut io.file, cs, self.l2_bytes, l2)?;
        let width = if self.extended { 16 } else { 8 };
        let entry = |i: u64| be64(table, n(i * width));
        let e = entry(first);
        if self.extended && e & COMPRESSED == 0 {
            // 32 subclusters, each allocated, zero, or neither (the backing file's).
            let bitmap = be64(table, n(first * width + 8));
            let host = e & OFFSET;
            let sub = cs / 32;
            let si = within / sub;
            let got = Self::sub(bitmap, si)?;
            let mut end = (si + 1) * sub;
            while end < cs && end < within + want && Self::sub(bitmap, end / sub)? == got {
                end += sub;
            }
            let k = n(want.min(end - within));
            if got == Got::Data {
                if host == 0 && !(has_data && e & COPIED != 0) {
                    return Err(Error::corrupt("qcow2: allocated subclusters in no cluster"));
                }
                if !host.is_multiple_of(cs) {
                    return Err(Error::corrupt(format!(
                        "qcow2: a cluster at {host}, not on a cluster"
                    )));
                }
                let src = io.data.as_mut().unwrap_or(&mut io.file);
                src.read_exact_at(host + within, &mut buf[..k], "qcow2: a subcluster")?;
            }
            return Ok((k, got));
        }
        let map = if self.extended {
            Map::Packed(e)
        } else {
            self.map(e, has_data)
        };
        // The entries of this table the read reaches.
        let last = self.l2_entries.min(first + (within + want).div_ceil(cs));
        let mut i = first + 1;
        match map {
            Map::Hole | Map::Zero => {
                while i < last && self.map(entry(i), has_data) == map {
                    i += 1;
                }
                let got = if map == Map::Hole {
                    Got::Hole
                } else {
                    Got::Zero
                };
                Ok((n(want.min((i - first) * cs - within)), got))
            }
            Map::At(host) => {
                if !host.is_multiple_of(cs) {
                    return Err(Error::corrupt(format!(
                        "qcow2: a cluster at {host}, not on a cluster"
                    )));
                }
                // Clusters stored one after another read in one go.
                while i < last && self.map(entry(i), has_data) == Map::At(host + (i - first) * cs) {
                    i += 1;
                }
                let k = n(want.min((i - first) * cs - within));
                let src = io.data.as_mut().unwrap_or(&mut io.file);
                src.read_exact_at(host + within, &mut buf[..k], "qcow2: a cluster")?;
                Ok((k, Got::Data))
            }
            Map::Packed(e) => {
                let k = n(want.min(cs - within));
                self.packed(io, e, ci, within, &mut buf[..k])?;
                Ok((k, Got::Data))
            }
        }
    }
}

/// The disk format a backing file is: the one the image records (`format`), else the one its
/// extension says, else what its first bytes are. `None` is a raw image.
fn backing_kind(format: Option<&str>, h: &mut Handle, o: &Origin) -> Result<Option<External>> {
    if let Some(f) = format {
        return match f {
            "qcow2" => Ok(Some(External::Qcow2)),
            "raw" | "file" => Ok(None),
            "vmdk" => Ok(Some(External::Vmdk)),
            "vdi" => Ok(Some(External::Vdi)),
            "vpc" => Ok(Some(External::Vhd)),
            "vhdx" => Ok(Some(External::Vhdx)),
            f => Err(Error::unsupported(format!(
                "qcow2: a backing file of format `{f}`, which BeeZip doesn't read"
            ))),
        };
    }
    let ext = o
        .path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    match ext.as_deref() {
        Some("qcow2") => return Ok(Some(External::Qcow2)),
        Some("vmdk") => return Ok(Some(External::Vmdk)),
        Some("vdi") => return Ok(Some(External::Vdi)),
        Some("vhd") => return Ok(Some(External::Vhd)),
        Some("vhdx" | "avhdx") => return Ok(Some(External::Vhdx)),
        _ => {}
    }
    let mut head = [0u8; 512];
    let got = h.read_upto(0, &mut head, "qcow2: the backing file")?;
    Ok(super::sniff(&head[..got]))
}

/// The levels of the QCOW2 `file` is, its backing files' below it.
pub fn layers(file: Handle, origin: Origin, files: &mut Files) -> Result<Vec<Box<dyn Layer>>> {
    let q = Qcow2::open(file, &origin, files)?;
    let (backing, format) = (q.backing.clone(), q.backing_format.clone());
    let mut out: Vec<Box<dyn Layer>> = vec![Box::new(q)];
    if let Some(name) = backing {
        let below = files.find(
            &origin,
            &[name.as_str()],
            false,
            true,
            "the backing file",
            |files, mut h, o| {
                let kind = backing_kind(format.as_deref(), &mut h, &o)?;
                super::layers(kind, h, o, files).map(Ok)
            },
        )?;
        out.extend(below);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::{io::Read, path::Path};

    use super::super::testing::{self, copy_into, digest, digest_of, dir, error_of, open_path};
    use super::super::{Files, Handle, Origin};
    use super::{COMPRESSED, COPIED, be32, be64};
    use crate::{ErrorKind, backend::External, io::Counter};

    /// Records `name` as the backing file of the QCOW2 at `path`, where its old name was.
    fn set_backing(path: &Path, name: &str) {
        let mut d = std::fs::read(path).unwrap();
        let (off, old) = (be64(&d, 8) as usize, be32(&d, 16) as usize);
        assert!(off != 0 && off + name.len() <= 1 << be32(&d, 20));
        d[off..off + old].fill(0);
        d[off..off + name.len()].copy_from_slice(name.as_bytes());
        d[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
        std::fs::write(path, d).unwrap();
    }

    #[test]
    fn every_qcow2_fixture_reads_as_expected() {
        testing::check_all(&[".qcow2", ".qcow"]);
    }

    #[test]
    fn a_backing_file_is_found_by_its_relative_path_or_its_name_beside() {
        for (child, base, name) in [
            ("q-child.qcow2", "q-v3.qcow2", "q-v3.qcow2"),
            (
                "kids/q-child.qcow2",
                "base/q-v3.qcow2",
                "../base/q-v3.qcow2",
            ),
            ("q-child.qcow2", "sub/q-v3.qcow2", "sub/q-v3.qcow2"),
            ("q-child.qcow2", "sub/q-v3.qcow2", r"sub\q-v3.qcow2"),
            (
                "q-child.qcow2",
                "q-v3.qcow2",
                "/var/lib/libvirt/images/q-v3.qcow2",
            ),
            ("q-child.qcow2", "q-v3.qcow2", r"C:\VMs\base\q-v3.qcow2"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            copy_into(
                tmp.path(),
                &[("q-child.qcow2", child), ("q-v3.qcow2", base)],
            );
            let path = tmp.path().join(child);
            set_backing(&path, name);
            let mut d = open_path(External::Qcow2, &path).unwrap();
            assert_eq!(
                digest(&mut d).unwrap(),
                digest_of("q-child.qcow2"),
                "{name}"
            );
        }
    }

    /// Gives the QCOW2 at `path`'s header extension of type `old` type `new`, which readers skip.
    fn retype_extension(path: &Path, old: u32, new: u32) {
        let mut d = std::fs::read(path).unwrap();
        let mut at = be32(&d, 100) as usize;
        while be32(&d, at) != old {
            assert_ne!(be32(&d, at), 0, "no extension {old:#x}");
            at += 8 + (be32(&d, at + 4) as usize).div_ceil(8) * 8;
        }
        d[at..at + 4].copy_from_slice(&new.to_be_bytes());
        std::fs::write(path, d).unwrap();
    }

    #[test]
    fn a_backing_format_not_recorded_is_the_extension_or_what_the_file_is() {
        let tmp = tempfile::tempdir().unwrap();
        copy_into(
            tmp.path(),
            &[
                ("q-child.qcow2", "q-child.qcow2"),
                ("q-v3.qcow2", "q-v3.qcow2"),
                ("q-v3.qcow2", "base.bin"),
            ],
        );
        let path = tmp.path().join("q-child.qcow2");
        retype_extension(&path, super::EXT_BACKING_FORMAT, 0x6E6F_6E65);
        // `q-v3.qcow2`: the extension says.
        let mut d = open_path(External::Qcow2, &path).unwrap();
        assert_eq!(digest(&mut d).unwrap(), digest_of("q-child.qcow2"));
        drop(d);
        // `base.bin`: its first bytes.
        set_backing(&path, "base.bin");
        let mut d = open_path(External::Qcow2, &path).unwrap();
        assert_eq!(digest(&mut d).unwrap(), digest_of("q-child.qcow2"));
    }

    #[test]
    fn a_backing_file_is_never_looked_for_at_an_absolute_path() {
        // QCOW2 records no identity to check a file found so against (docs/M8.md §3.6).
        let tmp = tempfile::tempdir().unwrap();
        copy_into(
            tmp.path(),
            &[
                ("q-child.qcow2", "kids/q-child.qcow2"),
                ("q-v3.qcow2", "elsewhere/base.qcow2"),
            ],
        );
        let path = tmp.path().join("kids").join("q-child.qcow2");
        let base = tmp.path().join("elsewhere").join("base.qcow2");
        set_backing(&path, &base.display().to_string());
        let e = error_of(External::Qcow2, &path);
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        let beside = tmp.path().join("kids").join("base.qcow2");
        assert!(
            e.message
                .contains(&format!("{} (its name", beside.display())),
            "{e}"
        );
    }

    #[test]
    fn a_missing_backing_or_data_file_names_where_it_was_looked_for() {
        let tmp = tempfile::tempdir().unwrap();
        copy_into(
            tmp.path(),
            &[
                ("q-child.qcow2", "q-child.qcow2"),
                ("q-data.qcow2", "q-data.qcow2"),
            ],
        );
        let e = error_of(External::Qcow2, &tmp.path().join("q-child.qcow2"));
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        let beside = tmp.path().join("q-v3.qcow2");
        assert!(
            e.message
                .contains("the backing file named by q-child.qcow2 isn't found")
                && e.message.contains(&format!(
                    "{} (its relative path q-v3.qcow2: not there)",
                    beside.display()
                )),
            "{e}"
        );
        let e = error_of(External::Qcow2, &tmp.path().join("q-data.qcow2"));
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(e.message.contains("q-data.bin"), "{e}");
    }

    #[test]
    fn names_that_arent_files_are_unsafe() {
        let tmp = tempfile::tempdir().unwrap();
        copy_into(tmp.path(), &[("q-child.qcow2", "q-child.qcow2")]);
        let path = tmp.path().join("q-child.qcow2");
        for name in [
            r#"json:{"file.driver":"file","file.filename":"/etc/passwd"}"#,
            "nbd://localhost:10809/x",
            "nbd:localhost:10809",
            r"\\server\share\q-v3.qcow2",
            "//server/share/q-v3.qcow2",
            r"\\?\UNC\server\share\q-v3.qcow2",
            r"\\.\PhysicalDrive0",
            "/dev/sda",
        ] {
            set_backing(&path, name);
            let e = error_of(External::Qcow2, &path);
            assert_eq!(e.kind, ErrorKind::Unsafe, "{name}: {e}");
        }
    }

    #[test]
    fn refusals_say_why() {
        for (f, says) in [
            ("q-aes.qcow2", "BeeZip doesn't decrypt disk images"),
            ("q-luks.qcow2", "BeeZip doesn't decrypt disk images"),
            (
                "q-refuse-bit.qcow2",
                "incompatible features BeeZip doesn't know (0x20)",
            ),
            ("q-refuse-ctype.qcow2", "compression type 2"),
        ] {
            let e = error_of(External::Qcow2, &dir().join(f));
            assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{f}: {e}");
            assert!(e.message.contains(says), "{f}: {e}");
        }
    }

    /// Clusters of 2 MiB, built here: qemu-img's would be 10 MB of fixture. 5 MiB: cluster 0
    /// stored, cluster 1 compressed, cluster 2 (half of it in the disk) a hole.
    #[test]
    fn clusters_of_2_mib_read() {
        use std::io::Write;
        let cs = 2usize << 20;
        let size = 5u64 << 20;
        let a: Vec<u8> = (0..cs).map(|i| (i * 7 % 251) as u8).collect();
        let b: Vec<u8> = (0..cs).map(|i| (i / 4096) as u8).collect();
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&b).unwrap();
        let packed = enc.finish().unwrap();
        let mut img = vec![0u8; 3 * cs];
        img[..4].copy_from_slice(b"QFI\xFB");
        img[4..8].copy_from_slice(&3u32.to_be_bytes());
        img[20..24].copy_from_slice(&21u32.to_be_bytes());
        img[24..32].copy_from_slice(&size.to_be_bytes());
        img[36..40].copy_from_slice(&1u32.to_be_bytes());
        img[40..48].copy_from_slice(&(cs as u64).to_be_bytes());
        img[96..100].copy_from_slice(&4u32.to_be_bytes());
        img[100..104].copy_from_slice(&104u32.to_be_bytes());
        let l1 = (2 * cs as u64) | COPIED;
        img[cs..cs + 8].copy_from_slice(&l1.to_be_bytes());
        let data = 3 * cs as u64;
        let at = data + cs as u64;
        let sectors = (at % 512 + packed.len() as u64).div_ceil(512) - 1;
        let e0 = data | COPIED;
        let e1 = COMPRESSED | sectors << (62 - 13) | at;
        img[2 * cs..2 * cs + 8].copy_from_slice(&e0.to_be_bytes());
        img[2 * cs + 8..2 * cs + 16].copy_from_slice(&e1.to_be_bytes());
        img.extend_from_slice(&a);
        img.extend_from_slice(&packed);
        let tmp = tempfile::tempdir().unwrap();
        let origin = Origin::of(&tmp.path().join("c2m.qcow2"));
        let mut files = Files::new(&origin, Counter::new());
        let len = img.len() as u64;
        let file = Handle::new(Box::new(std::io::Cursor::new(img)), len);
        let mut d = super::super::open(External::Qcow2, file, origin, &mut files).unwrap();
        let mut got = Vec::new();
        d.read_to_end(&mut got).unwrap();
        assert_eq!(got.len() as u64, size);
        assert!(got[..cs] == a[..]);
        assert!(got[cs..2 * cs] == b[..]);
        assert!(got[2 * cs..].iter().all(|&x| x == 0));
        assert_eq!(d.held_in(0, size), 2 * cs as u64);
    }

    #[test]
    fn holdings_are_exact() {
        // disk.img's 64 KiB clusters 0, 1 and 3 hold something; cluster 2 is zeros.
        for f in ["q-v3.qcow2", "q-deflate.qcow2", "q-zstd.qcow2"] {
            let d = open_path(External::Qcow2, &dir().join(f)).unwrap();
            assert_eq!(d.held_in(0, d.len()), 3 << 16, "{f}");
            assert_eq!(d.held_in(2 << 16, 1 << 16), 0, "{f}");
        }
        // Zero clusters aren't held, even the one still allocated.
        let d = open_path(External::Qcow2, &dir().join("q-zero.qcow2")).unwrap();
        assert_eq!(d.held_in(61_440, 8192), 0);
        testing::holdings_never_low(&[".qcow2"]);
    }

    #[test]
    fn info_gives_its_version_clusters_and_backing_files() {
        let disk = |f: &str| open_path(External::Qcow2, &dir().join(f)).unwrap();
        let has = |p: &[(&str, String)], k: &str, v: &str| {
            assert!(
                p.iter().any(|(a, b)| *a == k && b == v),
                "{k} = {v} in {p:?}"
            );
        };
        let p = disk("q-v2.qcow2").properties();
        has(&p, "Version", "2");
        has(&p, "Cluster Size", "4096");
        has(&disk("q-zstd.qcow2").properties(), "Compression", "zstd");
        has(&disk("q-el2.qcow2").properties(), "Subclusters", "32");
        has(&disk("q-rc1.qcow2").properties(), "Refcount Bits", "1");
        has(
            &disk("q-data.qcow2").properties(),
            "Data File",
            "q-data.bin",
        );
        has(
            &disk("q-data-raw.qcow2").properties(),
            "Data File",
            "q-data-raw.bin (raw)",
        );
        let p = disk("q-gchild.qcow2").properties();
        has(&p, "Backing File", "q-child.qcow2");
        has(&p, "Backing Format", "qcow2");
        has(&p, "Parent", "q-child.qcow2 > q-v3.qcow2");
        let d = disk("q-snap.qcow2");
        has(&d.properties(), "Snapshots", "2");
        assert!(d.notes().iter().any(|n| n.contains("2 internal snapshots")));
        assert!(
            disk("q-dirty.qcow2")
                .notes()
                .iter()
                .any(|n| n.contains("marked dirty"))
        );
        assert!(
            disk("q-corrupt.qcow2")
                .notes()
                .iter()
                .any(|n| n.contains("marked the QCOW2 corrupt"))
        );
        // Every file read counts: the image and its data file; a child and its backing file.
        let d = disk("q-data.qcow2");
        let sizes = |fs: &[&str]| -> u64 {
            fs.iter()
                .map(|f| std::fs::metadata(dir().join(f)).unwrap().len())
                .sum()
        };
        assert_eq!(d.file_bytes(), sizes(&["q-data.qcow2", "q-data.bin"]));
        assert_eq!(
            disk("q-child-raw.qcow2").file_bytes(),
            sizes(&["q-child-raw.qcow2", "disk.img"])
        );
    }

    #[test]
    fn mutated_qcow2s_never_panic() {
        testing::mutations(&[".qcow2", ".qcow"], 24, 0x5EED_0002);
    }
}
