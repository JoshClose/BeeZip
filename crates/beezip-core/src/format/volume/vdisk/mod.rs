//! Virtual disks BeeZip reads itself (docs/M8.md §3): VHD, VHDX, VMDK, QCOW2 and VDI, read only,
//! from their published descriptions.
//!
//! - **A disk is a stack of levels** ([`Layer`]): the opened image first, then its parent (a
//!   differencing VHD's or VHDX's parent, a VMDK's parent disk, a QCOW2's backing file, a VDI's
//!   parent), and so on. A level answers a read with data, zeros, or a hole; a hole reads from
//!   the next level down, and the last level's holes read zeros. A level shorter than the disk (a
//!   smaller backing file) reads zeros past its end.
//! - **Other files a disk names** (parents, extents, backing and data files) are found by
//!   [`files::Files`]' rules only: never a network or device path, and each checked by the
//!   identity its format records.
//! - **Every size and offset is checked before it's used,** and a table is read only when the
//!   file holds it, so memory is bounded by the files' size. A mapping that points past its file
//!   is `Corrupt` when it's read.
//! - **What a reader doesn't support** is `UnsupportedOperation`, which `source::open` hands to
//!   7-Zip when it's installed; damage is `Corrupt`, and a parent that can't be found `NotFound`,
//!   which 7-Zip couldn't read either.
//! - [`VirtualDisk`] is the stack read as one disk, which `DiskReader` opens before what's inside:
//!   `vhdx > gpt > ntfs`. [`VirtualDisk::held_in`] is what the ratio limit checks a raw item's
//!   claim against (docs/M8.md §3.7).

pub mod files;
pub mod qcow2;
#[cfg(test)]
mod testing;
pub mod vdi;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;

use std::{
    collections::VecDeque,
    io::{self, Read, Seek, SeekFrom},
};

pub use files::{Files, Origin};

use crate::{Error, Result, backend::External, format::volume::Input, io::read_error};

/// What a level's read gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Got {
    /// Bytes written into the buffer.
    Data,
    /// Zeros (a zero block, cluster or grain): the buffer isn't touched.
    Zero,
    /// Not in this level: the next one down, or zeros.
    Hole,
}

/// One image of a disk's chain (see the module's notes).
pub trait Layer: Send {
    /// The disk's size, as this level records it.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Its logical sector size: 512, or 4096 for a VHD or VHDX of 4 KiB sectors.
    fn sector(&self) -> u32 {
        512
    }

    /// What this level has at `off` (below [`Layer::len`]): at least one and at most
    /// `buf.len()` bytes, stopping where its mapping changes.
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)>;

    /// Bytes of `start..start + len` this level's files hold data for (not holes, nor blocks
    /// marked zero). An estimate may be high, never low.
    fn held_in(&self, start: u64, len: u64) -> u64;

    /// The sizes of this level's files, added up.
    fn file_bytes(&self) -> u64;

    /// What Info shows of it, under 7-Zip's names where 7-Zip has them.
    fn properties(&self, out: &mut Vec<(&'static str, String)>);

    /// What Info notes about it: a log replayed, blocks past the file's end.
    fn notes(&self, _out: &mut Vec<String>) {}
}

/// A virtual disk: its levels, read as one (see the module's notes).
pub struct VirtualDisk {
    format: External,
    layers: Vec<Box<dyn Layer>>,
    /// The file name of each level after the first, in order.
    parents: Vec<String>,
    len: u64,
    pos: u64,
}

impl VirtualDisk {
    /// `layers` (the opened image's first) as the disk `format` is.
    pub fn new(format: External, layers: Vec<Box<dyn Layer>>, parents: Vec<String>) -> Self {
        let len = layers.first().map_or(0, |l| l.len());
        Self {
            format,
            layers,
            parents,
            len,
            pos: 0,
        }
    }

    pub fn format(&self) -> External {
        self.format
    }

    /// The disk's size.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The disk's logical sector size.
    pub fn sector(&self) -> u32 {
        self.layers.first().map_or(512, |l| l.sector())
    }

    /// How many levels it has: 1 for a disk with no parent.
    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    /// The sizes of every file it reads, added up: the disk-wide ratio cap's base.
    pub fn file_bytes(&self) -> u64 {
        self.layers
            .iter()
            .fold(0u64, |a, l| a.saturating_add(l.file_bytes()))
    }

    /// Bytes of `start..start + len` its files hold data for, at most `len`: what a raw item
    /// there is claim-checked against.
    pub fn held_in(&self, start: u64, len: u64) -> u64 {
        self.layers
            .iter()
            .fold(0u64, |a, l| a.saturating_add(l.held_in(start, len)))
            .min(len)
    }

    /// What Info shows of the disk: its first level's properties, then its parents' names.
    pub fn properties(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(l) = self.layers.first() {
            l.properties(&mut out);
        }
        if !self.parents.is_empty() {
            out.push(("Parent", self.parents.join(" > ")));
        }
        out
    }

    /// What Info notes about it, every level's.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        for l in &self.layers {
            l.notes(&mut out);
        }
        out
    }

    /// Fills `buf` from level `level` at `off`: how many bytes it filled, at least one.
    fn fill(&mut self, level: usize, off: u64, buf: &mut [u8]) -> Result<usize> {
        let Some(layer) = self.layers.get_mut(level) else {
            buf.fill(0);
            return Ok(buf.len());
        };
        let len = layer.len();
        if off >= len {
            buf.fill(0);
            return Ok(buf.len());
        }
        let max = buf
            .len()
            .min(usize::try_from(len - off).unwrap_or(usize::MAX));
        let (n, got) = layer.read_at(off, &mut buf[..max])?;
        if n == 0 || n > max {
            return Err(Error::corrupt("a virtual disk's level read nothing"));
        }
        match got {
            Got::Data => {}
            Got::Zero => buf[..n].fill(0),
            Got::Hole => {
                let mut done = 0;
                while done < n {
                    done += self.fill(level + 1, off + done as u64, &mut buf[done..n])?;
                }
            }
        }
        Ok(n)
    }
}

impl Read for VirtualDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.len - self.pos).unwrap_or(usize::MAX));
        let mut done = 0;
        while done < want {
            let n = self
                .fill(0, self.pos + done as u64, &mut buf[done..want])
                .map_err(Error::into_io)?;
            done += n;
        }
        self.pos += done as u64;
        Ok(done)
    }
}

impl Seek for VirtualDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = to.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a seek before the disk's start",
            )
        })?;
        Ok(self.pos)
    }
}

/// The format of an image a disk names whose format isn't recorded, from its first bytes: a
/// QCOW2's backing file. `None` is a raw image.
pub fn sniff(head: &[u8]) -> Option<External> {
    if head.starts_with(b"QFI\xFB") {
        Some(External::Qcow2)
    } else if head.starts_with(b"KDMV")
        || head.starts_with(b"COWD")
        || head
            .strip_prefix(b"\xEF\xBB\xBF")
            .unwrap_or(head)
            .starts_with(b"# Disk DescriptorFile")
    {
        Some(External::Vmdk)
    } else if head.get(64..68) == Some(&[0x7F, 0x10, 0xDA, 0xBE]) {
        Some(External::Vdi)
    } else if head.starts_with(b"vhdxfile") {
        Some(External::Vhdx)
    } else {
        None
    }
}

/// The levels of the image `file` is, a `kind` disk (`None`: a raw image), and below them its
/// parents'.
pub fn layers(
    kind: Option<External>,
    file: Handle,
    origin: Origin,
    files: &mut Files,
) -> Result<Vec<Box<dyn Layer>>> {
    match kind {
        Some(External::Vhd) => vhd::layers(file, origin, files),
        Some(External::Vhdx) => vhdx::layers(file, origin, files),
        Some(External::Vmdk) => vmdk::layers(file, origin, files),
        Some(External::Qcow2) => qcow2::layers(file, origin, files),
        Some(External::Vdi) => vdi::layers(file, origin, files),
        None => Ok(vec![Box::new(RawLayer::new(file))]),
        Some(k) => Err(Error::unsupported(format!(
            "BeeZip doesn't read a {} itself",
            k.display_name()
        ))),
    }
}

/// Opens the `kind` disk `file` is (the file at `origin`) with its parents and other files.
pub fn open(
    kind: External,
    file: Handle,
    origin: Origin,
    files: &mut Files,
) -> Result<VirtualDisk> {
    let layers = layers(Some(kind), file, origin, files)?;
    Ok(VirtualDisk::new(kind, layers, files.parents().to_vec()))
}

/// A file read at offsets, with its length, past which every read is `Corrupt`.
pub struct Handle {
    input: Box<dyn Input>,
    pub len: u64,
}

impl Handle {
    pub fn new(input: Box<dyn Input>, len: u64) -> Self {
        Self { input, len }
    }

    /// Exactly `buf.len()` bytes at `at`; past the file's end is `Corrupt`, saying `what` it
    /// was reading.
    pub fn read_exact_at(&mut self, at: u64, buf: &mut [u8], what: &str) -> Result<()> {
        if at
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(Error::corrupt(format!(
                "{what}: {} bytes at {at} reach past the file's end ({} bytes)",
                buf.len(),
                self.len
            )));
        }
        self.input
            .seek(SeekFrom::Start(at))
            .and_then(|_| self.input.read_exact(buf))
            .map_err(|e| read_error(&e))
    }

    /// Up to `buf.len()` bytes at `at`, as many as the file has.
    pub fn read_upto(&mut self, at: u64, buf: &mut [u8], what: &str) -> Result<usize> {
        let have = self.len.saturating_sub(at);
        let n = buf.len().min(usize::try_from(have).unwrap_or(usize::MAX));
        if n > 0 {
            self.read_exact_at(at, &mut buf[..n], what)?;
        }
        Ok(n)
    }

    /// `n` bytes at `at` in a new buffer of at most `cap` bytes; the file must hold them.
    pub fn read_vec(&mut self, at: u64, n: u64, cap: u64, what: &str) -> Result<Vec<u8>> {
        if at.checked_add(n).is_none_or(|end| end > self.len) {
            return Err(Error::corrupt(format!(
                "{what}: {n} bytes at {at} reach past the file's end ({} bytes)",
                self.len
            )));
        }
        let mut v = alloc(n, cap, what)?;
        self.read_exact_at(at, &mut v, what)?;
        Ok(v)
    }
}

/// A raw image as a level: a QCOW2's raw backing or data file, a VMDK's flat extent.
pub struct RawLayer {
    file: Handle,
}

impl RawLayer {
    pub fn new(file: Handle) -> Self {
        Self { file }
    }
}

impl Layer for RawLayer {
    fn len(&self) -> u64 {
        self.file.len
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)> {
        self.file.read_exact_at(off, buf, "a raw image")?;
        Ok((buf.len(), Got::Data))
    }

    fn held_in(&self, start: u64, len: u64) -> u64 {
        self.file.len.saturating_sub(start).min(len)
    }

    fn file_bytes(&self) -> u64 {
        self.file.len
    }

    fn properties(&self, out: &mut Vec<(&'static str, String)>) {
        out.push(("Type", "raw".into()));
    }
}

/// A small cache of decoded grains or clusters, by where they are in their file.
pub struct Cache {
    slots: VecDeque<(u64, Vec<u8>)>,
    cap: usize,
}

impl Cache {
    pub fn new(cap: usize) -> Self {
        Self {
            slots: VecDeque::new(),
            cap,
        }
    }

    pub fn get(&mut self, key: u64) -> Option<&[u8]> {
        let i = self.slots.iter().position(|(k, _)| *k == key)?;
        if i != 0 {
            let s = self.slots.remove(i)?;
            self.slots.push_front(s);
        }
        self.slots.front().map(|(_, v)| v.as_slice())
    }

    /// A slot for `key`, `len` bytes long, filled by `fill`: once the cache is full, the least
    /// recently used slot's memory is reused. A failed fill leaves no slot.
    pub fn fill(
        &mut self,
        key: u64,
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<()>,
    ) -> Result<&[u8]> {
        let mut v = if self.slots.len() >= self.cap {
            self.slots.pop_back().map(|(_, v)| v).unwrap_or_default()
        } else {
            Vec::new()
        };
        v.resize(len, 0);
        fill(&mut v)?;
        self.slots.push_front((key, v));
        Ok(self.slots.front().map(|(_, v)| v.as_slice()).unwrap_or(&[]))
    }
}

/// Decoders kept from one grain or cluster to the next: making one each time costs more than
/// decoding a grain.
#[derive(Default)]
pub struct Decoders {
    zlib: Option<flate2::Decompress>,
    raw: Option<flate2::Decompress>,
    zstd: Option<zstd::stream::raw::Decoder<'static>>,
}

impl Decoders {
    /// Inflates `src` (zlib when `zlib`, else raw deflate) into exactly `out.len()` bytes;
    /// input left over is ignored. Less output is `Corrupt`.
    pub fn inflate(&mut self, src: &[u8], out: &mut [u8], zlib: bool, what: &str) -> Result<()> {
        let slot = if zlib { &mut self.zlib } else { &mut self.raw };
        let d = slot.get_or_insert_with(|| flate2::Decompress::new(zlib));
        d.reset(zlib);
        loop {
            let before = d.total_out();
            let at_in = usize::try_from(d.total_in())
                .unwrap_or(usize::MAX)
                .min(src.len());
            let at_out = usize::try_from(before).unwrap_or(usize::MAX).min(out.len());
            let st = d
                .decompress(
                    &src[at_in..],
                    &mut out[at_out..],
                    flate2::FlushDecompress::Finish,
                )
                .map_err(|e| Error::corrupt(format!("{what}: {e}")))?;
            let done = usize::try_from(d.total_out()).unwrap_or(usize::MAX);
            if done >= out.len() {
                return Ok(());
            }
            if st == flate2::Status::StreamEnd || d.total_out() == before {
                return Err(Error::corrupt(format!(
                    "{what}: decompresses to {done} bytes, not {}",
                    out.len()
                )));
            }
        }
    }

    /// Decodes one zstd frame from `src` into exactly `out.len()` bytes (at most 2 MiB, a
    /// cluster); input left over is ignored.
    pub fn unzstd(&mut self, src: &[u8], out: &mut [u8], what: &str) -> Result<()> {
        use zstd::stream::raw::{DParameter, Decoder, InBuffer, Operation, OutBuffer};
        let fail = |e: io::Error| Error::corrupt(format!("{what}: {e}"));
        if self.zstd.is_none() {
            let mut d = Decoder::new().map_err(fail)?;
            d.set_parameter(DParameter::WindowLogMax(22))
                .map_err(fail)?;
            self.zstd = Some(d);
        }
        let Some(d) = self.zstd.as_mut() else {
            return Err(Error::corrupt(what.to_owned()));
        };
        d.reinit().map_err(fail)?;
        let mut input = InBuffer::around(src);
        let mut output = OutBuffer::around(out);
        loop {
            let before = (input.pos(), output.pos());
            let hint = d.run(&mut input, &mut output).map_err(fail)?;
            if output.pos() == output.capacity() {
                return Ok(());
            }
            if hint == 0 || (input.pos(), output.pos()) == before {
                return Err(Error::corrupt(format!(
                    "{what}: decompresses to {} bytes, not {}",
                    output.pos(),
                    output.capacity()
                )));
            }
        }
    }
}

/// `n` zeroed bytes, refused past `cap` as `UnsupportedOperation` (the caller has checked the
/// file holds them, so it's a limit of BeeZip's, not damage).
pub fn alloc(n: u64, cap: u64, what: &str) -> Result<Vec<u8>> {
    if n > cap {
        return Err(Error::unsupported(format!(
            "{what} of {n} bytes; BeeZip reads them up to {cap}"
        )));
    }
    Ok(vec![
        0u8;
        usize::try_from(n)
            .map_err(|_| Error::unsupported(what.to_owned()))?
    ])
}

pub fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

pub fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or_default())
}

pub fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default())
}

pub fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

pub fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap_or_default())
}

pub fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap_or_default())
}

/// A GUID as Windows writes it, `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` from its mixed-endian
/// bytes, in lowercase.
pub fn guid(b: &[u8; 16]) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}}}",
        le32(b, 0),
        le16(b, 4),
        le16(b, 6),
        b[8],
        b[9],
        b[10..]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}
