//! DMG (docs/M5.md §5.11). STUB: replaced by the UDIF reader and writer and fstool's volumes.

use std::{io::Read, path::Path};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, ArchiveWriter, Entry, EntrySink, FormatCaps,
    FormatId, NewEntry, Selection,
};
use crate::{
    Ctx, Error, Result,
    detect::{Confidence, Probe},
    io::WriteSeek,
    source::Source,
};

pub struct Dmg;

/// The UDIF trailer's magic, at the start of the last 512 bytes.
pub const KOLY: &[u8; 4] = b"koly";
/// An encrypted image: `encrcdsa` at the start (version 2), `cdsaencr` at the end (version 1).
pub const ENCRYPTED_HEAD: &[u8; 8] = b"encrcdsa";
pub const ENCRYPTED_TAIL: &[u8; 8] = b"cdsaencr";

impl ArchiveFormat for Dmg {
    fn id(&self) -> FormatId {
        FormatId::Dmg
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".dmg"]
    }

    /// A `koly` trailer of version 4 and 512 bytes is certain. An encrypted image is likely, so
    /// it opens to be refused with a reason.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        if probe.head.starts_with(ENCRYPTED_HEAD) || probe.tail.ends_with(ENCRYPTED_TAIL) {
            return Some(Confidence::Likely);
        }
        let t = probe.tail;
        let koly = t.len().checked_sub(512).map(|at| &t[at..])?;
        if !koly.starts_with(KOLY) {
            return None;
        }
        let version = u32::from_be_bytes([koly[4], koly[5], koly[6], koly[7]]);
        let size = u32::from_be_bytes([koly[8], koly[9], koly[10], koly[11]]);
        if version == 4 && size == 512 {
            Some(Confidence::Certain)
        } else {
            Some(Confidence::Likely)
        }
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

/// How to write a DMG: an HFS+ volume, as UDZO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DmgWriteOptions {}

pub struct DmgReader {
    _source: Source,
}

impl DmgReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let _ = (source, cx);
        Err(Error::unsupported_format("DMG isn't read yet"))
    }
}

impl ArchiveReader for DmgReader {
    fn format(&self) -> FormatId {
        FormatId::Dmg
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&[])
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Err(Error::unsupported_format("DMG isn't read yet"))
    }

    fn extract(&mut self, _: &Selection, _: &mut dyn EntrySink, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported_format("DMG isn't read yet"))
    }

    fn open_entry(&mut self, _: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        Err(Error::unsupported_format("DMG isn't read yet"))
    }
}

pub struct DmgWriter {
    _out: Box<dyn WriteSeek>,
}

impl DmgWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: DmgWriteOptions, output: &Path) -> Result<Self> {
        let _ = (opts, output);
        Ok(Self { _out: out })
    }
}

impl ArchiveWriter for DmgWriter {
    fn add(&mut self, _: &NewEntry, _: &mut dyn Read, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported("DMG isn't written yet"))
    }

    fn finish(self: Box<Self>, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported("DMG isn't written yet"))
    }
}
