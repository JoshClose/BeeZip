//! ISO 9660 with Joliet and Rock Ridge, and UDF (docs/M5.md §5.9). STUB.

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

pub struct Iso;

/// Volume descriptors start at sector 16 of 2 048 bytes.
const DESCRIPTORS: usize = 16 * 2048;

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
        let mut found = None;
        for i in 0..3 {
            let at = DESCRIPTORS + i * 2048;
            let Some(d) = probe.head.get(at..at + 7) else {
                break;
            };
            let id = &d[1..6];
            if d[6] != 1 {
                continue;
            }
            if id == b"CD001" || id == b"BEA01" || id == b"NSR02" || id == b"NSR03" {
                found = Some(Confidence::Certain);
                break;
            }
        }
        found
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

/// How to write an ISO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IsoWriteOptions {}

pub struct IsoReader {
    _source: Source,
}

impl IsoReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let _ = (source, cx);
        Err(Error::unsupported_format("ISO isn't read yet"))
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
        Ok(&[])
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Err(Error::unsupported_format("ISO isn't read yet"))
    }

    fn extract(&mut self, _: &Selection, _: &mut dyn EntrySink, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported_format("ISO isn't read yet"))
    }

    fn open_entry(&mut self, _: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        Err(Error::unsupported_format("ISO isn't read yet"))
    }
}

pub struct IsoWriter {
    _out: Box<dyn WriteSeek>,
}

impl IsoWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: IsoWriteOptions, output: &Path) -> Result<Self> {
        let _ = (opts, output);
        Ok(Self { _out: out })
    }
}

impl ArchiveWriter for IsoWriter {
    fn reads_sources(&self) -> bool {
        true
    }

    fn add(&mut self, _: &NewEntry, _: &mut dyn Read, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported("ISO isn't written yet"))
    }

    fn finish(self: Box<Self>, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported("ISO isn't written yet"))
    }
}
