//! Reading squashfs 4.0 (docs/M5.md §5.10). STUB: replaced by the in-house reader.

use std::io::Read;

use crate::{
    Ctx, Error, Result,
    format::{ArchiveInfo, ArchiveReader, Entry, EntrySink, FormatId, Selection},
    source::Source,
};

pub struct SquashfsReader {
    _source: Source,
}

impl SquashfsReader {
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let _ = (source, cx);
        Err(Error::unsupported_format("squashfs isn't read yet"))
    }
}

impl ArchiveReader for SquashfsReader {
    fn format(&self) -> FormatId {
        FormatId::Squashfs
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&[])
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Err(Error::unsupported_format("squashfs isn't read yet"))
    }

    fn extract(&mut self, _: &Selection, _: &mut dyn EntrySink, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported_format("squashfs isn't read yet"))
    }

    fn open_entry(&mut self, _: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        Err(Error::unsupported_format("squashfs isn't read yet"))
    }
}
