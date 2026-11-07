//! Writing squashfs with backhand (docs/M5.md §5.10). STUB: replaced by the backhand writer.

use std::{io::Read, path::Path};

use super::SquashfsWriteOptions;
use crate::{
    Ctx, Error, Result,
    format::{ArchiveWriter, NewEntry},
    io::WriteSeek,
};

pub struct SquashfsWriter {
    _out: Box<dyn WriteSeek>,
}

impl SquashfsWriter {
    pub fn new(out: Box<dyn WriteSeek>, opts: SquashfsWriteOptions, output: &Path) -> Result<Self> {
        let _ = (opts, output);
        Ok(Self { _out: out })
    }
}

impl ArchiveWriter for SquashfsWriter {
    fn reads_sources(&self) -> bool {
        true
    }

    fn add(&mut self, _: &NewEntry, _: &mut dyn Read, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported("squashfs isn't written yet"))
    }

    fn finish(self: Box<Self>, _: &mut dyn Ctx) -> Result<()> {
        Err(Error::unsupported("squashfs isn't written yet"))
    }
}
