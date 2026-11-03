//! A bare compressed file (`notes.txt.gz`) seen as an archive with one entry.
//!
//! - The entry is named from the gzip FNAME field if there is one, otherwise from the file name
//!   minus the codec extensions (`notes.txt.gz` → `notes.txt`, `a.tgz` → `a.tar`).
//! - Its size comes from the xz index, or from gzip's ISIZE trailer when that can't have
//!   wrapped (ISIZE is mod 2³²). Otherwise it is unknown until the data is decoded.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
};
use crate::{
    CodecId, Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    codec::{gzip_header_name, gzip_trailer_size, strip_extension},
    detect::{Confidence, Probe},
    io::read_prefix,
    source::Source,
};

pub struct Stream;

impl ArchiveFormat for Stream {
    fn id(&self) -> FormatId {
        FormatId::Stream
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    /// Never sniffed: it is what's left when a codec's output isn't an archive.
    fn sniff(&self, _: &Probe<'_>) -> Option<Confidence> {
        None
    }

    /// Created through `stream.compress`, not `archive.create`.
    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}

pub struct StreamReader {
    source: Source,
    entries: Vec<Entry>,
    open: Option<Box<dyn Read>>,
}

impl StreamReader {
    pub fn open(source: Source) -> Result<Self> {
        let name = entry_name(&source)?;
        let mut entry = Entry::new(0, name, EntryKind::File);
        entry.packed_size = Some(source.size);
        entry.size = size_hint(&source);
        entry.modified = source.modified;
        entry.method = source.codecs.last().map(|c| c.name());
        Ok(Self {
            source,
            entries: vec![entry],
            open: None,
        })
    }
}

/// The gzip FNAME (for a single gzip layer), else the file name without its codec extensions.
fn entry_name(source: &Source) -> Result<String> {
    if source.codecs == [CodecId::Gzip] {
        let mut file = source.open_file()?;
        if let Some(name) = gzip_header_name(&read_prefix(&mut file, 64 * 1024)) {
            // Only the last component: FNAME is a plain name, but nothing enforces that.
            let base = name.rsplit(['/', '\\']).next().unwrap_or(&name);
            if !base.is_empty() {
                return Ok(base.to_owned());
            }
        }
    }
    let mut name = source.file_name();
    for codec in source.codecs.iter().rev() {
        match strip_extension(&name, *codec) {
            Some(stripped) => name = stripped,
            None => break,
        }
    }
    if name == source.file_name() || name.is_empty() {
        name.push_str(".out");
    }
    Ok(name)
}

/// Known sizes: the xz index, or gzip's ISIZE when the file is too small for it to wrap.
fn size_hint(source: &Source) -> Option<u64> {
    let mut file = File::open(&source.path).ok()?;
    match source.codecs.as_slice() {
        [CodecId::Xz] => lzma_rust2::xz_uncompressed_size(&mut file).ok(),
        // Deflate expands at most about 1032:1, so below ~4 MB of input ISIZE is exact
        // (for a single member).
        [CodecId::Gzip] if source.size.saturating_mul(1032) < 1 << 32 => {
            file.seek(SeekFrom::End(-4)).ok()?;
            let mut tail = [0u8; 4];
            file.read_exact(&mut tail).ok()?;
            gzip_trailer_size(&tail).map(u64::from)
        }
        _ => None,
    }
}

impl ArchiveReader for StreamReader {
    fn format(&self) -> FormatId {
        FormatId::Stream
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Stream,
            codecs: self.source.codecs.clone(),
            methods: Vec::new(),
            comment: None,
            encryption: Encryption::None,
            solid: true,
            sfx: false,
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let entry = self.entries[0].clone();
        if !sel.matches(&entry) {
            return Ok(());
        }
        let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
        meter.entries_total = Some(1);
        meter.current = Some(entry.path.clone());
        let mut data = self.source.guard(self.source.open_stream()?);
        let mut mcx = MeteredCtx::new(cx, &meter);
        mcx.report();
        sink.entry(&entry, &mut data, &mut mcx)?;
        meter.entries_done = 1;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, _: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        if id != 0 {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        }
        let stream = self.open.insert(self.source.open_stream()?);
        Ok(Box::new(self.source.guard(stream)))
    }
}
