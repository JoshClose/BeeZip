//! A `.bhive` built by hand, part by part: for the fixtures `cargo xtask gen-fixtures` makes and
//! for the tests, which need files the writer never makes: ones that break a rule, ones added
//! to in place, the specification's examples. Nothing here checks what it is given.

use std::sync::atomic::AtomicBool;

use super::{
    coder::{self, Level},
    layout::{self, Cell, Coder, Extent, IndexHead, ItemRef, Kind, Record, checksum, put_item},
};

/// The file so far, and what its index will say.
#[derive(Debug, Clone)]
pub struct Build {
    pub bytes: Vec<u8>,
    /// The index's table: every cell written.
    pub cells: Vec<Cell>,
    /// The index's entries, encoded, and how many.
    pub items: Vec<u8>,
    pub entries: u64,
    /// The items since the last cell: the next cell's journal.
    pub journal: Vec<u8>,
    pub journal_items: u32,
}

impl Default for Build {
    fn default() -> Self {
        Self::new()
    }
}

impl Build {
    /// A file that is a header.
    pub fn new() -> Self {
        Self {
            bytes: layout::header().to_vec(),
            cells: Vec::new(),
            items: Vec::new(),
            entries: 0,
            journal: Vec::new(),
            journal_items: 0,
        }
    }

    /// An entry: into the next cell's journal and the index.
    pub fn item(&mut self, item: &ItemRef<'_>) -> &mut Self {
        let at = self.journal.len();
        put_item(&mut self.journal, item);
        self.items.extend_from_slice(&self.journal[at..]);
        self.journal_items += 1;
        self.entries += 1;
        self
    }

    /// A file of the extents given, with nothing else said about it.
    pub fn file(&mut self, path: &str, extents: &[Extent]) -> &mut Self {
        self.item(&ItemRef {
            kind: Kind::File,
            path: path.as_bytes(),
            modified: None,
            created: None,
            mode: None,
            attrs: None,
            extents,
            target: b"",
        })
    }

    /// The number the next cell gets.
    pub fn next(&self) -> u32 {
        self.cells.len() as u32
    }

    /// A cell of `raw`, coded as `level` codes it, behind a record with the journal so far.
    /// Returns its number.
    pub fn cell(&mut self, raw: &[u8], level: Level) -> u32 {
        let coded = coder::encode(raw, level, &AtomicBool::new(false))
            .unwrap_or_else(|e| panic!("coding a cell: {e}"));
        let data = coded.data.unwrap_or_else(|| raw.to_vec());
        let record = Record {
            number: self.next(),
            raw: raw.len() as u32,
            stored: data.len() as u32,
            coder: coded.coder,
            param: coded.param,
            journal_zstd: false,
            journal_items: self.journal_items,
            journal_raw: self.journal.len() as u32,
            journal_stored: self.journal.len() as u32,
            checksum: checksum(raw),
        };
        let journal = std::mem::take(&mut self.journal);
        self.journal_items = 0;
        self.cell_as(&record, &journal, &data)
    }

    /// A stored cell of `raw`.
    pub fn stored(&mut self, raw: &[u8]) -> u32 {
        self.cell(raw, Level::None)
    }

    /// A cell block exactly as given: `record` over `journal` (as stored) and `data`. The
    /// index's table gets what the record says.
    pub fn cell_as(&mut self, record: &Record, journal: &[u8], data: &[u8]) -> u32 {
        self.bytes.extend_from_slice(&record.encode(journal));
        self.bytes.extend_from_slice(journal);
        self.cells.push(record.cell(self.bytes.len() as u64));
        self.bytes.extend_from_slice(data);
        self.next() - 1
    }

    /// The index's raw bytes for what was built.
    pub fn index(&self, level: Option<u8>) -> Vec<u8> {
        layout::encode_index(&self.cells, self.entries, &self.items, level)
    }

    /// An index block of `raw`, stored, and the footer that points to it.
    pub fn close_with(&mut self, raw: &[u8]) -> &mut Self {
        let offset = self.bytes.len() as u64;
        let head = IndexHead {
            zstd: false,
            stored: raw.len() as u64,
            raw: raw.len() as u64,
            checksum: checksum(raw),
        };
        self.bytes.extend_from_slice(&head.encode());
        self.bytes.extend_from_slice(raw);
        self.bytes.extend_from_slice(&layout::footer(offset));
        self
    }

    /// The index block for what was built, and the footer. More cells may follow, and another
    /// index: a file added to in place.
    pub fn close(&mut self) -> &mut Self {
        if self.journal_items > 0 {
            self.stored(&[]);
        }
        let raw = self.index(None);
        self.close_with(&raw)
    }

    /// The finished file.
    pub fn finish(mut self) -> Vec<u8> {
        self.close();
        self.bytes
    }
}

/// An extent.
pub fn extent(cell: u32, offset: u32, len: u32) -> Extent {
    Extent { cell, offset, len }
}

/// The coder's own name for a level's cells, for fixtures that list what they hold.
pub fn coder_of(level: Level) -> Coder {
    match level {
        Level::None => Coder::Stored,
        Level::Fast | Level::Balanced => Coder::Zstd,
        Level::High | Level::Max => Coder::Lzma2,
    }
}
