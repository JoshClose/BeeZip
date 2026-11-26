//! The envelope: the key block, slots, header MAC, and sealed records, cells and index
//! (bhive.md §12.2–§12.8). PR A builds it.

use super::{FileKey, Labelled, MadeSlot, Protection, SlotView, not_built};
use crate::{Ctx, Result};

/// What a writer seals with: a file key, a fresh archive id, and the key block that opens it.
/// Shared with the compression workers, which seal cells.
#[derive(Debug)]
#[allow(dead_code, reason = "PR A builds what reads these")]
pub struct Envelope {
    pub(crate) file_key: FileKey,
    pub(crate) archive_id: [u8; 32],
    /// The key block, from its `BHKY` tag through the header MAC.
    pub(crate) key_block: Vec<u8>,
    pub(crate) header_mac: [u8; 32],
    /// Section 5's body, when the writer has descriptions (bhive.md §12.9).
    pub(crate) descriptions: Option<Vec<u8>>,
}

impl Envelope {
    /// For a new archive: a new file key and archive id, a slot for each recipient
    /// ([`super::make_slot`]), and an edit's kept slots under a new archive id.
    pub fn new(protection: &Protection) -> Result<Self> {
        match protection {
            Protection::New(recipients) => Self::fresh(recipients),
            Protection::Keep(unlocked) => Self::kept(unlocked),
        }
    }

    fn fresh(recipients: &[Labelled]) -> Result<Self> {
        let _ = recipients;
        Err(not_built("writing an encrypted .bhive"))
    }

    fn kept(unlocked: &Unlocked) -> Result<Self> {
        let _ = unlocked;
        Err(not_built("editing an encrypted .bhive"))
    }

    /// Wraps the file key into a slot (bhive.md §12.4): the slot's bytes.
    pub fn wrap(&self, kind: super::SlotKind, made: &MadeSlot) -> Result<Vec<u8>> {
        let _ = (kind, made);
        Err(not_built("wrapping a slot"))
    }

    /// The key block, to write after the header.
    pub fn key_block(&self) -> &[u8] {
        &self.key_block
    }

    /// A new cell's id (bhive.md §12.2).
    pub fn new_cell_id(&self) -> Result<[u8; 32]> {
        Err(not_built("cell ids"))
    }

    /// A cell's stored bytes, sealed in segments under its key (bhive.md §12.8).
    pub fn seal_cell(&self, id: &[u8; 32], stored: &[u8]) -> Result<Vec<u8>> {
        let _ = (id, stored);
        Err(not_built("sealing a cell"))
    }

    /// A whole `BHCE` block for the cell block at `offset`: its 12-byte head and the sealed
    /// record of `id`, `head` and `journal` (bhive.md §12.6). The sealed cell follows it.
    pub fn record_block(
        &self,
        offset: u64,
        id: &[u8; 32],
        head: &[u8; 48],
        journal: &[u8],
        sealed_cell_len: u32,
    ) -> Result<Vec<u8>> {
        let _ = (offset, id, head, journal, sealed_cell_len);
        Err(not_built("sealing a record"))
    }

    /// The whole `BHIE` block for `inner`, a §5 index block (bhive.md §12.7).
    pub fn index_block(&self, inner: &[u8]) -> Result<Vec<u8>> {
        let _ = inner;
        Err(not_built("sealing the index"))
    }
}

/// What a reader holds once a slot has opened the archive and the header MAC has passed.
#[derive(Debug)]
#[allow(dead_code, reason = "PR A builds what reads these")]
pub struct Unlocked {
    pub(crate) file_key: FileKey,
    pub(crate) archive_id: [u8; 32],
    /// The slots' bytes, as the key block holds them, for an edit to keep.
    pub(crate) slots: Vec<u8>,
    pub(crate) slot_count: u16,
    pub(crate) header_mac: [u8; 32],
    /// The slot that opened it.
    pub(crate) opened_by: usize,
}

/// A key block, parsed but not opened (bhive.md §12.3).
#[derive(Debug, Clone)]
pub struct KeyBlock {
    pub suite: u8,
    pub archive_id: [u8; 32],
    /// Each slot's kind (`None` for a kind this BeeZip doesn't know) and its bytes' range in
    /// `bytes`.
    pub slots: Vec<(Option<super::SlotKind>, std::ops::Range<usize>)>,
    /// The header and the key block, through the MAC.
    pub bytes: Vec<u8>,
}

impl KeyBlock {
    /// Parses the key block that follows `header` in `r` and checks its framing.
    pub fn read(header: &[u8; 16], r: &mut dyn std::io::Read) -> Result<Self> {
        let _ = (header, r);
        Err(not_built("reading an encrypted .bhive"))
    }

    /// The known slots, to try and to list.
    pub fn views(&self) -> Vec<SlotView<'_>> {
        Vec::new()
    }

    /// The key block's length in the file, after the header.
    pub fn len(&self) -> usize {
        self.bytes.len().saturating_sub(16)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Unlocked {
    /// Opens `block`: tries what this machine has without asking (your software keys through
    /// the context's key source), then asks the context ([`Ctx::unlock`]) for a password, a
    /// recovery key or a way in, as many times as it allows. Checks the header MAC.
    pub fn open(block: &KeyBlock, cx: &mut dyn Ctx) -> Result<Self> {
        let _ = (block, cx);
        Err(not_built("opening an encrypted .bhive"))
    }

    /// A sealed record: the block at `offset` (its 12-byte head and the sealed record) gives
    /// the cell's id, record head and journal as stored.
    pub fn open_record(&self, offset: u64, block: &[u8]) -> Result<([u8; 32], [u8; 48], Vec<u8>)> {
        let _ = (offset, block);
        Err(not_built("reading a sealed record"))
    }

    /// A sealed cell's stored bytes, each segment checked before it is returned.
    pub fn open_cell(&self, id: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
        let _ = (id, sealed);
        Err(not_built("reading a sealed cell"))
    }

    /// The §5 index block inside a `BHIE` block.
    pub fn open_index(&self, block: &[u8]) -> Result<Vec<u8>> {
        let _ = block;
        Err(not_built("reading a sealed index"))
    }
}
