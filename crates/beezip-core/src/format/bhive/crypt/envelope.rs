//! The envelope: the key block, slots, header MAC, and sealed records, cells and index
//! (bhive.md §12.2–§12.8).
//!
//! - **Writing,** an [`Envelope`] holds the file key and the key block it opens with. It is made
//!   for new ways in ([`Envelope::fresh`]), for an edit that keeps the archive's key and slots
//!   ([`Envelope::kept`]), or with ways in added and removed under the same key.
//! - **Reading,** a [`KeyBlock`] is parsed and framed before anything is tried, then
//!   [`Unlocked::open`] finds a slot that opens and checks the header MAC before the file key is
//!   used for anything else.

use std::{io::Read, ops::Range, sync::OnceLock};

use ring::aead::LessSafeKey;
use zeroize::Zeroizing;

use super::{
    Description, FileKey, KEY_ID_LEN, Labelled, MAX_PASSWORD_SLOTS, MAX_SLOTS, MAX_SLOTS_LEN,
    MadeSlot, Protection, SLOT_TAIL_LEN, SUITE_1, SlotKind, SlotSecret, SlotView, TAG_LEN,
    UnlockAnswer, UnlockRequest, WayInfo, check_public, encode_descriptions, label, make_slot,
    password, prim, recovery, split_descriptions,
};
use crate::{
    Ctx, Error, ErrorKind, Result,
    format::bhive::layout::{
        self, HEADER_LEN, KEY_BLOCK_HEAD_LEN, KEY_TAG, RECORD_LEN, SEALED_CELL_HEAD_LEN,
        SEALED_CELL_TAG, SEALED_INDEX_HEAD_LEN, SEALED_INDEX_TAG, bad, sealed_len,
    },
};

/// How many answers an unlock takes before it gives up, whatever the context allows.
const MAX_ATTEMPTS: u32 = 64;
/// The least a sealed record holds: a cell id, a record head, a tag.
const MIN_RECORD: usize = 32 + RECORD_LEN + TAG_LEN;

/// The keys every sealed part is under, derived from the file key (bhive.md §12.2).
struct Keys {
    record: LessSafeKey,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(***)")
    }
}

impl Keys {
    fn new(file_key: &FileKey, archive_id: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            record: prim::key(&prim::hkdf(&file_key.0[..], archive_id, label::RECORD))?,
        })
    }
}

fn cell_key(file_key: &FileKey, id: &[u8; 32]) -> Result<LessSafeKey> {
    prim::key(&prim::hkdf(&file_key.0[..], id, label::CELL))
}

fn index_key(file_key: &FileKey, salt: &[u8]) -> Result<LessSafeKey> {
    prim::key(&prim::hkdf(&file_key.0[..], salt, label::INDEX))
}

/// A slot's wrap key and commitment, from its PRK (bhive.md §12.4 step 3).
fn slot_keys(prk: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let okm = prim::expand64(prk, label::SLOT);
    let mut wrap = Zeroizing::new([0u8; 32]);
    wrap.copy_from_slice(&okm[..32]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&okm[32..]);
    (wrap, commitment)
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Wraps `file_key` into a slot of `kind` under `key_id` (bhive.md §12.4): the slot's bytes.
fn wrap_with(
    file_key: &FileKey,
    key_id: &[u8; KEY_ID_LEN],
    kind: SlotKind,
    made: &MadeSlot,
) -> Result<Vec<u8>> {
    let body = u16::try_from(made.public.len() + SLOT_TAIL_LEN)
        .map_err(|_| Error::invalid_args("bhive: a slot too large"))?;
    let mut slot = Vec::with_capacity(4 + usize::from(body));
    slot.extend_from_slice(&[kind.id(), 0]);
    slot.extend_from_slice(&body.to_le_bytes());
    slot.extend_from_slice(&made.public);
    let SlotSecret::Shared(secret) = &made.secret else {
        return Err(Error::new(
            ErrorKind::Io,
            "bhive: a slot is made from its secret, not from a PRK",
        ));
    };
    // The context doesn't cover the commitment, which comes from it.
    let view = SlotView {
        index: 0,
        kind,
        key_id,
        framed: &slot,
        public: &slot[4..],
        commitment: &[0; 32],
    };
    let prk = Zeroizing::new(prim::hmac(&view.context(&made.recipient_key), &[secret]));
    let (wrap, commitment) = slot_keys(&prk);
    let mut wrapped = Zeroizing::new(file_key.0.to_vec());
    prim::seal(&prim::key(&wrap)?, [0; 12], &slot, &mut wrapped)?;
    slot.extend_from_slice(&commitment);
    slot.extend_from_slice(&wrapped);
    Ok(slot)
}

/// Each slot's bytes in `slots`, as a key block holds them; they were framed when it was read.
fn split_slots(slots: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= slots.len() {
        let end = (at + 4 + usize::from(u16_at(slots, at + 2))).min(slots.len());
        out.push(&slots[at..end]);
        at = end;
    }
    out
}

/// What a writer seals with: a file key, a fresh archive id, and the key block that opens it.
/// Shared with the compression workers, which seal cells.
#[derive(Debug)]
pub struct Envelope {
    pub(crate) file_key: FileKey,
    /// Made with the file key, kept with it (bhive.md §12.2).
    pub(crate) key_id: [u8; 16],
    pub(crate) archive_id: [u8; 32],
    /// The key block, from its `BHKY` tag through the header MAC.
    pub(crate) key_block: Vec<u8>,
    pub(crate) header_mac: [u8; 32],
    /// Section 5's body, when the writer has descriptions (bhive.md §12.9).
    pub(crate) descriptions: Option<Vec<u8>>,
    keys: Keys,
}

impl Envelope {
    /// For a new archive: a new file key and archive id, a slot for each recipient
    /// ([`super::make_slot`]), and an edit's kept slots under a new archive id.
    pub fn new(protection: &Protection) -> Result<Self> {
        match protection {
            Protection::New(recipients) => Self::fresh(recipients),
            Protection::Keep(unlocked) => Self::kept(unlocked),
            Protection::Change { from, remove, add } => Self::changed(from, remove, add),
        }
    }

    /// A new file key and key id, and a slot of fresh randomness for each recipient.
    fn fresh(recipients: &[Labelled]) -> Result<Self> {
        let file_key = FileKey(Zeroizing::new(prim::random()?));
        let key_id = prim::random()?;
        let kinds: Vec<SlotKind> = recipients.iter().map(|r| r.recipient.kind()).collect();
        let bound: Vec<bool> = recipients
            .iter()
            .map(|r| Description::of(r).machine_bound)
            .collect();
        check_ways(&kinds, &bound)?;
        let mut slots = Vec::new();
        for r in recipients {
            let made = make_slot(&r.recipient)?;
            slots.extend_from_slice(&wrap_with(&file_key, &key_id, r.recipient.kind(), &made)?);
        }
        let entries: Vec<Vec<u8>> = recipients
            .iter()
            .map(|r| Description::of(r).encode())
            .collect();
        Self::assemble(
            file_key,
            key_id,
            recipients.len(),
            slots,
            Some(encode_descriptions(&entries)),
        )
    }

    /// The archive's file key, key id and slots, byte for byte, under a new archive id.
    fn kept(unlocked: &Unlocked) -> Result<Self> {
        Self::assemble(
            unlocked.file_key.clone(),
            unlocked.key_id,
            usize::from(unlocked.slot_count),
            unlocked.slots.clone(),
            unlocked.descriptions.get().cloned(),
        )
    }

    /// The archive's slots less `remove`, and a slot for each of `add`, under its file key.
    fn changed(from: &Unlocked, remove: &[usize], add: &[Labelled]) -> Result<Self> {
        let old = split_slots(&from.slots);
        if let Some(&n) = remove.iter().find(|&&n| n >= old.len()) {
            return Err(Error::invalid_args(format!(
                "bhive: the archive has no way in {n}: it has {}",
                old.len()
            )));
        }
        let entries = from
            .descriptions
            .get()
            .and_then(|d| split_descriptions(d, old.len()))
            .unwrap_or_else(|| vec![Vec::new(); old.len()]);
        let (mut kinds, mut bound, mut slots, mut descs) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (n, slot) in old.iter().enumerate() {
            if remove.contains(&n) {
                continue;
            }
            // A kind this BeeZip doesn't know counts as a way in that works elsewhere.
            if let Some(kind) = from.kinds.get(n).copied().flatten() {
                kinds.push(kind);
            }
            bound.push(Description::parse(&entries[n]).is_ok_and(|d| d.machine_bound));
            slots.extend_from_slice(slot);
            descs.push(entries[n].clone());
        }
        for r in add {
            kinds.push(r.recipient.kind());
            bound.push(Description::of(r).machine_bound);
            let made = make_slot(&r.recipient)?;
            slots.extend_from_slice(&wrap_with(
                &from.file_key,
                &from.key_id,
                r.recipient.kind(),
                &made,
            )?);
            descs.push(Description::of(r).encode());
        }
        check_ways(&kinds, &bound)?;
        Self::assemble(
            from.file_key.clone(),
            from.key_id,
            descs.len(),
            slots,
            Some(encode_descriptions(&descs)),
        )
    }

    /// The key block of `count` slots and its MAC, under a new archive id.
    fn assemble(
        file_key: FileKey,
        key_id: [u8; KEY_ID_LEN],
        count: usize,
        slots: Vec<u8>,
        descriptions: Option<Vec<u8>>,
    ) -> Result<Self> {
        if count == 0 {
            return Err(Error::invalid_args(
                "bhive: an encrypted archive needs a way in",
            ));
        }
        if count > MAX_SLOTS || slots.len() > MAX_SLOTS_LEN {
            return Err(Error::invalid_args(format!(
                "bhive: {count} ways in, {} bytes of them: an archive holds at most {MAX_SLOTS}, \
                 and {MAX_SLOTS_LEN} bytes",
                slots.len()
            )));
        }
        let archive_id: [u8; 32] = prim::random()?;
        let mut kb = Vec::with_capacity(KEY_BLOCK_HEAD_LEN + slots.len() + 32);
        kb.extend_from_slice(&KEY_TAG);
        kb.extend_from_slice(&[SUITE_1, 0]);
        kb.extend_from_slice(&(count as u16).to_le_bytes());
        kb.extend_from_slice(&(slots.len() as u32).to_le_bytes());
        kb.extend_from_slice(&archive_id);
        kb.extend_from_slice(&key_id);
        kb.extend_from_slice(&slots);
        let mac_key = prim::hkdf(&file_key.0[..], &archive_id, label::MAC);
        let header_mac = prim::hmac(&mac_key[..], &[&layout::header_encrypted(), &kb]);
        kb.extend_from_slice(&header_mac);
        let keys = Keys::new(&file_key, &archive_id)?;
        Ok(Self {
            file_key,
            key_id,
            archive_id,
            key_block: kb,
            header_mac,
            descriptions,
            keys,
        })
    }

    /// Wraps the file key into a slot (bhive.md §12.4): the slot's bytes.
    pub fn wrap(&self, kind: SlotKind, made: &MadeSlot) -> Result<Vec<u8>> {
        wrap_with(&self.file_key, &self.key_id, kind, made)
    }

    /// The archive id this envelope writes, and its file key's key id.
    pub fn archive_id(&self) -> &[u8; 32] {
        &self.archive_id
    }

    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }

    /// The key block, to write after the header.
    pub fn key_block(&self) -> &[u8] {
        &self.key_block
    }

    /// Whether `unlocked` has this envelope's file key: its sealed cells copy as they are.
    pub fn same_key(&self, unlocked: &Unlocked) -> bool {
        self.key_id == unlocked.key_id && prim::same(&self.file_key.0[..], &unlocked.file_key.0[..])
    }

    /// A new cell's id (bhive.md §12.2).
    pub fn new_cell_id(&self) -> Result<[u8; 32]> {
        prim::random()
    }

    /// A cell's stored bytes, sealed in segments under its key (bhive.md §12.8).
    pub fn seal_cell(&self, id: &[u8; 32], stored: &[u8]) -> Result<Vec<u8>> {
        prim::seal_segments(&cell_key(&self.file_key, id)?, stored, &[])
    }

    /// A whole `BHCE` block for the cell block at `offset`: its 24-byte head with a fresh
    /// nonce, and the sealed record of `id`, `head` and `journal`, the offset in its associated
    /// data (bhive.md §12.6). The sealed cell follows it.
    pub fn record_block(
        &self,
        offset: u64,
        id: &[u8; 32],
        head: &[u8; 48],
        journal: &[u8],
        sealed_cell_len: u32,
    ) -> Result<Vec<u8>> {
        let stored = u64::from(u32_at(head, 12));
        if u64::from(sealed_cell_len) != sealed_len(stored) {
            return Err(Error::new(
                ErrorKind::Io,
                "bhive: a sealed cell's length isn't its stored length's",
            ));
        }
        let r = u32::try_from(MIN_RECORD + journal.len())
            .map_err(|_| Error::limit("bhive: a journal too large"))?;
        let nonce: [u8; 12] = prim::random()?;
        let mut block = Vec::with_capacity(SEALED_CELL_HEAD_LEN + r as usize);
        block.extend_from_slice(&SEALED_CELL_TAG);
        block.extend_from_slice(&r.to_le_bytes());
        block.extend_from_slice(&sealed_cell_len.to_le_bytes());
        block.extend_from_slice(&nonce);
        let mut aad = [0u8; SEALED_CELL_HEAD_LEN + 8];
        aad[..SEALED_CELL_HEAD_LEN].copy_from_slice(&block);
        aad[SEALED_CELL_HEAD_LEN..].copy_from_slice(&offset.to_le_bytes());
        let mut record = Vec::with_capacity(r as usize);
        record.extend_from_slice(id);
        record.extend_from_slice(head);
        record.extend_from_slice(journal);
        prim::seal(&self.keys.record, nonce, &aad, &mut record)?;
        block.extend_from_slice(&record);
        Ok(block)
    }

    /// The whole `BHIE` block for `inner`, a §5 index block (bhive.md §12.7).
    pub fn index_block(&self, inner: &[u8]) -> Result<Vec<u8>> {
        let salt: [u8; 32] = prim::random()?;
        let mut block = Vec::with_capacity(SEALED_INDEX_HEAD_LEN + inner.len() + TAG_LEN);
        block.extend_from_slice(&SEALED_INDEX_TAG);
        block.extend_from_slice(&[0; 4]);
        block.extend_from_slice(&sealed_len(inner.len() as u64).to_le_bytes());
        block.extend_from_slice(&salt);
        let mut aad = self.header_mac.to_vec();
        aad.extend_from_slice(&block);
        let sealed = prim::seal_segments(&index_key(&self.file_key, &salt)?, inner, &aad)?;
        block.extend_from_slice(&sealed);
        Ok(block)
    }
}

/// The rules every writer keeps (bhive.md §12.3, §12.5; docs/M14.md decision 11): at most 4
/// password slots, and a way in that leaves the machine.
fn check_ways(kinds: &[SlotKind], machine_bound: &[bool]) -> Result<()> {
    let passwords = kinds.iter().filter(|&&k| k == SlotKind::Password).count();
    if passwords > MAX_PASSWORD_SLOTS {
        return Err(Error::invalid_args(format!(
            "bhive: {passwords} passwords: an archive takes at most {MAX_PASSWORD_SLOTS}"
        )));
    }
    if !machine_bound.is_empty() && machine_bound.iter().all(|&b| b) {
        return Err(Error::invalid_args(
            "bhive: every way in is bound to this PC (its TPM or Windows Hello), so the archive \
             would open nowhere else: add a password, a recovery key or someone's key",
        ));
    }
    Ok(())
}

/// What a reader holds once a slot has opened the archive and the header MAC has passed.
#[derive(Debug)]
pub struct Unlocked {
    pub(crate) file_key: FileKey,
    pub(crate) key_id: [u8; 16],
    pub(crate) archive_id: [u8; 32],
    /// The slots' bytes, as the key block holds them, for an edit to keep.
    pub(crate) slots: Vec<u8>,
    pub(crate) slot_count: u16,
    pub(crate) header_mac: [u8; 32],
    /// The slot that opened it.
    pub(crate) opened_by: usize,
    /// Each slot's kind, `None` for a kind this BeeZip doesn't know.
    pub(crate) kinds: Vec<Option<SlotKind>>,
    /// Section 5's body, once the index is read, when its count is the slot count.
    pub(crate) descriptions: OnceLock<Vec<u8>>,
    keys: Keys,
}

/// A key block, parsed but not opened (bhive.md §12.3).
#[derive(Debug, Clone)]
pub struct KeyBlock {
    pub suite: u8,
    pub archive_id: [u8; 32],
    pub key_id: [u8; 16],
    /// Each slot's kind (`None` for a kind this BeeZip doesn't know) and its bytes' range in
    /// `bytes`.
    pub slots: Vec<(Option<super::SlotKind>, std::ops::Range<usize>)>,
    /// The header and the key block, through the MAC.
    pub bytes: Vec<u8>,
}

fn cut_off(e: &std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        bad("the key block is cut off")
    } else {
        crate::io::read_error(e)
    }
}

impl KeyBlock {
    /// Parses the key block that follows `header` in `r` and checks its framing (bhive.md
    /// §12.10): the tag, the suite, the counts and lengths, each known slot's public part, and
    /// at most 4 password slots.
    pub fn read(header: &[u8; 16], r: &mut dyn Read) -> Result<Self> {
        let mut head = [0u8; KEY_BLOCK_HEAD_LEN];
        r.read_exact(&mut head).map_err(|e| cut_off(&e))?;
        if head[..4] != KEY_TAG {
            return Err(bad("an encrypted archive without its key block"));
        }
        let suite = head[4];
        if suite != SUITE_1 {
            return Err(Error::unsupported_format(format!(
                "bhive: the archive was made by a newer program: it is sealed with suite \
                 {suite}, which this BeeZip doesn't have"
            )));
        }
        let count = usize::from(u16_at(&head, 6));
        if count == 0 || count > MAX_SLOTS {
            return Err(bad(format!("a key block of {count} slots (1 to 64)")));
        }
        let len = u32_at(&head, 8) as usize;
        if len > MAX_SLOTS_LEN {
            return Err(bad(format!(
                "a key block of {len} bytes of slots (at most 65,536)"
            )));
        }
        let mut bytes = Vec::with_capacity(HEADER_LEN + KEY_BLOCK_HEAD_LEN + len + 32);
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(&head);
        bytes.resize(HEADER_LEN + KEY_BLOCK_HEAD_LEN + len + 32, 0);
        r.read_exact(&mut bytes[HEADER_LEN + KEY_BLOCK_HEAD_LEN..])
            .map_err(|e| cut_off(&e))?;
        let start = HEADER_LEN + KEY_BLOCK_HEAD_LEN;
        let mut slots = Vec::with_capacity(count);
        let (mut at, mut passwords) = (start, 0);
        for n in 0..count {
            if at + 4 > start + len {
                return Err(bad(format!("slot {n} runs past the key block's slots")));
            }
            let body = usize::from(u16_at(&bytes, at + 2));
            if body < SLOT_TAIL_LEN || at + 4 + body > start + len {
                return Err(bad(format!(
                    "slot {n} has a body of {body} bytes, which doesn't fit"
                )));
            }
            let kind = SlotKind::from_id(bytes[at]);
            if let Some(kind) = kind {
                check_public(kind, &bytes[at + 4..at + 4 + body - SLOT_TAIL_LEN])?;
                passwords += usize::from(kind == SlotKind::Password);
            }
            slots.push((kind, at..at + 4 + body));
            at += 4 + body;
        }
        if at != start + len {
            return Err(bad(
                "the key block's slots length isn't the sum of its slots",
            ));
        }
        if passwords > MAX_PASSWORD_SLOTS {
            return Err(bad(format!(
                "a key block of {passwords} password slots (at most {MAX_PASSWORD_SLOTS})"
            )));
        }
        let mut archive_id = [0u8; 32];
        archive_id.copy_from_slice(&head[12..44]);
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&head[44..60]);
        Ok(Self {
            suite,
            archive_id,
            key_id,
            slots,
            bytes,
        })
    }

    /// The known slots, to try and to list.
    pub fn views(&self) -> Vec<SlotView<'_>> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, (kind, range))| {
                let framed = &self.bytes[range.start..range.end - SLOT_TAIL_LEN];
                let tail = range.end - SLOT_TAIL_LEN;
                let commitment = self.bytes[tail..tail + 32]
                    .try_into()
                    .expect("a slot's tail holds its commitment");
                kind.map(|kind| SlotView {
                    index,
                    kind,
                    key_id: &self.key_id,
                    framed,
                    public: &framed[4..],
                    commitment,
                })
            })
            .collect()
    }

    /// The key block's length in the file, after the header.
    pub fn len(&self) -> usize {
        self.bytes.len().saturating_sub(16)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The kinds of every slot, in order: what anyone can see of who can open the archive.
    pub fn kinds(&self) -> Vec<Option<SlotKind>> {
        self.slots.iter().map(|(k, _)| *k).collect()
    }

    /// Tries `secret` on `view`: `None` when its commitment isn't the slot's (a wrong secret);
    /// `Corrupt` when the commitment matches and the key or the header MAC doesn't.
    fn try_slot(&self, view: &SlotView<'_>, secret: &SlotSecret) -> Result<Option<Unlocked>> {
        let prk: Zeroizing<[u8; 32]> = match secret {
            SlotSecret::Extracted(prk) => prk.clone(),
            SlotSecret::Shared(_)
                if matches!(
                    view.kind,
                    SlotKind::X25519 | SlotKind::EcP256 | SlotKind::EcP384
                ) =>
            {
                return Err(Error::new(
                    ErrorKind::Io,
                    format!(
                        "bhive: a key source gave slot {} of kind {} its shared secret, not its \
                         PRK",
                        view.index,
                        view.kind.id()
                    ),
                ));
            }
            SlotSecret::Shared(s) => Zeroizing::new(prim::hmac(&view.context(&[]), &[s])),
        };
        let (wrap, commitment) = slot_keys(&prk);
        let range: &Range<usize> = &self.slots[view.index].1;
        let tail = &self.bytes[range.end - SLOT_TAIL_LEN..range.end];
        if !prim::same(&commitment, &tail[..32]) {
            return Ok(None);
        }
        // Opened in place, it holds the file key: wiped when dropped, as the key is.
        let mut wrapped = Zeroizing::new(tail[32..].to_vec());
        let Some(32) = prim::open(&prim::key(&wrap)?, [0; 12], view.framed, &mut wrapped) else {
            return Err(bad(format!(
                "slot {} fits the secret, but the key it holds doesn't open: the file is damaged",
                view.index
            )));
        };
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&wrapped[..32]);
        let file_key = FileKey(k);
        let mac_key = prim::hkdf(&file_key.0[..], &self.archive_id, label::MAC);
        let mac_at = self.bytes.len() - 32;
        let mac = prim::hmac(&mac_key[..], &[&self.bytes[..mac_at]]);
        if !prim::same(&mac, &self.bytes[mac_at..]) {
            return Err(bad(
                "the header MAC fails: the slots or the header were changed, or the file is \
                 damaged",
            ));
        }
        let start = HEADER_LEN + KEY_BLOCK_HEAD_LEN;
        Ok(Some(Unlocked {
            keys: Keys::new(&file_key, &self.archive_id)?,
            file_key,
            key_id: self.key_id,
            archive_id: self.archive_id,
            slots: self.bytes[start..mac_at].to_vec(),
            slot_count: self.slots.len() as u16,
            header_mac: mac,
            opened_by: view.index,
            kinds: self.kinds(),
            descriptions: OnceLock::new(),
        }))
    }
}

/// An unlock that no answer can satisfy: no slot takes a password or a recovery key, and no key
/// here fits.
fn key_required(views: &[SlotView<'_>]) -> Error {
    let mut kinds: Vec<u8> = views.iter().map(|v| v.kind.id()).collect();
    kinds.dedup();
    Error::new(
        ErrorKind::KeyRequired,
        format!(
            "bhive: no key or device here opens this archive (its ways in are of kinds {kinds:?}); \
             it opens with someone's key, a certificate or a device"
        ),
    )
}

/// Whether a password slot whose Argon2 takes `need` bytes asks first, on a machine with
/// `total` (docs/M14.md §5): when it is more than half.
fn asks_first(need: u64, total: u64) -> bool {
    need > total / 2
}

/// What an unlock knows of its password slots' memory (docs/M14.md §5): whether each may spend
/// it, asked at most once a slot, and why the last slot that couldn't be tried wasn't.
struct Memory {
    /// By slot: `Some(false)` once its memory was refused, or wasn't there to be had.
    allowed: Vec<Option<bool>>,
    refused: Option<Error>,
    /// This machine's memory, when the system says.
    total: Option<u64>,
}

impl Memory {
    fn new(slots: usize, total: Option<u64>) -> Self {
        Self {
            allowed: vec![None; slots],
            refused: None,
            total,
        }
    }

    /// Whether `v`'s Argon2 may run: the context is asked, once, about a slot that takes more
    /// than half the machine's memory.
    fn allows(&mut self, v: &SlotView<'_>, cx: &mut dyn Ctx) -> Result<bool> {
        if let Some(ok) = self.allowed[v.index] {
            return Ok(ok);
        }
        let ok = match (password::memory(v.public), self.total) {
            (Some(need), Some(total)) if asks_first(need, total) => {
                let ok = cx.spend_memory(need, total)?;
                if !ok {
                    self.refused = Some(Error::limit(format!(
                        "bhive: slot {}'s password takes {} MiB of memory, more than half of this \
                         machine's {} MiB, and it wasn't allowed to spend it",
                        v.index,
                        need >> 20,
                        total >> 20
                    )));
                }
                ok
            }
            _ => true,
        };
        self.allowed[v.index] = Some(ok);
        Ok(ok)
    }

    /// `v`'s Argon2 couldn't have its memory: it isn't tried again.
    fn failed(&mut self, v: &SlotView<'_>, e: Error) {
        self.allowed[v.index] = Some(false);
        self.refused = Some(e);
    }
}

impl Unlocked {
    /// Opens `block`: tries the secrets the context kept from an earlier open
    /// ([`Ctx::kept_secret`]) and what this machine has without asking (your software keys
    /// through the context's key source), then asks the context ([`Ctx::unlock`]) for a
    /// password, a recovery key or a way in, as many times as it allows. A way in chosen that doesn't open
    /// it (another security key, a closed dialog, a refused PIN) is asked again for, as a wrong
    /// password is, while another answer could still open the archive; a cancelled Unlock
    /// prompt ends it. A password slot that takes more than half the machine's memory is tried
    /// only when the context says to ([`Ctx::spend_memory`]). Checks the header MAC. The
    /// secret that opened it goes back to the context ([`Ctx::keep_secret`]), however it came.
    pub fn open(block: &KeyBlock, cx: &mut dyn Ctx) -> Result<Self> {
        Self::open_with(block, cx, super::super::mem::physical())
    }

    fn open_with(block: &KeyBlock, cx: &mut dyn Ctx, total: Option<u64>) -> Result<Self> {
        let views = block.views();
        if views.is_empty() {
            return Err(Error::unsupported_format(
                "bhive: the archive was made by a newer program: none of its ways in is one \
                 this BeeZip has",
            ));
        }
        // What opened this archive before, kept by the context (a desktop tab's): nobody is
        // asked and no device is touched, whatever the slot's kind.
        for v in &views {
            if let Some(secret) = cx.kept_secret(v)
                && let Some(u) = block.try_slot(v, &secret)?
            {
                cx.keep_secret(v, &secret);
                return Ok(u);
            }
        }
        // Keys this machine has open without anyone being asked; devices wait to be chosen, as
        // do keys with a PIN that BeeZip asks for.
        let mut here = vec![false; views.len()];
        let mut needs_pin = vec![false; views.len()];
        if let Some(source) = cx.key_source() {
            for (i, v) in views.iter().enumerate() {
                here[i] = source.offers(v);
                if !here[i] {
                    continue;
                }
                needs_pin[i] = source.needs_pin(v);
                if v.kind.needs_device() {
                    continue;
                }
                if let Some(secret) = source.secret(v, false)?
                    && let Some(u) = block.try_slot(v, &secret)?
                {
                    cx.keep_secret(v, &secret);
                    return Ok(u);
                }
            }
        }
        let typed = views
            .iter()
            .any(|v| matches!(v.kind, SlotKind::Password | SlotKind::RecoveryKey));
        let ways: Vec<WayInfo> = views
            .iter()
            .zip(here.iter().zip(&needs_pin))
            .map(|(v, (&here, &needs_pin))| WayInfo {
                slot: v.index as u32,
                kind: v.kind,
                here,
                needs_pin,
            })
            .collect();
        let mut memory = Memory::new(block.slots.len(), total);
        // Why the way in the last answer chose didn't open it, when its key or device failed.
        let mut failed: Option<Error> = None;
        for attempt in 0..MAX_ATTEMPTS {
            let request = UnlockRequest {
                ways: ways.clone(),
                attempt,
                // What the person didn't do themselves: a closed dialog needs no reason.
                failed: failed
                    .as_ref()
                    .filter(|e| e.kind != ErrorKind::Cancelled)
                    .map(|e| e.message.clone()),
            };
            let answer = match cx.unlock(&request) {
                Ok(a) => a,
                // A context with no answer after the first may say a key is needed instead.
                Err(e)
                    if matches!(
                        e.kind,
                        ErrorKind::PasswordRequired | ErrorKind::WrongPassword
                    ) || (attempt > 0 && e.kind == ErrorKind::KeyRequired) =>
                {
                    // Nobody left to ask: the device the last answer chose, or a slot that
                    // couldn't be tried, says why first.
                    return Err(match failed.take().or_else(|| memory.refused.take()) {
                        Some(why) => why,
                        None if !typed => key_required(&views),
                        None => e,
                    });
                }
                Err(e) => return Err(e),
            };
            failed = None;
            if let Some(u) = Self::answer(block, &views, &answer, &mut memory, &mut failed, cx)? {
                return Ok(u);
            }
            // Nothing left that another answer could open. A way in here whose device failed
            // is still one: the right security key may be plugged in, the dialog not closed.
            let left = views.iter().zip(&here).any(|(v, &here)| {
                here || match v.kind {
                    SlotKind::Password => memory.allowed[v.index] != Some(false),
                    SlotKind::RecoveryKey => true,
                    _ => false,
                }
            });
            if !left && let Some(why) = failed.take().or_else(|| memory.refused.take()) {
                return Err(why);
            }
        }
        Err(failed.or(memory.refused).unwrap_or_else(|| {
            Error::new(
                ErrorKind::WrongPassword,
                "bhive: none of the answers opened the archive",
            )
        }))
    }

    /// Tries an answer on the slots it fits. A password that is 48 digits and nothing else is
    /// tried as a recovery key too, for a context that only asks for passwords. A way in whose
    /// key or device fails opens nothing, and `failed` says why; only a damaged slot, or a
    /// cancelled job, is an error. The secret that opens it goes to [`Ctx::keep_secret`].
    fn answer(
        block: &KeyBlock,
        views: &[SlotView<'_>],
        answer: &UnlockAnswer,
        memory: &mut Memory,
        failed: &mut Option<Error>,
        cx: &mut dyn Ctx,
    ) -> Result<Option<Self>> {
        let of = |kind: SlotKind| views.iter().filter(move |v| v.kind == kind);
        match answer {
            UnlockAnswer::Password(p) => {
                for v in of(SlotKind::Password) {
                    if !memory.allows(v, cx)? {
                        continue;
                    }
                    cx.check()?;
                    let secret = match password::secret(v, p) {
                        Ok(s) => s,
                        // Memory that isn't free: the other slots may still open.
                        Err(e) if e.kind == ErrorKind::LimitExceeded => {
                            memory.failed(v, e);
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    if let Some(u) = block.try_slot(v, &secret)? {
                        cx.keep_secret(v, &secret);
                        return Ok(Some(u));
                    }
                }
                if recovery::typed_as_password(p) {
                    let key = UnlockAnswer::RecoveryKey(p.clone());
                    return Self::answer(block, views, &key, memory, failed, cx);
                }
                Ok(None)
            }
            UnlockAnswer::RecoveryKey(typed) => {
                if recovery::parse(typed).is_err() {
                    return Ok(None);
                }
                for v in of(SlotKind::RecoveryKey) {
                    let secret = recovery::secret(v, typed)?;
                    if let Some(u) = block.try_slot(v, &secret)? {
                        cx.keep_secret(v, &secret);
                        return Ok(Some(u));
                    }
                }
                Ok(None)
            }
            UnlockAnswer::Way { slot, pin } => {
                let Some(v) = views.iter().find(|v| v.index as u32 == *slot) else {
                    return Ok(None);
                };
                let Some(source) = cx.key_source() else {
                    return Ok(None);
                };
                let secret = match pin {
                    Some(pin) => source.secret_with_pin(v, pin),
                    None => source.secret(v, true),
                };
                match secret {
                    Ok(Some(secret)) => {
                        let opened = block.try_slot(v, &secret)?;
                        if opened.is_some() {
                            cx.keep_secret(v, &secret);
                        }
                        Ok(opened)
                    }
                    Ok(None) => Ok(None),
                    // Another try won't mend a damaged slot.
                    Err(e) if e.kind == ErrorKind::Corrupt => Err(e),
                    // Another security key, a closed dialog, a wrong PIN, a device that
                    // couldn't be reached, a TPM that Windows is blocking: the archive may open
                    // another way, or this one again.
                    Err(e) => {
                        cx.check()?;
                        if e.kind != ErrorKind::Cancelled {
                            cx.warn(format!(
                                "bhive: slot {}'s key or device didn't open the archive: {}",
                                v.index, e.message
                            ));
                        }
                        *failed = Some(e);
                        Ok(None)
                    }
                }
            }
        }
    }

    /// The archive id of the file it opened, and the key id of its file key (bhive.md §12.2).
    pub fn archive_id(&self) -> &[u8; 32] {
        &self.archive_id
    }

    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }

    /// Each slot's kind, in the key block's order; `None` for kinds this BeeZip doesn't know.
    pub fn kinds(&self) -> &[Option<SlotKind>] {
        &self.kinds
    }

    /// The slot that opened the archive.
    pub fn opened_by(&self) -> usize {
        self.opened_by
    }

    /// What section 5 says of each slot, when the archive has it (bhive.md §12.9). Claims, not
    /// facts: anyone who has held the file key can write them.
    pub fn descriptions(&self) -> Option<Vec<Description>> {
        let entries = split_descriptions(self.descriptions.get()?, self.kinds.len())?;
        Some(
            entries
                .iter()
                .map(|e| Description::parse(e).unwrap_or_default())
                .collect(),
        )
    }

    /// Keeps section 5's body when its count is the slot count; otherwise it is ignored.
    pub(crate) fn set_descriptions(&self, body: &[u8]) {
        if split_descriptions(body, self.kinds.len()).is_some() {
            let _ = self.descriptions.set(body.to_vec());
        }
    }

    /// A sealed record: the block at `offset` (its 24-byte head and the sealed record) gives
    /// the cell's id, record head and journal as stored. The record head's stored length must
    /// make the block's sealed cell length (bhive.md §12.6).
    pub fn open_record(&self, offset: u64, block: &[u8]) -> Result<([u8; 32], [u8; 48], Vec<u8>)> {
        if block.len() < SEALED_CELL_HEAD_LEN + MIN_RECORD || block[..4] != SEALED_CELL_TAG {
            return Err(bad(format!("no sealed cell block at {offset}")));
        }
        let r = u32_at(block, 4) as usize;
        let c = u64::from(u32_at(block, 8));
        if r != block.len() - SEALED_CELL_HEAD_LEN {
            return Err(bad(format!(
                "the cell block at {offset} has a record of {r} bytes"
            )));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&block[12..24]);
        let mut aad = [0u8; SEALED_CELL_HEAD_LEN + 8];
        aad[..SEALED_CELL_HEAD_LEN].copy_from_slice(&block[..SEALED_CELL_HEAD_LEN]);
        aad[SEALED_CELL_HEAD_LEN..].copy_from_slice(&offset.to_le_bytes());
        let mut record = block[SEALED_CELL_HEAD_LEN..].to_vec();
        let Some(len) = prim::open(&self.keys.record, nonce, &aad, &mut record) else {
            return Err(bad(format!(
                "the record at {offset} fails its check: it was changed or moved"
            )));
        };
        record.truncate(len);
        let mut id = [0u8; 32];
        id.copy_from_slice(&record[..32]);
        let mut head = [0u8; RECORD_LEN];
        head.copy_from_slice(&record[32..32 + RECORD_LEN]);
        if c != sealed_len(u64::from(u32_at(&head, 12))) {
            return Err(bad(format!(
                "the cell block at {offset} says {c} sealed bytes, which isn't what its stored \
                 length makes"
            )));
        }
        Ok((id, head, record[32 + RECORD_LEN..].to_vec()))
    }

    /// A sealed cell's stored bytes, each segment checked before it is returned.
    pub fn open_cell(&self, id: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
        prim::open_segments(&cell_key(&self.file_key, id)?, sealed, &[], "a sealed cell")
    }

    /// The §5 index block inside a `BHIE` block (its 48-byte head and the sealed index). Its
    /// inner head's stored length must be the rest of what it holds (bhive.md §12.7).
    pub fn open_index(&self, block: &[u8]) -> Result<Vec<u8>> {
        if block.len() < SEALED_INDEX_HEAD_LEN || block[..4] != SEALED_INDEX_TAG {
            return Err(bad("the footer doesn't point at a sealed index"));
        }
        let s = u64::from_le_bytes(block[8..16].try_into().unwrap_or_default());
        if s != (block.len() - SEALED_INDEX_HEAD_LEN) as u64 {
            return Err(bad("the sealed index's length isn't what it holds"));
        }
        let mut aad = self.header_mac.to_vec();
        aad.extend_from_slice(&block[..SEALED_INDEX_HEAD_LEN]);
        let key = index_key(&self.file_key, &block[16..48])?;
        let inner = prim::open_segments(&key, &block[SEALED_INDEX_HEAD_LEN..], &aad, "the index")?;
        let head = layout::IndexHead::parse(&inner)?;
        if head.stored != (inner.len() - layout::INDEX_HEAD_LEN) as u64 {
            return Err(bad(
                "the sealed index's own head says a length that isn't what follows it",
            ));
        }
        Ok(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{KeySource, Recipient, SEGMENT, Strength};
    use super::*;
    use crate::SimpleCtx;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/bhive-m14/vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn h(v: &serde_json::Value) -> Vec<u8> {
        hex(v.as_str().unwrap())
    }

    fn arr<const N: usize>(v: &serde_json::Value) -> [u8; N] {
        h(v).try_into().unwrap()
    }

    /// vectors.json's `slots`: each kind's slot is what wrapping its secret gives, with the
    /// recipient's key in the context for kinds 3, 6 and 7.
    #[test]
    fn every_slot_vector_wraps_as_the_specification_says() {
        let v = vectors();
        let s = &v["slots"];
        let file_key = FileKey(Zeroizing::new(arr(&s["file_key"])));
        let key_id: [u8; 16] = arr(&s["key_id"]);
        for name in [
            "password",
            "recovery_key",
            "x25519",
            "xwing",
            "rsa",
            "p256",
            "p384",
            "fido2",
        ] {
            let vec = &s[name];
            let slot = h(&vec["slot"]);
            let kind = SlotKind::from_id(slot[0]).unwrap();
            let made = MadeSlot {
                public: slot[4..slot.len() - SLOT_TAIL_LEN].to_vec(),
                secret: SlotSecret::Shared(Zeroizing::new(h(&vec["secret"]))),
                recipient_key: match name {
                    "x25519" | "p256" | "p384" => h(&vec["recipient_public"]),
                    _ => Vec::new(),
                },
            };
            assert_eq!(
                wrap_with(&file_key, &key_id, kind, &made).unwrap(),
                slot,
                "{name}"
            );
            let (wrap, commitment) = slot_keys(&arr(&vec["prk"]));
            assert_eq!(wrap.to_vec(), h(&vec["wrap_key"]), "{name}");
            assert_eq!(commitment.to_vec(), h(&vec["commitment"]), "{name}");
        }
        // The password's secret is Argon2id of its NFC form, whatever form it was typed in.
        let pw = &s["password"];
        let slot = h(&pw["slot"]);
        let cost = password::Cost::parse(&slot[4..52]).unwrap();
        let typed = pw["password_as_typed_nfd"].as_str().unwrap();
        assert_eq!(*password::argon2id(typed, &cost).unwrap(), h(&pw["secret"]));
        // The recovery key's digits.
        let rk = &s["recovery_key"];
        let digits = rk["digits"].as_str().unwrap();
        assert_eq!(*recovery::format(&arr(&rk["key"])), digits);
        assert_eq!(recovery::parse(digits).unwrap().to_vec(), h(&rk["key"]));
    }

    /// vectors.json's `keys` and `segments`.
    #[test]
    fn the_keys_and_segments_are_the_specifications() {
        let v = vectors();
        let k = &v["keys"];
        let fk = h(&k["file_key"]);
        let archive_id = h(&k["archive_id"]);
        let derived = |salt: &[u8], info: &[u8]| prim::hkdf(&fk, salt, info).to_vec();
        assert_eq!(derived(&archive_id, label::MAC), h(&k["mac_key"]));
        assert_eq!(derived(&archive_id, label::RECORD), h(&k["record_key"]));
        assert_eq!(derived(&h(&k["cell_id"]), label::CELL), h(&k["cell_key"]));
        assert_eq!(
            derived(&h(&k["index_salt"]), label::INDEX),
            h(&k["index_key"])
        );
        let seg = &v["segments"];
        let plain: Vec<u8> = (0..1_048_581).map(|i| (i % 251) as u8).collect();
        let key = prim::key(&arr(&seg["key"])).unwrap();
        let sealed = prim::seal_segments(&key, &plain, &[]).unwrap();
        assert_eq!(sealed.len() as u64, seg["sealed_length"].as_u64().unwrap());
        let digest = ring::digest::digest(&ring::digest::SHA256, &sealed);
        assert_eq!(digest.as_ref(), h(&seg["sealed_sha256"]));
        assert_eq!(sealed[SEGMENT..SEGMENT + 16], h(&seg["tag_0"])[..]);
        assert_eq!(sealed[sealed.len() - 16..], h(&seg["tag_1"])[..]);
    }

    const DIGITS: &str = "000011-000022-000033-000044-000055-000066-000077-000088";
    const OTHER: &str = "000110-000220-000330-000440-000550-000660-000770-000880";

    fn recovery_slot(digits: &str, label: Option<&str>) -> Labelled {
        Labelled {
            recipient: Recipient::RecoveryKey(recovery::parse(digits).unwrap()),
            label: label.map(str::to_owned),
        }
    }

    fn envelope(ways: Vec<Labelled>) -> Envelope {
        Envelope::new(&Protection::New(ways)).unwrap()
    }

    /// The header and the key block of `env`.
    fn start(env: &Envelope) -> Vec<u8> {
        let mut b = layout::header_encrypted().to_vec();
        b.extend_from_slice(env.key_block());
        b
    }

    fn read(bytes: &[u8]) -> Result<KeyBlock> {
        let header: [u8; 16] = bytes[..16].try_into().unwrap();
        KeyBlock::read(&header, &mut &bytes[16..])
    }

    fn unlock(bytes: &[u8], answer: &str) -> Result<Unlocked> {
        Unlocked::open(&read(bytes)?, &mut SimpleCtx::new().with_password(answer))
    }

    #[test]
    fn a_key_block_opens_with_its_way_in_and_its_mac() {
        let env = envelope(vec![recovery_slot(DIGITS, Some("Recovery key"))]);
        let bytes = start(&env);
        let u = unlock(&bytes, DIGITS).unwrap();
        assert!(env.same_key(&u));
        assert_eq!(u.archive_id(), env.archive_id());
        assert_eq!(u.opened_by(), 0);
        let wrong = "000011-000022-000033-000044-000055-000066-000077-000099";
        assert_eq!(
            unlock(&bytes, wrong).unwrap_err().kind,
            ErrorKind::WrongPassword
        );
        assert_eq!(
            unlock(&bytes, "honey").unwrap_err().kind,
            ErrorKind::WrongPassword
        );
        let e = Unlocked::open(&read(&bytes).unwrap(), &mut SimpleCtx::new()).unwrap_err();
        assert_eq!(e.kind, ErrorKind::PasswordRequired);
    }

    #[test]
    fn the_second_of_two_ways_opens_too() {
        let env = envelope(vec![
            recovery_slot(DIGITS, Some("Recovery key")),
            recovery_slot(OTHER, None),
        ]);
        let u = unlock(&start(&env), OTHER).unwrap();
        assert_eq!(u.opened_by(), 1);
        // Section 5 is known once the index is read.
        assert_eq!(u.descriptions(), None);
        u.set_descriptions(env.descriptions.as_ref().unwrap());
        let d = u.descriptions().unwrap();
        assert_eq!(d[0].label.as_deref(), Some("Recovery key"));
        assert_eq!(d[1].label, None);
        // A count that isn't the slot count is ignored.
        let u = unlock(&start(&env), OTHER).unwrap();
        u.set_descriptions(&encode_descriptions(&[Vec::new()]));
        assert_eq!(u.descriptions(), None);
    }

    /// Each field of the key block and its slot, changed: refused as the specification says
    /// (bhive.md §12.10), never opened.
    #[test]
    fn a_changed_key_block_is_refused() {
        let env = envelope(vec![recovery_slot(DIGITS, None)]);
        let good = start(&env);
        // Slot 0 starts at 76: kind, reserved, body length, salt, commitment, wrapped key.
        let cases: &[(usize, &str, ErrorKind)] = &[
            (16, "tag", ErrorKind::Corrupt),
            (20, "suite", ErrorKind::UnsupportedFormat),
            (28, "archive id", ErrorKind::Corrupt),
            (60, "key id", ErrorKind::WrongPassword),
            (77, "reserved", ErrorKind::WrongPassword),
            (80, "salt", ErrorKind::WrongPassword),
            (112, "commitment", ErrorKind::WrongPassword),
            (150, "wrapped key", ErrorKind::Corrupt),
            (good.len() - 1, "MAC", ErrorKind::Corrupt),
        ];
        for &(at, what, kind) in cases {
            let mut b = good.clone();
            b[at] ^= 0x40;
            let e = unlock(&b, DIGITS).unwrap_err();
            assert_eq!(e.kind, kind, "{what}: {}", e.message);
        }
        for len in 16..good.len() {
            let e = read(&good[..len]).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Corrupt, "{len}");
        }
    }

    /// A key block of `slots`, framed, with a MAC under `fk`.
    fn block_of(slots: &[Vec<u8>], fk: &FileKey) -> Vec<u8> {
        let body: Vec<u8> = slots.concat();
        let mut b = layout::header_encrypted().to_vec();
        b.extend_from_slice(&KEY_TAG);
        b.extend_from_slice(&[SUITE_1, 0]);
        b.extend_from_slice(&(slots.len() as u16).to_le_bytes());
        b.extend_from_slice(&(body.len() as u32).to_le_bytes());
        b.extend_from_slice(&[1; 32]);
        b.extend_from_slice(&[2; 16]);
        b.extend_from_slice(&body);
        let mac_key = prim::hkdf(&fk.0[..], &[1; 32], label::MAC);
        let mac = prim::hmac(&mac_key[..], &[&b]);
        b.extend_from_slice(&mac);
        b
    }

    fn slot(kind: u8, public: &[u8]) -> Vec<u8> {
        let mut s = vec![kind, 0];
        s.extend_from_slice(&((public.len() + SLOT_TAIL_LEN) as u16).to_le_bytes());
        s.extend_from_slice(public);
        s.extend_from_slice(&[0; SLOT_TAIL_LEN]);
        s
    }

    fn pw(memory: u32, passes: u32, lanes: u32) -> Vec<u8> {
        password::Cost {
            memory_kib: memory,
            passes,
            lanes,
            salt: [5; 32],
        }
        .public()
    }

    #[test]
    fn the_key_blocks_limits_are_kept() {
        let fk = FileKey(Zeroizing::new([9; 32]));
        let rec = slot(2, &[0; 32]);
        assert!(read(&block_of(std::slice::from_ref(&rec), &fk)).is_ok());
        assert!(read(&block_of(&vec![rec.clone(); 64], &fk)).is_ok());
        let refused = |slots: &[Vec<u8>], what: &str| {
            let e = read(&block_of(slots, &fk)).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Corrupt, "{what}: {}", e.message);
        };
        refused(&[], "no slots");
        refused(&vec![rec.clone(); 65], "65 slots");
        refused(&[slot(2, &[0; 31])], "a recovery salt of 31 bytes");
        refused(&[slot(1, &pw(256, 2, 4)[..47])], "a short password part");
        refused(&[slot(1, &pw(256, 2, 17))], "17 lanes");
        refused(&[slot(1, &pw(256, 17, 4))], "17 passes");
        refused(&[slot(1, &pw(5 << 20, 2, 4))], "5 GiB");
        let mut v12 = slot(1, &pw(256, 2, 4));
        v12[4] = 0x12;
        refused(&[v12], "Argon2 version 0x12");
        assert!(read(&block_of(&vec![slot(1, &pw(256, 2, 4)); 4], &fk)).is_ok());
        refused(&vec![slot(1, &pw(256, 2, 4)); 5], "5 password slots");
        let mut short = vec![2, 0];
        short.extend_from_slice(&79u16.to_le_bytes());
        short.extend_from_slice(&[0; 79]);
        refused(&[short], "a body of 79 bytes");
        // The slots length isn't the sum of the slots.
        let mut b = block_of(std::slice::from_ref(&rec), &fk);
        b[24] += 1;
        b.push(0);
        assert_eq!(read(&b).unwrap_err().kind, ErrorKind::Corrupt);
        let mut b = block_of(std::slice::from_ref(&rec), &fk);
        b[24..28].copy_from_slice(&65_537u32.to_le_bytes());
        assert_eq!(read(&b).unwrap_err().kind, ErrorKind::Corrupt);
        // A kind this BeeZip doesn't know is skipped; with no other, the archive is newer.
        let k = read(&block_of(&[slot(200, &[1, 2, 3]), rec.clone()], &fk)).unwrap();
        assert_eq!(k.kinds(), vec![None, Some(SlotKind::RecoveryKey)]);
        assert_eq!(k.views().len(), 1);
        assert_eq!(k.views()[0].index, 1);
        let only = read(&block_of(&[slot(200, &[])], &fk)).unwrap();
        let e = Unlocked::open(&only, &mut SimpleCtx::new()).unwrap_err();
        assert_eq!(e.kind, ErrorKind::UnsupportedFormat);
    }

    fn password(passes: u32) -> Labelled {
        Labelled {
            recipient: Recipient::Password {
                password: Zeroizing::new("honey".into()),
                strength: Strength::Cost {
                    memory_kib: 64,
                    passes,
                    lanes: 1,
                },
            },
            label: None,
        }
    }

    #[test]
    fn writers_keep_the_rules_readers_check() {
        let many = vec![recovery_slot(DIGITS, None); 65];
        assert!(Envelope::new(&Protection::New(many)).is_err());
        assert!(Envelope::new(&Protection::New(Vec::new())).is_err());
        assert!(Envelope::new(&Protection::New(vec![password(1); 4])).is_ok());
        let e = Envelope::new(&Protection::New(vec![password(1); 5])).unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidArgs);
        // An Argon2 cost a reader would refuse.
        assert!(Envelope::new(&Protection::New(vec![password(17)])).is_err());
    }

    /// Fresh randomness in every slot, and a new key id with every file key.
    #[test]
    fn every_slot_written_is_new() {
        let a = envelope(vec![recovery_slot(DIGITS, None)]);
        let b = envelope(vec![recovery_slot(DIGITS, None)]);
        assert_ne!(a.key_id, b.key_id);
        assert_ne!(a.key_block[60..], b.key_block[60..]);
        let ka = read(&start(&a)).unwrap();
        let kb = read(&start(&b)).unwrap();
        assert_ne!(ka.views()[0].public, kb.views()[0].public);
    }

    /// Ways in added and removed under the same key: the kept slots are kept byte for byte.
    #[test]
    fn a_change_keeps_the_key_and_the_slots_it_keeps() {
        let env = envelope(vec![recovery_slot(DIGITS, None)]);
        let u = std::sync::Arc::new(unlock(&start(&env), DIGITS).unwrap());
        u.set_descriptions(env.descriptions.as_ref().unwrap());
        let add = vec![recovery_slot(OTHER, Some("Second"))];
        let changed = Envelope::new(&Protection::Change {
            from: u.clone(),
            remove: Vec::new(),
            add: add.clone(),
        })
        .unwrap();
        assert!(changed.same_key(&u));
        assert_ne!(changed.archive_id, env.archive_id);
        let k = read(&start(&changed)).unwrap();
        assert_eq!(k.slots.len(), 2);
        assert_eq!(&k.bytes[k.slots[0].1.clone()], &u.slots[..]);
        assert_eq!(unlock(&start(&changed), OTHER).unwrap().opened_by(), 1);
        // Removing the first leaves the second.
        let removed = Envelope::new(&Protection::Change {
            from: u.clone(),
            remove: vec![0],
            add,
        })
        .unwrap();
        let e = unlock(&start(&removed), DIGITS).unwrap_err();
        assert_eq!(e.kind, ErrorKind::WrongPassword);
        assert!(unlock(&start(&removed), OTHER).is_ok());
        for remove in [vec![0], vec![1]] {
            let p = Protection::Change {
                from: u.clone(),
                remove,
                add: Vec::new(),
            };
            assert_eq!(Envelope::new(&p).unwrap_err().kind, ErrorKind::InvalidArgs);
        }
    }

    /// Records, cells and the index: each opens only as written, where it was written, and
    /// with the lengths the specification ties together (bhive.md §12.6–§12.8).
    #[test]
    fn sealed_parts_open_only_as_they_were_sealed() {
        let env = envelope(vec![recovery_slot(DIGITS, None)]);
        let u = unlock(&start(&env), DIGITS).unwrap();
        let id = env.new_cell_id().unwrap();
        let stored = b"0123456789".to_vec();
        let rec = layout::Record {
            number: 0,
            raw: 10,
            stored: 10,
            coder: layout::Coder::Stored,
            param: 0,
            journal_zstd: false,
            journal_items: 0,
            journal_raw: 3,
            journal_stored: 3,
            checksum: layout::checksum(&stored),
        };
        let head = rec.encode(b"abc");
        let c = sealed_len(10) as u32;
        let block = env.record_block(500, &id, &head, b"abc", c).unwrap();
        assert_eq!(block.len(), SEALED_CELL_HEAD_LEN + MIN_RECORD + 3);
        let (i, h, j) = u.open_record(500, &block).unwrap();
        assert_eq!((i, h, j), (id, head, b"abc".to_vec()));
        // Moved: its offset is in the associated data.
        assert_eq!(
            u.open_record(501, &block).unwrap_err().kind,
            ErrorKind::Corrupt
        );
        let mut b = block.clone();
        b[13] ^= 1;
        assert!(u.open_record(500, &b).is_err());
        // A writer refuses a sealed length its stored length doesn't make.
        assert!(env.record_block(500, &id, &head, b"abc", c + 16).is_err());
        // And a reader does too, under a good tag.
        let mut lying = SEALED_CELL_TAG.to_vec();
        lying.extend_from_slice(&((MIN_RECORD + 3) as u32).to_le_bytes());
        lying.extend_from_slice(&(c + 16).to_le_bytes());
        lying.extend_from_slice(&[7; 12]);
        let mut aad = lying.clone();
        aad.extend_from_slice(&500u64.to_le_bytes());
        let mut plain = id.to_vec();
        plain.extend_from_slice(&head);
        plain.extend_from_slice(b"abc");
        prim::seal(&env.keys.record, [7; 12], &aad, &mut plain).unwrap();
        lying.extend_from_slice(&plain);
        let e = u.open_record(500, &lying).unwrap_err();
        assert!(e.message.contains("stored length"), "{}", e.message);

        // A cell opens only under its own id, and its own archive's file key.
        let sealed = env.seal_cell(&id, &stored).unwrap();
        assert_eq!(u.open_cell(&id, &sealed).unwrap(), stored);
        assert!(u.open_cell(&env.new_cell_id().unwrap(), &sealed).is_err());
        assert!(u.open_cell(&id, &sealed[..sealed.len() - 1]).is_err());
        let other = envelope(vec![recovery_slot(DIGITS, None)]);
        assert!(
            u.open_cell(&id, &other.seal_cell(&id, &stored).unwrap())
                .is_err()
        );

        // The index: its inner head's stored length must be what follows it.
        let raw = vec![0u8, 0];
        let ih = layout::IndexHead {
            zstd: false,
            stored: raw.len() as u64,
            raw: raw.len() as u64,
            checksum: layout::checksum(&raw),
        };
        let mut inner = ih.encode().to_vec();
        inner.extend_from_slice(&raw);
        let ib = env.index_block(&inner).unwrap();
        assert_eq!(u.open_index(&ib).unwrap(), inner);
        let mut longer = inner.clone();
        longer.push(0);
        let e = u
            .open_index(&env.index_block(&longer).unwrap())
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Corrupt);
        // Bound to the header MAC: another key block's index doesn't open here.
        let again = std::sync::Arc::new(unlock(&start(&env), DIGITS).unwrap());
        let kept = Envelope::new(&Protection::Keep(again)).unwrap();
        assert!(kept.same_key(&u));
        assert!(u.open_index(&kept.index_block(&inner).unwrap()).is_err());
        let mut salted = ib.clone();
        salted[20] ^= 1;
        assert!(u.open_index(&salted).is_err());
        assert!(u.open_index(&ib[..ib.len() - 1]).is_err());
    }

    /// Answers passwords in turn, and says `yes` or no when asked to spend memory, counting the
    /// asks.
    struct Asked {
        inner: SimpleCtx,
        yes: bool,
        asks: u32,
    }

    impl Asked {
        fn new(answers: &[&str], yes: bool) -> Self {
            Self {
                inner: SimpleCtx::new().with_passwords(answers),
                yes,
                asks: 0,
            }
        }
    }

    impl Ctx for Asked {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn progress(&mut self, _: &crate::Progress) {}

        fn warn(&mut self, message: String) {
            self.inner.warn(message);
        }

        fn password(&mut self, entry: Option<&str>, attempt: u32) -> Result<String> {
            self.inner.password(entry, attempt)
        }

        fn overwrite(&mut self, existing: &std::path::Path) -> Result<crate::OverwriteChoice> {
            self.inner.overwrite(existing)
        }

        fn spend_memory(&mut self, _: u64, _: u64) -> Result<bool> {
            self.asks += 1;
            Ok(self.yes)
        }
    }

    /// A password slot that takes more than half the machine's memory is tried only when the
    /// context says to, and the context is asked once a slot however many answers it gives
    /// (docs/M14.md §5). Here the machine is made to have 100 KiB, against the slots' 64.
    #[test]
    fn memory_over_half_the_machine_is_asked_for_once_a_slot() {
        assert!(!asks_first(1 << 30, 4 << 30) && !asks_first(2 << 30, 4 << 30));
        assert!(asks_first((2 << 30) + 1, 4 << 30));
        let total = Some(100 << 10);
        let env = envelope(vec![password(1), password(2)]);
        let block = read(&start(&env)).unwrap();

        // Refused: neither slot is tried, and the unlock says why.
        let mut cx = Asked::new(&["honey", "honey", "honey"], false);
        let e = Unlocked::open_with(&block, &mut cx, total).unwrap_err();
        assert_eq!(e.kind, ErrorKind::LimitExceeded, "{}", e.message);
        assert_eq!(cx.asks, 2);
        // The default context has nobody to ask, so it refuses too.
        let mut simple = SimpleCtx::new().with_password("honey");
        let e = Unlocked::open_with(&block, &mut simple, total).unwrap_err();
        assert_eq!(e.kind, ErrorKind::LimitExceeded);
        // Allowed: asked once for each slot tried, over every wrong answer.
        let mut cx = Asked::new(&["bees", "wasps", "honey"], true);
        let u = Unlocked::open_with(&block, &mut cx, total).unwrap();
        assert!(env.same_key(&u));
        assert_eq!(cx.asks, 2);
        // Enough memory: nobody is asked.
        let mut cx = Asked::new(&["honey"], false);
        Unlocked::open_with(&block, &mut cx, Some(1 << 30)).unwrap();
        assert_eq!(cx.asks, 0);

        // A refused slot leaves the recovery key, which opens.
        let env = envelope(vec![password(1), recovery_slot(DIGITS, None)]);
        let block = read(&start(&env)).unwrap();
        let mut cx = Asked::new(&["honey", DIGITS], false);
        let u = Unlocked::open_with(&block, &mut cx, total).unwrap();
        assert_eq!((u.opened_by(), cx.asks), (1, 1));
    }

    /// A password with 48 digits among letters is never taken for a recovery key; the digits
    /// alone, with any separators that aren't letters, are.
    #[test]
    fn only_digits_are_tried_as_a_recovery_key() {
        let env = envelope(vec![recovery_slot(DIGITS, None)]);
        let bytes = start(&env);
        assert!(unlock(&bytes, &DIGITS.replace('-', " ")).is_ok());
        let e = unlock(&bytes, &DIGITS.replace('-', "x")).unwrap_err();
        assert_eq!(e.kind, ErrorKind::WrongPassword);
        // Asked for as a recovery key, the same text is one: separators are any characters.
        let typed = UnlockAnswer::RecoveryKey(DIGITS.replace('-', "x"));
        let block = read(&bytes).unwrap();
        let mut memory = Memory::new(block.slots.len(), None);
        let views = block.views();
        let mut failed = None;
        let u = Unlocked::answer(
            &block,
            &views,
            &typed,
            &mut memory,
            &mut failed,
            &mut SimpleCtx::new(),
        );
        assert!(u.unwrap().is_some());
    }

    /// A security key standing in for a device: it fails with each of `fails` in turn when
    /// chosen, then gives the slot's secret. Never asked unless chosen; offered unless it isn't
    /// `here`. With `pin`, it stands in for a This PC key whose PIN BeeZip asks for: it opens
    /// only with that PIN, and keeps the PINs it was given.
    struct Device {
        secret: [u8; 32],
        fails: Vec<ErrorKind>,
        asked: u32,
        here: bool,
        pin: Option<&'static str>,
        pins: Vec<Option<String>>,
    }

    impl KeySource for Device {
        fn offers(&mut self, slot: &SlotView<'_>) -> bool {
            self.here && slot.kind == SlotKind::Fido2
        }

        fn needs_pin(&mut self, slot: &SlotView<'_>) -> bool {
            self.offers(slot) && self.pin.is_some()
        }

        fn secret(&mut self, slot: &SlotView<'_>, device: bool) -> Result<Option<SlotSecret>> {
            if slot.kind != SlotKind::Fido2 || !device {
                return Ok(None);
            }
            self.asked += 1;
            if !self.fails.is_empty() {
                let kind = self.fails.remove(0);
                return Err(Error::new(kind, format!("the device failed: {kind:?}")));
            }
            if self.pin.is_some() {
                self.pins.push(None);
                return Err(Error::new(ErrorKind::PasswordRequired, "no PIN was given"));
            }
            Ok(Some(SlotSecret::Shared(Zeroizing::new(
                self.secret.to_vec(),
            ))))
        }

        fn secret_with_pin(
            &mut self,
            slot: &SlotView<'_>,
            pin: &str,
        ) -> Result<Option<SlotSecret>> {
            let Some(right) = self.pin else {
                return self.secret(slot, true);
            };
            self.asked += 1;
            self.pins.push(Some(pin.to_owned()));
            if pin != right {
                return Err(Error::new(ErrorKind::WrongPassword, "the PIN is wrong"));
            }
            Ok(Some(SlotSecret::Shared(Zeroizing::new(
                self.secret.to_vec(),
            ))))
        }
    }

    /// Answers in turn, one per attempt, then says nobody is left to ask, or with `cancel` that
    /// the Unlock prompt was cancelled. With `cancel_job` the job is cancelled once the device
    /// has been asked. Keeps the attempts it was asked at, whether each way was here, and what
    /// it was warned of.
    struct Choosing {
        device: Device,
        answers: Vec<UnlockAnswer>,
        cancel: bool,
        cancel_job: bool,
        attempts: Vec<u32>,
        here: Vec<bool>,
        needs_pin: Vec<bool>,
        failed: Vec<Option<String>>,
        warnings: Vec<String>,
    }

    impl Choosing {
        fn new(fails: &[ErrorKind], answers: Vec<UnlockAnswer>) -> Self {
            Self {
                device: Device {
                    secret: [0x5e; 32],
                    fails: fails.to_vec(),
                    asked: 0,
                    here: true,
                    pin: None,
                    pins: Vec::new(),
                },
                answers,
                cancel: false,
                cancel_job: false,
                attempts: Vec::new(),
                here: Vec::new(),
                needs_pin: Vec::new(),
                failed: Vec::new(),
                warnings: Vec::new(),
            }
        }
    }

    impl Ctx for Choosing {
        fn is_cancelled(&self) -> bool {
            self.cancel_job && self.device.asked > 0
        }

        fn progress(&mut self, _: &crate::Progress) {}

        fn warn(&mut self, message: String) {
            self.warnings.push(message);
        }

        fn password(&mut self, _: Option<&str>, _: u32) -> Result<String> {
            Err(Error::new(ErrorKind::PasswordRequired, "nobody to ask"))
        }

        fn overwrite(&mut self, existing: &std::path::Path) -> Result<crate::OverwriteChoice> {
            SimpleCtx::new().overwrite(existing)
        }

        fn unlock(&mut self, request: &UnlockRequest) -> Result<UnlockAnswer> {
            self.attempts.push(request.attempt);
            self.here = request.ways.iter().map(|w| w.here).collect();
            self.needs_pin = request.ways.iter().map(|w| w.needs_pin).collect();
            self.failed.push(request.failed.clone());
            match self.answers.get(request.attempt as usize) {
                Some(a) => Ok(a.clone()),
                None if self.cancel => Err(Error::cancelled()),
                None => Err(Error::new(
                    ErrorKind::PasswordRequired,
                    "nobody left to ask",
                )),
            }
        }

        fn key_source(&mut self) -> Option<&mut dyn KeySource> {
            Some(&mut self.device)
        }
    }

    /// A key block with a security-key slot (0) whose secret is the device's, and, with
    /// `password_too`, a password slot (1) for "honey".
    fn device_block(password_too: bool) -> (Envelope, KeyBlock) {
        let mut ways = vec![Labelled {
            recipient: Recipient::Fido2 {
                credential_id: vec![1, 2, 3],
                rp_id: "beezip".into(),
                salt: [3; 32],
                prf: false,
                secret: Zeroizing::new([0x5e; 32]),
                machine_bound: false,
            },
            label: None,
        }];
        if password_too {
            ways.push(password(1));
        }
        let env = envelope(ways);
        let block = read(&start(&env)).unwrap();
        (env, block)
    }

    /// The way in chosen fails (another security key, a closed dialog, a refused PIN, a device
    /// that couldn't be reached): the Unlock prompt is asked again, as after a wrong password,
    /// and the password opens it. Only what the person didn't do themselves is warned of.
    #[test]
    fn a_device_that_fails_asks_again_and_a_password_opens() {
        let (env, block) = device_block(true);
        let honey = UnlockAnswer::Password("honey".into());
        for kind in [
            ErrorKind::KeyRequired,
            ErrorKind::Cancelled,
            ErrorKind::WrongPassword,
            ErrorKind::Io,
            ErrorKind::UnsupportedOperation,
        ] {
            let mut cx = Choosing::new(&[kind], vec![UnlockAnswer::way(0), honey.clone()]);
            let u = Unlocked::open(&block, &mut cx).unwrap();
            assert!(env.same_key(&u), "{kind:?}");
            assert_eq!(u.opened_by(), 1, "{kind:?}");
            assert_eq!(cx.attempts, [0, 1], "{kind:?}");
            assert_eq!(cx.device.asked, 1, "{kind:?}");
            let warned = usize::from(kind != ErrorKind::Cancelled);
            assert_eq!(cx.warnings.len(), warned, "{kind:?}: {:?}", cx.warnings);
        }
        // Or the same way again, once the right key is there.
        let mut cx = Choosing::new(
            &[ErrorKind::KeyRequired, ErrorKind::Cancelled],
            vec![UnlockAnswer::way(0); 3],
        );
        let u = Unlocked::open(&block, &mut cx).unwrap();
        assert_eq!((u.opened_by(), cx.device.asked), (0, 3));
        assert_eq!(cx.attempts, [0, 1, 2]);
    }

    /// The reason a chosen way in failed reaches the next Unlock prompt, except a closed dialog's,
    /// which the person did themselves.
    #[test]
    fn the_next_prompt_says_why_the_way_in_failed() {
        let (_, block) = device_block(true);
        let honey = UnlockAnswer::Password("honey".into());
        let mut cx = Choosing::new(
            &[ErrorKind::Io, ErrorKind::Cancelled],
            vec![UnlockAnswer::way(0), UnlockAnswer::way(0), honey],
        );
        Unlocked::open(&block, &mut cx).unwrap();
        assert_eq!(
            cx.failed,
            [None, Some("the device failed: Io".to_owned()), None]
        );
    }

    /// A This PC key whose PIN BeeZip asks for: the Unlock prompt says so, the PIN typed reaches
    /// the key source, and a wrong one is asked again for with the reason, as a wrong password
    /// is. Chosen without its PIN, it fails rather than ask in a dialog of its own.
    #[test]
    fn a_pin_beezip_asks_for_reaches_the_source() {
        let (env, block) = device_block(true);
        let with = |pin: &str| UnlockAnswer::Way {
            slot: 0,
            pin: Some(Zeroizing::new(pin.to_owned())),
        };
        let mut cx = Choosing::new(&[], vec![with("0000"), with("1234")]);
        cx.device.pin = Some("1234");
        let u = Unlocked::open(&block, &mut cx).unwrap();
        assert!(env.same_key(&u));
        assert_eq!(u.opened_by(), 0);
        assert_eq!(cx.attempts, [0, 1]);
        assert_eq!(cx.needs_pin, [true, false]);
        assert_eq!(cx.failed, [None, Some("the PIN is wrong".to_owned())]);
        assert_eq!(
            cx.device.pins,
            [Some("0000".to_owned()), Some("1234".to_owned())]
        );
        assert_eq!(cx.warnings.len(), 1, "{:?}", cx.warnings);
        assert!(
            cx.warnings[0].contains("the PIN is wrong"),
            "{:?}",
            cx.warnings
        );
        // An answer's PIN never reaches a log.
        assert_eq!(format!("{:?}", with("1234")), "Way(0, PIN ***)");

        // No PIN: the source refuses, and the password still opens it.
        let honey = UnlockAnswer::Password("honey".into());
        let mut cx = Choosing::new(&[], vec![UnlockAnswer::way(0), honey]);
        cx.device.pin = Some("1234");
        let u = Unlocked::open(&block, &mut cx).unwrap();
        assert_eq!(u.opened_by(), 1);
        assert_eq!(cx.device.pins, [None]);

        // A way in that needs none ignores the PIN given.
        let mut cx = Choosing::new(&[], vec![with("5678")]);
        let u = Unlocked::open(&block, &mut cx).unwrap();
        assert_eq!(u.opened_by(), 0);
        assert_eq!(cx.needs_pin, [false, false]);
    }

    /// Cancelling the Unlock prompt itself still ends the open; so do a job cancelled while the
    /// device's dialog was up and a damaged slot.
    #[test]
    fn a_cancelled_unlock_prompt_still_ends_it() {
        let (_, block) = device_block(true);
        let mut cx = Choosing::new(&[ErrorKind::Cancelled], vec![UnlockAnswer::way(0)]);
        cx.cancel = true;
        let e = Unlocked::open(&block, &mut cx).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Cancelled);
        assert_eq!(cx.attempts, [0, 1]);

        let honey = UnlockAnswer::Password("honey".into());
        let mut cx = Choosing::new(&[ErrorKind::Cancelled], vec![UnlockAnswer::way(0), honey]);
        cx.cancel_job = true;
        let e = Unlocked::open(&block, &mut cx).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Cancelled);
        assert_eq!(cx.attempts, [0]);

        let mut cx = Choosing::new(&[ErrorKind::Corrupt], vec![UnlockAnswer::way(0)]);
        let e = Unlocked::open(&block, &mut cx).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Corrupt);
        assert_eq!(cx.attempts, [0]);
    }

    /// With nobody left to ask, the device's failure is the error, not a wrong password; with
    /// no answer left that could open the archive, it is the error at once.
    #[test]
    fn with_nobody_left_to_ask_the_device_says_why() {
        let (_, block) = device_block(false);
        let mut cx = Choosing::new(&[ErrorKind::KeyRequired], vec![UnlockAnswer::way(0)]);
        let e = Unlocked::open(&block, &mut cx).unwrap_err();
        assert_eq!(e.kind, ErrorKind::KeyRequired);
        assert!(e.message.contains("the device failed"), "{}", e.message);
        assert_eq!(
            cx.attempts,
            [0, 1],
            "asked again: the right key may be there"
        );

        // A wrong password after the device: the password is what failed last.
        let (_, block) = device_block(true);
        let mut cx = Choosing::new(
            &[ErrorKind::Cancelled],
            vec![UnlockAnswer::way(0), UnlockAnswer::Password("bees".into())],
        );
        let e = Unlocked::open(&block, &mut cx).unwrap_err();
        assert_eq!(e.kind, ErrorKind::PasswordRequired, "{}", e.message);
        assert_eq!(cx.attempts, [0, 1, 2]);

        // Nothing here offers the slot, and no password or recovery key opens the archive.
        let (_, block) = device_block(false);
        let mut cx = Choosing::new(&[ErrorKind::Io], vec![UnlockAnswer::way(0)]);
        cx.device.here = false;
        let e = Unlocked::open(&block, &mut cx).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Io, "{}", e.message);
        assert_eq!(cx.attempts, [0]);
        assert_eq!(cx.here, [false]);
    }

    /// What opened an archive, as a context that keeps it unlocked holds it (a desktop tab's):
    /// each secret by its slot's `kept_id`, and the slot of every `keep_secret`, in order.
    #[derive(Default)]
    struct Memo {
        secrets: std::collections::HashMap<[u8; 32], SlotSecret>,
        kept: Vec<usize>,
    }

    impl Memo {
        /// The same secrets, with no `keep_secret` seen yet.
        fn copy(&self) -> Self {
            Self {
                secrets: self.secrets.clone(),
                kept: Vec::new(),
            }
        }
    }

    /// `inner` with a memo, counting the unlock prompts and the key-source calls that reach it.
    struct Remembering<C> {
        inner: C,
        memo: Memo,
        asked: u32,
        sourced: u32,
    }

    impl<C: Ctx> Remembering<C> {
        fn new(inner: C, memo: Memo) -> Self {
            Self {
                inner,
                memo,
                asked: 0,
                sourced: 0,
            }
        }
    }

    impl<C: Ctx> Ctx for Remembering<C> {
        fn is_cancelled(&self) -> bool {
            self.inner.is_cancelled()
        }

        fn progress(&mut self, p: &crate::Progress) {
            self.inner.progress(p);
        }

        fn warn(&mut self, message: String) {
            self.inner.warn(message);
        }

        fn password(&mut self, entry: Option<&str>, attempt: u32) -> Result<String> {
            self.inner.password(entry, attempt)
        }

        fn overwrite(&mut self, existing: &std::path::Path) -> Result<crate::OverwriteChoice> {
            self.inner.overwrite(existing)
        }

        fn unlock(&mut self, request: &UnlockRequest) -> Result<UnlockAnswer> {
            self.asked += 1;
            self.inner.unlock(request)
        }

        fn key_source(&mut self) -> Option<&mut dyn KeySource> {
            self.sourced += 1;
            self.inner.key_source()
        }

        fn kept_secret(&mut self, slot: &SlotView<'_>) -> Option<SlotSecret> {
            self.memo.secrets.get(&slot.kept_id()).cloned()
        }

        fn keep_secret(&mut self, slot: &SlotView<'_>, secret: &SlotSecret) {
            self.memo.kept.push(slot.index);
            self.memo.secrets.insert(slot.kept_id(), secret.clone());
        }
    }

    /// One of your keys, standing in for a software key: it opens a recovery-key slot for
    /// `DIGITS` without asking anyone.
    struct Quiet;

    impl KeySource for Quiet {
        fn offers(&mut self, slot: &SlotView<'_>) -> bool {
            slot.kind == SlotKind::RecoveryKey
        }

        fn secret(&mut self, slot: &SlotView<'_>, _device: bool) -> Result<Option<SlotSecret>> {
            recovery::secret(slot, DIGITS).map(Some)
        }
    }

    /// A context whose only way in is [`Quiet`]: nobody to ask.
    struct Keyed(Quiet);

    impl Ctx for Keyed {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn progress(&mut self, _: &crate::Progress) {}

        fn warn(&mut self, _: String) {}

        fn password(&mut self, _: Option<&str>, _: u32) -> Result<String> {
            Err(Error::new(ErrorKind::PasswordRequired, "nobody to ask"))
        }

        fn overwrite(&mut self, existing: &std::path::Path) -> Result<crate::OverwriteChoice> {
            SimpleCtx::new().overwrite(existing)
        }

        fn key_source(&mut self) -> Option<&mut dyn KeySource> {
            Some(&mut self.0)
        }
    }

    /// Opens `block` with nobody to ask and nothing but `memo`.
    fn reopen(block: &KeyBlock, memo: Memo) -> (Result<Unlocked>, Remembering<SimpleCtx>) {
        let mut cx = Remembering::new(SimpleCtx::new(), memo);
        let u = Unlocked::open(block, &mut cx);
        (u, cx)
    }

    /// Whatever opened the archive (a password, a recovery key, one of your keys, a device
    /// chosen), its secret is kept for the slot it opened, and the next open takes it first:
    /// no prompt, no key source, no device (docs/M14.md §8).
    #[test]
    fn what_opened_a_slot_is_kept_and_opens_it_again_without_asking() {
        // A password: slot 1, after a recovery key's slot.
        let env = envelope(vec![recovery_slot(OTHER, None), password(1)]);
        let block = read(&start(&env)).unwrap();
        let mut cx = Remembering::new(SimpleCtx::new().with_password("honey"), Memo::default());
        assert_eq!(Unlocked::open(&block, &mut cx).unwrap().opened_by(), 1);
        assert_eq!((cx.memo.kept.as_slice(), cx.asked), (&[1][..], 1));
        let (u, again) = reopen(&block, cx.memo);
        assert!(env.same_key(&u.unwrap()));
        assert_eq!((again.asked, again.sourced), (0, 0));
        assert_eq!(again.memo.kept, [1, 1], "kept again by the open it made");

        // A recovery key, given where a password is asked for: slot 1, after a password's.
        let env = envelope(vec![password(1), recovery_slot(DIGITS, None)]);
        let block = read(&start(&env)).unwrap();
        let mut cx = Remembering::new(SimpleCtx::new().with_password(DIGITS), Memo::default());
        assert_eq!(Unlocked::open(&block, &mut cx).unwrap().opened_by(), 1);
        assert_eq!(cx.memo.kept, [1]);
        let (u, again) = reopen(&block, cx.memo);
        assert!(env.same_key(&u.unwrap()));
        assert_eq!((again.asked, again.sourced), (0, 0));

        // One of your keys, with nobody asked.
        let mut cx = Remembering::new(Keyed(Quiet), Memo::default());
        assert_eq!(Unlocked::open(&block, &mut cx).unwrap().opened_by(), 1);
        assert_eq!((cx.memo.kept.as_slice(), cx.asked), (&[1][..], 0));
        let (u, again) = reopen(&block, cx.memo);
        assert!(env.same_key(&u.unwrap()));
        assert_eq!((again.asked, again.sourced), (0, 0));

        // A security key chosen in the Unlock prompt, after a wrong password: only the slot
        // that opened it is kept, and the device isn't touched again.
        let (env, block) = device_block(true);
        let choosing = Choosing::new(
            &[],
            vec![UnlockAnswer::Password("bees".into()), UnlockAnswer::way(0)],
        );
        let mut cx = Remembering::new(choosing, Memo::default());
        assert_eq!(Unlocked::open(&block, &mut cx).unwrap().opened_by(), 0);
        assert_eq!(cx.inner.device.asked, 1);
        assert_eq!((cx.memo.kept.as_slice(), cx.asked), (&[0][..], 2));
        let honey = UnlockAnswer::Password("honey".into());
        let mut again = Remembering::new(Choosing::new(&[], vec![honey]), cx.memo);
        assert!(env.same_key(&Unlocked::open(&block, &mut again).unwrap()));
        assert_eq!(
            (again.asked, again.sourced, again.inner.device.asked),
            (0, 0, 0)
        );

        // Nothing opens it: nothing is kept.
        let env = envelope(vec![recovery_slot(DIGITS, None)]);
        let block = read(&start(&env)).unwrap();
        let mut cx = Remembering::new(SimpleCtx::new().with_password(OTHER), Memo::default());
        assert!(Unlocked::open(&block, &mut cx).is_err());
        assert!(cx.memo.kept.is_empty() && cx.memo.secrets.is_empty());
    }

    /// A kept secret opens its slot only as it was: the same slots under a new archive id (an
    /// edit, or a way in removed beside it) still open with it; the slot removed, or rebuilt
    /// for a new key (another archive with the same recovery key is the same), asks again.
    #[test]
    fn a_kept_secret_fits_only_the_slot_it_opened() {
        let env = envelope(vec![
            recovery_slot(DIGITS, None),
            recovery_slot(OTHER, None),
        ]);
        let block = read(&start(&env)).unwrap();
        let mut cx = Remembering::new(SimpleCtx::new().with_password(DIGITS), Memo::default());
        let u = std::sync::Arc::new(Unlocked::open(&block, &mut cx).unwrap());
        assert_eq!(cx.memo.kept, [0]);
        let memo = cx.memo;

        // An edit: the file key and the slots, byte for byte, under a new archive id.
        let edited = Envelope::new(&Protection::Keep(u.clone())).unwrap();
        assert_ne!(edited.archive_id, env.archive_id);
        let (opened, again) = reopen(&read(&start(&edited)).unwrap(), memo.copy());
        assert!(edited.same_key(&opened.unwrap()));
        assert_eq!(again.asked, 0);
        // The other way in removed: slot 0 stays as it was.
        let fewer = Envelope::new(&Protection::Change {
            from: u.clone(),
            remove: vec![1],
            add: Vec::new(),
        })
        .unwrap();
        let (opened, again) = reopen(&read(&start(&fewer)).unwrap(), memo.copy());
        assert!(opened.is_ok());
        assert_eq!(again.asked, 0);

        // The way in that opened it removed.
        let removed = Envelope::new(&Protection::Change {
            from: u.clone(),
            remove: vec![0],
            add: Vec::new(),
        })
        .unwrap();
        let (opened, again) = reopen(&read(&start(&removed)).unwrap(), memo.copy());
        assert_eq!(opened.unwrap_err().kind, ErrorKind::PasswordRequired);
        assert_eq!(again.asked, 1);
        // Rebuilt, with a new key id.
        let rebuilt = envelope(vec![
            recovery_slot(DIGITS, None),
            recovery_slot(OTHER, None),
        ]);
        let (opened, again) = reopen(&read(&start(&rebuilt)).unwrap(), memo.copy());
        assert_eq!(opened.unwrap_err().kind, ErrorKind::PasswordRequired);
        assert_eq!(again.asked, 1);
        let a = read(&start(&env)).unwrap();
        let b = read(&start(&rebuilt)).unwrap();
        for (x, y) in a.views().iter().zip(b.views().iter()) {
            assert_ne!(x.kept_id(), y.kept_id());
        }
        assert_ne!(a.views()[0].kept_id(), a.views()[1].kept_id());
    }
}
