//! The `.bhive` index parser alone (docs/M13.md §8), on bytes that needn't be compressed or
//! checksummed first: the cell table, the entries and their extents, the sections. It must
//! never panic, and what it accepts must keep the rules the reader relies on: every cell
//! inside the file and in order, every extent inside its cell, every size the sum of its
//! extents. The same bytes are then read as a journal, where an extent may only name the
//! cells so far.

#![no_main]

use beezip_core::format::bhive::layout::{self, Items, RECORD_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first two bytes choose where the index block would start; the rest is the index.
    let Some((head, raw)) = data.split_first_chunk::<2>() else {
        return;
    };
    let index_offset = u64::from(u16::from_le_bytes(*head)) * 64;
    if let Ok(index) = layout::parse_index(raw, index_offset, Some(10_000)) {
        let mut end = layout::HEADER_LEN as u64;
        for cell in &index.cells {
            assert!(cell.offset >= end + RECORD_LEN as u64);
            assert!(cell.end() <= index_offset);
            assert!(cell.raw <= layout::MAX_CELL);
            end = cell.end();
        }
        assert!(index.items.items.len() <= 10_000);
        for item in &index.items.items {
            let mut size = 0u64;
            for x in index.items.extents_of(item) {
                let cell = &index.cells[x.cell as usize];
                assert!(x.len > 0 && u64::from(x.offset) + u64::from(x.len) <= u64::from(cell.raw));
                size += u64::from(x.len);
            }
            assert_eq!(size, item.size);
        }
        // What was parsed can be written again, and reads back the same.
        let mut items = Vec::new();
        for item in &index.items.items {
            layout::put_item(
                &mut items,
                &layout::ItemRef {
                    kind: item.kind,
                    path: &item.path,
                    modified: item.modified,
                    created: item.created,
                    mode: item.mode,
                    attrs: item.attrs,
                    extents: index.items.extents_of(item),
                    target: &item.target,
                },
            );
        }
        let again = layout::encode_index(
            &index.cells,
            index.items.items.len() as u64,
            &items,
            index.level,
        );
        let back = layout::parse_index(&again, index_offset, None).expect("its own index");
        assert_eq!(back, index);

        // As a journal: the same items, against the cells so far.
        let mut out = Items::default();
        let count = index.items.items.len() as u32;
        let _ = layout::parse_journal(&items, count, &index.cells, &mut out);
        if let Some((_, fewer)) = index.cells.split_last() {
            let _ = layout::parse_journal(&items, count, fewer, &mut Items::default());
        }
    }
    let _ = layout::parse_journal(raw, u32::from(head[0]), &[], &mut Items::default());
});
