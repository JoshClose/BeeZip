//! Parses the input as an encrypted `.bhive`'s key block (docs/bhive.md §12.3–§12.5): its
//! framing, every slot's public part and the limits on them, each slot's context and tag, and
//! section 5's slot descriptions from what follows. Whatever the parser accepts keeps the rules
//! the reader relies on.

#![no_main]

use beezip_core::format::bhive::{
    crypt::{Description, SLOT_TAIL_LEN, envelope::KeyBlock, split_descriptions},
    layout,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let header = layout::header_encrypted();
    let mut input = data;
    let Ok(block) = KeyBlock::read(&header, &mut input) else {
        return;
    };
    assert!(!block.slots.is_empty() && block.slots.len() <= 64);
    assert_eq!(block.len(), data.len() - input.len());
    let mut end = 16 + 60;
    for (_, range) in &block.slots {
        assert_eq!(range.start, end);
        assert!(range.len() >= 4 + SLOT_TAIL_LEN);
        end = range.end;
    }
    assert_eq!(end + 32, block.bytes.len());
    for view in block.views() {
        let _ = view.context(b"recipient");
        let _ = view.tag_for(b"spki");
        assert_eq!(view.tag().is_some(), view.tag_for(b"spki").is_some());
    }
    // The rest, as section 5's body for this many slots.
    if let Some(entries) = split_descriptions(input, block.slots.len()) {
        for e in entries {
            if let Ok(d) = Description::parse(&e) {
                assert!(Description::parse(&d.encode()).is_ok());
            }
        }
    }
});
