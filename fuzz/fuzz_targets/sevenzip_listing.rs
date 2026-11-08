//! The 7-Zip backend reads another program's output (docs/M6.md §10): `7z l -slt` listings,
//! whose names and comments come from the archive, and 7-Zip's stderr. Neither reader may panic,
//! a listing stays within `max_entries`, and every exit code gets an answer.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{NameDecoding, SimpleCtx, backend::slt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = common::limits();
    if let Ok(l) = slt::parse(
        &mut &data[..],
        &NameDecoding::default(),
        &limits,
        &mut SimpleCtx::new(),
    ) {
        let max = limits.max_entries.unwrap_or(u64::MAX);
        assert!(l.items.len() as u64 <= max, "more entries than max_entries");
        for (n, i) in l.items.iter().enumerate() {
            assert_eq!(i.entry.id, n, "entries out of order");
        }
    }

    // The first byte picks the exit code: 7-Zip's are 0, 1, 2, 7, 8 and 255, and `None` is a
    // 7-Zip that was killed.
    let (code, stderr) = match data.split_first() {
        Some((&b, rest)) if b < 0xF0 => (Some(i32::from(b)), rest),
        Some((&b, rest)) if b < 0xF8 => (Some(255), rest),
        Some((_, rest)) => (None, rest),
        None => (Some(0), data),
    };
    let m = slt::messages(stderr);
    match m.error(code) {
        None => assert!(
            matches!(code, Some(0 | 1)) && m.errors.is_empty() && m.entries.is_empty(),
            "a failure without an error"
        ),
        Some(e) => assert!(!e.message.is_empty(), "an error without a message"),
    }
});
