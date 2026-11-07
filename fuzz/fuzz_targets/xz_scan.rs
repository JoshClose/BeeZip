//! The multithreaded xz decoder's scan reads an index and block headers from the end of any
//! bytes (docs/M6.md §6.4). It must never panic or hang, and whatever the threaded decoder
//! accepts, the one-threaded one must decode to the same bytes.

#![no_main]

#[path = "common.rs"]
mod common;

use std::io::{Cursor, Read};

use beezip_core::{CodecId, codec::xz_decoder_mt, io::Counter};
use libfuzzer_sys::fuzz_target;

/// Output is capped: a valid bomb is not a bug.
const CAP: u64 = 16 << 20;

fn decode(mut r: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    r.by_ref().take(CAP).read_to_end(&mut out).ok()?;
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let limits = common::limits();
    let input = Cursor::new(data.to_vec());
    let Some(threaded) = xz_decoder_mt(input, &limits, 2, &Counter::new()) else {
        return;
    };
    let Some(out) = decode(threaded) else {
        return;
    };
    let one = CodecId::Xz
        .decoder(Box::new(data), &limits)
        .ok()
        .and_then(decode);
    assert!(
        one.as_ref() == Some(&out),
        "the threaded decoder took what one thread doesn't decode the same"
    );
});
