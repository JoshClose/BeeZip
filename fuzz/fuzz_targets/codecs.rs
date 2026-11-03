//! The first byte picks a codec; the rest is decoded under tight limits.

#![no_main]

#[path = "common.rs"]
mod common;

use std::io::Read;

use beezip_core::CodecId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let codec = CodecId::ALL[usize::from(pick) % CodecId::ALL.len()];
    let limits = common::limits();
    if let Ok(dec) = codec.codec().decoder(Box::new(rest), &limits) {
        // Output is capped: a valid bomb is not a bug.
        let _ = std::io::copy(&mut dec.take(16 << 20), &mut std::io::sink());
    }
});
