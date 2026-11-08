//! Opens the input as a ZOO archive.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::zoo::ZooReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.zoo");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = ZooReader::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut reader, &mut cx);
});
