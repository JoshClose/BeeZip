//! Opens the input as a cabinet: its folders and files, then each folder decoded (none, MSZIP,
//! LZX).

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::cab::CabReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.cab");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = CabReader::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut reader, &mut cx);
});
