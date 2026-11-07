//! Opens the input as an LHA archive through delharc, with BeeZip's names, symlinks and CRC-16
//! checks.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::lzh::LzhReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.lzh");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = LzhReader::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut reader, &mut cx);
});
