//! Opens the input as an ISO through hadris-iso and hadris-udf: the Rock Ridge, Joliet or
//! primary tree, the UDF tree when there is one, and BeeZip's zisofs (`ZF`) scan of each folder.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::iso::IsoReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.iso");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = IsoReader::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut reader, &mut cx);
});
