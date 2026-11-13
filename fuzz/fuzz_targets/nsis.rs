//! Opens the input as an NSIS installer through BeeZip's own reader (docs/M10.md): the first
//! header, the method, the header's blocks, strings and instructions, the scan for each file's
//! size, then every file, in one pass and one by one, through BeeZip's inflater and bzip2 and
//! lzma-rust2.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::nsis, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.exe");
    let Ok(source) = Source::new(&path, Vec::new(), &common::open_options()) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = nsis::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut *reader, &mut cx);
});
