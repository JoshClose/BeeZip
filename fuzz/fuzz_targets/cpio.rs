//! Opens the input as a plain cpio (every header format), lists it, extracts every entry into a
//! `NullSink`, and reads a few entries through `open_entry`.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::cpio::CpioReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.cpio");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let mut reader = CpioReader::new(source);
    common::exercise(&mut reader, &mut cx);
});
