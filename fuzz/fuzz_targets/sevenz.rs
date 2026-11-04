//! Opens the input as a 7z (the encoded-header check first), lists it, extracts every entry
//! into a `NullSink`, and reads a few through `open_entry`, which decodes on a helper thread.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{format::sevenz::SevenZReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SevenZReader reads through `Source`, which opens a path.
    let path = common::scratch(data, "input.7z");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = beezip_core::SimpleCtx::new().with_password("fuzz");
    if let Ok(mut reader) = SevenZReader::open(source, false, &mut cx) {
        common::exercise(&mut reader, &mut cx);
    }
});
