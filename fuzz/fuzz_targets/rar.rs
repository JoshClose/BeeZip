//! Opens the input as a RAR through UnRAR, lists it, tests every entry into a `NullSink`, and
//! reads a few through `open_entry`. UnRAR only opens paths, so each input goes to a scratch
//! file. The C++ isn't instrumented, so coverage comes from the Rust side, but crashes in UnRAR
//! still end the run.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{format::rar::RarReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.rar");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = beezip_core::SimpleCtx::new().with_password("fuzz");
    if let Ok(mut reader) = RarReader::open(source, false, &mut cx) {
        common::exercise(reader.as_mut(), &mut cx);
    }
});
