//! Opens the input as an RPM: the lead, both headers with every index entry checked, then the
//! cpio payload through the codecs.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::rpm::RpmReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.rpm");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = RpmReader::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut reader, &mut cx);
});
