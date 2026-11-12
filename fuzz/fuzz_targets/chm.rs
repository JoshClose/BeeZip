//! Opens the input as a CHM help file through BeeZip's own reader (docs/M9.md): the header, the
//! directory's chunks, the section names, section 1's control data and reset table, then every
//! entry, in one pass and one by one, each frame through BeeZip's LZX decoder.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::chm, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.chm");
    let Ok(source) = Source::new(&path, Vec::new(), &common::open_options()) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = chm::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut *reader, &mut cx);
});
