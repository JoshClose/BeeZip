//! Opens the input as a CramFS image through BeeZip's own reader (docs/M10.md): the superblock
//! at 0 or 512 in either byte order, the folders, the block size from the layout, the links'
//! targets, then every file, in one pass and one by one, block by block.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::cramfs, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.cramfs");
    let Ok(source) = Source::new(&path, Vec::new(), &common::open_options()) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = cramfs::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut *reader, &mut cx);
});
