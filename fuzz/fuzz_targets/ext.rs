//! Opens the input as an ext2/3/4 volume through BeeZip's own reader (docs/M7.md §5): the
//! superblock checks, fstool's group descriptors, a journal replayed in memory, then every
//! folder, link and file (block maps, extent trees, inline data).

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{External, SimpleCtx, format::volume::DiskReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.img");
    let opts = common::open_options();
    if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
        let mut cx = SimpleCtx::new();
        if let Ok(mut reader) = DiskReader::open(source, External::Ext, &mut cx) {
            common::exercise(&mut reader, &mut cx);
        }
    }
});
