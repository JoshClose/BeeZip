//! Opens the input as a VHD through BeeZip's own reader (docs/M8.md §3.1): the disk, what's inside it, then every entry.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{External, SimpleCtx, format::volume::DiskReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.vhd");
    let opts = common::open_options();
    for kind in [External::Vhd] {
        if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
            let mut cx = SimpleCtx::new();
            if let Ok(mut reader) = DiskReader::open(source, kind, &mut cx) {
                common::exercise(&mut reader, &mut cx);
            }
        }
    }
});
