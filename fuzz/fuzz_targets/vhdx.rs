//! Opens the input as a VHDX through BeeZip's own reader (docs/M8.md §3.2), its log replayed in memory: the disk, what's inside it, then every entry.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{External, SimpleCtx, format::volume::DiskReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.vhdx");
    let opts = common::open_options();
    for kind in [External::Vhdx] {
        if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
            let mut cx = SimpleCtx::new();
            if let Ok(mut reader) = DiskReader::open(source, kind, &mut cx) {
                common::exercise(&mut reader, &mut cx);
            }
        }
    }
});
