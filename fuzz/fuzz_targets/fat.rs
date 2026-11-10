//! Opens the input as a bare FAT volume through BeeZip's own reader (docs/M7.md §4): the boot
//! sector, the FAT, every folder's chain and long names, then every file's chain.

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
        if let Ok(mut reader) = DiskReader::open(source, External::Fat, &mut cx) {
            common::exercise(&mut reader, &mut cx);
        }
    }
});
