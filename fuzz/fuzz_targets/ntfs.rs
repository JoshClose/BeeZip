//! Opens the input as a bare NTFS volume through BeeZip's own reader (docs/M7.md §6): the boot
//! sector and `$MFT`'s first record checked before fstool reads them, every record checked before
//! fstool walks its attributes, BeeZip's folder walk, links and reparse points, then every entry
//! through fstool's stream reader (LZNT1, holes) under the shared ratio check.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{External, SimpleCtx, format::volume::DiskReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.ntfs");
    let opts = common::open_options();
    if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
        let mut cx = SimpleCtx::new();
        if let Ok(mut reader) = DiskReader::open(source, External::Ntfs, &mut cx) {
            common::exercise(&mut reader, &mut cx);
        }
    }
});
