//! Opens the input as a disk (GPT or MBR, by the first byte's low bit) and as a bare HFS+ or APFS
//! volume, through BeeZip's own readers (docs/M7.md §3, §7): the partition table, each
//! partition's file system, then every entry.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{External, SimpleCtx, format::volume::DiskReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.img");
    let opts = common::open_options();
    let kinds = match data.first() {
        Some(b) if b & 1 == 1 => [External::Mbr, External::Hfs],
        _ => [External::Gpt, External::Apfs],
    };
    for kind in kinds {
        if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
            let mut cx = SimpleCtx::new();
            if let Ok(mut reader) = DiskReader::open(source, kind, &mut cx) {
                common::exercise(&mut reader, &mut cx);
            }
        }
    }
});
