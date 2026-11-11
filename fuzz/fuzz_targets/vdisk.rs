//! Opens the input as a VMDK, a QCOW2 and a VDI through BeeZip's own readers (docs/M8.md §3.3-3.5): the disk, what's inside it, then every entry. Each reader checks its own signature, so trying all three costs little.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{External, SimpleCtx, format::volume::DiskReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.img");
    let opts = common::open_options();
    for kind in [External::Vmdk, External::Qcow2, External::Vdi] {
        if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
            let mut cx = SimpleCtx::new();
            if let Ok(mut reader) = DiskReader::open(source, kind, &mut cx) {
                common::exercise(&mut reader, &mut cx);
            }
        }
    }
});
