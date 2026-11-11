//! Opens the input as a WIM through BeeZip's own reader (docs/M8.md §5): the header, the lookup
//! table, solid resources and chunk tables, the XML, each image's metadata and folder walk, the
//! reparse points, then every entry, on one worker and on two. Nothing is beside the scratch
//! file, so a split set's other parts are missing; LZMS is Windows' own decoder, so on Linux an
//! LZMS image stops at the open.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::wim, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.wim");
    for threads in [1, 2] {
        let opts = common::open_options().with_threads(threads);
        let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
            return;
        };
        let mut cx = SimpleCtx::new();
        let Ok(mut reader) = wim::open(source, &mut cx) else {
            return;
        };
        common::exercise(&mut *reader, &mut cx);
    }
});
