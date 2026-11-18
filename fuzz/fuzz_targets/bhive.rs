//! Opens the input as a `.bhive` (docs/M13.md §8): the footer, the index block and every rule
//! of docs/bhive.md §9, then every entry in one pass and one by one, and the whole archive
//! tested cell by cell. Then again from the records before the cells, as a cut archive is
//! recovered.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{
    ArchiveReader, OpenOptions, SimpleCtx, format::bhive::BhiveReader, source::Source,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.bhive");
    for recover in [false, true] {
        let opts = OpenOptions {
            recover,
            ..common::open_options()
        };
        let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
            return;
        };
        let mut cx = SimpleCtx::new();
        let Ok(mut reader) = BhiveReader::open(source, &mut cx) else {
            continue;
        };
        common::exercise(&mut reader, &mut cx);
        let _ = reader.test(&mut cx);
    }
});
