//! Opens the input as a plain tar, lists it, extracts every entry into a `NullSink`, and reads
//! a few entries through `open_entry` (seeking, and rescanning for sparse files and links).

#![no_main]

#[path = "common.rs"]
mod common;

use std::io::Read;

use beezip_core::{
    ArchiveReader, NullSink, Selection, SimpleCtx, format::tar::TarReader, source::Source,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.tar");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let mut reader = TarReader::new(source);
    let count = reader.entries(&mut cx).map(<[_]>::len).unwrap_or(0);
    let _ = reader.info(&mut cx);
    let _ = reader.extract(&Selection::all(), &mut NullSink::default(), &mut cx);
    for id in 0..count.min(8) {
        if let Ok(mut r) = reader.open_entry(id, &mut cx) {
            let _ = std::io::copy(&mut r.by_ref().take(1 << 20), &mut std::io::sink());
        }
    }
});
