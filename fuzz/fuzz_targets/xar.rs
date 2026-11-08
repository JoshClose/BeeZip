//! Opens the input as a XAR archive, then as a macOS package.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{
    SimpleCtx,
    format::{pkg::PkgReader, xar::XarReader},
    source::Source,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.xar");
    let opts = common::open_options();
    let mut cx = SimpleCtx::new();
    if let Ok(source) = Source::new(&path, Vec::new(), &opts)
        && let Ok(mut reader) = XarReader::open(source, &mut cx)
    {
        common::exercise(&mut reader, &mut cx);
    }
    if let Ok(source) = Source::new(&path, Vec::new(), &opts)
        && let Ok(mut reader) = PkgReader::open(source, &mut cx)
    {
        common::exercise(&mut reader, &mut cx);
    }
});
