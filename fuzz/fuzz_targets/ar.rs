//! Opens the input as an ar, then as a Debian package (`debian-binary`, then tars through the
//! codecs), and exercises each reader that opens.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{
    SimpleCtx,
    format::{ar::ArReader, deb::DebReader},
    source::Source,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.ar");
    let opts = common::open_options();
    let mut cx = SimpleCtx::new();
    if let Ok(source) = Source::new(&path, Vec::new(), &opts)
        && let Ok(mut r) = ArReader::open(source, &mut cx)
    {
        common::exercise(&mut r, &mut cx);
    }
    if let Ok(source) = Source::new(&path, Vec::new(), &opts)
        && let Ok(mut r) = DebReader::open(source, &mut cx)
    {
        common::exercise(&mut r, &mut cx);
    }
});
