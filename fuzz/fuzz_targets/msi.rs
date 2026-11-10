//! Opens the input as a Windows Installer package: the compound file (cfb), the string pool
//! and catalog, the tables, the folders' layout and its caps, the embedded cabinets, then every
//! entry. Nothing is beside the scratch file, so external cabinets and source files are missing.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::msi, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.msi");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = msi::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut *reader, &mut cx);
});
