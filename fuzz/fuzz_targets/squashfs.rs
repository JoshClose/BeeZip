//! Opens the input as a squashfs image: the superblock, the inode and directory tables walked
//! into a listing, then every file decoded (gzip, lzma, lzo, xz, lz4, zstd), its blocks, holes
//! and fragments.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{SimpleCtx, format::squashfs::SquashfsReader, source::Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.squashfs");
    let opts = common::open_options();
    let Ok(source) = Source::new(&path, Vec::new(), &opts) else {
        return;
    };
    let mut cx = SimpleCtx::new();
    let Ok(mut reader) = SquashfsReader::open(source, &mut cx) else {
        return;
    };
    common::exercise(&mut reader, &mut cx);
});
