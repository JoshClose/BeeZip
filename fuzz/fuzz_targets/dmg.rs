//! Opens the input as a disk image: the UDIF trailer and plist, the chunk tables, the partition
//! map and the HFS+ or APFS volume through fstool, then every entry. The same bytes are also
//! decoded as one chunk of each codec (lzfse_rust's unsafe code among them, docs/M5.md §1) and as
//! an Apple-compressed file (decmpfs: zlib, LZVN and LZFSE, inline and in a resource fork).

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::{
    SimpleCtx,
    format::{
        dmg::{DmgReader, decode_decmpfs},
        udif,
    },
    source::Source,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = common::scratch(data, "input.dmg");
    let opts = common::open_options();
    if let Ok(source) = Source::new(&path, Vec::new(), &opts) {
        let mut cx = SimpleCtx::new();
        if let Ok(mut reader) = DmgReader::open(source, &mut cx) {
            common::exercise(&mut reader, &mut cx);
        }
    }

    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let kinds = [
        udif::ZLIB,
        udif::BZIP2,
        udif::LZFSE,
        udif::LZMA,
        udif::ADC,
        udif::RAW,
    ];
    let kind = kinds[usize::from(pick) % kinds.len()];
    let want = (usize::from(pick >> 3) + 1) * 4096;
    let mem_kib = opts.limits.decoder_memory_kib();
    let _ = udif::decode_chunk(kind, rest, want, pick & 1 == 1, mem_kib);

    // The attribute, then the resource fork.
    let split = rest.len().min(usize::from(pick) * 16 + 16);
    let (attr, fork) = rest.split_at(split);
    let _ = decode_decmpfs(attr, (!fork.is_empty()).then_some(fork), 1 << 20);
});
