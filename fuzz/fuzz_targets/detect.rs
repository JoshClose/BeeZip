//! Detection takes any bytes: it must never panic, and must stop at `max_layers`.

#![no_main]

#[path = "common.rs"]
mod common;

use beezip_core::detect_bytes;
use libfuzzer_sys::fuzz_target;

const NAMES: [Option<&str>; 6] = [
    None,
    Some("x.tar.gz"),
    Some("x.zip"),
    Some("x.br"),
    Some("x.lzma"),
    Some("x.zz"),
];

fuzz_target!(|data: &[u8]| {
    let limits = common::limits();
    let name = NAMES[data.len() % NAMES.len()];
    let det = detect_bytes(data, name, &limits);
    assert!(det.codecs().len() <= limits.max_layers);
    if !det.layers.is_empty() {
        assert!(
            det.format().is_some(),
            "a chain must end in a format: {det:?}"
        );
    }
});
