//! Inputs the fuzzers found (`tests/fixtures/regress/`). Each must give an error or a result,
//! never a panic. The mutation test runs over them too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use beezip_core::{NullSink, OpenOptions, Selection, SimpleCtx, open};

fn each(f: impl Fn(&Path)) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/regress");
    for e in std::fs::read_dir(dir).unwrap() {
        f(&e.unwrap().path());
    }
}

/// The `sevenz` fuzzer, 2026-11-04: a 7z whose BZip2 block makes libbz2-rs-sys 0.2.6 subtract
/// past zero (`curr -= 1` in `decompress.rs`). Release builds wrap and then reject the data;
/// the workspace turns overflow checks off for that crate so debug builds do the same.
#[test]
fn fuzzer_finds_stay_fixed() {
    each(|path| {
        let mut cx = SimpleCtx::new().with_password("fuzz");
        if let Ok(mut opened) = open(path, &OpenOptions::default(), &mut cx) {
            let _ = opened.reader.entries(&mut cx);
            let _ = opened
                .reader
                .extract(&Selection::all(), &mut NullSink::default(), &mut cx);
        }
    });
}
