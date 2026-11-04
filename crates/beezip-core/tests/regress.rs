//! Inputs the fuzzers and the mutation test found (`tests/fixtures/regress/`). Each must give an
//! error or a result within a few seconds: never a panic, never a hang. The mutation test runs
//! over them too.
//!
//! - `fuzz-sevenz-bzip2-overflow.7z` (the `sevenz` fuzzer): its BZip2 block makes
//!   libbz2-rs-sys 0.2.6 subtract past zero. Release builds wrap and then reject the data; the
//!   workspace turns overflow checks off for that crate so debug builds do the same.
//! - `mutation-rar4-header-password-loop.rar` (`mutations.rs`): a RAR 4 whose damaged header
//!   claims encrypted names. UnRAR asked for the password while reading the first header, the
//!   listing gave the same answer every time, and retried forever.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::Path, sync::mpsc, thread, time::Duration};

use beezip_core::{NullSink, OpenOptions, Selection, SimpleCtx, open};

#[test]
fn regressions_end_quickly_without_panicking() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/regress");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let path = e.unwrap().path();
        n += 1;
        let (tx, rx) = mpsc::channel();
        let p = path.clone();
        thread::spawn(move || {
            let mut cx = SimpleCtx::new().with_password("fuzz");
            if let Ok(mut opened) = open(&p, &OpenOptions::default(), &mut cx) {
                let _ = opened.reader.entries(&mut cx);
                let _ = opened
                    .reader
                    .extract(&Selection::all(), &mut NullSink::default(), &mut cx);
            }
            let _ = tx.send(());
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("{} hangs", path.display()),
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{} panicked", path.display()),
        }
    }
    assert_eq!(n, 2);
}
