//! Inputs the fuzzers and the mutation test found (`tests/fixtures/regress/`). Each must give an
//! error or a result within a few seconds: never a panic, never a hang. The mutation test runs
//! over them too.
//!
//! - `fuzz-sevenz-bzip2-overflow.7z` (the `sevenz` fuzzer): its BZip2 block makes
//!   libbz2-rs-sys 0.2.6 subtract past zero. Release builds wrap and then reject the data; the
//!   workspace turns overflow checks off for that crate so debug builds do the same.
//! - `fuzz-sevenz-bzip2-reread.7z` (the `sevenz` fuzzer): a solid block whose BZip2 stream is
//!   bad from its first block. The sinks record the damaged entry and go on, and sevenz-rust2
//!   then read the failed decoder again for the next. libbz2-rs-sys 0.2.6 resumed from where
//!   the error left it and indexed past an array, a panic in an `extern "C"` function, so the
//!   process aborted. The 7z reader now stops a block whose decoder failed.
//! - `bzip2-reread.tar.bz2`: the same through the codecs. One bzip2 stream holding the tar's
//!   first 1024 bytes (a header and part of `a.bin`), then the 7z's BZip2 stream. The tar
//!   reader read on to the next header and aborted the same way; now every codec's decoder is
//!   a `LatchReader`.
//! - `mutation-rar4-header-password-loop.rar` (`mutations.rs`): a RAR 4 whose damaged header
//!   claims encrypted names. UnRAR asked for the password while reading the first header, the
//!   listing gave the same answer every time, and retried forever.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::Duration,
};

use beezip_core::{ErrorKind, NullSink, OpenOptions, Selection, SimpleCtx, TestSink, open};

#[test]
fn regressions_end_quickly_without_panicking() {
    let mut n = 0;
    for e in std::fs::read_dir(dir()).unwrap() {
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
    assert_eq!(n, 4);
}

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/regress")
}

/// What `archive.test` sees: the damaged entry, then one error for what couldn't be read after
/// it. (Reading the failed decoder again aborted the test process.)
fn test_errors(name: &str) -> (Vec<String>, beezip_core::Error) {
    let mut cx = SimpleCtx::new();
    let mut opened = open(&dir().join(name), &OpenOptions::default(), &mut cx).unwrap();
    let mut sink = TestSink::default();
    let err = opened
        .reader
        .extract(&Selection::all(), &mut sink, &mut cx)
        .unwrap_err();
    let paths = sink.report.errors.iter().map(|e| e.path.clone()).collect();
    (paths, err)
}

#[test]
fn a_7z_block_stops_when_its_decoder_fails() {
    let (paths, err) = test_errors("fuzz-sevenz-bzip2-reread.7z");
    assert_eq!(paths, ["tree/data/random.bin"]);
    assert_eq!(err.kind, ErrorKind::Corrupt);
    assert_eq!(
        err.message,
        "the rest of the solid block after tree/data/random.bin can't be decoded"
    );
}

#[test]
fn a_failed_codec_is_not_read_again() {
    let (paths, err) = test_errors("bzip2-reread.tar.bz2");
    assert_eq!(paths, ["a.bin"]);
    assert_eq!(err.kind, ErrorKind::Corrupt);
    assert_eq!(err.message, "tar: bzip2: invalid data");
}
