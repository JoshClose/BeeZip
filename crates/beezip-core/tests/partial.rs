//! `partial::abandon_all` (docs/M3.md §3.7, §6). It refuses partial files for the rest of the
//! process, so it has this test binary to itself.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use beezip_core::{
    ErrorKind,
    safefs::partial::{self, Partial},
};

#[test]
fn abandon_all_deletes_open_files_and_refuses_new_ones() {
    let dir = tempfile::tempdir().unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let writer = {
        let dir = dir.path().to_path_buf();
        let done = done.clone();
        thread::spawn(move || {
            let mut p = Partial::create(&dir, "big.bin").unwrap();
            tx.send(p.path().to_path_buf()).unwrap();
            let chunk = vec![7u8; 64 * 1024];
            // Keep writing while the main thread abandons it, as an extracting job would.
            while !done.load(Ordering::Relaxed) {
                p.file_mut().write_all(&chunk).unwrap();
            }
            p.persist(&dir.join("big.bin")).unwrap_err().kind
        })
    };
    let path = rx.recv().unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(path.exists());
    assert_eq!(partial::live(), 1);

    assert_eq!(partial::abandon_all(), 1);
    assert!(!path.exists(), "the open partial file was deleted");
    assert_eq!(partial::live(), 0);

    done.store(true, Ordering::Relaxed);
    assert_eq!(writer.join().unwrap(), ErrorKind::Cancelled);
    assert!(!dir.path().join("big.bin").exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

    let err = Partial::create(dir.path(), "later").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
}
