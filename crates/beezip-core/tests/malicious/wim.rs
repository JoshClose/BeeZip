//! The malicious WIMs (docs/M8.md §9), made by `tests/fixtures/make-wim.sh` from its own
//! images, and inputs the M8 spike's fuzzer found:
//!
//! - `wim-folder-loop.wim`: `sub/nested`'s folder list is the root's (its metadata's SHA-1
//!   redone, so the image opens).
//! - `wim-solid-1tb.esd`: a solid resource that claims 1 TB of data.
//! - `wim-chunk-back.wim`: `text.txt`'s chunk table goes back.
//! - `wim-spike-panic.wim`: a stored solid chunk shorter than it says (the prototype panicked).
//! - `wim-spike-hang.wim`: an LZMS solid chunk that doesn't decode, held by every blob (the
//!   prototype decoded it again for each).
//! - `wim-spike-slow.wim`: slow on a loaded machine; its first image's metadata doesn't match
//!   its SHA-1.
//!
//! Each opens or fails at once, and what opens is tested and extracted within its limits, with
//! no panic: BeeZip's own reader only, never 7-Zip.

use std::time::{Duration, Instant};

use beezip_core::{ArchiveReader, FsSink, TestReport, format::wim, source::Source};

use super::*;

fn native(name: &str) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let source = Source::new(&corpus(name), Vec::new(), &OpenOptions::default())?;
    wim::open(source, &mut SimpleCtx::new())
}

/// The test's report and the extraction's result, each within a few seconds.
fn exercise(name: &str, r: &mut dyn ArchiveReader) -> (TestReport, beezip_core::Result<()>) {
    let t = Instant::now();
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let mut sink = FsSink::new(dest.path(), FsOptions::default()).unwrap();
    let extracted = r
        .extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .and_then(|()| sink.finish(&mut SimpleCtx::new()).map(|_| ()));
    let ids: Vec<usize> = (0..r.entries(&mut SimpleCtx::new()).unwrap().len()).collect();
    for id in ids {
        if let Ok(mut d) = r.open_entry(id, &mut SimpleCtx::new()) {
            let _ = std::io::copy(&mut d, &mut std::io::sink());
        }
    }
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "{name}: {:?}",
        t.elapsed()
    );
    (report, extracted)
}

#[test]
fn wim_claims_are_refused_or_read_within_limits() {
    for name in ["wim-solid-1tb.esd", "wim-spike-slow.wim"] {
        let t = Instant::now();
        let e = native(name).err().unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{name}: {e}");
        assert!(t.elapsed() < Duration::from_secs(2), "{name}");
    }

    let mut cx = SimpleCtx::new();
    let source = Source::new(
        &corpus("wim-folder-loop.wim"),
        Vec::new(),
        &OpenOptions::default(),
    )
    .unwrap();
    let mut r = wim::open(source, &mut cx).unwrap();
    assert!(
        cx.warnings.iter().any(|w| w.contains("isn't listed again")),
        "{:?}",
        cx.warnings
    );
    let (report, extracted) = exercise("wim-folder-loop.wim", &mut *r);
    assert!(report.ok(), "{report:?}");
    extracted.unwrap();

    let mut r = native("wim-chunk-back.wim").unwrap();
    let (report, extracted) = exercise("wim-chunk-back.wim", &mut *r);
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert_eq!(report.errors[0].path, "text.txt");
    let e = extracted.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Corrupt);
    assert!(e.message.contains("text.txt"), "{e}");

    // Its solid resource says LZMS: on Windows, read and found damaged; elsewhere, left to 7-Zip.
    let opened = native("wim-spike-panic.wim");
    assert_eq!(opened.is_ok(), cfg!(windows), "{:?}", opened.as_ref().err());
    match opened {
        Ok(mut r) => {
            let (report, _) = exercise("wim-spike-panic.wim", &mut *r);
            assert!(!report.ok());
            assert!(
                report
                    .errors
                    .iter()
                    .all(|e| e.kind == ErrorKind::Corrupt || e.kind == ErrorKind::NotFound),
                "{report:?}"
            );
        }
        Err(e) => assert_eq!(e.kind, ErrorKind::UnsupportedOperation),
    }

    // LZMS: on Windows, read and found damaged; elsewhere, left to 7-Zip.
    let opened = native("wim-spike-hang.wim");
    assert_eq!(opened.is_ok(), cfg!(windows), "{:?}", opened.as_ref().err());
    match opened {
        Ok(mut r) => {
            let (report, _) = exercise("wim-spike-hang.wim", &mut *r);
            assert!(!report.ok());
        }
        Err(e) => assert_eq!(e.kind, ErrorKind::UnsupportedOperation),
    }
}
