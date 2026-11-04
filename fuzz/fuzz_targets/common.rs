//! Shared by the targets: tight limits, and a scratch file for readers that want a path.

#![allow(dead_code)]

use std::{path::PathBuf, sync::OnceLock};

use beezip_core::{Limits, OpenOptions};

/// Small enough that a bomb in the corpus can't stall a run or exhaust memory.
pub fn limits() -> Limits {
    Limits {
        max_ratio: Some(200),
        ratio_grace: 1 << 20,
        max_total_bytes: Some(32 << 20),
        max_entries: Some(10_000),
        max_layers: 4,
        decoder_memory: 64 << 20,
    }
}

pub fn open_options() -> OpenOptions {
    OpenOptions::new(limits())
}

/// Writes `data` to this process's scratch file and returns its path. Each fuzzing process runs
/// one input at a time, so one file is enough.
pub fn scratch(data: &[u8], name: &str) -> PathBuf {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    let dir = DIR.get_or_init(|| tempfile::tempdir().expect("a temp dir"));
    let path = dir.path().join(name);
    std::fs::write(&path, data).expect("writing the scratch file");
    path
}

/// What the archive targets do with a reader: list it, describe it, extract every entry into a
/// `NullSink`, and read a few entries through `open_entry`.
pub fn exercise(r: &mut dyn beezip_core::ArchiveReader, cx: &mut beezip_core::SimpleCtx) {
    use std::io::Read;
    let count = r.entries(cx).map(<[_]>::len).unwrap_or(0);
    let _ = r.info(cx);
    let _ = r.extract(
        &beezip_core::Selection::all(),
        &mut beezip_core::NullSink::default(),
        cx,
    );
    for id in 0..count.min(8) {
        if let Ok(mut e) = r.open_entry(id, cx) {
            let _ = std::io::copy(&mut e.by_ref().take(1 << 20), &mut std::io::sink());
        }
    }
}
