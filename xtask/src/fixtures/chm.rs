//! The malicious CHM help files (docs/M9.md §8), written by core's hand-made CHM writer
//! (`beezip_core::format::chm::write`, section 1 as LZX uncompressed blocks): names that leave
//! the destination; a directory whose chunk size or first entry can't be read; and a section 1
//! that claims a terabyte, whose reset table goes backwards, whose window or reset interval LZX
//! doesn't have, or whose entries point past the end.

use beezip_core::format::chm::write::{File, Layout, Raw, chm};

fn files() -> Vec<File<'static>> {
    vec![
        File {
            name: "/index.htm",
            section: 1,
            data: b"<html>index</html>",
        },
        File {
            name: "/#SYSTEM",
            section: 0,
            data: b"\x03\x00\x00\x00",
        },
    ]
}

fn with(layout: Layout) -> Vec<u8> {
    chm(&files(), &layout)
}

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        (
            "traversal.chm",
            chm(
                &[
                    File {
                        name: "/../evil.txt",
                        section: 1,
                        data: b"escaped",
                    },
                    File {
                        name: "/sub/../../evil2.txt",
                        section: 0,
                        data: b"escaped",
                    },
                    File {
                        name: "/safe.txt",
                        section: 1,
                        data: b"safe",
                    },
                ],
                &Layout::default(),
            ),
        ),
        (
            "chm-chunk-4gib.chm",
            with(Layout {
                chunk_size_field: Some(u32::MAX),
                ..Layout::default()
            }),
        ),
        (
            "chm-long-encint.chm",
            with(Layout {
                encint_padding: 20,
                ..Layout::default()
            }),
        ),
        (
            "chm-1tb.chm",
            with(Layout {
                uncompressed: Some(1 << 40),
                ..Layout::default()
            }),
        ),
        (
            "chm-reset-back.chm",
            with(Layout {
                reset_starts: Some(vec![100, 0]),
                uncompressed: Some(0x1_0000),
                ..Layout::default()
            }),
        ),
        (
            "chm-window-4mib.chm",
            with(Layout {
                window_frames: 128,
                ..Layout::default()
            }),
        ),
        (
            "chm-reset-0.chm",
            with(Layout {
                reset_frames: 0,
                ..Layout::default()
            }),
        ),
        (
            "chm-past-end.chm",
            with(Layout {
                extra: vec![
                    Raw {
                        name: b"/stored-1tb.bin".to_vec(),
                        section: 0,
                        offset: 1 << 40,
                        length: 1 << 40,
                    },
                    Raw {
                        name: b"/packed-1tb.bin".to_vec(),
                        section: 1,
                        offset: 0,
                        length: 1 << 40,
                    },
                ],
                ..Layout::default()
            }),
        ),
    ])
}
