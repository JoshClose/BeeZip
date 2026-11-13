//! The malicious NSIS installers (docs/M10.md §8), written by core's hand-made NSIS writer
//! (`beezip_core::format::nsis::write`) and then broken: names that leave the destination; a
//! header of 4 GiB, instructions past the header's end, and a string with no end; 10,000 nested
//! `SetOutPath "$OUTDIR\x"`; records that claim 4 GiB or point past the end; an LZMA dictionary
//! of 4 GiB; an uninstaller's patch outside the stub; and a deflate bomb, solid and not.

use beezip_core::format::nsis::write::{Layout, Method, Op, nsis};

/// A small installer's layout: a one-sector stub.
fn small() -> Layout {
    Layout {
        stub: 512,
        ..Layout::default()
    }
}

fn files() -> Vec<Op<'static>> {
    vec![
        Op::SetOutPath(b"$INSTDIR"),
        Op::File(b"first.txt", b"the first file"),
        Op::File(b"big.bin", &[0x5A; 6000]),
        Op::File(b"safe.txt", b"safe"),
    ]
}

/// Where a non-solid installer's stored header starts: after the stub, the first header and
/// the header record's length.
const STORED: usize = 512 + 28 + 4;

/// `files()` with the header stored, not compressed.
fn stored_header() -> Vec<u8> {
    nsis(
        &files(),
        &Layout {
            solid: false,
            method: Method::Deflate,
            header_compressed: false,
            ..small()
        },
    )
}

/// Bytes of a little-endian u32 at `at`, replaced.
fn set32(mut b: Vec<u8>, at: usize, v: u32) -> Vec<u8> {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    b
}

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    let first_header = 512;
    let nested: Vec<Op<'static>> = std::iter::once(Op::SetOutPath(b"$INSTDIR"))
        .chain((0..10_000).map(|_| Op::SetOutPath(b"$OUTDIR\\x")))
        .chain(std::iter::once(Op::File(b"deep.txt", b"deep")))
        .collect();
    let zeros = vec![0u8; 8 << 20];
    Ok(vec![
        (
            "traversal.nsis.exe",
            nsis(
                &[
                    Op::SetOutPath(b"$INSTDIR"),
                    Op::File(b"..\\..\\evil.txt", b"escaped"),
                    Op::File(b"sub\\..\\..\\evil2.txt", b"escaped"),
                    Op::File(b"safe.txt", b"safe"),
                ],
                &small(),
            ),
        ),
        (
            "nsis-header-4gib.exe",
            set32(nsis(&files(), &small()), first_header + 20, u32::MAX),
        ),
        // A stored header: its instruction count past its end, and its last string's NUL gone.
        (
            "nsis-instructions-past-end.exe",
            set32(stored_header(), STORED + 24, 0x00FF_FFFF),
        ),
        ("nsis-string-no-end.exe", {
            let mut b = stored_header();
            let len = u32::from_le_bytes(b[first_header + 20..first_header + 24].try_into()?);
            let last = STORED + len as usize - 2;
            b[last] = b'x';
            b
        }),
        ("nsis-nested-10000.exe", nsis(&nested, &small())),
        (
            "nsis-record-4gib.exe",
            nsis(
                &files(),
                &Layout {
                    lengths: vec![(1, u32::MAX >> 1)],
                    ..small()
                },
            ),
        ),
        (
            "nsis-record-past-end.exe",
            nsis(
                &[
                    Op::File(b"first.txt", b"the first file"),
                    Op::FileAt(b"past-end.bin", 0x7000_0000),
                    Op::File(b"safe.txt", b"safe"),
                ],
                &Layout {
                    solid: false,
                    method: Method::Deflate,
                    ..small()
                },
            ),
        ),
        // The dictionary in the solid stream's LZMA properties, after the first header: almost
        // 4 GiB, its low bytes 0 as NSIS's are (or it wouldn't be taken for LZMA).
        (
            "nsis-dict-4gib.exe",
            set32(nsis(&files(), &small()), first_header + 28 + 1, 0xFFFF_0000),
        ),
        (
            "nsis-patch-outside.exe",
            nsis(
                &[
                    Op::File(b"safe.txt", b"safe"),
                    Op::WriteUninstaller {
                        name: b"$INSTDIR\\uninstall.exe",
                        alt: None,
                        data: b"uninstaller data",
                        patches: vec![(1 << 20, b"ICON".to_vec())],
                    },
                ],
                &small(),
            ),
        ),
        (
            "nsis-bomb.exe",
            nsis(
                &[
                    Op::File(b"zeros.bin", &zeros),
                    Op::File(b"safe.txt", b"safe"),
                ],
                &Layout {
                    solid: false,
                    method: Method::Deflate,
                    ..small()
                },
            ),
        ),
        (
            "nsis-bomb-solid.exe",
            nsis(
                &[
                    Op::File(b"zeros.bin", &zeros),
                    Op::File(b"safe.txt", b"safe"),
                ],
                &Layout {
                    method: Method::Deflate,
                    ..small()
                },
            ),
        ),
    ])
}
