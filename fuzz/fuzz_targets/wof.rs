//! A WOF file's compressed stream (docs/M8.md §4) through BeeZip's `WofReader`: the first byte
//! gives the algorithm, the next three the file's size (up to 16 MiB), the rest is the stream.
//! Reading it whole and seeking about must fail cleanly or give the file's size, never panic.

#![no_main]

use std::io::{Cursor, Read, Seek, SeekFrom};

use beezip_core::format::volume::wof::{Algorithm, WofReader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((head, stream)) = data.split_first_chunk::<4>() else {
        return;
    };
    let Some(algo) = Algorithm::from_id(u32::from(head[0] & 3)) else {
        return;
    };
    let size = u64::from(u32::from_le_bytes([head[1], head[2], head[3], 0]));
    let Ok(mut r) = WofReader::new(Cursor::new(stream), "fuzz", algo, size) else {
        return;
    };
    let mut out = Vec::new();
    if r.read_to_end(&mut out).is_ok() {
        assert_eq!(out.len() as u64, size);
    }
    for at in [size / 2, size.saturating_sub(1), 0] {
        if r.seek(SeekFrom::Start(at)).is_ok() {
            let _ = r.read(&mut [0u8; 64]);
        }
    }
});
