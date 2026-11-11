//! BeeZip's XPRESS Huffman decoder (docs/M8.md §4.2) on any bytes: the first two give the
//! output's size (up to 64 KiB, a WIM chunk), the rest is the stream. It must fail cleanly or
//! fill the output, never panic.

#![no_main]

use beezip_core::format::xpress::Decoder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((size, stream)) = data.split_first_chunk::<2>() else {
        return;
    };
    let mut out = vec![0u8; usize::from(u16::from_le_bytes(*size)) + 1];
    let _ = Decoder::new().decode(stream, &mut out);
});
