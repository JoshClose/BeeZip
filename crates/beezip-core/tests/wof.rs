//! The WOF streams `tests/fixtures/make-ntfs.sh` puts in `thirdparty/ntfs/wof.img` (docs/M8.md
//! §4, §9): an ignored test that writes them, here on Windows, since XPRESS's are made by
//! Windows' own compressor.
//!
//! `cargo test -p beezip-core --test wof -- --ignored write_the_xpress_streams` writes
//! `tests/fixtures/wof/xpress{4,8,16}k.stream`: each the same 40,000 bytes ([`content`]) in
//! WOF's layout, every chunk compressed alone by `RtlCompressBuffer` with XPRESS Huffman's
//! standard engine, as WOF compresses (the M8 spike matched `compact /exe:`'s allocations to the
//! cluster with it), stored when it doesn't shrink. `streams.txt` beside them records each one's
//! size and the content's SHA-256. The LZX stream is wimlib's, made in make-ntfs.sh's container.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use sha2::{Digest, Sha256};

/// Text, a run of zeros and noise that doesn't compress, so the streams hold compressed chunks,
/// a long match and stored chunks.
fn content() -> Vec<u8> {
    let mut v = Vec::new();
    let mut i = 0u32;
    while v.len() < 24_000 {
        v.extend_from_slice(
            format!("line {i:05} of a file Windows compressed with WOF\n").as_bytes(),
        );
        i += 1;
    }
    v.truncate(24_000);
    v.extend(std::iter::repeat_n(0u8, 6_000));
    let mut x = 0x2545_F491u32;
    while v.len() < 40_000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        v.push(x as u8);
    }
    v
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn rtl_compress(chunk: &[u8]) -> Vec<u8> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetCompressionWorkSpaceSize(format: u16, buffer: *mut u32, fragment: *mut u32)
        -> i32;
        fn RtlCompressBuffer(
            format: u16,
            src: *const u8,
            src_len: u32,
            dst: *mut u8,
            dst_len: u32,
            chunk: u32,
            final_size: *mut u32,
            workspace: *mut u8,
        ) -> i32;
    }
    // COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_STANDARD
    let format = 4u16;
    let (mut ws, mut frag) = (0u32, 0u32);
    // SAFETY: both out-pointers are locals.
    let st = unsafe { RtlGetCompressionWorkSpaceSize(format, &raw mut ws, &raw mut frag) };
    assert_eq!(st, 0, "RtlGetCompressionWorkSpaceSize");
    let mut workspace = vec![0u8; ws as usize];
    let mut out = vec![0u8; chunk.len() * 2 + 1024];
    let mut size = 0u32;
    // SAFETY: the buffers are ours, with their lengths; the workspace is as large as asked.
    let st = unsafe {
        RtlCompressBuffer(
            format,
            chunk.as_ptr(),
            chunk.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
            4096,
            &raw mut size,
            workspace.as_mut_ptr(),
        )
    };
    // STATUS_BUFFER_ALL_ZEROS (0x117) is a success too.
    assert!(st == 0 || st == 0x117, "RtlCompressBuffer: {st:#x}");
    out.truncate(size as usize);
    out
}

/// `data` in WOF's layout with chunks of `chunk` bytes (see the module's notes).
fn stream(data: &[u8], chunk: usize, compress: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    let mut starts = Vec::new();
    for c in data.chunks(chunk) {
        starts.push(body.len() as u32);
        let z = compress(c);
        body.extend_from_slice(if z.len() < c.len() { &z } else { c });
    }
    let mut out = Vec::new();
    for s in starts.iter().skip(1) {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out.extend_from_slice(&body);
    out
}

#[cfg(windows)]
#[test]
#[ignore = "writes tests/fixtures/wof/: run it to remake them"]
fn write_the_xpress_streams() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/wof");
    std::fs::create_dir_all(&dir).unwrap();
    let data = content();
    let sha: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut list = String::new();
    for (name, chunk) in [
        ("xpress4k", 4096),
        ("xpress8k", 8192),
        ("xpress16k", 16_384),
    ] {
        let s = stream(&data, chunk, &rtl_compress);
        // Each decodes with BeeZip's own decoder.
        let mut back = Vec::new();
        for (i, c) in data.chunks(chunk).enumerate() {
            let z = rtl_compress(c);
            let mut out = vec![0u8; c.len()];
            if z.len() < c.len() {
                beezip_core::format::xpress::Decoder::new()
                    .decode(&z, &mut out)
                    .unwrap_or_else(|e| panic!("{name} chunk {i}: {e}"));
            } else {
                out.copy_from_slice(c);
            }
            back.extend_from_slice(&out);
        }
        assert!(back == data, "{name}");
        std::fs::write(dir.join(format!("{name}.stream")), &s).unwrap();
        list.push_str(&format!("{name} {} {sha}\n", data.len()));
    }
    std::fs::write(dir.join("streams.txt"), list).unwrap();
}
