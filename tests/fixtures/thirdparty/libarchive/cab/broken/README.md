# Broken fixtures

From libarchive 3.8.11's tests (BSD-2-Clause, see ../../COPYING).
They aren't in manifest.json: each must fail as below, without a panic, a hang or a large
allocation. fetch-libarchive.ps1 writes this file.

| File | Expected | Why |
|---|---|---|
| `test_read_format_cab_lzx_invalid_history.cab` | Reads (should be Corrupt) | An LZX match reaches back before the start of the output (`LZX decompression failed (-25)` in libarchive); 7-Zip reports a data error. lzxd 0.2.7 decodes it as zeros instead, and a cabinet has no checksum of its decoded data, so BeeZip reads it (on the upstream list). |
| `test_read_format_cab_lzx_oob.cab` | UnsupportedFormat or Corrupt | Malformed LZX state that read out of bounds in libarchive (test_read_format_cab_lzx_oob.c only checks it survives); 7-Zip can't open it. |
| `test_read_format_cab_skip_malformed.cab` | UnsupportedFormat or Corrupt | A malformed payload that crashed libarchive's skip (test_read_format_cab_skip_malformed.c); 7-Zip can't open it. |
