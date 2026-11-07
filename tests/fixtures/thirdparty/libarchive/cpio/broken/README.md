# Broken fixtures

From libarchive 3.8.11's tests (BSD-2-Clause, see ../../COPYING).
They aren't in manifest.json: each must fail as below, without a panic, a hang or a large
allocation. fetch-libarchive.ps1 writes this file.

| File | Expected | Why |
|---|---|---|
| `test_read_format_cpio_afio_header.part1.cpio` | UnsupportedFormat | afio's large ASCII header (`070727`), which BeeZip doesn't read; libarchive reads it across both parts (test_read_format_cpio_afio.c). |
| `test_read_format_cpio_afio_header.part2.cpio` | UnsupportedFormat | The rest of part1's member: no header at the start. |
