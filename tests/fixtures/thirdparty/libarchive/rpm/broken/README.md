# Broken fixtures

From libarchive 3.8.11's tests (BSD-2-Clause, see ../../COPYING).
They aren't in manifest.json: each must fail as below, without a panic, a hang or a large
allocation. fetch-libarchive.ps1 writes this file.

| File | Expected | Why |
|---|---|---|
| `test_read_format_huge_rpm.rpm` | Corrupt | Truncated: its header asks for 34 359 738 384 bytes of the 10 256 there are (test_read_format_huge_rpm.c). Must fail before allocating. 7-Zip opens it as tar. |
