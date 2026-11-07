# Broken fixtures

From libarchive 3.8.11's tests (BSD-2-Clause, see ../../COPYING).
They aren't in manifest.json: each must fail as below, without a panic, a hang or a large
allocation. fetch-libarchive.ps1 writes this file.

| File | Expected | Why |
|---|---|---|
| `test_fuzz.lzh` | 29 entries, or Corrupt | test_fuzz.c's seed, not malformed as such: one archive of 29 entries in header levels 0 to 3 (the same six, symlinks included, at each level, then INSTALL), ended by its zero byte, with nine more archives run on after it. delharc 0.8.0 reads the 29, every CRC-16 good, and stops at the end mark; 7-Zip lists 18 with a headers error (it can't read level 3). Duplicate names keep it out of the manifest. |
| `test_read_format_lha_oversize_header.lzh` | Corrupt | The 19th header is larger than the file allows (test_read_format_lha_oversize_header.c: 18 entries, then ARCHIVE_FATAL). |
| `test_read_format_lha_symlink_missing_target.lzh` | Corrupt | A symlink entry whose name lacks the `|target` part; libarchive fails that entry and reads `second` after it (test_read_format_lha_symlink_missing_target.c). `second`'s level-0 header has no CRC field, an old variant libarchive takes and delharc refuses, so BeeZip fails the archive there. 7-Zip reports a headers error. |
| `test_copy_data_warning.lzh` | Corrupt | file1's data fails its CRC-16 (tar/test/test_copy_data_warning.c); 7-Zip reports a data error. |
