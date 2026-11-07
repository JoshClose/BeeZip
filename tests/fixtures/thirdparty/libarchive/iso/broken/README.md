# Broken fixtures

From libarchive 3.8.11's tests (BSD-2-Clause, see ../../COPYING).
They aren't in manifest.json: each must fail as below, without a panic, a hang or a large
allocation. fetch-libarchive.ps1 writes this file.

| File | Expected | Why |
|---|---|---|
| `test_read_format_iso_zisofs.iso.Z` | UnsupportedOperation | file and hardlink are zisofs-compressed (Rock Ridge ZF): listed with their real size (12 345 684 bytes), and extracting either is UnsupportedOperation, as BeeZip doesn't decompress zisofs (docs/M5.md §5.9). 7-Zip lists their compressed bytes. |
| `test_read_format_iso_joliet_overlong.iso.Z` | Reads | Joliet names past the 103 characters libarchive takes (test_read_format_isojoliet_long.c reads them cut, as in joliet_long); 7-Zip can't open it. BeeZip lists the same three entries as test_read_format_iso_joliet_long. |
| `test_read_format_iso_joliet_utf16be_cycle.iso.Z` | Reads (lists nothing) | The Joliet tree loops back on itself (test_read_format_iso_joliet_utf16be_cycle.c: libarchive fails with "Pathname is too long"). hadris reads the Joliet root as empty, so nothing is listed; no hang. |
| `test_read_format_iso_joliet_utf16be_overflow.iso` | Reads | A Joliet path longer than libarchive's buffer (test_read_format_iso_joliet_utf16be_overflow.c: "Pathname is too long"). BeeZip lists the six folders; extraction makes the path if the file system takes it. |
| `test_read_format_iso_rockridge_ce_loop.iso.Z` | Corrupt | A Rock Ridge continuation area (CE) that points at itself (test_read_format_isorr_ce_loop.c: ARCHIVE_FATAL). hadris lists the entry under its ISO 9660 name; opening it fails. |
| `test_read_format_iso_rockridge_ce_overflow.iso.Z` | Corrupt | A CE entry whose offset and length run past its block (test_read_format_iso_rockridge_ce_overflow.c: "Invalid parameter in SUSP "CE" extension"). |
| `test_read_format_iso_rockridge_cl_re_cycle.iso.Z` | Reads | Relocated folders (CL and RE) that point at each other (test_read_format_iso_rockridge_cl_re_cycle.c: ARCHIVE_FATAL). hadris doesn't follow the loop: the folders are listed where they are stored, in rr_moved; no hang. |
| `test_read_format_iso_rockridge_sl_leak.iso` | Corrupt | compress(1) data despite its name, cut short: the .Z stream fails, as in 7-Zip ("Data Error"). libarchive's test_read_format_iso_rockridge_sl_leak.c only checks that a symlink's SL entries don't leak. |
| `test_read_format_iso_rockridge_zf_overflow.iso` | Corrupt | A ZF entry cut short in the root's continuation area, which over-read libarchive's buffer (test_read_format_iso_rockridge_zf_overflow.c). |
| `test_read_format_iso_zisofs_overflow.iso` | Corrupt | A zisofs header with a block size of 4 bytes and a size of 0xFFFFFFF9 (test_read_format_iso_zisofs_overflow.c). hadris refuses the directory record. |
