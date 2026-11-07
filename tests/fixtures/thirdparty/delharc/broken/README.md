# Broken fixtures

From delharc 0.8.0's tests (MIT OR Apache-2.0, see ../LICENSE-MIT and ../LICENSE-APACHE; most come from lhasa's regression set).
They aren't in manifest.json: each must fail as below, without a panic, a hang or a large
allocation. fetch-libarchive.ps1 writes this file.

| File | Expected | Why |
|---|---|---|
| `regression-truncated.lzh` | Corrupt | An -lh5- archive cut short (lhasa's regression set). |
| `regression-evil_pm2.lzh` | Corrupt | Overflowed an array in -pm2- decoders (GHSA-j2m3-h278-rrg9). |
| `regression-dotdot.lzh` | Unsafe | `../evil1.txt` and `foo/../../evil2.txt`: listing works; extraction must skip both (Traversal), then fail with Unsafe. |
| `regression-symlink2.lzh` | Unsafe | A symlink `etc` to `../../etc`, then `etc/passwd` through it: listing works; extraction must refuse the link (LinkOutside, or LinksDisabled) and must not write through it (OutsideDest). |
| `regression-symlink3.lzh` | Unsafe | A symlink `etc` to `/tmp`, then `etc/passwd` through it: as symlink2. |
| `regression-clusterfuzz-1.bin` | Corrupt or UnsupportedFormat | Made delharc's LhaV2Decoder panic (delharc issue 7). |
| `regression-fuzz-10-1.bin` | Corrupt or UnsupportedFormat | Made delharc's LhaHeader::read panic (delharc issue 10). |
| `unlha32-lh2.lzh` | UnsupportedFormat | -lh2-, which delharc doesn't decode: listing works, reading the file must fail. |
