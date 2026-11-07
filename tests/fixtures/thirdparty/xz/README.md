# xz fixtures for the multithreaded decoder

Made by XZ Utils 5.4.5 (Ubuntu 24.04 in WSL) from `seq 1 50000 > seq.txt` (288 894 bytes,
SHA-256 `44969d026ed4164dbe77d48d4d359e98ac4057008cafd61723be72bff83e5fd4`). The tests in
`crates/beezip-core/src/codec/xz_mt.rs` decode each on several threads and compare with
`XzReader`; they aren't in `manifest.json`.

| File | Command | What it tests |
|---|---|---|
| `seq-T0.xz` | `xz -6 -T0 --block-size=8KiB -c seq.txt` | 36 blocks, CRC-64, every block padding length, sizes in the block headers |
| `seq-T0-crc32.xz` | the same with `-C crc32` | CRC-32 |
| `seq-T0-sha256.xz` | the same with `-C sha256` | SHA-256 |
| `seq-T0-none.xz` | the same with `-C none` | no check |
| `seq-T0-x86.xz` | `xz -T0 --block-size=8KiB --x86 --lzma2=preset=6 -c seq.txt` | a BCJ chain: one thread |
| `seq-T1.xz` | `xz -6 -T1 -c seq.txt` | one block: one thread |

Concatenated streams, stream padding, and BeeZip's own threaded writer's files are made by the
tests from these.
