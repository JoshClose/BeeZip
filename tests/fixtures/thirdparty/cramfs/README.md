# CramFS fixtures

Made by `tests/fixtures/make-cramfs.sh` (docs/M10.md §8) from one seeded tree with every kind of
node: files of 0 to 64 KiB, runs of zeros, non-ASCII and 248-byte names, 20 nested folders, an
empty folder, five links, a character and a block device, a FIFO and a socket. Their records in
`manifest.json` list that tree; BeeZip reads every image itself.

| File | Made by | What it is |
|---|---|---|
| `le.img` | mkfs.cramfs 2.39.3 `-n BeeZipCramfs -e 7` | little-endian, 4 KiB blocks |
| `be.img` | mkfs.cramfs `-N big` | big-endian |
| `holes.img` | mkfs.cramfs `-z` | all-zero blocks as holes (7-Zip 26.00: "Data Error") |
| `pad.img` | mkfs.cramfs `-p` | after a 512-byte boot block (7-Zip can't open it) |
| `b16k.img` | mkfs.cramfs `-b 16384` | 16 KiB blocks (7-Zip: "Unsupported Method") |
| `ext-ptrs.img` | make-cramfs.sh | Linux 4.15's extended block pointers: stored, direct stored, direct compressed and plain blocks |
| `sevenzip-lzma.img` | make-cramfs.sh | 7-Zip's own variant ("Modified CramFS"): LZMA, 4 KiB blocks |
| `sevenzip-{lzma,zlib}-{4k,64k,512k}.img` | make-cramfs.sh | the same variant, LZMA and zlib, blocks of 4, 64 and 512 KiB |
| `bit31.img` | make-cramfs.sh | flag bit 31 set, which BeeZip and 7-Zip ignore |

7-Zip 26.00 extracts the same files from `le.img`, `be.img` and the variant's images (checked by the
script).
