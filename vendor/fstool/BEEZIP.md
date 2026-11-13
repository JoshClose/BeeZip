# fstool 0.5.2, patched for BeeZip

This is fstool 0.5.2 as published on crates.io (MIT, see LICENSE; the source is
https://github.com/KarpelesLab/fstool), with three fixes, so that BeeZip reads what only 7-Zip
read for it before (docs/M11.md §6.3). The workspace uses it through `[patch.crates-io]`. Cargo
normalised `Cargo.toml` when the crate was published.

**Trimmed:** the binary, examples, tests and the file systems BeeZip's features don't build
(`affs`, `archive`, `cramfs`, `exfat`, `f2fs`, `fat`, `grf`, `hfs`, `hybrid`, `iso9660`,
`littlefs`, `ramfs`, `squashfs`, `tar`, `udf`, `xfs`, and `volume`, `fuse_adapter.rs`,
`wasm.rs`) aren't vendored, and their targets are gone from `Cargo.toml`. Each module is behind
its feature, so nothing else changes. BeeZip builds `hfs-plus`, `apfs`, `ext` and `ntfs`.

Each fix is in `patches/`, made against the published crate, and marked `BeeZip:` in the source.
`docs/UPSTREAM.md` lists them with fstool's other bugs; the copy goes when upstream has them.

- **`patches/ntfs-clusters.diff`** (`src/fs/ntfs/boot.rs`): a sectors-per-cluster byte over 0x80
  is NTFS's negative form, 2^(256 - value) sectors, as Windows writes clusters of 128 KiB to
  2 MiB (`format /A:128K`-`2M`, mkntfs `-c`); it was read as a linear count and the volume refused.
  The cluster size is kept in bytes (`cluster_bytes`).
- **`patches/hfs-overflow.diff`** (`src/fs/hfs_plus/mod.rs`, `writer.rs`): a catalog or
  attributes file in more than eight extents, as a long-used volume's is, was refused
  ("extents-overflow file is not supported in v1"). `special_fork` builds their forks with the
  extents the extents-overflow file holds for CNIDs 4 and 8, for `open`, `open_writable` (which
  `open` calls, and which reads the catalog too) and BeeZip's own resource-fork reader.
- **`patches/apfs-sealed.diff`** (`src/fs/apfs/mod.rs`, new `src/fs/apfs/fext.rs`): the
  sealed-volume flag was tested as `0x80`, where Apple's reference and 7-Zip have `0x20`, so a
  sealed volume (macOS 11 and later's system volume) was read without its files' extents, which
  are in its file-extent tree: every file read as zeros. The flag is `0x20` now, and such a
  volume's extents come from that tree (`apfs_fext_tree_oid`), a physical B-tree of 16-byte keys
  and values walked within a node budget. Its integrity hashes aren't checked.
- **`patches/trim.diff`** (`src/merge.rs`): `BodyRef::HardLink` is made only on Unix or with
  `tar`, which this copy leaves out, so it would warn on Windows.

BeeZip's tests for them: `clusters_of_128_kib_and_2_mib_read` (`format/volume/ntfs/tests.rs`) and
`an_overflowed_catalog_and_a_sealed_volume_read_as_their_sources` (`tests/dmg.rs`), on volumes
made by `tests/fixtures/make-ntfs.sh` and `make-apple-variants.py`.
