# HFS+ and APFS variants

Made by `tests/fixtures/make-apple-variants.py` (docs/M11.md §6.3) from the committed bare volumes
`thirdparty/7zip/dmg-hfs.hfs` and `dmg-apfs.apfs`, in layouts real Macs write and fstool 0.5.2
didn't read. Each holds the files of the volume it came from, byte for byte (7-Zip extracts the
same files from each pair, checked by the script), and is xz-compressed: BeeZip reads it through
the codec. `tests/dmg.rs` checks them.

| File | What it is |
|---|---|
| `hfs-catalog-overflow.hfs.xz` | the catalog's 20 blocks moved apart, one extent each: eight in the volume header, twelve in the extents-overflow file |
| `apfs-sealed.apfs.xz` | a sealed volume: the flag set (0x20), its files' extents in a file-extent tree and out of the fs-tree |
