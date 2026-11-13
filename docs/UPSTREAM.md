# Upstream bugs

Bugs in other people's code that BeeZip works around. None of them has been reported upstream, and
none will be: this list is for checking whether a new version has fixed them.

**When a dependency or tool is updated,** look it up here. For each of its entries, run the check.
If the new version fixes the bug, take BeeZip's workaround out where the entry says it can go,
and move the entry to [Fixed upstream](#fixed-upstream) with the version that fixed it. A
workaround marked *keep* guards against damaged input as well, so it stays either way.

Each entry gives the version the bug was seen in, the bug, how to check it, and BeeZip's
workaround. Checks that name a test run with `cargo test`; files under `tests/` are in git, and
files under `target/` exist only on the machine that found the bug. The milestone docs
(`docs/M3.md` to `docs/M6.md`, §16) have the longer stories.

## Rust crates BeeZip builds with

### libbz2-rs-sys 0.2.6, through bzip2 0.6.1 (trifectatechfoundation/libbzip2-rs)

- **A `u8` counter overflows.** `decompress.rs`, state `BZ_X_CODING_3`, does `curr -= 1` and
  `curr += 1` on a `u8`; C wraps and then rejects the data, Rust with overflow checks on (debug
  builds, cargo-fuzz) panics. The fix is `wrapping_sub` and `wrapping_add`.
  - *Check:* remove the override and run a debug `beezip t` on
    `tests/fixtures/regress/fuzz-sevenz-bzip2-overflow.7z`.
  - *Workaround:* `overflow-checks = false` for the crate in the root `Cargo.toml`'s dev profile
    and in `fuzz/Cargo.toml`. It can go once fixed. (M3 §11 item 35, M4 §15.)
- **Decoding again after a data error aborts the process.** After `BZ_DATA_ERROR` the state is
  kept, a later call resumes from it, and `pos[..=selectorMtf[i]]` (`decompress.rs:1022`) indexes
  past its 6 entries. The panic is inside an `extern "C"` function, so release builds abort
  (`0xc0000409`) too.
  - *Check:* `tests/fixtures/regress/bzip2-reread.tar.bz2` and `fuzz-sevenz-bzip2-reread.7z`,
    reading the decoder again after its first error.
  - *Workaround (keep):* `LatchReader` on every codec's decoder (`CodecId::decoder`), and the 7z
    reader's `DecodeTag` latch. (M4 §16, PR 3 item 18.)

### zlib-rs 0.6.8, through flate2 1.1.10 (trifectatechfoundation/zlib-rs)

- **`reset()` and `set_dictionary` give other bytes than a fresh `Compress`.** A reused raw
  deflate `Compress`, primed with the previous 32 KiB, compresses the next block differently from
  a new one primed the same way, at levels 1 to 8.
  - *Check:* `target/m6-spikes/parallel/repro/zlibrs-reset`.
  - *Workaround:* a fresh `Compress` per 128 KiB block (`codec/deflate_par.rs`, `deflate_block`),
    about 12 % slower at level 1. It can go once fixed. (M6 §6.1.)

### zip 9.4.1 (zip-rs/zip2)

- **Raw copies drop general-purpose flag bits.** `ZipWriter::raw_copy_file` clears bit 0 of a
  ZipCrypto entry (the copy claims to be unencrypted) and bit 1 of an LZMA entry (its end marker);
  `ZipWriter::new_append` writes kept LZMA entries' central records without bit 1. Seen from
  9.2.2 on.
  - *Check:* `raw_copy_file` each entry of `tests/fixtures/thirdparty/7z-zipcrypto.zip`,
    `7z-lzma.zip` and `7z-lzma-zipcrypto.zip` into a new `ZipWriter`, then `7z t` the result
    (password `beezip`).
  - *Workaround (keep):* BeeZip never calls `raw_copy_file*`, `merge_archive` or `new_append`; it
    copies kept entries and their central records byte for byte (`format/zip_edit.rs`, and
    `copy_into` in `format/zip.rs`). (M5 §16.)

### sevenz-rust2 0.25.0 (hasenbanck/sevenz-rust)

- **A CRC mismatch in a solid block ends the block.** When the callback carries on past an entry
  whose CRC is wrong, `Crc32VerifyingReader` reports the mismatch again and the rest of the block
  is never decoded. 7-Zip reports the one entry and goes on.
  - *Check:* `target/m6-spikes/bump/repro/out/crc-solid-damaged.7z`, or take the workaround out
    and run `roundtrip::sevenz_crc_mismatch_fails_only_its_entry`.
  - *Workaround:* `SevenZReader::open` keeps each file's CRC and clears `has_crc`, and `DecodeTag`
    checks the CRCs (`format/sevenz.rs`, test `decode_tag_checks_the_crc`). (M6 §16, PR 1.)

### lzma-rust2 0.25.0 (hasenbanck/lzma-rust2)

- **`XzReader` checks only how many index records there are, not their sizes.** Its sans-I/O
  `XzStream` does check them. `xz -t` calls such a file corrupt.
  - *Check:* `tests/fixtures/thirdparty/xz/seq-T1.xz` with the index's uncompressed size lowered
    by one and the index CRC fixed (the script that did it wasn't kept).
  - *Workaround:* none on one thread, where the block checks still verify the data; BeeZip's
    threaded decoder refuses such a file. (M6 §16, PR 2.)
- Also: `XzReaderMt` skips block checks (BeeZip doesn't use it), and the private CRC-64 goes a
  byte at a time, about 40 % of `XzReader`'s time.

### lzokay 2.0.1 (encounter/lzokay-rs)

- **Compressing empty input gives a block no decoder reads** (4 bytes that liblzo2 and lzokay's
  own decoder reject).
  - *Check:* compress `b""` and decompress the result.
  - *Workaround (keep):* the lzop writer writes no block for empty input (`codec/lzop.rs`, test
    `empty_input_has_no_block`), and an empty squashfs fragment block is written as nothing.

### delharc 0.8.0 (royaltm/rust-delharc)

- **Uninitialized memory handed to `read_exact`**: `header/parser.rs:189` and `stub_io.rs:62`
  make `&mut [u8]` from uninitialized memory.
  - *Check:* read those two places.
  - *Workaround:* none needed; every reader BeeZip hands delharc only writes into the buffer.

### hadris-iso 3.0.0-rc.3 (hxyulin/hadris), vendored in `vendor/hadris-iso`

- **Name de-duplication is quadratic**: 20 000 files whose long names share a prefix take about
  80 s to plan.
- **Rock Ridge symlink targets lose empty components** (`.///file` reads `./file`).
  - *Check, both:* on a new release, drop `vendor/hadris-iso` and its `[patch.crates-io]` (main
    and fuzz workspaces), then run `colliding_names_plan_quickly` (`format/iso.rs`) and
    `fixtures.rs`, whose libarchive Rock Ridge images expect the symlinks `.///file` and
    `/tmp//..`.
  - *Workaround:* `vendor/hadris-iso/patches/dedup.diff` and `symlink.diff`
    (`vendor/hadris-iso/BEEZIP.md`).
- **An entry whose continuation area loops is listed and readable**; only `open` fails.
  - *Check:* `tests/fixtures/thirdparty/libarchive/iso/broken/test_read_format_iso_rockridge_ce_loop.iso.Z`.
  - *Workaround (keep):* BeeZip opens every file before reading it (`format/iso.rs`, `data`).

### backhand 0.25.5 (wcampbell0x2a/backhand), for writing squashfs

- **The writer panics on a symlink target of 256 bytes or more** (`Inode::to_bytes` unwraps a
  failed `#[deku(assert)]`); the reader fails such images too.
  - *Check:* `links_missing_folders_and_odd_paths` (`crates/beezip-core/tests/squashfs.rs`), and
    `target/m5-spikes/squashfs/repro/symlink-256-fails.sqfs`.
  - *Workaround:* such links are left out with a warning, and `write` runs under `catch_unwind`.
- **gzip compressor options written as 7 bytes**, which unsquashfs rejects.
  - *Check:* `target/m5-spikes/squashfs/repro/gzip-opts.sqfs`.
  - *Workaround:* BeeZip writes the options block as mksquashfs does (test
    `compressor_options_are_mksquashfs_s`).
- **Duplicate-file detection leaves stale bytes after the image** and compares only sizes and a
  64-bit hash.
  - *Workaround:* detection off (`set_no_duplicate_files(false)`; the name reads backwards).
- **Names are host paths**: on Windows a name holding `\` or like `C:` can't be written, and `..`
  pops a level everywhere.
  - *Check:* `paths_squashfs_cant_hold_are_named` (`format/squashfs/write.rs`), and
    `target/m5-spikes/squashfs/repro/win-backslash-name-fails.sqfs`.
  - *Workaround:* such paths are left out with a warning.

### fstool 0.5.2 (KarpelesLab/fstool), for HFS+, APFS, NTFS and ext

0.5.3 (2026-11-09) changes only archive, zip and tar writing, and fixes none of these.

Since M11, BeeZip builds a patched copy (`vendor/fstool`, through `[patch.crates-io]`; its
`BEEZIP.md` and `patches/` list each change, marked `BeeZip:` in the source): the NTFS, HFS+ and
APFS bugs below marked *Patched*. On a bump, check each against the new release, and drop the copy
once none is needed.

- **The decmpfs header's magic is read big-endian**, so every Apple-compressed file fails.
  - *Workaround:* BeeZip decodes decmpfs itself (`format/dmg/decmpfs.rs`, `lzvn.rs`) and never
    asks fstool for a compressed file's body.
- **APFS compressed files read as empty with no error**, and their resource forks can't be reached.
  - *Check:* the `apfs_volumes` test in `format/dmg.rs`.
  - *Workaround:* every empty file's `com.apple.decmpfs` is checked; inline types are decoded,
    resource-fork ones are `UnsupportedOperation`.
- **`get_xattr` sizes an attribute from its claimed length**, so a crafted volume could allocate
  gigabytes.
  - *Workaround (keep):* attributes are read through a `Capped` device of 64 KiB
    (`format/volume/apple.rs`).
- **NTFS: a self-referring `$MFT` overflows the stack**, which aborts the process:
  `Ntfs::read_mft_record` (`src/fs/ntfs/mod.rs:281`) and `bootstrap_mft_runs` (`:390`) call each
  other without end when record 0's unnamed `$DATA` has no runs and its attribute list names one
  in another record.
  - *Check:* open `tests/fixtures/malicious/ntfs-mft-recursion.img` with fstool directly.
  - *Workaround (keep):* `check_mft` in `format/volume/ntfs.rs` reads `$MFT` first and refuses
    empty runs.
- **NTFS: a short resident attribute panics** in `AttributeIter::next` (`src/fs/ntfs/attribute.rs:170`),
  which reads the value offset before checking that it fits ("range end index 1028 out of range
  for slice of length 1024"), for an attribute of 16–23 bytes at a record's end.
  - *Check:* the `fstool_still_reads_past_a_short_attribute` test in `format/volume/ntfs/tests.rs`
    (`should_panic`: it fails once fstool fixes this). Repro:
    `tests/fixtures/malicious/ntfs-short-attr.img`.
  - *Workaround (keep):* `check_attrs` vets every record before fstool walks it.
- **NTFS: `read_directory` drops a second name of a file in the same folder** (the `seen_refs`
  dedup, `src/fs/ntfs/mod.rs:578–598`), so a hard link goes missing.
  - *Check:* list `tests/fixtures/thirdparty/7zip/ntfs.img` through `read_directory`: one of
    `readme.txt` and `hard-readme.txt` is missing.
  - *Workaround:* BeeZip walks the indexes itself.
- **NTFS: `load_record_set` takes attributes from any record an attribute list names**
  (`src/fs/ntfs/mod.rs:459–494`), without checking that record's base reference, so another
  file's data can be merged in.
  - *Check:* `tests/fixtures/malicious/ntfs-alist-foreign.img`.
  - *Workaround (keep):* BeeZip gathers the set itself and refuses records that aren't the file's.
- **NTFS: data stored twice isn't refused:** `open_stream_by_record` (`src/fs/ntfs/mod.rs:831`,
  `:879`) prefers any resident `$DATA` and takes the size from the first piece without checking
  that the pieces line up, so it reads past what's there.
  - *Check:* `tests/fixtures/malicious/ntfs-dup-data.img`.
  - *Workaround (keep):* such streams are `Corrupt`; the size listed is the one fstool reads.
- **NTFS: clusters over 64 KiB read as damaged:** `BootSector::decode` (`src/fs/ntfs/boot.rs:70`)
  rejects the negative encoding of sectors per cluster (over 0x80) that such volumes use.
  - *Patched (M11):* `decode` takes a value over 0x80 as 2^(256 - value) sectors and keeps the
    cluster size in bytes (`cluster_bytes`; `vendor/fstool/patches/ntfs-clusters.diff`).
  - *Check:* `clusters_of_128_kib_and_2_mib_read` (`format/volume/ntfs/tests.rs`), on mkntfs's
    `thirdparty/ntfs/c128k.img.xz` and `c2m.img.xz`, through an unpatched fstool.
- **NTFS, found by reading the code and avoided rather than reproduced:**
  - `descend_index` (`src/fs/ntfs/mod.rs:667`) reads an index block as contiguous bytes from its
    first cluster, and `read_directory` (`:553`) assumes the root's first entry is at 16: BeeZip
    walks the indexes itself.
  - `RunMap::lookup` (`src/fs/ntfs/run_list.rs:80`) scans zero-length runs one by one: BeeZip
    refuses such runs.
  - The two compression-unit buffers can reach 256 MiB each (`src/fs/ntfs/mod.rs:894`): BeeZip
    caps a unit at 1 MiB.
  - Not worked around: `read_mft_record` (`:310`) reads a record larger than a cluster as
    contiguous bytes, which misreads a record that crosses runs of a fragmented `$MFT` with
    clusters under 1 KiB (its fixups then fail it cleanly); LZNT1's `decompress_unit`
    (`src/fs/ntfs/compression.rs:70`) doesn't pad a short chunk to 4 KiB, as ntfs-3g does.
- **ext: the group layout allocates before checking the device:** `Vec::with_capacity(num_groups)`
  (`src/fs/ext/layout.rs:683`) can ask for 128 GiB from a superblock of about 4 billion groups,
  and `1u32 << log_groups_per_flex` (`:680`) overflows (a panic with overflow checks).
  - *Check:* open `tests/fixtures/malicious/ext4-groups.img` and `ext4-flex-shift.img` with
    fstool directly.
  - *Workaround (keep):* `format/volume/ext.rs` checks the superblock first: block size, flex
    shift, blocks per group, and a group count the image can hold. `format/volume/apple.rs` opens
    HFS+ and APFS by their own signatures, never through `AnyFs::open`, whose detection tries ext
    first and would reach this layout: CI's `part` fuzz target did, on `ext4-groups.img` opened as
    APFS.
- **ext: a symlink's target is read past its cap:** the cap (`src/fs/ext/mod.rs:4923`) checks only
  the size's low 32 bits before `read_to_end` (`:4961`).
  - *Check:* `tests/fixtures/malicious/ext4-symlink-size.img`, `ext4-symlink-100g.img`.
  - *Workaround (keep):* BeeZip reads targets itself, at most 4096 bytes.
- **ext: a bigalloc group's unwritten bitmap is indexed past its end** (`synth_block_bitmap`,
  `src/fs/ext/mod.rs:5285` → `group.rs:86`), a panic in release builds too ("index 1125, len
  1024"), when a BLOCK_UNINIT group's bitmap lies 8 × the block size or more into the group.
  - *Check:* the `a_bigalloc_group_with_metadata_past_its_bitmap_is_refused` test in
    `format/volume/ext.rs`.
  - *Workaround (keep):* `check_unwritten_bitmaps` refuses such volumes.
- **ext: 48-bit block numbers are cut to 32 bits** (`src/fs/ext/mod.rs:5763` `phys as u32`, `:4602`
  and `:5740` `idx.leaf as u32`), so another block is read with no error, and
  `r.logical + len as u32` (`:5751`) and `(pos / bs) as u32` (`:5063`) overflow. The superblock
  and group descriptors are read as 32-bit only (`superblock.rs:300`, `GroupDesc::decode`), and
  incompatible features BeeZip doesn't know (compression, dirdata) aren't refused.
  - *Workaround:* BeeZip maps blocks itself, in u64 checked against the block count, a whole run
    at a time; volumes over 2^32 blocks and unknown incompatible features are
    `UnsupportedOperation`.
- **ext: `replay_pending_journal` writes onto the device and gets replay wrong** (from reading the
  code): it replays whenever `s_start` isn't 0, ignoring needs_recovery (`src/fs/ext/mod.rs:828`);
  `b.fs_block * bs as u64` overflows on a 64-bit tag and the block isn't checked against the
  volume (`jbd2.rs:531`); `ring_next`'s `idx + 1` overflows and `s_start`/`s_first` aren't checked
  against `s_maxlen` (`jbd2.rs:551`); and a first tag of block 0 with flags 0 is taken for an empty
  descriptor (`jbd2.rs:576`), losing that transaction and every one after.
  - *Workaround:* BeeZip replays the journal itself, as the kernel does (two passes, with
    revocations), only when needs_recovery is set, into an overlay in memory.
- **ext: lossy or missing results:** inline folders list empty and inline symlinks fail
  (`list_inode` and `read_symlink_target` take `i_block` for a block map); names and targets are
  made lossy (`src/fs/ext/mod.rs:4700`, `:4944`, `:4963`); and one attribute in an EA inode, or
  with a name that isn't UTF-8, fails all of `read_xattrs` (`xattr.rs:280`, `:290`).
  - *Check:* `tests/fixtures/thirdparty/ext/inline.img` through fstool's `list` and
    `read_symlink_target`.
  - *Workaround:* BeeZip reads folders, symlinks and `system.data` itself.
- **ext, costs rather than bugs:** `Ext::open` keeps both bitmaps of every group in memory
  (`src/fs/ext/mod.rs:5226–5227`), bounded by BeeZip's group-count check, and `FileReader` reads
  one block per `read`, walking the extent tree again each time (`:5048–5085`), which BeeZip's
  own block map avoids.
- **APFS: sealed volumes aren't recognised** (found in M11's planning, from reading the code and
  Apple's reference): `APFS_INCOMPAT_SEALED_VOLUME` is tested as `0x80`
  (`src/fs/apfs/mod.rs:782`), but Apple's *APFS Reference* and 7-Zip (`ApfsHandler.cpp:215`) give
  `0x20`. So a sealed volume (macOS 11 and later's system volume, an IPSW's) isn't refused as
  fstool means to, and is read without its file-extent tree, which holds a sealed volume's
  extents: its files probably read wrong or empty. Not reproduced: there's no sealed sample here.
  Reproduced in M11 with a crafted sealed volume: every file reads as zeros.
  - *Patched (M11):* the flag is `0x20`, and a sealed volume's files take their extents from the
    file-extent tree (`apfs_fext_tree_oid`, a new `fext.rs`; `vendor/fstool/patches/apfs-sealed.diff`).
    Its integrity hashes aren't checked.
  - *Check:* `an_overflowed_catalog_and_a_sealed_volume_read_as_their_sources` (`tests/dmg.rs`),
    on `thirdparty/apple/apfs-sealed.apfs.xz`, through an unpatched fstool.
- **HFS+: a catalog or attributes file in more than eight extents is refused**
  (`ForkReader::from_inline`, `src/fs/hfs_plus/btree.rs:171`: "extents-overflow file is not
  supported in v1"), though `from_inline_plus_overflow` (`:199`) is there. A long-used volume
  fragments them. 7-Zip follows the overflow extents (`HfsHandler.cpp`).
  `open_writable` reads the catalog the same way, and `open` calls it.
  - *Patched (M11):* `special_fork` builds the catalog's and attributes' forks with their overflow
    extents (keyed by CNIDs 4 and 8), for `open`, `open_writable` and BeeZip's own resource-fork
    reader (`vendor/fstool/patches/hfs-overflow.diff`).
  - *Check:* the same test, on `thirdparty/apple/hfs-catalog-overflow.hfs.xz`.
- **Its DMG layer caches one decoded chunk** (10 000 files took 25 s against 0.18 s) and caps a
  chunk at 8 GiB.
  - *Workaround:* BeeZip's own UDIF reader (`format/udif.rs`) behind fstool's `BlockDevice`.

### wry 0.57.1, through Tauri 2.12.5 (tauri-apps/wry)

- **The webview's drop target keeps its state after a drag without files**
  (`src/webview2/drag_drop.rs`). `DragEnter` returns early when there's no `CF_HDROP` without
  resetting `enter_is_valid` or the effect, so after one real file drop, a drag of text still gets
  drag-over and drop events and the old copy cursor.
  - *Check:* drop a file on the window, then drag selected text from a browser over it.
  - *Workaround:* the page ignores drag events while its drag-out runs; the drop source shows the
    no cursor and cancels a release over BeeZip's own windows. (M6 §16, PR 7 item 4.)

## Build and test tools

### Tauri CLI 2.12.4 (tauri-bundler 2.10.4)

- **nsExec.dll is left unsigned in a signed installer** (`NSIS_PLUGIN_FILES`, `nsis/mod.rs:62`).
  - *Workaround:* `packaging/windows/sign.ps1` signs it, and `xtask dist` checks every plugin's
    signature after a signed build.
  - Also: a DLL resource mapped to a new name is packed twice in an MSI (ICE30); BeeZip ships no
    MSI.
- **Linux desktop entries have no `%F`**, so opening an associated file starts the app without it.
  - *Workaround:* `packaging/linux/beezip.desktop` as the deb and rpm `desktopTemplate`.
- **The rpm doesn't own the folders of `bundle.linux.rpm.files`**, so `/usr/share/doc/beezip`
  stays after removal.
  - *Workaround:* `packaging/linux/rpm-postun.sh`.

### tauri-driver 2.1.0, with msedgedriver

- **`tauri:options.args` become lowercased Chromium switches**, so an archive can't be passed to
  the app.
  - *Workaround:* `tests/e2e/smoke.mjs` hands the archive over with a second launch.

### cargo-about 0.9.3 (EmbarkStudios/cargo-about)

- **A clarification's `LicenseRef-` text is dropped** (`generate.rs:172` lacks the `!` the SPDX
  arm at :120 has).
  - *Workaround:* `about.toml` names UnRAR's file `LicenseRef-UnRAR-file`; `xtask notices` fails
    on any LicenseRef without a text.
- **Its file walker skips `license-mit` and `LICENSE_MIT`**, so windows-rs 0.62 crates and some
  Tauri plugins get the canonical MIT text without a copyright line.
  - *Workaround:* `[crate.clarify]` entries in `about.toml`.
- **`--color never` doesn't reach its log lines.**
  - *Workaround:* `xtask notices` strips the escapes.

### WebKitWebDriver (webkit2gtk 2.52, Ubuntu)

- **Get Element Text returns "" for a virtualised grid row** whose `innerText` isn't empty.
  - *Workaround:* `tests/e2e/smoke.mjs` falls back to `innerText` through Execute Script.

### Rust 1.99.1 standard library, x86_64-unknown-linux-gnu

- **Built against glibc 2.39, it leaves weak `GLIBC_2.39` version references** (`pidfd_spawnp`,
  `pidfd_getpid`), so every start on glibc 2.35 or 2.36 prints `weak version 'GLIBC_2.39' not found`.
  - *Check:* build on Ubuntu 24.04 and run `beezip --version` on 22.04.
  - *Workaround:* CI's linux-bundle job and release.yml's linux job build on ubuntu-22.04.

### wixl 0.103 (msitools, Ubuntu 24.04), which makes the MSI fixture

- **Under code page 65001 a non-ASCII file name is written empty**, and Latin-1 names are written
  under code page 0; code page 932 crashes it.
  - *Check:* `tests/fixtures/make-7z.sh`'s `wixl.msi`: its `名前.txt` is listed by its key, `cjk`.
  - *Workaround:* none; the fixture's record names that file `cjk`, and the test packages with
    non-ASCII names are built by the `msi` crate in `tests/msi.rs`.
- **With `<Package Compressed="no">` it writes no Media row and keeps the "compressed" bit.**
  Seen while planning M11 (docs/M11.md §14): it fails its own assertion
  (`wixl_msi_table_media_set_last_sequence: assertion 'rec != NULL' failed`), leaves the Media
  table empty, and still writes word count 10 (bit 1, files compressed by default), so the
  package names no source for its files.
  - *Check:* `target/m11-spikes/made/v1/p.wxs` built with `wixl -D Compressed=no`, then
    `msiinfo export u1.msi Media` (no rows) and `msiinfo suminfo u1.msi` (`Source: 10`).
  - *Workaround:* `make-msi-extras.ps1` adds the Media row and sets the word count to 8 with
    Windows Installer's own API before the SDK's patch tools read the images.

### qemu-img 8.2.2 (Ubuntu 24.04), which makes the virtual-disk fixtures

Seen while planning M8 (docs/M8.md §15); repros in `target/m8-spikes/vmdk-qcow-vdi/repro/` and
`target/m8-spikes/vhd/repro/` (images named under `vhd/images/` were deleted after planning;
`vhd/scripts/` remakes them).
- **A VMDK descriptor's ZERO extent is dropped,** so the disk comes out 16 KiB short and
  everything after it moves up (`repro/qemu-zero-extent/`).
- **A backing-file loop never finishes;** its memory grows (1.5 GB after 5.7 minutes,
  `repro/qemu-backing-loop/`).
- **A `json:` backing name is followed to any file** (`repro/qemu-json-backing/` reads
  `/etc/passwd`).
- **A QCOW2 `data_file` is opened relative to the working folder,** not the image's.
- **A bare hosted sparse VMDK extent can't be opened alone** ("Invalid argument").
- **A VHDX of 4 KiB logical sectors can't be opened** ("Operation not supported").
- **An active VHDX log with no valid sequence is read as clean**
  (`target/m8-spikes/vhd/images/log/dirty-noseq.vhdx`).
- *Workaround:* none needed; the fixtures that need these are crafted from the specifications
  instead (`make-vdisk.sh`, M8 §9), and their expected data isn't taken from qemu-img.

### chmcmd 3.2.2 (Free Pascal, Ubuntu 24.04), which makes the CHM fixtures

Seen while planning M9 (docs/M9.md §14), in `target/m9-spikes/chm/big/big.chm` (Rust's `std`
docs; `big/make.sh` remakes it).
- **A multi-chunk directory names the wrong first listing chunk.** The ITSP header says the first
  PMGL chunk is 1, but chunk 0 is a PMGL chunk too (its next is 1), holding 108 entries. A reader
  that starts where the header says loses them (98 files); 7-Zip reads every chunk.
  - *Check:* the multi-chunk chmcmd fixture (M9 §8): the ITSP header's field at 0x20 against the
    lowest PMGL chunk.
  - *Workaround (keep):* the CHM reader reads every chunk and takes every PMGL one, whatever the
    header says (M9 decision 3).

### mkfs.cramfs 2.39.3 (util-linux, Ubuntu 24.04), which makes the CramFS fixtures

Seen while planning M10 (docs/M10.md §14), in `target/m10-spikes/cramfs/` (`make.sh` remakes it).
- **A name of 253 to 255 bytes writes an image nothing can read.** `MAX_INPUT_NAMELEN` is 255
  (`disk-utils/cramfs.h`), but the inode's name length holds at most 252 bytes (63 four-byte
  units). The name pads to 256, `inode->namelen = len >> 2` wraps to 0, and the folder's next
  inode is read from the name's bytes. There's no warning; util-linux's master is the same.
  - *Check:* `mkfs.cramfs` on a folder holding a 255-byte name, then `fsck.cramfs` or `7z l`.
  - *Workaround (keep):* the fixture scripts keep names to 252 bytes; the CramFS reader refuses a
    zero name length as `Corrupt`, and the malicious corpus has such an image.

## Programs BeeZip runs or targets

### 7-Zip 26.00

Since M11 (0.6.0) BeeZip never runs 7-Zip: it's only a test oracle, the program the fixture
scripts, the opt-in sample comparisons and CI's Windows interop tests check BeeZip's readers and
archives against (docs/M11.md §7). These bugs matter only there, where a test compares with it.
CI's Windows runner shows which 7-Zip it has.

- **An NSIS solid-LZMA installer lists a file's size wrong** (sizes come from the script, as
  estimates): `$PLUGINSDIR/StartMenu.dll` in BeeZip's own installer lists 13 316 bytes and
  extracts 7 680.
  - *Check:* compare `7z l -slt` with `7z x` on an installer from `cargo xtask dist`.
  - *Workaround (until M11):* the 7-Zip backend extracted NSIS installers into a staging folder
    first. The fixture records take sizes from `7z x`.
- **CramFS names are read in the OEM code page**, and `-mcp` is refused for CramFS and WIM.
  - *Check:* `7z l -slt -sccUTF-8` on the CramFS fixture in `tests/fixtures/thirdparty/7zip/`.
  - *Workaround:* the oracle tests map a name back to its bytes (`seven_zip_name` in
    `tests/cramfs.rs`).
- Not worked around, since BeeZip doesn't ask 7-Zip for these:
  - an ARJ volume set opens one part at a time and tests OK;
  - ntfs-3g's Interix links list as plain files, but `7z x` makes them links;
  - ntfs-3g's sparse files fail with "Data Error" and extract as empty files (`sparse.bin` in
    `tests/fixtures/thirdparty/ntfs/rich.img`); BeeZip reads NTFS itself since M7;
  - a qemu-img streamOptimized VMDK can't be opened;
  - neither can a VHDX whose disk is an odd number of 512-byte sectors;
  - a VHD footer's UTC time is shifted by the local offset, even with `-slmu`;
  - a 4 KiB-sector GPT disk is read as an MBR disk (BeeZip reads such disks itself since M7);
  - `7z t tests/fixtures/malicious/bomb.dmg` runs for minutes on a 1.3 KB file.
- Seen while planning M8 (docs/M8.md §15), not worked around since BeeZip reads these itself
  from M8; repros under `target/m8-spikes/` (the spikes' samples and images were deleted after
  planning: `target/m8-spikes/samples/README.md`, `vm/run.ps1` and each spike's `scripts/` remake
  them):
  - **a QCOW2 with extended L2 entries is read as if its entries were 8 bytes:** with compressed
    clusters 7 of 11 clusters come out wrong and `7z t` says "Everything is Ok"
    (`vmdk-qcow-vdi/repro/7zip-el2-compressed/`; `7z x -tqcow -so q-el2-deflate.qcow2` against
    `raw.img`);
  - a VMDK descriptor with a ZERO extent gives "Data Error" (`vmdk-qcow-vdi/repro/qemu-zero-extent/`);
  - the qemu-img streamOptimized VMDK above can't be opened because qemu writes the grain
    directory at the start with no footer, where VMware writes it at the end
    (`vmdk-qcow-vdi/repro/7zip-qemu-stream/`);
  - **an active VHDX log isn't replayed:** it reports "non-empty LOG was not replayed", reads the
    stale disk and doesn't open what's inside (`samples/vhdx-dirty/dirty.vhdx`, made by Windows);
  - a VHDX parent is found only by its `relative_path`, never with `..\`, by its absolute path or
    beside the child (`vhd/images/ms/kids/fat-mod1.avhdx`); a VHD's parent is tried by its W2ku
    absolute path too, which probably opens a UNC path a crafted VHD names (not verified);
  - no VMDK, QCOW2 or VDI child or backing file is followed, zstd QCOW2 clusters and compressed
    QCOW version 1 are "Unsupported method", a QCOW2 data file is "Unexpected end of archive", and
    VDI blocks other than 1 MiB aren't read;
  - **a file Windows compressed with WOF extracts as zeros of its full size,** with the
    compressed data beside it as `file:WofCompressedData`, and `7z t` says "Everything is Ok"
    (`wof/repro/7zip-wof-zeros.ntfs`); a WOF file inside a WIM fails "Incorrect reparse stream";
  - DISM's split WIM (`samples/dism/split.swm`) reports "Unexpected end of archive", so
    `beezip test` calls it Corrupt today; wimlib's warns "There are data after the end of
    archive";
  - Microsoft's boot.wim warns "Some files have incorrect reference count";
  - an LZMS WIM is decoded on one thread;
  - an MSI whose cabinet folder continues into a second embedded cabinet lists only its streams
    (`cab/span/span.msi`).
- Seen while building M8 PR 1 (docs/M8.md §16), repros committed:
  - **a QCOW2 with incompatible-feature bits it doesn't know opens, and `7z t` says "Everything is
    Ok",** where qemu's qcow2.txt says to refuse it
    (`tests/fixtures/thirdparty/vdisk/q-refuse-bit.qcow2`);
  - a VHD child's `..\` W2ru locator isn't followed either ("Missing volume :
    ..\parents\fe.vhd", `tests/fixtures/thirdparty/vhd/kids/fe-1.vhd`); when a VHD's parent fails,
    it names the parent's W2ku absolute path ("Can't open parent VHD file :
    C:\BeeZip\fixtures\vhd\kids\fe-1.vhd" for `kids/fe-2.vhd`), more sign that it would open a
    UNC path a crafted VHD names (still not verified);
  - the extended-L2 wrong data above shows with 16 KiB clusters too.
- Seen while planning M10 (docs/M10.md §14), not worked around since BeeZip reads these itself
  from M10; samples under `target/m10-spikes/` (`cramfs/make.sh`, `cramfs/craft.py` and
  `nsis/make.sh` remake the made ones):
  - **CramFS:** a file with holes fails with "Data Error" at its first hole (`mkfs.cramfs -z`);
    an image of 8 to 64 KiB blocks fails every file over 4 KiB as "Unsupported Method"
    (`-b 16384`); an image padded for a boot block can't be opened (`-p`), though the superblock
    is where Linux and util-linux look for it; Linux 4.15's extended-pointer flag (0x800) is read
    as a block size of 8 KiB (`crafted/ext-ptrs.img`);
  - **NSIS:** an NSIS 2 zlib installer from a makensis linked to the system's zlib (Ubuntu 16.04's
    2.50) fails from its first stored block, since 7-Zip reads NSIS 2's form there (its source
    says it can't tell these apart); the uninstaller is left out when its instruction-layout
    guess marks one of Tauri's instructions bad ("BadCmd=13", BeeZip's own installers); a stored
    header with compressed files (MuMu Player's tools) extracts them as empty with "Not
    implemented".

### Windows 11 (build 26300)

- **A packaged `IExplorerCommand` flyout draws no separator.** `ECF_SEPARATORBEFORE` on a
  subcommand is ignored; a subcommand with `ECF_ISSEPARATOR` is dropped when its title is empty
  and shown as an ordinary row otherwise. The classic menu draws both.
  - *Check:* with Windows 11's menu registered, right-click a .zip and hover BeeZip: there should
    be a line between "Test archive" and "Add to …".
  - *Workaround:* none possible.
- Seen while planning M8 (docs/M8.md §15), for anyone making test disks:
  - **`Get-VHD` and `Test-VHD` replay an active VHDX log in place,** writing the file. Never run
    them on a file that mustn't change.
  - Windows replays a log whose FlushedFileOffset is past the file's end (MS-VHDX says that's
    damage).
  - **`Convert-VHD`, flattening a differencing VHD,** copies a child's block whole where the
    parent hasn't allocated it, ignoring the child's sector bitmap, so absent sectors come out as
    the child's stale bytes (`target/m8-spikes/vhd/scripts/bitmap-probe.py`). Hyper-V zero-fills
    new blocks, so only crafted files show it.
  - `New-VHD` refuses `.avhdx` names, for a new disk and as a parent; `Convert-VHD` can't make a
    differencing disk.
  - Hyper-V's VHD children store a Parent Time Stamp of 0 and the absolute path in Parent Unicode
    Name.
  - The Compression API's LZMS and XPRESS decoders sometimes decode damaged input "successfully"
    to wrong bytes (as their documentation warns); one LZMS decoder handle used by two threads at
    once crashes. BeeZip checks WIM's SHA-1s and keeps one decoder per worker (M8 §5.3).
  - MS-XCA's decoder pseudocode lacks the 32-bit match length its encoder pseudocode and
    Windows' compressor write.
- Seen while building M8 PR 1, for anyone making test disks: `New-VHD` refuses disks under 3 MB,
  though `Convert-VHD` writes smaller ones; `Convert-VHD` of a 4 KiB-sector VHDX to `.vhd` fails
  with "The parameter is incorrect (0x80070057)", which doesn't say why; a differencing VHDX
  child gets its parent's Virtual Disk ID.

## Fixed upstream

- **sevenz-rust2 0.24.2: an entry whose stream ends early read as complete.** Fixed in 0.25.0.
  BeeZip's `DecodeTag` still counts each entry's bytes, as a second guard.

## Not used because of their bugs

Crates checked and passed over, mostly because they panic or abort on crafted input (docs/M5.md
§16 "Found while planning", docs/M6.md §16 "Found while planning"): cab 0.6.0, ar 0.9.0, cpio
0.4.2, rpm 0.30.2, udif 0.4.2, hfsplus 0.4.0, apfs 0.4.1, compcol 0.7.8, and unarc-rs 0.8.1.
BeeZip's ARJ, ACE and ZOO readers began as unarc-rs's modules and fix its bugs there; the crate
also ships HA, UC2 and JAR code derived from GPL, LGPL and proprietary sources under MIT OR
Apache-2.0.

lzxd 0.2.7 read CAB's LZX until M7, when BeeZip's own decoder (`format/cab/lzx.rs`) replaced it
(docs/M7.md §8.4): it decoded at about a third of 7-Zip's speed; its E8 translation turned an
operand of 0 into the translation size (`postprocess`, lib.rs ~272, tests `is_positive()` where the
spec says `>= 0`); `Window::copy_from_self` underflowed (`window.rs:118`) on a repeated offset an
uncompressed block set past the window, a panic with overflow checks; `FOOTER_BITS` has 289
entries for 290 position slots; a match reaching before the stream's start decoded as zeros
(`tests/fixtures/thirdparty/libarchive/cab/broken/test_read_format_cab_lzx_invalid_history.cab`,
now `Corrupt`); and an empty block asserted.

For M7's disks and installers (docs/M7.md §15, with repros in its spikes): ext4-view 1.0.0 (can't
move between threads, no inode numbers, refuses times before 1970 and many features, three
aborting allocations), ntfs 0.4.0 and its master (11 panics in 15 minutes of fuzzing, allocations
of 4 GiB, compressed files read as raw clusters with no error), fatfs 0.3.6 and its master
(refuses small FAT32 volumes, panics, hangs, reads wrong data with no error), gpt 4.1.0 (asserts
128-byte entries, so the spec's 256-byte entries panic; needs write access), and msi 0.11.1 at run
time. msi stays a dev-dependency for building test packages:
- allocations of up to 4 GiB from a string pool's or a summary string's claimed length
  (`stringpool.rs:115`, `propset.rs:69`): `tests/fixtures/malicious/pool-4gib.msi`,
  `summary-2gib.msi`;
- `unwrap()` on null cells of its catalog (`package.rs:317, 348, 350, 358, 359, 386, 391, 425`):
  `catalog-nulls.msi`;
- code page 0 read as UTF-8 rather than the system's ANSI code page, and `CodePage::from_id(0)`
  maps to UTF-8, so it can't write a code page 0 package (the test writes 1252 and zeroes the
  header through cfb);
- its file needs read and write access: `File::create` gives "Access is denied".

For M8's virtual disks, WOF and WIM (docs/M8.md §15, with repros in its spikes under
`target/m8-spikes/`):
- **vhdx-core 0.4.1:** replays a VHDX log wrong with no error (applies CRC-valid entries from
  offset 0 to the first gap; no sequence search), and has no parent locating or identity check
  (`vhd/repro/vhdx-core-log-not-replayed.vhdx`).
- **virtdisk 0.3.1:** a lifetime budget of 16 Mi reads that can't be raised stops it 5.7 GB into a
  real Windows disk; refuses qemu's VDIs (0x180-byte header) and streamOptimized VMDK.
- **rust-img-vhdx 0.6.1:** `VhdxReader::open`, documented read-only, opens the file read-write and
  replays the log into it (`vhd/repro/rust-img-vhdx-writes.vhdx`). **rust-img-vhd 0.6.1** fails
  every Windows-written differencing VHD.
- **vhdx-rs 0.2.0:** wrong data from a dirty log. **vhd 0.1.1, vhd-core 0.1.4:** read the whole
  file into memory. **vhdx 0.1.0:** replays by writing the file, panics.
- **rust-img-vmdk 0.5.1:** sizes a grain buffer from the header, so a 267 KB VMDK asks for 1 GiB
  (`reader.rs:808`, `vmdk-qcow-vdi/repro/img-vmdk-grain-alloc/`). **rust-img-qcow2 0.6.1:** a raw
  or VMDK backing file fails "bad magic". Both, and **fstool 0.5.2's `qcow2`**, open an absolute or
  UNC backing path as written; fstool also fails a raw backing file shorter than the disk.
- **qcow 1.2.0:** a child's unallocated clusters read as zeros instead of the backing file's
  (`reader.rs:216`). **vdi 0.2.0:** allocates `blocks_in_image * 4` unchecked, divides by a block
  size of 0.
- **xpress-huffman 0.1.3:** short output with no error on 29 % of valid Windows streams.
  **compcol 0.8.0:** fails every XPRESS stream with a 32-bit match length.
  **keramics-compression 0.0.1:** short output with no error on streams Windows decodes whole.
- **wim-parser 0.1.2:** allocates the XML from the header's size unchecked;
  `default-features = false` doesn't build. **geezipx-core 0.7.4:** panics on Microsoft's
  boot.wim ("capacity overflow", `resource.rs:124`), and overflows its stack on a looping folder.
- Rejected without running, on licence or provenance: vmdk-core 0.8.4 (cross-checked against
  qemu's and libvmdk's code), calf 0.3.0, wim/wim-format/wim-types (LGPL/GPL), ms-compress 0.2.1
  and newtua-mscompress 0.1.0 (LGPL, from wimlib), and the unpublished LZMS decoders listed in
  `target/m8-spikes/lzms/REPORT.md`.

## Notes

- **License files missing** (the reason for some of `about.toml`'s clarifications): rmcp 3.8.0
  declares Apache-2.0 while its LICENSE keeps MIT for some contributions; @tauri-apps/plugin-dialog
  2.8.4 and plugin-opener 2.7.2 ship only `LICENSE.spdx`; tauri-plugin 2.7.2, alloc-stdlib 0.3.0,
  ts-rs and ts-rs-macros 12.0.1, webview2-com and -sys 0.39.1, webview2-com-macros 0.8.1,
  backhand 0.25.5 and unrar_sys 0.5.8's bindings ship none.
- **Microsoft's Artifact Signing docs** give the signtool minimum as "10.0.2261.755" (10.0.22621.755)
  and say the client needs .NET 8, while `Microsoft.ArtifactSigning.Client` 1.0.147+ needs .NET 10.
- **APFS keeps a file's old name** when a rename replaces it under another case. That's how APFS
  works, not a bug; BeeZip removes the earlier name first.
- **cfb 0.16.0 refuses a compound file with `/`, `\`, `:` or `!` in a name** ("Object name
  cannot contain / character"), as MS-CFB §2.6.1 forbids those characters; 7-Zip lists such
  names with `_`. Windows Installer never writes them, so BeeZip calls such a file damaged
  (docs/M11.md §5.2). Not a bug.
- **wixl 0.103 can't make merge modules** ("unhandled child Wix node Module"): a missing feature,
  not a bug. M11's merge-module fixtures come from Windows Installer's own API instead.
- **cfb 0.16.0's `Stream` can't move between threads** (its `flusher` is a `Box<dyn Flusher>`,
  `src/internal/stream.rs:29`): a design choice, not a bug. BeeZip's `CfbStream`
  (`format/msi/tables.rs`) reopens the stream for each read, under a mutex.
- **Tools met while making test files** (none is used by BeeZip): unar 1.10.1 reads only an ARJ
  set's first volume, flattens Unix ARJ folders, garbles CP437 names and segfaults on some ARC
  entries; arc 5.21q never writes a squeezed stream's last partial byte; Debian's zoo 2.10 leaves
  bytes after a short name uninitialised and writes wrong DOS times; xar 1.6.1 can't extract
  bsdtar's data-less hard link; bsdtar 3.7.2 can't open a XAR with a SHA-256 or SHA-512 table
  checksum; libarchive 3.7.2 and 3.8.9 write the packed table's first bytes after a XAR's data
  and mark every symlink broken; unace 2.5 hangs on a DELTA block cut short; mtools 4.0.43 keeps
  16 bits of characters past the BMP; mke2fs 1.47.0 `-d` drops nanoseconds; wixl 0.103 ignores
  `<Package Id>`.
