# Fixtures first made for the 7-Zip backend

Made by `tests/fixtures/make-7z.sh` (docs/M6.md §10), which also writes this file and 7-Zip's
records in `manifest.json`: oracle data since M11, when BeeZip stopped running 7-Zip; BeeZip's own
records of the same images come from `native-records.py`. Every image holds the same seeded tree, as far as its file system can: text, an
empty file, 64 KiB of pseudo-random bytes, nested folders, names in CJK, an emoji, accents and a
space, a folder with a non-ASCII name, a symlink, a symlink to a folder and a hard link, every time
2026-01-01T00:00:00Z but `mtime.txt`'s (2024-05-06T07:08:09.123456789Z). A record's `levels` are the
types 7-Zip opens, outermost first; its `note` says what 7-Zip does with the format that a reader of
its listing should know.

Each image is as small as its tool makes it, mostly zeros: ext4's journal is at least 1 MiB, NTFS
at least 1 MiB, a VHDX's header, log, metadata and block table take 1 MiB each and its blocks
1 MiB (qemu-img's payload, which starts at 8 MiB, is moved down), a dynamic VHD's block is 2 MiB,
and the APFS container is the one hdiutil made (10.5 MiB, 104 KiB compressed).

| File | Size | Levels | Made by |
|---|---|---|---|
| `ext4.img` | 2.0 MiB | ext | mke2fs 1.47.0 (e2fsprogs, Ubuntu 24.04 in Docker) |
| `ext2.img` | 256 KiB | ext | mke2fs 1.47.0 (e2fsprogs, Ubuntu 24.04 in Docker) |
| `fat12.img` | 256 KiB | fat | mkfs.fat 4.2 and mcopy 4.0.43 (Ubuntu 24.04 in Docker) |
| `fat32.img` | 1.0 MiB | fat | mkfs.fat 4.2 and mcopy 4.0.43 (Ubuntu 24.04 in Docker) |
| `ntfs.img` | 1.2 MiB | ntfs | mkntfs and ntfs-3g 2022.10.3 (Ubuntu 24.04 in Docker) |
| `cramfs.img` | 68 KiB | cramfs | mkfs.cramfs 2.39.3 (util-linux, Ubuntu 24.04 in Docker) |
| `mbr-fat.img` | 288 KiB | mbr > fat | sfdisk 2.39.3 (util-linux, Ubuntu 24.04 in Docker) |
| `gpt-fat-ext4.img` | 692 KiB | gpt | sfdisk 2.39.3 (util-linux, Ubuntu 24.04 in Docker) |
| `gpt-ntfs.img` | 1.3 MiB | gpt > ntfs | sfdisk 2.39.3 (util-linux, Ubuntu 24.04 in Docker) |
| `gpt-fat-ext4.qcow2` | 768 KiB | qcow2 > gpt | qemu-img 8.2.2 (Ubuntu 24.04 in Docker) |
| `gpt-fat-ext4.vdi` | 1.0 MiB | vdi > gpt | qemu-img 8.2.2 (Ubuntu 24.04 in Docker) |
| `gpt-fat-ext4.vmdk` | 512 KiB | vmdk > gpt | qemu-img 8.2.2 (Ubuntu 24.04 in Docker) |
| `mbr-fat.vhd` | 2.0 MiB | vhd > mbr > fat | qemu-img 8.2.2 (Ubuntu 24.04 in Docker) |
| `mbr-fat-fixed.vhd` | 288 KiB | vhd > mbr > fat | qemu-img 8.2.2 (Ubuntu 24.04 in Docker) |
| `gpt-ntfs.vhdx` | 6.0 MiB | vhdx > gpt > ntfs | qemu-img 8.2.2 (Ubuntu 24.04 in Docker) |
| `wimlib.wim` | 69 KiB | wim | wimlib 1.14.4 (Ubuntu 24.04 in Docker) |
| `wimlib-solid.esd` | 66 KiB | wim | wimlib 1.14.4 (Ubuntu 24.04 in Docker) |
| `tree.wim` | 67 KiB | wim | 7-Zip 26.00 (Windows) |
| `nsis-lzma.exe` | 163 KiB | nsis | makensis 3.09 (Ubuntu 24.04 in Docker) |
| `nsis-zlib.exe` | 162 KiB | nsis | makensis 3.09 (Ubuntu 24.04 in Docker) |
| `nsis-bzip2.exe` | 161 KiB | nsis | makensis 3.09 (Ubuntu 24.04 in Docker) |
| `chmcmd.chm` | 10 KiB | chm | chmcmd 3.2.2 (Free Pascal, Ubuntu 24.04 in Docker) |
| `wixl.msi` | 74 KiB | msi > cab | wixl 0.103 (msitools, Ubuntu 24.04 in Docker) |
| `dmg-hfs.hfs` | 2.2 MiB | hfs | hdiutil (macOS, make-dmg.sh) |
| `dmg-apfs.apfs` | 10.5 MiB | apfs | hdiutil (macOS, make-dmg.sh) |

## Malicious images

In `tests/fixtures/malicious/`, not in `manifest.json`. What 7-Zip 26.00 on Windows lists for each
(`7z l -slt -sccUTF-8 -slmu -slsl -sns-`; `\r` and `\n` stand for the characters, `\xNN` for
the U+EF80–U+EFFF 7-Zip lists for a byte that isn't UTF-8), and what BeeZip must do. Nothing may
be written outside the destination, and every rule is FsSink's, applied to the names 7-Zip lists,
never 7-Zip's own renaming.

### `ext4-hostile.img`

An ext4 image (no journal) whose names and links can't be trusted. ext allows any byte in a name
but `/` and NUL; Windows' 7-Zip turns `\` (and `\n`) into `_` when it lists, 7-Zip on Linux may not.

| Path | Kind | Size | Link |
|---|---|---|---|
| `lost+found` | folder |  |  |
| `.. ` | folder |  |  |
| `...` | file | 5 |  |
| `.._.._escape.txt` | file | 12 |  |
| `C:` | folder |  |  |
| `CON` | file | 12 |  |
| `ads:stream.txt` | file | 6 |  |
| `aux.txt` | file | 12 |  |
| `bad\xff\xfe.txt` | file | 10 |  |
| `cr\rname.txt` | file | 16 |  |
| `dir` | folder |  |  |
| `fifo` | FIFO | 0 |  |
| `link-abs` | symlink | 11 | `/etc/passwd` |
| `link-dir` | symlink | 3 | `dir` |
| `link-drive` | symlink | 18 | `C:/Windows/win.ini` |
| `link-rel` | symlink | 17 | `../../outside.txt` |
| `link-unc` | symlink | 16 | `//server/share/x` |
| `link-up` | symlink | 5 | `../..` |
| `null` | character device | 0 |  |
| `safe.txt` | file | 5 |  |
| `trail ` | file | 15 |  |
| `trail.` | file | 13 |  |
| `x__Path = forged.._.._out.txt_Folder = -_Size = 5` | file | 7 |  |
| `.. /escape.txt` | file | 14 |  |
| `C:/drive.txt` | file | 6 |  |
| `dir/inside.txt` | file | 7 |  |

BeeZip must:
- extract `safe.txt` and `dir/inside.txt` as they are, and rename `...` (Windows drops trailing
  dots and spaces, so it would name the folder itself);
- never let `.. ` (which Windows would trim to `..`) or `.._.._escape.txt` (or `..\..\escape.txt`)
  climb out: `.. /escape.txt` is refused as traversal or renamed so it stays inside;
- land `C:/drive.txt` inside (the drive made relative or renamed, as `absolute.zip`'s);
- rename `ads:stream.txt` (no alternate stream), `CON` and `aux.txt` (`_CON`, `_aux.txt`), the
  name with a CR and the forged name with `_` for what Windows can't hold;
- turn `bad\xff\xfe.txt` back into its bytes and write it as BeeZip writes any name that isn't
  UTF-8;
- treat `trail.` and `trail ` as two names that become one (`trail_`) only once made safe: the
  overwrite policy decides, never "the same path twice";
- skip the character device `null` and the FIFO `fifo` (kind `other`);
- with links off, skip every link; with links on, refuse `link-rel`, `link-abs`, `link-drive`,
  `link-unc` and `link-up` as leading out, and make `link-dir` (listed with Folder = +, a link all
  the same).

### `ext4-sparse-100g.img`

A 256 KiB ext4 image holding one sparse file that claims 100 GB (107 374 182 400 bytes: `start` at
0, `end` at the end, holes between).

| Path | Kind | Size | Link |
|---|---|---|---|
| `lost+found` | folder |  |  |
| `safe.txt` | file | 5 |  |
| `sparse.bin` | file | 107374182400 |  |

BeeZip must refuse it before 7-Zip starts (LimitExceeded: the listed 100 GB is more than the
default `max_ratio`, 10 000, times the image's 256 KiB), and leave nothing behind, `safe.txt`
included; `archive.test` must stop the same way rather than read 100 GB of holes.

### `wim-links-out.wim`

A WIM from wimlib (`wimcapture --norpfix`) whose symlinks, stored as reparse points, lead out.

| Path | Kind | Size | Link |
|---|---|---|---|
| `dir` | folder |  |  |
| `link-dir` | symlink | 28 | `dir` |
| `link-up` | symlink | 36 | `..\..` |
| `dir/inside.txt` | file | 7 |  |
| `safe.txt` | file | 5 |  |
| `link-abs` | symlink | 76 | `C:\etc\passwd` |
| `link-rel` | symlink | 84 | `..\..\outside.txt` |

BeeZip must extract `safe.txt` and `dir/inside.txt`; with links off, skip the links; with links
on, refuse `link-rel`, `link-abs` and `link-up` as leading out (the targets keep their `\`), and
make `link-dir`.
