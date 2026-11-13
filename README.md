# BeeZip

An archive manager for Windows, also built for Linux and macOS, with a desktop app, a command-line tool (`beezip`) and an MCP server, all driven by one Rust command engine.

**Website, downloads and documentation:** <https://joshclose.github.io/BeeZip/>. What's new in each version is in [CHANGELOG.md](CHANGELOG.md).

> **Status:** milestone M5 is done: the engine, the command line, the MCP server and the desktop app read, write and edit zip, 7z, tar, cpio and ar, write CAB and the disk images (ISO, squashfs, DMG), read RAR, Debian packages, RPMs, CAB, LHA, UDF and the disk images, and Explorer's right-click menu reaches them. See [`docs/PLAN.md`](docs/PLAN.md) for the architecture and roadmap, and [`docs/M5.md`](docs/M5.md) for the current milestone.

## Building

Prerequisites: Rust (the pinned toolchain in `rust-toolchain.toml` installs automatically), Node 24 and pnpm (`corepack enable pnpm`), and [Tauri's prerequisites](https://tauri.app/start/prerequisites/): on Windows WebView2 and the MSVC build tools, on Linux WebKitGTK 4.1 and its build packages, on macOS Xcode's command-line tools.

```powershell
cargo build --workspace
cargo test --workspace
.\target\debug\beezip.exe --help

cd apps\desktop
pnpm install
pnpm test           # the frontend's tests (vitest)
pnpm tauri dev      # the desktop app, reloading as you edit
```

- **Bindings:** after changing a command's input or output types, regenerate the TypeScript bindings with `cargo xtask codegen`.
- **Installer:** `cargo xtask dist` builds it (`target\dist\release\bundle\nsis\BeeZip_<version>_x64-setup.exe`), and the portable copy beside it (`bundle\portable\BeeZip_<version>_x64-portable.zip`); `--debug` is quicker. On Linux it builds the deb, rpm and AppImage, and on macOS the app and its disk image (`target/dist/release/bundle/…`), signed ad hoc unless `APPLE_SIGNING_IDENTITY` names a Developer ID. `--sign-dev` adds Windows 11's menu as a package signed with the certificate `cargo xtask dev-cert` makes; Windows installs it once that certificate is trusted, with the elevated command dev-cert prints. `BEEZIP_SIGN` chooses how a build is signed (`none`, `dev`, `pfx` with `BEEZIP_SIGN_PFX` and its password, or `artifact` for Azure Artifact Signing); `packaging/windows/sign.ps1` does the signing.
- **Third-party notices:** `cargo xtask notices` regenerates `THIRD_PARTY_NOTICES.md` with cargo-about 0.9.3 (`cargo install --locked cargo-about --version 0.9.3 --features cli`), after `pnpm --dir apps/desktop build`; CI fails when it's out of date, so run it after a lockfile changes.
- **Releases:** `cargo xtask release --version V` sets the version everywhere and prints the commands to commit and tag `vV`; the tag makes `.github/workflows/release.yml` build everything and publish the release, with GitHub's source zip. Before 1.0.0, Windows gets the portable zip only; from 1.0.0 the installer too, and the workflow stops rather than publish it unsigned. The release's notes are its version's section of `CHANGELOG.md`, written for the people using BeeZip; the workflow stops without one, and CI checks the workspace's version has one. `cargo xtask winget` writes the winget manifest from a release (`--local`: from the installer built here).
- **Explorer's menu, from this tree:** `cargo xtask shell` registers the classic menu with the debug DLL and app, and `cargo xtask shell --mode modern` registers Windows 11's menu as a development package, which needs Developer Mode but no certificate. `--remove` takes either away. A click starts the debug app, so keep `pnpm dev` running.
- **A big test archive:** `cargo xtask bigzip` writes a zip of a million entries, for trying the browser.
- **Upstream bugs:** `docs/UPSTREAM.md` lists the bugs in dependencies and tools that BeeZip works around, each with a check for whether a new version fixes it. Look a dependency up there when you update it.
- **The website:** `node site/build.mjs --cli target\debug\beezip.exe` builds `site/` into `site/dist` (open `site\dist\index.html`) with Node's own modules. It runs the CLI for the command reference, the formats and the settings, renders `CHANGELOG.md` as the Releases page (each version dated by its `vX.Y.Z` tag), and fails on a broken link or a setting the settings page leaves out; CI builds it too. `.github/workflows/pages.yml` publishes it to GitHub Pages when master changes it, and after each release.

## Desktop app

`BeeZip.exe` opens archives in tabs: a folder tree, the entries (a million is fine; click a column to sort), and a preview of text, hex or images. Drag the edges between them to resize the tree and the preview, and the top edge of the jobs list to make it taller (double-click an edge for the default); BeeZip keeps the sizes for next time. A job's Copy button puts its result and its whole log on the clipboard.

- **Opening:** Open (Ctrl+O), drag an archive onto the welcome screen or the tabs, or double-click one once BeeZip is installed. Launching BeeZip again opens the archive in the running window.
- **Extract** (Ctrl+E) everything or the selected entries. **New archive** (Ctrl+N) packs files and folders, or files dropped on the welcome screen or the tabs, as zip, 7z or tar, encrypted and split as you choose. **Test** checks every CRC. **Convert** writes the archive again in another format, or with other options.
- **Dragging out** (Windows): drag selected entries onto Explorer or the desktop. They're extracted when you let go, as with 7-Zip, so Explorer waits until they're out. Ctrl copies instead of moving them out of BeeZip's temp folder; nothing leaves the archive. More than 2 GiB opens Extract instead, saying why.
- **Editing** a zip, 7z or tar: **Add files** and **Add folder** (or drop files on the entries) open the add dialog, with the folder they go into and what to do about entries already there. **Delete** (Del) asks first; **Rename** (F2) edits the name in place. Afterwards the tab lists again with the same selection. An archive that can't be edited (RAR, a split or self-extracting archive, a read-only file) says why, and files dropped on it go into a new archive.
- **Opening an entry** (double-click or Enter) opens it in its app; an archive inside opens in a tab, and a program asks first. Change the file, come back to BeeZip, and it offers to update the archive.
- **Progress:** the jobs panel shows each job's progress, with Cancel, its log and its result. Cancelling removes any partly written files.
- **Passwords and overwrites** are asked as they come up. A password stays in memory for its tab, until you close it, and is never saved.
- **Commands:** Ctrl+K lists every action and every BeeZip command; a command without a dialog of its own gets a form.
- **Copy as CLI**, on every dialog, copies the `beezip` command that does the same, without the password.
- **Settings** (Ctrl+,, or from the welcome screen) change `config.toml` as you go, and the next job uses them. Each is saved as you change it, keeping the file's comments; a value BeeZip can't take shows its error beside the field and isn't saved.
- **Theme:** System (Windows' light or dark mode), Light or Dark, in Settings or from Ctrl+K ("Theme: Dark"). Every window switches at once.
- **Updates:** at most once a day, BeeZip asks GitHub for its newest release and, when there's one, shows a banner with what's new and "Update and restart". Nothing downloads before you click; running jobs finish first; the installer's signature must match the release's version. Settings turns the check off; About checks now. The command line and the MCP server never check. A portable copy doesn't install updates: its banner's Download gets the new zip.

**The portable copy** (`BeeZip_<version>_x64-portable.zip`, the only Windows download before 1.0.0) runs from any folder: unzip it and run `BeeZip.exe`. Nothing is installed. `bin\beezip.exe` is the command line, and Settings → Explorer menu adds the right-click menu, which runs BeeZip from that folder, so remove the menu before moving or deleting it. File types and PATH are left alone. To update, close BeeZip and unzip the new version over the folder; the zip's `README.txt` says the same.

**The installer** works per user, with no admin rights:
- **Files:** it puts `BeeZip.exe` in `%LOCALAPPDATA%\BeeZip`, and adds its `bin` folder (holding `beezip.exe`) to your PATH.
- **File types:** it registers BeeZip for zip, 7z, rar, tar and the compressed and split formats, but not for zip-based documents such as `.docx` or `.jar`. Windows asks which app to use the first time you open each kind of file, with BeeZip offered. An app you've already chosen for a type (Windows sets Explorer's zip folder for `.zip` on many machines) stays until you pick BeeZip under *Open with → Choose another app*.
- **Explorer's menu:** a "BeeZip" submenu on files and folders, with Extract here, Extract to "a\", Test archive, Add to "a.zip" and the rest. A click opens a small window for the job, or BeeZip's own dialogs for Extract to… and Compress to…. When `a.zip` is already there, the window offers to add to it, replace it, keep both or skip. Settings → Explorer menu chooses the items and removes or repairs the menu; so do `beezip shell status`, `beezip shell install` and `beezip shell uninstall`.
- **On Windows 11** the menu needs BeeZip's signed package to be in Windows 11's own menu. Until releases are signed, the installer puts it under *Show more options*. With Developer Mode on, `beezip shell install --mode modern --dev` moves it into the Windows 11 menu, and `beezip shell install --mode classic` moves it back. Only one of the two is registered at a time.
- **Uninstalling** removes the PATH entry, the menu and the registrations, and leaves your file types as they were. An upgrade keeps the file types you had before BeeZip, too.
- **A running `beezip`,** such as an MCP server an AI app started, doesn't stop an upgrade or an uninstall: it keeps running from `%TEMP%` until its app restarts it, and Windows deletes that copy at your next sign-in. A running BeeZip window is closed first; the silent (`/S`) and passive (`/P`) installers close it without asking.

**On Linux and macOS** the app is the same, without Explorer's menu and its job windows:
- **Linux** (x86-64, glibc 2.35 or newer: Ubuntu 22.04, Debian 12 and later): the deb (`sudo apt install ./beezip_<version>_amd64.deb`) or the rpm installs the app as `beezip-desktop` and the command line as `/usr/bin/beezip`, and offers BeeZip in the file manager's *Open With* for the archive types it reads; packages, snaps and disk images stay with the apps that install or mount them. The AppImage runs as it is on a desktop with GTK.
- **macOS** (Apple silicon): drag BeeZip from its disk image to Applications. Releases are signed ad hoc, not with an Apple Developer ID, so the first time macOS won't open BeeZip: choose *Open Anyway* in System Settings › Privacy & Security. It then opens the archive types it registers (zip, 7z, rar, tar and the compressed and split formats; disk images and installer packages stay with macOS) from Finder's *Open With*. The command line is inside the app, as `BeeZip.app/Contents/MacOS/bin/beezip`; link it into your PATH to use `beezip`. Extracted files keep the archive's quarantine, as Archive Utility does, so macOS still checks an app that came in a download; `[extract] mark_of_the_web` turns that off too.
- **Settings** are in `~/.config/BeeZip/config.toml` on Linux and `~/Library/Application Support/BeeZip/config.toml` on macOS.

## Command line

`beezip` reads and writes ZIP, 7z, TAR, cpio (newc, as initramfs images are), ar, CAB, ISO 9660 (with Joliet and Rock Ridge), squashfs and DMG, `tar` and `cpio` under any codec (`.tar.gz`, `.tar.zst`, `.tgz`, `.cpio.gz`…), and bare compressed files (`.gz`, `.bz2`, `.xz`, `.lzma`, `.lz`, `.zst`, `.lz4`, `.br`, `.sz`, `.zz`, Unix `.Z`, `.lzo`). It reads RAR 1.5–7, through UnRAR, but never writes it, and reads Debian packages (listed as `dpkg-deb -R` unpacks them: the files, and the control files under `DEBIAN/`), RPMs, and LHA/LZH. cpio reads every header format (newc, crc, odc, old binary); CAB reads none, MSZIP and LZX, and cabinet sets; ar reads GNU and BSD archives. ISOs list their Rock Ridge, Joliet or plain names, or their UDF tree when it has more (Windows' ISOs); zisofs files are listed but not extracted, and El Torito boot images aren't listed. squashfs reads every compressor (gzip, xz, lzma, lzo, lz4, zstd). DMGs (zlib, bzip2, LZFSE, LZMA, ADC or raw) list the HFS+, HFSX or APFS volume inside, Apple-compressed files decoded (on APFS, not those compressed into a resource fork), or their partitions when there's no volume; encrypted and sparse images aren't read. Split archives (`a.7z.001`, `a.zip.001`, `a.part1.rar`, `a.rar` with `a.r00`…, `a.arj` with `a.a01`…, `a.ace` with `a.c00`…) open from any part, and self-extracting 7z, RAR, zip, CAB and LHA executables open like archives. It detects formats by content, not by extension.

It also reads the old DOS-era formats ARJ (garbled archives too, but not GOST40 encryption), ACE 1.0 and 2.0 (but not ACE 2.0's EXE, DELTA, SOUND and PIC modes), ZOO and ARC (but not PAK's crushed and distilled methods), with names in the OEM code page, and XAR archives and macOS packages. A package is listed as `pkgutil --expand-full` unpacks it: its `Payload` and `Scripts` are folders of their contents, gzip'd or pbzx; a payload in Apple Archive format stays one file. None of these is written.

It reads disk images and installers too (docs/M7.md, docs/M8.md): the virtual disks VHD, VHDX, VMDK, QCOW2 and VDI (differencing disks with their parents, snapshots and backing files, a VHDX's pending log replayed in memory), GPT and MBR disks (512-byte or 4 KiB sectors, a damaged GPT header from its backup, MBR's logical partitions), FAT12/16/32, NTFS, ext2/3/4, HFS+ and APFS volumes, and MSI installers, patches, transforms and merge modules. A virtual disk opens through its levels (`vhdx > gpt > ntfs`). A disk with one partition opens straight into its file system; with several, each one BeeZip reads is a folder (`0.data/`) and the others are files of their sectors; a disk with nothing BeeZip reads inside is one file, `<name>.img`. A differencing disk's parent is looked for by the path it records, by its name beside it, and (VHD, VHDX, VMDK) on a local drive by its absolute path, and must be the disk the child was made from; a network or device path is never opened. NTFS (clusters of up to 2 MiB) lists its system files under `[SYSTEM]/`, alternate streams as `file:stream`, second names as hard links, and symlinks and junctions as links, and reads compressed and sparse files; ext keeps names as bytes for name decoding, nanosecond times and hard links, and replays a pending journal in memory; FAT reads long names and OEM short names. WIM, ESD and split WIM images (docs/M8.md §5) list each image as a folder (`1/`, `2/`; one image at the top), with hard links, alternate streams and links as NTFS's are, and every file checked against its SHA-1; chunks decode on every core, and LZMS (ESD) through Windows' own decoder, or on Linux and macOS through wimlib's library when it's installed (`apt install wimtools`, `dnf install wimlib`, `brew install wimlib`; the `.deb` and `.rpm` recommend it). An MSI lists its files where they install (`ProgramFiles64Folder/RustDesk/RustDesk.exe`), checked against its File table and hashes, with `[Binary]/` and `[Icon]/`; a merge module lists its files where it puts them (`SystemFolder/vcruntime140.dll`), and a patch or transform lists its storages and streams as 7-Zip does (`!File`, `[5]SummaryInformation`), with `.cab` added to a cabinet's name so it opens as one (docs/M11.md). A sparse file that claims far more than the image holds, or a virtual disk's partition that claims far more than its files hold, hits the ratio limit before anything is written. HFS+ reads a catalog in any number of pieces, and APFS a sealed volume (macOS 11 and later's system volume) through its file-extent tree. A volume that uses something these readers don't (an ext volume over 16 TiB) is refused, saying what; NTFS files Windows compressed (WOF: CompactOS, `compact /exe:`, XPRESS or LZX) read as they are; those encrypted with EFS, deduplicated, or compressed from a WIM elsewhere (WIMBoot) are listed, and extraction skips them (`unreadable`) and writes the rest.

It reads CHM help files too (docs/M9.md), on every platform: listed as 7-Zip lists them, a page decoded on its own for a preview, and from a file cut short every file before the cut. Installing BeeZip leaves `.chm` with the system's help viewer.

It reads CramFS images too (docs/M10.md), Linux's compressed ROM file system: either byte order, blocks of 4 to 64 KiB (worked out from the image, which doesn't record them), holes, a 512-byte boot block before the image, and Linux 4.15's extended block pointers, which 7-Zip reads none of, and 7-Zip's own variant (LZMA or zlib, blocks up to 512 KiB). Devices, FIFOs and sockets are listed and skipped, and testing checks the image's CRC.

It reads NSIS installers too (docs/M10.md): solid or not, in zlib, NSIS's bzip2 or LZMA (with or without its x86 filter), from NSIS 2 (whose deflate and ANSI names it reads as such), Jim Park's Unicode NSIS and NSIS 3, 32- and 64-bit. Files are listed as 7-Zip lists them (`$INSTDIR\` dropped, other variables such as `$PLUGINSDIR` kept as folders), with exact sizes (a solid installer is decoded once as it opens, to read them), and the uninstaller is rebuilt as the installer writes it. Testing checks the installer's CRC, and an installer cut short gives every file before the cut.

BeeZip reads every format it lists with its own code and runs no other program to read anything (docs/M11.md): since 0.6.0 it doesn't use 7-Zip, and a `[seven_zip]` section left in an old config is ignored. The only library it loads is the system's own LZMS decoder for ESD images: Windows' `cabinet.dll`, or wimlib's on Linux and macOS when it's installed. What a reader doesn't support is refused with a message saying what: encrypted disk images, an ext volume over 16 TiB, WIM 1.09 to 1.12 from Longhorn's betas, pipable WIMs, VMware's ESXi snapshot and raw-device extents, VHDX version 2, and a few layouts no tool is known to write. 7-Zip stays in BeeZip's tests, as the program its readers are checked against.

```powershell
beezip formats                        # what BeeZip reads and writes, with levels and threading
beezip detect download.bin            # zstd → tar, a zip SFX, or "not an archive (Portable Executable)"
beezip info backup.tar.zst            # entries, sizes, ratio, methods, encryption
beezip list backup.zip                # one folder level; --flat for everything, --glob "*.md" to filter
beezip list photos.rar --sort size --reverse --kind file
beezip read backup.zip docs/a.md      # print part of an entry (--encoding hex|base64, --offset, --max-bytes)
beezip test backup.zip                # read everything back and check CRCs; exit 8 if damaged
beezip list old.zip --name-encoding cp932   # names a Japanese Windows wrote; the default reads
                                            # UTF-8, else Windows' own code page

beezip x backup.zip -o out            # extract (default: the current directory)
beezip x backup.zip docs --smart      # just docs/; into a folder named after the archive if needed
beezip x backup.zip --overwrite rename --dry-run

beezip create backup.tar.zst src -l 19          # format from the extension
beezip c secret.zip src -p "pass phrase"         # AES-256; --encryption zipcrypto for old tools
beezip c logs.zip logs -m ppmd --exclude "*.tmp"
beezip c backup.7z src -p "pass phrase"          # LZMA2, solid; the names are encrypted too
beezip c big.7z videos -v 4g --solid=false       # big.7z.001, big.7z.002…; -m lzma|ppmd|bzip2|deflate|copy
beezip x big.7z.002 -o out                       # any part opens the whole set
beezip c initrd.cpio.gz rootfs                   # newc; files of 4 GiB or more don't fit
beezip c drivers.cab inf -m mszip                # or -m store; files only, as in ar
beezip c disc.iso photos                         # ISO 9660 level 3, Joliet and Rock Ridge
beezip c rootfs.squashfs rootfs -m zstd          # gzip (the default), xz, zstd, lz4 or lzo
beezip c app.dmg build/App                       # an HFS+ volume, zlib-compressed (UDZO)
beezip list python3-six_1.17.0-1_all.deb         # DEBIAN/ and usr/, as dpkg-deb -R unpacks it

beezip add backup.zip notes.txt --dir docs      # alias a; asks about an entry already there
beezip rename backup.zip docs papers             # alias rn; a folder takes everything under it
beezip remove backup.7z "*.tmp" --dry-run        # alias d; --glob for patterns, --dry-run to see
beezip convert old.rar new.7z                    # any archive BeeZip reads; the source stays
beezip convert a.tar.gz a.tar.zst                # tar entries copied, the stream encoded again
beezip open backup.zip docs/a.md                 # extract to %TEMP%\BeeZip\open and open it

beezip compress big.log -c xz -l 9    # big.log.xz, keeping big.log
beezip decompress backup.tar.zst      # backup.tar: one codec layer per call

beezip bench                          # the common codecs and levels on BeeZip's own 8 MiB sample:
                                      # size, MB/s and memory each way, every round trip checked
beezip bench big.iso --grid full      # 8 MiB of the file, in 16 slices; every codec at every level
beezip bench -g zstd:3,zstd:19:0,xz:6 # codec[:level[:threads]]; threads 0 is one per core
```

- **Safety:** extraction never writes outside the destination. Paths with `..`, and links leading out, are skipped. The rest is extracted, then the command fails with exit code 14. Absolute paths, drive letters, reserved names such as `CON` and characters Windows can't store are rewritten, and reported. Symlinks are off by default (`--links` turns them on); hard links are extracted as copies. Zip bombs hit a 10 000:1 ratio limit.
- **Editing:** `add`, `remove` and `rename` change zip, 7z, tar, cpio and ar archives (tar and cpio compressed or not). They never write into the archive: a new one is written beside it and swapped in, so a failed or cancelled change leaves it as it was, and the Mark of the Web, hidden attribute and creation time carry over. Entries that stay are copied without decoding: zip entries byte for byte, whole 7z blocks (a solid block that loses an entry is encoded again), tar, cpio and ar members (a compressed tar's or cpio's stream is encoded again). An ar's symbol table is left out of an edit, since it would be stale (`ranlib` makes it again). CAB, the disk images, packages, LHA, ARJ, ACE, ZOO, ARC and XAR aren't edited. Adding to an archive with encrypted entries needs a password for the new files, or `--unencrypted`. Split and self-extracting archives aren't edited; `convert` makes one file of them. `convert` of an encrypted archive needs `--new-password` or `--decrypt`.
- **Prompts:** in a terminal, BeeZip asks for passwords and what to do with existing files. Without one, it fails and says which flag to pass (`--password`, `--overwrite`).
- **Output:** `--output json` prints one JSON document, `--output ndjson` streams every job event (progress included, and `bench`'s cells as each finishes), and `-q` hides progress bars. Ctrl+C cancels and removes the partly written file; a second Ctrl+C exits at once, and still removes it.
- **7z and RAR passwords:** 7z and RAR 1.5–4 have no password check, so a wrong password shows as damaged data; BeeZip asks again, up to three times. A RAR whose entries have different passwords asks for each.
- **Volumes:** `-v/--volume-size` takes bytes or `100m`, `4g`, `700MB` (powers of 1024) and works for every format. Spanned zips (`.z01`) aren't supported.
- **Every command is also reachable generically:** `beezip commands` lists them, `beezip schema archive.extract` prints the JSON schemas, and `beezip run archive.list --json '{"archive":"a.zip"}'` runs one with JSON arguments, as the desktop app and the MCP server do.
- **Exit codes:** 0 OK, 2 invalid arguments, 3 not found, 4 unsupported format, 6 password required, 7 wrong password, 8 corrupt, 10 conflict (the file exists), 11 limit exceeded, 13 I/O error, 14 unsafe entries skipped, 130 cancelled.

### Configuration

`%APPDATA%\BeeZip\config.toml` (or the file `BEEZIP_CONFIG` names) sets the defaults; the arguments above override them. `beezip settings get` lists every setting with its value, and `beezip settings set` changes them in place, keeping the file's comments and refusing a key or value BeeZip doesn't take (nothing is written then):

```powershell
beezip settings get
beezip settings set extract.overwrite=rename levels.zstd=19     # VALUE is TOML; a bare word is a string
beezip settings set "mcp.roots=['C:\Users\you\Unpacked']" --reset limits.max_ratio
```

```toml
[extract]
overwrite = "ask"          # ask | always | never | rename | newer
links = false
mark_of_the_web = "all"    # copy the archive's Zone.Identifier (macOS: its quarantine) to extracted files, as Explorer and Archive Utility do
threads = 0                # extracting zips and decoding xz: 0 = one per core, 1 = one

[edit]
overwrite = "ask"          # adding over an entry already there (beezip add, the add dialog): ask | always | never | rename | newer

[create]
threads = 0                # 0 = one per core

[levels]                   # per codec, zip method and 7z method
zstd = 3
deflate = 6
lzma2 = 5

[stream]
codec = "zstd"             # for `beezip compress`

[limits]
max_ratio = 10000
max_entries = 10000000
decoder_memory_mib = 1024

[mcp]                      # `beezip mcp`; --root and --read-only override these
roots = ['C:\Users\you\Unpacked']
read_only = false

[desktop]
theme = "system"           # system | light | dark

[updates]
check = true               # the desktop app looks for a new release at most once a day

[shell]                    # Explorer's right-click menu
cascade = true             # classic menu: false puts each item at the top level
[shell.items]              # every item shows unless set to false: open, extract-here,
test = false               # extract-folder, extract-to, test, add-zip, add-7z, add-tar-zst, compress-to

[jobs]
close_when_done = true     # a job window from Explorer closes after a clean success
```

The settings are hidden from MCP clients: one that could change `[mcp] roots` could widen its own sandbox.

## MCP server

`beezip mcp` serves the same commands as MCP tools over stdin/stdout, so an assistant such as Claude can list, test, read, extract and create archives. Commands that write may only write under the `--root` directories; reads aren't confined.

```powershell
claude mcp add beezip -- C:\path\to\beezip.exe mcp --root C:\Users\you\Unpacked
```

- **Overwrites:** BeeZip asks the user about existing files through the client, where the client supports it.
- **Passwords:** it never asks for them over MCP; the assistant passes them.
- **Limits:** a list page holds at most 500 entries, and a read returns at most 256 KiB.

[`docs/MCP.md`](docs/MCP.md) covers Claude Desktop, the MCP Inspector, every tool, and the sandbox rules.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

BeeZip reads RAR archives with UnRAR by Alexander Roshal, which has its own license: it may be used to extract RAR archives, not to create them. Its text, and the other notices BeeZip ships, are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
