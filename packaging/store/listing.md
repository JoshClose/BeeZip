# BeeZip's Microsoft Store listing

The text for Partner Center (docs/M12.md §5), for the user to enter. Partner Center keeps the
listing, not this file: change both together. The product is reserved as "BeeZip", an MSIX app,
Store ID 9P9HHSVMM3M3.

The Store copy has no command line until Microsoft grants the HeadlessAppBypass waiver
(docs/M12.md §14), so the listing doesn't offer `beezip`, MCP or Copy as CLI. When a package
with the command line goes in, put back what the 0.7.0 draft had: the short description's last
sentence, the "For the command line and AI assistants" paragraph, features 8 and 9 with Copy as
CLI in the themes line, the certification notes' `beezip --help`, and the alias in the
`runFullTrust` justification.

## Properties

- **Category:** Utilities & tools. **Subcategory:** File managers.
- **Privacy policy URL:** https://joshclose.github.io/BeeZip/privacy.html
- **Website:** https://joshclose.github.io/BeeZip/
- **Support contact:** https://github.com/JoshClose/BeeZip/issues
- **System requirements:** Windows 10 version 2004 or later, x64. Nothing else is needed: the
  WebView2 runtime comes with Windows 11 and almost every Windows 10.
- **Product declarations:** none apply. BeeZip has no in-app purchases, no ads and no accounts.
  It doesn't use the network, so it works offline, and it collects nothing.

## Pricing and availability

- **Price:** free, in every market.
- **Visibility:** public.

## Age ratings

The questionnaire, answered by the user. BeeZip has no user-generated content, no chat, no
location, no purchases, and no violence or other mature content. It doesn't share anything with
anyone. Expect the lowest rating everywhere (IARC 3+ / Everyone).

## Store listing (English, United States)

**Product name:** BeeZip

**Short description** (up to 1,000 characters):

> Open, extract and create archives from Explorer's right-click menu or a fast desktop app: zip,
> 7z, RAR, tar, ISO, CAB, MSI, WIM, virtual disks and dozens more.

**Description** (up to 10,000 characters):

> BeeZip is an archive manager for Windows. Right-click files in Explorer to extract or compress
> them, or open archives in BeeZip's own window to look inside, preview, extract, edit and
> convert them.
>
> **Explorer's right-click menu, on Windows 10 and 11**
> Extract here, Extract to "a\", Extract to…, Test archive, Add to "a.zip", Add to "a.7z",
> Add to "a.tar.zst" and Compress to…, on files and folders, one or many. Extract here is smart:
> an archive holding more than one item goes into a folder named after it. Each job gets a small
> window with its progress, the password when one is needed, and what to do with files already
> there. Choose which items show in Settings.
>
> **A desktop app for big archives**
> Tabs, one per archive, with a folder tree, the entries and a preview of text, hex or images. A
> million entries list without a pause. Extract everything or what you select, drag entries out
> onto Explorer, open an entry in its app and put your changes back. Edit zip, 7z, tar, cpio and
> ar archives in place. Test, Info, Convert and Benchmark. Light and dark themes.
>
> **Formats**
> Reads and writes zip (with AES-256), 7z (with AES-256 that hides the names), tar, cpio, ar,
> CAB, ISO 9660, squashfs and DMG, and tar under gzip, bzip2, xz, Zstandard, LZ4, Brotli and more.
> Reads RAR 1.5 to 7, Debian packages, RPMs, LHA, UDF and XAR, Windows' WIM and ESD images, MSI
> installers and their patches, transforms and merge modules, NSIS installers, CHM help files,
> virtual disks (VHD, VHDX, VMDK, QCOW2, VDI) and the disks and file systems inside them (GPT,
> MBR, FAT, NTFS, ext, HFS+, APFS). Split and self-extracting archives open from any part. BeeZip
> reads every one of these itself and runs no other program.
>
> **Careful by default**
> Paths that try to escape the folder you extract to are refused, partly written files are
> removed when a job is cancelled, files you download keep Windows' mark of the web when they're
> extracted, and limits you can change stop archives that expand out of all proportion.
>
> BeeZip is open source, under the MIT and Apache 2.0 licenses.

**Product features** (up to 20, 200 characters each):

1. Extract and compress from Explorer's right-click menu, on Windows 10 and 11
2. Smart Extract here: one folder per archive when it holds more than one item
3. Opens zip, 7z, RAR, tar, ISO, CAB, MSI, WIM, ESD, DMG, virtual disks and dozens more
4. Creates zip and 7z with AES-256, and tar with gzip, xz, Zstandard and more
5. A desktop app with tabs, a folder tree, previews and a million entries without a pause
6. Edit zip, 7z and tar archives: add, delete and rename entries in place
7. Drag entries out onto Explorer, or open one in its app and put your changes back
8. Safe by default: escaping paths refused, the mark of the web kept, cancelled jobs cleaned up
9. Light and dark themes, and a command palette
10. Open source, with no ads, no accounts and no data collected

**What's new in this version:** the first release in the Microsoft Store. For later versions,
use that version's section of `CHANGELOG.md`.

**Search terms** (up to 7): zip, 7z, rar, archive, extract, compress, unzip

**Copyright and trademark info:** © 2026 Close Consulting, Inc

**Additional license terms:** MIT or Apache-2.0, https://github.com/JoshClose/BeeZip

**Screenshots** (1920×1080, made from a release build over WebView2's DevTools protocol):
1. An archive open in a tab: the folder tree, the entries and a preview.
2. The extract dialog.
3. Explorer's right-click menu with BeeZip's submenu.
4. A job window extracting, with its progress.

## Submission options

**Notes for certification:**

> BeeZip is an archive manager (a Rust and Tauri desktop app on WebView2). To try it: open any
> .zip with BeeZip (File Explorer → right-click → Open with → BeeZip), or right-click a file or
> folder and use the BeeZip submenu (on Windows 11 it's in the main menu; Extract here and Add to
> "<name>.zip" show what it does). No account or network connection is needed.

**Restricted capability, `runFullTrust`:**

> BeeZip is a full-trust desktop app. It reads and writes archives and files wherever the user
> chooses, provides File Explorer's context-menu commands through its COM server (the
> windows.comServer and desktop4:FileExplorerContextMenus extensions), and opens archive entries
> in their default apps. None of this runs in an AppContainer.
