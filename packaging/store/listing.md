# BeeZip's Microsoft Store listing

The text for Partner Center (docs/M12.md §5), for the user to enter. Partner Center keeps the
listing, not this file: change both together. The product is reserved as "BeeZip", an MSIX app,
Store ID 9P9HHSVMM3M3.

## Properties

- **Category:** Utilities & tools. **Subcategory:** File managers.
- **Privacy policy URL:** https://joshclose.github.io/BeeZip/privacy.html
- **Website:** https://joshclose.github.io/BeeZip/
- **Support contact:** https://github.com/JoshClose/BeeZip/issues
- **System requirements:** leave every hardware box and value empty, for both minimum and
  recommended. The package manifest already limits BeeZip to desktop Windows 10 version 2004 or
  later on x64 (`MinVersion` 10.0.19041.0), and the Store uses that. Nothing else is needed: the
  WebView2 runtime comes with Windows 11 and almost every Windows 10.
- **Product declarations:** check only "install to alternate drives or removable storage" and
  "include this product's data in automatic backups to OneDrive" (both on by default; the only
  data is settings). Uncheck "record and broadcast clips", which is for games only. Leave the rest
  unchecked: BeeZip has no purchases of its own, no pen or ink support and no generative AI, and it
  hasn't had an accessibility test pass. It has no ads and no accounts. It doesn't use the
  network, so it works offline, and it collects nothing.

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
> 7z, RAR, tar, ISO, CAB, MSI, WIM, virtual disks and dozens more. A `beezip` command line and an
> MCP server for AI assistants come with it.

**Description** (up to 10,000 characters). Partner Center takes plain text, so type the bold
lines as plain headings and keep each paragraph on one line:

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
> **For the command line and AI assistants**
> `beezip` works in any terminal: list, extract, create, test and convert, with JSON output for
> scripts. `beezip mcp` serves the same commands to AI assistants such as Claude, writing only
> under the folders you allow.
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
8. The `beezip` command line in any terminal, with JSON output for scripts
9. An MCP server for AI assistants, confined to the folders you allow
10. Safe by default: escaping paths refused, the mark of the web kept, cancelled jobs cleaned up
11. Light and dark themes, a command palette, and Copy as CLI on every dialog
12. Open source, with no ads, no accounts and no data collected

**What's new in this version:** 0.7.1's was "The first release in the Microsoft Store." For
each later version, use that version's section of `CHANGELOG.md`.

**Search terms** (up to 7): zip, 7z, rar, archive, extract, compress, unzip

**Copyright and trademark info:** © 2026 The BeeZip Authors. Published by Close Consulting, Inc.
(The copyright holder is the one `LICENSE-MIT` names.)

**Additional license terms:** BeeZip is open source, licensed under the MIT License or the Apache
License 2.0, at your option. Source code and license texts: https://github.com/JoshClose/BeeZip

**Developed by:** Close Consulting, Inc

**Short title, voice title:** empty (Xbox only).

**Screenshots** (1920×1080 PNG: the page at 1280×720 at 150 %, captured over WebView2's DevTools
protocol from a debug build of v0.7.1 run with `BEEZIP_STORE=1`, so it shows the Store copy; the
samples are BeeZip's own source from `git archive`, so no one's files show):
1. Two tabs, the zip's `icons` folder, and `icon.png` previewed (light).
2. The Extract dialog, with the destination `D:\Downloads` in place of a real path (light).
3. The source's `format` folder with `tar.rs` previewed as text (dark).
4. Settings scrolled to the Explorer menu items (dark), with the config path in the footer
   hidden, since it holds the user's name.

Explorer's own right-click menu can't be captured over the protocol. A screenshot of it, if one
is wanted, is taken by hand in a folder with nothing personal in it. The shots show 0.7.1's Store
copy, which had no Copy as CLI button in its dialogs; they still fit later versions.

**Store logos:** none is required; without them the Store uses the package's logos. Poster art
and box art are left empty: Microsoft's page says they're for games (and Xbox, which BeeZip
doesn't target). The three "Store display images" are uploaded, all made from
`packaging/brand/app-icon.svg` by `cargo xtask icons`, so the listing matches the package:
- 300×300: `packaging/windows/store/Assets/Square150x150Logo.scale-200.png`;
- 150×150: `packaging/windows/store/Assets/Square150x150Logo.scale-100.png`;
- 71×71: `apps/desktop/src-tauri/icons/Square71x71Logo.png`.

The 16:9 super hero art is optional and not made yet.

## Submission options

**Publishing hold:** the default, publish as soon as it passes certification.

**Notes for certification** (Partner Center now takes them on the "Additional Testing
Information" page that the Submission options page links to):

> BeeZip is an archive manager: a full-trust desktop app (Rust and Tauri, on WebView2). No
> account, sign-in, purchase or network connection is needed.
>
> To try it:
> 1. Start BeeZip from Start, click Open (Ctrl+O) and pick any .zip or .7z. Its entries list in a
>    tab: select a file to preview it, or click Extract all.
> 2. In File Explorer, right-click a file or folder and choose BeeZip > Add to "<name>.zip" (on
>    Windows 11 the BeeZip submenu is in the main menu; on Windows 10, in the classic one). Then
>    right-click the new zip and choose BeeZip > Extract here.
> 3. Right-click any .zip > Open with > BeeZip opens it in the app.
> 4. In a terminal, run `beezip --help`, or `beezip list <path to a .zip>`: the command line comes
>    through the app's execution alias.

**Restricted capability, `runFullTrust`:**

> BeeZip is a full-trust desktop archive manager (Rust and Tauri, on WebView2), not a UWP app. It
> needs runFullTrust to:
> - read and write archives and extracted files in any folder or drive the user chooses, with the
>   user's own permissions, which an AppContainer doesn't allow;
> - add its commands to File Explorer's right-click menu (Extract here, Add to "<name>.zip" and
>   others) through the package's COM server (windows.comServer, a surrogate server) and the
>   windows.fileExplorerContextMenus extension;
> - open the archive types it's associated with (windows.fileTypeAssociation), and open archive
>   entries in their default apps;
> - give terminals its command-line tool, `beezip`, through the app's console execution alias
>   (windows.appExecutionAlias), with the same permissions;
> - keep Windows' mark of the web (the Zone.Identifier stream) on files extracted from downloaded
>   archives, as File Explorer does.
>
> It installs no drivers or services, never runs elevated, makes no network requests and collects
> no data.
