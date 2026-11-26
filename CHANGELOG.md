# Changelog

What's new in each version of BeeZip, for the people who use it. Each release's notes on GitHub
come from its section here; the website's Releases page shows them all.

Write a new section as `## X.Y.Z`, with `###` groups and `- ` items, describing what someone
using BeeZip will notice. Leave the date out: the Releases page dates each version by its
`vX.Y.Z` tag.

## 0.9.0

### Encrypted .bhive archives

- **A `.bhive` can be encrypted, names and all.** Without a way in, nobody can list it, learn
  its files' names, dates or folders, or change a byte without BeeZip noticing. It's part of
  `.bhive` version 1, so every later BeeZip reads it. BeeZip 0.8 refuses an encrypted `.bhive`
  rather than misread it.
- **Any number of ways in, any one enough:** a password, a recovery key, someone's public key, a
  certificate, This PC, a security key or Windows Hello.
- **Passwords are slow to guess:** each guess takes a gigabyte of memory, and opening takes about
  0.3 s on a fast desktop; Strong takes 2 GiB. BeeZip warns about a weak password, though it
  lets you keep it, and **Suggest one** gives six random words. A password beside someone
  else's key gets a warning too: they could make an archive your password opens.
- **A recovery key,** 48 digits as BitLocker's, opens the archive when every other way in is
  lost. BeeZip shows it once and never keeps it: copy it, save it or print it.
- **Public keys in age's format:** post-quantum `age1pq1…` keys by default, and classic `age1…`
  keys. A key made by `age-keygen` works in BeeZip, and BeeZip's work in age (1.3 or later for
  post-quantum keys). The archives are BeeZip's own, not age files.
- **Certificates:** RSA (2,048 bits or more) and EC (P-256, P-384), from Windows' stores, the
  macOS Keychain or a file. BeeZip says why it can't use one, such as an EC certificate whose key
  can only sign.
- **This PC** keeps a key in the PC's TPM, behind an optional PIN, and **Windows Hello** uses
  your face, a fingerprint or its PIN. Both open the archive on that PC alone, so BeeZip always
  asks for another way in beside them. **Security keys** (FIDO2) need a touch. Security keys and
  smart cards haven't been tried on a physical device yet.
- **Safe from quantum computers, or not:** BeeZip says which. Passwords, recovery keys,
  post-quantum keys and security keys are; classic keys, certificates and This PC aren't.
- **Changing who can open it doesn't recompress it:** add a way in, remove one, or make a new
  key, which seals everything again so that someone who kept the old key can't open later
  versions.
- **Edits keep the encryption:** adding, removing and renaming need one way in, and new files
  are sealed with the rest. Converting an encrypted `.bhive` into a `.bhive` keeps who can open
  it, unless you give it new ways in.
- **Zip and 7z keep their own encryption,** as 0.8.4 left it. With a password on one, BeeZip
  says what a `.bhive` hides that they don't.

### Signatures

- **Sign a `.bhive`,** encrypted or not, with your own signing key or a certificate, to show who
  made what's in it and that nothing has changed since. Several people can sign one archive.
- **What's signed is the contents:** changing who can open it, a new key, or encrypting it keeps
  the signatures. Adding, removing or renaming files drops them, and so does converting with
  other entries, another level or into another format; BeeZip says so first. The app offers to
  sign again with your keys that signed it; on the command line, `add --sign` does, or
  `beezip sign` afterwards.
- **Checked as it opens:** "Signed by" you, a contact or a certificate the system trusts; "an
  unknown signer", with a fingerprint to compare by phone; or, in red, "Changed after it was
  signed", and BeeZip asks before extracting. The time a signature gives is the signer's claim.
- **Your signing key is post-quantum,** ML-DSA-65 with Ed25519, both checked.
- **BeeZip 0.8 still reads a signed `.bhive`** that isn't encrypted, and ignores the signature.

### Keys and certificates

- **Your own keys:** make one in Settings or with `beezip keys create`, for opening archives
  (post-quantum by default) or for signing them. Its private key stays on this machine, sealed
  by the system: by Windows for your account, in the login Keychain on macOS, in a file only you
  can read on Linux. Back it up as text, after a warning.
- **Your keys open archives without asking.** Key files open them too: age identities, PEM and
  PKCS #8 keys, and `.pfx` and `.p12` files on Windows and macOS. On Linux a `.pfx` is refused,
  with the `openssl pkcs12` command that turns it into a PEM file.
- **Contacts:** other people's public keys and certificates, by name, to encrypt to and to know
  their signatures by.
- **Windows asks** for a smart card's or the TPM's PIN, or a touch, in its own dialog, and only
  for the way in you chose. After a wrong key or a closed dialog, BeeZip asks again.

### The desktop app

- **New archive and Convert** have a Protection section for `.bhive`: the password with its
  strength, a recovery key, people and keys, This PC, a security key and Windows Hello, and
  **Sign with**.
- **Unlock** asks for a way into an encrypted `.bhive` none of your keys opens: the password, the
  recovery key, or a button for each key or device this PC has.
- **Who can open this** lists an archive's ways in, adds and removes them, and makes a new key.
- **A signature line** at the top of the archive, with its details and **Add to contacts**; and
  **Sign**, to add or remove signatures.
- **Settings** has Your keys, Contacts and Certificates.

### The command line

- **New options:** `--recovery-key`, `--to`, `--to-cert`, `--this-pc`, `--security-key`,
  `--windows-hello` and `--strength` on create and convert, `--sign` on create, add and
  convert; `-i`/`--identity` and `--password-stdin` everywhere; `--require-signer` on extract
  and test.
- **New commands:** `beezip protection`, `protect`, `sign`, `verify`, `keys` and
  `certificates list`.
- **Exit codes:** an encrypted `.bhive` with a password or recovery key, and none given, is 6,
  as a zip is. New: 15 when only keys, certificates or devices open it and none given does, and
  16 when it isn't signed as `verify` or `--require-signer` asks.

### AI assistants (MCP)

- **Encrypted `.bhive` over MCP:** an assistant can make one with a password, public keys or
  certificates, open one with a password or a recovery key (your stored keys are tried
  silently), and check signatures. It never uses This PC, a security key or Windows Hello, never
  makes a recovery key, never signs, and doesn't change who can open an archive. New tools:
  `archive_protection`, `archive_verify`, `keys_list` and `certificates_list`.

## 0.8.4

### Fixes

- **Passwords on 7z archives are much harder to guess.** BeeZip ran a 7z password through 256
  rounds of SHA-256 to make its key, where 7-Zip runs 524,288, so someone trying passwords on a
  7z from BeeZip could try them 2,048 times faster than on one from 7-Zip. BeeZip now does what
  7-Zip does, and gives each part of the archive its own starting value (IV), as 7-Zip does,
  instead of one for all of them. Any program that opens 7z files opens the new ones. 7z archives
  that earlier versions of BeeZip encrypted keep the weak setting: to strengthen one, extract it
  and create it again, or convert it to 7z and give it a password again.

## 0.8.3

### The desktop app

- **Explorer's menu opens its windows with BeeZip in them.** On Windows, extracting, adding
  or testing from Explorer's right-click menu opened a window that was empty and white, even in
  dark mode, and filled in a moment later. That window now appears when it has something to
  show, as BeeZip's main window has since 0.8.2.

### Fixes

- **A damaged VMDK disk image is reported as damaged.** One whose grain table names the same
  compressed grain twice stopped testing or extracting with an internal error ("command
  panicked"). BeeZip now says which grain is wrong.

## 0.8.2

### The desktop app

- **BeeZip's window comes up with BeeZip in it.** On Windows the window used to appear at
  once as an empty white rectangle and fill in a moment later, longer on a busy machine. It
  now appears when it has something to show, in light and dark mode alike, at the moment it
  used to fill in.

## 0.8.1

### The Microsoft Store copy

- **No blue square behind the taskbar icon.** With Windows in light mode, the Store copy's
  icon on the taskbar sat on a square of your accent colour. It is the bee alone now, as in
  dark mode.

## 0.8.0

### .bhive, BeeZip's own archive format

- **A new format, `.bhive`,** made for today's machines. Files are packed into independent
  cells, so every core works when you make an archive and when you extract or test one, and
  opening one file doesn't decode the rest.
- **What repeats is stored once:** copies of a file, versions of it, the same library in ten
  folders.
- **Five levels:** None, Fast, Balanced (the default), High and Max. Fast and Balanced use
  zstd; High and Max use LZMA2, for the smallest archives.
- **A download cut short still opens.** BeeZip says the archive is incomplete, and
  `--recover` (or `recover` in the MCP tools) lists and extracts the files that arrived.
- **Editing without compressing again:** add, remove and rename copy the archive's cells as
  they are, and the archive keeps the level it was made at.
- **Everywhere BeeZip is:** New archive and Convert offer it, with the levels by name;
  Explorer's menu has **Add to "a.bhive"**; `beezip create a.bhive src -l high`; and the MCP
  tools take it like any format. Installing BeeZip registers it for `.bhive` files.
- **Open, though only BeeZip reads it today:** the format has a complete specification
  (`docs/bhive.md`) and a second reader in Python, checked on every change. zip stays the
  default format. Version 1 has no encryption.

### Explorer's menu

- **Items at the top level stay in order** now that there are ten: they are numbered with two
  digits. If you had turned the submenu off, BeeZip replaces the old items the next time it
  registers the menu (Settings → Explorer menu → Repair does it at once).

### The Microsoft Store copy

- **The command line is back in the Microsoft Store copy:** `beezip` in any terminal, Copy as
  CLI on every dialog, and the MCP server's settings. The package now gives `beezip` through the
  app itself instead of a hidden part, which the Store refused in 0.7.0.

## 0.7.1

### The Microsoft Store copy

- **The Microsoft Store copy has no command line for now.** The Store refused 0.7.0's package
  because of the hidden part that gives `beezip` to terminals, which needs Microsoft's
  permission first. Until Microsoft allows it, the Store copy is the app and Explorer's menu,
  with no `beezip`, no Copy as CLI and no MCP server settings. The installer and the portable
  copy keep all of them.

## 0.7.0

### BeeZip in the Microsoft Store

- **A Microsoft Store copy of BeeZip,** signed by Microsoft, is on its way: this version is the
  first one built for the Store. Once its listing is live, it's the same app, installed and
  updated by the Store, with Explorer's menu on Windows 10 and 11 and `beezip` in any terminal.
- **In the Store copy,** Settings has no update setting, since the Store updates BeeZip, and
  the Explorer menu needs no install or repair. A **Default apps** button opens Windows' page
  where BeeZip becomes the app for archives. Copy as CLI gives plain `beezip`.
- **With two copies installed,** such as the Store's and the installer's, Settings and
  `beezip shell status` say Explorer shows two BeeZip menus.
- **A privacy page** on the website: BeeZip collects nothing.

## 0.6.0

### MSI patches, transforms and merge modules without 7-Zip

- **Merge modules (`.msm`) list their files where they put them,** as an MSI does
  (`SystemFolder/vcruntime140.dll`), checked against their hashes, where 7-Zip lists their
  streams and names their files by internal keys. Info gives the module's ID, version and
  language.
- **Patches (`.msp`) and transforms (`.mst`) list their storages and streams as 7-Zip does**
  (`!File`, `[5]SummaryInformation`), checked stream for stream against 7-Zip on 4 patches and
  631 transforms. A patch's cabinets get `.cab` added to their names, so they open with a
  double-click. Info gives a patch's name and description, and a transform's product codes and
  versions.
- **Transforms open:** BeeZip didn't recognise them before, through 7-Zip or otherwise.

### ESD images on Linux and macOS, and what only 7-Zip read

- **ESD images and LZMS WIMs open on Linux and macOS** through wimlib's library, loaded only
  when one is opened, as Windows' own decoder is on Windows: `apt install wimtools`,
  `dnf install wimlib` or `brew install wimlib`. The `.deb` and `.rpm` recommend it. Without
  it, opening an ESD says what to install.
- **QCOW version 1 images** (`qemu-img -O qcow`) open: plain, compressed or with a backing file.
  7-Zip reads only the uncompressed ones.
- **Virtual disks BeeZip refused open:** a VHDX over 8 TiB in 1 MiB blocks, VHDs and VMDKs of
  larger blocks and grains, VMDK's VMFSRAW extents (ESXi), and VirtualBox undo images.
- **7-Zip's own CramFS variant** opens: LZMA or zlib, with blocks of 4 to 512 KiB.
- **WIM chunks of up to 1 GiB**, which wimlib writes on request, and CHM help files and WIM
  images with layouts no tool is known to write, read as 7-Zip reads them.
- **NTFS volumes of clusters over 64 KiB** open: Windows formats clusters of up to 2 MiB
  (`format /A:2M`).
- **HFS+ volumes whose catalog is in many pieces** open, as a long-used Mac's are, alone or in
  a DMG.
- **Sealed APFS volumes read right:** macOS 11 and later's system volume, alone or in a DMG, read
  every file as zeros before.

### BeeZip without 7-Zip

- **BeeZip never runs 7-Zip now.** It reads every format it lists itself; what a reader doesn't
  support (an encrypted disk image, an ext volume over 16 TiB, a WIM from Windows Longhorn's
  betas) is refused with a message saying what, where it used to go to 7-Zip.
- **Settings' 7-Zip section, Install 7-Zip and `beezip 7zip install` are gone.** A `[seven_zip]`
  section left in your `config.toml` is ignored, with no warning, and setting one of its keys
  (`beezip settings set seven_zip.path=…`) says it was removed.
- **For scripts and MCP clients:** `formats.list` no longer has `seven_zip`, nor each format's
  `backend` and `available`, and `archive.info` no longer has `backend`. They had been the same
  for every format BeeZip reads itself.

### Fixes

- **Making a zip always ends when it's cancelled or fails.** A zip is made on several threads,
  and when it was cancelled, or a file couldn't be read part-way through, one of them could
  miss being told to stop. Rarely, the job then never finished.

## 0.5.0

### NSIS installers without 7-Zip

- **BeeZip reads NSIS installers itself,** on every platform: NSIS 2 and 3 and Jim Park's
  Unicode NSIS, 32- and 64-bit, in zlib, bzip2 or LZMA, solid or not. Files are listed as 7-Zip
  lists them, checked file for file against 7-Zip on 55 installers.
- **Sizes are exact:** 7-Zip lists none for about a quarter of an installer's files, and some
  wrong. A solid installer takes a moment to open while BeeZip finds them.
- **Extracting an installer is much faster:** BeeZip no longer copies it through a folder of
  7-Zip's first, which took six times as long as 7-Zip on its own.
- **The uninstaller is extracted too,** rebuilt as the installer writes it, where 7-Zip leaves
  it out, as it does from BeeZip's own installer.
- **Installers 7-Zip gets wrong read right:** those built by Ubuntu's makensis 2.50, and those
  with a stored header before compressed files.
- **Testing checks the installer's CRC,** and an installer cut short gives every file before
  the cut.

### CramFS images without 7-Zip

- **BeeZip reads CramFS images itself,** on every platform, as 7-Zip lists them: checked file
  for file against 7-Zip on 13 images made by Linux's `mkfs.cramfs`.
- **Images 7-Zip can't read open too:** files with holes, blocks of 8 to 64 KiB, an image after
  a 512-byte boot block, and Linux 4.15's extended block pointers.
- **Testing checks the image's CRC,** and an image cut short gives every file before the cut.

### 7-Zip

- **7-Zip is now needed only for MSI patches, transforms and merge modules,** and for the few
  files of other formats BeeZip doesn't read itself.

## 0.4.0

### CHM help files without 7-Zip

- **BeeZip reads CHM help files itself,** on every platform: listed as 7-Zip lists them,
  checked file for file against 7-Zip on 81 help files from Windows, Office, Visual Studio and
  others. Previewing a page decodes only what it needs, and a help file cut short gives every
  file before the cut.
- **A double-click on a `.chm` still opens the help:** installing BeeZip leaves it with the
  help viewer, and BeeZip's items are in its right-click menu.
- **7-Zip is now needed only for NSIS installers, CramFS images and MSI patches,** and for the
  few files of other formats BeeZip doesn't read itself.

### Fixes

- **Settings' 7-Zip section** no longer says WIM images and virtual disks need 7-Zip, which
  hasn't been so since 0.3.0.
- **"Can't be edited" names the right reader:** for an MSI installer, a disk or virtual disk
  image or a WIM image, it said BeeZip reads the file through 7-Zip, though BeeZip reads them
  itself.
- **Settings' compression levels say what each one is for:** zstd's covers `.zst` and
  `.tar.zst` files, and zstd in zip and SquashFS archives. Where a format's own default differs,
  the row says so (SquashFS's zstd is 15); the page showed 3 for all of them.
- **A default level can't be one a format refuses.** The deflate and gzip sliders went down to
  0, which zip's and 7z's deflate and SquashFS's gzip don't take: with deflate at 0, every new
  zip failed. Both start at 1 now, and `beezip settings set` refuses such a level too.

## 0.3.0

### Virtual disks without 7-Zip

- **BeeZip reads VHD, VHDX, VMDK, QCOW2 and VDI itself,** with the disks and file systems in
  them, so they open without 7-Zip: `vhdx › gpt › ntfs`. A disk of several partitions shows
  each one BeeZip reads as a folder, where 7-Zip gave partition images to extract and open in
  turn.
- **Differencing disks and snapshots open with their parents,** found by the path the disk
  records, by name beside it, or by its full path on a local drive, and checked to be the disk
  the child was made from. 7-Zip follows only a VHDX parent in the same folder. A network path
  in a disk is never opened.
- **A VHDX that Hyper-V left with writes pending** shows its latest contents: the log is applied
  in memory, never to the file. 7-Zip shows the disk as it was before.
- **More variants read:** qemu's stream-optimized VMDKs, QCOW2 with zstd or extended L2 entries,
  VDIs with blocks other than 1 MiB, and VMDK descriptors with zero extents.
- **On Windows, `.vmdk`, `.qcow2` and `.vdi` open in BeeZip** once it's installed; `.vhd` and
  `.vhdx` stay with Windows, which mounts them. On Linux and macOS they stay with your virtual
  machine apps.

### WIM and ESD images without 7-Zip

- **BeeZip reads WIM, ESD and split WIM images itself,** Windows' install images among them:
  each image is a folder (`1/`, `2/`), every file is checked against the SHA-1 the image
  records, and chunks decode on every core. Testing all seven images of Windows 10's
  `install.esd` takes 12–15 s here, where 7-Zip takes 46 s for one.
- **On Windows, ESD's LZMS is decoded by Windows' own decoder;** on Linux and macOS an ESD still
  goes to 7-Zip.
- **`.wim`, `.esd` and `.swm` open in BeeZip** on Windows and macOS once it's installed.

### Windows-compressed files on NTFS

- **Files Windows compressed on NTFS extract,** with CompactOS or `compact /exe:` (XPRESS4K,
  XPRESS8K, XPRESS16K or LZX), where 0.2.0 skipped them, and their compressed data isn't listed
  beside them any more. 7-Zip 26.00 extracts such a file as zeros. Files compressed from a WIM
  elsewhere (WIMBoot), encrypted with EFS or deduplicated are still skipped, with the reason.

### Installers and cabinets

- **MSI installers and cabinets extract about twice as fast,** with a faster LZX decoder:
  LLVM's installer in 6.7 s where 0.2.0 took 13 s (7-Zip: 4.7 s), and QGIS's 35,800 files in
  21 s where 0.2.0 took 41 s (7-Zip: 18 s). Testing one takes about half as long.
- **Files an installer holds twice are copied, not decoded again,** as LLVM's `clang.exe` and
  `clang++.exe` are, and testing passes the copy without reading it twice.
- **Small files are written on other threads** while the next ones decode, as `[extract]
  threads` allows; and an installer's file hashes are checked on a thread of their own.
- **An MSI whose cabinet runs on into a second embedded cabinet** extracts whole. 0.2.0 failed
  the files that spanned the two.

### Fixes

- **An NTFS volume Windows formatted extracts whole.** BeeZip 0.2.0 took the empty files
  Windows keeps on every volume (such as `$Extend/$RmMetadata/$Repair`) for damaged, so testing
  reported them and extracting stopped there.
- **A cabinet or MSI with an LZX match that runs past its 32 KiB frame is damaged,** as the
  format and 7-Zip say. BeeZip 0.2.0 could decode such a file to the wrong bytes with no error.
  No real installer tested has one.

## 0.2.0

### Disks and installers without 7-Zip

- **BeeZip reads FAT, NTFS, ext2/3/4, HFS+ and APFS volumes, GPT and MBR disks, and MSI
  installers itself,** so they open without 7-Zip.
- **An MSI lists its files where they install,** such as
  `ProgramFiles64Folder/RustDesk/RustDesk.exe`, instead of the installer's internal keys. Its
  custom-action DLLs and icons are under `[Binary]` and `[Icon]`, and files it keeps outside
  itself are read from beside it.
- **A disk with several partitions** shows each one BeeZip reads as a folder (`0.data`), and the
  others as files to open in turn. A disk with 4 KiB sectors opens too, and a GPT disk whose
  header is damaged opens from its backup.
- **NTFS** lists hard links, alternate data streams (`file:stream`), compressed and sparse
  files, and symlinks and junctions as links. Sparse files that 7-Zip 26.00 can't extract come
  out right. Files BeeZip can't read, encrypted with EFS, compressed by Windows (CompactOS) or
  deduplicated, are skipped with the reason, and the rest extracts.
- **ext2/3/4** lists hard links, keeps names that aren't UTF-8 for Name encoding to read, keeps
  times to the nanosecond, and shows a volume that wasn't cleanly unmounted with its latest
  contents.
- **FAT** reads long names, and short ones in your system's OEM code page.
- **Cabinets and MSI installers decode about 40% faster,** with BeeZip's own LZX decoder. A
  large installer still takes two to three times as long to extract as with 7-Zip.
- **Info** shows a disk's levels (`gpt › ntfs`) and a volume's label and cluster size.
- **Still through 7-Zip:** WIM, CHM, NSIS and CramFS, the virtual disks VHD, VHDX, VMDK, QCOW2
  and VDI, MSI patches and merge modules, and a volume that uses something BeeZip doesn't read,
  which Info then says.

## 0.1.0

The first release. On Windows it comes as a portable copy, to unzip and run; the signed
installer, and with it Windows 11's own right-click menu, come with 1.0.0.

### Explorer's right-click menu

- **A BeeZip submenu on files and folders:** Open with BeeZip, Extract here, Extract to "a\",
  Extract to…, Test archive, Add to "a.zip", Add to "a.7z", Add to "a.tar.zst" and Compress to….
- **A small window for each job,** with its progress, and questions as they come up: a password,
  or what to do with a file that's already there.
- **When the archive you're making already exists,** add to it, replace it, keep both or skip.
- **Choose the items, and the submenu,** in Settings → Explorer menu, which also repairs and
  removes the menu.

### The desktop app

- **Tabs for archives,** each with a folder tree, the entries and a preview of text, hex or
  images. A million entries list without a pause; click a column to sort.
- **Drag the edges** between the tree, the entries and the preview, and the top of the jobs list,
  to resize them. BeeZip keeps the sizes; double-click an edge for the default.
- **Open archives every way you'd expect:** Open (Ctrl+O), dropping them on the window,
  double-clicking one, or launching BeeZip again, which opens it in the window already running.
- **Extract everything or just what you selected,** with the destination, what to do with files
  already there, and how many leading folders to drop.
- **New archives** as zip, 7z, tar and more, encrypted and split as you choose, from files you
  pick or drop on the window.
- **Add, delete and rename** inside zip, 7z, tar, cpio and ar archives.
- **Open a file from an archive** in its app; change it, come back, and BeeZip offers to put it
  back in the archive.
- **Drag entries out** onto Explorer or the desktop. They're extracted as you let go.
- **Test, Info, Convert, and Name encoding** for archives whose names came from another
  system's code page.
- **The jobs list** shows each job's progress, with Cancel, its log in full and its result. Copy
  puts a job's result and its whole log on the clipboard.
- **Every action is a Ctrl+K away,** and Copy as CLI copies the command that does the same.
- **Settings** save as you change them, into the same `config.toml` the command line reads.
- **Light and dark themes,** following Windows or chosen.
- **BeeZip tells you about new versions,** at most once a day. A portable copy links to the new
  zip.

### Formats

- **Reads and writes** zip, 7z, tar, cpio, ar, CAB, ISO, squashfs and DMG, and tar and cpio under
  any compressor (`.tar.gz`, `.tar.zst`, `.tgz`…).
- **Reads** RAR 1.5 to 7, Debian packages, RPMs, LHA, UDF, XAR and macOS packages, and the old DOS
  formats ARJ, ACE, ZOO and ARC.
- **With 7-Zip installed,** also reads WIM and ESD images, CHM files, MSI and NSIS installers,
  and disk images and their file systems: VHD, VHDX, VMDK, QCOW2, VDI, FAT, NTFS, ext, HFS+,
  APFS and more.
- **Installs 7-Zip for you** on Windows: where a file needs it, and in Settings, **Install 7-Zip**
  installs it with winget (or updates one older than 25.01), and the file opens when it's done.
  `beezip 7zip install` does the same.
- **Compresses single files** with gzip, bzip2, xz, zstd, lz4, Brotli and more.
- **Recognises a file by what's inside it,** not its name. Split archives open from any of their
  parts, and self-extracting ones open like any other.

### Safety

- **Extracting never writes outside the folder you chose.** Entries that try are skipped and
  listed.
- **Zip bombs are stopped** before they can fill a disk.
- **Downloaded archives keep Windows' warning:** extracted files carry the archive's Mark of the
  Web, as Explorer does.
- **Changes never rewrite an archive in place,** so a failed or cancelled change leaves it as it
  was.
- **Encryption is never dropped without asking.**

### The command line

- **`beezip`** lists, tests, extracts, creates, changes and converts archives, with the same
  settings and safety as the app.
- **JSON output** for scripts, a stream of progress events, and exit codes that say what went
  wrong.
- **`beezip bench`** compares the compressors on your own files.

### For AI assistants

- **`beezip mcp`** lets Claude and other MCP clients read and make archives, writing only in the
  folders you allow.
