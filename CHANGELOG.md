# Changelog

What's new in each version of BeeZip, for the people who use it. Each release's notes on GitHub
come from its section here; the website's Releases page shows them all.

Write a new section as `## X.Y.Z`, with `###` groups and `- ` items, describing what someone
using BeeZip will notice. Leave the date out: the Releases page dates each version by its
`vX.Y.Z` tag.

## 0.3.0

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
