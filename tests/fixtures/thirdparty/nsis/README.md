# NSIS fixtures

Made by `tests/fixtures/make-nsis.sh` (docs/M10.md §8) with makensis 3.09: one script built
seven ways. It puts files under `$INSTDIR`, a subfolder, `$INSTDIR\$0`, `$PLUGINSDIR`, `$SYSDIR`,
`$APPDATA\BeeZip` and `$TEMP`; renames one (`/oname`); stores one twice; writes an empty file
(`FileOpen` and `FileClose`); calls a plugin (nsExec); and writes its uninstaller.

| File | Strings | Compressor | Solid |
|---|---|---|---|
| `u-zlib.exe` | Unicode | zlib | no |
| `u-bzip2-solid.exe` | Unicode | bzip2 | yes |
| `u-lzma-solid.exe` | Unicode | LZMA | yes |
| `a-bzip2.exe` | ANSI | bzip2 | no |
| `a-zlib-solid.exe` | ANSI | zlib | yes |
| `x64-lzma.exe` | Unicode, 64-bit | LZMA | no |
| `u-nocrc.exe` | Unicode, `CRCCheck off` | LZMA | yes |

Their records in `manifest.json` list what 7-Zip 26.00 extracts from each, checked by the script
against the tree it installs. BeeZip reads every one itself.
