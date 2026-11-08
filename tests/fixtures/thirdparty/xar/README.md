# XAR fixtures

Made by `tests/fixtures/make-xar.sh` (docs/M6.md §10), in Docker (make-xar.Dockerfile) and with
Windows' own tar.exe, which also writes this file and the records in `manifest.json`; a rerun writes
the same bytes.

The tree: `readme.txt`, `empty.txt`, `text.txt`, `random.bin` (4 KiB of Python's Random(42)),
`mtime.txt`, `exec.sh` (0755), `sub/nested/deep.txt`, the empty folder `emptydir`,
`Ünïcödé/日本語.txt`, `bee-🐝.txt` and `café.txt` (both tools store the CJK and emoji names in
base64, the others as they are), the symlinks
`link-to-readme`, `dangling` (to `does/not/exist`) and `sub/link-to-nested` (to a folder), and
`hard-readme.txt`, a hard link to `readme.txt`; every time 2026-01-01T00:00:00Z but mtime.txt's,
2024-05-06T07:08:09Z. tar.exe's XARs hold the ASCII-only files and the hard link: bsdtar 3.8.9 for
Windows crashes on any other name, and Windows makes symlinks only in Developer Mode.

xar and bsdtar ran under a frozen clock and an LD_PRELOAD shim giving every stat() one device
number and change time; tar.exe's TOCs have their creation, change and access times and inode
numbers fixed afterwards. Between them the files cover every compression (none, gzip as x-gzip
and as RFC 6713's zlib, bzip2, xz, and lzma in both xar's xz-format and libarchive's .lzma-format
flavours) and every checksum (none, MD5, SHA-1, SHA-256 and SHA-512, the last two in xar's
64-byte header). 7-Zip 26.00 reads XAR but not x-xz or x-lzma, shows base64 names undecoded,
extracts xar's hard links empty and calls a SHA-512 TOC a CRC error: each record's note says which
files it gets wrong.

| File | Size | Made by | Command |
|---|---|---|---|
| `bsdtar-gzip-sha1.xar` | 6.1 KiB | bsdtar 3.7.2 (Ubuntu 24.04's libarchive-tools, in Docker) | `bsdtar -c -f bsdtar-gzip-sha1.xar --format xar .` |
| `bsdtar-lzma-md5.xar` | 6.0 KiB | bsdtar 3.7.2 (Ubuntu 24.04's libarchive-tools, in Docker) | `bsdtar -c -f bsdtar-lzma-md5.xar --format xar --options xar:compression=lzma,xar:checksum=md5,xar:toc-checksum=md5 .` |
| `bsdtar-none-md5.xar` | 9.1 KiB | bsdtar 3.7.2 (Ubuntu 24.04's libarchive-tools, in Docker) | `bsdtar -c -f bsdtar-none-md5.xar --format xar --options xar:compression=none,xar:checksum=md5,xar:toc-checksum=md5 .` |
| `bsdtar-xz-none.xar` | 5.8 KiB | bsdtar 3.7.2 (Ubuntu 24.04's libarchive-tools, in Docker) | `bsdtar -c -f bsdtar-xz-none.xar --format xar --options xar:compression=xz,xar:checksum=none,xar:toc-checksum=none .` |
| `xar-bzip2-md5.xar` | 6.6 KiB | xar 1.6.1 (mackyle/xar 66d451d, built in Docker on Ubuntu 24.04) | `xar -c -f xar-bzip2-md5.xar --compression=bzip2 --toc-cksum=md5 --file-cksum=md5 .` |
| `xar-gzip-none.xar` | 5.5 KiB | xar 1.6.1 (mackyle/xar 66d451d, built in Docker on Ubuntu 24.04) | `xar -c -f xar-gzip-none.xar --compression=gzip --toc-cksum=none --file-cksum=none .` |
| `xar-gzip-sha256.xar` | 6.4 KiB | xar 1.6.1 (mackyle/xar 66d451d, built in Docker on Ubuntu 24.04) | `xar -c -f xar-gzip-sha256.xar --compression=gzip --toc-cksum=sha256 --file-cksum=sha256 .` |
| `xar-lzma-sha512.xar` | 7.2 KiB | xar 1.6.1 (mackyle/xar 66d451d, built in Docker on Ubuntu 24.04) | `xar -c -f xar-lzma-sha512.xar --compression=lzma --toc-cksum=sha512 --file-cksum=sha512 .` |
| `xar-none-sha1.xar` | 9.1 KiB | xar 1.6.1 (mackyle/xar 66d451d, built in Docker on Ubuntu 24.04) | `xar -c -f xar-none-sha1.xar --compression=none .` |
| `xar-xz-sha1.xar` | 6.4 KiB | xar 1.6.1 (mackyle/xar 66d451d, built in Docker on Ubuntu 24.04) | `xar -c -f xar-xz-sha1.xar --compression=xz .` |
| `tarexe-gzip-sha1.xar` | 5.4 KiB | bsdtar 3.8.9 (Windows' tar.exe) | `tar.exe -c -f tarexe-gzip-sha1.xar --format xar -C tree .` |
| `tarexe-bzip2-md5.xar` | 5.8 KiB | bsdtar 3.8.9 (Windows' tar.exe) | `tar.exe -c -f tarexe-bzip2-md5.xar --format xar --options xar:compression=bzip2,xar:checksum=md5,xar:toc-checksum=md5 -C tree .` |
