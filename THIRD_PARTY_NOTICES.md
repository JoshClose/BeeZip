# Third-party notices

BeeZip is licensed under MIT OR Apache-2.0. It depends on third-party crates and npm packages under their own licenses; `cargo deny check licenses` enforces the allowlist in `deny.toml`.

This file covers the components whose licenses ask for a notice, and ships with BeeZip: next to `BeeZip.exe` and on the About page. A generated list of every dependency with its license text replaces it before the first release (M6).

## MPL-2.0 components

These crates are used unmodified, as dependencies of Tauri. Their source is available from crates.io.

| Crate | Pulled in by |
|---|---|
| `option-ext` | `dirs-sys` ← `dirs` ← `tauri` |
| `cssparser`, `cssparser-macros`, `dtoa-short`, `selectors` | `dom_query` ← `tauri-utils` |

## Compression libraries under other permissive licenses

These crates are used unmodified by `beezip-core`. Their licenses are on the `deny.toml` allowlist but, unlike MIT and Apache-2.0, ask for their notice to be reproduced. The full license texts ship with the generated notices file in M6.

| Crate | License | What it is |
|---|---|---|
| `zstd`, `zstd-safe`, `zstd-sys` | BSD-3-Clause | the Zstandard library (bundled C source, © Meta Platforms) and its bindings |
| `brotli`, `brotli-decompressor`, `alloc-no-stdlib`, `alloc-stdlib` | BSD-3-Clause AND MIT | a Rust port of Google's Brotli |
| `snap` | BSD-3-Clause | Snappy |
| `libbz2-rs-sys` | bzip2-1.0.6 | a Rust port of libbzip2 (© Julian Seward) |
| `zlib-rs` | Zlib | a Rust port of zlib |
| `ppmd-rust` | CC0-1.0 OR MIT-0 | PPMd, used by zip's PPMd method |

## Name encodings

Names stored in legacy code pages are read with these crates (docs/M5.md §6).

| Crate | License | What it is |
|---|---|---|
| `encoding_rs` | (Apache-2.0 OR MIT) AND BSD-3-Clause | the WHATWG encodings (Shift-JIS, GBK, Big5, the Windows code pages…), © Mozilla Foundation. It includes data derived from the WHATWG Encoding Standard's data files, which are under the BSD 3-Clause License |
| `oem_cp` | MIT | the DOS code pages (437, 850, 852…) |

## 7z

| Crate | License | What it is |
|---|---|---|
| `sevenz-rust2` | Apache-2.0 | 7z reading and writing, a maintained fork of `sevenz-rust` |
| `cbc`, `block-padding` | MIT OR Apache-2.0 | AES-CBC for 7z's AES-256 |

## M5 formats

BeeZip reads and writes cpio, ar, CAB, Unix `.Z` and lzop, and reads Debian packages, RPMs and LHA, with its own code over these crates (docs/M5.md §5).

| Crate | License | What it is |
|---|---|---|
| `delharc` | MIT OR Apache-2.0 | LHA/LZH decoding (lh0–lh7, lhx, lz*, pm*) |
| `lzokay` | MIT | LZO1X blocks, for lzop: © Luke Street, a Rust port of Jack Andersen's lzokay |
| `lzxd` | MIT OR Apache-2.0 | LZX decoding, for CAB |
| `zerocopy`, `zerocopy-derive` | BSD-2-Clause OR Apache-2.0 OR MIT | used by `lzokay` |
| `bytemuck`, `bytemuck_derive` | Zlib OR Apache-2.0 OR MIT | used by `delharc` |
| `chrono` | MIT OR Apache-2.0 | dates in LHA headers, through `delharc` |

## Disk images

BeeZip reads and writes ISO 9660 (with Joliet and Rock Ridge), squashfs and DMG, and reads UDF, with these crates and its own code (docs/M5.md §5.9–§5.11). The squashfs reader and the DMG container (UDIF, ADC, LZVN, Apple's file compression) are BeeZip's.

| Crate | License | What it is |
|---|---|---|
| `hadris-iso` | MIT | ISO 9660, Joliet and Rock Ridge, © hxyulin. BeeZip builds a patched copy of 3.0.0-rc.3 (`vendor/hadris-iso`, its changes in `BEEZIP.md` there) |
| `hadris-udf`, `hadris-fs`, `hadris-io`, `hadris-storage`, `hadris-part`, `hadris-iso-raw`, `hadris-udf-raw`, `hadris-macros` | MIT | UDF, and the filesystem, I/O and storage layers both use, © hxyulin |
| `spin` | MIT | locks for `hadris-fs` |
| `backhand` | MIT OR Apache-2.0 | writing squashfs (BeeZip's own codecs compress for it) |
| `deku`, `deku_derive`, `darling`, `ident_case` | MIT OR Apache-2.0 (`darling`: MIT) | binary layouts, for `backhand` |
| `bitvec`, `funty`, `radium`, `tap`, `wyz` | MIT | bit fields, for `deku` |
| `solana-nohash-hasher` | Apache-2.0 OR MIT | a hasher for `backhand`'s tables |
| `xxhash-rust` | BSL-1.0 | xxHash, for `backhand` (the Boost Software License: an exception in `deny.toml`) |
| `fstool` | MIT | HFS+, HFSX and APFS volumes inside DMGs, and the HFS+ writer |
| `intl` | MIT | Unicode case folding and normalization, for `fstool`'s APFS names |
| `lzfse_rust` | MIT OR Apache-2.0 | LZFSE, for DMG chunks and Apple-compressed files |

## ARJ, ACE, ZOO, ARC, XAR and macOS packages

BeeZip reads these formats with its own code (docs/M6.md §4, §5). Its ARJ, ACE and ZOO readers began as the `arj`, `ace` and `zoo` modules of unarc-rs 0.8.1 (https://github.com/mkrueger/unarc-rs, MIT OR Apache-2.0, taken under MIT), rewritten into BeeZip's source; unarc-rs isn't a dependency. Its ACE module is itself a port of acefile 0.6 (https://github.com/droe/acefile, BSD-2-Clause), whose tables BeeZip's ACE cipher and decoder carry. The ARC and XAR readers are BeeZip's own.

| Crate | License | What it is |
|---|---|---|
| `quick-xml` | MIT | XAR's table of contents |
| `md-5`, `sha1` | MIT OR Apache-2.0 | XAR's MD5 and SHA-1 checksums |

unarc-rs's license, as BeeZip takes it:

```text
MIT License

Copyright (c) Mike Krüger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

acefile's license, in full:

```text
# License and copyright

## Copyright

Copyright (c) 2017-2026, Daniel Roethlisberger and contributors.
All rights reserved.
Licensed under the 2-clause BSD license contained herein.


## Contributions

By contributing to the software, the contributor releases their
contribution under the license and copyright terms herein.  While
contributors retain copyright to their contributions, they grant the
main copyright holder of the software the irrevocable, transferable
right to relicense the software as a whole or in part, including their
contributions, under different open source licenses than the one
contained herein.


## License

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


## Note

The ACE archive format and ACE compression and decompression
algorithms have been designed by Marcel Lemke.  The above copyright
notice and license does not constitute a claim of intellectual property
over ACE technology beyond the copyright of this python implementation.
```

## UnRAR

BeeZip reads RAR archives with UnRAR 7.1.0 by Alexander Roshal, compiled into BeeZip through the `unrar_sys` crate (whose own bindings are MIT OR Apache-2.0). BeeZip only extracts RAR archives; it can't create them, and UnRAR's code is not used to do so. The UnRAR source BeeZip builds is the copy `unrar_sys` 0.5.8 vendors, which carries that crate's patches. Its license, in full:

```text
 ******    *****   ******   UnRAR - free utility for RAR archives
 **   **  **   **  **   **  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ******   *******  ******    License for use and distribution of
 **   **  **   **  **   **   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 **   **  **   **  **   **         FREE portable version
                                   ~~~~~~~~~~~~~~~~~~~~~

      The source code of UnRAR utility is freeware. This means:

   1. All copyrights to RAR and the utility UnRAR are exclusively
      owned by the author - Alexander Roshal.

   2. UnRAR source code may be used in any software to handle
      RAR archives without limitations free of charge, but cannot be
      used to develop RAR (WinRAR) compatible archiver and to
      re-create RAR compression algorithm, which is proprietary.
      Distribution of modified UnRAR source code in separate form
      or as a part of other software is permitted, provided that
      full text of this paragraph, starting from "UnRAR source code"
      words, is included in license, or in documentation if license
      is not available, and in source code comments of resulting package.

   3. The UnRAR utility may be freely distributed. It is allowed
      to distribute UnRAR inside of other software packages.

   4. THE RAR ARCHIVER AND THE UnRAR UTILITY ARE DISTRIBUTED "AS IS".
      NO WARRANTY OF ANY KIND IS EXPRESSED OR IMPLIED.  YOU USE AT 
      YOUR OWN RISK. THE AUTHOR WILL NOT BE LIABLE FOR DATA LOSS, 
      DAMAGES, LOSS OF PROFITS OR ANY OTHER KIND OF LOSS WHILE USING
      OR MISUSING THIS SOFTWARE.

   5. Installing and using the UnRAR utility signifies acceptance of
      these terms and conditions of the license.

   6. If you don't agree with terms of the license you must remove
      UnRAR files from your storage devices and cease to use the
      utility.

      Thank you for your interest in RAR and UnRAR.


                                            Alexander L. Roshal
```
