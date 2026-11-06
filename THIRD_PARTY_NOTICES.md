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
