# Third-party notices

BeeZip is licensed under MIT OR Apache-2.0. It depends on third-party crates and npm packages under their own licenses; `cargo deny check licenses` enforces the allowlist in `deny.toml`.

This file is a placeholder. A generated list of every dependency with its license text replaces it before the first release (M3).

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
