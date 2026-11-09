# Third-party notices

BeeZip is licensed under MIT OR Apache-2.0, at your choice. It includes third-party code under other licenses, listed below with their texts: code taken into BeeZip's own source, then the Rust crates and the npm packages it is built with.

`cargo xtask notices` generates this file from Cargo.lock, through cargo-about and `about.toml`, and from the npm packages in the interface's bundle. Its hand-written parts are in `packaging/notices/`: edit those, not this file. It ships next to `BeeZip.exe` and on the About page.

**UnRAR.** BeeZip reads RAR archives with UnRAR 7.1.0 by Alexander Roshal, compiled into BeeZip through the `unrar_sys` crate (whose own bindings are MIT OR Apache-2.0). BeeZip only extracts RAR archives; it can't create them, and UnRAR's code is not used to do so. UnRAR's license is below, in full.

**MPL-2.0.** `cssparser`, `cssparser-macros`, `dtoa-short`, `option-ext` and `selectors` are under the Mozilla Public License 2.0. BeeZip uses them unmodified, as dependencies of Tauri. Their source code is available from crates.io (`https://crates.io/crates/<name>`), at the versions listed below.
