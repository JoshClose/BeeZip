# Third-party notices

BeeZip is licensed under MIT OR Apache-2.0. It depends on third-party crates and npm packages under their own licenses; `cargo deny check licenses` enforces the allowlist in `deny.toml`.

This file is a placeholder. A generated list of every dependency with its license text replaces it before the first release (M3).

## MPL-2.0 components

These crates are used unmodified, as dependencies of Tauri. Their source is available from crates.io.

| Crate | Pulled in by |
|---|---|
| `option-ext` | `dirs-sys` ← `dirs` ← `tauri` |
| `cssparser`, `cssparser-macros`, `dtoa-short`, `selectors` | `dom_query` ← `tauri-utils` |
