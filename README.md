# BeeZip

A Windows archive manager with a desktop app, a command-line tool (`beezip`) and an MCP server, all driven by one Rust command engine.

> **Status:** early scaffold (milestone M0). It does not compress anything yet. See [`docs/PLAN.md`](docs/PLAN.md) for the architecture and roadmap, and [`docs/M0.md`](docs/M0.md) for the current milestone.

## Building

Prerequisites: Rust (the pinned toolchain in `rust-toolchain.toml` installs automatically), Node 24 and pnpm (`corepack enable pnpm`), and the [Tauri prerequisites for Windows](https://tauri.app/start/prerequisites/) (WebView2 and the MSVC build tools).

```powershell
cargo build --workspace
cargo test --workspace
.\target\debug\beezip.exe --help

cd apps\desktop
pnpm install
pnpm tauri dev
```

After changing a command's input or output types, regenerate the TypeScript bindings with `cargo xtask codegen`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
