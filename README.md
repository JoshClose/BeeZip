# BeeZip

A Windows archive manager with a desktop app, a command-line tool (`beezip`) and an MCP server, all driven by one Rust command engine.

> **Status:** milestone M2: the engine, the command line and the MCP server work; the desktop app is still a shell. See [`docs/PLAN.md`](docs/PLAN.md) for the architecture and roadmap, and [`docs/M2.md`](docs/M2.md) for the current milestone.

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

## Command line

`beezip` reads ZIP and TAR, `tar` under any codec (`.tar.gz`, `.tar.zst`, `.tgz`…), and bare compressed files (`.gz`, `.bz2`, `.xz`, `.lzma`, `.lz`, `.zst`, `.lz4`, `.br`, `.sz`, `.zz`). It detects formats by content, not by extension.

```powershell
beezip formats                        # what BeeZip reads and writes, with levels and threading
beezip detect download.bin            # zstd → tar, a zip SFX, or "not an archive (Portable Executable)"
beezip info backup.tar.zst            # entries, sizes, ratio, methods, encryption
beezip list backup.zip                # one folder level; --flat for everything, --glob "*.md" to filter
beezip read backup.zip docs/a.md      # print part of an entry (--encoding hex|base64, --offset, --max-bytes)
beezip test backup.zip                # read everything back and check CRCs; exit 8 if damaged

beezip x backup.zip -o out            # extract (default: the current directory)
beezip x backup.zip docs --smart      # just docs/; into a folder named after the archive if needed
beezip x backup.zip --overwrite rename --dry-run

beezip create backup.tar.zst src -l 19          # format from the extension
beezip c secret.zip src -p "pass phrase"         # AES-256; --encryption zipcrypto for old tools
beezip c logs.zip logs -m ppmd --exclude "*.tmp"

beezip compress big.log -c xz -l 9    # big.log.xz, keeping big.log
beezip decompress backup.tar.zst      # backup.tar: one codec layer per call
```

- **Safety:** extraction never writes outside the destination. Paths with `..`, and links leading out, are skipped. The rest is extracted, then the command fails with exit code 14. Absolute paths, drive letters, reserved names such as `CON` and characters Windows can't store are rewritten, and reported. Symlinks are off by default (`--links` turns them on); hard links are extracted as copies. Zip bombs hit a 10 000:1 ratio limit.
- **Prompts:** in a terminal, BeeZip asks for passwords and what to do with existing files. Without one, it fails and says which flag to pass (`--password`, `--overwrite`).
- **Output:** `--output json` prints one JSON document, `--output ndjson` streams every job event (progress included), and `-q` hides progress bars. Ctrl+C cancels and removes the partly written file.
- **Every command is also reachable generically:** `beezip commands` lists them, `beezip schema archive.extract` prints the JSON schemas, and `beezip run archive.list --json '{"archive":"a.zip"}'` runs one with JSON arguments, as the desktop app and the MCP server do.
- **Exit codes:** 0 OK, 2 invalid arguments, 3 not found, 4 unsupported format, 6 password required, 7 wrong password, 8 corrupt, 10 conflict (the file exists), 11 limit exceeded, 13 I/O error, 14 unsafe entries skipped, 130 cancelled.

### Configuration

`%APPDATA%\BeeZip\config.toml` (or the file `BEEZIP_CONFIG` names) sets the defaults; the arguments above override them.

```toml
[extract]
overwrite = "ask"          # ask | always | never | rename | newer
links = false
mark_of_the_web = "all"    # copy the archive's Zone.Identifier to extracted files, as Explorer does

[create]
threads = 0                # 0 = one per core

[levels]                   # per codec and zip method
zstd = 3
deflate = 6

[stream]
codec = "zstd"             # for `beezip compress`

[limits]
max_ratio = 10000
max_entries = 10000000
decoder_memory_mib = 1024

[mcp]                      # `beezip mcp`; --root and --read-only override these
roots = ['C:\Users\you\Unpacked']
read_only = false
```

## MCP server

`beezip mcp` serves the same commands as MCP tools over stdin/stdout, so an assistant such as Claude can list, test, read, extract and create archives. Commands that write may only write under the `--root` directories; reads aren't confined.

```powershell
claude mcp add beezip -- C:\path\to\beezip.exe mcp --root C:\Users\you\Unpacked
```

- **Overwrites:** BeeZip asks the user about existing files through the client, where the client supports it.
- **Passwords:** it never asks for them over MCP; the assistant passes them.
- **Limits:** a list page holds at most 500 entries, and a read returns at most 256 KiB.

[`docs/MCP.md`](docs/MCP.md) covers Claude Desktop, the MCP Inspector, every tool, and the sandbox rules.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
