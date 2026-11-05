# BeeZip

A Windows archive manager with a desktop app, a command-line tool (`beezip`) and an MCP server, all driven by one Rust command engine.

> **Status:** milestone M3: the engine, the command line, the MCP server and the desktop app read and write zip, 7z and tar and read RAR. See [`docs/PLAN.md`](docs/PLAN.md) for the architecture and roadmap, and [`docs/M3.md`](docs/M3.md) for the current milestone.

## Building

Prerequisites: Rust (the pinned toolchain in `rust-toolchain.toml` installs automatically), Node 24 and pnpm (`corepack enable pnpm`), and the [Tauri prerequisites for Windows](https://tauri.app/start/prerequisites/) (WebView2 and the MSVC build tools).

```powershell
cargo build --workspace
cargo test --workspace
.\target\debug\beezip.exe --help

cd apps\desktop
pnpm install
pnpm test           # the frontend's tests (vitest)
pnpm tauri dev      # the desktop app, reloading as you edit
```

- **Bindings:** after changing a command's input or output types, regenerate the TypeScript bindings with `cargo xtask codegen`.
- **Installer:** `cargo xtask dist` builds it (`target\dist\release\bundle\nsis\BeeZip_<version>_x64-setup.exe`); `--debug` is quicker.
- **A big test archive:** `cargo xtask bigzip` writes a zip of a million entries, for trying the browser.

## Desktop app

`BeeZip.exe` opens archives in tabs: a folder tree, the entries (a million is fine; click a column to sort), and a preview of text, hex or images.

- **Opening:** Open (Ctrl+O), drag an archive onto the window, or double-click one once BeeZip is installed. Launching BeeZip again opens the archive in the running window.
- **Extract** (Ctrl+E) everything or the selected entries. **New archive** (Ctrl+N) packs files and folders, or files dropped on the window, as zip, 7z or tar, encrypted and split as you choose. **Test** checks every CRC.
- **Progress:** the jobs panel shows each job's progress, with Cancel, its log and its result. Cancelling removes any partly written files.
- **Passwords and overwrites** are asked as they come up. A password stays in memory for its tab, until you close it, and is never saved.
- **Commands:** Ctrl+K lists every action and every BeeZip command; a command without a dialog of its own gets a form.
- **Copy as CLI**, on every dialog, copies the `beezip` command that does the same, without the password.
- **Settings** (Ctrl+,, or from the welcome screen) change `config.toml` as you go, and the next job uses them. Each is saved as you change it, keeping the file's comments; a value BeeZip can't take shows its error beside the field and isn't saved.
- **Theme:** System (Windows' light or dark mode), Light or Dark, in Settings or from Ctrl+K ("Theme: Dark"). Every window switches at once.

**The installer** works per user, with no admin rights:
- **Files:** it puts `BeeZip.exe` in `%LOCALAPPDATA%\BeeZip`, and adds its `bin` folder (holding `beezip.exe`) to your PATH.
- **File types:** it registers BeeZip for zip, 7z, rar, tar and the compressed and split formats, but not for zip-based documents such as `.docx` or `.jar`. Windows asks which app to use the first time you open each kind of file, with BeeZip offered. An app you've already chosen for a type (Windows sets Explorer's zip folder for `.zip` on many machines) stays until you pick BeeZip under *Open with → Choose another app*.
- **Uninstalling** removes the PATH entry and the registrations, and leaves your file types as they were.

## Command line

`beezip` reads and writes ZIP, 7z and TAR, `tar` under any codec (`.tar.gz`, `.tar.zst`, `.tgz`…), and bare compressed files (`.gz`, `.bz2`, `.xz`, `.lzma`, `.lz`, `.zst`, `.lz4`, `.br`, `.sz`, `.zz`). It reads RAR 1.5–7, through UnRAR, but never writes it. Split archives (`a.7z.001`, `a.zip.001`, `a.part1.rar`, `a.rar` with `a.r00`…) open from any part, and self-extracting 7z, RAR and zip executables open like archives. It detects formats by content, not by extension.

```powershell
beezip formats                        # what BeeZip reads and writes, with levels and threading
beezip detect download.bin            # zstd → tar, a zip SFX, or "not an archive (Portable Executable)"
beezip info backup.tar.zst            # entries, sizes, ratio, methods, encryption
beezip list backup.zip                # one folder level; --flat for everything, --glob "*.md" to filter
beezip list photos.rar --sort size --reverse --kind file
beezip read backup.zip docs/a.md      # print part of an entry (--encoding hex|base64, --offset, --max-bytes)
beezip test backup.zip                # read everything back and check CRCs; exit 8 if damaged

beezip x backup.zip -o out            # extract (default: the current directory)
beezip x backup.zip docs --smart      # just docs/; into a folder named after the archive if needed
beezip x backup.zip --overwrite rename --dry-run

beezip create backup.tar.zst src -l 19          # format from the extension
beezip c secret.zip src -p "pass phrase"         # AES-256; --encryption zipcrypto for old tools
beezip c logs.zip logs -m ppmd --exclude "*.tmp"
beezip c backup.7z src -p "pass phrase"          # LZMA2, solid; the names are encrypted too
beezip c big.7z videos -v 4g --solid=false       # big.7z.001, big.7z.002…; -m lzma|ppmd|bzip2|deflate|copy
beezip x big.7z.002 -o out                       # any part opens the whole set

beezip compress big.log -c xz -l 9    # big.log.xz, keeping big.log
beezip decompress backup.tar.zst      # backup.tar: one codec layer per call
```

- **Safety:** extraction never writes outside the destination. Paths with `..`, and links leading out, are skipped. The rest is extracted, then the command fails with exit code 14. Absolute paths, drive letters, reserved names such as `CON` and characters Windows can't store are rewritten, and reported. Symlinks are off by default (`--links` turns them on); hard links are extracted as copies. Zip bombs hit a 10 000:1 ratio limit.
- **Prompts:** in a terminal, BeeZip asks for passwords and what to do with existing files. Without one, it fails and says which flag to pass (`--password`, `--overwrite`).
- **Output:** `--output json` prints one JSON document, `--output ndjson` streams every job event (progress included), and `-q` hides progress bars. Ctrl+C cancels and removes the partly written file; a second Ctrl+C exits at once, and still removes it.
- **7z and RAR passwords:** 7z and RAR 1.5–4 have no password check, so a wrong password shows as damaged data; BeeZip asks again, up to three times. A RAR whose entries have different passwords asks for each.
- **Volumes:** `-v/--volume-size` takes bytes or `100m`, `4g`, `700MB` (powers of 1024) and works for every format. Spanned zips (`.z01`) aren't supported.
- **Every command is also reachable generically:** `beezip commands` lists them, `beezip schema archive.extract` prints the JSON schemas, and `beezip run archive.list --json '{"archive":"a.zip"}'` runs one with JSON arguments, as the desktop app and the MCP server do.
- **Exit codes:** 0 OK, 2 invalid arguments, 3 not found, 4 unsupported format, 6 password required, 7 wrong password, 8 corrupt, 10 conflict (the file exists), 11 limit exceeded, 13 I/O error, 14 unsafe entries skipped, 130 cancelled.

### Configuration

`%APPDATA%\BeeZip\config.toml` (or the file `BEEZIP_CONFIG` names) sets the defaults; the arguments above override them. `beezip settings get` lists every setting with its value, and `beezip settings set` changes them in place, keeping the file's comments and refusing a key or value BeeZip doesn't take (nothing is written then):

```powershell
beezip settings get
beezip settings set extract.overwrite=rename levels.zstd=19     # VALUE is TOML; a bare word is a string
beezip settings set "mcp.roots=['C:\Users\you\Unpacked']" --reset limits.max_ratio
```

```toml
[extract]
overwrite = "ask"          # ask | always | never | rename | newer
links = false
mark_of_the_web = "all"    # copy the archive's Zone.Identifier to extracted files, as Explorer does

[create]
threads = 0                # 0 = one per core

[levels]                   # per codec, zip method and 7z method
zstd = 3
deflate = 6
lzma2 = 5

[stream]
codec = "zstd"             # for `beezip compress`

[limits]
max_ratio = 10000
max_entries = 10000000
decoder_memory_mib = 1024

[mcp]                      # `beezip mcp`; --root and --read-only override these
roots = ['C:\Users\you\Unpacked']
read_only = false

[desktop]
theme = "system"           # system | light | dark

[shell]                    # Explorer's right-click menu, which comes later in M4
cascade = true             # classic menu: false puts each item at the top level
[shell.items]              # every item shows unless set to false: open, extract-here,
test = false               # extract-folder, extract-to, test, add-zip, add-7z, add-tar-zst, compress-to

[jobs]
close_when_done = true     # a job window from Explorer closes after a clean success
```

The settings are hidden from MCP clients: one that could change `[mcp] roots` could widen its own sandbox.

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

BeeZip reads RAR archives with UnRAR by Alexander Roshal, which has its own license: it may be used to extract RAR archives, not to create them. Its text, and the other notices BeeZip ships, are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
