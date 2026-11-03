# BeeZip — Implementation Plan

## Context
BeeZip is a Windows-first desktop archive manager (Tauri 2 + React) that opens, reads and writes the mainstream compression formats and reaches the long tail through optional backends. It must also run fully headless. The CLI and the MCP server are **not** extra features bolted on: the GUI, the CLI and MCP are three thin front ends over one **command engine**, so all three always offer the same features.

`C:\Users\narsh\Projects\CompressionUI` was empty when this plan was written, so there was nothing to reuse. Available toolchain: rustc/cargo 1.99.1 and Node 24. pnpm is missing. Node is installed under `C:\Program Files\nodejs`, which non-admin users can't write to, so run `corepack enable pnpm` once from an elevated terminal (or use `corepack enable pnpm --install-directory <dir on PATH>`). The pnpm version is pinned by `packageManager` in `apps/desktop/package.json`, which CI's `pnpm/action-setup` also reads. Node 25+ no longer ships corepack.

**Decisions taken from your answers:**
- **Formats:** native Rust crates for the mainstream formats, with optional backends for the long tail.
- **Platform:** Windows first.
- **License:** MIT/Apache-2.0, so no GPL dependencies. UnRAR is allowed for extraction only, with its license notice shipped.
- **MCP:** full command set by default, but writes are sandboxed to configured roots.
- **Name:** **BeeZip**.
- **Own archive format:** none in v1. `.bhive` is reserved for a possible future one; see §6.

### Naming
| Thing | Name |
|---|---|
| Product / window title | BeeZip |
| Rust crates | `beezip-core`, `beezip-commands`, `beezip-mcp`, `beezip-cli`, `beezip-shell`, `beezip-desktop` (Tauri) |
| CLI binary | `beezip.exe`, installed to `<installdir>\bin\` and added to PATH. Optional later: a short alias `bzx` as a tiny forwarding shim in `bin\`. **Avoid** these names: `bz` (Bandizip's CLI, which has the same `x`/`c`/`t`/`l` subcommands), `bzr` (Bazaar), `bzz` (DjVuLibre) and `bzp` (appears as a malware filename) |
| GUI binary | `BeeZip.exe` at `<installdir>\` (installed name; the Cargo bin is `beezip-desktop`, see below) |
| MCP server | `beezip mcp` (server name `beezip`) |
| Tauri identifier | `app.beezip.desktop` |
| Config | `%APPDATA%\BeeZip\config.toml` |
| Explorer menu | "BeeZip ▸", registry verb key `BeeZip`, `beezip_shell_<ver>.dll`, `beezip-sparse.msix` |

- **Why two folders:** Windows file names are case-insensitive, so `BeeZip.exe` and `beezip.exe` can't share a folder. The CLI therefore lives in `bin\`, which is the only folder added to PATH.
- **The same clash exists in `target/`.** Tauri 2 names the GUI binary after the Cargo bin (`beezip-desktop.exe`), not after `productName`. The only override is `mainBinaryName`, which `tauri build` applies as an `fs::rename` inside `target/<profile>/`. That folder also holds the CLI's `beezip.exe`. On NTFS the rename replaces the CLI, and a later `cargo build -p beezip-cli` overwrites the GUI. So:
  - `mainBinaryName` stays unset during development.
  - Packaging (M3) builds the installer's CLI with its own `--target-dir` and stages it as `bin\beezip.exe` through `bundle.resources`. Only then does it set `mainBinaryName = "BeeZip"`.
  - An `xtask dist` runs these steps in order.
- **Domains:** beezip.app and beezip.dev were unregistered as of 2026-11-01. beezip.com has been registered since 2000 and appears parked.

---

## 1. Architecture

```
            ┌──────────── apps/desktop (Tauri 2.12 + React) ───────────┐
            │  invoke("cmd_run",{name,args}) + Channel<JobEvent>        │
            └──────────────────────────┬───────────────────────────────┘
 beezip CLI (clap) ─ run / subcmds ────┤
 beezip mcp (rmcp 3.8, stdio | http) ──┤
                                       ▼
                   beezip-commands: Registry · Engine · Jobs · Policy
                                       ▼
          beezip-core: Detect · Codecs · ArchiveFormats · Backends · SafeFs
               native crates │ 7-Zip external (opt) │ libarchive (opt feature)
```

### Workspace layout
```
Cargo.toml                    # workspace; exact-pinned versions for churny crates
rust-toolchain.toml           # 1.99.1 (exact; "1.99" makes rustup fetch a second toolchain)
deny.toml                     # cargo-deny license allowlist
crates/beezip-core/           # format engine (sync Read/Write/Seek; no tokio)
  src/{detect,codec/*,format/*,backend/*,safefs,volume,progress,error}.rs
crates/beezip-commands/       # Command trait, registry, engine, jobs, policy, config
  src/commands/*.rs           # one file per command
crates/beezip-mcp/            # rmcp ServerHandler built dynamically from the registry
crates/beezip-cli/            # bin `beezip`; `beezip mcp` subcommand runs beezip-mcp
crates/beezip-shell/          # Windows-only cdylib: IExplorerCommand COM handler (Win11 + classic menus)
packaging/windows/            # sparse-package AppxManifest.xml, NSIS hooks, icons, dev-cert script
apps/desktop/src-tauri/       # Tauri app (beezip-desktop); depends on beezip-commands only
apps/desktop/src/             # React 19 + TS + Vite
xtask/                        # codegen (TS types, schemas, docs), fixture generation
tests/fixtures/               # reference archives + manifest.json (entries + hashes)
```

### Core abstractions (`beezip-core`)
- **`Codec`** (single-stream formats: gzip, bz2, xz, zstd and so on): `sniff(head)`, `caps()`, `decoder(Box<dyn Read>)`, `encoder(Box<dyn Write>, EncodeOpts)`.
- **`ArchiveFormat`**: `sniff(&Probe) -> Confidence`, `caps() -> FormatCaps`, `open(Source) -> Box<dyn ArchiveReader>`, `create(Sink) -> Box<dyn ArchiveWriter>`.
  - `FormatCaps` flags: list, extract, create, append, delete, rename, encrypt, encrypt_headers, solid, volumes, random_access.
- **`ArchiveReader`**:
  - `entries()` returns the cached index.
  - `extract(&Selection, &mut dyn EntrySink, &Ctx)` streams entries in archive order, which keeps solid archives fast.
  - `open_entry(id) -> Read`.
- **`ArchiveWriter`**:
  - `add(meta, Read, &Ctx)`.
  - `add_raw_from(reader, id) -> bool`, which copies an entry without recompressing it (zip `raw_copy_file`).
  - `finish()`.
- **`Backend`** groups formats: `Native`, `SevenZipCli` and `Libarchive`. The registry picks a backend for each format and operation using capabilities and priority.
- **No serialization in core:** core doesn't depend on serde, schemars or ts-rs. `beezip-commands` owns every wire type and converts, so core types can change without changing the API the front ends see.
- **`Source`** is one of:
  - a file (Read+Seek);
  - a `VolumeSet` (`.001…`, `.7z.001`, `.partN.rar`), which concatenates its parts behind Read+Seek;
  - a decoded stream. When a format needs Seek, as `zip.gz` does, the stream is spooled to a temp file.
- **Detection:**
  1. BeeZip's own sniffers, one per format and codec: magic bytes plus a structural check where there is one, such as the tar header checksum;
  2. compound probing: decode the first 64 KiB of a stream codec and re-probe it, so `tar.zst` is recognised;
  3. a scan for SFX signatures in PE overlays;
  4. extension as a tie-breaker.

  The `file-format` crate only labels files that aren't archives (for example "Portable Network Graphics"). It has no brotli or LZMA-alone signature, and it reports DOCX, JAR and EPUB as their own formats, while BeeZip opens them as ZIP.
- **`SafeFs` / `FsSink`** is the only code that writes extracted files to disk, whatever the backend. The full rules are in [`docs/M1.md`](M1.md) §3.5. It handles:
  - **Rewritten paths** (extraction continues, and the rewrite is reported): absolute, drive and UNC prefixes are stripped; `<>:"|?*` and control characters become `_` (which also blocks ADS `:`); trailing dots and spaces become `_`; Windows device names (CON, NUL, COM1…) get a `_` prefix.
  - **Refused entries** (skipped, then the job fails with `Unsafe`): any `..` component (zip-slip), and any parent that leads outside the destination through a symlink or junction. Each existing directory level is canonicalised and checked before anything is created inside it.
  - **Long paths:** Rust's std already turns long absolute paths into `\\?\` form on Windows, so SafeFs adds no prefixes itself.
  - **Name collisions:** case-insensitive clashes.
  - **Links:** symlinks are off by default. When on, a symlink is allowed only inside the destination and is created after every other entry. Hardlinks are always extracted as copies.
  - **Policies:** overwrite (ask/always/never/rename/newer).
  - **Bomb limits:** compression ratio, total bytes, entry count, nesting depth and decoder memory, counted on bytes actually written.
  - **Atomic writes:** `.partial` + rename, with cleanup on cancel.
  - **Metadata:** timestamps and attributes are kept (`filetime`).
  - **Mark of the Web:** on Windows, the archive's `Zone.Identifier` stream is copied to every extracted file, as Explorer does, so SmartScreen and Office Protected View still apply. It is on by default, and config can turn it off.
  - **Filename encoding:** zip CP437 vs UTF-8, with a codepage override (`encoding_rs`/`oem_cp`).
- **Progress** comes from a `CountingReader` on the compressed input, so it is reliable, and is throttled to about 10 Hz. **Cancellation** is a shared `CancelToken` that is checked between buffers.
- **Threading:** core is synchronous. The engine runs each job on its own thread rather than a worker pool, because jobs are few and long-running. Parallelism inside a job comes from the codecs (zstdmt, xz MT, and in M6 the zip rayon writer and parallel extraction of non-solid zips).

### Command engine (`beezip-commands`): the single source of truth
```rust
pub trait Command: Send + Sync + 'static {
    const NAME: &'static str;        // "archive.extract"
    const EFFECT: Effect;            // ReadOnly | Writes | Destructive | System  (→ MCP hints, sandbox, UI confirms)
    const SURFACES: Surfaces = Surfaces::ALL;  // front ends that expose it (entry.open, shell.* are hidden from MCP)
    const CLI: Option<CliSpec> = None;         // generated subcommand name + aliases, e.g. "extract" / ["x"]
    type Input:  Serialize + DeserializeOwned + JsonSchema + clap::Args + ts_rs::TS; // ONE struct for all front ends
    type Output: Serialize + DeserializeOwned + JsonSchema + ts_rs::TS;
    fn run(input: Self::Input, cx: &mut JobCtx) -> Result<Self::Output, CmdError>;
    fn human(output: &Self::Output) -> Option<String> { None }  // CLI `--output human`; None = pretty JSON
    fn access(input: &Self::Input) -> Vec<Access> { Vec::new() } // paths read/written, checked against Policy before run
}
```
- **Registry:** a `Registry` holds type-erased entries (`name`, doc, effect, input/output JSON schema from schemars 1.x, `run(Value) -> Value`). Doc comments on the Input struct become the clap help, the MCP tool description and the TS docs. The registry reads the doc once, from the schemars `description`, and passes it to all three.
- **Engine:** `Engine::invoke(name, args, Interactor) -> JobHandle`. The handle has an id, an event stream, `cancel()` and `result()`. Jobs are listed and can be cancelled. Each job's `run` is wrapped in `catch_unwind`, so a panic in a decoder becomes `CmdError::Internal` instead of taking down the GUI or the MCP server. This is why every profile keeps `panic = "unwind"`, including the release profile the Tauri template sets to `abort`.
- **`JobEvent`:** `Started | Progress{bytes_done,bytes_total,entries_done,entries_total,current} | Log | Prompt{id, Password|Overwrite{..}} | Finished{output} | Failed{CmdError} | Cancelled`.
- **`Interactor`:** each front end answers prompts its own way:
  - **CLI:** TTY prompt, or fail with a flag hint when not interactive.
  - **GUI:** event out, then a `cmd_respond` call back in.
  - **MCP:** elicitation if the client supports it; otherwise a structured `PasswordRequired` error telling the model which parameter to pass.
- **`Policy`:** sandbox roots, read_only, limits, default overwrite policy. The engine enforces it before any command runs, using the paths the command's `access()` declares (path resolution checks the canonicalised parent, so junction and symlink escapes are caught).
- **`CmdError`:** stable codes, plus an optional `details` value for structured extras (the extract report, per-entry test errors, which limit was hit). The codes are:
  - `NotFound`, `UnsupportedFormat`, `UnsupportedOperation`, `PasswordRequired`, `WrongPassword`, `Corrupt`, `OutsideSandbox`, `Conflict`, `LimitExceeded`, `Cancelled`, `BackendUnavailable`, `Io`;
  - `Unsafe`: the archive contains something BeeZip refuses to extract (an unsafe path, a link leaving the destination, overlapping entries). The safe entries are still extracted;
  - `InvalidArgs`: arguments that fail to deserialise or validate, from `beezip run --json` or MCP;
  - `Internal`: a caught panic or bug.

  Each code maps to a CLI exit code, to MCP `isError` + structuredContent, and to a UI toast.
- **Config:** `%APPDATA%\BeeZip\config.toml`, shared by the GUI, the CLI and MCP. It holds default levels, the overwrite policy, the 7-Zip path, MCP roots and limits. The settings commands read and write it.
- **Index cache (M3):** an LRU of parsed archive indexes keyed by (path, size, mtime). Commands stay stateless, which suits MCP and the CLI, and the GUI can still page through a 1M-entry archive quickly. It arrives with the GUI browser in M3; until then each command re-reads the index.

### Command catalog (v1)
| Command | Effect | Notes |
|---|---|---|
| `formats.list` | RO | capability matrix (the format/backend table) |
| `file.detect` | RO | format chain + confidence, e.g. `zstd → tar` |
| `archive.info` | RO | totals, method, solid, encrypted, volumes, comment |
| `archive.list` | RO | `dir` (folder inside the archive), `glob`, `flat`, `offset/limit` paging |
| `archive.test` | RO | CRC/integrity check |
| `entry.read` | RO | `offset/max_bytes`; text, hex or base64 (for preview and MCP) |
| `archive.extract` | W | all or selected, `dest`, overwrite policy, password, `strip_components`, `--dry-run` |
| `archive.create` | W | inputs, format chain, level/method/threads, solid, password, encrypt headers, volume size, excludes, `--dry-run` |
| `archive.add` / `archive.remove` / `archive.rename` | Destructive | rewrite to temp + atomic replace; raw copy for unchanged entries |
| `archive.convert` | W | streams reader to writer, no temp extraction where possible |
| `stream.compress` / `stream.decompress` | W | single-file codecs (`a.txt → a.txt.zst`) |
| `entry.open` | W | extract to temp cache + open with the default app (GUI/CLI only, hidden from MCP) |
| `bench.run` | RO | codecs × levels on a sample, giving ratio/speed table (M6) |
| `settings.get` / `settings.set` | W | config.toml |
| `shell.status` / `shell.install` / `shell.uninstall` | System | Explorer menus (`--classic`, `--modern`, per-item toggles). Windows only; GUI/CLI only, hidden from MCP |

Every archive command names the archive file `archive`. The M1 inputs and outputs are specified in [`docs/M1.md`](M1.md) §4.3.

### Front ends
- **CLI (`beezip`, clap 4.6):**
  - Generated subcommands: `beezip extract a.zip -o out`, `beezip list`, `beezip create`, `beezip convert`, `beezip test`, `beezip formats`. Short aliases `x`, `l`, `c`, `t`.
  - Generic forms: `beezip run <name> --json '{…}'` (or `@file`), `beezip commands` and `beezip schema <name>`.
  - Global `--output human|json|ndjson`. `ndjson` streams the `JobEvent`s, which suits scripts and CI. indicatif progress bars draw on a TTY.
- **MCP (`beezip mcp`, rmcp 3.8, spec 2026-07-28):**
  - Implements `ServerHandler` **by hand**, not with `#[tool]` macros. `list_tools` and `call_tool` iterate the registry, so no new command ever needs MCP-specific code.
  - **Tools:** names like `archive_extract`, with input/output schemas and annotations (`readOnlyHint`, `destructiveHint`).
  - **Results:** returned as structuredContent.
  - **Progress and cancellation:** `notify_progress` for progress; `RequestContext.ct` is wired to the job's `CancelToken`.
  - **Sandbox:** writes require `--root <dir>` (repeatable); the client's MCP roots are intersected with them. `--read-only` and `--unrestricted` flags. Limits are stricter by default: a list page holds at most 500 entries and `entry.read` returns at most 256 KiB.
  - **Transport:** stdio first; streamable HTTP on 127.0.0.1 (axum) later.
- **Desktop (Tauri 2.12.x, staying off the 3.0 alpha):**
  - **IPC:** exactly four Tauri commands: `cmd_run(name, args, Channel<JobEvent>) -> JobId`, `cmd_cancel`, `cmd_respond` and `cmd_list`.
  - **TS types:** `xtask codegen` uses ts-rs, which is stable; tauri-specta is still an RC. It writes `src/gen/commands.ts`, a typed `CommandMap` so that `run("archive.extract", {...})` is fully typed. CI fails if the generated file is stale. Codegen details:
      - It uses ts-rs 12 with `Config::with_large_int("number")`, because the wire format is JSON numbers.
      - Types don't use `#[ts(export)]`, so `cargo test` writes no files.
      - The full pipeline is described in [`docs/M0.md`](M0.md) §4.
  - **Libraries:** React 19 + Vite + TS, TanStack Table + Virtual (large archives), Zustand, Tailwind + Radix/shadcn, lucide.
  - **Screens and features:**
    - archive browser: folder tree, virtualised entry table, breadcrumb;
    - preview pane: text, hex or image, through `entry.read`;
    - drag-and-drop in to open or add;
    - extract and create dialogs; the create dialog has format, level, method, solid, threads, password, split size and excludes;
    - jobs panel with progress, cancel and logs;
    - password and overwrite prompts;
    - formats/capabilities page and settings;
    - **Ctrl+K command palette** listing registry commands;
    - **"Copy as CLI"** on every dialog, which shows the equivalent `beezip …` line.
  - **Integration:**
    - `bundle.fileAssociations` for every readable extension;
    - `tauri-plugin-single-instance` forwards files to the running window;
    - `tauri-plugin-dialog` and `tauri-plugin-opener`;
    - NSIS installer that installs `BeeZip.exe` and `bin\beezip.exe` (the CLI is staged separately; see Naming), and adds `bin\` to PATH;
    - a **job mode**, `BeeZip.exe --job <args.json>`, which opens a compact progress window. If the main app isn't running, the window exits when the job finishes; if it is, single-instance forwards the job to the running app. Explorer menu actions launch through this.

### Explorer context-menu integration (Windows 11 modern menu + classic menu)
**One COM handler, registered two ways.** `crates/beezip-shell` is a small Rust `cdylib`. It uses the `windows` crate's `#[implement(IExplorerCommand)]`, plus `IEnumExplorerCommand` for the submenu, a class factory, and `DllGetClassObject`/`DllCanUnloadNow`.

- **Windows 11 top-level menu.** The modern menu only accepts handlers from apps with package identity. We use a **sparse package** (packaged with external location), so we keep the NSIS install instead of moving to full MSIX:
  - `packaging/windows/AppxManifest.xml` declares `desktop4:FileExplorerContextMenus` with `desktop5:ItemType` entries for `*` and `Directory`, and a `com:SurrogateServer` pointing at `beezip_shell_<ver>.dll`.
  - The manifest is packed into `beezip-sparse.msix`, signed, and registered by the installer with `Add-AppxPackage -ExternalLocation <installdir>` (or the PackageManager API).
  - `BeeZip.exe` gets a matching `<msix …/>` identity element in its Windows manifest, set through `tauri_build::WindowsAttributes::app_manifest`.
- **Classic menu** (Windows 10, and Windows 11's "Show more options"). Registry keys under HKCU, so no admin is needed:
  - `Software\Classes\{*,Directory}\shell\BeeZip` with `ExplorerCommandHandler={CLSID}`;
  - `CLSID\{…}\InprocServer32` pointing at the same DLL, with `ThreadingModel=Apartment`.
  - Classic verbs never show up in the Win11 modern menu, so nothing appears twice.
  - **Spike to run first:** check that the classic menu shows our `ECF_HASSUBCOMMANDS` cascade on Windows 10 22H2 and in Win11's "Show more options". If it doesn't, add an `IContextMenu` implementation to the same DLL, which is what 7-Zip does.
- **Menu items** (cascaded under "BeeZip ▸" by default; each can be flattened or hidden in settings):
  - For archives: Open with BeeZip, Extract here (smart: if the archive doesn't have a single top-level folder, it extracts into a folder), Extract to "name\", Extract to…, Test archive.
  - For any files or folders: Add to "name.zip", Add to "name.7z", Compress to… (opens the create dialog), and compress-to-format submenus for tar.zst and others.
  - Multi-select works through `IShellItemArray`.
- **How an item runs.** Each menu item is a registry command plus an args template, the same idea as "Copy as CLI":
  - Clicking it writes the selection and args to a temp JSON file, which avoids command-line length limits.
  - It then starts `BeeZip.exe --job <file>` with `CreateProcessW`.
  - No archive work ever runs inside `explorer.exe`.
- **Keeping the DLL fast and safe:**
  - It does not depend on beezip-core. Deciding whether an item applies uses only the file extension (the list is configurable).
  - Settings come from a small registry value that `settings.set` mirrors, so the DLL never parses TOML.
  - `GetState` returns `ECS_HIDDEN` for items that don't apply.
  - It never lets a panic cross the FFI boundary: every COM method body runs inside `catch_unwind` and returns `E_UNEXPECTED` if it panics. The build keeps `panic = "unwind"`, for three reasons:
  - with `abort`, `catch_unwind` catches nothing, and a panic would kill explorer.exe;
  - Cargo can't set `panic` per package anyway;
  - since Rust 1.81, a panic that escapes an `extern "system"` function aborts the process.
  - Icons are taken from `BeeZip.exe,N`.
- **Install, upgrade and uninstall** happen in the NSIS `installerHooks` (Tauri `bundle.windows.nsis`), which call `beezip shell install|uninstall`, so the CLI owns the logic.
  - The DLL file name includes the version (`beezip_shell_<ver>.dll`) so an upgrade doesn't fight Explorer's lock on the old file.
  - Old DLLs are deleted on the next run or at reboot (`MoveFileEx` with `DELAY_UNTIL_REBOOT`).
- **Signing.** Windows only installs the sparse package if it is signed by a certificate the machine trusts, and that certificate's subject must equal `Publisher` in the manifest.
  - Development: `xtask dev-cert` creates a self-signed certificate and installs it into LocalMachine\TrustedPeople. This needs admin once.
  - Release: a real code-signing certificate or Azure Trusted Signing, used to sign the exe, the DLL, `beezip-sparse.msix` and the installer.

---

## 2. Format / backend matrix
Crate versions were checked on 2026-11-01. Churny crates are pinned exactly behind adapters (zip has had 8 majors since 2024; rmcp 1→3 in 2026).

| Format | R | W | Implementation | Milestone |
|---|---|---|---|---|
| ZIP: deflate, bzip2, zstd, xz, ppmd, AES/ZipCrypto, Zip64 | ✓ | ✓ | `zip` =9.2.2: deflate through zlib-rs (levels 0–9, no zopfli); PPMd read and write; ZipCrypto writing through zip's `unstable` API; deflate64/lzma/legacy are read-only | M1 |
| TAR (ustar/pax/gnu) | ✓ | ✓ | `tar` 0.4.46 | M1 |
| gzip / zlib / raw deflate | ✓ | ✓ | `flate2` + zlib-rs. Raw deflate has no magic or extension, so it is never detected (`--codec deflate` only). Parallel gzip (`gzp`) moves to M6: its defaults build C zlib-ng/libdeflate, and its `deflate_rust` feature uses miniz_oxide rather than zlib-rs | M1 |
| bzip2 | ✓ | ✓ | `bzip2` 0.6 (pure-Rust libbz2-rs-sys) | M1 |
| xz / lzma / lzip | ✓ | ✓ | `lzma-rust2` =0.23.0 (pure Rust, multithreaded; the version zip 9.2.2 requires, so only one copy is built) | M1 |
| zstd | ✓ | ✓ | `zstd` 0.14 (bundled C, zstdmt) | M1 |
| lz4 / brotli / snappy | ✓ | ✓ | `lz4_flex` / `brotli` / `snap` | M1 |
| tar.{gz,bz2,xz,zst,lz4,br,lz} | ✓ | ✓ | codec chain composition | M1 |
| 7z: LZMA/2, PPMd, BCJ*, AES-256, solid | ✓ | ✓ | `sevenz-rust2` 0.24 + our `VolumeSet` for `.7z.001` | M3 |
| RAR 1.5–7 incl. multipart and passwords | ✓ | ✗ | `unrar` (cargo feature `rar`, on by default; UnRAR license notice shipped). `rars` (pure Rust) still to be evaluated as a fallback. RAR creation is never offered | M3 |
| Split files (.001…) | ✓ | ✓ | in-house `VolumeSet` reader/writer | M3 |
| CAB | ✓ | ✓ (MSZIP) | `cab` (LZX is read-only) | M5 |
| ISO 9660 / Joliet / Rock Ridge | ✓ | ✓ | `hadris-iso` 2.5 | M5 |
| cpio, ar, deb (ar + tar.*) | ✓ | ✓ | `cpio`, `ar`, composition | M5 |
| RPM | ✓ | — | `rpm` (writing deferred) | M5 |
| LHA/LZH | ✓ | ✗ | `delharc` | M5 |
| Unix `.Z` | ✓ | ✓ | in-house LZW (weezl cannot handle `.Z`) | M5 |
| lzop | ✓ | ✓ | `lzokay` + in-house container (avoid the GPL lzo crates) | M5 |
| squashfs | ✓ | ✓ | `backhand` (`xz-static`, **no** `lzo` feature) | M5 |
| DMG (UDIF) | ✓ | ✓ | `udif` 0.4 | M5 |
| ARJ, ACE, ARC, ZOO, HA, UC2, Amiga LZX… | ✓ | ✗ | `unarc-rs` (**license to be checked before adopting**) | M6 |
| WIM, CHM, MSI, NSIS, VHD(X), VMDK, QCOW2, HFS/APFS, NTFS/FAT/EXT images, UDF, CramFS… | ✓ | ✗ | `SevenZipCli` backend: finds an installed `7z.exe` (configurable path) and parses `7z l -slt`. Extraction goes to a staging dir, then through `FsSink` safety | M6 |
| XAR/pkg | ✓ | ? | evaluate `zar` (MIT) first; apple-xar (MPL-2.0) is acceptable with a per-crate cargo-deny exception if needed | M6 |
| libarchive (everything it reads or writes) | ✓ | some | `libarchive2` behind cargo feature `libarchive`, **off** by default (needs vcpkg/CMake on MSVC) | optional |

Formats that are known not to be supported (or only partly): split/spanned ZIP (.z01) in v1 (not supported by `zip`; reading them may come later via `VolumeSet` + offset fix-up), writing LZMA/Deflate64 inside ZIP, and BCJ2 is read-only.

`cargo-deny` allowlist: MIT, MIT-0 (`ppmd-rust`, used by zip's PPMd support; MIT without the attribution clause), Apache-2.0, Apache-2.0 WITH LLVM-exception (`target-lexicon`, a Linux build dependency of Tauri; the exception only adds permissions), BSD-2/3, ISC, Zlib, Unicode-3.0, bzip2-1.0.6. GPL and LGPL are denied.
- **Advisories:** vulnerabilities always fail. Unmaintained-crate advisories only fail for our direct dependencies (`unmaintained = "workspace"`); Tauri 2.12's tree alone carries four (`proc-macro-error`, `zbus_names`, `zvariant`, `zvariant_derive`) that nothing here can fix.
- **MPL-2.0 is not on the allowlist**, but Tauri 2.12 itself depends on five MPL-2.0 crates (checked 2026-11-01):
  - `option-ext`, via dirs-sys ← dirs ← tauri;
  - `cssparser`, `cssparser-macros`, `dtoa-short` and `selectors`, via dom_query ← tauri-utils.
- These crates get per-crate exceptions and are listed in `THIRD_PARTY_NOTICES`. MPL is file-level copyleft, so using them unmodified in an MIT/Apache app is fine. Any new MPL crate still fails the check until it gets its own exception.
- The UnRAR license (`unrar_sys`) gets an exception in M3.
- On the Windows runner, cargo-deny runs as an installed binary, because `cargo-deny-action` is a Docker action and only runs on Linux.

---

## 3. Milestones
After approval I implement **M0 + M1** and then stop for your review before going further.

- **M0 — Scaffold.** Detailed plan: [`docs/M0.md`](M0.md).
  - The workspace above, `rust-toolchain.toml`, and the Tauri 2 + React app shell (`pnpm create tauri-app`, React-TS template, productName `BeeZip`, identifier `app.beezip.desktop`). The git repo already exists; its default branch is `master`.
  - `xtask`, `deny.toml`, and GitHub Actions on `windows-latest` running fmt, clippy `-D warnings`, test, deny, the codegen staleness check and a Tauri build smoke test. An ubuntu job runs the core/commands/mcp/cli tests so the code stays portable.
  - One command, `app.version`, wired end to end: `beezip version`, `beezip run app.version`, Tauri `cmd_run` shown in the UI, and MCP `tools/list`.
- **M1 — Engine + CLI.** Detailed plan: [`docs/M1.md`](M1.md). It lands as two PRs: core first, then commands and CLI.
  - **beezip-core:** detection, all M1 codecs, the ZIP and TAR formats, the codec-chain composition, `SafeFs`, progress and cancel.
  - **beezip-commands:** registry, engine, policy, config, and the commands `formats.list`, `file.detect`, `archive.{info,list,test,extract,create}`, `entry.read` and `stream.{compress,decompress}`.
  - **beezip-cli:** generated subcommands, `run`/`commands`/`schema`, the output modes and progress bars.
  - **Fuzzing:** a separate Linux workflow on nightly (`cargo +nightly fuzz`), because cargo-fuzz needs nightly and the pinned toolchain is stable. It fuzzes each target for 10 minutes nightly and for 1 minute on PRs that touch core or `fuzz/`.
- **M2 — MCP.**
  - `beezip-mcp` builds its tool list dynamically from the registry, with sandbox roots, read-only mode, progress, cancellation, elicitation and paging.
  - Docs for `claude mcp add beezip -- beezip mcp --root <dir>` and Claude Desktop config.
- **M3 — Desktop MVP + 7z/RAR/volumes.**
  - The four-command IPC, browser, preview, extract and create dialogs, jobs panel, prompts, palette and "Copy as CLI".
  - File associations and single-instance forwarding.
  - The 7z, RAR and VolumeSet formats.
- **M4 — Explorer integration.**
  - First the classic-cascade spike, then `beezip-shell`, which carries one menu model and both registrations.
  - `shell.{status,install,uninstall}`, the sparse package + `xtask dev-cert`, and NSIS hooks.
  - A settings page with per-item toggles, then end-to-end checks on Win11 and on a Win10 VM.
- **M5 — Editing + breadth.**
  - `archive.add/remove/rename/convert`, `entry.open`, and the M5 formats in §2 (CAB, ISO, cpio/ar/deb, RPM, LHA, .Z, lzop, squashfs, DMG).
  - Filename codepage override.
- **M6 — Long tail + ship.**
  - `SevenZipCli` backend, `unarc-rs`, XAR, `bench.run` with a UI chart.
  - NSIS/MSI installer, production signing, `tauri-plugin-updater`, a winget manifest (`BeeZip.BeeZip`).
  - Turn on the macOS/Linux bundle jobs.

---

## 4. Verification
- **Unit and round-trip tests** (`cargo test --workspace`): every writable format gets a proptest that creates an archive from a random tree, extracts it and checks the result is byte-identical, including metadata where the format supports it.
- **Fixtures:** `tests/fixtures/` holds reference archives made by other tools. `manifest.json` records the expected entries and SHA-256 hashes, and `xtask gen-fixtures` regenerates the malicious corpus.
  - **M1:** the tools available on Windows: 7-Zip 26.00, GNU tar 1.35, bsdtar 3.8.9 (Windows `tar.exe`) and .NET (`Compress-Archive`).
  - **Later:** WinRAR, Info-ZIP and macOS ditto.
- **Interop:** Windows CI runners already have 7-Zip, so CI runs `7z t` on every archive we produce, and we read every archive 7-Zip produces.
- **Malicious corpus:** zip-slip, absolute/UNC paths, reserved names, ADS names, symlink escapes, overlapping-entry zip bomb, deep nesting. Each one must be rejected with the correct `CmdError`.
- **Fuzzing:** cargo-fuzz targets for detection, each pure-Rust reader, the codecs and the path sanitiser. They run in a separate Linux workflow on nightly: 10 minutes per target each night, and 1 minute per target on PRs that touch core or `fuzz/`.
- **CLI:** `trycmd` snapshot tests. Smoke test: `beezip formats`, `beezip create t.tar.zst src -l 19`, `beezip test t.tar.zst`, `beezip x t.tar.zst -o out`, `beezip run archive.list --json "{\"archive\":\"t.tar.zst\"}" --output json`.
- **Parity test:** for every command in the registry:
  - it can be called through `beezip run`;
  - it appears in MCP `tools/list` with the same schema (MCP-excluded commands aside);
  - it has a TS binding in `commands.ts`.
- **MCP:**
  - an integration test that spawns `beezip mcp --root <tmp>` with the rmcp client, runs initialize → tools/list → tools/call, and checks progress notifications, cancellation, and that a write outside the root fails with `OutsideSandbox`;
  - manual checks with `npx @modelcontextprotocol/inspector beezip mcp --root C:\tmp\sbx` and `claude mcp add beezip -- beezip mcp --root C:\tmp\sbx`.
- **Desktop:**
  - `pnpm tauri dev`: open a fixture by dialog, drag-drop and double-click (association + single-instance), browse a 1M-entry zip smoothly, preview, extract with cancel mid-way (no partial files left), create a password-protected 7z, check "Copy as CLI" output runs unchanged in a terminal;
  - vitest for components; a tauri-driver smoke E2E in M6.
- **Explorer integration:**
  - Unit tests for the pure `selection → menu items` function, kept separate from the COM glue.
  - A Windows CI harness that loads `beezip_shell_<ver>.dll` with `CoCreateInstance`, builds an `IShellItemArray` from fixture paths (`SHCreateShellItemArrayFromShellItem`), and checks the title, state, subcommands and that `Invoke` writes the job file.
  - `beezip shell install --classic` → `beezip shell status` → check the registry keys → `beezip shell uninstall` leaves nothing behind.
  - Manual on Win11, in both the modern menu and "Show more options": single file, multi-select, folder, a non-archive file (archive items hidden), and "Extract here" opens the job window and finishes.
  - Upgrade the installer while Explorer has the old DLL loaded. Repeat on a Win10 22H2 VM.

## 5. Risks and mitigations
- **API churn** (zip, rmcp, specta): wrap each crate in an adapter module, pin versions exactly, use Renovate, and keep ts-rs instead of tauri-specta for now.
- **UnRAR license:** keep it behind a feature, ship the notice in `THIRD_PARTY_NOTICES`, never offer RAR creation, and track `rars` as a pure-Rust replacement.
- **libarchive on Windows:** optional feature, off by default. Most of the long tail comes from the 7-Zip external backend, which carries no license coupling because it runs as a separate process.
- **Solid archives and random access:** previews use the index cache plus a temp extraction cache, and `FormatCaps.random_access` tells the UI when a preview will be slow.
- **Native drag-out to Explorer from the webview:** stretch goal (M6). The fallback is "Extract to…" plus dragging out a temp extraction.
- **The Win11 menu needs package identity and a trusted signature.** Unsigned dev builds only get the classic menu until `xtask dev-cert` has been run. Releases need a real certificate.
- **A shell extension crashing takes Explorer down with it.** Mitigations: keep the DLL tiny and free of beezip-core, `catch_unwind` in every COM method (with `panic = "unwind"`), no file I/O in `GetState`, and fuzz the selection-to-items logic.
- **The name:**
  - BeeZip is one letter away from **BreeZip**, an existing open-source Windows archiver. Use distinct bee-themed branding and run a trademark search before the first public release.
  - beezip.com is taken, so use beezip.app as the primary domain. Register beezip.app and beezip.dev soon.
  - The ASPLOS 2024 "BeeZip" compression accelerator is academic and causes no conflict.

## 6. Future note: `.bhive` archive format (not scheduled)
- **Extension check:** `.bhive` was checked on 2026-11-01. It has no entries in any file-extension database and no `.bhive` files on GitHub.
- **Nearby names that don't clash:** the BHive x86 benchmark, the `bhived` MCP server, and the `.bh` BlakHole archive format.
- **Rejected alternatives:**
  - `.bz` is bzip;
  - `.bee` is Bee Archiver;
  - `.bbz` is already used by several formats;
  - `.hive` is Flutter's Hive database;
  - `.hyv` is Hy-Tek swim meet files;
  - `.hv` is registry hives and medical imaging;
  - `.cmb` is Reason and Chromeleon;
  - `.bhv` is MOOS-IvP and looks like `.bvh`;
  - `.b2z` looks like `.bz2`.
- **Suggested design if built:** a `.bhive` file is a **standard container underneath**, either `.7z` or `.tar.zst`, with a small `beezip.json` manifest as its first entry. The manifest holds the format version, the creating app and optional metadata.
  - BeeZip gets branding, its own icon and a file association.
  - Other tools can still open the file after renaming it. No new codec is needed, so the format can't lock users in.
- **Until then:** don't register `.bhive` as a file association or emit `.bhive` files. Keep the extension unused so a future spec has no legacy files to stay compatible with.
- **If it's adopted:** add a `bhive` entry to `ArchiveFormat` that wraps the 7z or tar.zst backend. Add `.bhive` to `bundle.fileAssociations` and to the Explorer "Add to…" menu. Publish a one-page spec in `docs/bhive.md`.
