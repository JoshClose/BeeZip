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
| Explorer menu | "BeeZip ▸", registry verb key `BeeZip`, `beezip_shell_<ver>.dll`, `beezip-sparse.msix` (package identity `BeeZip`; publisher `CN=BeeZip Dev` until a production certificate exists, then that certificate's subject) |

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
crates/beezip-unrar/          # UnRAR through unrar_sys, core's `rar` feature. Unsafe code lives here, in beezip-shell, and in a few Windows calls in core: bench.rs's private bytes, safefs/disk.rs's seek penalty (M6), format/wim/lzms_win.rs's LZMS through cabinet.dll (M8)
crates/beezip-commands/       # Command trait, registry, engine, jobs, policy, config
  src/commands/*.rs           # one file per command
crates/beezip-mcp/            # rmcp ServerHandler built dynamically from the registry
crates/beezip-cli/            # bin `beezip`; `beezip mcp` subcommand runs beezip-mcp
crates/beezip-menu/           # the Explorer menu model and job request, shared by the DLL, the commands and the desktop
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
  - `FormatCaps` flags: list, extract, create, append, delete, rename, encrypt, encrypt_headers, solid, volumes, random_access. Append, delete and rename are on for zip, 7z, tar, cpio and ar from M5 (docs/M5.md §3.9).
- **`ArchiveReader`**:
  - `entries()` returns the cached index.
  - `extract(&Selection, &mut dyn EntrySink, &Ctx)` streams entries in archive order, which keeps solid archives fast.
  - `open_entry(id) -> Read`.
- **`ArchiveWriter`**:
  - `expect(entries)`: every entry the archive will hold, before the first is written, so a writer can refuse what it can't store before writing anything (a cpio's 4 GiB files) and write tables first (ar's long names, CAB's file list) (docs/M5.md §16, PR 4).
  - `holds(kind)`: ar and CAB hold files only, so folders and links are left out of them, the links reported.
  - `add(meta, Read, &Ctx)`.
  - `copy_from(reader, keep) -> ids not copied`, which copies entries without recompressing them: zip entries byte for byte (BeeZip's own copy, not the zip crate's `raw_copy_file`, whose copies are corrupt for ZipCrypto and LZMA), whole 7z blocks, tar, cpio and ar members. It takes a list rather than one id because 7z copies whole blocks (docs/M5.md §3.2).
  - `finish()`.
- **`Backend`** groups formats: `Native`, `SevenZipCli` and `Libarchive`. The registry picks a backend for each format and operation using capabilities and priority.
  - The 7-Zip backend (M6) is one `ArchiveReader` for the formats in docs/M6.md §3.2. It reads `7z l -slt` and streams `7z x -so` into FsSink; only NSIS installers go through a staging folder. It needs 7-Zip 25.01 or newer.
  - From M7, BeeZip reads partitioned disks, FAT, NTFS, ext2/3/4, bare HFS+ and APFS volumes and MSI installers itself (docs/M7.md); 7-Zip reads only what those readers don't support, when it's installed (docs/M7.md §2).
- **No serialization in core:** core doesn't depend on serde, schemars or ts-rs. `beezip-commands` owns every wire type and converts, so core types can change without changing the API the front ends see.
- **`Source`** is one of:
  - a file (Read+Seek);
  - a `VolumeSet` (`.001…`, `.7z.001`, `.partN.rar`), which concatenates its parts behind Read+Seek;
  - a decoded stream. When a format needs Seek, as `zip.gz` does, the stream is spooled to a temp file.
- **Detection:**
  1. BeeZip's own sniffers, one per format and codec: magic bytes plus a structural check where there is one, such as the tar header checksum;
  2. compound probing: decode the first 64 KiB of a stream codec and re-probe it, so `tar.zst` is recognised;
  3. a scan for SFX signatures in PE overlays: the PE section table gives where the image ends, and the 7z and RAR sniffers look there (zip SFX keeps its end-record check);
  4. volume sets: any part of `a.7z.001`… is probed as the joined set, and RAR's `.partN.rar` and `.rar`/`.r00` names find the first part;
  5. extension as a tie-breaker.

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
  - **Filename encoding:** names stored as bytes (zip without the UTF-8 flag, tar, cpio, LHA…) are read as UTF-8 when marked or valid, otherwise in the system's OEM code page for zip and its ANSI code page for the others; an encoding can be chosen for every format that stores names as bytes (`encoding_rs`/`oem_cp`, docs/M5.md §6).
- **Progress** comes from a `CountingReader` on the compressed input, so it is reliable, and is throttled to about 10 Hz. **Cancellation** is a shared `CancelToken` that is checked between buffers.
- **Threading:** core is synchronous. The engine runs each job on its own thread rather than a worker pool, because jobs are few and long-running. Parallelism inside a job comes from the codecs (zstdmt, xz and lzip compression, 7z's LZMA2 decoding) and, from M6, from BeeZip's own workers, scoped threads per job: parallel deflate, the zip writer, xz decoding and the extraction of zips (docs/M6.md §6). The zip crate has no parallel writer, and its `rayon` feature isn't used.

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
  - **MCP:** overwrite questions use elicitation when the client supports it. Spec 2026-07-28 sends it inside an `InputRequiredResult`, and the job waits, parked, for the retry; older sessions get a plain `elicitation/create`. Passwords are never elicited, since form mode must not carry secrets. A structured `PasswordRequired` error tells the model which parameter to pass ([`docs/M2.md`](M2.md) §3.3).
- **`Policy`:** sandbox roots, read_only, limits, default overwrite policy. The engine enforces it before any command runs, using the paths the command's `access()` declares (path resolution checks the canonicalised parent, so junction and symlink escapes are caught).
- **`CmdError`:** stable codes, plus an optional `details` value for structured extras (the extract report, per-entry test errors, which limit was hit). The codes are:
  - `NotFound`, `UnsupportedFormat`, `UnsupportedOperation`, `PasswordRequired`, `WrongPassword`, `Corrupt`, `OutsideSandbox`, `Conflict`, `LimitExceeded`, `Cancelled`, `BackendUnavailable`, `Io`;
  - `Unsafe`: the archive contains something BeeZip refuses to extract (an unsafe path, a link leaving the destination, overlapping entries). The safe entries are still extracted;
  - `InvalidArgs`: arguments that fail to deserialise or validate, from `beezip run --json` or MCP;
  - `Internal`: a caught panic or bug.

  Each code maps to a CLI exit code, to MCP `isError` + structuredContent, and to a UI toast.
- **Config:** `%APPDATA%\BeeZip\config.toml`, shared by the GUI, the CLI and MCP. It holds default levels, the overwrite policy, the 7-Zip path, MCP roots, limits, the Explorer menu's items and the desktop's theme. The settings commands read and write it, keeping its comments (`toml_edit`).
- **Index cache (M3):** it caches open readers along with their indexes, keyed by the canonical path and each volume's size and mtime: up to four archives and 4 million entries. A job borrows its archive and puts it back, so a reader is never shared. Encrypted archives aren't cached, so no cached reader carries a password between jobs. Commands stay stateless, which suits MCP and the CLI, and the GUI can still page through a 1M-entry archive quickly ([`docs/M3.md`](M3.md) §4.2).

### Command catalog (v1)
| Command | Effect | Notes |
|---|---|---|
| `formats.list` | RO | capability matrix (the format/backend table) |
| `file.detect` | RO | format chain + confidence, e.g. `zstd → tar` |
| `archive.info` | RO | totals, method, solid, encrypted, volumes, comment; from M6 `backend` ("7-Zip 26.00") and `levels` (`vhdx > gpt > ntfs`) |
| `archive.list` | RO | `dir` (folder inside the archive), `glob`, `flat`, `offset/limit` paging |
| `archive.test` | RO | CRC/integrity check |
| `entry.read` | RO | `offset/max_bytes`; text, hex or base64 (for preview and MCP) |
| `archive.extract` | W | all or selected, `dest`, overwrite policy, password, `strip_components`, `--dry-run` |
| `archive.create` | W | inputs, format chain, level/method/threads, solid, password, encrypt headers, volume size, excludes, `--dry-run` |
| `archive.add` / `archive.remove` / `archive.rename` | Destructive | rewrite to temp + atomic replace; raw copy for unchanged entries. Volume sets and SFX archives are refused (docs/M5.md §3.7). CLI aliases `a`, `d`, `rn` |
| `archive.convert` | W | streams reader to writer, no temp extraction where possible. Never drops encryption silently: an encrypted source needs `new_password` or `decrypt` |
| `stream.compress` / `stream.decompress` | W | single-file codecs (`a.txt → a.txt.zst`) |
| `entry.open` | W | extract to temp cache + open with the default app (GUI/CLI only, hidden from MCP). CLI: `beezip open` |
| `bench.run` | RO | codecs × levels × threads on a file or the built-in sample, in memory: ratio, MB/s each way, peak memory, each round trip checked; cells arrive as job events, and a cancelled run returns those it finished (M6, docs/M6.md §7). CLI: `beezip bench` |
| `settings.get` / `settings.set` | RO / W | config.toml, edited in place. Hidden from MCP: an assistant that could set `[mcp] roots` could widen its own sandbox. CLI: `beezip settings get`, `beezip settings set KEY=VALUE… [--reset KEY]` |
| `shell.status` | RO | which Explorer registration is in place, and why (docs/M4.md §5.5) |
| `shell.install` / `shell.uninstall` | System | Explorer menus (`--mode classic\|modern\|auto`). Windows only; GUI/CLI only, hidden from MCP. CLI: `beezip shell …` |
| `shell.plan` | RO | turns an Explorer job request into the steps a job window runs (docs/M4.md §6.1) |

Every archive command names the archive file `archive`. The M1 inputs and outputs are specified in [`docs/M1.md`](M1.md) §4.3.

### Front ends
- **CLI (`beezip`, clap 4.6):**
  - Generated subcommands: `beezip extract a.zip -o out`, `beezip list`, `beezip create`, `beezip convert`, `beezip test`, `beezip formats`. Short aliases `x`, `l`, `c`, `t`.
  - Generic forms: `beezip run <name> --json '{…}'` (or `@file`), `beezip commands` and `beezip schema <name>`.
  - Groups: a command's `CliSpec` can name a group, so `settings.*` and `shell.*` are `beezip settings get` and `beezip shell install`.
  - Global `--output human|json|ndjson`. `ndjson` streams the `JobEvent`s, which suits scripts and CI. indicatif progress bars draw on a TTY.
  - Ctrl+C cancels the job, which removes its partial files. A second Ctrl+C exits at once, and deletes every partial file the process still has open first (`partial::abandon_all`), since `process::exit` runs no destructors.
- **MCP (`beezip mcp`, rmcp 3.8, spec 2026-07-28):**
  - Implements `ServerHandler` **by hand**, not with `#[tool]` macros. `list_tools` and `call_tool` iterate the registry, so no new command ever needs MCP-specific code.
  - **Tools:** names like `archive_extract`, with input/output schemas and annotations (`readOnlyHint`, `destructiveHint`).
  - **Results:** returned as structuredContent.
  - **Progress and cancellation:** `notify_progress` for requests that carry a `progressToken`; `RequestContext.ct` is wired to the job's `CancelToken`. No logging notifications (deprecated by SEP-2577).
  - **Sandbox:** writes require `--root <dir>` (repeatable). In sessions that still have client roots (2025-11-25 and older; 2026-07-28 deprecates them), a non-empty list is intersected with `--root`. `--read-only` (which also hides the write tools) and `--unrestricted` flags. Limits are stricter by default: a list page holds at most 500 entries and `entry.read` returns at most 256 KiB, through two `Policy` caps the CLI and GUI leave unset.
  - **Transport:** stdio. Streamable HTTP on 127.0.0.1 (axum) isn't scheduled.
- **Desktop (Tauri 2.12.x, staying off the 3.0 alpha):**
  - **IPC:** exactly four Tauri commands: `cmd_run(name, args, Channel<JobEvent>) -> JobId`, `cmd_cancel`, `cmd_respond` and `cmd_list`. Rust sends the page `open-paths`, with the files a second instance forwards, and from M5 `entry-changed`, when a file `entry.open` extracted has changed; the page sends Rust `opened-forget` when a tab closes, so its files stop being checked (docs/M5.md §8.3); the paths `BeeZip.exe` starts with reach the page through an initialization script. Prompts carry the job id, so `cmd_respond(job, prompt, reply)` knows which job asked. "Copy as CLI" lines come from the `cli.line` command, built from the same clap definition that parses them.
  - **TS types:** `xtask codegen` uses ts-rs, which is stable; tauri-specta is still an RC. It writes `src/gen/commands.ts`, a typed `CommandMap` so that `run("archive.extract", {...})` is fully typed. CI fails if the generated file is stale. Codegen details:
      - It uses ts-rs 12 with `Config::with_large_int("number")`, because the wire format is JSON numbers.
      - Types don't use `#[ts(export)]`, so `cargo test` writes no files.
      - The full pipeline is described in [`docs/M0.md`](M0.md) §4.
  - **Libraries:** React 19 + Vite + TS, TanStack Virtual (large archives), Zustand, Tailwind + Radix/shadcn, lucide. Not TanStack Table: its v9 is a different API, and sorting a million entries happens in `archive.list`, in Rust.
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
    - `bundle.fileAssociations` for the archive extensions BeeZip reads, not the zip-based document formats (docx, jar, epub…). The NSIS installer makes BeeZip their default handler, and uninstall restores the previous one;
    - `tauri-plugin-single-instance` forwards files to the running window;
    - `tauri-plugin-dialog` and `tauri-plugin-opener`;
    - NSIS installer that installs `BeeZip.exe` and `bin\beezip.exe` (the CLI is staged separately; see Naming), and adds `bin\` to PATH. NSIS only, no MSI (docs/M6.md §9.3);
    - from M6, `tauri-plugin-updater`: it checks GitHub Releases at most once a day, and installs only on a click (docs/M6.md §9.4);
    - a **job mode**, `BeeZip.exe --job <request.json>`: Explorer writes a job request, and `shell.plan` expands it into steps. Each request gets one compact job window; dialogs ("Extract to…", "Compress to…") open in the main window. A second `BeeZip.exe` hands its request to the running one, and the process exits when its last window closes (docs/M4.md §6).

### Explorer context-menu integration (Windows 11 modern menu + classic menu)
**One COM handler, registered one of two ways.** `crates/beezip-shell` is a small Rust `cdylib`. It uses the `windows` crate's `#[implement(IExplorerCommand)]` (`windows =0.62.2`, the version Tauri builds; the umbrella crate wasn't published at 0.100), plus `IEnumExplorerCommand` for the submenu, a class factory, and `DllGetClassObject`/`DllCanUnloadNow`, exported `PRIVATE` through a `.def` file. The registry goes through windows-registry 0.6.1. The menu model and the job request it writes live in `crates/beezip-menu`, pure Rust, shared with the commands and the desktop.

- **Windows 11 top-level menu.** The modern menu only accepts handlers from apps with package identity. We use a **sparse package** (packaged with external location), so we keep the NSIS install instead of moving to full MSIX:
  - `packaging/windows/AppxManifest.xml` declares `desktop4:FileExplorerContextMenus` with `desktop5:ItemType` entries for `*` and `Directory`, and a `com:SurrogateServer` pointing at `beezip_shell_<ver>.dll`. The handler runs in `DllHost.exe`, the COM surrogate, not in `explorer.exe`.
  - The manifest is packed into `beezip-sparse.msix`, signed, and registered by the installer with `Add-AppxPackage -ExternalLocation <installdir>` (or the PackageManager API).
  - Processes the handler starts inherit the package's identity, so the manifest turns off file-system and registry write virtualization; otherwise their AppData writes land in the package's folder.
  - `BeeZip.exe` gets no `<msix …/>` identity element, so there's no `tauri_build` manifest change.
  - The Windows 11 menu shows one entry per package: items can be hidden there, but not moved to the top level.
- **Classic menu** (Windows 10, and Windows 11 when the package can't be registered). Registry keys under HKCU, so no admin is needed:
  - `Software\Classes\{*,Directory}\shell\BeeZip` with `ExplorerCommandHandler={CLSID}`;
  - `CLSID\{…}\InprocServer32` pointing at the same DLL, with `ThreadingModel=Apartment`.
  - Classic verbs never load for the Windows 11 menu, but packaged verbs do appear under "Show more options". So registering both would show BeeZip twice there: Windows 11 uses the package when it can be registered, and the classic keys otherwise; Windows 10 uses the classic keys.
  - The `ECF_HASSUBCOMMANDS` cascade showed in Windows 11's "Show more options" (docs/M4.md §16). Windows 10 22H2 is checked on a VM before M4 builds on it; if it fails there, the DLL adds an `IContextMenu`, as 7-Zip does.
- **Menu items** (cascaded under "BeeZip ▸" by default; each can be hidden in settings, and in the classic menu `cascade = false` puts them at the top level):
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
  - Old DLLs are deleted when they can be. A locked one is moved to `%TEMP%` and removed at the next sign-in through HKCU `RunOnce`; `MoveFileEx(DELAY_UNTIL_REBOOT)` needs admin, which a per-user install doesn't have.
- **Signing.** Windows only installs the sparse package if it is signed by a certificate the machine trusts, and that certificate's subject must equal `Publisher` in the manifest.
  - An unsigned `.msix` can't be installed without admin, and a certificate trusted only in `CurrentUser\TrustedPeople` isn't enough (docs/M4.md §16).
  - Development: the unsigned manifest is registered under Developer Mode, with no admin and no certificate. `xtask dev-cert` (a self-signed certificate in `LocalMachine\TrustedPeople`, admin once) is only for trying the signed installer path. CI runs as administrator and covers it.
  - Release: a real code-signing certificate, used to sign the exe, the DLL, `beezip-sparse.msix` and the installer. The options (Azure Artifact Signing, Certum's open-source certificate, others) are in docs/M6.md §9.2. The package's Publisher is the certificate's subject.

---

## 2. Format / backend matrix
Crate versions were checked on 2026-11-01. Churny crates are pinned exactly behind adapters (zip has had 8 majors since 2024; rmcp 1→3 in 2026).

| Format | R | W | Implementation | Milestone |
|---|---|---|---|---|
| ZIP: deflate, bzip2, zstd, xz, ppmd, AES/ZipCrypto, Zip64 | ✓ | ✓ | `zip` =9.4.1 (from M6): deflate through zlib-rs (levels 1–9, no zopfli); PPMd read and write; ZipCrypto writing through zip's `unstable` API; deflate64/lzma/legacy are read-only | M1 |
| TAR (ustar/pax/gnu) | ✓ | ✓ | `tar` 0.4.46 | M1 |
| gzip / zlib / raw deflate | ✓ | ✓ | `flate2` + zlib-rs. Raw deflate has no magic or extension, so it is never detected (`--codec deflate` only). Parallel compression is BeeZip's own (docs/M6.md §6.1), not gzp | M1 |
| bzip2 | ✓ | ✓ | `bzip2` 0.6 (pure-Rust libbz2-rs-sys) | M1 |
| xz / lzma / lzip | ✓ | ✓ | `lzma-rust2` =0.25.0 (pure Rust; multithreaded compression; multithreaded xz decoding from M6, docs/M6.md §6.4; the version zip 9.4.1 and sevenz-rust2 0.25.0 require, so only one copy is built) | M1 |
| zstd | ✓ | ✓ | `zstd` 0.14 (bundled C, zstdmt) | M1 |
| lz4 / brotli / snappy | ✓ | ✓ | `lz4_flex` / `brotli` / `snap` | M1 |
| tar.{gz,bz2,xz,zst,lz4,br,lz} | ✓ | ✓ | codec chain composition | M1 |
| 7z: LZMA/2, PPMd, BCJ*, AES-256, solid | ✓ | ✓ | `sevenz-rust2` `=0.25.0` (from M6) + our `VolumeSet` for `.7z.001`. It reads everything listed plus Deflate, BZip2, LZ4, Brotli and ARM64, but not zstd. It writes LZMA2, LZMA, PPMd, BZip2, Deflate and Copy, with encrypted headers on by default when there is a password and solid blocks capped at 1 GiB. BeeZip checks decoder memory itself (the crate's own limit, new in 0.25, isn't used), and checks entry CRCs itself, so a bad entry in a solid block fails only that entry (docs/M6.md §1) | M3 |
| RAR 1.5–7 incl. multipart and passwords | ✓ | ✗ | UnRAR through `unrar_sys` in a new `beezip-unrar` crate, not the `unrar` crate, which can only buffer whole entries. BeeZip declares UnRAR's packed structs itself, links advapi32, and takes one lock for every call into UnRAR (cargo feature `rar`, on by default; UnRAR license notice shipped). `rars` (pure Rust) stays the tracked alternative. RAR creation is never offered | M3 |
| Split files (.001…) | ✓ | ✓ | in-house `VolumeSet` reader/writer | M3 |
| CAB | ✓ | ✓ (none, MSZIP) | in-house; cabinet sets read (docs/M5.md §5.5). LZX was read through `lzxd` 0.2.7 until M7, which replaced it with BeeZip's own decoder (docs/M7.md §8.4), made 1.45× faster in M8; a file sharing another's data is served from the copy written (`EntrySink::same_as`), and small files are written on other threads (docs/M8.md §6) | M5 |
| ISO 9660 / Joliet / Rock Ridge, UDF | ✓ | ✓ (ISO 9660 level 3 + Joliet + Rock Ridge) | `hadris-iso` and `hadris-udf` 3.0, patched (docs/M5.md §5.9) | M5 |
| cpio | ✓ | ✓ (newc) | in-house: newc, crc, odc, binary, RPM's large files; also under every tar codec | M5 |
| ar | ✓ | ✓ (GNU) | in-house | M5 |
| deb | ✓ | ✗ | in-house over ar and tar, listed as `dpkg-deb -R` unpacks it | M5 |
| RPM | ✓ | ✗ | in-house headers, cpio payload through the codecs | M5 |
| LHA/LZH | ✓ | ✗ | `delharc` 0.8.0, names decoded by BeeZip | M5 |
| Unix `.Z` | ✓ | ✓ | in-house LZW | M5 |
| lzop | ✓ | ✓ | in-house container, `lzokay` 2.0.1 blocks | M5 |
| squashfs | ✓ | ✓ | in-house reader; `backhand` 0.25.5 writer with BeeZip's codecs | M5 |
| DMG (UDIF) | ✓ (HFS+, HFSX, APFS) | ✓ (HFS+, UDZO) | in-house UDIF; `fstool` 0.5.2 for the volumes | M5 |
| ARJ, ACE, ZOO, ARC | ✓ | ✗ | in-house, from unarc-rs's ARJ, ACE and ZOO modules (MIT) and acefile (BSD-2); ARC BeeZip's own. HA, UC2, JAR, HYP and SQZ aren't read (license; docs/M6.md §4) | M6 |
| NSIS, CramFS; MSI patches, transforms and merge modules (`.msp`, `.mst`, `.msm`) | ✓ | ✗ | `SevenZipCli` backend: finds an installed 7-Zip 25.01 or newer (configurable path), parses `7z l -slt` and streams `7z x -so` into `FsSink`; staging only for NSIS (docs/M6.md §3). Until M7 it also read the disks, file systems and MSI below, until M8 the virtual disks and WIM, and until M9 CHM | M6 |
| CHM | ✓ | ✗ | in-house reader (docs/M9.md): the ITSF/ITSP directory, every listing chunk read; section 1 decoded by BeeZip's LZX decoder a 32 KiB frame at a time from the reset table, the last frame whole; a CHM using something else goes to 7-Zip | M9 |
| WIM, ESD, SWM | ✓ | ✗ | in-house reader (docs/M8.md §5): 1.13 and ESD 0.14, none/XPRESS/LZX/LZMS, solid resources, split sets, every blob's SHA-1, chunks decoded on `[extract] threads` workers; LZMS through Windows' Compression API (cabinet.dll from System32) on Windows, 7-Zip elsewhere | M8 |
| VHD, VHDX, VMDK, QCOW2, VDI | ✓ | ✗ | in-house readers (docs/M8.md §3): fixed, dynamic and differencing VHD/VHDX with a VHDX's log replayed in memory; VMDK hosted, split, flat, stream-optimized and child disks; QCOW2 v2/v3 with deflate/zstd clusters, extended L2, backing and data files; VDI with its snapshots. Parents found by BeeZip's rules, never over the network. M7's partition and file-system readers run inside them. What they refuse goes to 7-Zip when it's installed | M8 |
| MBR/GPT disks, FAT12/16/32, NTFS, ext2/3/4, bare HFS+/HFSX/APFS | ✓ | ✗ | in-house partition reader (GPT with 512- or 4096-byte sectors, MBR with its EBR chain) and FAT reader; `fstool` =0.5.2 (features `ext`, `ntfs`) for ext and NTFS behind BeeZip's own checks, folder walks, names, times and links; HFS+/APFS as for DMG. A volume using something BeeZip doesn't support goes to 7-Zip when it's installed. Files Windows compressed with WOF (XPRESS4K/8K/16K, LZX) decode through BeeZip's own XPRESS decoder and `format/lzx.rs` (docs/M8.md §4); files a volume can't read (EFS, deduplicated, WIMBoot) are skipped and reported when extracting (docs/M7.md §2–§7) | M7 |
| MSI | ✓ | ✗ | in-house tables on `cfb` =0.16.0, listed by the paths they install to, files from BeeZip's CAB reader (docs/M7.md §8); embedded cabinet sets, MsiFileHash on a thread of its own (docs/M8.md §6, §7) | M7 |
| XAR/pkg | ✓ | ✗ | in-house reader; pkg listed expanded, as `pkgutil --expand-full`; quick-xml (docs/M6.md §5) | M6 |
| libarchive (everything it reads or writes) | ✓ | some | `libarchive2` behind cargo feature `libarchive`, **off** by default (needs vcpkg/CMake on MSVC) | optional |

Formats that are known not to be supported (or only partly): split/spanned ZIP (.z01) in v1 (not supported by `zip`; reading them may come later via `VolumeSet` + offset fix-up), writing LZMA/Deflate64 inside ZIP, and BCJ2 is read-only.

`cargo-deny` allowlist: MIT, MIT-0 (`ppmd-rust`, used by zip's PPMd support; MIT without the attribution clause), Apache-2.0, Apache-2.0 WITH LLVM-exception (`target-lexicon`, a Linux build dependency of Tauri; the exception only adds permissions), BSD-2/3, ISC, Zlib, Unicode-3.0, bzip2-1.0.6. GPL and LGPL are denied.
- **Advisories:** vulnerabilities always fail. Unmaintained-crate advisories only fail for our direct dependencies (`unmaintained = "workspace"`); Tauri 2.12's tree alone carries four (`proc-macro-error`, `zbus_names`, `zvariant`, `zvariant_derive`) that nothing here can fix.
- **MPL-2.0 is not on the allowlist**, but Tauri 2.12 itself depends on five MPL-2.0 crates (checked 2026-11-01):
  - `option-ext`, via dirs-sys ← dirs ← tauri;
  - `cssparser`, `cssparser-macros`, `dtoa-short` and `selectors`, via dom_query ← tauri-utils.
- These crates get per-crate exceptions and are listed in `THIRD_PARTY_NOTICES`. MPL is file-level copyleft, so using them unmodified in an MIT/Apache app is fine. Any new MPL crate still fails the check until it gets its own exception.
- **BSL-1.0** has one per-crate exception, `xxhash-rust`, which backhand needs to write squashfs (M5). The Boost license is permissive; the exception keeps any other BSL crate visible.
- The UnRAR license (`unrar_sys`) gets a cargo-deny clarification as well as an exception (M3). `unrar_sys` declares MIT OR Apache-2.0, but it compiles UnRAR's own C++, so the clarification makes it `(MIT OR Apache-2.0) AND LicenseRef-UnRAR`.
- **Third-party notices** ship in the installer and on the About page from M3. From M6, `cargo xtask notices` generates `THIRD_PARTY_NOTICES.md` from the Rust crates and the bundled npm packages, and CI checks it (docs/M6.md §9.1).
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
- **M2 — MCP.** Detailed plan: [`docs/M2.md`](M2.md).
  - `beezip-mcp` builds its tool list dynamically from the registry, with sandbox roots, read-only mode, progress, cancellation, elicitation and paging.
  - Docs for `claude mcp add beezip -- beezip mcp --root <dir>` and Claude Desktop config.
- **M3 — Desktop MVP + 7z/RAR/volumes.**
  - The four-command IPC, browser, preview, extract and create dialogs, jobs panel, prompts, palette and "Copy as CLI".
  - File associations and single-instance forwarding.
  - The 7z, RAR and VolumeSet formats.
- **M4 — Explorer integration.** Detailed plan: [`docs/M4.md`](M4.md).
  - Settings (`settings.get`/`set`, the settings page, the theme), job mode, the classic menu, then the Windows 11 menu: four PRs.
  - `beezip-menu` and `beezip-shell`, which carry one menu model and either registration.
  - `shell.{status,install,uninstall,plan}`, the sparse package + `xtask dev-cert`, and NSIS hooks.
  - End-to-end checks on Win11 and on a Win10 VM.
- **M5 — Editing + breadth.**
  - `archive.add/remove/rename/convert`, `entry.open`, and the M5 formats in §2 (CAB, ISO, cpio/ar/deb, RPM, LHA, .Z, lzop, squashfs, DMG).
  - Filename codepage override.
- **M6 — Long tail + ship.** Detailed plan: [`docs/M6.md`](M6.md).
  - The `SevenZipCli` backend; ARJ, ACE, ZOO and ARC; XAR and pkg.
  - Parallel gzip, zip writing, zip extraction and xz decoding; `bench.run` with a chart in the desktop.
  - Generated notices, a signing pipeline for a production certificate, NSIS installer fixes, `tauri-plugin-updater`, draft releases, a winget manifest (`CloseConsulting.BeeZip`), Linux and macOS bundles on CI.
  - The early-launch fix, a tauri-driver E2E test, and drag-out to Explorer as a stretch goal.
  - The first public release comes after the look-and-feel pass.
- **M7 — Native disk images and MSI.** Detailed plan: [`docs/M7.md`](M7.md). Ships in 0.2.0.
  - BeeZip's own readers for GPT and MBR disks, FAT, NTFS, ext2/3/4, bare HFS+ and APFS volumes, and MSI installers.
  - Files a volume can't read (EFS, WOF, deduplicated) are skipped and reported on extraction (after M7, PR #33).
- **M8 — Virtual disks, Windows compression, WIM and installer speed.** Detailed plan: [`docs/M8.md`](M8.md), approved 2026-11-10. Ships in 0.3.0, with two 0.2.0 fixes (no 0.2.1).
  - VHD, VHDX, VMDK, QCOW2 and VDI read by BeeZip, so the M7 readers run inside them.
  - WOF-compressed NTFS files decompressed (XPRESS, LZX).
  - WIM and ESD read by BeeZip (XPRESS, LZX; LZMS through Windows' own decoder on Windows, 7-Zip elsewhere).
  - Faster CAB and MSI extraction, and MSI cabinets that continue from one embedded cabinet into the next.
- **M9 — CHM.** Detailed plan: [`docs/M9.md`](M9.md), approved 2026-11-11. Ships in 0.4.0.
  - CHM help files read by BeeZip on its own LZX decoder, so 7-Zip is left with NSIS, CramFS and MSI patches.
  - `.chm` stays with the system's help viewer; Explorer's menu keeps BeeZip's items on it.

---

## 4. Verification
- **Unit and round-trip tests** (`cargo test --workspace`): every writable format gets a proptest that creates an archive from a random tree, extracts it and checks the result is byte-identical, including metadata where the format supports it.
- **Fixtures:** `tests/fixtures/` holds reference archives made by other tools. `manifest.json` records the expected entries and SHA-256 hashes, and `xtask gen-fixtures` regenerates the malicious corpus.
  - **M1:** the tools available on Windows: 7-Zip 26.00, GNU tar 1.35, bsdtar 3.8.9 (Windows `tar.exe`) and .NET (`Compress-Archive`).
  - **M3:** 7-Zip 26.00 for 7z; the RAR fixtures come from libarchive 3.8.11's and rars 0.12.3's test suites, made by real WinRAR versions, with 7-Zip as the oracle for their contents. WinRAR isn't needed.
  - **Later:** Info-ZIP and macOS ditto.
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
  - vitest for components; a tauri-driver smoke E2E from M6, on Windows and Linux CI (tauri-driver has no macOS driver).
- **Explorer integration:**
  - Unit tests for the pure `selection → menu items` function (`beezip-menu`), kept separate from the COM glue.
  - A Windows CI harness that loads the DLL directly (`LoadLibrary` + `DllGetClassObject`, nothing registered), builds an `IShellItemArray` from fixture paths, and checks the title, state, subcommands and that `Invoke` writes the job file.
  - `menu_dump` builds the classic menu as the shell does, which also lists packaged verbs, so one tool checks both registrations.
  - On the CI runner, as administrator: `beezip shell install --mode classic` → `menu_dump` → `beezip shell uninstall` leaves nothing behind; then the same with a test-signed package.
  - Manual on Win11, in both the modern menu and "Show more options": single file, multi-select, folder, a non-archive file (archive items hidden), and "Extract here" opens the job window and finishes.
  - Upgrade the installer while Explorer has the old DLL loaded. Repeat on a Win10 22H2 VM.

## 5. Risks and mitigations
- **API churn** (zip, rmcp, specta): wrap each crate in an adapter module, pin versions exactly, use Renovate, and keep ts-rs instead of tauri-specta for now.
- **The zip crate's raw copy** (`raw_copy_file`, `new_append`, 9.2.2–9.4.1) rebuilds the flags it copies, so ZipCrypto and LZMA entries come out corrupt. Worked around: BeeZip copies zip entries itself, byte for byte (docs/M5.md §3.3).
- **UnRAR license:** keep it behind a feature, ship the notice in `THIRD_PARTY_NOTICES`, never offer RAR creation, and track `rars` as a pure-Rust replacement.
- **libarchive on Windows:** optional feature, off by default. Most of the long tail comes from the 7-Zip external backend, which carries no license coupling because it runs as a separate process.
- **The 7-Zip backend's names:** FsSink checks every name 7-Zip lists, as for any format; BeeZip never relies on 7-Zip's own renaming, since 7-Zip never writes to the destination (docs/M6.md §3.4).
- **Installers and a running BeeZip:** Tauri's installer closes a running BeeZip without asking in silent and passive mode (winget, the updater). The updater cancels running jobs first (docs/M6.md §9.3, §9.4).
- **Solid archives and random access:** previews use the index cache plus a temp extraction cache, and `FormatCaps.random_access` tells the UI when a preview will be slow.
- **Native drag-out to Explorer from the webview:** stretch goal (M6). The fallback is "Extract to…" plus dragging out a temp extraction.
- **The Win11 menu needs package identity and a trusted signature.** Development registers the unsigned manifest under Developer Mode; an installer without a trusted certificate gives Windows 11 the classic menu. Releases need a real certificate (M6).
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
