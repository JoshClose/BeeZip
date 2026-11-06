# BeeZip's MCP server

`beezip mcp` serves BeeZip's commands as [MCP](https://modelcontextprotocol.io) tools over stdin/stdout. An assistant such as Claude can then list, test, read, extract and create archives. The tools are the same commands as the CLI's and the desktop app's, with the same arguments; see `beezip schema <command>` for any of them.

It speaks MCP 2026-07-28, as well as 2025-11-25 and older through the `initialize` handshake.

## Setting it up

Give the full path to `beezip.exe`, and name the directories BeeZip may write to with `--root`. Without a root, the assistant can read archives but can't extract or create anything.

**Claude Code:**
```powershell
claude mcp add beezip -- C:\path\to\beezip.exe mcp --root C:\Users\you\Unpacked
# for every project:  claude mcp add --scope user beezip -- …
```

**Claude Desktop:** open Settings → Developer → Edit Config (`%APPDATA%\Claude\claude_desktop_config.json`), add the server, then restart Claude Desktop:
```json
{
  "mcpServers": {
    "beezip": {
      "command": "C:\\path\\to\\beezip.exe",
      "args": ["mcp", "--root", "C:\\Users\\you\\Unpacked"]
    }
  }
}
```

**MCP Inspector**, for trying the tools by hand:
```powershell
npx @modelcontextprotocol/inspector C:\path\to\beezip.exe mcp --root C:\tmp\sbx
npx @modelcontextprotocol/inspector --cli C:\path\to\beezip.exe mcp --method tools/list
```

## Options

| Flag | |
|---|---|
| `--root <DIR>` | A directory commands may write under. Repeat it for more. It replaces `[mcp] roots` from the config. |
| `--read-only` | Offer only the tools that don't write. |
| `--unrestricted` | Let commands write anywhere. Use it only with a client you trust to ask before every call. |

The same settings can live in `config.toml` (see the README), so every client gets them:
```toml
[mcp]
roots = ['C:\Users\you\Unpacked']
read_only = false
```
The rest of the config (default levels, the overwrite policy, limits) applies too.

## Tools

| Tool | Writes | What it does |
|---|---|---|
| `formats_list` | | The formats and codecs BeeZip reads and writes: zip, 7z, RAR (read only), tar under any codec, and bare compressed files. |
| `file_detect` | | What a file is: `zstd → tar`, a 7z, a RAR or zip SFX, a volume set (`a.7z.001`…, `a.part1.rar`…), or not an archive. |
| `archive_info` | | Counts, sizes, ratio, methods, encryption, solid blocks, and the volumes of a split archive. |
| `archive_list` | | Entries, one folder level at a time or `flat`, with `glob` filters, `kind`, and `sort` (folders first). |
| `archive_test` | | Reads everything back and checks CRCs. |
| `entry_read` | | Part of one entry, as text, hex or base64. |
| `archive_extract` | ✓ | All entries, or selected ones, into `dest`. |
| `archive_create` | ✓ | A zip, 7z or tar (optionally compressed) from files and folders, optionally split into volumes (`volume_size`). A 7z with a password encrypts the names too, unless `encrypt_headers` is false. |
| `stream_compress` | ✓ | One file through one codec: `a.txt` → `a.txt.zst`. |
| `stream_decompress` | ✓ | One codec layer off: `a.tar.zst` → `a.tar`. |
| `app_version` | | BeeZip's version. |

Each tool has an output schema, and its results come back as structured content plus the same JSON as text. The tools that read an archive take `name_encoding` for names it stores as bytes (zips without the UTF-8 flag, tars): `auto`, the default, reads UTF-8 and otherwise Windows' code page; `cp932`, `cp936`, `cp866` and the rest read the names that system wrote. The archive tools read zip, 7z, RAR 1.5–7 and tar (RAR is read only), and any part of a split archive (`a.7z.002`, `a.part3.rar`) opens the whole set.

## Where it may write

- **Writes go only under the roots.** Every path a command writes to (an extraction's `dest`, a new archive, a compressed file) is resolved first, following junctions and symlinks. A path outside every root fails with `OutsideSandbox`, and the error names the roots.
- **Reads aren't confined.** The assistant can open an archive anywhere the user can.
- **Paths should be absolute.** Relative ones resolve against the server's working directory, which depends on the client. The server tells the assistant this, and names that directory.
- **Client roots:** clients on MCP 2025-11-25 or older can share roots of their own. If a client shares some, writes must fall inside both its roots and `--root`. If it shares none, `--root` applies as it is. MCP 2026-07-28 deprecates client roots, so those sessions use `--root` alone.

## Questions and passwords

- **Existing files:** when an extraction meets a file that already exists and no `overwrite` policy was given, BeeZip asks the user through the client: replace, replace all, keep, keep all, or keep both. This only happens in clients that support elicitation forms; elsewhere the call fails with `Conflict` and the assistant can retry with `overwrite`.
  - On MCP 2026-07-28 the question comes back as an `input_required` result, and the job waits for the client's retry. If no retry arrives within 10 minutes, the job is cancelled.
  - Declining the question cancels the job.
- **Passwords are never asked for over MCP.** The spec forbids asking for secrets in elicitation forms. An encrypted archive fails with `PasswordRequired` (with `details.param = "password"`). The assistant asks the user and calls again with `password`. That means the password passes through the assistant's context, so only give it one you are willing to share there.

## Limits

- **`archive_list`** returns at most 500 entries per call, whatever `limit` asks for. While `has_more` is true, call it again with a larger `offset`.
- **`entry_read`** returns at most 256 KiB per call (64 KiB by default). Continue from `offset + bytes_read` until `eof` is true.
- **The config's `[limits]`** (compression ratio, entry count, decoder memory, total bytes) apply as they do in the CLI.

## Progress, cancellation and errors

- **Progress:** jobs send `notifications/progress` (bytes read so far, and the entry being processed) to clients that pass a `progressToken`.
- **Cancellation:** cancelling a call (`notifications/cancelled`) cancels its job, which removes its partly written file. When the client disconnects, running jobs are cancelled too.
- **Errors:** failures come back as tool results with `isError: true`. Their structured content is `{code, message, details?}`, where `code` is stable:
  - `NotFound`, `InvalidArgs`, `UnsupportedFormat`, `UnsupportedOperation`;
  - `PasswordRequired`, `WrongPassword`;
  - `Corrupt`;
  - `OutsideSandbox`, `Conflict`, `LimitExceeded`, `Unsafe`;
  - `Cancelled`, `Io`, `Internal`.

  `Unsafe` means the archive held entries BeeZip refused to extract, such as paths climbing out with `..`. The rest were extracted, and `details` lists both.
