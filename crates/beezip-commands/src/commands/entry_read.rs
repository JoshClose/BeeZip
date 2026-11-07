use std::{io::Read, path::PathBuf};

use base64::Engine as _;
use beezip_core::{EntryKind, format::normalize, io::read_error};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx,
    commands::util::with_archive,
    wire::{NameEncoding, Secret, TextEncoding},
};

/// Read part of one entry without extracting it, as text, hex or base64. An offset is reached
/// by decoding up to it, since a compressed entry can't seek.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct EntryReadInput {
    /// The archive.
    pub archive: PathBuf,
    /// The entry's path. With duplicates, the last copy; use `index` for another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// The entry's index in archive order, as `archive.list` shows it.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    /// Where to start, in bytes.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// At most this many bytes [default: 65536; at most 16 MiB, or 256 KiB over MCP].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// How to return the data [default: text].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<TextEncoding>,
    /// The password for an encrypted entry.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How names stored as bytes are read: zip names without the UTF-8 flag, tar names outside
    /// pax records, cpio, ar, LHA and squashfs names, CAB names without the UTF-8 flag, ISO
    /// names outside Joliet [default: from config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
}

pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024;
pub const MAX_BYTES_CEILING: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EntryReadOutput {
    pub entry: String,
    pub index: u64,
    pub data: String,
    pub encoding: TextEncoding,
    pub offset: u64,
    pub bytes_read: u64,
    /// The entry's size, if the archive records it.
    pub size: Option<u64>,
    /// The read reached the end of the entry.
    pub eof: bool,
    /// Text only: some bytes weren't UTF-8 and were replaced.
    pub lossy: bool,
}

pub struct EntryRead;

impl Command for EntryRead {
    const NAME: &'static str = "entry.read";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "read",
        aliases: &[],
        group: None,
    });

    type Input = EntryReadInput;
    type Output = EntryReadOutput;

    fn access(input: &EntryReadInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: EntryReadInput, cx: &mut JobCtx) -> Result<EntryReadOutput, CmdError> {
        let max = input.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
        if max > MAX_BYTES_CEILING {
            return Err(CmdError::invalid_args(format!(
                "max_bytes is at most {MAX_BYTES_CEILING} (16 MiB)"
            )));
        }
        // A front end's cap (MCP's 256 KiB) shortens the read; `eof: false` says to read on.
        let max = max.min(cx.policy().max_read_bytes.unwrap_or(u64::MAX));
        let encoding = input.encoding.unwrap_or_default();
        let offset = input.offset.unwrap_or(0);
        let given = input.archive.clone();
        let (path, id, size, skipped, mut buf, eof) = with_archive(
            &given,
            input.password.as_ref(),
            input.name_encoding,
            cx,
            |a, cx| {
                let opened = &mut a.opened;
                let entries = opened.reader.entries(cx)?;
                a.entries = Some(entries.len());
                let entry = match (&input.entry, input.index) {
                    (_, Some(i)) => entries
                        .get(usize::try_from(i).unwrap_or(usize::MAX))
                        .ok_or_else(|| CmdError::not_found(format!("there is no entry {i}")))?,
                    (Some(path), None) => {
                        let want = normalize(path);
                        entries
                            .iter()
                            .rev()
                            .find(|e| normalize(&e.path) == want)
                            .ok_or_else(|| {
                                CmdError::not_found(format!("no entry named `{path}`"))
                            })?
                    }
                    (None, None) => {
                        return Err(CmdError::invalid_args("give an entry path or an index"));
                    }
                };
                if entry.kind == EntryKind::Dir {
                    return Err(CmdError::new(
                        ErrorCode::UnsupportedOperation,
                        format!("`{}` is a folder", entry.path),
                    ));
                }
                let (path, id, size) = (entry.path.clone(), entry.id, entry.size);

                let mut r = opened.reader.open_entry(id, cx)?;
                let skipped = std::io::copy(&mut r.by_ref().take(offset), &mut std::io::sink())
                    .map_err(|e| CmdError::from(read_error(&e)))?;
                // One byte more than asked, to tell whether the entry goes on.
                let mut buf = Vec::new();
                r.by_ref()
                    .take(max + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| CmdError::from(read_error(&e)))?;
                let eof = buf.len() as u64 <= max;
                drop(r);
                Ok((path, id, size, skipped, buf, eof))
            },
        )?;
        buf.truncate(usize::try_from(max).unwrap_or(usize::MAX));

        let (data, lossy) = match encoding {
            TextEncoding::Text => {
                // A character cut off by `max_bytes` is left for the next read, not replaced.
                if !eof
                    && let Err(e) = std::str::from_utf8(&buf)
                    && e.error_len().is_none()
                {
                    buf.truncate(e.valid_up_to());
                }
                let text = String::from_utf8_lossy(&buf);
                let lossy = matches!(text, std::borrow::Cow::Owned(_));
                (text.into_owned(), lossy)
            }
            TextEncoding::Hex => (buf.iter().map(|b| format!("{b:02x}")).collect(), false),
            TextEncoding::Base64 => (
                base64::engine::general_purpose::STANDARD.encode(&buf),
                false,
            ),
        };
        Ok(EntryReadOutput {
            entry: path,
            index: id as u64,
            data,
            encoding,
            offset: skipped,
            bytes_read: buf.len() as u64,
            size,
            eof,
            lossy,
        })
    }

    fn human(out: &EntryReadOutput) -> Option<String> {
        Some(out.data.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<EntryReadInput>(
            &["a.zip", "docs/a.md"],
            serde_json::json!({ "archive": "a.zip", "entry": "docs/a.md" }),
        );
    }
}
