use std::path::PathBuf;

use beezip_core::{Encryption, EntryKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::util::{absolute, as_given, with_archive},
    wire::{NameEncoding, Secret, human_size, ratio},
};

/// Summarise an archive: its format chain, entry counts, sizes and compression ratio, methods,
/// encryption, whether it is solid or self-extracting, and its comment.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveInfoInput {
    /// The archive.
    pub archive: PathBuf,
    /// The password, if entry names or data need one.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How names stored as bytes are read: zip names without the UTF-8 flag, tar names outside
    /// pax records [default: from config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
}

/// How many entries are encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionState {
    None,
    Some,
    All,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveInfoOutput {
    pub archive: PathBuf,
    /// `zip`, `7z`, `rar`, `tar` or `stream`.
    pub format: String,
    /// `zstd → tar`.
    pub chain: String,
    pub codecs: Vec<String>,
    pub entries: u64,
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    /// The uncompressed size of the files.
    pub size: u64,
    /// The archive file's size.
    pub packed_size: u64,
    /// `packed_size / size`: 0.25 means the archive is a quarter of the original.
    pub ratio: f64,
    pub methods: Vec<String>,
    pub encryption: EncryptionState,
    /// Entries can't be decoded on their own (a solid 7z or RAR, a compressed tar, a bare
    /// compressed file).
    pub solid: bool,
    pub sfx: bool,
    pub comment: Option<String>,
    /// The files the archive is split across, first part first; just the archive when it
    /// isn't split.
    pub volumes: Vec<PathBuf>,
    /// 7z: blocks holding more than one file (reading a file decodes its block from the start).
    pub solid_blocks: Option<u64>,
    /// The entry names are encrypted too, so listing needs the password.
    pub encrypted_headers: bool,
    /// RAR: locked against changes.
    pub locked: bool,
    /// RAR: has a recovery record, for repairing damage.
    pub recovery_record: bool,
    /// Why `archive.add`, `archive.remove` and `archive.rename` would refuse the archive: its
    /// format, a volume set, a self-extracting archive, a read-only file. `null` when they
    /// wouldn't.
    pub not_editable: Option<String>,
}

pub struct ArchiveInfo;

impl Command for ArchiveInfo {
    const NAME: &'static str = "archive.info";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "info",
        aliases: &[],
        group: None,
    });

    type Input = ArchiveInfoInput;
    type Output = ArchiveInfoOutput;

    fn access(input: &ArchiveInfoInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: ArchiveInfoInput, cx: &mut JobCtx) -> Result<ArchiveInfoOutput, CmdError> {
        let given = input.archive.clone();
        with_archive(
            &given,
            input.password.as_ref(),
            input.name_encoding,
            cx,
            |a, cx| {
                let opened = &mut a.opened;
                let info = opened.reader.info(cx)?;
                let entries = opened.reader.entries(cx)?;
                a.entries = Some(entries.len());
                let count = |pred: fn(&EntryKind) -> bool| {
                    entries.iter().filter(|e| pred(&e.kind)).count() as u64
                };
                let files = count(|k| matches!(k, EntryKind::File | EntryKind::Hardlink { .. }));
                let dirs = count(|k| *k == EntryKind::Dir);
                let links = count(|k| matches!(k, EntryKind::Symlink { .. }));
                let size: u64 = entries
                    .iter()
                    .filter(|e| e.kind == EntryKind::File)
                    .filter_map(|e| e.size)
                    .sum();
                let entries_total = entries.len() as u64;
                let not_editable = beezip_core::edit::refusal(&absolute(&given), opened, cx)
                    .unwrap_or_else(|e| Some(e.message));
                let out = ArchiveInfoOutput {
                    format: info.format.name().into(),
                    chain: opened.detection.chain(),
                    codecs: info.codecs.iter().map(|c| c.name().to_owned()).collect(),
                    entries: entries_total,
                    files,
                    dirs,
                    links,
                    size,
                    packed_size: opened.size,
                    ratio: ratio(size, opened.size),
                    methods: info.methods.iter().map(|m| (*m).to_owned()).collect(),
                    encryption: match info.encryption {
                        Encryption::None => EncryptionState::None,
                        Encryption::Some => EncryptionState::Some,
                        Encryption::All => EncryptionState::All,
                    },
                    solid: info.solid,
                    sfx: info.sfx,
                    volumes: as_given(&input.archive, &opened.detection.volumes),
                    solid_blocks: info.solid_blocks,
                    encrypted_headers: info.encrypted_headers,
                    locked: info.locked,
                    recovery_record: info.recovery_record,
                    not_editable,
                    comment: info.comment,
                    archive: input.archive,
                };
                Ok(out)
            },
        )
    }

    fn human(out: &ArchiveInfoOutput) -> Option<String> {
        let mut s = format!(
            "{}: {}{}\n  {} entries: {} files, {} folders, {} links\n  {} in {} ({:.0}%)",
            out.archive.display(),
            out.chain,
            if out.sfx { " (self-extracting)" } else { "" },
            out.entries,
            out.files,
            out.dirs,
            out.links,
            human_size(out.size),
            human_size(out.packed_size),
            out.ratio * 100.0,
        );
        if !out.methods.is_empty() {
            s.push_str(&format!("\n  methods: {}", out.methods.join(", ")));
        }
        if out.encryption != EncryptionState::None {
            let which = if out.encryption == EncryptionState::All {
                "all"
            } else {
                "some"
            };
            s.push_str(&format!("\n  encrypted: {which} entries"));
        }
        if out.encrypted_headers {
            s.push_str("\n  names encrypted");
        }
        if out.solid {
            match out.solid_blocks {
                Some(1) => s.push_str("\n  solid (1 solid block)"),
                Some(n) => s.push_str(&format!("\n  solid ({n} solid blocks)")),
                None => s.push_str("\n  solid"),
            }
        }
        if out.locked {
            s.push_str("\n  locked");
        }
        if out.recovery_record {
            s.push_str("\n  recovery record");
        }
        if out.volumes.len() > 1 {
            s.push_str(&format!("\n  {} volumes:", out.volumes.len()));
            for v in &out.volumes {
                s.push_str(&format!("\n    {}", v.display()));
            }
        }
        if let Some(c) = &out.comment {
            s.push_str(&format!("\n  comment: {c}"));
        }
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveInfoInput>(
            &["a.zip"],
            serde_json::json!({ "archive": "a.zip" }),
        );
    }
}
