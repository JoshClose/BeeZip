use std::path::PathBuf;

use beezip_core::{Encryption, EntryKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::util::open_archive,
    wire::{Secret, human_size, ratio},
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
    /// `zip`, `tar` or `stream`.
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
    /// Entries can't be decoded on their own (a compressed tar, a bare compressed file).
    pub solid: bool,
    pub sfx: bool,
    pub comment: Option<String>,
}

pub struct ArchiveInfo;

impl Command for ArchiveInfo {
    const NAME: &'static str = "archive.info";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "info",
        aliases: &[],
    });

    type Input = ArchiveInfoInput;
    type Output = ArchiveInfoOutput;

    fn access(input: &ArchiveInfoInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: ArchiveInfoInput, cx: &mut JobCtx) -> Result<ArchiveInfoOutput, CmdError> {
        let mut opened = open_archive(&input.archive, input.password.as_ref(), cx)?;
        let info = opened.reader.info(cx)?;
        let entries = opened.reader.entries(cx)?;
        let count =
            |pred: fn(&EntryKind) -> bool| entries.iter().filter(|e| pred(&e.kind)).count() as u64;
        let files = count(|k| matches!(k, EntryKind::File | EntryKind::Hardlink { .. }));
        let dirs = count(|k| *k == EntryKind::Dir);
        let links = count(|k| matches!(k, EntryKind::Symlink { .. }));
        let size: u64 = entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .filter_map(|e| e.size)
            .sum();
        let entries_total = entries.len() as u64;
        Ok(ArchiveInfoOutput {
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
            comment: info.comment,
            archive: input.archive,
        })
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
        if out.solid {
            s.push_str("\n  solid");
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
