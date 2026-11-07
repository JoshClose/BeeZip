use std::path::PathBuf;

use beezip_core::EditOp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::edit::{EditOutput, SpecArgs, human, run_edit},
    wire::{NameEncoding, Secret},
};

/// Rename an entry of an archive, or a folder and everything under it (zip, 7z, tar, cpio and
/// ar, and tar and cpio under any codec). `to` is the new full path, so a rename can also move an entry. The new
/// name mustn't be taken, unless only its case differs. Entries are copied without decoding,
/// encrypted ones included; renamed names are stored in UTF-8. A new archive is written beside
/// the old one and swapped in.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveRenameInput {
    /// The archive.
    pub archive: PathBuf,
    /// The entry or folder to rename, as listed (a folder may exist only as the parent of
    /// entries).
    pub from: String,
    /// Its new full path inside the archive.
    pub to: String,
    /// The password, if entry names need one (a 7z with encrypted names).
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How names stored as bytes are read, so `from` matches them as listed [default: from
    /// config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
    /// Show what would be renamed without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

pub struct ArchiveRename;

impl Command for ArchiveRename {
    const NAME: &'static str = "archive.rename";
    const EFFECT: Effect = Effect::Destructive;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "rename",
        aliases: &["rn"],
        group: None,
    });

    type Input = ArchiveRenameInput;
    type Output = EditOutput;

    fn access(input: &ArchiveRenameInput) -> Vec<Access> {
        vec![Access::Write(input.archive.clone())]
    }

    fn run(input: ArchiveRenameInput, cx: &mut JobCtx) -> Result<EditOutput, CmdError> {
        let op = EditOp::Rename {
            from: input.from.clone(),
            to: input.to.clone(),
        };
        run_edit(
            &input.archive,
            &op,
            &SpecArgs::default(),
            input.password.as_ref(),
            input.name_encoding,
            input.dry_run.unwrap_or(false),
            cx,
        )
    }

    fn human(out: &EditOutput) -> Option<String> {
        Some(human(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveRenameInput>(
            &["a.zip", "docs/a.txt", "docs/b.txt"],
            serde_json::json!({ "archive": "a.zip", "from": "docs/a.txt", "to": "docs/b.txt" }),
        );
    }
}
