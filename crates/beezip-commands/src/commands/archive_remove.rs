use std::path::PathBuf;

use beezip_core::{EditOp, Selection};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::edit::{EditOutput, SpecArgs, human, run_edit},
    wire::{NameEncoding, Secret},
};

/// Remove entries from an archive (zip, 7z, tar and tar under any codec). A folder takes
/// everything under it. A new archive is written beside the old one and swapped in, so a failed
/// or cancelled removal leaves it as it was; the entries that stay are copied without decoding,
/// except the rest of a 7z solid block that loses one, which is encoded again. Fails with
/// `NotFound` when nothing matches.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveRemoveInput {
    /// The archive.
    pub archive: PathBuf,
    /// Entries to remove (a folder takes everything under it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,
    /// Also remove entries matching these patterns. Without `/` a pattern matches a name at any
    /// depth (`*.tmp`); with `/` the whole path (`build/**/*.o`).
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<Vec<String>>,
    /// Keep entries matching these patterns, even if `entries` or `glob` take them.
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    /// The password, if entry names need one (a 7z with encrypted names), or a 7z block that is
    /// encoded again does.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How names stored as bytes are read, so `entries` match them as listed [default: from
    /// config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
    /// Show what would be removed without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

pub struct ArchiveRemove;

impl Command for ArchiveRemove {
    const NAME: &'static str = "archive.remove";
    const EFFECT: Effect = Effect::Destructive;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "remove",
        aliases: &["d"],
        group: None,
    });

    type Input = ArchiveRemoveInput;
    type Output = EditOutput;

    fn access(input: &ArchiveRemoveInput) -> Vec<Access> {
        vec![Access::Write(input.archive.clone())]
    }

    fn run(input: ArchiveRemoveInput, cx: &mut JobCtx) -> Result<EditOutput, CmdError> {
        let entries = input.entries.clone().unwrap_or_default();
        let glob = input.glob.clone().unwrap_or_default();
        if entries
            .iter()
            .all(|e| e.trim_matches(['/', '\\', '.']).is_empty())
            && glob.is_empty()
        {
            return Err(CmdError::invalid_args(
                "say what to remove: entries, or `glob` patterns",
            ));
        }
        let sel = Selection::new(
            &entries,
            &glob,
            input.exclude.as_deref().unwrap_or_default(),
        )?;
        run_edit(
            &input.archive,
            &EditOp::Remove(sel),
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
        crate::commands::util::tests::cli_matches_json::<ArchiveRemoveInput>(
            &["a.zip", "docs"],
            serde_json::json!({ "archive": "a.zip", "entries": ["docs"] }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveRemoveInput>(
            &[
                "a.zip",
                "--glob",
                "*.tmp",
                "--exclude",
                "keep/*",
                "--dry-run",
            ],
            serde_json::json!({
                "archive": "a.zip", "glob": ["*.tmp"], "exclude": ["keep/*"], "dry_run": true
            }),
        );
    }
}
