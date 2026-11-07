use std::path::PathBuf;

use beezip_core::{AddOptions, CreateOptions, EditOp};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::{
        edit::{EditOutput, SpecArgs, human, run_edit},
        util::absolute,
    },
    wire::{EncryptionName, MethodName, NameEncoding, OverwritePolicy, Secret},
};

/// Add files and folders to an archive (zip, 7z, tar and tar under any codec). Each input is
/// stored under its own name, as `archive.create` stores them, in `dir` if given. The archive
/// isn't written in place: a new one is written beside it and swapped in, so a failed or
/// cancelled add leaves it as it was. Entries that stay are copied without decoding. An archive
/// whose entries are encrypted needs a password for the new files, unless `unencrypted`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveAddInput {
    /// The archive to add to.
    pub archive: PathBuf,
    /// Files and folders to add.
    #[arg(required = true)]
    pub inputs: Vec<PathBuf>,
    /// The folder inside the archive to add into [default: the top].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// What to do when the archive has an entry with a new file's path (ignoring case on
    /// Windows): `ask`, `always` (replace it), `never` (keep it), `newer` (replace it if the
    /// file is newer) or `rename` (add the file as `a (1).txt`) [default: from config, `ask`].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<OverwritePolicy>,
    /// The compression method for the new files and any 7z block encoded again: for zip
    /// `store`, `deflate` (the default), `bzip2`, `zstd`, `xz` or `ppmd`; for 7z `lzma2` (the
    /// default), `lzma`, `ppmd`, `bzip2`, `deflate` or `copy`. A tar keeps its codec.
    #[arg(short, long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<MethodName>,
    /// The compression level, for the new files, or a compressed tar's stream.
    #[arg(short, long, allow_negative_numbers = true)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<i32>,
    /// Compression threads for codecs that have them; 0 is one per core [default: from config].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<u32>,
    /// Encrypt the new files with this password (zip, 7z). It also reads a 7z whose names are
    /// encrypted.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How to encrypt a zip's new files [default: aes256]. Zip only.
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionName>,
    /// Add the new files in the clear to an archive whose entries are encrypted.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unencrypted: Option<bool>,
    /// Compress the new files together in solid blocks [default: true]. 7z only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solid: Option<bool>,
    /// Leave out files and folders matching these patterns.
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    /// Store what symlinks point to instead of the links.
    #[arg(short = 'L', long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_links: Option<bool>,
    /// How names stored as bytes are read, so `dir` matches them as listed [default: from
    /// config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
    /// Show what would change without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

pub struct ArchiveAdd;

impl Command for ArchiveAdd {
    const NAME: &'static str = "archive.add";
    const EFFECT: Effect = Effect::Destructive;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "add",
        aliases: &["a"],
        group: None,
    });

    type Input = ArchiveAddInput;
    type Output = EditOutput;

    fn access(input: &ArchiveAddInput) -> Vec<Access> {
        let mut a: Vec<Access> = input.inputs.iter().cloned().map(Access::Read).collect();
        a.push(Access::Write(input.archive.clone()));
        a
    }

    fn run(input: ArchiveAddInput, cx: &mut JobCtx) -> Result<EditOutput, CmdError> {
        let config = cx.config()?.clone();
        let op = EditOp::Add(AddOptions {
            inputs: input.inputs.iter().map(|p| absolute(p)).collect(),
            dir: input.dir.clone().unwrap_or_default(),
            overwrite: input.overwrite.unwrap_or(config.edit.overwrite).into(),
            create: CreateOptions {
                follow_links: input.follow_links.unwrap_or(false),
                exclude: input.exclude.clone().unwrap_or_default(),
                ..CreateOptions::default()
            },
            unencrypted: input.unencrypted.unwrap_or(false),
        });
        if input.unencrypted == Some(true) && input.password.is_some() {
            return Err(CmdError::invalid_args(
                "`unencrypted` adds the files in the clear; leave out `password`",
            ));
        }
        let args = SpecArgs {
            method: input.method,
            level: input.level,
            threads: input.threads,
            password: input.password.as_ref().map(|p| p.expose().to_owned()),
            encryption: input.encryption,
            encrypt_headers: None,
            solid: input.solid,
        };
        run_edit(
            &input.archive,
            &op,
            &args,
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
        crate::commands::util::tests::cli_matches_json::<ArchiveAddInput>(
            &["a.zip", "src"],
            serde_json::json!({ "archive": "a.zip", "inputs": ["src"] }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveAddInput>(
            &[
                "a.7z",
                "a",
                "b",
                "--dir",
                "docs",
                "--overwrite",
                "rename",
                "-m",
                "ppmd",
                "--solid=false",
                "--unencrypted",
                "--dry-run",
            ],
            serde_json::json!({
                "archive": "a.7z", "inputs": ["a", "b"], "dir": "docs", "overwrite": "rename",
                "method": "ppmd", "solid": false, "unencrypted": true, "dry_run": true
            }),
        );
    }
}
