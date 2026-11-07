use std::path::PathBuf;

use beezip_core::{ConvertOptions, Selection, ops::ArchiveKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::{
        edit::{SpecArgs, spec_for},
        util::{absolute, open_options},
    },
    wire::{
        ArchiveFormatName, ByteSize, EncryptionName, MethodName, NameEncoding, Secret, human_size,
        ratio,
    },
};

/// Write an archive's entries to a new archive in another format, or with other options: zip,
/// 7z, tar, cpio, ar or cab, tar and cpio under a codec too, from any archive BeeZip reads (RAR,
/// packages and split archives included). The source isn't changed. Entries are copied without decoding when the formats
/// match and no option asks for something else (`a.tar.gz` → `a.tar.zst` keeps every tar
/// entry, encoding the stream again). An encrypted source needs `new_password` or `decrypt`:
/// encryption is never dropped silently. What the new format can't hold is left out and
/// reported in `skipped`; hard links become files where the format has none.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveConvertInput {
    /// The archive to convert.
    pub archive: PathBuf,
    /// The archive to write.
    pub output: PathBuf,
    /// Entries to convert (a folder takes everything under it). All when none are given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,
    /// Only entries matching these patterns.
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<Vec<String>>,
    /// Leave out entries matching these patterns.
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    /// The new archive's format [default: from the output's extension].
    #[arg(short, long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ArchiveFormatName>,
    /// The compression method, as for `archive.create`.
    #[arg(short, long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<MethodName>,
    /// The compression level; `formats.list` shows each codec's and method's range.
    #[arg(short, long, allow_negative_numbers = true)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<i32>,
    /// Compression threads for codecs that have them; 0 is one per core [default: from config].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<u32>,
    /// The source's password, if it is encrypted.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Encrypt the new archive with this password (zip, 7z).
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_password: Option<Secret>,
    /// How to encrypt a new zip [default: aes256]. Zip only.
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionName>,
    /// Encrypt the new 7z's names too [default: true with a password]. 7z only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypt_headers: Option<bool>,
    /// Write an encrypted source's entries in the clear.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypt: Option<bool>,
    /// Compress files together in solid blocks [default: true]. 7z only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solid: Option<bool>,
    /// Split the new archive into volumes of this size: `<output>.001`, `.002`…
    #[arg(short = 'v', long, value_name = "SIZE")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_size: Option<ByteSize>,
    /// Replace the output if it exists.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<bool>,
    /// How the source's names stored as bytes are read [default: from config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
    /// Show what would be written without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

/// An entry the new archive couldn't hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ConvertSkipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveConvertOutput {
    pub path: PathBuf,
    pub format: ArchiveFormatName,
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    /// The source's size.
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// `bytes_out / bytes_in`.
    pub ratio: f64,
    /// Entries copied as they were, without decoding.
    pub copied: u64,
    /// Entries decoded and encoded again.
    pub recompressed: u64,
    /// Entries the new format can't hold, left out.
    pub skipped: Vec<ConvertSkipped>,
    pub dry_run: bool,
    /// The entries a dry run would write.
    pub plan: Option<Vec<String>>,
    /// The volumes written, first part first, when the archive was split.
    pub volumes: Option<Vec<PathBuf>>,
}

pub struct ArchiveConvert;

impl Command for ArchiveConvert {
    const NAME: &'static str = "archive.convert";
    const EFFECT: Effect = Effect::Writes;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "convert",
        aliases: &[],
        group: None,
    });

    type Input = ArchiveConvertInput;
    type Output = ArchiveConvertOutput;

    fn access(input: &ArchiveConvertInput) -> Vec<Access> {
        vec![
            Access::Read(input.archive.clone()),
            Access::Write(input.output.clone()),
        ]
    }

    fn run(input: ArchiveConvertInput, cx: &mut JobCtx) -> Result<ArchiveConvertOutput, CmdError> {
        let output = absolute(&input.output);
        let kind = match input.format {
            Some(f) => f.kind(),
            None => {
                let name = output
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                ArchiveKind::from_file_name(&name).ok_or_else(|| {
                    CmdError::invalid_args(format!(
                        "can't tell the format from `{name}`; pass `format` (zip, 7z, tar, tar.zst…)"
                    ))
                })?
            }
        };
        let decrypt = input.decrypt.unwrap_or(false);
        if decrypt && input.new_password.is_some() {
            return Err(CmdError::invalid_args(
                "`decrypt` writes the entries in the clear; leave out `new_password`",
            ));
        }
        let args = SpecArgs {
            method: input.method,
            level: input.level,
            threads: input.threads,
            password: input.new_password.as_ref().map(|p| p.expose().to_owned()),
            encryption: input.encryption,
            encrypt_headers: input.encrypt_headers,
            solid: input.solid,
        };
        let config = cx.config()?.clone();
        let spec = spec_for(kind, &args, &config)?;
        // Raw copies only when nothing asks the entries to change.
        let raw = input.method.is_none()
            && input.level.is_none()
            && input.new_password.is_none()
            && input.encryption.is_none()
            && input.encrypt_headers.is_none()
            && input.solid.is_none()
            && !decrypt;
        let opts = ConvertOptions {
            selection: Selection::new(
                input.entries.as_deref().unwrap_or_default(),
                input.glob.as_deref().unwrap_or_default(),
                input.exclude.as_deref().unwrap_or_default(),
            )?,
            raw,
            overwrite: input.overwrite.unwrap_or(false),
            volume_size: input.volume_size.as_ref().map(ByteSize::bytes),
            decrypt,
            dry_run: input.dry_run.unwrap_or(false),
        };
        cx.set_password(input.password.as_ref());
        let open_opts = open_options(input.name_encoding, cx);
        let r = beezip_core::ops::convert(
            &absolute(&input.archive),
            &output,
            kind,
            &spec,
            &opts,
            &open_opts,
            cx,
        )?;
        Ok(ArchiveConvertOutput {
            path: input.output,
            format: ArchiveFormatName::from_kind(kind),
            files: r.files,
            dirs: r.dirs,
            links: r.links,
            bytes_in: r.bytes_in,
            bytes_out: r.bytes_out,
            ratio: ratio(r.bytes_in, r.bytes_out),
            copied: r.copied,
            recompressed: r.recompressed,
            skipped: r
                .skipped
                .into_iter()
                .map(|s| ConvertSkipped {
                    path: s.path,
                    reason: s.reason,
                })
                .collect(),
            dry_run: opts.dry_run,
            plan: opts.dry_run.then_some(r.plan),
            volumes: (!r.volumes.is_empty()).then_some(r.volumes),
        })
    }

    fn human(out: &ArchiveConvertOutput) -> Option<String> {
        if let Some(plan) = &out.plan {
            let mut s = format!(
                "Would write {} ({}) with:\n",
                out.path.display(),
                out.format.name()
            );
            for p in plan {
                s.push_str(&format!("  {p}\n"));
            }
            return Some(s.trim_end().to_owned());
        }
        let mut s = format!(
            "Converted to {} ({}): {} files, {} folders, {} -> {}",
            out.path.display(),
            out.format.name(),
            out.files,
            out.dirs,
            human_size(out.bytes_in),
            human_size(out.bytes_out),
        );
        match (out.copied, out.recompressed) {
            (0, 0) => {}
            (c, 0) => s.push_str(&format!(" ({c} entries copied as they were)")),
            (0, r) => s.push_str(&format!(" ({r} entries recompressed)")),
            (c, r) => s.push_str(&format!(" ({c} copied as they were, {r} recompressed)")),
        }
        if !out.skipped.is_empty() {
            s.push_str(&format!("\n  {} entries left out:", out.skipped.len()));
            for k in out.skipped.iter().take(20) {
                s.push_str(&format!("\n    {} ({})", k.path, k.reason));
            }
        }
        if let Some(v) = &out.volumes {
            let first = v
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            s.push_str(&format!("\n  in {} volumes, from {first}", v.len()));
        }
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveConvertInput>(
            &["a.zip", "a.tar.zst"],
            serde_json::json!({ "archive": "a.zip", "output": "a.tar.zst" }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveConvertInput>(
            &[
                "a.7z",
                "b.zip",
                "docs",
                "-p",
                "old",
                "--new-password",
                "new",
                "--encryption",
                "zipcrypto",
                "--overwrite",
            ],
            serde_json::json!({
                "archive": "a.7z", "output": "b.zip", "entries": ["docs"], "password": "old",
                "new_password": "new", "encryption": "zipcrypto", "overwrite": true
            }),
        );
    }
}
