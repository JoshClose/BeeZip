use std::path::PathBuf;

use beezip_core::{
    CreateOptions, WriteSpec,
    ops::{self, ArchiveKind},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::{
        edit::{SpecArgs, spec_for},
        util::absolute,
    },
    wire::{ArchiveFormatName, ByteSize, EncryptionName, MethodName, Secret, human_size, ratio},
};

/// Create an archive from files and folders. Each input is stored under its own name (`src/`
/// becomes `src/…`). The format comes from `format` or the output's extension (`.zip`, `.tar`,
/// `.tar.zst`, `.tgz`…). The archive is written to a temporary file and renamed into place, so a
/// failed or cancelled create leaves nothing behind.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveCreateInput {
    /// The archive to write.
    pub output: PathBuf,
    /// Files and folders to add.
    #[arg(required = true)]
    pub inputs: Vec<PathBuf>,
    /// The archive format [default: from the output's extension].
    #[arg(short, long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ArchiveFormatName>,
    /// The compression method: for zip `store`, `deflate` (the default), `bzip2`, `zstd`, `xz`
    /// or `ppmd`; for 7z `lzma2` (the default), `lzma`, `ppmd`, `bzip2`, `deflate` or `copy`.
    /// A tar's codec comes from `format`.
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
    /// Encrypt the entries with this password (AES-256). Zip and 7z.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How to encrypt a zip [default: aes256]. `zipcrypto` is weak, for tools that can't read
    /// AES. Zip only.
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionName>,
    /// Encrypt the file names too, so the archive can't even be listed without the password
    /// [default: true with a password]. 7z only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypt_headers: Option<bool>,
    /// Compress files together in solid blocks of up to 64 MiB (or four dictionaries, at most
    /// 1 GiB): smaller archives, but reading one file decodes its block from the start
    /// [default: true]. 7z only.
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
    /// Split the archive into volumes of this size: `<output>.001`, `.002`… Bytes, or a size
    /// such as `100m`, `4g` or `700MB` (powers of 1024). At least 1 KiB.
    #[arg(short = 'v', long, value_name = "SIZE")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_size: Option<ByteSize>,
    /// Replace the output if it exists.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<bool>,
    /// Show what would be added without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveCreateOutput {
    pub path: PathBuf,
    pub format: ArchiveFormatName,
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// `bytes_out / bytes_in`.
    pub ratio: f64,
    pub dry_run: bool,
    /// The archive paths a dry run would add.
    pub plan: Option<Vec<String>>,
    /// The volumes written, first part first, when the archive was split.
    pub volumes: Option<Vec<PathBuf>>,
}

pub struct ArchiveCreate;

impl ArchiveCreate {
    fn spec(
        input: &ArchiveCreateInput,
        kind: ArchiveKind,
        cx: &JobCtx,
    ) -> Result<WriteSpec, CmdError> {
        let args = SpecArgs {
            method: input.method,
            level: input.level,
            threads: input.threads,
            password: input.password.as_ref().map(|p| p.expose().to_owned()),
            encryption: input.encryption,
            encrypt_headers: input.encrypt_headers,
            solid: input.solid,
        };
        spec_for(kind, &args, cx.config()?)
    }
}

impl Command for ArchiveCreate {
    const NAME: &'static str = "archive.create";
    const EFFECT: Effect = Effect::Writes;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "create",
        aliases: &["c"],
        group: None,
    });

    type Input = ArchiveCreateInput;
    type Output = ArchiveCreateOutput;

    fn access(input: &ArchiveCreateInput) -> Vec<Access> {
        let mut a: Vec<Access> = input.inputs.iter().cloned().map(Access::Read).collect();
        a.push(Access::Write(input.output.clone()));
        a
    }

    fn run(input: ArchiveCreateInput, cx: &mut JobCtx) -> Result<ArchiveCreateOutput, CmdError> {
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
        let spec = Self::spec(&input, kind, cx)?;
        let inputs: Vec<PathBuf> = input.inputs.iter().map(|p| absolute(p)).collect();
        let opts = CreateOptions {
            follow_links: input.follow_links.unwrap_or(false),
            exclude: input.exclude.clone().unwrap_or_default(),
            overwrite: input.overwrite.unwrap_or(false),
            volume_size: input.volume_size.as_ref().map(ByteSize::bytes),
        };
        let format = ArchiveFormatName::from_kind(kind);

        if input.dry_run.unwrap_or(false) {
            let plan = ops::plan(&inputs, &output, &opts)?;
            let bytes_in = plan.iter().map(|p| p.entry.size).sum();
            let count = |k: fn(&beezip_core::NewKind) -> bool| {
                plan.iter().filter(|p| k(&p.entry.kind)).count() as u64
            };
            return Ok(ArchiveCreateOutput {
                path: input.output,
                format,
                files: count(|k| *k == beezip_core::NewKind::File),
                dirs: count(|k| *k == beezip_core::NewKind::Dir),
                links: count(|k| matches!(k, beezip_core::NewKind::Symlink { .. })),
                bytes_in,
                bytes_out: 0,
                ratio: 1.0,
                dry_run: true,
                plan: Some(plan.into_iter().map(|p| p.entry.path).collect()),
                volumes: None,
            });
        }

        let report = ops::create(&output, &inputs, &spec, &opts, cx)?;
        Ok(ArchiveCreateOutput {
            path: input.output,
            format,
            files: report.files,
            dirs: report.dirs,
            links: report.links,
            bytes_in: report.bytes_in,
            bytes_out: report.bytes_out,
            ratio: ratio(report.bytes_in, report.bytes_out),
            dry_run: false,
            plan: None,
            volumes: (!report.volumes.is_empty()).then_some(report.volumes),
        })
    }

    fn human(out: &ArchiveCreateOutput) -> Option<String> {
        if let Some(plan) = &out.plan {
            let mut s = format!(
                "Would create {} ({}) with:\n",
                out.path.display(),
                out.format.name()
            );
            for p in plan {
                s.push_str(&format!("  {p}\n"));
            }
            s.push_str(&format!(
                "{} files, {}",
                out.files,
                human_size(out.bytes_in)
            ));
            return Some(s);
        }
        let mut s = format!(
            "Created {} ({}): {} files, {} folders, {} -> {} ({:.0}%)",
            out.path.display(),
            out.format.name(),
            out.files,
            out.dirs,
            human_size(out.bytes_in),
            human_size(out.bytes_out),
            out.ratio * 100.0
        );
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
        crate::commands::util::tests::cli_matches_json::<ArchiveCreateInput>(
            &["out.zip", "src"],
            serde_json::json!({ "output": "out.zip", "inputs": ["src"] }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveCreateInput>(
            &[
                "out.tar.zst",
                "a",
                "b",
                "-l",
                "19",
                "-L",
                "--exclude",
                "*.o",
            ],
            serde_json::json!({
                "output": "out.tar.zst", "inputs": ["a", "b"], "level": 19,
                "follow_links": true, "exclude": ["*.o"]
            }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveCreateInput>(
            &[
                "out.7z",
                "a",
                "-f",
                "7z",
                "-m",
                "ppmd",
                "--solid=false",
                "-p",
                "pw",
                "--encrypt-headers=false",
                "-v",
                "100m",
            ],
            serde_json::json!({
                "output": "out.7z", "inputs": ["a"], "format": "7z", "method": "ppmd",
                "solid": false, "password": "pw", "encrypt_headers": false, "volume_size": "100m"
            }),
        );
    }
}
