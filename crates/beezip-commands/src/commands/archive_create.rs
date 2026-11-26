use std::path::{Path, PathBuf};

use beezip_core::{
    CreateOptions, WriteSpec,
    format::bhive::crypt::Protection,
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
    protect::{self, WaysArgs},
    wire::{
        ArchiveFormatName, ByteSize, EncryptionName, LevelArg, MethodName, Secret, human_size,
        ratio,
    },
};

/// Create an archive from files and folders. Each input is stored under its own name (`src/`
/// becomes `src/…`). The format comes from `format` or the output's extension (`.zip`,
/// `.bhive`, `.7z`, `.tar`, `.tar.zst`, `.tgz`, `.cpio.gz`, `.ar`, `.cab`, `.iso`, `.squashfs`,
/// `.dmg`…); ar and cab hold files only. A `.bhive` is BeeZip's own format: it stores
/// repeated content once, reads any file without decoding the rest, and uses every core. An ISO has Joliet and Rock Ridge, a DMG is an HFS+ volume in a
/// zlib-compressed image. The archive is written to a temporary file and renamed into place,
/// so a failed or cancelled create leaves nothing behind.
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
    /// or `ppmd`; for 7z `lzma2` (the default), `lzma`, `ppmd`, `bzip2`, `deflate` or `copy`; for
    /// cab `mszip` (the default) or `store`; for squashfs `gzip` (the default), `xz`, `zstd`,
    /// `lz4` or `lzo`. A tar's or cpio's codec comes from `format`.
    #[arg(short, long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<MethodName>,
    /// The compression level; `formats.list` shows each codec's and method's range. A .bhive's
    /// is 0 to 4, or its name: `none`, `fast`, `balanced` (the default), `high` or `max`.
    #[arg(short, long, allow_negative_numbers = true)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<LevelArg>,
    /// Compression threads for codecs that have them; 0 is one per core [default: from config].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<u32>,
    /// Encrypt with this password (AES-256): a zip's or 7z's entries, or a whole .bhive,
    /// names and all.
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
    /// Make a recovery key that opens the archive, shown once in the output: 48 digits to keep
    /// somewhere safe. `.bhive` only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<bool>,
    /// Encrypt to these public keys, so their owners open it with their private keys:
    /// `age1…`, `age1pq1…`, or a contact's name. `.bhive` only.
    #[arg(long, value_name = "KEY")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Encrypt to these certificates: a thumbprint in your stores, or a certificate file.
    /// `.bhive` only.
    #[arg(long, value_name = "CERT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_cert: Option<Vec<String>>,
    /// Let this PC open it, with a key in its TPM. Needs another way in that works elsewhere.
    /// `.bhive` on Windows.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_pc: Option<bool>,
    /// A PIN for the This PC key, which the TPM protects against guessing.
    #[arg(long, value_name = "PIN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_pc_pin: Option<Secret>,
    /// Let a security key open it: Windows asks for a touch. `.bhive` on Windows.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_key: Option<bool>,
    /// Let Windows Hello open it (a face, a fingerprint or its PIN). It works only on this PC,
    /// so it needs another way in that works elsewhere. `.bhive` on Windows.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_hello: Option<bool>,
    /// How hard a `.bhive`'s password makes guessing [default: standard].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strength: Option<crate::crypt::StrengthName>,
    /// Sign it: your signing key by name, a certificate's thumbprint in your stores, a
    /// certificate file with its key beside it, or a `.pfx` (Windows, macOS). `.bhive` only.
    #[arg(long, value_name = "SIGNER")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<Vec<String>>,
    /// Show what would be added without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

impl ArchiveCreateInput {
    /// The ways in it asks for (docs/M14.md §8).
    fn ways(&self) -> WaysArgs<'_> {
        WaysArgs {
            password: self.password.as_ref(),
            recovery_key: self.recovery_key.unwrap_or(false),
            to: self.to.as_deref().unwrap_or_default(),
            to_cert: self.to_cert.as_deref().unwrap_or_default(),
            this_pc: self.this_pc.unwrap_or(false),
            this_pc_pin: self.this_pc_pin.as_ref(),
            security_key: self.security_key.unwrap_or(false),
            windows_hello: self.windows_hello.unwrap_or(false),
            strength: self.strength,
            kept: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveCreateOutput {
    /// The recovery key that was made (`recovery_key`): shown this once, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub recovery_key: Option<Secret>,
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

/// Refuses a `.bhive`'s options for another format, naming the first one given.
pub(crate) fn bhive_only(
    kind: ArchiveKind,
    ways: &WaysArgs<'_>,
    sign: &[String],
) -> Result<(), CmdError> {
    if kind == ArchiveKind::Bhive {
        return Ok(());
    }
    let option = ways
        .bhive_only()
        .or_else(|| (!sign.is_empty()).then_some("sign"));
    match option {
        Some(option) => Err(CmdError::invalid_args(format!(
            "`{option}` is for a .bhive; a {} can't hold it",
            kind.name()
        ))),
        None => Ok(()),
    }
}

/// Puts the ways in and the signers into a `.bhive`'s write options, making what they need
/// (a recovery key, then a security key's touch or Windows Hello, then a This PC key), once
/// `ready` has checked what can be checked before; the recovery key, to show once.
pub(crate) fn protect_spec(
    spec: &mut WriteSpec,
    ways: &WaysArgs<'_>,
    sign: &[String],
    ready: impl FnOnce() -> Result<(), CmdError>,
    cx: &mut JobCtx,
) -> Result<Option<Secret>, CmdError> {
    let WriteSpec::Bhive(o) = spec else {
        return Ok(None);
    };
    // Signers first: nothing is made for an archive that can't be signed.
    o.signing = protect::signing(sign, cx)?;
    let mut made = protect::ways(ways, cx)?;
    if made.recipients.is_empty() && made.devices.is_empty() {
        return Ok(None);
    }
    // Decision 11 on every way in, devices included, before any is asked.
    made.check()?;
    if !made.devices.is_empty() {
        ready()?;
        made.make_devices(cx)?;
    }
    o.protection = Some(Protection::New(made.recipients));
    Ok(made.recovery_key)
}

/// `Conflict` when `output` is in the way of a new archive, as core says it, before a device
/// is asked for a way into an archive that couldn't be written.
pub(crate) fn output_free(output: &Path, overwrite: bool, split: bool) -> Result<(), CmdError> {
    if !split && !overwrite && std::fs::symlink_metadata(output).is_ok() {
        return Err(CmdError::new(
            crate::ErrorCode::Conflict,
            format!("`{}` already exists", output.display()),
        ));
    }
    Ok(())
}

/// How the CLI shows a recovery key that was made.
pub(crate) fn recovery_key_text(key: &Secret) -> String {
    format!(
        "\nRecovery key: {}\n  It opens the archive if every other way in is lost. It is shown \
         only this once: keep it somewhere safe, apart from the archive.",
        key.expose()
    )
}

impl ArchiveCreate {
    fn spec(
        input: &ArchiveCreateInput,
        kind: ArchiveKind,
        cx: &JobCtx,
    ) -> Result<WriteSpec, CmdError> {
        let args = SpecArgs {
            method: input.method,
            level: input.level.and_then(LevelArg::number),
            level_name: input.level.and_then(LevelArg::name),
            threads: input.threads,
            // A .bhive's password is one of its ways in (`protection`).
            password: (kind != ArchiveKind::Bhive)
                .then(|| input.password.as_ref().map(|p| p.expose().to_owned()))
                .flatten(),
            encryption: input.encryption,
            encrypt_headers: input.encrypt_headers,
            solid: input.solid,
            ..SpecArgs::default()
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
        let mut spec = Self::spec(&input, kind, cx)?;
        let sign = input.sign.as_deref().unwrap_or_default();
        bhive_only(kind, &input.ways(), sign)?;
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
                recovery_key: None,
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

        let recovery_key = protect_spec(
            &mut spec,
            &input.ways(),
            sign,
            || output_free(&output, opts.overwrite, opts.volume_size.is_some()),
            cx,
        )?;
        let report = ops::create(&output, &inputs, &spec, &opts, cx)?;
        Ok(ArchiveCreateOutput {
            recovery_key,
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
        if let Some(key) = &out.recovery_key {
            s.push_str(&recovery_key_text(key));
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
