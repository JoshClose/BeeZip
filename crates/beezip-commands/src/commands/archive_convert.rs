use std::path::PathBuf;

use beezip_core::{ConvertOptions, Selection, WriteSpec, ops::ArchiveKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::{
        edit::{SpecArgs, spec_for},
        util::{absolute, open_options},
    },
    protect::WaysArgs,
    wire::{
        ArchiveFormatName, ByteSize, EncryptionName, LevelArg, MethodName, NameEncoding, Secret,
        human_size, ratio,
    },
};

/// Write an archive's entries to a new archive in another format, or with other options: zip,
/// bhive, 7z, tar, cpio, ar, cab, ISO, squashfs or DMG, tar and cpio under a codec too, from any archive
/// BeeZip reads (RAR, packages, disk images and split archives included). The source isn't changed. Entries are copied without decoding when the formats
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
    /// The compression level; `formats.list` shows each codec's and method's range. A .bhive's
    /// is 0 to 4, or its name: `none`, `fast`, `balanced` (the default), `high` or `max`.
    #[arg(short, long, allow_negative_numbers = true)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<LevelArg>,
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
    /// Open a .bhive whose index is missing or damaged (a download cut short) from the
    /// records before its cells, with the entries they still hold.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recover: Option<bool>,
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
    /// Sign it: your signing key by name, a certificate's thumbprint in your stores, or a
    /// certificate file with its key beside it. `.bhive` only.
    #[arg(long, value_name = "SIGNER")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<Vec<String>>,
    /// Show what would be written without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

impl ArchiveConvertInput {
    /// The ways in the new archive gets (docs/M14.md §8).
    fn ways(&self) -> WaysArgs<'_> {
        WaysArgs {
            password: self.new_password.as_ref(),
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

/// An entry the new archive couldn't hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ConvertSkipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveConvertOutput {
    /// The recovery key that was made (`recovery_key`): shown this once, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub recovery_key: Option<Secret>,
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
        if decrypt && !input.ways().is_empty() {
            return Err(CmdError::invalid_args(
                "`decrypt` writes the entries in the clear; leave out `new_password` and the \n                 other ways in",
            ));
        }
        let args = SpecArgs {
            method: input.method,
            level: input.level.and_then(LevelArg::number),
            level_name: input.level.and_then(LevelArg::name),
            threads: input.threads,
            // A .bhive's password is one of its ways in (`protection`).
            password: (kind != ArchiveKind::Bhive)
                .then(|| input.new_password.as_ref().map(|p| p.expose().to_owned()))
                .flatten(),
            encryption: input.encryption,
            encrypt_headers: input.encrypt_headers,
            solid: input.solid,
            ..SpecArgs::default()
        };
        let config = cx.config()?.clone();
        let mut spec = spec_for(kind, &args, &config)?;
        let sign = input.sign.as_deref().unwrap_or_default();
        crate::commands::archive_create::bhive_only(kind, &input.ways(), sign)?;
        // Raw copies only when nothing asks the entries to change: a .bhive's cells are then
        // copied as they are stored, sealed again under its new ways in. Its signatures don't
        // carry over yet (`sign` signs the new archive); a source's slots are kept by core when
        // no new ways in are given (docs/M14.md §3).
        let raw = input.method.is_none()
            && input.level.is_none()
            && (input.new_password.is_none() || kind == ArchiveKind::Bhive)
            && input.encryption.is_none()
            && input.encrypt_headers.is_none()
            && input.solid.is_none()
            && !decrypt;
        let mut opts = ConvertOptions {
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
        let source = absolute(&input.archive);
        let recovery_key = if opts.dry_run {
            None
        } else {
            crate::commands::archive_create::protect_spec(
                &mut spec,
                &input.ways(),
                sign,
                || {
                    crate::commands::archive_create::output_free(
                        &output,
                        opts.overwrite,
                        opts.volume_size.is_some(),
                    )?;
                    std::fs::metadata(&source).map(|_| ()).map_err(|e| {
                        beezip_core::Error::io(format!("opening {}", input.archive.display()), &e)
                            .into()
                    })
                },
                cx,
            )?
        };
        // An encrypted source into a .bhive with new ways in: its entries are opened and sealed
        // again, so core's "encrypted source" rule is met (core sees only a zip's or a 7z's
        // password as encrypting).
        if matches!(&spec, WriteSpec::Bhive(o) if o.protection.is_some()) {
            opts.decrypt = true;
        }
        if !opts.dry_run && sign.is_empty() {
            let why = if kind == ArchiveKind::Bhive {
                "won't carry over to the new archive: pass `sign` to sign it again".to_owned()
            } else {
                format!("can't go into a {}", kind.name())
            };
            crate::protect::warn_signatures_dropped(&source, &why, cx);
        }
        cx.set_password(input.password.as_ref());
        let open_opts = open_options(
            crate::commands::util::Opening::new(input.name_encoding, input.recover),
            cx,
        );
        let r = beezip_core::ops::convert(&source, &output, kind, &spec, &opts, &open_opts, cx)?;
        Ok(ArchiveConvertOutput {
            recovery_key,
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
