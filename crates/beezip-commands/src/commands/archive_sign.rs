use std::path::PathBuf;

use beezip_core::edit::sign::{SignOptions, sign};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx, Surfaces,
    commands::util::{absolute, open_options},
    crypt::SignatureReport,
    protect,
    wire::Secret,
};

/// Sign a `.bhive`, or remove its signatures (docs/bhive.md §13). A signature says who made the
/// archive's contents and that they haven't changed since; changing who can open it keeps it,
/// changing the contents drops it. Signing reads every cell once, to make its digests or to
/// check the cells against them.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveSignInput {
    /// The archive.
    pub archive: PathBuf,
    /// Sign with these: your signing key by name, a certificate's thumbprint in your stores,
    /// a certificate file with its key beside it, or a `.pfx` (Windows, macOS).
    #[arg(long, value_name = "SIGNER")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<Vec<String>>,
    /// Remove these signatures, by their place in the list `archive.info` shows, from 1.
    #[arg(long, value_name = "N")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<Vec<u32>>,
    /// Remove every signature.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_all: Option<bool>,
    /// The password or recovery key, for an encrypted archive none of your keys opens.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveSignOutput {
    /// The archive's signatures afterwards.
    pub signatures: Vec<SignatureReport>,
}

pub struct ArchiveSign;

impl Command for ArchiveSign {
    const NAME: &'static str = "archive.sign";
    const EFFECT: Effect = Effect::Destructive;
    // Never over MCP: a signature says that you made the archive (docs/M14.md decision 27).
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "sign",
        aliases: &[],
        group: None,
    });

    type Input = ArchiveSignInput;
    type Output = ArchiveSignOutput;

    fn access(input: &ArchiveSignInput) -> Vec<Access> {
        vec![Access::Write(input.archive.clone())]
    }

    fn run(input: ArchiveSignInput, cx: &mut JobCtx) -> Result<ArchiveSignOutput, CmdError> {
        let names = input.sign.clone().unwrap_or_default();
        let remove_all = input.remove_all.unwrap_or(false);
        let places = input.remove.clone().unwrap_or_default();
        if names.is_empty() && !remove_all && places.is_empty() {
            return Err(CmdError::invalid_args(
                "nothing to do: pass `sign` to sign it, `remove` to remove some of its \
                 signatures, or `remove_all` to remove them all",
            ));
        }
        if places.contains(&0) {
            return Err(CmdError::invalid_args(
                "signatures are numbered from 1, as `archive.info` lists them",
            ));
        }
        let remove = places.iter().map(|&n| n as usize - 1).collect();
        let signing = protect::signing(&names, cx)?.unwrap_or_default();
        let path = absolute(&input.archive);
        let canonical = std::fs::canonicalize(&path).map_err(|e| {
            CmdError::from(beezip_core::Error::io(
                format!("opening {}", input.archive.display()),
                &e,
            ))
        })?;
        let _guard = cx.edit_lock(&canonical)?;
        cx.set_password(input.password.as_ref());
        cx.set_archive(&path);
        let opts = SignOptions {
            open: open_options(None, cx),
            signing,
            remove,
            remove_all,
        };
        let report = sign(&path, &opts, cx);
        // The cache forgets the archive once it has changed, or once a change of it failed.
        if let Some(cache) = cx.cache() {
            cache.evict(&canonical);
        }
        let report = report?;
        Ok(ArchiveSignOutput {
            signatures: protect::reports(&report.signatures, cx),
        })
    }

    fn human(out: &ArchiveSignOutput) -> Option<String> {
        if out.signatures.is_empty() {
            return Some("not signed".into());
        }
        Some(
            protect::signatures_text(&out.signatures)
                .trim_start()
                .to_owned(),
        )
    }
}
