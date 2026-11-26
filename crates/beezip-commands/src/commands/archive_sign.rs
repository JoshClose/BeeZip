use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use std::sync::Arc;

use beezip_core::format::bhive::{BhiveWriteOptions, crypt::Protection};

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built,
    crypt::SignatureReport, protect, wire::Secret,
};

/// Sign a `.bhive`, or remove its signatures (docs/bhive.md §13). A signature says who made the
/// archive's contents and that they haven't changed since; changing who can open it keeps it,
/// changing the contents drops it. Signing an archive that has no cell digests yet reads every
/// cell once.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveSignInput {
    /// The archive.
    pub archive: PathBuf,
    /// Sign with these: your signing key by name, a certificate's thumbprint in your stores,
    /// or a certificate file with its key beside it.
    #[arg(long, value_name = "SIGNER")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<Vec<String>>,
    /// Remove these signatures, by their place in the list.
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
        if names.is_empty() && !remove_all && input.remove.is_none() {
            return Err(CmdError::invalid_args(
                "nothing to do: pass `sign` to sign it, or `remove_all` to remove its signatures",
            ));
        }
        if input.remove.is_some() {
            return Err(not_built(
                "removing some signatures and keeping the others (pass `remove_all` to remove \
                 them all)",
            ));
        }
        let signing = protect::signing(&names, cx)?;
        let threads = cx.config()?.create.threads;
        protect::rewrite_bhive(
            &input.archive,
            input.password.as_ref(),
            cx,
            |_, reader, _| {
                if !remove_all && !reader.signatures().signatures.is_empty() {
                    return Err(not_built(
                        "adding a signature beside the ones an archive has (pass `remove_all` \
                         to replace them)",
                    ));
                }
                Ok(BhiveWriteOptions {
                    threads,
                    // The archive keeps its file key and every way in (docs/M14.md §3).
                    protection: reader.unlocked().map(|u| Protection::Keep(Arc::clone(u))),
                    signing: signing.clone(),
                    ..BhiveWriteOptions::default()
                })
            },
        )?;
        Ok(ArchiveSignOutput {
            signatures: signing
                .map(|s| protect::signed_reports(&s, cx))
                .unwrap_or_default(),
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
