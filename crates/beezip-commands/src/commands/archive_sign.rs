use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built,
    crypt::SignatureReport, wire::Secret,
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
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = ArchiveSignInput;
    type Output = ArchiveSignOutput;

    fn access(input: &ArchiveSignInput) -> Vec<Access> {
        vec![Access::Write(input.archive.clone())]
    }

    fn run(_: ArchiveSignInput, _: &mut JobCtx) -> Result<ArchiveSignOutput, CmdError> {
        Err(not_built("archive.sign"))
    }
}
