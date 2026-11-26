use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built, crypt::KeyInfo,
    wire::Secret,
};

/// Add a key: a private key (`AGE-SECRET-KEY-…`, `BZSIG-SECRET-KEY-1…`, or an age identity
/// file) becomes yours; a public key (`age1…`, `age1pq1…`, `bzsig1…`) or a certificate file
/// becomes a contact's.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct KeysImportInput {
    /// What to call it.
    pub name: String,
    /// The key as text.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<Secret>,
    /// Or a file that holds it.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
}

pub struct KeysImport;

impl Command for KeysImport {
    const NAME: &'static str = "keys.import";
    const EFFECT: Effect = Effect::Writes;
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = KeysImportInput;
    type Output = KeyInfo;

    fn run(_: KeysImportInput, _: &mut JobCtx) -> Result<KeyInfo, CmdError> {
        Err(not_built("keys.import"))
    }
}
