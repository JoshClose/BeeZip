use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built, wire::Secret};

/// Show a key as text: its public key, to share, or with `secret` its private key, for a
/// backup. Anyone who has a private key can open what it opens, or sign as you.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct KeysExportInput {
    pub name: String,
    /// The private key instead of the public one.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct KeysExportOutput {
    pub text: Secret,
}

pub struct KeysExport;

impl Command for KeysExport {
    const NAME: &'static str = "keys.export";
    const EFFECT: Effect = Effect::ReadOnly;
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = KeysExportInput;
    type Output = KeysExportOutput;

    fn run(_: KeysExportInput, _: &mut JobCtx) -> Result<KeysExportOutput, CmdError> {
        Err(not_built("keys.export"))
    }
}
