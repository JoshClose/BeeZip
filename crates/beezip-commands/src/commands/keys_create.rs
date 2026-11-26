use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CmdError, Command, Effect, JobCtx, Surfaces,
    commands::util::not_built,
    crypt::{KeyInfo, KeyKindName},
};

/// Make a key of your own: one that archives can be encrypted to (post-quantum by default), or
/// one that signs them. Its private key stays on this machine, sealed by the system.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct KeysCreateInput {
    /// What to call it.
    pub name: String,
    /// What it is for [default: post-quantum].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<KeyKindName>,
}

pub struct KeysCreate;

impl Command for KeysCreate {
    const NAME: &'static str = "keys.create";
    const EFFECT: Effect = Effect::Writes;
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = KeysCreateInput;
    type Output = KeyInfo;

    fn run(_: KeysCreateInput, _: &mut JobCtx) -> Result<KeyInfo, CmdError> {
        Err(not_built("keys.create"))
    }
}
