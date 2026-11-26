use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built, crypt::KeyInfo,
};

/// List your keys (for opening archives and for signing them) and your contacts' public keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct KeysListInput {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct KeysListOutput {
    pub keys: Vec<KeyInfo>,
}

pub struct KeysList;

impl Command for KeysList {
    const NAME: &'static str = "keys.list";
    const EFFECT: Effect = Effect::ReadOnly;
    // Hidden until PR C builds it (docs/M14.md §10).
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = KeysListInput;
    type Output = KeysListOutput;

    fn run(_: KeysListInput, _: &mut JobCtx) -> Result<KeysListOutput, CmdError> {
        Err(not_built("keys.list"))
    }
}
