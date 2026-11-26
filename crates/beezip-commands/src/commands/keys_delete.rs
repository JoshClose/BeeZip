use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built};

/// Delete a key or contact. Archives only it opens can't be opened any more.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct KeysDeleteInput {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct KeysDeleteOutput {
    pub deleted: String,
}

pub struct KeysDelete;

impl Command for KeysDelete {
    const NAME: &'static str = "keys.delete";
    const EFFECT: Effect = Effect::Destructive;
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = KeysDeleteInput;
    type Output = KeysDeleteOutput;

    fn run(_: KeysDeleteInput, _: &mut JobCtx) -> Result<KeysDeleteOutput, CmdError> {
        Err(not_built("keys.delete"))
    }
}
