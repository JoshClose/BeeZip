use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::keys_list::{keys_dir, store};
use crate::{CliSpec, CmdError, Command, Effect, JobCtx, Surfaces, policy::Access};

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
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "delete",
        aliases: &[],
        group: Some("keys"),
    });

    type Input = KeysDeleteInput;
    type Output = KeysDeleteOutput;

    fn run(input: KeysDeleteInput, cx: &mut JobCtx) -> Result<KeysDeleteOutput, CmdError> {
        // The name as it is kept, whatever case and spaces it was given with.
        let deleted = store(cx)?.delete(&input.name)?.name;
        Ok(KeysDeleteOutput { deleted })
    }

    fn human(out: &KeysDeleteOutput) -> Option<String> {
        Some(format!("Deleted `{}`.", out.deleted))
    }

    fn access(_: &KeysDeleteInput) -> Vec<Access> {
        keys_dir().map(Access::Write).into_iter().collect()
    }
}
