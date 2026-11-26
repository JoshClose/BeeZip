use beezip_keys::identity::KeyKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::keys_list::{info, keys_dir, kind_label, store};
use crate::{
    CliSpec, CmdError, Command, Effect, JobCtx, Surfaces,
    crypt::{KeyInfo, KeyKindName},
    policy::Access,
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
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "create",
        aliases: &[],
        group: Some("keys"),
    });

    type Input = KeysCreateInput;
    type Output = KeyInfo;

    fn run(input: KeysCreateInput, cx: &mut JobCtx) -> Result<KeyInfo, CmdError> {
        let kind = match input.kind.unwrap_or_default() {
            KeyKindName::PostQuantum => KeyKind::XWing,
            KeyKindName::Classic => KeyKind::X25519,
            KeyKindName::Signing => KeyKind::Signing,
        };
        Ok(info(store(cx)?.create(&input.name, kind)?))
    }

    fn human(out: &KeyInfo) -> Option<String> {
        Some(made(out, "Made"))
    }

    fn access(_: &KeysCreateInput) -> Vec<Access> {
        keys_dir().map(Access::Write).into_iter().collect()
    }
}

/// What `keys.create` and `keys.import` print: the key, and its public key to share.
pub(crate) fn made(out: &KeyInfo, verb: &str) -> String {
    let whose = if out.own { "your" } else { "a contact's" };
    format!(
        "{verb} `{}`, {whose} {} key, fingerprint {}.\nIts public key, to share:\n{}",
        out.name,
        kind_label(out.kind),
        out.fingerprint,
        out.public
    )
}
