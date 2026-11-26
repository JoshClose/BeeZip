use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::keys_list::{keys_dir, store};
use crate::{
    CliSpec, CmdError, Command, Effect, JobCtx, LogLevel, Surfaces, policy::Access, wire::Secret,
};

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
    // Never to an assistant: a private key would pass through its context (decision 15).
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "export",
        aliases: &[],
        group: Some("keys"),
    });

    type Input = KeysExportInput;
    type Output = KeysExportOutput;

    fn run(input: KeysExportInput, cx: &mut JobCtx) -> Result<KeysExportOutput, CmdError> {
        let secret = input.secret.unwrap_or(false);
        let text = store(cx)?.export(&input.name, secret)?;
        if secret {
            cx.log(
                LogLevel::Warn,
                "this is your private key: anyone who has it can open what it opens, or sign \
                 as you. Keep it somewhere safe and never share it",
            );
        }
        Ok(KeysExportOutput {
            text: Secret::new(text.as_str()),
        })
    }

    /// Only the text, so that `beezip keys export NAME > key.txt` writes the key.
    fn human(out: &KeysExportOutput) -> Option<String> {
        Some(out.text.expose().to_owned())
    }

    fn access(_: &KeysExportInput) -> Vec<Access> {
        keys_dir().map(Access::Read).into_iter().collect()
    }
}
