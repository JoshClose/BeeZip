use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{CliSpec, CmdError, Command, Effect, JobCtx};

/// Show the BeeZip version and build information.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct AppVersionInput {}

/// The BeeZip version and how this binary was built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AppVersionOutput {
    /// The workspace version, e.g. `0.1.0`.
    pub version: String,
    /// The git commit, when the build set `BEEZIP_GIT_SHA` (CI does).
    pub commit: Option<String>,
    /// `<os>-<arch>`, e.g. `windows-x86_64`.
    pub platform: String,
    /// `debug` or `release` (CI drill: this doc change is not regenerated).
    pub profile: String,
}

pub struct AppVersion;

impl Command for AppVersion {
    const NAME: &'static str = "app.version";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "version",
        aliases: &[],
    });

    type Input = AppVersionInput;
    type Output = AppVersionOutput;

    fn run(_input: AppVersionInput, _cx: &mut JobCtx) -> Result<AppVersionOutput, CmdError> {
        Ok(AppVersionOutput {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: option_env!("BEEZIP_GIT_SHA").map(str::to_owned),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .to_owned(),
        })
    }

    fn human(out: &AppVersionOutput) -> Option<String> {
        let commit = out
            .commit
            .as_deref()
            .map(|c| format!(", {}", &c[..c.len().min(12)]))
            .unwrap_or_default();
        Some(format!(
            "BeeZip {} ({}, {}{commit})",
            out.version, out.platform, out.profile
        ))
    }
}
