use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built, crypt::CertificateInfo,
};

/// What a listed certificate is wanted for.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum CertPurposeName {
    /// Every certificate in your stores.
    #[default]
    All,
    /// Those an archive can be encrypted to.
    Encrypt,
    /// Those whose private key is here and can sign.
    Sign,
}

/// List the certificates in your stores (Personal and Other People on Windows, the Keychain on
/// macOS) that can encrypt archives or sign them, with why the others can't.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct CertificatesListInput {
    /// Which to list [default: all].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<CertPurposeName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CertificatesListOutput {
    pub certificates: Vec<CertificateInfo>,
}

pub struct CertificatesList;

impl Command for CertificatesList {
    const NAME: &'static str = "certificates.list";
    const EFFECT: Effect = Effect::ReadOnly;
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = CertificatesListInput;
    type Output = CertificatesListOutput;

    fn run(_: CertificatesListInput, _: &mut JobCtx) -> Result<CertificatesListOutput, CmdError> {
        Err(not_built("certificates.list"))
    }
}
