use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::{ArchiveTest, ArchiveTestInput, ArchiveTestOutput, archive_test::test},
    wire::Secret,
};

/// Check a `.bhive`'s signatures, and that every cell is what was signed, read to the end as
/// `archive.test` reads it. It passes when no signature failed and one is valid: from each
/// signer `require_signer` names, or without it from someone you trust (yourself, a contact,
/// or a certificate the system trusts). Fails with `SignatureRequired` when the archive isn't
/// signed that way or changed after it was signed, and `Corrupt` when a cell doesn't match
/// the digest that was signed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveVerifyInput {
    /// The archive.
    pub archive: PathBuf,
    /// The password or recovery key, for an encrypted archive none of your keys opens.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Signed, validly, by each of these: a `bzsig1…` key, a certificate file, or the name of
    /// a signing key or contact. Matched by their whole SHA-256, never a fingerprint.
    #[arg(long, value_name = "SIGNER")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_signer: Option<Vec<String>>,
}

pub struct ArchiveVerify;

impl Command for ArchiveVerify {
    const NAME: &'static str = "archive.verify";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "verify",
        aliases: &[],
        group: None,
    });

    type Input = ArchiveVerifyInput;
    type Output = ArchiveTestOutput;

    fn access(input: &ArchiveVerifyInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: ArchiveVerifyInput, cx: &mut JobCtx) -> Result<ArchiveTestOutput, CmdError> {
        test(
            ArchiveTestInput {
                archive: input.archive,
                password: input.password,
                name_encoding: None,
                recover: None,
                require_signer: input.require_signer,
            },
            true,
            cx,
        )
    }

    fn human(out: &ArchiveTestOutput) -> Option<String> {
        ArchiveTest::human(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveVerifyInput>(
            &["a.bhive", "--require-signer", "bzsig1x"],
            serde_json::json!({ "archive": "a.bhive", "require_signer": ["bzsig1x"] }),
        );
    }
}
