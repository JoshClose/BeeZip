use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CmdError, Command, Effect, JobCtx, Surfaces, commands::util::not_built, crypt::WayIn,
    wire::Secret,
};

/// List the ways into an encrypted `.bhive` (passwords, recovery keys, keys, certificates,
/// This PC, security keys), with their labels, and say whether it resists quantum computers.
/// Needs a way in: the archive's descriptions of its ways in are encrypted too.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveProtectionInput {
    /// The archive.
    pub archive: PathBuf,
    /// The password or recovery key that opens it, if none of your keys does.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveProtectionOutput {
    pub encrypted: bool,
    pub ways: Vec<WayIn>,
    /// Every way in is post-quantum: a quantum computer couldn't open the archive.
    pub post_quantum: bool,
}

pub struct ArchiveProtection;

impl Command for ArchiveProtection {
    const NAME: &'static str = "archive.protection";
    const EFFECT: Effect = Effect::ReadOnly;
    // Hidden until PR F builds it (docs/M14.md §10).
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = ArchiveProtectionInput;
    type Output = ArchiveProtectionOutput;

    fn access(input: &ArchiveProtectionInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(_: ArchiveProtectionInput, _: &mut JobCtx) -> Result<ArchiveProtectionOutput, CmdError> {
        Err(not_built("archive.protection"))
    }
}
