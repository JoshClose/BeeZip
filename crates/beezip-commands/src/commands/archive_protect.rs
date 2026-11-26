use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CmdError, Command, Effect, JobCtx, Surfaces,
    commands::util::not_built,
    crypt::{StrengthName, WayIn},
    wire::Secret,
};

/// Change who can open an encrypted `.bhive`, without recompressing it: add ways in, remove
/// them, or make a new file key, which seals every cell again and rebuilds every slot.
/// Removing a way in isn't revoking it: someone who opened the archive before could have kept
/// its key; a new key is what shuts them out of later versions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveProtectInput {
    /// The archive.
    pub archive: PathBuf,
    /// The password or recovery key that opens it, if none of your keys does.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Add a password.
    #[arg(long, value_name = "PASSWORD")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_password: Option<Secret>,
    /// Add a recovery key, shown once in the output.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<bool>,
    /// Add public keys: `age1…`, `age1pq1…`, or a contact's name.
    #[arg(long, value_name = "KEY")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Add certificates: a thumbprint in your stores, or a certificate file.
    #[arg(long, value_name = "CERT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_cert: Option<Vec<String>>,
    /// Add this PC (a key in its TPM). Windows only; needs another way in that works
    /// elsewhere.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_pc: Option<bool>,
    /// A PIN for the This PC key, which the TPM protects against guessing.
    #[arg(long, value_name = "PIN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_pc_pin: Option<Secret>,
    /// Add a security key or Windows Hello: Windows asks for a touch. Windows only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_key: Option<bool>,
    /// How hard an added password makes guessing [default: standard].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strength: Option<StrengthName>,
    /// Remove these ways in, by slot, as `archive.protection` lists them.
    #[arg(long, value_name = "SLOT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<Vec<u32>>,
    /// Make a new file key: every cell sealed again, every slot rebuilt.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_key: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveProtectOutput {
    pub ways: Vec<WayIn>,
    pub post_quantum: bool,
    /// A recovery key that was added: shown this once, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub recovery_key: Option<Secret>,
}

pub struct ArchiveProtect;

impl Command for ArchiveProtect {
    const NAME: &'static str = "archive.protect";
    const EFFECT: Effect = Effect::Destructive;
    const SURFACES: Surfaces = Surfaces::NONE;

    type Input = ArchiveProtectInput;
    type Output = ArchiveProtectOutput;

    fn access(input: &ArchiveProtectInput) -> Vec<Access> {
        vec![Access::Write(input.archive.clone())]
    }

    fn run(_: ArchiveProtectInput, _: &mut JobCtx) -> Result<ArchiveProtectOutput, CmdError> {
        Err(not_built("archive.protect"))
    }
}
