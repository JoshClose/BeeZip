use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use beezip_core::format::bhive::BhiveReader;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx, Surfaces,
    commands::util::{Opening, absolute, with_archive},
    crypt::WayIn,
    protect,
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
    const SURFACES: Surfaces = Surfaces::ALL;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "protection",
        aliases: &[],
        group: None,
    });

    type Input = ArchiveProtectionInput;
    type Output = ArchiveProtectionOutput;

    fn access(input: &ArchiveProtectionInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(
        input: ArchiveProtectionInput,
        cx: &mut JobCtx,
    ) -> Result<ArchiveProtectionOutput, CmdError> {
        let path = absolute(&input.archive);
        with_archive(
            &input.archive,
            input.password.as_ref(),
            Opening::default(),
            cx,
            |a, cx| {
                let reader = &mut *a.opened.reader;
                if reader.as_any_mut().downcast_mut::<BhiveReader>().is_none() {
                    return Err(CmdError::invalid_args(format!(
                        "{} isn't a .bhive: only a .bhive has ways in (a zip's or 7z's password \
                         is its only one)",
                        input.archive.display()
                    )));
                }
                let (protection, _) = protect::security(&path, reader, cx)?;
                Ok(protection.unwrap_or(ArchiveProtectionOutput {
                    encrypted: false,
                    ways: Vec::new(),
                    post_quantum: false,
                }))
            },
        )
    }

    fn human(out: &ArchiveProtectionOutput) -> Option<String> {
        if !out.encrypted {
            return Some("not encrypted: anyone can open it".into());
        }
        Some(protect::protection_text(out).trim_start().to_owned())
    }
}
