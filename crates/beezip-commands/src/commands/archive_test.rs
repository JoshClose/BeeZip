use std::path::PathBuf;

use beezip_core::{Selection, TestSink};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx,
    commands::util::open_archive,
    wire::{Secret, human_size},
};

/// Test an archive's integrity: read every entry to the end, checking CRCs and codec checksums.
/// Fails with `Corrupt`, listing the damaged entries in `details`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveTestInput {
    /// The archive.
    pub archive: PathBuf,
    /// The password for encrypted entries.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveTestOutput {
    pub archive: PathBuf,
    pub entries: u64,
    /// Uncompressed bytes read.
    pub bytes: u64,
}

pub struct ArchiveTest;

impl Command for ArchiveTest {
    const NAME: &'static str = "archive.test";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "test",
        aliases: &["t"],
    });

    type Input = ArchiveTestInput;
    type Output = ArchiveTestOutput;

    fn access(input: &ArchiveTestInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: ArchiveTestInput, cx: &mut JobCtx) -> Result<ArchiveTestOutput, CmdError> {
        let mut opened = open_archive(&input.archive, input.password.as_ref(), cx)?;
        let mut sink = TestSink::default();
        match opened.reader.extract(&Selection::all(), &mut sink, cx) {
            Ok(()) => {}
            // A stream that breaks part-way (a damaged tar.gz) ends the test as a failure.
            Err(e) if e.kind == beezip_core::ErrorKind::Corrupt => sink.report.record("", &e),
            Err(e) => return Err(e.into()),
        }
        let report = sink.report;
        if !report.ok() {
            let first = &report.errors[0];
            let what = if first.path.is_empty() {
                first.message.clone()
            } else {
                format!("{}: {}", first.path, first.message)
            };
            let errors: Vec<_> = report
                .errors
                .iter()
                .map(|e| json!({ "path": e.path, "code": ErrorCode::from(e.kind), "message": e.message }))
                .collect();
            let noun = if report.errors_total == 1 {
                "entry"
            } else {
                "entries"
            };
            return Err(CmdError::new(
                ErrorCode::Corrupt,
                format!("{} damaged {noun} ({what})", report.errors_total),
            )
            .with_details(json!({
                "errors": errors,
                "errors_total": report.errors_total,
                "entries": report.entries,
                "bytes": report.bytes,
            })));
        }
        Ok(ArchiveTestOutput {
            archive: input.archive,
            entries: report.entries,
            bytes: report.bytes,
        })
    }

    fn human(out: &ArchiveTestOutput) -> Option<String> {
        Some(format!(
            "{}: OK, {} entries, {}",
            out.archive.display(),
            out.entries,
            human_size(out.bytes)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveTestInput>(
            &["a.zip"],
            serde_json::json!({ "archive": "a.zip" }),
        );
    }
}
