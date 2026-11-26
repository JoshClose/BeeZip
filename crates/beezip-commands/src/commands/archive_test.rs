use std::path::PathBuf;

use beezip_core::{Selection, TestSink};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx,
    commands::ArchiveProtectionOutput,
    commands::util::open_archive,
    crypt::SignatureReport,
    protect,
    wire::{NameEncoding, Secret, human_size},
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
    /// How names stored as bytes are read: zip names without the UTF-8 flag, tar names outside
    /// pax records, cpio, ar, LHA, ARJ, ACE, ZOO, ARC and squashfs names, CAB names without the
    /// UTF-8 flag, ISO names outside Joliet [default: from config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
    /// Open a .bhive whose index is missing or damaged (a download cut short) from the
    /// records before its cells, with the entries they still hold.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recover: Option<bool>,
    /// Refuse the archive unless it is signed, validly, by each of these: a `bzsig1…` key, a
    /// certificate file, or the name of a signing key or contact. Matched by their whole
    /// SHA-256, never a fingerprint (docs/M14.md §11).
    #[arg(long, value_name = "SIGNER")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_signer: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveTestOutput {
    pub archive: PathBuf,
    pub entries: u64,
    /// Uncompressed bytes read.
    pub bytes: u64,
    /// What the test couldn't check: a format that stores no checksums of its files' data (a
    /// CHM help file, a disk image's FAT) shows only that every file can be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// A `.bhive`'s ways in, when it is encrypted. Their names and keys are what the archive
    /// says of itself, which anyone who could open it could have changed (docs/bhive.md §12.9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub protection: Option<ArchiveProtectionOutput>,
    /// A `.bhive`'s signatures, checked (docs/bhive.md §13).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub signatures: Option<Vec<SignatureReport>>,
}

pub struct ArchiveTest;

impl Command for ArchiveTest {
    const NAME: &'static str = "archive.test";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "test",
        aliases: &["t"],
        group: None,
    });

    type Input = ArchiveTestInput;
    type Output = ArchiveTestOutput;

    fn access(input: &ArchiveTestInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: ArchiveTestInput, cx: &mut JobCtx) -> Result<ArchiveTestOutput, CmdError> {
        test(input, false, cx)
    }

    fn human(out: &ArchiveTestOutput) -> Option<String> {
        let mut text = format!(
            "{}: OK, {} entries, {}",
            out.archive.display(),
            out.entries,
            human_size(out.bytes)
        );
        if let Some(note) = &out.note {
            text.push('\n');
            text.push_str(note);
        }
        if let Some(p) = &out.protection {
            text.push_str(&protect::protection_text(p));
        }
        if let Some(sigs) = &out.signatures {
            text.push_str(&protect::signatures_text(sigs));
        }
        Some(text)
    }
}

/// Tests an archive: every entry read to the end. `verify` also needs a valid signature
/// (`archive.verify`), checked before anything is read.
pub(crate) fn test(
    input: ArchiveTestInput,
    verify: bool,
    cx: &mut JobCtx,
) -> Result<ArchiveTestOutput, CmdError> {
    let wanted = protect::wanted(input.require_signer.as_deref().unwrap_or_default(), cx)?;
    let mut opened = open_archive(
        &input.archive,
        input.password.as_ref(),
        crate::commands::util::Opening::new(input.name_encoding, input.recover),
        cx,
    )?;
    let path = crate::commands::util::absolute(&input.archive);
    let (protection, signatures) = protect::security(&path, &mut *opened.reader, cx)?;
    protect::require(protect::signatures_of(&mut *opened.reader), &wanted)?;
    if verify {
        protect::verified(
            signatures.as_deref().unwrap_or_default(),
            !wanted.is_empty(),
        )?;
    }
    // A reader with a test of its own (CHM, CramFS, NSIS, MSI) runs it; the rest read every
    // entry.
    let report = match opened.reader.test(cx) {
        Some(report) => report?,
        None => {
            let mut sink = TestSink::default();
            match opened.reader.extract(&Selection::all(), &mut sink, cx) {
                Ok(()) => {}
                // A stream that breaks part-way (a damaged tar.gz) ends the test as a
                // failure.
                Err(e) if e.kind == beezip_core::ErrorKind::Corrupt => {
                    sink.report.record("", &e);
                }
                Err(e) => return Err(e.into()),
            }
            sink.report
        }
    };
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
            "note": report.note,
        })));
    }
    Ok(ArchiveTestOutput {
        archive: input.archive,
        entries: report.entries,
        bytes: report.bytes,
        note: report.note,
        protection,
        signatures,
    })
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
