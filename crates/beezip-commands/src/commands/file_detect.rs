use std::path::PathBuf;

use beezip_core::{LayerKind, detect_path};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::util::{absolute, as_given},
};

/// Detect what a file is: its chain of codecs and archive format (`zstd → tar`), whether it is
/// a self-extracting archive, and what it is when it isn't an archive at all.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct FileDetectInput {
    /// The file to look at.
    pub path: PathBuf,
}

/// One layer of a file, outermost first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct LayerInfo {
    /// `codec` or `format`.
    pub kind: String,
    /// The codec or format id, e.g. `zstd` or `tar`.
    pub id: String,
    /// `certain` (magic and a structural check), `likely` (magic only) or `guess` (the
    /// extension only).
    pub confidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct FileDetectOutput {
    pub path: PathBuf,
    pub layers: Vec<LayerInfo>,
    /// `zstd → tar`, or `gzip` for a compressed file that isn't an archive. Empty when nothing
    /// was recognised.
    pub chain: String,
    /// The archive format at the bottom (`zip`, `7z`, `rar`, `tar`, or `stream` for a bare
    /// compressed file or a split file of anything else).
    pub format: Option<String>,
    /// An archive inside an executable: a zip, 7z or RAR SFX.
    pub sfx: bool,
    /// What the file (or a stream's content) is when it isn't an archive, e.g. "Portable
    /// Network Graphics".
    pub label: Option<String>,
    /// Whether the extension fits what the file is.
    pub extension_agrees: bool,
    /// The parts of a volume set (`a.7z.001`…, `a.part1.rar`…), first part first; just the
    /// file otherwise. Any part detects as the whole set.
    pub volumes: Vec<PathBuf>,
}

pub struct FileDetect;

impl Command for FileDetect {
    const NAME: &'static str = "file.detect";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "detect",
        aliases: &[],
    });

    type Input = FileDetectInput;
    type Output = FileDetectOutput;

    fn access(input: &FileDetectInput) -> Vec<Access> {
        vec![Access::Read(input.path.clone())]
    }

    fn run(input: FileDetectInput, cx: &mut JobCtx) -> Result<FileDetectOutput, CmdError> {
        let det = detect_path(&absolute(&input.path), &cx.policy().limits)?;
        Ok(FileDetectOutput {
            layers: det
                .layers
                .iter()
                .map(|l| LayerInfo {
                    kind: match l.kind {
                        LayerKind::Codec(_) => "codec",
                        LayerKind::Format(_) => "format",
                    }
                    .into(),
                    id: l.kind.name().into(),
                    confidence: l.confidence.name().into(),
                })
                .collect(),
            chain: det.chain(),
            format: det.format().map(|f| f.name().to_owned()),
            sfx: det.sfx,
            label: det.label.clone(),
            extension_agrees: det.extension_agrees,
            volumes: as_given(&input.path, &det.volumes),
            path: input.path,
        })
    }

    fn human(out: &FileDetectOutput) -> Option<String> {
        let path = out.path.display();
        let what = match out.format.as_deref() {
            None => match &out.label {
                Some(label) => format!("not an archive ({label})"),
                None => "not an archive".into(),
            },
            Some("stream") if out.chain.is_empty() => match &out.label {
                Some(label) => format!("a file split into volumes ({label})"),
                None => "a file split into volumes".into(),
            },
            Some("stream") => {
                let content = out
                    .label
                    .as_deref()
                    .map(|l| format!(" of {l}"))
                    .unwrap_or_default();
                format!("{} compressed file{content}", out.chain)
            }
            _ if out.sfx => format!("{} (self-extracting)", out.chain),
            _ => out.chain.clone(),
        };
        let note = if out.extension_agrees {
            ""
        } else {
            " (the extension says otherwise)"
        };
        let parts = if out.volumes.len() > 1 {
            format!(", {} volumes", out.volumes.len())
        } else {
            String::new()
        };
        Some(format!("{path}: {what}{parts}{note}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<FileDetectInput>(
            &["x.zip"],
            serde_json::json!({ "path": "x.zip" }),
        );
    }
}
