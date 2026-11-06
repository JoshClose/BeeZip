use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use beezip_core::{
    EntryKind, ExtractReport, FsOptions, FsSink, Selection,
    format::normalize,
    safefs::{
        SkipReason, motw,
        sanitize::{Refusal, sanitize},
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx,
    commands::util::{absolute, archive_stem, open_archive_with, open_options},
    config::MarkOfTheWeb,
    wire::{NameEncoding, OverwritePolicy, Secret, human_size},
};

/// Extract an archive, or the selected entries. Unsafe entries (paths climbing out with `..`,
/// links leading out) are skipped and the rest extracted; the command then fails with `Unsafe`
/// and the report in `details`. Without `dest`, files go into the current directory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveExtractInput {
    /// The archive.
    pub archive: PathBuf,
    /// Entries to extract (a folder takes everything under it). All when none are given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,
    /// Where to extract [default: the current directory].
    #[arg(short = 'o', long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<PathBuf>,
    /// Extract only entries matching these patterns. Without `/` a pattern matches a name at
    /// any depth (`*.txt`); with `/` the whole path (`docs/**/*.md`).
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<Vec<String>>,
    /// Leave out entries matching these patterns.
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    /// Drop this many leading path components, as with `tar --strip-components`.
    #[arg(long, value_name = "N")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_components: Option<u32>,
    /// If the selection has more than one top-level item, extract into a folder named after the
    /// archive (`a.tar.zst` → `a/`), as Explorer's "Extract here" does.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smart: Option<bool>,
    /// What to do with files that exist [default: from config, `ask`].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<OverwritePolicy>,
    /// Create symlinks that stay inside the destination [default: from config, off]. Hard
    /// links are always extracted as copies.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<bool>,
    /// The password for encrypted entries.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How names stored as bytes are read: zip names without the UTF-8 flag, tar names outside
    /// pax records [default: from config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
    /// Show what would be extracted, and where, without writing anything.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

/// An entry that wasn't extracted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SkippedInfo {
    pub path: String,
    /// `traversal`, `outside-dest`, `links-disabled`, `link-outside`, `link-target-missing`,
    /// `invalid-path`, `unsupported`, `exists`, `not-newer`, `blocked` or `link-failed`.
    pub reason: String,
    /// Refused for safety; these make the command fail with `Unsafe`.
    pub refused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RenamedInfo {
    /// As stored in the archive.
    pub from: String,
    /// As written, relative to `dest`.
    pub to: String,
}

/// One entry of a dry run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PlannedEntry {
    pub path: String,
    /// Where it would go, relative to `dest`.
    pub to: Option<String>,
    /// Why it would be skipped.
    pub skip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveExtractOutput {
    pub dest: PathBuf,
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes: u64,
    /// At most 1 000; `skipped_total` counts all.
    pub skipped: Vec<SkippedInfo>,
    pub skipped_total: u64,
    /// At most 1 000; `renamed_total` counts all.
    pub renamed: Vec<RenamedInfo>,
    pub renamed_total: u64,
    pub unsafe_total: u64,
    pub dry_run: bool,
    /// The entries a dry run would extract.
    pub plan: Option<Vec<PlannedEntry>>,
}

impl ArchiveExtractOutput {
    fn from_report(dest: PathBuf, r: ExtractReport) -> Self {
        Self {
            dest,
            files: r.files,
            dirs: r.dirs,
            links: r.links,
            bytes: r.bytes,
            skipped: r
                .skipped
                .iter()
                .map(|s| SkippedInfo {
                    path: s.path.clone(),
                    reason: s.reason.name().into(),
                    refused: s.reason.is_unsafe(),
                })
                .collect(),
            skipped_total: r.skipped_total,
            renamed: r
                .renamed
                .into_iter()
                .map(|r| RenamedInfo {
                    from: r.from,
                    to: r.to,
                })
                .collect(),
            renamed_total: r.renamed_total,
            unsafe_total: r.unsafe_total,
            dry_run: false,
            plan: None,
        }
    }
}

pub struct ArchiveExtract;

impl ArchiveExtract {
    fn dest(input: &ArchiveExtractInput) -> PathBuf {
        absolute(input.dest.as_deref().unwrap_or(Path::new(".")))
    }
}

impl Command for ArchiveExtract {
    const NAME: &'static str = "archive.extract";
    const EFFECT: Effect = Effect::Writes;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "extract",
        aliases: &["x"],
        group: None,
    });

    type Input = ArchiveExtractInput;
    type Output = ArchiveExtractOutput;

    fn access(input: &ArchiveExtractInput) -> Vec<Access> {
        vec![
            Access::Read(input.archive.clone()),
            Access::Write(Self::dest(input)),
        ]
    }

    fn run(input: ArchiveExtractInput, cx: &mut JobCtx) -> Result<ArchiveExtractOutput, CmdError> {
        let config = cx.config()?.clone();
        let paths = input.entries.clone().unwrap_or_default();
        let sel = Selection::new(
            &paths,
            input.glob.as_deref().unwrap_or_default(),
            input.exclude.as_deref().unwrap_or_default(),
        )?;
        let open_opts = open_options(input.name_encoding, cx);
        let mut opened =
            open_archive_with(&input.archive, input.password.as_ref(), &open_opts, cx)?;
        let links = input.links.unwrap_or(config.extract.links);
        let strip = input.strip_components.unwrap_or(0) as usize;

        let mut dest = Self::dest(&input);
        if input.smart.unwrap_or(false) {
            let top: BTreeSet<String> = opened
                .reader
                .entries(cx)?
                .iter()
                .filter(|e| sel.matches(e))
                .filter_map(|e| normalize(&e.path).split('/').next().map(str::to_owned))
                .filter(|t| !t.is_empty())
                .collect();
            if top.len() > 1 {
                dest = dest.join(archive_stem(&input.archive));
            }
        }

        if input.dry_run.unwrap_or(false) {
            let entries = opened.reader.entries(cx)?;
            let plan: Vec<PlannedEntry> = entries
                .iter()
                .filter(|e| sel.matches(e))
                .map(|e| plan_entry(e, strip, links))
                .collect();
            return Ok(ArchiveExtractOutput {
                dry_run: true,
                plan: Some(plan),
                ..ArchiveExtractOutput::from_report(dest, ExtractReport::default())
            });
        }

        let archive_path = absolute(&input.archive);
        let fs = FsOptions {
            overwrite: input.overwrite.unwrap_or(config.extract.overwrite).into(),
            links,
            strip_components: strip,
            zone: match config.extract.mark_of_the_web {
                MarkOfTheWeb::All => motw::read_zone_of(&opened.detection.volumes)
                    .or_else(|| motw::read_zone(&archive_path)),
                MarkOfTheWeb::None => None,
            },
            limits: cx.policy().limits.clone(),
            input: opened.input.clone(),
            budget: open_opts.budget.clone(),
        };
        let mut sink = FsSink::new(&dest, fs)?;
        opened.reader.extract(&sel, &mut sink, cx)?;
        let report = sink.finish(cx)?;
        let out = ArchiveExtractOutput::from_report(dest, report);
        if out.unsafe_total > 0 {
            let message = format!(
                "{} unsafe {} skipped; {} files extracted to {}",
                out.unsafe_total,
                if out.unsafe_total == 1 {
                    "entry was"
                } else {
                    "entries were"
                },
                out.files,
                out.dest.display()
            );
            let details = serde_json::to_value(&out).unwrap_or_default();
            return Err(CmdError::new(ErrorCode::Unsafe, message).with_details(details));
        }
        Ok(out)
    }

    fn human(out: &ArchiveExtractOutput) -> Option<String> {
        if let Some(plan) = &out.plan {
            let mut s = format!("Would extract to {}:\n", out.dest.display());
            for p in plan {
                match (&p.to, &p.skip) {
                    (_, Some(why)) => s.push_str(&format!("  skip {}  ({why})\n", p.path)),
                    (Some(to), None) if *to != p.path => {
                        s.push_str(&format!("  {} -> {to}\n", p.path));
                    }
                    (Some(to), None) => s.push_str(&format!("  {to}\n")),
                    (None, None) => {}
                }
            }
            return Some(s.trim_end().to_owned());
        }
        let mut s = format!(
            "Extracted {} files, {} folders ({}) to {}",
            out.files,
            out.dirs,
            human_size(out.bytes),
            out.dest.display()
        );
        if out.links > 0 {
            s.push_str(&format!(", {} links", out.links));
        }
        let others = out.skipped_total - out.unsafe_total;
        if others > 0 {
            s.push_str(&format!("; {others} skipped"));
        }
        if out.renamed_total > 0 {
            s.push_str(&format!("; {} renamed", out.renamed_total));
        }
        Some(s)
    }
}

fn plan_entry(e: &beezip_core::Entry, strip: usize, links: bool) -> PlannedEntry {
    let skip = |r: SkipReason| PlannedEntry {
        path: e.path.clone(),
        to: None,
        skip: Some(r.name().into()),
    };
    match &e.kind {
        EntryKind::Symlink { .. } if !links => return skip(SkipReason::LinksDisabled),
        EntryKind::Other => return skip(SkipReason::Unsupported),
        _ => {}
    }
    match sanitize(&e.path) {
        Ok(mut safe) => {
            if safe.components.len() <= strip {
                return PlannedEntry {
                    path: e.path.clone(),
                    to: None,
                    skip: None,
                };
            }
            safe.components.drain(..strip);
            PlannedEntry {
                path: e.path.clone(),
                to: Some(safe.joined()),
                skip: None,
            }
        }
        Err(Refusal::Traversal) => skip(SkipReason::Traversal),
        Err(Refusal::Empty) => PlannedEntry {
            path: e.path.clone(),
            to: None,
            skip: (!e.is_dir()).then(|| SkipReason::InvalidPath.name().into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveExtractInput>(
            &["a.zip"],
            serde_json::json!({ "archive": "a.zip" }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveExtractInput>(
            &[
                "a.zip",
                "docs",
                "x.txt",
                "-o",
                "out",
                "--smart",
                "--overwrite",
                "rename",
                "--links=false",
            ],
            serde_json::json!({
                "archive": "a.zip", "entries": ["docs", "x.txt"], "dest": "out",
                "smart": true, "overwrite": "rename", "links": false
            }),
        );
    }
}
