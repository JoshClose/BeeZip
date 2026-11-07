//! `shell.plan` (docs/M4.md §6.1): a click on the Explorer menu, as the steps `BeeZip.exe --job`
//! runs. Job windows run the `run` steps; the main window takes the others.

use std::path::{Path, PathBuf};

use beezip_menu::{Item, JobRequest, REQUEST_VERSION, Selected, archive_stem};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

use beezip_core::{ErrorKind, SimpleCtx};

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx, Surfaces, commands::util::open_options,
};

/// One thing a click does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Run a command in a job window, after the steps before it.
    Run {
        /// What the window says while it runs: "Extracting a.zip".
        title: String,
        command: String,
        args: Value,
        /// The archive an add item would write is there already. The window asks whether to add
        /// to it (`archive.add`, when `can_add`), replace it (`overwrite`) or keep both.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        existing: Option<Existing>,
    },
    /// Open archives as tabs in the main window.
    Open { paths: Vec<PathBuf> },
    /// The main window's extract dialog, for one archive.
    ExtractDialog { archive: PathBuf },
    /// The main window's create dialog, with these inputs.
    CreateDialog { inputs: Vec<PathBuf> },
    /// A step that can't run, because its path has gone or its volume set has a gap. The other
    /// steps still run.
    Failed { title: String, error: CmdError },
}

/// An output that exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Existing {
    pub path: PathBuf,
    /// A free name beside it, for keeping both: `a (1).zip`.
    pub keep_both: PathBuf,
    /// `archive.add` can add to it: it's an archive BeeZip edits, not a volume set, a
    /// self-extracting archive or a read-only file (docs/M5.md §9).
    pub can_add: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ShellPlanOutput {
    /// In order: the job window runs its steps one after another.
    pub steps: Vec<Step>,
}

pub struct ShellPlan;

impl Command for ShellPlan {
    const NAME: &'static str = "shell.plan";
    const EFFECT: Effect = Effect::ReadOnly;
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "plan",
        aliases: &[],
        group: Some("shell"),
    });

    type Input = JobRequest;
    type Output = ShellPlanOutput;

    fn access(input: &JobRequest) -> Vec<Access> {
        input.paths.iter().cloned().map(Access::Read).collect()
    }

    fn run(input: JobRequest, cx: &mut JobCtx) -> Result<ShellPlanOutput, CmdError> {
        if input.version != REQUEST_VERSION {
            return Err(CmdError::invalid_args(format!(
                "a job request of version {} can't be read; this BeeZip reads version {REQUEST_VERSION}",
                input.version
            )));
        }
        if input.paths.is_empty() {
            return Err(CmdError::invalid_args(
                "a job request needs at least one path",
            ));
        }
        if let Some(p) = input.paths.iter().find(|p| !p.is_absolute()) {
            return Err(CmdError::invalid_args(format!(
                "`{}` isn't absolute; a job request's paths are",
                p.display()
            )));
        }
        Ok(ShellPlanOutput {
            steps: plan(&input, cx)?,
        })
    }
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn gone(path: &Path) -> Step {
    Step::Failed {
        title: name_of(path),
        error: CmdError::not_found(format!("`{}` isn't there any more", path.display())),
    }
}

/// An archive to work on: the first part of its volume set, and the set's name (`a.7z` for
/// `a.7z.001`).
struct Archive {
    first: PathBuf,
    name: String,
}

/// The selected archives, a volume set once, in the order selected. A path that has gone, or a
/// set with a gap, is a failed step.
fn archives(paths: &[PathBuf]) -> Vec<Result<Archive, Step>> {
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut out = Vec::new();
    for path in paths {
        if !exists(path) {
            out.push(Err(gone(path)));
            continue;
        }
        let archive = match beezip_core::volume::find_set(path) {
            Ok(Some(set)) => Archive {
                first: set.parts.first().cloned().unwrap_or_else(|| path.clone()),
                name: set.name,
            },
            Ok(None) => Archive {
                first: path.clone(),
                name: name_of(path),
            },
            Err(e) => {
                out.push(Err(Step::Failed {
                    title: name_of(path),
                    error: e.into(),
                }));
                continue;
            }
        };
        if !seen.contains(&archive.first) {
            seen.push(archive.first.clone());
            out.push(Ok(archive));
        }
    }
    out
}

fn folder_of(path: &Path) -> PathBuf {
    path.parent().unwrap_or(path).to_path_buf()
}

/// `<name> (1)<ext>`, `<name> (2)<ext>`… in `dir`: the first that isn't there.
fn keep_both(dir: &Path, name: &str, ext: &str) -> PathBuf {
    let mut n = 1u32;
    loop {
        let candidate = dir.join(format!("{name} ({n}){ext}"));
        if !exists(&candidate) || n == u32::MAX {
            return candidate;
        }
        n += 1;
    }
}

fn plan(req: &JobRequest, cx: &JobCtx) -> Result<Vec<Step>, CmdError> {
    let mut steps = Vec::new();
    match req.item {
        Item::ExtractHere | Item::ExtractFolder | Item::Test => {
            for archive in archives(&req.paths) {
                let a = match archive {
                    Ok(a) => a,
                    Err(failed) => {
                        steps.push(failed);
                        continue;
                    }
                };
                let folder = folder_of(&a.first);
                let (title, command, args) = match req.item {
                    Item::ExtractHere => (
                        format!("Extracting {}", a.name),
                        "archive.extract",
                        json!({ "archive": a.first, "dest": folder, "smart": true }),
                    ),
                    Item::ExtractFolder => (
                        format!("Extracting {}", a.name),
                        "archive.extract",
                        json!({ "archive": a.first, "dest": folder.join(archive_stem(&a.name)) }),
                    ),
                    _ => (
                        format!("Testing {}", a.name),
                        "archive.test",
                        json!({ "archive": a.first }),
                    ),
                };
                steps.push(Step::Run {
                    title,
                    command: command.into(),
                    args,
                    existing: None,
                });
            }
        }
        Item::ExtractTo => {
            let mut found = archives(&req.paths);
            if found.len() > 1 {
                return Err(CmdError::invalid_args(
                    "\"Extract to…\" takes one archive, or one volume set",
                ));
            }
            match found.pop() {
                Some(Ok(a)) => steps.push(Step::ExtractDialog { archive: a.first }),
                Some(Err(failed)) => steps.push(failed),
                None => {}
            }
        }
        Item::Open | Item::AddZip | Item::Add7z | Item::AddTarZst | Item::CompressTo => {
            let (present, missing): (Vec<&PathBuf>, Vec<&PathBuf>) =
                req.paths.iter().partition(|p| exists(p));
            steps.extend(missing.into_iter().map(|p| gone(p)));
            if present.is_empty() {
                return Ok(steps);
            }
            let present: Vec<PathBuf> = present.into_iter().cloned().collect();
            steps.push(match req.item {
                Item::Open => Step::Open { paths: present },
                Item::CompressTo => Step::CreateDialog { inputs: present },
                _ => add(req.item, present, cx),
            });
        }
    }
    Ok(steps)
}

/// Whether `archive.add` could add to `archive`, by the rules it applies (docs/M5.md §9). A
/// password needed to read it (a 7z with encrypted names) is asked for when adding, so it
/// doesn't count against it; nobody is asked here.
fn can_add(archive: &Path, cx: &JobCtx) -> bool {
    let opts = open_options(None, cx);
    let mut quiet = SimpleCtx::new();
    let needs_password = |e: &beezip_core::Error| e.kind == ErrorKind::PasswordRequired;
    match beezip_core::open(archive, &opts, &mut quiet) {
        Ok(mut opened) => match beezip_core::edit::refusal(archive, &mut opened, &mut quiet) {
            Ok(why) => why.is_none(),
            Err(e) => needs_password(&e),
        },
        Err(e) => needs_password(&e),
    }
}

/// "Add to "a.zip"": the archive beside the first input, named as the menu's title says.
fn add(item: Item, inputs: Vec<PathBuf>, cx: &JobCtx) -> Step {
    let selection: Vec<Selected> = inputs
        .iter()
        .map(|p| Selected {
            path: Some(p.to_string_lossy().into_owned()),
            folder: p.is_dir(),
        })
        .collect();
    let name = beezip_menu::add_name(&selection);
    let ext = item.add_extension().unwrap_or(".zip");
    let dir = folder_of(&inputs[0]);
    let output = dir.join(format!("{name}{ext}"));
    let existing = exists(&output).then(|| Existing {
        path: output.clone(),
        keep_both: keep_both(&dir, &name, ext),
        can_add: can_add(&output, cx),
    });
    Step::Run {
        title: format!("Creating {name}{ext}"),
        command: "archive.create".into(),
        args: json!({ "output": output, "inputs": inputs }),
        existing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<JobRequest>(
            &["extract-here", r"C:\a.zip", r"C:\b.7z"],
            json!({ "version": 1, "item": "extract-here", "paths": [r"C:\a.zip", r"C:\b.7z"] }),
        );
    }
}
