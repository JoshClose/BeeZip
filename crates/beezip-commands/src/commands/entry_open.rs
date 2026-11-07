use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use beezip_core::{
    EntryKind, FsOptions, FsSink, OverwritePolicy, Selection, format::normalize, safefs::motw,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx, Surfaces,
    commands::util::{absolute, open_archive_with, open_options},
    config::MarkOfTheWeb,
    wire::{NameEncoding, Secret},
};

/// Open an archive's file with its default app (Windows' "Open with" dialog when there is
/// none). The entry is extracted, with the archive's Mark of the Web, into a folder of its own
/// under `%TEMP%\BeeZip\open`, so two entries of one name don't collide; folders there older
/// than a day are deleted as it goes. Programs run as they would from Explorer: SmartScreen sees
/// the mark.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct EntryOpenInput {
    /// The archive.
    pub archive: PathBuf,
    /// The file inside it, as listed.
    pub entry: String,
    /// The password, if the entry is encrypted.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// How names stored as bytes are read, so `entry` matches them as listed [default: from
    /// config, `auto`].
    #[arg(long, value_enum, value_name = "ENCODING")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_encoding: Option<NameEncoding>,
    /// Open the extracted file; `false` only extracts it, for the caller to open [default:
    /// true].
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EntryOpenOutput {
    /// The extracted file.
    pub path: PathBuf,
    pub launched: bool,
}

/// Where opened entries go: `%TEMP%\BeeZip\open`.
pub fn open_root() -> PathBuf {
    std::env::temp_dir().join("BeeZip").join("open")
}

/// How long an opened entry's folder stays: an editor may still have it.
const KEEP: Duration = Duration::from_secs(24 * 60 * 60);

/// Deletes folders under `root` older than [`KEEP`], skipping any whose files are in use.
fn sweep(root: &Path) {
    let Ok(dirs) = std::fs::read_dir(root) else {
        return;
    };
    let now = SystemTime::now();
    for d in dirs.flatten() {
        let old = d
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age > KEEP));
        if old && d.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = std::fs::remove_dir_all(d.path());
        }
    }
}

pub struct EntryOpen;

impl Command for EntryOpen {
    const NAME: &'static str = "entry.open";
    const EFFECT: Effect = Effect::Writes;
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "open",
        aliases: &[],
        group: None,
    });

    type Input = EntryOpenInput;
    type Output = EntryOpenOutput;

    fn access(input: &EntryOpenInput) -> Vec<Access> {
        vec![
            Access::Read(input.archive.clone()),
            Access::Write(open_root()),
        ]
    }

    fn run(input: EntryOpenInput, cx: &mut JobCtx) -> Result<EntryOpenOutput, CmdError> {
        let config = cx.config()?.clone();
        let open_opts = open_options(input.name_encoding, cx);
        let mut opened =
            open_archive_with(&input.archive, input.password.as_ref(), &open_opts, cx)?;
        let want = normalize(&input.entry);
        let fold = |s: &str| {
            if cfg!(windows) {
                s.to_lowercase()
            } else {
                s.to_owned()
            }
        };
        let entries = opened.reader.entries(cx)?;
        let entry = entries
            .iter()
            .find(|e| normalize(&e.path) == want)
            .or_else(|| {
                entries
                    .iter()
                    .find(|e| fold(&normalize(&e.path)) == fold(&want))
            })
            .cloned()
            .ok_or_else(|| {
                CmdError::new(
                    ErrorCode::NotFound,
                    format!("`{}` isn't in the archive", input.entry),
                )
            })?;
        let what = match entry.kind {
            EntryKind::File => None,
            EntryKind::Dir => Some("a folder"),
            EntryKind::Symlink { .. } | EntryKind::Hardlink { .. } => Some("a link"),
            EntryKind::Other => Some("a device or FIFO"),
        };
        if let Some(what) = what {
            return Err(CmdError::invalid_args(format!(
                "`{}` is {what}; only files open",
                input.entry
            )));
        }

        let root = open_root();
        std::fs::create_dir_all(&root)
            .map_err(|e| beezip_core::Error::io(format!("creating {}", root.display()), &e))?;
        sweep(&root);
        let dir = tempfile::Builder::new()
            .prefix("")
            .rand_bytes(8)
            .tempdir_in(&root)
            .map_err(|e| {
                beezip_core::Error::io(format!("creating a folder in {}", root.display()), &e)
            })?
            .keep();
        let path = normalize(&entry.path);
        let depth = path.matches('/').count();
        let archive_path = absolute(&input.archive);
        let fs = FsOptions {
            overwrite: OverwritePolicy::Always,
            links: false,
            strip_components: depth,
            zone: match config.extract.mark_of_the_web {
                MarkOfTheWeb::All => motw::read_zone_of(&opened.detection.volumes)
                    .or_else(|| motw::read_zone(&archive_path)),
                MarkOfTheWeb::None => None,
            },
            limits: cx.policy().limits.clone(),
            input: opened.input.clone(),
            budget: open_opts.budget.clone(),
        };
        let mut sink = FsSink::new(&dir, fs)?;
        opened
            .reader
            .extract(&Selection::ids([entry.id]), &mut sink, cx)?;
        let report = sink.finish(cx)?;
        let name = path.rsplit('/').next().unwrap_or(&path).to_owned();
        let file = report
            .renamed
            .first()
            .map_or_else(|| dir.join(&name), |r| dir.join(&r.to));
        if !file.is_file() {
            let why = report
                .skipped
                .first()
                .map_or("it couldn't be written", |s| s.reason.name());
            return Err(CmdError::new(
                ErrorCode::Unsafe,
                format!("`{}` wasn't extracted: {why}", input.entry),
            ));
        }
        let launch = input.launch.unwrap_or(true);
        if launch {
            open::that_detached(&file)
                .map_err(|e| beezip_core::Error::io(format!("opening {}", file.display()), &e))?;
        }
        Ok(EntryOpenOutput {
            path: file,
            launched: launch,
        })
    }

    fn human(out: &EntryOpenOutput) -> Option<String> {
        Some(if out.launched {
            format!("Opened {}", out.path.display())
        } else {
            format!("Extracted to {}", out.path.display())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<EntryOpenInput>(
            &["a.zip", "docs/a.txt"],
            serde_json::json!({ "archive": "a.zip", "entry": "docs/a.txt" }),
        );
        crate::commands::util::tests::cli_matches_json::<EntryOpenInput>(
            &["a.zip", "docs/a.txt", "--launch=false"],
            serde_json::json!({ "archive": "a.zip", "entry": "docs/a.txt", "launch": false }),
        );
    }

    #[test]
    fn old_folders_are_swept() {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("old");
        let new = root.path().join("new");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join("a.txt"), "a").unwrap();
        let long_ago = filetime::FileTime::from_unix_time(1_000_000_000, 0);
        filetime::set_file_mtime(&old, long_ago).unwrap();
        sweep(root.path());
        assert!(!old.exists());
        assert!(new.exists());
    }
}
