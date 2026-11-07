//! What `archive.add`, `archive.remove`, `archive.rename` and `archive.convert` share
//! (docs/M5.md §7): the write options for an archive kind, the per-archive edit lock, the
//! cache's eviction after a swap, and the edits' output.

use std::path::{Path, PathBuf};

use beezip_core::{
    Action, ArchiveKind, EditOp, EditOptions, EditReport, EncodeOpts, WriteSpec,
    format::{
        cab::{CabMethod, CabWriteOptions},
        sevenz::{SevenZMethod, SevenZWriteOptions},
        zip::{ZipMethod, ZipWriteOptions},
    },
    ops,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CmdError, JobCtx,
    commands::util::{absolute, open_options},
    config::Config,
    wire::{
        ArchiveFormatName, EncryptionName, MethodName, NameEncoding, Secret, SevenZMethodName,
        ZipMethodName, human_size,
    },
};

/// The options a new archive or an edit is written with, as the inputs give them.
#[derive(Debug, Clone, Default)]
pub struct SpecArgs {
    pub method: Option<MethodName>,
    pub level: Option<i32>,
    pub threads: Option<u32>,
    pub password: Option<String>,
    pub encryption: Option<EncryptionName>,
    pub encrypt_headers: Option<bool>,
    pub solid: Option<bool>,
}

/// A level for `name` (a codec or zip method): the input's, else the config's, else none.
fn level(input: Option<i32>, name: &str, config: &Config) -> Option<i32> {
    input.or_else(|| config.level(name))
}

/// How to write `kind` with `args`, checked before anything is touched. `what` names the
/// archive in messages about options that don't fit its format.
pub fn spec_for(
    kind: ArchiveKind,
    args: &SpecArgs,
    config: &Config,
) -> Result<WriteSpec, CmdError> {
    let threads = args.threads.unwrap_or(config.create.threads);
    let only_7z = |what: &str, set: bool| -> Result<(), CmdError> {
        if set && kind != ArchiveKind::SevenZ {
            return Err(CmdError::invalid_args(format!("`{what}` is for 7z")));
        }
        Ok(())
    };
    only_7z("solid", args.solid.is_some())?;
    only_7z("encrypt_headers", args.encrypt_headers.is_some())?;
    match kind {
        ArchiveKind::SevenZ => {
            let method = match args.method {
                None => SevenZMethod::Lzma2,
                Some(m) => m.sevenz().map(SevenZMethodName::method).ok_or_else(|| {
                    CmdError::invalid_args(format!(
                        "`{}` isn't a 7z method; use lzma2, lzma, ppmd, bzip2, deflate or copy",
                        m.name()
                    ))
                })?,
            };
            if args.encryption.is_some() {
                return Err(CmdError::invalid_args(
                    "`encryption` is for zip; a 7z with a password is always AES-256",
                ));
            }
            if args.encrypt_headers == Some(true) && args.password.is_none() {
                return Err(CmdError::invalid_args("`encrypt_headers` needs a password"));
            }
            let opts = SevenZWriteOptions {
                method,
                level: level(args.level, method.name(), config),
                threads,
                password: args.password.clone(),
                encrypt_headers: args.encrypt_headers.unwrap_or(true),
                solid: args.solid.unwrap_or(true),
            };
            // Check the level now, before any file is touched.
            opts.resolve_level()?;
            Ok(WriteSpec::SevenZ(opts))
        }
        ArchiveKind::Zip => {
            let method = match args.method {
                None => ZipMethod::Deflate,
                Some(m) => m.zip().map(ZipMethodName::method).ok_or_else(|| {
                    CmdError::invalid_args(format!(
                        "`{}` isn't a zip method; use store, deflate, bzip2, zstd, xz or ppmd",
                        m.name()
                    ))
                })?,
            };
            if args.encryption.is_some() && args.password.is_none() {
                return Err(CmdError::invalid_args("`encryption` needs a password"));
            }
            let opts = ZipWriteOptions {
                method,
                level: level(args.level, method.name(), config),
                password: args.password.clone(),
                encryption: args
                    .encryption
                    .map(EncryptionName::encryption)
                    .unwrap_or_default(),
            };
            opts.check()?;
            Ok(WriteSpec::Zip(opts))
        }
        ArchiveKind::Tar(codec) | ArchiveKind::Cpio(codec) => {
            let what = if matches!(kind, ArchiveKind::Tar(_)) {
                "tar"
            } else {
                "cpio"
            };
            if args.method.is_some() {
                return Err(CmdError::invalid_args(format!(
                    "`method` is for zip, 7z and cab; a {what}'s codec comes from its name or `format`"
                )));
            }
            if args.password.is_some() || args.encryption.is_some() {
                return Err(CmdError::invalid_args(format!(
                    "{what} can't be encrypted; use zip or 7z"
                )));
            }
            let level = match codec {
                Some(c) => {
                    let l = level(args.level, c.name(), config);
                    EncodeOpts {
                        level: l,
                        ..EncodeOpts::default()
                    }
                    .resolve_level(c, c.codec().levels())?;
                    l
                }
                None if args.level.is_some() => {
                    return Err(CmdError::invalid_args(format!(
                        "a plain {what} isn't compressed, so it has no level"
                    )));
                }
                None => None,
            };
            let opts = EncodeOpts {
                level,
                threads,
                ..EncodeOpts::default()
            };
            Ok(match kind {
                ArchiveKind::Tar(_) => WriteSpec::Tar { codec, opts },
                _ => WriteSpec::Cpio { codec, opts },
            })
        }
        ArchiveKind::Ar => {
            if args.method.is_some() || args.level.is_some() {
                return Err(CmdError::invalid_args(
                    "an ar isn't compressed, so it has no `method` or `level`",
                ));
            }
            if args.password.is_some() || args.encryption.is_some() {
                return Err(CmdError::invalid_args(
                    "ar can't be encrypted; use zip or 7z",
                ));
            }
            Ok(WriteSpec::Ar)
        }
        ArchiveKind::Cab => {
            let method = match args.method {
                None => CabMethod::Mszip,
                Some(m) => m.cab().ok_or_else(|| {
                    CmdError::invalid_args(format!(
                        "`{}` isn't a cab method; use mszip or store",
                        m.name()
                    ))
                })?,
            };
            if args.level.is_some() {
                return Err(CmdError::invalid_args("a cab has no compression levels"));
            }
            if args.password.is_some() || args.encryption.is_some() {
                return Err(CmdError::invalid_args(
                    "a cab can't be encrypted; use zip or 7z",
                ));
            }
            Ok(WriteSpec::Cab(CabWriteOptions { method }))
        }
    }
}

/// What happens to an entry, in a dry run's plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeAction {
    Add,
    Replace,
    Remove,
    Rename,
    Skip,
}

impl From<Action> for ChangeAction {
    fn from(a: Action) -> Self {
        match a {
            Action::Add => Self::Add,
            Action::Replace => Self::Replace,
            Action::Remove => Self::Remove,
            Action::Rename => Self::Rename,
            Action::Skip => Self::Skip,
        }
    }
}

/// One change of a dry run: `path` is the entry's path afterwards (or the one removed); `from`
/// is the old path of a rename, or the file on disk being added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Change {
    pub action: ChangeAction,
    pub path: String,
    pub from: Option<String>,
}

/// What `archive.add`, `archive.remove` and `archive.rename` return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EditOutput {
    pub path: PathBuf,
    pub format: ArchiveFormatName,
    pub added: u64,
    /// Entries replaced by a file of the same path.
    pub replaced: u64,
    pub removed: u64,
    pub renamed: u64,
    /// Files not added because an entry was there (the `never` and `newer` policies, or a skip).
    pub skipped: u64,
    /// How many entries the archive has now.
    pub entries: u64,
    /// Entries copied as they were, without decoding.
    pub copied: u64,
    /// Entries decoded and encoded again: a changed 7z block's, or a compressed tar's.
    pub recompressed: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// New files added in the clear to an archive whose entries are encrypted (`unencrypted`).
    pub unencrypted: u64,
    pub dry_run: bool,
    /// For a dry run, each change.
    pub plan: Option<Vec<Change>>,
}

/// Runs `op` on `archive`: one edit of it at a time in this process, then the cache forgets
/// it. `password` is tried first for reading; `args` give the write options.
pub fn run_edit(
    archive: &Path,
    op: &EditOp,
    args: &SpecArgs,
    password: Option<&Secret>,
    names: Option<NameEncoding>,
    dry_run: bool,
    cx: &mut JobCtx,
) -> Result<EditOutput, CmdError> {
    let path = absolute(archive);
    let canonical = std::fs::canonicalize(&path).map_err(|e| {
        CmdError::from(beezip_core::Error::io(
            format!("opening {}", archive.display()),
            &e,
        ))
    })?;
    let _guard = cx.edit_lock(&canonical)?;
    let config = cx.config()?.clone();
    cx.set_password(password);
    let opts = EditOptions {
        open: open_options(names, cx),
        dry_run,
    };
    let mut spec = |kind| spec_for(kind, args, &config).map_err(beezip_core::Error::from);
    let result = ops::edit(&path, op, &mut spec, &opts, cx);
    if !dry_run && let Some(cache) = cx.cache() {
        cache.evict(&canonical);
    }
    let r = result?;
    Ok(output(archive, r))
}

fn output(archive: &Path, r: EditReport) -> EditOutput {
    EditOutput {
        path: archive.to_path_buf(),
        format: r
            .kind
            .map(ArchiveFormatName::from_kind)
            .unwrap_or(ArchiveFormatName::Zip),
        added: r.added,
        replaced: r.replaced,
        removed: r.removed,
        renamed: r.renamed,
        skipped: r.skipped,
        entries: r.entries,
        copied: r.copied,
        recompressed: r.recompressed,
        bytes_before: r.bytes_before,
        bytes_after: r.bytes_after,
        unencrypted: r.unencrypted,
        dry_run: r.dry_run,
        plan: r.dry_run.then(|| {
            r.plan
                .into_iter()
                .map(|c| Change {
                    action: c.action.into(),
                    path: c.path,
                    from: c.from,
                })
                .collect()
        }),
    }
}

fn count(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The one-line summary (docs/M5.md §7.4): "Added 3 files to a.zip (12 entries copied as they
/// were); 1.2 MiB → 1.4 MiB". A dry run lists its changes.
pub fn human(out: &EditOutput) -> String {
    let name = out.path.file_name().map_or_else(
        || out.path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    if let Some(plan) = &out.plan {
        let mut s = format!("Would change {name}:\n");
        for c in plan {
            let line = match (c.action, &c.from) {
                (ChangeAction::Add, _) => format!("  add      {}", c.path),
                (ChangeAction::Replace, _) => format!("  replace  {}", c.path),
                (ChangeAction::Remove, _) => format!("  remove   {}", c.path),
                (ChangeAction::Rename, Some(f)) => format!("  rename   {f} -> {}", c.path),
                (ChangeAction::Rename, None) => format!("  rename   {}", c.path),
                (ChangeAction::Skip, _) => format!("  skip     {}  (already there)", c.path),
            };
            s.push_str(&line);
            s.push('\n');
        }
        return s.trim_end().to_owned();
    }
    // (verb, what, preposition), in order; the last one's preposition goes before the name.
    let mut parts: Vec<(&str, String, &str)> = Vec::new();
    if out.added > 0 {
        parts.push(("added", count(out.added, "file", "files"), "to"));
    }
    if out.replaced > 0 {
        parts.push(("replaced", count(out.replaced, "entry", "entries"), "in"));
    }
    if out.removed > 0 {
        parts.push(("removed", count(out.removed, "entry", "entries"), "from"));
    }
    if out.renamed > 0 {
        parts.push(("renamed", count(out.renamed, "entry", "entries"), "in"));
    }
    let mut s = match parts.last() {
        None => format!("Nothing changed in {name}"),
        Some((_, _, prep)) => {
            let said: Vec<String> = parts.iter().map(|(v, n, _)| format!("{v} {n}")).collect();
            let mut s = format!("{} {prep} {name}", said.join(", "));
            s[..1].make_ascii_uppercase();
            s
        }
    };
    let mut notes = Vec::new();
    match out.copied {
        0 => {}
        1 => notes.push("1 entry copied as it was".to_owned()),
        n => notes.push(format!("{n} entries copied as they were")),
    }
    if out.recompressed > 0 {
        notes.push(format!(
            "{} recompressed",
            count(out.recompressed, "entry", "entries")
        ));
    }
    if out.skipped > 0 {
        notes.push(format!("{} skipped", count(out.skipped, "file", "files")));
    }
    if out.unencrypted > 0 {
        notes.push(format!(
            "{} not encrypted",
            count(out.unencrypted, "new file", "new files")
        ));
    }
    if !notes.is_empty() {
        s.push_str(&format!(" ({})", notes.join(", ")));
    }
    if !parts.is_empty() {
        s.push_str(&format!(
            "; {} → {}",
            human_size(out.bytes_before),
            human_size(out.bytes_after)
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out() -> EditOutput {
        EditOutput {
            path: Path::new("x").join("a.zip"),
            format: ArchiveFormatName::Zip,
            added: 3,
            replaced: 0,
            removed: 0,
            renamed: 0,
            skipped: 0,
            entries: 15,
            copied: 12,
            recompressed: 0,
            bytes_before: 1_258_291,
            bytes_after: 1_468_006,
            unencrypted: 0,
            dry_run: false,
            plan: None,
        }
    }

    #[test]
    fn summaries() {
        assert_eq!(
            human(&out()),
            "Added 3 files to a.zip (12 entries copied as they were); 1.2 MiB → 1.4 MiB"
        );
        let o = EditOutput {
            added: 1,
            replaced: 1,
            copied: 1,
            recompressed: 2,
            ..out()
        };
        assert_eq!(
            human(&o),
            "Added 1 file, replaced 1 entry in a.zip (1 entry copied as it was, 2 entries \
             recompressed); 1.2 MiB → 1.4 MiB"
        );
        let o = EditOutput {
            added: 0,
            skipped: 2,
            copied: 0,
            ..out()
        };
        assert_eq!(human(&o), "Nothing changed in a.zip (2 files skipped)");
    }
}
