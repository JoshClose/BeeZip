use std::path::PathBuf;

use beezip_core::format::normalize;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::{listing::ListKey, util::with_archive},
    wire::{EntryInfo, EntryKindName, Secret, human_size, local_time},
};

/// List an archive's entries. Without `flat`, one folder level at a time (the root, or `dir`),
/// with folders that only exist as parts of paths shown too; with `flat` or a `glob`, every
/// entry under `dir`. Results come in pages with `offset` and `limit`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveListInput {
    /// The archive.
    pub archive: PathBuf,
    /// A folder inside the archive to list instead of the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Every entry below `dir`, not just one level.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flat: Option<bool>,
    /// Only entries matching these patterns (implies `flat`). Without `/` a pattern matches a
    /// name at any depth (`*.txt`); with `/` the whole path (`docs/**/*.md`).
    #[arg(long, value_name = "PATTERN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<Vec<String>>,
    /// Entries to skip, for paging.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// At most this many entries (over MCP, at most 500).
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Sort by this, folders first [default: archive order].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<SortKey>,
    /// Reverse the sort (folders stay first).
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse: Option<bool>,
    /// Only entries of this kind: `file` (files and hard links), `dir`, or `link` (symlinks).
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<KindFilter>,
    /// The password, if entry names need one.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveListOutput {
    pub entries: Vec<EntryInfo>,
    /// Entries in this listing before paging.
    pub total: u64,
    pub offset: u64,
    pub has_more: bool,
}

/// What `archive.list` sorts by.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum SortKey {
    Name,
    Size,
    Packed,
    Modified,
    /// Folders, files, then links; by name within each.
    Kind,
    /// The compression method's name; entries without one first.
    Method,
    Crc,
    /// Unencrypted entries first.
    Encrypted,
}

/// Which entries `archive.list` keeps.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum KindFilter {
    /// Files and hard links (which extract as files).
    File,
    Dir,
    /// Symlinks.
    Link,
}

impl KindFilter {
    pub(crate) fn matches(self, kind: EntryKindName) -> bool {
        match self {
            Self::File => matches!(
                kind,
                EntryKindName::File | EntryKindName::Hardlink | EntryKindName::Other
            ),
            Self::Dir => kind == EntryKindName::Dir,
            Self::Link => kind == EntryKindName::Symlink,
        }
    }
}

pub struct ArchiveList;

impl Command for ArchiveList {
    const NAME: &'static str = "archive.list";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "list",
        aliases: &["l"],
        group: None,
    });

    type Input = ArchiveListInput;
    type Output = ArchiveListOutput;

    fn access(input: &ArchiveListInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: ArchiveListInput, cx: &mut JobCtx) -> Result<ArchiveListOutput, CmdError> {
        let key = ListKey {
            dir: input.dir.as_deref().map(normalize).unwrap_or_default(),
            flat: input.flat.unwrap_or(false),
            globs: input.glob.clone().unwrap_or_default(),
            kind: input.kind,
            sort: input.sort,
            reverse: input.reverse.unwrap_or(false),
        };
        with_archive(&input.archive, input.password.as_ref(), cx, |a, cx| {
            let entries = a.opened.reader.entries(cx)?;
            a.entries = Some(entries.len());
            // Built once per archive and key, then kept with the archive in the cache.
            let listing = a.memo.listing(entries, &key)?;

            let total = listing.len() as u64;
            let offset = input.offset.unwrap_or(0).min(total);
            // A front end's cap (MCP's 500) shortens the page; `has_more` says to ask for more.
            let limit = input
                .limit
                .unwrap_or(u64::MAX)
                .min(cx.policy().max_list_entries.unwrap_or(u64::MAX));
            let page: Vec<EntryInfo> = listing
                .iter()
                .skip(usize::try_from(offset).unwrap_or(usize::MAX))
                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                .map(|row| a.memo.info(entries, *row))
                .collect();
            let has_more = offset + (page.len() as u64) < total;
            Ok(ArchiveListOutput {
                entries: page,
                total,
                offset,
                has_more,
            })
        })
    }

    fn human(out: &ArchiveListOutput) -> Option<String> {
        let mut s = format!(
            "{:<16}  {:>10}  {:>10}  {:<8}  NAME\n",
            "MODIFIED", "SIZE", "PACKED", "METHOD"
        );
        for e in &out.entries {
            let modified = e.modified.as_deref().map(local_time).unwrap_or_default();
            let size = e.size.map(human_size).unwrap_or_default();
            let packed = e.packed_size.map(human_size).unwrap_or_default();
            let mut name = e.path.clone();
            match e.kind {
                EntryKindName::Dir if !name.ends_with('/') => name.push('/'),
                EntryKindName::Symlink | EntryKindName::Hardlink => {
                    let arrow = if e.kind == EntryKindName::Symlink {
                        "->"
                    } else {
                        "=>"
                    };
                    name = match e.target.as_deref() {
                        Some(t) if !t.is_empty() => format!("{name} {arrow} {t}"),
                        // 7z keeps a link's target in its data, read when it is extracted.
                        _ => format!("{name} (link)"),
                    };
                }
                _ => {}
            }
            if e.encrypted {
                name.push_str(" *");
            }
            s.push_str(&format!(
                "{modified:<16}  {size:>10}  {packed:>10}  {:<8}  {name}\n",
                e.method.as_deref().unwrap_or("")
            ));
        }
        let shown = out.entries.len() as u64;
        s.push_str(&format!("{shown} of {} entries", out.total));
        if out.has_more {
            s.push_str(&format!(" (more from --offset {})", out.offset + shown));
        }
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveListInput>(
            &["a.zip"],
            serde_json::json!({ "archive": "a.zip" }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveListInput>(
            &["a.zip", "docs", "--flat", "--glob", "*.md", "--limit", "5"],
            serde_json::json!({ "archive": "a.zip", "dir": "docs", "flat": true, "glob": ["*.md"], "limit": 5 }),
        );
        crate::commands::util::tests::cli_matches_json::<ArchiveListInput>(
            &["a.7z", "--sort", "size", "--reverse", "--kind", "dir"],
            serde_json::json!({ "archive": "a.7z", "sort": "size", "reverse": true, "kind": "dir" }),
        );
    }

    #[test]
    fn enum_names_agree() {
        crate::wire::tests::names_agree::<SortKey>();
        crate::wire::tests::names_agree::<KindFilter>();
    }

    #[test]
    fn kinds_filter() {
        use EntryKindName as K;
        assert!(KindFilter::File.matches(K::Hardlink));
        assert!(!KindFilter::File.matches(K::Dir));
        assert!(KindFilter::Link.matches(K::Symlink));
        assert!(KindFilter::Dir.matches(K::Dir));
    }
}
