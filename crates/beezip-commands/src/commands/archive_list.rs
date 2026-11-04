use std::{collections::HashSet, path::PathBuf};

use beezip_core::{Selection, format::normalize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::util::open_archive,
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
    fn matches(self, kind: EntryKindName) -> bool {
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

/// Folders first, then by `key`; ties go by name, then archive order (a stable sort).
fn sort(entries: &mut [EntryInfo], key: SortKey, reverse: bool) {
    use std::cmp::Ordering;
    let rank = |k: EntryKindName| match k {
        EntryKindName::Dir => 0,
        EntryKindName::File | EntryKindName::Hardlink | EntryKindName::Other => 1,
        EntryKindName::Symlink => 2,
    };
    let name = |e: &EntryInfo| {
        let p = normalize(&e.path);
        let base = p.rsplit('/').next().unwrap_or(&p).to_owned();
        (base.to_lowercase(), base)
    };
    entries.sort_by(|a, b| {
        let dirs = (a.kind != EntryKindName::Dir).cmp(&(b.kind != EntryKindName::Dir));
        if dirs != Ordering::Equal {
            return dirs;
        }
        let by = match key {
            SortKey::Name => Ordering::Equal,
            SortKey::Size => a.size.unwrap_or(0).cmp(&b.size.unwrap_or(0)),
            SortKey::Packed => a.packed_size.unwrap_or(0).cmp(&b.packed_size.unwrap_or(0)),
            // RFC 3339 in UTC sorts as text; entries without a time come first.
            SortKey::Modified => a.modified.cmp(&b.modified),
            SortKey::Kind => rank(a.kind).cmp(&rank(b.kind)),
        };
        let order = by.then_with(|| name(a).cmp(&name(b)));
        if reverse { order.reverse() } else { order }
    });
}

pub struct ArchiveList;

impl Command for ArchiveList {
    const NAME: &'static str = "archive.list";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "list",
        aliases: &["l"],
    });

    type Input = ArchiveListInput;
    type Output = ArchiveListOutput;

    fn access(input: &ArchiveListInput) -> Vec<Access> {
        vec![Access::Read(input.archive.clone())]
    }

    fn run(input: ArchiveListInput, cx: &mut JobCtx) -> Result<ArchiveListOutput, CmdError> {
        let mut opened = open_archive(&input.archive, input.password.as_ref(), cx)?;
        let entries = opened.reader.entries(cx)?;
        let dir = input.dir.as_deref().map(normalize).unwrap_or_default();
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let under = |path: &str| dir.is_empty() || path.starts_with(&prefix);
        let globs = input.glob.clone().unwrap_or_default();
        let flat = input.flat.unwrap_or(false) || !globs.is_empty();

        let listing: Vec<EntryInfo> = if flat {
            let sel = Selection::new(&[], &globs, &[])?;
            entries
                .iter()
                .filter(|e| {
                    let p = normalize(&e.path);
                    under(&p) && p != dir && sel.matches(e)
                })
                .map(EntryInfo::from_entry)
                .collect()
        } else {
            // One level: entries directly in `dir`, plus folders implied by deeper paths.
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            for e in entries {
                let p = normalize(&e.path);
                if !under(&p) || p == dir {
                    continue;
                }
                let rest = &p[prefix.len()..];
                match rest.split_once('/') {
                    None => {
                        if seen.insert(rest.to_owned()) {
                            out.push(EntryInfo::from_entry(e));
                        } else if let Some(i) = out
                            .iter()
                            .position(|o: &EntryInfo| o.id.is_none() && normalize(&o.path) == p)
                        {
                            // The folder's own entry, after a path inside it made it implied.
                            out[i] = EntryInfo::from_entry(e);
                        }
                    }
                    Some((first, _)) => {
                        if seen.insert(first.to_owned()) {
                            out.push(EntryInfo::implied_dir(format!("{prefix}{first}")));
                        }
                    }
                }
            }
            out
        };
        let mut listing = listing;
        if let Some(k) = input.kind {
            listing.retain(|e| k.matches(e.kind));
        }
        if let Some(key) = input.sort {
            sort(&mut listing, key, input.reverse.unwrap_or(false));
        }

        let total = listing.len() as u64;
        let offset = input.offset.unwrap_or(0).min(total);
        // A front end's cap (MCP's 500) shortens the page; `has_more` says to ask for the next.
        let limit = input
            .limit
            .unwrap_or(u64::MAX)
            .min(cx.policy().max_list_entries.unwrap_or(u64::MAX));
        let page: Vec<EntryInfo> = listing
            .into_iter()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .collect();
        let has_more = offset + (page.len() as u64) < total;
        Ok(ArchiveListOutput {
            entries: page,
            total,
            offset,
            has_more,
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

    fn info(path: &str, kind: EntryKindName, size: u64, modified: &str) -> EntryInfo {
        EntryInfo {
            id: Some(0),
            path: path.into(),
            kind,
            size: Some(size),
            packed_size: Some(size / 2),
            modified: Some(modified.into()),
            crc32: None,
            method: None,
            encrypted: false,
            target: None,
        }
    }

    #[test]
    fn sorting_puts_folders_first() {
        use EntryKindName as K;
        let all = vec![
            info("b.txt", K::File, 30, "2026-01-02T00:00:00Z"),
            info("Z", K::Dir, 0, "2026-01-05T00:00:00Z"),
            info("a.txt", K::File, 10, "2026-01-03T00:00:00Z"),
            info("l", K::Symlink, 0, "2026-01-01T00:00:00Z"),
            info("c.txt", K::File, 20, "2026-01-01T00:00:00Z"),
            info("a", K::Dir, 0, "2026-01-04T00:00:00Z"),
        ];
        let order = |key, reverse| {
            let mut v = all.clone();
            sort(&mut v, key, reverse);
            v.into_iter().map(|e| e.path).collect::<Vec<_>>()
        };
        assert_eq!(
            order(SortKey::Name, false),
            ["a", "Z", "a.txt", "b.txt", "c.txt", "l"]
        );
        assert_eq!(
            order(SortKey::Name, true),
            ["Z", "a", "l", "c.txt", "b.txt", "a.txt"]
        );
        assert_eq!(
            order(SortKey::Size, false),
            ["a", "Z", "l", "a.txt", "c.txt", "b.txt"]
        );
        assert_eq!(order(SortKey::Size, true)[..2], ["Z", "a"]);
        assert_eq!(
            order(SortKey::Modified, false)[2..],
            ["c.txt", "l", "b.txt", "a.txt"]
        );
        assert_eq!(
            order(SortKey::Kind, false),
            ["a", "Z", "a.txt", "b.txt", "c.txt", "l"]
        );
        let kept: Vec<_> = all
            .iter()
            .filter(|e| KindFilter::Link.matches(e.kind))
            .collect();
        assert_eq!(kept.len(), 1);
    }
}
