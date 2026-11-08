//! What `archive.list` builds over an archive's index, and the archive cache keeps with it
//! (docs/M3.md §4.2): the folder tree, and the listings it has filtered and sorted.
//!
//! Both hold row numbers rather than [`EntryInfo`]s, so a folder of a million entries costs
//! 8 MB here, and a page turns rows into `EntryInfo`s only for the entries it returns.

use std::{cmp::Ordering, collections::HashMap, sync::Arc, time::UNIX_EPOCH};

use beezip_core::{
    Selection,
    format::{Entry, EntryKind, normalize},
};

use crate::{
    CmdError,
    commands::archive_list::{KindFilter, SortKey},
    wire::{EntryInfo, EntryKindName},
};

/// The listings one archive keeps; the oldest goes first.
const MAX_LISTINGS: usize = 8;

/// One row of a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    /// `entries[i]`.
    Entry(usize),
    /// A folder that only exists as part of the paths under it: `Tree::implied[i]`.
    Implied(usize),
}

/// Every folder's children, in the order `archive.list` has always shown them: by first
/// appearance in the archive, the folder's own entry replacing the stand-in a path inside
/// it made first, and later duplicates left out.
#[derive(Debug, Default)]
pub struct Tree {
    levels: HashMap<String, Vec<Row>>,
    implied: Vec<String>,
}

enum Seen {
    Real,
    /// An implied folder, at this index of its parent's level.
    Implied(usize),
}

impl Tree {
    /// One pass over the index.
    pub fn build(entries: &[Entry]) -> Self {
        let mut tree = Self::default();
        // Every path placed so far. Dropped when the tree is built.
        let mut seen: HashMap<String, Seen> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            let p = normalize(&e.path);
            if p.is_empty() {
                continue;
            }
            for (j, _) in p.match_indices('/') {
                let dir = &p[..j];
                if !seen.contains_key(dir) {
                    let level = tree.levels.entry(parent(dir).to_owned()).or_default();
                    level.push(Row::Implied(tree.implied.len()));
                    seen.insert(dir.to_owned(), Seen::Implied(level.len() - 1));
                    tree.implied.push(dir.to_owned());
                }
            }
            let level = tree.levels.entry(parent(&p).to_owned()).or_default();
            match seen.get(p.as_str()) {
                None => {
                    level.push(Row::Entry(i));
                    seen.insert(p, Seen::Real);
                }
                Some(Seen::Implied(at)) => {
                    level[*at] = Row::Entry(i);
                    seen.insert(p, Seen::Real);
                }
                Some(Seen::Real) => {}
            }
        }
        tree
    }

    /// The children of `dir` (normalised; `""` is the root).
    pub fn level(&self, dir: &str) -> &[Row] {
        self.levels.get(dir).map(Vec::as_slice).unwrap_or_default()
    }

    fn rows(&self) -> usize {
        self.levels.values().map(Vec::len).sum()
    }
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
}

/// What makes two listings the same, apart from paging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListKey {
    /// Normalised; `""` is the root.
    pub dir: String,
    pub flat: bool,
    pub globs: Vec<String>,
    pub kind: Option<KindFilter>,
    pub sort: Option<SortKey>,
    pub reverse: bool,
}

/// The tree and the listings built over one archive's index.
#[derive(Debug, Default)]
pub struct Memo {
    tree: Option<Tree>,
    /// Most recently used last.
    listings: Vec<(ListKey, Arc<Vec<Row>>)>,
}

impl Memo {
    /// How many rows it holds, which the cache counts against its entry limit.
    pub fn rows(&self) -> usize {
        self.tree.as_ref().map_or(0, Tree::rows)
            + self.listings.iter().map(|(_, l)| l.len()).sum::<usize>()
    }

    /// The listing `key` describes, built once.
    pub fn listing(&mut self, entries: &[Entry], key: &ListKey) -> Result<Arc<Vec<Row>>, CmdError> {
        if let Some(i) = self.listings.iter().position(|(k, _)| k == key) {
            let hit = self.listings.remove(i);
            let rows = Arc::clone(&hit.1);
            self.listings.push(hit);
            return Ok(rows);
        }
        let mut rows: Vec<Row> = if key.flat || !key.globs.is_empty() {
            let sel = Selection::new(&[], &key.globs, &[])?;
            let prefix = format!("{}/", key.dir);
            entries
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    let p = normalize(&e.path);
                    (key.dir.is_empty() || p.starts_with(&prefix)) && p != key.dir && sel.matches(e)
                })
                .map(|(i, _)| Row::Entry(i))
                .collect()
        } else {
            self.tree
                .get_or_insert_with(|| Tree::build(entries))
                .level(&key.dir)
                .to_vec()
        };
        let implied: &[String] = self.tree.as_ref().map_or(&[], |t| &t.implied);
        if let Some(k) = key.kind {
            rows.retain(|r| k.matches(kind_of(entries, *r)));
        }
        if let Some(by) = key.sort {
            sort(&mut rows, entries, implied, by, key.reverse);
        }
        let rows = Arc::new(rows);
        if self.listings.len() >= MAX_LISTINGS {
            self.listings.remove(0);
        }
        self.listings.push((key.clone(), Arc::clone(&rows)));
        Ok(rows)
    }

    /// A row as `archive.list` returns it.
    pub fn info(&self, entries: &[Entry], row: Row) -> EntryInfo {
        match row {
            Row::Entry(i) => EntryInfo::from_entry(&entries[i]),
            Row::Implied(i) => EntryInfo::implied_dir(
                self.tree
                    .as_ref()
                    .and_then(|t| t.implied.get(i))
                    .cloned()
                    .unwrap_or_default(),
            ),
        }
    }
}

fn kind_of(entries: &[Entry], row: Row) -> EntryKindName {
    match row {
        Row::Implied(_) => EntryKindName::Dir,
        Row::Entry(i) => match entries[i].kind {
            EntryKind::File => EntryKindName::File,
            EntryKind::Dir => EntryKindName::Dir,
            EntryKind::Symlink { .. } => EntryKindName::Symlink,
            EntryKind::Hardlink { .. } => EntryKindName::Hardlink,
            EntryKind::Other => EntryKindName::Other,
        },
    }
}

/// Folders first, then by `key`; ties go by name (case-insensitively, then exactly), then
/// archive order (a stable sort). `reverse` turns everything but the folders-first round.
fn sort(rows: &mut Vec<Row>, entries: &[Entry], implied: &[String], key: SortKey, reverse: bool) {
    struct Keyed<'e> {
        row: Row,
        not_dir: bool,
        by: i128,
        text: &'e str,
        folded: String,
        name: String,
    }
    let rank = |k: EntryKindName| match k {
        EntryKindName::Dir => 0,
        EntryKindName::File | EntryKindName::Hardlink | EntryKindName::Other => 1,
        EntryKindName::Symlink => 2,
    };
    let mut keyed: Vec<Keyed<'_>> = rows
        .iter()
        .map(|&row| {
            let kind = kind_of(entries, row);
            let (path, e) = match row {
                Row::Entry(i) => (normalize(&entries[i].path), Some(&entries[i])),
                Row::Implied(i) => (implied.get(i).cloned().unwrap_or_default(), None),
            };
            let name = path.rsplit('/').next().unwrap_or(&path).to_owned();
            let by = match key {
                SortKey::Name => 0,
                SortKey::Size => i128::from(e.and_then(|e| e.size).unwrap_or(0)),
                SortKey::Packed => i128::from(e.and_then(|e| e.packed_size).unwrap_or(0)),
                // Entries without a time come first.
                SortKey::Modified => e.and_then(|e| e.modified).map_or(i128::MIN, |t| {
                    match t.duration_since(UNIX_EPOCH) {
                        Ok(d) => d.as_nanos() as i128,
                        Err(before) => -(before.duration().as_nanos() as i128),
                    }
                }),
                SortKey::Kind => rank(kind),
                SortKey::Crc => e.and_then(|e| e.crc32).map_or(-1, i128::from),
                SortKey::Encrypted => i128::from(e.is_some_and(|e| e.encrypted)),
                SortKey::Method => 0,
            };
            let text = match key {
                SortKey::Method => e.and_then(|e| e.method.as_deref()).unwrap_or(""),
                _ => "",
            };
            Keyed {
                row,
                not_dir: kind != EntryKindName::Dir,
                by,
                text,
                folded: name.to_lowercase(),
                name,
            }
        })
        .collect();
    keyed.sort_by(|a, b| {
        let dirs = a.not_dir.cmp(&b.not_dir);
        if dirs != Ordering::Equal {
            return dirs;
        }
        let order =
            a.by.cmp(&b.by)
                .then_with(|| a.text.cmp(b.text))
                .then_with(|| a.folded.cmp(&b.folded))
                .then_with(|| a.name.cmp(&b.name));
        if reverse { order.reverse() } else { order }
    });
    *rows = keyed.into_iter().map(|k| k.row).collect();
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    fn entry(id: usize, path: &str, kind: EntryKind, size: u64, day: u64) -> Entry {
        let mut e = Entry::new(id, path.into(), kind);
        if matches!(e.kind, EntryKind::File) {
            e.method = Some(if size > 15 { "Deflate" } else { "Store" }.into());
            e.crc32 = Some(size as u32);
        }
        e.size = Some(size);
        e.packed_size = Some(size / 2);
        e.modified = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(day * 86_400));
        e
    }

    fn key(dir: &str) -> ListKey {
        ListKey {
            dir: dir.into(),
            flat: false,
            globs: Vec::new(),
            kind: None,
            sort: None,
            reverse: false,
        }
    }

    fn paths(memo: &Memo, entries: &[Entry], rows: &[Row]) -> Vec<String> {
        rows.iter().map(|r| memo.info(entries, *r).path).collect()
    }

    #[test]
    fn levels_keep_archive_order_and_imply_folders() {
        let entries = vec![
            entry(0, "b/x.txt", EntryKind::File, 1, 1),
            entry(1, "a.txt", EntryKind::File, 1, 1),
            entry(2, "b", EntryKind::Dir, 0, 1),
            entry(3, "c/d/e.txt", EntryKind::File, 1, 1),
            entry(4, "a.txt", EntryKind::File, 2, 1),
            entry(5, "./c/d/f.txt", EntryKind::File, 1, 1),
        ];
        let mut memo = Memo::default();
        let root = memo.listing(&entries, &key("")).unwrap();
        // `b` was implied first, then replaced by its own entry; the second `a.txt` is a
        // duplicate.
        assert_eq!(
            root.as_slice(),
            [Row::Entry(2), Row::Entry(1), Row::Implied(1)]
        );
        assert_eq!(paths(&memo, &entries, &root), ["b", "a.txt", "c"]);
        let c = memo.listing(&entries, &key("c")).unwrap();
        assert_eq!(paths(&memo, &entries, &c), ["c/d"]);
        let d = memo.listing(&entries, &key("c/d")).unwrap();
        assert_eq!(paths(&memo, &entries, &d), ["c/d/e.txt", "./c/d/f.txt"]);
        assert!(memo.listing(&entries, &key("nowhere")).unwrap().is_empty());
    }

    #[test]
    fn sorting_puts_folders_first() {
        let entries = vec![
            entry(0, "b.txt", EntryKind::File, 30, 2),
            entry(1, "Z", EntryKind::Dir, 0, 5),
            entry(2, "a.txt", EntryKind::File, 10, 3),
            entry(
                3,
                "l",
                EntryKind::Symlink {
                    target: "a.txt".into(),
                },
                0,
                1,
            ),
            entry(4, "c.txt", EntryKind::File, 20, 1),
            entry(5, "a", EntryKind::Dir, 0, 4),
        ];
        let order = |by, reverse| {
            let mut memo = Memo::default();
            let k = ListKey {
                sort: Some(by),
                reverse,
                ..key("")
            };
            let rows = memo.listing(&entries, &k).unwrap();
            paths(&memo, &entries, &rows)
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
        assert_eq!(
            order(SortKey::Encrypted, false)[2..],
            ["a.txt", "b.txt", "c.txt", "l"]
        );
        assert_eq!(
            order(SortKey::Crc, true)[2..],
            ["b.txt", "c.txt", "a.txt", "l"]
        );
        assert_eq!(
            order(SortKey::Method, false)[2..],
            ["l", "b.txt", "c.txt", "a.txt"]
        );
    }

    #[test]
    fn listings_are_kept_and_counted() {
        let entries: Vec<Entry> = (0..10)
            .map(|i| entry(i, &format!("d/f{i}"), EntryKind::File, i as u64, 1))
            .collect();
        let mut memo = Memo::default();
        let a = memo.listing(&entries, &key("d")).unwrap();
        let b = memo.listing(&entries, &key("d")).unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "the second call reuses the first listing"
        );
        // The tree (1 implied folder + 10 files) and one listing of 10.
        assert_eq!(memo.rows(), 11 + 10);
        let flat = ListKey {
            flat: true,
            kind: Some(KindFilter::Dir),
            ..key("")
        };
        assert!(memo.listing(&entries, &flat).unwrap().is_empty());
        for n in 0..MAX_LISTINGS {
            let k = ListKey {
                globs: vec![format!("f{n}")],
                ..key("")
            };
            assert_eq!(memo.listing(&entries, &k).unwrap().len(), 1);
        }
        assert_eq!(memo.listings.len(), MAX_LISTINGS);
    }
}
