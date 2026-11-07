//! Editing (docs/M5.md §3). Nothing writes into an archive: every edit writes a new one beside
//! it and swaps it in ([`swap`]). [`rewrite`] writes an archive from a source's entries, copied
//! as they are where the writer can ([`crate::ArchiveWriter::copy_from`]) and decoded
//! otherwise ([`generic`]), then new files from disk. [`edit`] adds, removes or renames entries
//! of an archive; [`convert`] writes its entries to another.

pub mod generic;
pub mod swap;

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{
    CodecId, Ctx, Error, ErrorKind, Meter, MeteredCtx, OverwriteChoice, Result,
    format::{
        ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind, FormatId, Keep, NewKind,
        Selection, caps_for, normalize,
        sevenz::SevenZReader,
        zip::{ZipReader, ZipWriter},
    },
    io::{Counter, WriteSeek},
    ops::{ArchiveKind, CreateOptions, Planned, TAR_CODECS, WriteSpec, add_planned, create_writer},
    safefs::{OverwritePolicy, Partial},
    source::{OpenOptions, Opened, open},
    volume::VolumeWriter,
};

/// One entry of the archive being written (docs/M5.md §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// An entry of the source, under its own name or a new one.
    Keep(Keep),
    /// A file, folder or link from disk, as `ops::plan` finds them.
    New(Planned),
}

/// An entry that couldn't go into the new archive, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

/// What [`rewrite`] wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RewriteReport {
    /// Source entries copied without decoding.
    pub copied: u64,
    /// Source entries decoded and encoded again: a changed 7z block's, a compressed tar's, or
    /// any the writer couldn't copy.
    pub recompressed: u64,
    /// Entries written of each kind, from the source and from disk.
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    /// New files' bytes, read from disk.
    pub bytes_in: u64,
    pub skipped: Vec<Skipped>,
}

/// Writes `items` to `writer` and finishes it: the kept entries in the source's order, copied
/// as they are when `raw` allows and the writer can, decoded otherwise; then the new ones, in
/// `ops::plan`'s order.
pub fn rewrite(
    source: &mut dyn ArchiveReader,
    items: &[Item],
    mut writer: Box<dyn ArchiveWriter>,
    raw: bool,
    cx: &mut dyn Ctx,
) -> Result<RewriteReport> {
    let keeps: Vec<Keep> = items
        .iter()
        .filter_map(|i| match i {
            Item::Keep(k) => Some(k.clone()),
            Item::New(_) => None,
        })
        .collect();
    let news: Vec<Planned> = items
        .iter()
        .filter_map(|i| match i {
            Item::New(p) => Some(p.clone()),
            Item::Keep(_) => None,
        })
        .collect();
    let counter = Counter::new();
    let new_bytes: u64 = news.iter().map(|p| p.entry.size).sum();
    let mut meter = Meter::new(counter.clone(), Some(new_bytes));
    meter.entries_total = Some(items.len() as u64);
    let mut report = RewriteReport::default();

    if !keeps.is_empty() {
        // How each kept entry counts, by the source's kinds.
        let kinds: HashMap<usize, EntryKind> = source
            .entries(cx)?
            .iter()
            .map(|e| (e.id, e.kind.clone()))
            .collect();
        let copied = if raw {
            let mut mcx = MeteredCtx::new(cx, &meter);
            writer.copy_from(source, &keeps, &mut mcx)?
        } else {
            crate::format::Copied::nothing(&keeps)
        };
        report.copied = copied.copied;
        report.recompressed = copied.recompressed;
        let rest: HashSet<usize> = copied.rest.iter().copied().collect();
        for k in keeps.iter().filter(|k| !rest.contains(&k.id)) {
            match kinds.get(&k.id) {
                Some(EntryKind::Dir) => report.dirs += 1,
                Some(EntryKind::Symlink { .. }) => report.links += 1,
                _ => report.files += 1,
            }
        }
        meter.entries_done = report.copied + report.recompressed;
        if !rest.is_empty() {
            let rest: Vec<Keep> = keeps.into_iter().filter(|k| rest.contains(&k.id)).collect();
            let decoded = generic::decode_into(source, &mut *writer, &rest, &mut meter, cx)?;
            report.recompressed += decoded.files + decoded.dirs + decoded.links;
            report.files += decoded.files;
            report.dirs += decoded.dirs;
            report.links += decoded.links;
            report.skipped = decoded.skipped;
        }
    }
    let first = meter.entries_done;
    let added = add_planned(&mut *writer, &news, &counter, &mut meter, first, cx)?;
    report.files += added.files;
    report.dirs += added.dirs;
    report.links += added.links;
    writer.finish()?;
    meter.entries_done = items.len() as u64;
    MeteredCtx::new(cx, &meter).report();
    report.bytes_in = counter.get();
    Ok(report)
}

/// A writer for `spec` on `file`. A zip written to a file can copy another zip's entries byte
/// for byte, since it reads its own output back (docs/M5.md §3.3).
pub fn file_writer(spec: &WriteSpec, file: fs::File) -> Result<Box<dyn ArchiveWriter>> {
    match spec {
        WriteSpec::Zip(o) => Ok(Box::new(ZipWriter::editing(file, o.clone())?)),
        other => create_writer(other, Box::new(file)),
    }
}

/// What happens to an entry in an edit, for dry runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Add,
    Replace,
    Remove,
    Rename,
    Skip,
}

/// One change an edit makes: `path` is the entry's path afterwards (before, for a removal),
/// `from` its old path for a rename, or the file on disk for an add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub action: Action,
    pub path: String,
    pub from: Option<String>,
}

/// What to add, and how (`archive.add`, docs/M5.md §7.1).
#[derive(Debug, Clone, Default)]
pub struct AddOptions {
    pub inputs: Vec<PathBuf>,
    /// The folder inside the archive to add into; empty for the top.
    pub dir: String,
    /// An entry with the same path (ignoring case on Windows): ask, replace it, keep it, replace
    /// it when the file is newer, or add the file as `a (1).txt`.
    pub overwrite: OverwritePolicy,
    /// `exclude` and `follow_links`, as for create.
    pub create: CreateOptions,
    /// Add the new files in the clear to an archive whose entries are encrypted.
    pub unencrypted: bool,
}

/// An edit.
#[derive(Debug, Clone)]
pub enum EditOp {
    Add(AddOptions),
    /// Removes what the selection matches; a folder takes everything under it.
    Remove(Selection),
    /// Renames an entry, or a folder and everything under it; `to` is the new full path.
    Rename {
        from: String,
        to: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct EditOptions {
    pub open: OpenOptions,
    /// Report what would change, and write nothing.
    pub dry_run: bool,
}

/// What an edit did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EditReport {
    /// The canonical path of the archive written.
    pub path: PathBuf,
    pub kind: Option<ArchiveKind>,
    pub added: u64,
    pub replaced: u64,
    pub removed: u64,
    pub renamed: u64,
    pub skipped: u64,
    /// The entries the archive has afterwards.
    pub entries: u64,
    pub copied: u64,
    pub recompressed: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// New files added in the clear to an archive whose entries are encrypted.
    pub unencrypted: u64,
    pub dry_run: bool,
    /// Every change, in order; filled for dry runs.
    pub plan: Vec<Change>,
}

/// `path` as selections compare it: `/`-separated, and folded to lower case on Windows.
fn key(path: &str) -> String {
    let p = normalize(path);
    if cfg!(windows) { p.to_lowercase() } else { p }
}

/// `parent/name`, without doubling the slash.
fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

/// The parent folders of a key: `a/b/c` → `a`, `a/b`.
fn parents(key: &str) -> impl Iterator<Item = &str> {
    key.match_indices('/').map(move |(i, _)| &key[..i])
}

/// A name as the archive's users see it, for messages.
fn shown(archive: &Path) -> String {
    archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| archive.display().to_string())
}

/// The archive kind an edit writes back, or why the archive can't be edited (docs/M5.md
/// §3.7, §3.9).
pub fn editable(name: &str, opened: &mut Opened, cx: &mut dyn Ctx) -> Result<ArchiveKind> {
    let d = &opened.detection;
    let split = || {
        Error::unsupported(format!(
            "{name} is split into volumes, and BeeZip doesn't edit split archives. Convert it \
             to one file (`beezip convert`), or extract it and create it again."
        ))
    };
    if d.joined || d.volumes.len() > 1 {
        return Err(split());
    }
    let (format, codecs) = d.require_archive()?;
    let caps = caps_for(format, &codecs);
    if !(caps.append && caps.delete && caps.rename) {
        return Err(Error::unsupported(match format {
            FormatId::Rar => {
                format!("{name} is a RAR archive, which BeeZip reads but never writes")
            }
            FormatId::Stream => format!(
                "{name} is a compressed file, not an archive; there are no entries to change"
            ),
            other => format!("BeeZip doesn't edit {} archives", other.display_name()),
        }));
    }
    let sfx = d.sfx || d.offset > 0;
    let info = opened.reader.info(cx)?;
    if sfx || info.sfx {
        return Err(Error::unsupported(format!(
            "{name} is a self-extracting archive, and BeeZip doesn't edit those: its program \
             would have to be kept. Convert it to an archive (`beezip convert`), or extract it \
             and create it again."
        )));
    }
    if info.volumes > 1 {
        return Err(split());
    }
    let kind = match (format, codecs.as_slice()) {
        (FormatId::Zip, []) => ArchiveKind::Zip,
        (FormatId::SevenZ, []) => ArchiveKind::SevenZ,
        (FormatId::Tar, []) => ArchiveKind::Tar(None),
        (FormatId::Tar, [c]) if TAR_CODECS.contains(c) => ArchiveKind::Tar(Some(*c)),
        (_, cs) => {
            let chain: Vec<&str> = cs.iter().map(|c: &CodecId| c.name()).collect();
            return Err(Error::unsupported(format!(
                "{name} is a {} inside {}, which BeeZip doesn't edit; convert it first",
                format.display_name(),
                chain.join(" inside ")
            )));
        }
    };
    if let Some(z) = opened.reader.as_any_mut().downcast_mut::<ZipReader>()
        && z.has_duplicate_names()
    {
        return Err(Error::unsupported(format!(
            "{name} holds two entries with the same name, and an edit would lose one of them. \
             Extract it and create it again."
        )));
    }
    Ok(kind)
}

/// Why `archive`, opened as `opened`, can't be edited, or `None` when it can: the checks
/// [`edit`] makes before it writes anything ([`editable`], then a read-only file), for front ends
/// that disable their edit commands up front (docs/M5.md §8.1, §9). Errors other than these
/// refusals, such as a password nobody could give, are returned as they are.
pub fn refusal(archive: &Path, opened: &mut Opened, cx: &mut dyn Ctx) -> Result<Option<String>> {
    let name = shown(archive);
    match editable(&name, opened, cx) {
        Ok(_) => {}
        Err(e) if e.kind == ErrorKind::UnsupportedOperation => return Ok(Some(e.message)),
        Err(e) => return Err(e),
    }
    let read_only = fs::metadata(archive).is_ok_and(|m| m.permissions().readonly());
    Ok(read_only.then(|| format!("{name} is read-only")))
}

/// The items and changes of an edit.
struct Plan {
    items: Vec<Item>,
    changes: Vec<Change>,
}

/// `name (1).ext`, `name (2).ext`… in `parent`, whichever isn't `taken`.
fn free_name(path: &str, taken: &HashSet<String>) -> String {
    let p = normalize(path);
    let (parent, name) = match p.rfind('/') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => ("", p.as_str()),
    };
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..)
        .map(|n| join(parent, &format!("{stem} ({n}){ext}")))
        .find(|c| !taken.contains(&key(c)))
        .unwrap_or_else(|| join(parent, &format!("{stem} (copy){ext}")))
}

fn plan_add(archive: &Path, entries: &[Entry], add: &AddOptions, cx: &mut dyn Ctx) -> Result<Plan> {
    let name = shown(archive);
    let dir = normalize(&add.dir);
    if dir.split('/').any(|c| c == "..") {
        return Err(Error::invalid_args("`dir` can't contain `..`"));
    }
    let planned = crate::ops::plan(&add.inputs, archive, &add.create)?;
    let existing: HashMap<String, usize> = entries.iter().map(|e| (key(&e.path), e.id)).collect();
    // Folders that exist only as the parents of entries.
    let implied: HashSet<String> = entries
        .iter()
        .flat_map(|e| {
            parents(&key(&e.path))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    let mut taken: HashSet<String> = existing.keys().cloned().collect();
    taken.extend(implied.iter().cloned());
    let mut removed: HashSet<usize> = HashSet::new();
    let mut news = Vec::new();
    let mut changes = Vec::new();
    let (mut replace_all, mut skip_all) = (false, false);
    for mut p in planned {
        cx.check()?;
        let path = join(&dir, &p.entry.path);
        let k = key(&path);
        let from = Some(p.source.display().to_string());
        let is_dir = p.entry.kind == NewKind::Dir;
        // A new path under something that is a file in the archive.
        if let Some(file) = parents(&k).find(|q| {
            existing
                .get(*q)
                .is_some_and(|&id| !entries[id].is_dir() && !removed.contains(&id))
        }) {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!("`{file}` is a file in {name}, so `{path}` can't go under it"),
            ));
        }
        let Some(&id) = existing.get(&k) else {
            if implied.contains(&k) {
                if is_dir {
                    continue;
                }
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!("`{path}` is a folder in {name}"),
                ));
            }
            p.entry.path = path.clone();
            news.push(p);
            changes.push(Change {
                action: Action::Add,
                path,
                from,
            });
            continue;
        };
        let old = &entries[id];
        if old.is_dir() && is_dir {
            continue;
        }
        if old.is_dir() != is_dir {
            let what = if old.is_dir() { "a folder" } else { "a file" };
            return Err(Error::new(
                ErrorKind::Conflict,
                format!("`{}` is {what} in {name}", old.path.trim_end_matches('/')),
            ));
        }
        let choice = match add.overwrite {
            OverwritePolicy::Always => OverwriteChoice::Replace,
            OverwritePolicy::Never => OverwriteChoice::Skip,
            OverwritePolicy::Rename => OverwriteChoice::Rename,
            OverwritePolicy::Newer => match (p.entry.modified, old.modified) {
                (Some(new), Some(old)) if new <= old => OverwriteChoice::Skip,
                _ => OverwriteChoice::Replace,
            },
            OverwritePolicy::Ask if replace_all => OverwriteChoice::Replace,
            OverwritePolicy::Ask if skip_all => OverwriteChoice::Skip,
            OverwritePolicy::Ask => {
                let c = cx.overwrite_entry(archive, &old.path)?;
                replace_all |= c == OverwriteChoice::ReplaceAll;
                skip_all |= c == OverwriteChoice::SkipAll;
                c
            }
        };
        match choice {
            OverwriteChoice::Replace | OverwriteChoice::ReplaceAll => {
                removed.insert(id);
                p.entry.path = path.clone();
                news.push(p);
                changes.push(Change {
                    action: Action::Replace,
                    path,
                    from,
                });
            }
            OverwriteChoice::Skip | OverwriteChoice::SkipAll => changes.push(Change {
                action: Action::Skip,
                path,
                from,
            }),
            OverwriteChoice::Rename => {
                let renamed = free_name(&path, &taken);
                taken.insert(key(&renamed));
                p.entry.path = renamed.clone();
                news.push(p);
                changes.push(Change {
                    action: Action::Add,
                    path: renamed,
                    from,
                });
            }
        }
    }
    let mut items: Vec<Item> = entries
        .iter()
        .filter(|e| !removed.contains(&e.id))
        .map(|e| {
            Item::Keep(Keep {
                id: e.id,
                path: e.path.clone(),
            })
        })
        .collect();
    items.extend(news.into_iter().map(Item::New));
    Ok(Plan { items, changes })
}

/// Hard links among `kept` whose target is in `gone`, by the target's path.
fn orphaned_links(entries: &[Entry], gone: &HashSet<usize>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in entries.iter().filter(|e| !gone.contains(&e.id)) {
        let EntryKind::Hardlink { target } = &e.kind else {
            continue;
        };
        let t = normalize(target);
        if let Some(to) = entries[..e.id.min(entries.len())]
            .iter()
            .rev()
            .find(|x| normalize(&x.path) == t)
            && gone.contains(&to.id)
        {
            out.push((t.clone(), e.path.clone()));
        }
    }
    out
}

fn plan_remove(archive: &Path, entries: &[Entry], sel: &Selection) -> Result<Plan> {
    let name = shown(archive);
    let gone: HashSet<usize> = entries
        .iter()
        .filter(|e| sel.matches(e))
        .map(|e| e.id)
        .collect();
    if gone.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("nothing in {name} matches"),
        ));
    }
    let orphans = orphaned_links(entries, &gone);
    if !orphans.is_empty() {
        let mut by_target: Vec<(String, Vec<String>)> = Vec::new();
        for (t, l) in orphans {
            match by_target.iter_mut().find(|(x, _)| *x == t) {
                Some((_, ls)) => ls.push(l),
                None => by_target.push((t, vec![l])),
            }
        }
        let list: Vec<String> = by_target
            .iter()
            .map(|(t, ls)| format!("`{t}` (from {})", ls.join(", ")))
            .collect();
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "hard links in {name} that would stay point to {}. Remove the links too, or \
                 extract the archive and create it again.",
                list.join("; ")
            ),
        ));
    }
    let mut items = Vec::new();
    let mut changes = Vec::new();
    for e in entries {
        if gone.contains(&e.id) {
            changes.push(Change {
                action: Action::Remove,
                path: e.path.clone(),
                from: None,
            });
        } else {
            items.push(Item::Keep(Keep {
                id: e.id,
                path: e.path.clone(),
            }));
        }
    }
    Ok(Plan { items, changes })
}

/// Checks a rename's new path (docs/M5.md §7.3): not empty or absolute, no `..`.
fn check_new_path(to: &str) -> Result<String> {
    let raw = to.replace('\\', "/");
    let drive = raw.len() >= 2 && raw.as_bytes()[1] == b':';
    if raw.starts_with('/') || drive {
        return Err(Error::invalid_args(format!(
            "`{to}` is absolute; give a path inside the archive"
        )));
    }
    let n = normalize(&raw);
    if n.is_empty() {
        return Err(Error::invalid_args("the new name is empty"));
    }
    if n.split('/').any(|c| c == ".." || c == "." || c.is_empty()) {
        return Err(Error::invalid_args(format!(
            "`{to}` can't contain `..`, `.` or empty parts"
        )));
    }
    Ok(n)
}

fn plan_rename(archive: &Path, entries: &[Entry], from: &str, to: &str) -> Result<Plan> {
    let name = shown(archive);
    let from = normalize(from);
    let to = check_new_path(to)?;
    let (fk, tk) = (key(&from), key(&to));
    if from.is_empty() {
        return Err(Error::invalid_args("say which entry to rename"));
    }
    if to == from {
        return Err(Error::invalid_args(format!(
            "`{from}` already has that name"
        )));
    }
    if tk.starts_with(&format!("{fk}/")) {
        return Err(Error::invalid_args(format!(
            "`{to}` is inside `{from}`, so it can't move there"
        )));
    }
    let under = |k: &str, root: &str| k == root || k.starts_with(&format!("{root}/"));
    let moving: HashSet<usize> = entries
        .iter()
        .filter(|e| under(&key(&e.path), &fk))
        .map(|e| e.id)
        .collect();
    if moving.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("`{from}` isn't in {name}"),
        ));
    }
    if tk != fk {
        let clash = entries
            .iter()
            .filter(|e| !moving.contains(&e.id))
            .find(|e| {
                let k = key(&e.path);
                under(&k, &tk) || (!e.is_dir() && parents(&tk).any(|p| p == k))
            });
        if let Some(e) = clash {
            let k = key(&e.path);
            let msg = if under(&k, &tk) {
                format!("`{to}` is already in {name}")
            } else {
                format!(
                    "`{}` is a file in {name}, so `{to}` can't go under it",
                    e.path
                )
            };
            return Err(Error::new(ErrorKind::Conflict, msg));
        }
    }
    let mut items = Vec::new();
    let mut changes = Vec::new();
    for e in entries {
        if !moving.contains(&e.id) {
            items.push(Item::Keep(Keep {
                id: e.id,
                path: e.path.clone(),
            }));
            continue;
        }
        let n = normalize(&e.path);
        let rest = &n[from.len().min(n.len())..];
        let mut path = format!("{to}{rest}");
        if e.path.ends_with('/') {
            path.push('/');
        }
        changes.push(Change {
            action: Action::Rename,
            path: path.clone(),
            from: Some(e.path.clone()),
        });
        items.push(Item::Keep(Keep { id: e.id, path }));
    }
    Ok(Plan { items, changes })
}

/// Edits `archive` in place (docs/M5.md §3.1): checks it, plans the change, writes the new
/// archive beside it and swaps it in. `spec` gives the write options for the archive's kind;
/// the encryption is then made to follow the archive's (§3.7).
pub fn edit(
    archive: &Path,
    op: &EditOp,
    spec: &mut dyn FnMut(ArchiveKind) -> Result<WriteSpec>,
    opts: &EditOptions,
    cx: &mut dyn Ctx,
) -> Result<EditReport> {
    let target = swap::Target::check(archive)?;
    let name = target.name.clone();
    let mut opened = open(&target.path, &opts.open, cx)?;
    let kind = editable(&name, &mut opened, cx)?;
    // The write options are checked before anything else, dry runs included.
    let mut spec = spec(kind)?;
    let entries = opened.reader.entries(cx)?.to_vec();
    let plan = match op {
        EditOp::Add(add) => plan_add(&target.path, &entries, add, cx)?,
        EditOp::Remove(sel) => plan_remove(&target.path, &entries, sel)?,
        EditOp::Rename { from, to } => plan_rename(&target.path, &entries, from, to)?,
    };
    let count = |a: Action| plan.changes.iter().filter(|c| c.action == a).count() as u64;
    let mut report = EditReport {
        path: target.path.clone(),
        kind: Some(kind),
        added: count(Action::Add),
        replaced: count(Action::Replace),
        removed: count(Action::Remove),
        renamed: count(Action::Rename),
        skipped: count(Action::Skip),
        entries: plan.items.len() as u64,
        bytes_before: target.stamp.size,
        dry_run: opts.dry_run,
        ..EditReport::default()
    };
    if opts.dry_run {
        report.bytes_after = report.bytes_before;
        report.plan = plan.changes;
        return Ok(report);
    }
    let changed = plan.changes.iter().any(|c| c.action != Action::Skip);
    if !changed {
        // Everything was skipped: nothing to write.
        report.bytes_after = report.bytes_before;
        return Ok(report);
    }

    let new_files = plan
        .items
        .iter()
        .filter(|i| matches!(i, Item::New(p) if p.entry.kind == NewKind::File))
        .count() as u64;
    let unencrypted = matches!(op, EditOp::Add(a) if a.unencrypted);
    let info = opened.reader.info(cx)?;
    let encrypted = info.encryption != Encryption::None;
    match &mut spec {
        WriteSpec::Zip(o) => {
            if unencrypted {
                o.password = None;
            } else if encrypted && new_files > 0 && o.password.is_none() {
                o.password = Some(cx.password(None, 0)?);
            }
        }
        WriteSpec::SevenZ(o) => {
            let r = opened.reader.as_any_mut().downcast_mut::<SevenZReader>();
            let header = r.as_ref().is_some_and(|r| r.encrypted_header());
            o.encrypt_headers = header;
            if header {
                // The names stay encrypted, with the password that opened them; new blocks use it.
                o.password = r.and_then(|r| r.password().map(str::to_owned));
            } else if unencrypted {
                o.password = None;
            } else if encrypted && new_files > 0 && o.password.is_none() {
                o.password = Some(cx.password(None, 0)?);
            }
        }
        WriteSpec::Tar { .. } => {}
    }
    if unencrypted && encrypted {
        report.unencrypted = new_files;
    }

    let partial = target.partial()?;
    let writer = file_writer(&spec, partial.try_clone()?)?;
    let written = rewrite(&mut *opened.reader, &plan.items, writer, true, cx)?;
    drop(opened);
    report.copied = written.copied;
    report.recompressed = written.recompressed;
    target.swap(partial, cx)?;
    report.bytes_after = fs::metadata(&target.path).map(|m| m.len()).unwrap_or(0);
    Ok(report)
}

/// How to convert (docs/M5.md §7.5).
#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    /// The entries to convert; all by default.
    pub selection: Selection,
    /// Copy entries as they are when the output's format is the source's. Off when an option
    /// asks for something else (a method, a level, a password).
    pub raw: bool,
    pub overwrite: bool,
    pub volume_size: Option<u64>,
    /// Write an encrypted source's entries in the clear.
    pub decrypt: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConvertReport {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub copied: u64,
    pub recompressed: u64,
    pub skipped: Vec<Skipped>,
    /// The source's size.
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// The volumes written, first part first, when the output was split.
    pub volumes: Vec<PathBuf>,
    /// For a dry run, the entries that would be written.
    pub plan: Vec<String>,
}

/// Writes `source`'s entries to a new archive at `output` as `spec` says, through a partial
/// file, as create does. The source isn't changed.
pub fn convert(
    source: &Path,
    output: &Path,
    kind: ArchiveKind,
    spec: &WriteSpec,
    opts: &ConvertOptions,
    open_opts: &OpenOptions,
    cx: &mut dyn Ctx,
) -> Result<ConvertReport> {
    let name = shown(source);
    let same = |a: &Path, b: &Path| match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if same(source, output) {
        return Err(Error::invalid_args(format!(
            "the output is {name} itself; add, remove and rename change an archive in place"
        )));
    }
    if opts.volume_size.is_none() && !opts.overwrite && fs::symlink_metadata(output).is_ok() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("`{}` already exists", output.display()),
        ));
    }
    let mut opened = open(source, open_opts, cx)?;
    let (format, codecs) = opened.detection.require_archive()?;
    let info = opened.reader.info(cx)?;
    let entries = opened.reader.entries(cx)?.to_vec();
    let selected: Vec<&Entry> = entries
        .iter()
        .filter(|e| opts.selection.matches(e))
        .collect();
    if selected.is_empty() && !opts.selection.is_all() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("nothing in {name} matches"),
        ));
    }
    // Raw copies need the source's own format, as it is (a zip or 7z inside a codec is
    // spooled, and its copies would come from the spool).
    let same_format = kind.format() == format
        && (format == FormatId::Tar || codecs.is_empty())
        && opened.detection.volumes.len() <= 1;
    let raw = opts.raw && same_format;
    let encrypts = match spec {
        WriteSpec::Zip(o) => o.password.is_some(),
        WriteSpec::SevenZ(o) => o.password.is_some(),
        WriteSpec::Tar { .. } => false,
    };
    if info.encryption != Encryption::None && !raw && !encrypts && !opts.decrypt {
        return Err(Error::invalid_args(format!(
            "{name} is encrypted; pass `new_password` to encrypt the new archive, or `decrypt` to \
             write its entries in the clear"
        )));
    }
    if opts.dry_run {
        return Ok(ConvertReport {
            files: selected
                .iter()
                .filter(|e| matches!(e.kind, EntryKind::File | EntryKind::Hardlink { .. }))
                .count() as u64,
            dirs: selected.iter().filter(|e| e.is_dir()).count() as u64,
            links: selected
                .iter()
                .filter(|e| matches!(e.kind, EntryKind::Symlink { .. }))
                .count() as u64,
            bytes_in: opened.size,
            plan: selected.iter().map(|e| e.path.clone()).collect(),
            ..ConvertReport::default()
        });
    }
    let items: Vec<Item> = selected
        .iter()
        .map(|e| {
            Item::Keep(Keep {
                id: e.id,
                path: e.path.clone(),
            })
        })
        .collect();
    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let out_name = output
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut report = ConvertReport {
        bytes_in: opened.size,
        ..ConvertReport::default()
    };
    let written = match opts.volume_size {
        None => {
            let partial = Partial::create(&dir, &format!(".{out_name}"))?;
            let writer = file_writer(spec, partial.try_clone()?)?;
            let w = rewrite(&mut *opened.reader, &items, writer, raw, cx)?;
            drop(opened);
            partial.persist(output)?;
            report.bytes_out = fs::metadata(output).map(|m| m.len()).unwrap_or(0);
            w
        }
        Some(size) => {
            let volumes = VolumeWriter::create(output, size, opts.overwrite)?;
            let out: Box<dyn WriteSeek> = Box::new(volumes.clone());
            let writer = create_writer(spec, out)?;
            let w = rewrite(&mut *opened.reader, &items, writer, raw, cx)?;
            drop(opened);
            report.volumes = volumes.finish()?;
            report.bytes_out = report
                .volumes
                .iter()
                .filter_map(|p| fs::metadata(p).ok())
                .map(|m| m.len())
                .sum();
            w
        }
    };
    report.files = written.files;
    report.dirs = written.dirs;
    report.links = written.links;
    report.copied = written.copied;
    report.recompressed = written.recompressed;
    report.skipped = written.skipped;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_names_count_up() {
        let taken: HashSet<String> = ["docs/a.txt", "docs/a (1).txt"]
            .iter()
            .map(|s| key(s))
            .collect();
        assert_eq!(free_name("docs/a.txt", &taken), "docs/a (2).txt");
        assert_eq!(free_name("b", &taken), "b (1)");
        assert_eq!(free_name(".hidden", &taken), ".hidden (1)");
    }

    #[test]
    fn new_paths_are_checked() {
        assert_eq!(check_new_path("a\\b").unwrap(), "a/b");
        assert_eq!(check_new_path("./a/").unwrap(), "a");
        for bad in ["", "/a", "C:/a", "a/../b", "a//b", "../a"] {
            assert!(check_new_path(bad).is_err(), "{bad}");
        }
    }
}
