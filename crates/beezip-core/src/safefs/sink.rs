use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};

use filetime::FileTime;

use super::{
    ExtractReport, FsOptions, OverwritePolicy, Partial, SkipReason, motw,
    sanitize::{self, Refusal, SafePath},
};
use crate::{
    Ctx, Error, OverwriteChoice, Result,
    format::{Entry, EntryKind, EntrySink},
    io::copy,
    limits::{Guarded, RatioGuard},
};

/// Writes entries under a destination directory, applying every SafeFs rule. Call
/// [`FsSink::finish`] after the reader is done: it creates the symlinks (which come last, so
/// nothing can be written through one) and sets directory times.
pub struct FsSink {
    /// Absolute but not canonical: paths are built from it, so std's long-path handling applies
    /// and no `\\?\` prefix is added here.
    dest: PathBuf,
    /// Canonical, for containment checks.
    dest_canon: PathBuf,
    opts: FsOptions,
    /// Directories already verified to be inside `dest`.
    checked: HashSet<PathBuf>,
    /// Files written by this job, by case-folded relative path.
    written: HashMap<String, Written>,
    /// The file written for each archive name ([`name_key`]), last one kept: what a hardlink's
    /// target means.
    by_name: HashMap<String, PathBuf>,
    links: Vec<PendingLink>,
    dir_times: Vec<(PathBuf, SystemTime)>,
    replace_all: bool,
    skip_all: bool,
    entries: u64,
    /// Hardlink copies produce data without consuming input; their bytes are held to the
    /// ratio limit against the whole job's input.
    link_guard: Option<RatioGuard>,
    report: ExtractReport,
}

struct Written {
    /// The archive name it came from ([`name_key`]).
    name: String,
    path: PathBuf,
    /// The entry's time, which the file gets: what the `newer` policy compares a later entry
    /// with while the file may not be written yet (parallel extraction plans first).
    modified: Option<SystemTime>,
}

/// A file [`FsSink::plan`] has placed and recorded, for [`FsSink::write_job`] to write, on any
/// thread (docs/M6.md §6.3).
#[derive(Debug, Clone)]
pub(crate) struct FileJob {
    /// Its folder, made and checked.
    pub(crate) dir: PathBuf,
    pub(crate) target: PathBuf,
}

struct PendingLink {
    from: String,
    components: Vec<String>,
    target: String,
}

enum Decision {
    Write(PathBuf),
    Skip(SkipReason),
}

impl FsSink {
    /// Creates `dest` if needed.
    pub fn new(dest: &Path, opts: FsOptions) -> Result<Self> {
        let ctx = |what: &str, e: &io::Error| Error::io(format!("{what} {}", dest.display()), e);
        fs::create_dir_all(dest).map_err(|e| ctx("creating", &e))?;
        let abs = std::path::absolute(dest).map_err(|e| ctx("resolving", &e))?;
        let canon = fs::canonicalize(dest).map_err(|e| ctx("resolving", &e))?;
        let link_guard = Some(RatioGuard::new(&opts.input, &opts.limits));
        Ok(Self {
            dest: abs.clone(),
            dest_canon: canon,
            opts,
            checked: HashSet::from([abs]),
            written: HashMap::new(),
            by_name: HashMap::new(),
            links: Vec::new(),
            dir_times: Vec::new(),
            replace_all: false,
            skip_all: false,
            entries: 0,
            link_guard,
            report: ExtractReport::default(),
        })
    }

    pub fn dest(&self) -> &Path {
        &self.dest
    }

    pub fn report(&self) -> &ExtractReport {
        &self.report
    }

    /// Creates the deferred symlinks, sets directory times (deepest first) and returns the
    /// report.
    pub fn finish(mut self, cx: &mut dyn Ctx) -> Result<ExtractReport> {
        let links = std::mem::take(&mut self.links);
        let link_paths: HashSet<String> = links
            .iter()
            .map(|l| fold(&l.components.join("/")))
            .collect();
        for link in &links {
            cx.check()?;
            self.create_link(link, &link_paths, cx)?;
        }
        self.dir_times
            .sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
        for (dir, t) in &self.dir_times {
            if let Err(e) = filetime::set_file_mtime(dir, FileTime::from_system_time(*t)) {
                cx.warn(format!("could not set the time of {}: {e}", dir.display()));
            }
        }
        Ok(self.report)
    }

    /// Makes each directory level under `dest`, one at a time. An existing level is
    /// canonicalised and must stay inside the canonical `dest`, so a planted symlink or junction
    /// can't redirect writes.
    fn ensure_dirs(&mut self, components: &[String]) -> Result<Result<PathBuf, SkipReason>> {
        let mut cur = self.dest.clone();
        for comp in components {
            cur.push(comp);
            if self.checked.contains(&cur) {
                continue;
            }
            match fs::symlink_metadata(&cur) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&cur) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        if let Err(reason) = self.verify_existing(&cur)? {
                            return Ok(Err(reason));
                        }
                    }
                    Err(e) => return Err(Error::io(format!("creating {}", cur.display()), &e)),
                },
                Err(e) => return Err(Error::io(format!("reading {}", cur.display()), &e)),
                Ok(_) => {
                    if let Err(reason) = self.verify_existing(&cur)? {
                        return Ok(Err(reason));
                    }
                }
            }
            self.checked.insert(cur.clone());
        }
        Ok(Ok(cur))
    }

    fn verify_existing(&self, path: &Path) -> Result<Result<(), SkipReason>> {
        let canon = match fs::canonicalize(path) {
            Ok(c) => c,
            // A dangling link: it leads nowhere we can check.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Err(SkipReason::OutsideDest));
            }
            Err(e) => return Err(Error::io(format!("resolving {}", path.display()), &e)),
        };
        if !canon.starts_with(&self.dest_canon) {
            return Ok(Err(SkipReason::OutsideDest));
        }
        if !canon.is_dir() {
            return Ok(Err(SkipReason::Blocked));
        }
        Ok(Ok(()))
    }

    /// `name` is the entry's archive name ([`name_key`]); `rel` is where it goes, made safe.
    fn decide(
        &mut self,
        name: &str,
        rel: &str,
        target: PathBuf,
        entry: &Entry,
        cx: &mut dyn Ctx,
    ) -> Result<Decision> {
        let existing = match fs::symlink_metadata(&target) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::io(format!("reading {}", target.display()), &e)),
        };
        if existing.as_ref().is_some_and(fs::Metadata::is_dir) {
            return Ok(Decision::Skip(SkipReason::Blocked));
        }
        let earlier = self
            .written
            .get(&fold(rel))
            .map(|w| (w.name == name, w.modified));
        if existing.is_none() && earlier.is_none() {
            return Ok(Decision::Write(target));
        }
        // The same name twice in one archive (common in appended tars): the last one wins. Two
        // names that only meet once made safe (`a.` and `a `, `a:b` and `a_b`), or once
        // `strip_components` has gone, are a clash like a case-only one, so the policy decides.
        if earlier.is_some_and(|(same, _)| same) {
            return Ok(Decision::Write(target));
        }
        let choice = match self.opts.overwrite {
            OverwritePolicy::Always => OverwriteChoice::Replace,
            OverwritePolicy::Never => OverwriteChoice::Skip,
            OverwritePolicy::Rename => OverwriteChoice::Rename,
            OverwritePolicy::Newer => {
                // An earlier entry's file has that entry's time, or the time it was written,
                // whether or not it's on disk yet.
                let theirs = match earlier {
                    Some((_, t)) => Some(t.unwrap_or_else(SystemTime::now)),
                    None => existing.as_ref().and_then(|m| m.modified().ok()),
                };
                return Ok(match (entry.modified, theirs) {
                    (Some(ours), Some(theirs)) if ours > theirs => Decision::Write(target),
                    (Some(_), None) => Decision::Write(target),
                    _ => Decision::Skip(SkipReason::NotNewer),
                });
            }
            OverwritePolicy::Ask if self.replace_all => OverwriteChoice::Replace,
            OverwritePolicy::Ask if self.skip_all => OverwriteChoice::Skip,
            OverwritePolicy::Ask => cx.overwrite(&target)?,
        };
        Ok(match choice {
            OverwriteChoice::Replace => Decision::Write(target),
            OverwriteChoice::ReplaceAll => {
                self.replace_all = true;
                Decision::Write(target)
            }
            OverwriteChoice::Skip => Decision::Skip(SkipReason::Exists),
            OverwriteChoice::SkipAll => {
                self.skip_all = true;
                Decision::Skip(SkipReason::Exists)
            }
            OverwriteChoice::Rename => Decision::Write(self.free_name(&target)),
        })
    }

    /// `name (1).ext`, `name (2).ext`… whichever is free on disk and in this job.
    fn free_name(&self, target: &Path) -> PathBuf {
        let parent = target.parent().unwrap_or(&self.dest);
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (stem, ext) = match name.rfind('.') {
            Some(i) if i > 0 => (&name[..i], &name[i..]),
            _ => (name.as_str(), ""),
        };
        let taken: HashSet<&Path> = self.written.values().map(|w| w.path.as_path()).collect();
        (1..)
            .map(|n| parent.join(format!("{stem} ({n}){ext}")))
            .find(|p| !taken.contains(p.as_path()) && fs::symlink_metadata(p).is_err())
            .unwrap_or_else(|| parent.join(format!("{stem} (copy){ext}")))
    }

    fn write_file(
        &mut self,
        entry: &Entry,
        safe: &SafePath,
        data: &mut dyn Read,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let Some(job) = self.place(entry, safe, cx)? else {
            return Ok(());
        };
        let bytes = self.write_job(&job, entry, data, cx)?;
        self.wrote(bytes);
        Ok(())
    }

    /// Decides where a file goes and records it as written there, before any data is read:
    /// folders, the overwrite policy (prompts included), the report's skips and renames.
    /// `None`: it's skipped, and the report says why.
    fn place(
        &mut self,
        entry: &Entry,
        safe: &SafePath,
        cx: &mut dyn Ctx,
    ) -> Result<Option<FileJob>> {
        let (name, parents) = safe
            .components
            .split_last()
            .ok_or_else(|| Error::corrupt("empty path"))?;
        let parent = match self.ensure_dirs(parents)? {
            Ok(p) => p,
            Err(reason) => {
                self.report.skip(&entry.path, reason);
                return Ok(None);
            }
        };
        let rel = safe.joined();
        let key = name_key(&entry.path);
        let target = match self.decide(&key, &rel, parent.join(name), entry, cx)? {
            Decision::Write(t) => t,
            Decision::Skip(reason) => {
                self.report.skip(&entry.path, reason);
                return Ok(None);
            }
        };
        // One record per entry, whether the sanitiser or the `rename` policy changed the name.
        let rel = self.relative(&target).unwrap_or(rel);
        if safe.renamed || rel != safe.joined() {
            self.report.rename(&entry.path, rel.clone());
        }
        self.by_name.insert(key.clone(), target.clone());
        self.written.insert(
            fold(&rel),
            Written {
                name: key,
                path: target.clone(),
                modified: entry.modified,
            },
        );
        Ok(Some(FileJob {
            dir: parent,
            target,
        }))
    }

    /// Plans one entry for parallel extraction, in archive order on the job's thread: a file is
    /// placed ([`FsSink::place`]) and handed back for [`FsSink::write_job`]; everything else is
    /// done here, as [`EntrySink::entry`] does it. Hard links aren't planned: their data is a
    /// file this job writes, which may not exist yet (zips have none).
    pub(crate) fn plan(&mut self, entry: &Entry, cx: &mut dyn Ctx) -> Result<Option<FileJob>> {
        match entry.kind {
            EntryKind::File => {}
            EntryKind::Hardlink { .. } => {
                return Err(Error::unsupported("a hard link in a parallel extraction"));
            }
            _ => {
                self.entry(entry, &mut io::empty(), cx)?;
                return Ok(None);
            }
        }
        cx.check()?;
        self.entries += 1;
        self.opts.limits.check_entries(self.entries)?;
        let Some(safe) = self.safe_path(entry) else {
            return Ok(None);
        };
        self.place(entry, &safe, cx)
    }

    /// Writes a placed file: the partial file, the rename, then its time, attributes and mark.
    /// It changes nothing in the sink, so workers can share it. Returns the bytes written.
    pub(crate) fn write_job(
        &self,
        job: &FileJob,
        entry: &Entry,
        data: &mut dyn Read,
        cx: &mut dyn Ctx,
    ) -> Result<u64> {
        let bytes = self.write_atomically(&job.dir, &job.target, data, cx)?;
        self.apply_metadata(&job.target, entry, cx);
        Ok(bytes)
    }

    /// Counts a file [`FsSink::write_job`] wrote, or one a later entry replaced.
    pub(crate) fn wrote(&mut self, bytes: u64) {
        self.report.files += 1;
        self.report.bytes += bytes;
    }

    /// Writes `<name>.<random>.beezip-partial` next to the target, then renames it over the
    /// target. The partial file deletes itself on cancel, error or panic (`safefs::partial`).
    fn write_atomically(
        &self,
        dir: &Path,
        target: &Path,
        data: &mut dyn Read,
        cx: &mut dyn Ctx,
    ) -> Result<u64> {
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut tmp = Partial::create(dir, &name)?;
        let bytes = copy(data, tmp.file_mut(), cx)?;
        // Windows won't rename over a read-only file.
        #[cfg(windows)]
        if let Ok(m) = fs::symlink_metadata(target)
            && m.permissions().readonly()
        {
            let mut p = m.permissions();
            #[allow(clippy::permissions_set_readonly_false)] // Windows: just the attribute
            p.set_readonly(false);
            let _ = fs::set_permissions(target, p);
        }
        tmp.persist(target)?;
        Ok(bytes)
    }

    fn apply_metadata(&self, path: &Path, entry: &Entry, cx: &mut dyn Ctx) {
        if let Some(zone) = &self.opts.zone
            && let Err(e) = motw::write_zone(path, zone)
        {
            cx.warn(format!(
                "could not mark {} as downloaded: {e}",
                path.display()
            ));
        }
        if let Some(t) = entry.modified
            && let Err(e) = filetime::set_file_mtime(path, FileTime::from_system_time(t))
        {
            cx.warn(format!("could not set the time of {}: {e}", path.display()));
        }
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777));
        }
        #[cfg(windows)]
        if entry.dos_attrs.is_some_and(|a| a & 0x01 != 0)
            && let Ok(m) = fs::metadata(path)
        {
            let mut p = m.permissions();
            p.set_readonly(true);
            let _ = fs::set_permissions(path, p);
        }
    }

    fn relative(&self, path: &Path) -> Option<String> {
        let rel = path.strip_prefix(&self.dest).ok()?;
        Some(
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
        )
    }

    /// The entry path made safe, with `strip_components` applied. `None`: nothing to write,
    /// with any refusal already recorded.
    fn safe_path(&mut self, entry: &Entry) -> Option<SafePath> {
        let mut safe = match sanitize::sanitize(&entry.path) {
            Ok(s) => s,
            Err(Refusal::Traversal) => {
                self.report.skip(&entry.path, SkipReason::Traversal);
                return None;
            }
            // `./` and the like: the destination itself.
            Err(Refusal::Empty) if entry.is_dir() => return None,
            Err(Refusal::Empty) => {
                self.report.skip(&entry.path, SkipReason::InvalidPath);
                return None;
            }
        };
        let strip = self.opts.strip_components;
        if strip > 0 {
            if safe.components.len() <= strip {
                return None;
            }
            safe.components.drain(..strip);
        }
        Some(safe)
    }

    fn hardlink(
        &mut self,
        entry: &Entry,
        target: &str,
        safe: &SafePath,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        if sanitize::is_absolute(target) {
            self.report.skip(&entry.path, SkipReason::LinkOutside);
            return Ok(());
        }
        // The target is an archive name: the file written for that name, not whichever file
        // took the same place once made safe.
        let source = match sanitize::sanitize(target) {
            Ok(_) => self.by_name.get(&name_key(target)).cloned(),
            Err(Refusal::Traversal) => {
                self.report.skip(&entry.path, SkipReason::LinkOutside);
                return Ok(());
            }
            Err(Refusal::Empty) => None,
        };
        let Some(source) = source else {
            self.report.skip(&entry.path, SkipReason::LinkTargetMissing);
            return Ok(());
        };
        let file = fs::File::open(&source)
            .map_err(|e| Error::io(format!("reading {}", source.display()), &e))?;
        let guard = self
            .link_guard
            .take()
            .unwrap_or_else(|| RatioGuard::new(&self.opts.input, &self.opts.limits));
        let mut data = Guarded::new(file, guard, self.opts.budget.clone());
        let result = self.write_file(entry, safe, &mut data, cx);
        self.link_guard = Some(data.into_parts().1);
        result
    }

    /// Creates one deferred symlink if its target stays inside the destination. The target is
    /// resolved from the link's own location; `..` after a component that is itself a link, or
    /// a link located under another link, is refused, since the lexical answer could then
    /// differ from what the file system does.
    fn create_link(
        &mut self,
        link: &PendingLink,
        link_paths: &HashSet<String>,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let refuse = |this: &mut Self| {
            this.report.skip(&link.from, SkipReason::LinkOutside);
            Ok(())
        };
        let (name, parents) = match link.components.split_last() {
            Some(x) => x,
            None => return refuse(self),
        };
        let is_link = |this: &Self, comps: &[String]| {
            link_paths.contains(&fold(&comps.join("/")))
                || fs::symlink_metadata(this.dest.join(comps.join("/")))
                    .is_ok_and(|m| m.file_type().is_symlink())
        };
        if (1..=parents.len()).any(|n| is_link(self, &parents[..n])) {
            return refuse(self);
        }
        if link.target.is_empty() || sanitize::is_absolute(&link.target) {
            return refuse(self);
        }
        let mut resolved: Vec<String> = parents.to_vec();
        for comp in link.target.replace('\\', "/").split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    if resolved.is_empty() || is_link(self, &resolved) {
                        return refuse(self);
                    }
                    resolved.pop();
                }
                c => {
                    // A name the sanitiser would change (a stream, a device) isn't followed.
                    if sanitize::sanitize(c).map(|s| s.renamed).unwrap_or(true) {
                        return refuse(self);
                    }
                    resolved.push(c.to_owned());
                }
            }
        }
        let parent = match self.ensure_dirs(parents)? {
            Ok(p) => p,
            Err(reason) => {
                self.report.skip(&link.from, reason);
                return Ok(());
            }
        };
        let path = parent.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            self.report.skip(&link.from, SkipReason::Exists);
            return Ok(());
        }
        let target: PathBuf = link.target.replace('\\', "/").split('/').collect();
        let points_at_dir = self.dest.join(resolved.join("/")).is_dir();
        match make_symlink(&target, &path, points_at_dir) {
            Ok(()) => self.report.links += 1,
            Err(e) => {
                cx.warn(format!(
                    "could not create the symlink {}: {e}",
                    path.display()
                ));
                self.report.skip(&link.from, SkipReason::LinkFailed);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn make_symlink(target: &Path, path: &Path, _dir: bool) -> io::Result<()> {
    std::os::unix::fs::symlink(target, path)
}

#[cfg(windows)]
fn make_symlink(target: &Path, path: &Path, dir: bool) -> io::Result<()> {
    if dir {
        std::os::windows::fs::symlink_dir(target, path)
    } else {
        std::os::windows::fs::symlink_file(target, path)
    }
}

/// The key for case-insensitive collisions.
fn fold(rel: &str) -> String {
    rel.to_lowercase()
}

/// An archive name as a key: `\` as `/`, without `.` or empty components, otherwise as the
/// archive has it (before `strip_components` and before it's made safe).
fn name_key(path: &str) -> String {
    path.split(['/', '\\'])
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

impl EntrySink for FsSink {
    fn as_fs_sink(&mut self) -> Option<&mut FsSink> {
        Some(self)
    }

    fn entry(&mut self, entry: &Entry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        cx.check()?;
        self.entries += 1;
        self.opts.limits.check_entries(self.entries)?;
        let Some(safe) = self.safe_path(entry) else {
            return Ok(());
        };
        match &entry.kind {
            EntryKind::Dir => match self.ensure_dirs(&safe.components)? {
                Ok(dir) => {
                    if safe.renamed {
                        self.report.rename(&entry.path, safe.joined());
                    }
                    self.report.dirs += 1;
                    if let Some(t) = entry.modified {
                        self.dir_times.push((dir, t));
                    }
                }
                Err(reason) => self.report.skip(&entry.path, reason),
            },
            EntryKind::File => self.write_file(entry, &safe, data, cx)?,
            EntryKind::Hardlink { target } => self.hardlink(entry, target, &safe, cx)?,
            EntryKind::Symlink { target } => {
                if self.opts.links {
                    self.links.push(PendingLink {
                        from: entry.path.clone(),
                        components: safe.components,
                        target: target.clone(),
                    });
                } else {
                    self.report.skip(&entry.path, SkipReason::LinksDisabled);
                }
            }
            EntryKind::Other => {
                cx.warn(format!(
                    "skipped `{}`: {}",
                    entry.path,
                    SkipReason::Unsupported.describe()
                ));
                self.report.skip(&entry.path, SkipReason::Unsupported);
            }
        }
        Ok(())
    }
}
