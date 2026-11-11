use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::SystemTime,
};

use filetime::FileTime;

use super::{
    ExtractReport, FsOptions, OverwritePolicy, Partial, SkipReason,
    behind::{self, Behind, Meta, Write1},
    motw,
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
    /// The file written for each entry of this job, by entry id: what a later entry with the
    /// same data is copied from ([`EntrySink::same_as`]).
    by_id: HashMap<usize, PathBuf>,
    links: Vec<PendingLink>,
    dir_times: Vec<(PathBuf, SystemTime)>,
    replace_all: bool,
    skip_all: bool,
    entries: u64,
    /// Hardlink copies produce data without consuming input; their bytes are held to the
    /// ratio limit against the whole job's input.
    link_guard: Option<RatioGuard>,
    report: ExtractReport,
    /// Small files' writing, on other threads (docs/M8.md §6.3): see [`FsSink::write_behind`].
    behind: Option<Behind>,
}

struct Written {
    /// The archive name it came from ([`name_key`]).
    name: String,
    /// The entry it came from.
    id: usize,
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
    /// A file this job wrote earlier, which `target` names under another case: one file where
    /// names ignore case. It's removed just before the rename, so the file takes the later
    /// entry's name: renaming over it would keep the old name on APFS, though not on NTFS
    /// (docs/M6.md §16, PR 6).
    pub(crate) replaces: Option<PathBuf>,
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
            by_id: HashMap::new(),
            links: Vec::new(),
            dir_times: Vec::new(),
            replace_all: false,
            skip_all: false,
            entries: 0,
            link_guard,
            report: ExtractReport::default(),
            behind: None,
        })
    }

    /// Writes small files on other threads from now on, while the reader decodes the next
    /// ([`behind`]): what a reader that decodes on one thread asks for, given `[extract]
    /// threads` (0: one a logical core). Left to BeeZip, a spinning disk gets none, as zip's
    /// parallel extraction does; one thread is none.
    pub(crate) fn write_behind(&mut self, threads: u32) {
        let mut workers = crate::codec::resolve_threads(threads) as usize;
        if threads == 0 && super::disk::seek_penalty(&self.dest) == Some(true) {
            workers = 1;
        }
        if workers >= 2 && self.behind.is_none() {
            self.behind = Some(Behind::new(workers, self.opts.zone.clone()));
        }
    }

    /// Waits for the files being written on other threads, and counts them.
    fn wait_behind(&mut self, cx: &mut dyn Ctx) -> Result<()> {
        if let Some(b) = &mut self.behind {
            let done = b.wait()?;
            self.took(done, cx);
        }
        Ok(())
    }

    fn took(&mut self, done: behind::Done, cx: &mut dyn Ctx) {
        self.report.files += done.files;
        self.report.bytes += done.bytes;
        for w in done.warnings {
            cx.warn(w);
        }
    }

    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// Whether names ignore case where this job writes, asked of the file system rather than
    /// assumed from the platform: Windows' and macOS's usual volumes ignore it, Linux's don't,
    /// but a case-sensitive APFS volume, a FAT or exFAT drive on Linux, or a casefolded folder
    /// turn that round. A file `.beezip-case-<random>.tmp` is made in `dest` and looked for by
    /// its upper-case name, then removed. Parallel extraction asks once (docs/M6.md §16, PR 6).
    pub(crate) fn ignores_case(&self) -> bool {
        let Ok(probe) = tempfile::Builder::new()
            .prefix(".beezip-case-")
            .suffix(".tmp")
            .tempfile_in(&self.dest)
        else {
            return cfg!(any(windows, target_os = "macos"));
        };
        let name = probe
            .path()
            .file_name()
            .map(|n| n.to_string_lossy().to_uppercase())
            .unwrap_or_default();
        let upper = self.dest.join(name);
        upper != probe.path() && fs::symlink_metadata(&upper).is_ok()
    }

    pub fn report(&self) -> &ExtractReport {
        &self.report
    }

    /// Creates the deferred symlinks, sets directory times (deepest first) and returns the
    /// report.
    pub fn finish(mut self, cx: &mut dyn Ctx) -> Result<ExtractReport> {
        self.wait_behind(cx)?;
        self.behind = None;
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
        if let Some(b) = &self.behind
            && entry.size.is_some_and(|n| n <= behind::SMALL)
        {
            if b.touches(&job) {
                self.wait_behind(cx)?;
            }
            // The data is read here, through the reader's checks; a file that turns out larger
            // than it said is written here after all.
            let mut buf = Vec::with_capacity(entry.size.unwrap_or(0) as usize);
            copy(&mut data.take(behind::SMALL + 1), &mut buf, cx)?;
            if buf.len() as u64 <= behind::SMALL {
                let meta = Meta {
                    modified: entry.modified,
                    unix_mode: entry.unix_mode,
                    readonly: entry.dos_attrs.is_some_and(|a| a & 0x01 != 0),
                };
                let target = job.target.clone();
                if let Some(b) = &mut self.behind {
                    b.send(Write1 {
                        job,
                        data: buf,
                        meta,
                    })?;
                    let done = b.poll()?;
                    self.took(done, cx);
                }
                self.by_id.insert(entry.id, target);
                return Ok(());
            }
            let mut rest = io::Cursor::new(buf).chain(data);
            let bytes = self.write_job(&job, entry, &mut rest, cx)?;
            self.wrote(bytes);
            self.by_id.insert(entry.id, job.target);
            return Ok(());
        }
        let bytes = self.write_job(&job, entry, data, cx)?;
        self.wrote(bytes);
        self.by_id.insert(entry.id, job.target);
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
        let replaces = self
            .written
            .get(&fold(&rel))
            .map(|w| w.path.clone())
            .filter(|earlier| *earlier != target && same_file(earlier, &target));
        self.by_name.insert(key.clone(), target.clone());
        self.written.insert(
            fold(&rel),
            Written {
                name: key,
                id: entry.id,
                path: target.clone(),
                modified: entry.modified,
            },
        );
        Ok(Some(FileJob {
            dir: parent,
            target,
            replaces,
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
        let bytes = self.write_atomically(job, data, cx)?;
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
        job: &FileJob,
        data: &mut dyn Read,
        cx: &mut dyn Ctx,
    ) -> Result<u64> {
        let (dir, target) = (job.dir.as_path(), job.target.as_path());
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut tmp = Partial::create(dir, &name)?;
        let bytes = copy(data, tmp.file_mut(), cx)?;
        before_rename(target, job.replaces.as_deref())?;
        tmp.persist(target)?;
        Ok(bytes)
    }

    fn apply_metadata(&self, path: &Path, entry: &Entry, cx: &mut dyn Ctx) {
        let meta = Meta {
            modified: entry.modified,
            unix_mode: entry.unix_mode,
            readonly: entry.dos_attrs.is_some_and(|a| a & 0x01 != 0),
        };
        metadata(path, self.opts.zone.as_deref(), &meta, &mut |m| cx.warn(m));
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
        // A copy reads the file it links to, which may still be being written.
        self.wait_behind(cx)?;
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

/// Whether `a` and `b` name one file, as a name and its case variant do where names ignore
/// case (macOS). Only asked on Unix: on Windows, renaming over a file takes the new name anyway.
#[cfg(unix)]
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::symlink_metadata(a), fs::symlink_metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file(_a: &Path, _b: &Path) -> bool {
    false
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

impl FsSink {
    /// Skips a file whose data its reader doesn't read, as a device is skipped, with the
    /// reader's reason as a warning: an EFS-encrypted or WOF-compressed file on NTFS
    /// (`format::volume::unreadable`). The rest of the extraction goes on.
    pub fn skip_unreadable(&mut self, entry: &Entry, why: &Error, cx: &mut dyn Ctx) -> Result<()> {
        cx.check()?;
        self.entries += 1;
        self.opts.limits.check_entries(self.entries)?;
        if self.safe_path(entry).is_none() {
            return Ok(());
        }
        cx.warn(format!("skipped `{}`: {}", entry.path, why.message));
        self.report.skip(&entry.path, SkipReason::Unreadable);
        Ok(())
    }
}

/// What renaming a written file over `target` needs first: Windows won't rename over a read-only
/// file, and a file this job wrote under another case (`replaces`) goes.
pub(super) fn before_rename(target: &Path, replaces: Option<&Path>) -> Result<()> {
    #[cfg(windows)]
    if let Ok(m) = fs::symlink_metadata(target)
        && m.permissions().readonly()
    {
        let mut p = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)] // Windows: just the attribute
        p.set_readonly(false);
        let _ = fs::set_permissions(target, p);
    }
    if let Some(earlier) = replaces {
        match fs::remove_file(earlier) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                return Err(Error::io(format!("replacing {}", earlier.display()), &e));
            }
            _ => {}
        }
    }
    Ok(())
}

/// A written file's Mark of the Web, time and attributes; what can't be set is a warning.
pub(super) fn metadata(
    path: &Path,
    zone: Option<&[u8]>,
    meta: &Meta,
    warn: &mut dyn FnMut(String),
) {
    if let Some(zone) = zone
        && let Err(e) = motw::write_zone(path, zone)
    {
        warn(format!(
            "could not mark {} as downloaded: {e}",
            path.display()
        ));
    }
    if let Some(t) = meta.modified
        && let Err(e) = filetime::set_file_mtime(path, FileTime::from_system_time(t))
    {
        warn(format!("could not set the time of {}: {e}", path.display()));
    }
    #[cfg(unix)]
    if let Some(mode) = meta.unix_mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777));
    }
    #[cfg(windows)]
    if meta.readonly
        && let Ok(m) = fs::metadata(path)
    {
        let mut p = m.permissions();
        p.set_readonly(true);
        let _ = fs::set_permissions(path, p);
    }
}

impl EntrySink for FsSink {
    fn as_fs_sink(&mut self) -> Option<&mut FsSink> {
        Some(self)
    }

    /// A copy of the file written for `earlier`, while it's still there as written; the copy's
    /// bytes are held to the ratio limit as a hard link's are.
    fn same_as(
        &mut self,
        entry: &Entry,
        earlier: &Entry,
        decoded: bool,
        cx: &mut dyn Ctx,
    ) -> Result<bool> {
        if decoded || !matches!(entry.kind, EntryKind::File) {
            return Ok(false);
        }
        // Still the file written for it: no later entry has taken its place.
        let Some(source) = self.by_id.get(&earlier.id).cloned() else {
            return Ok(false);
        };
        self.wait_behind(cx)?;
        let current = self
            .relative(&source)
            .and_then(|rel| self.written.get(&fold(&rel)));
        if current.map(|w| w.id) != Some(earlier.id) {
            return Ok(false);
        }
        match fs::metadata(&source) {
            Ok(m) if m.is_file() && Some(m.len()) == earlier.size => {}
            _ => return Ok(false),
        }
        let Ok(file) = fs::File::open(&source) else {
            return Ok(false);
        };
        cx.check()?;
        self.entries += 1;
        self.opts.limits.check_entries(self.entries)?;
        let Some(safe) = self.safe_path(entry) else {
            return Ok(true);
        };
        let guard = self
            .link_guard
            .take()
            .unwrap_or_else(|| RatioGuard::new(&self.opts.input, &self.opts.limits));
        let mut data = Guarded::new(file, guard, self.opts.budget.clone());
        let result = self.write_file(entry, &safe, &mut data, cx);
        self.link_guard = Some(data.into_parts().1);
        result.map(|()| true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_destination_says_whether_names_ignore_case() {
        let dir = tempfile::tempdir().unwrap();
        let sink = FsSink::new(dir.path(), FsOptions::default()).unwrap();
        // The usual volumes: NTFS and APFS ignore case, Linux's don't.
        assert_eq!(sink.ignores_case(), cfg!(any(windows, target_os = "macos")));
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the probe is gone"
        );
    }
}
