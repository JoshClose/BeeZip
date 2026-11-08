//! The 7-Zip backend's reader (docs/M6.md §3.3–§3.5).
//!
//! Opening lists the archive once (`7z l -slt`). Extracting streams one `7z x -so` process per
//! job: 7-Zip writes every item that isn't a folder to stdout, in listing order, exactly its
//! listed size, and each goes to the sink as a reader cut at that size. Folders and links come
//! from the listing, so every SafeFs rule applies to the names 7-Zip lists, not to what 7-Zip
//! would make of them. An NSIS installer's listed sizes are only estimates, so it (and any
//! listing with an unknown size before its last item) is extracted into a private staging
//! folder first, then handed to the sink file by file.

use std::{
    any::Any,
    collections::HashMap,
    ffi::OsString,
    fs::File,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::ChildStdout,
    time::Duration,
};

use super::{
    External, ExternalInfo, LevelProperty, SevenZipOptions,
    find::{SevenZip, find},
    process::{Exit, Run},
    slt::{self, Level, Listing, Messages},
};
use crate::{
    Ctx, Error, ErrorKind, Result,
    ctx::{MAX_PASSWORD_TRIES, Meter, MeteredCtx},
    format::{
        ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
    },
    io::{Counter, CountingReader, drain},
    limits::{Guarded, RatioGuard},
    sinks::TestReport,
    source::Source,
};

/// The switches every command gets: names in UTF-8 both ways, times in UTC, `/` separators,
/// and NTFS alternate streams off in both `l` (where they're hidden anyway) and `x` (where
/// they'd be written).
const COMMON: [&str; 6] = ["-sccUTF-8", "-scsUTF-8", "-slmu", "-slsl", "-sns-", "-bse2"];

/// The level keys `archive.info` shows.
const SHOWN: [&str; 13] = [
    "Label",
    "File System",
    "Method",
    "Images",
    "Cluster Size",
    "Sector Size",
    "Headers Size",
    "Free Space",
    "Created",
    "Modified",
    "Creator Application",
    "Code Page",
    "Host OS",
];

/// An archive read through 7-Zip.
pub struct SevenZipReader {
    /// What 7-Zip opened it as: the outermost level's format.
    kind: External,
    source: Source,
    seven_zip: SevenZip,
    /// The archive's absolute path, as 7-Zip is given it.
    path: PathBuf,
    password: Option<String>,
    levels: Vec<Level>,
    entries: Vec<Entry>,
    /// The paths 7-Zip printed, where they differ from the entries' (names decoded from bytes
    /// that weren't UTF-8): what selects them on its command line.
    listed: HashMap<usize, Box<str>>,
}

impl SevenZipReader {
    /// Finds 7-Zip and lists the archive. `kind` is what detection sniffed; 7-Zip's outermost
    /// level has to be one of the backend's formats too.
    pub fn open(
        source: Source,
        kind: External,
        opts: &SevenZipOptions,
        cx: &mut dyn Ctx,
    ) -> Result<Self> {
        let seven_zip = find(opts).map_err(|m| m.error(kind.display_name()))?;
        let path = std::path::absolute(&source.path)
            .map_err(|e| Error::io(format!("reading {}", source.path.display()), &e))?;
        let mut password: Option<String> = None;
        let mut attempt = 0u32;
        let (listing, messages, code) = loop {
            let (listing, messages, code) =
                list(&seven_zip.exe, &path, password.as_deref(), &source, cx)?;
            if !listing.levels.is_empty() {
                break (listing, messages, code);
            }
            let err = opening_error(&listing, &messages, code, kind);
            if err.kind != ErrorKind::WrongPassword || attempt >= MAX_PASSWORD_TRIES {
                return Err(err);
            }
            // The names are encrypted: ask, and list again.
            password = Some(cx.password(None, attempt)?);
            attempt += 1;
        };
        let opened = opened_as(&listing.levels)?;
        for msg in listing.errors.iter().chain(&messages.errors) {
            cx.warn(format!("7-Zip: {msg}"));
        }
        for msg in listing.warnings.iter().chain(&messages.warnings) {
            cx.warn(format!("7-Zip: {msg}"));
        }
        if let Some(err) = messages.error(code)
            && err.kind == ErrorKind::WrongPassword
        {
            return Err(err);
        }
        let mut entries = Vec::with_capacity(listing.items.len());
        let mut listed = HashMap::new();
        for item in listing.items {
            if let Some(l) = item.listed {
                listed.insert(entries.len(), l);
            }
            entries.push(item.entry);
        }
        Ok(Self {
            kind: opened,
            source,
            seven_zip,
            path,
            password,
            levels: listing.levels,
            entries,
            listed,
        })
    }

    /// The program reading it: "7-Zip 26.00".
    pub fn backend(&self) -> &str {
        &self.seven_zip.name
    }

    /// The path 7-Zip printed for entry `id`.
    fn listed(&self, id: usize) -> &str {
        self.listed
            .get(&id)
            .map_or(self.entries[id].path.as_str(), |l| l)
    }

    /// `cmd`, its own switches, the common ones, the password switch, then the archive.
    fn args(&self, cmd: &str, extra: Vec<OsString>) -> Vec<OsString> {
        args(cmd, extra, self.password.as_deref(), &self.path)
    }

    /// Asks for the password before reading encrypted entries, once.
    fn need_password(&mut self, encrypted: bool, cx: &mut dyn Ctx) -> Result<()> {
        if encrypted && self.password.is_none() {
            self.password = Some(cx.password(None, 0)?);
        }
        Ok(())
    }

    /// An entry's data with the ratio and total-size checks. 7-Zip's reads of the archive
    /// can't be counted, so the ratio compares an entry with the archive's whole size.
    fn guarded<R: Read>(&self, r: R) -> Guarded<R> {
        let input = Counter::new();
        let ratio = RatioGuard::new(&input, &self.source.limits);
        input.set(self.source.size.max(1));
        Guarded::new(r, ratio, self.source.budget.clone())
    }

    /// The limits against what the listing claims, before 7-Zip starts: an image can claim
    /// far more than it holds (a sparse file of 100 GB).
    fn check_limits(&self, selected: &[bool]) -> Result<()> {
        let limits = &self.source.limits;
        let size = self.source.size.max(1);
        let mut total = 0u64;
        for e in self
            .entries
            .iter()
            .zip(selected)
            .filter(|(_, s)| **s)
            .map(|(e, _)| e)
        {
            let n = e.size.unwrap_or(0);
            total = total.saturating_add(n);
            if let Some(max) = limits.max_ratio
                && n > limits.ratio_grace
                && n / size > max
            {
                return Err(Error::limit(format!(
                    "`{}` claims {n} bytes from a {size}-byte file, more than {max}:1 (limit `max_ratio`)",
                    e.path
                )));
            }
        }
        if let Some(max) = limits.max_total_bytes
            && total > max
        {
            return Err(Error::limit(format!(
                "the selected entries claim {total} bytes, more than {max} (limit `max_total_bytes`)"
            )));
        }
        Ok(())
    }

    /// A list file selecting `ids` (7-Zip's paths, one per line), when every name can be
    /// written to one and `7z l` with it matches exactly those entries. `None` means stream
    /// everything and keep what's selected.
    fn selection(&self, ids: &[usize], cx: &mut dyn Ctx) -> Result<Option<tempfile::TempPath>> {
        let names: Vec<&str> = ids.iter().map(|&i| self.listed(i)).collect();
        // List files are read line by line and trimmed.
        if names.iter().any(|n| {
            n.is_empty() || n.trim() != *n || n.contains(['\n', '\r']) || n.starts_with('\u{FEFF}')
        }) {
            return Ok(None);
        }
        let mut file = tempfile::Builder::new()
            .prefix("beezip-7z-")
            .suffix(".txt")
            .tempfile()
            .map_err(|e| Error::io("writing 7-Zip's list file", &e))?;
        for n in &names {
            writeln!(file, "{n}").map_err(|e| Error::io("writing 7-Zip's list file", &e))?;
        }
        let list = file.into_temp_path();
        let mut flag = OsString::from("-i@");
        flag.push(&*list);
        let args = self.args("l", vec!["-slt".into(), "-spd".into(), "-ssc".into(), flag]);
        let mut run = Run::spawn(&self.seven_zip.exe, &args, self.password.as_deref())?;
        let out = run.take_stdout().ok_or_else(no_stdout)?;
        let matched = slt::parse(
            &mut BufReader::new(out),
            &self.source.names,
            &self.source.limits,
            cx,
        )?;
        let exit = run.finish()?;
        let got: Vec<&str> = matched
            .items
            .iter()
            .filter(|i| i.entry.kind != EntryKind::Dir)
            .map(slt::Item::listed)
            .collect();
        Ok((exit.code == Some(0) && got == names).then_some(list))
    }

    fn extract_streamed(
        &mut self,
        selected: &[bool],
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let all = selected.iter().all(|&s| s);
        let picked_items: Vec<usize> = (0..self.entries.len())
            .filter(|&i| selected[i] && self.entries[i].kind != EntryKind::Dir)
            .collect();
        let list = if all || picked_items.is_empty() {
            None
        } else {
            self.selection(&picked_items, cx)?
        };
        // What comes down the pipe: every item that isn't a folder, or the selected ones.
        let on_pipe: Vec<bool> = self
            .entries
            .iter()
            .zip(selected)
            .map(|(e, &s)| e.kind != EntryKind::Dir && (list.is_none() || s))
            .collect();
        let last = on_pipe.iter().rposition(|&p| p);
        let total: u64 = self
            .entries
            .iter()
            .zip(&on_pipe)
            .filter(|(_, p)| **p)
            .filter_map(|(e, _)| e.size)
            .sum();

        let mut run = None;
        if last.is_some() {
            let mut extra = vec!["-so".into(), "-bsp0".into(), "-spd".into(), "-ssc".into()];
            if let Some(list) = &list {
                let mut flag = OsString::from("-i@");
                flag.push(&**list);
                extra.push(flag);
            }
            let args = self.args("x", extra);
            run = Some(Run::spawn(
                &self.seven_zip.exe,
                &args,
                self.password.as_deref(),
            )?);
        }
        let counter = Counter::new();
        let mut out = match run.as_mut() {
            Some(r) => Some(CountingReader::new(
                BufReader::with_capacity(1 << 20, r.take_stdout().ok_or_else(no_stdout)?),
                counter.clone(),
            )),
            None => None,
        };
        let mut meter = Meter::new(counter, Some(total));
        meter.entries_total = Some(selected.iter().filter(|&&s| s).count() as u64);

        let result = (|| -> Result<()> {
            for id in 0..self.entries.len() {
                if !selected[id] && !on_pipe[id] {
                    continue;
                }
                let e = &self.entries[id];
                meter.current = Some(e.path.clone());
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.check()?;
                if !on_pipe[id] {
                    // A folder: nothing on the pipe.
                    sink.entry(e, &mut io::empty(), &mut mcx)?;
                    meter.entries_done += 1;
                    continue;
                }
                let Some(out) = out.as_mut() else {
                    return Err(no_stdout());
                };
                let to_end = Some(id) == last;
                let mut piece = Piece::new(out, e.size, to_end)?;
                if selected[id] {
                    if e.kind == EntryKind::File {
                        let mut data = self.guarded(&mut piece);
                        sink.entry(e, &mut data, &mut mcx)?;
                    } else if matches!(&e.kind, EntryKind::Symlink { target } if target.is_empty())
                    {
                        // CramFS and HFS+ keep a link's target only in its data.
                        let mut t = Vec::new();
                        (&mut piece)
                            .take(64 * 1024)
                            .read_to_end(&mut t)
                            .map_err(|err| Error::io("reading 7-Zip's output", &err))?;
                        while t.last() == Some(&0) {
                            t.pop();
                        }
                        let mut linked = e.clone();
                        linked.kind = EntryKind::Symlink {
                            target: String::from_utf8_lossy(&t).into_owned(),
                        };
                        sink.entry(&linked, &mut io::empty(), &mut mcx)?;
                    } else {
                        // A link's target or a device's nothing: the sink takes those from the
                        // listing.
                        sink.entry(e, &mut io::empty(), &mut mcx)?;
                    }
                }
                // What the sink didn't read: a file it skipped, a link's target.
                drain(&mut piece, &mut mcx)?;
                if selected[id] {
                    meter.entries_done += 1;
                }
            }
            if let Some(out) = out.as_mut() {
                let mut more = [0u8; 1];
                if out
                    .read(&mut more)
                    .map_err(|e| Error::io("reading 7-Zip's output", &e))?
                    > 0
                {
                    return Err(Error::corrupt(
                        "7-Zip wrote more than it listed: the listing and the data disagree",
                    ));
                }
            }
            Ok(())
        })();
        drop(out);
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        let Some(run) = run else {
            return result;
        };
        match result {
            Ok(()) => {
                let exit = run.finish()?;
                self.after(&exit, cx)
            }
            Err(e) => Err(why_it_stopped(run, e)),
        }
    }

    /// 7-Zip's verdict once it has written everything: an entry it found damaged after
    /// writing it (a WIM's hash), or its warnings.
    fn after(&self, exit: &Exit, cx: &mut dyn Ctx) -> Result<()> {
        let messages = slt::messages(&exit.stderr);
        if let Some(err) = messages.error(exit.code) {
            return Err(err);
        }
        for w in &messages.warnings {
            cx.warn(format!("7-Zip: {w}"));
        }
        Ok(())
    }

    fn extract_staged(
        &mut self,
        selected: &[bool],
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let all = selected.iter().all(|&s| s);
        let files: Vec<usize> = (0..self.entries.len())
            .filter(|&i| selected[i] && self.entries[i].kind == EntryKind::File)
            .collect();
        let staging = staging_dir(sink.as_fs_sink().map(|fs| fs.dest().to_path_buf()))?;
        let list = if all || files.is_empty() {
            None
        } else {
            self.selection(&files, cx)?
        };
        let mut meter = Meter::new(Counter::new(), None);
        meter.entries_total = Some(selected.iter().filter(|&&s| s).count() as u64);

        let mut messages = Messages::default();
        // What 7-Zip said went wrong: files it did write are still handed on, as `7z x` leaves
        // them, and the job fails with this at the end.
        let mut failure = None;
        if !files.is_empty() {
            let mut out = OsString::from("-o");
            out.push(staging.path());
            let mut extra = vec![
                out,
                "-y".into(),
                "-bsp0".into(),
                "-bso0".into(),
                "-spd".into(),
                "-ssc".into(),
            ];
            if let Some(list) = &list {
                let mut flag = OsString::from("-i@");
                flag.push(&**list);
                extra.push(flag);
            }
            let args = self.args("x", extra);
            let mut run = Run::spawn(&self.seven_zip.exe, &args, self.password.as_deref())?;
            loop {
                if let Err(e) = MeteredCtx::new(cx, &meter).check() {
                    run.kill();
                    return Err(e);
                }
                if run.try_wait()? {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let exit = run.finish()?;
            messages = slt::messages(&exit.stderr);
            failure = messages.error(exit.code);
            if let Some(err) = &failure
                && matches!(
                    err.kind,
                    ErrorKind::WrongPassword
                        | ErrorKind::PasswordRequired
                        | ErrorKind::Cancelled
                        | ErrorKind::Io
                        | ErrorKind::LimitExceeded
                )
            {
                return Err(err.clone());
            }
        }

        for (id, e) in self.entries.iter().enumerate() {
            if !selected[id] {
                continue;
            }
            meter.current = Some(e.path.clone());
            let mut mcx = MeteredCtx::new(cx, &meter);
            mcx.check()?;
            if e.kind != EntryKind::File {
                sink.entry(e, &mut io::empty(), &mut mcx)?;
                meter.entries_done += 1;
                continue;
            }
            let staged = staging.path().join(staged_name(self.listed(id)));
            let file = match open_staged(&staged) {
                Ok(f) => f,
                // 7-Zip failed and left this one out: the failure ends the job below.
                Err(err) if err.kind == ErrorKind::NotFound && failure.is_some() => {
                    mcx.warn(format!("{}: 7-Zip extracted nothing for it", e.path));
                    continue;
                }
                Err(err) if err.kind == ErrorKind::NotFound => {
                    return Err(Error::corrupt("7-Zip extracted nothing for it").context(&e.path));
                }
                Err(err) => return Err(err.context(&e.path)),
            };
            // The listed size was 7-Zip's estimate: the staged file is the truth.
            let mut actual = e.clone();
            actual.size = file.metadata().ok().map(|m| m.len());
            let mut data = self.guarded(BufReader::with_capacity(1 << 20, file));
            sink.entry(&actual, &mut data, &mut mcx)?;
            meter.entries_done += 1;
        }
        meter.current = None;
        MeteredCtx::new(cx, &meter).report();
        for w in &messages.warnings {
            cx.warn(format!("7-Zip: {w}"));
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn run_test(&mut self, cx: &mut dyn Ctx) -> Result<TestReport> {
        // A test reads everything, so it stops where extracting everything would.
        self.check_limits(&vec![true; self.entries.len()])?;
        let encrypted = self.entries.iter().any(|e| e.encrypted);
        self.need_password(encrypted, cx)?;
        let files = self.entries.iter().filter(|e| e.kind != EntryKind::Dir);
        let total: u64 = files.clone().filter_map(|e| e.size).sum();
        let count = files.count() as u64;
        let args = self.args("t", vec!["-bsp1".into(), "-bso0".into()]);
        let mut run = Run::spawn(&self.seven_zip.exe, &args, self.password.as_deref())?;
        let mut out = run.take_stdout().ok_or_else(no_stdout)?;
        let counter = Counter::new();
        let mut meter = Meter::new(counter.clone(), Some(total));
        meter.entries_total = Some(count);
        // `-bsp1` writes "  5% 12 - name" and rubs it out with backspaces.
        let mut buf = vec![0u8; 4096];
        loop {
            if let Err(e) = MeteredCtx::new(cx, &meter).check() {
                run.kill();
                return Err(e);
            }
            let n = match out.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::io("reading 7-Zip's progress", &e)),
            };
            if let Some(pct) = last_percent(&buf[..n]) {
                counter.set(total / 100 * u64::from(pct));
            }
        }
        drop(out);
        let exit = run.finish()?;
        let messages = slt::messages(&exit.stderr);
        let mut report = TestReport {
            entries: count,
            bytes: total,
            ..TestReport::default()
        };
        for m in &messages.entries {
            if m.kind == ErrorKind::WrongPassword {
                return Err(Error::new(m.kind, format!("7-Zip: {}", m.message)));
            }
            report.record(
                &m.path,
                &Error::new(m.kind, format!("7-Zip: {}", m.message)),
            );
        }
        if messages.entries.is_empty()
            && let Some(err) = messages.error(exit.code)
        {
            if matches!(
                err.kind,
                ErrorKind::WrongPassword
                    | ErrorKind::PasswordRequired
                    | ErrorKind::Cancelled
                    | ErrorKind::Io
                    | ErrorKind::LimitExceeded
            ) {
                return Err(err);
            }
            report.record("", &err);
        }
        if !self.kind.checks_data() {
            report.note = Some(format!(
                "This {} stores no checksums of its files' data, so the test shows that 7-Zip can read every file, not that their contents are intact.",
                self.kind.display_name()
            ));
        }
        Ok(report)
    }
}

/// `7z <cmd> <extra> <common> [-p] -- <archive>`. Without a password, an empty `-p` stops
/// 7-Zip asking for one; with one, it goes in through stdin.
fn args(cmd: &str, extra: Vec<OsString>, password: Option<&str>, archive: &Path) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![cmd.into()];
    a.extend(extra);
    a.extend(COMMON.iter().map(OsString::from));
    if password.is_none() {
        a.push("-p".into());
    }
    a.push("--".into());
    a.push(archive.as_os_str().to_owned());
    a
}

fn no_stdout() -> Error {
    Error::new(ErrorKind::Io, "7-Zip's output wasn't connected")
}

/// One `7z l -slt`, read as it arrives.
fn list(
    exe: &Path,
    path: &Path,
    password: Option<&str>,
    source: &Source,
    cx: &mut dyn Ctx,
) -> Result<(Listing, Messages, Option<i32>)> {
    let args = args("l", vec!["-slt".into()], password, path);
    let mut run = Run::spawn(exe, &args, password)?;
    let out = run.take_stdout().ok_or_else(no_stdout)?;
    let listing = slt::parse(
        &mut BufReader::with_capacity(1 << 16, out),
        &source.names,
        &source.limits,
        cx,
    )?;
    let exit = run.finish()?;
    Ok((listing, slt::messages(&exit.stderr), exit.code))
}

/// Why 7-Zip opened nothing.
fn opening_error(
    listing: &Listing,
    messages: &Messages,
    code: Option<i32>,
    kind: External,
) -> Error {
    let mut all = messages.clone();
    all.errors.extend(listing.errors.iter().cloned());
    all.error(code.filter(|&c| c != 0).or(Some(2)))
        .map(|e| {
            if e.kind == ErrorKind::UnsupportedFormat {
                Error::unsupported_format(format!(
                    "7-Zip can't open it as a {}: {}",
                    kind.display_name(),
                    e.message
                ))
            } else {
                e
            }
        })
        .unwrap_or_else(|| Error::corrupt("7-Zip listed nothing"))
}

/// The format 7-Zip opened, from its levels: the outermost, past a numbered split, and past
/// the executable around an NSIS installer.
fn opened_as(levels: &[Level]) -> Result<External> {
    let mut types = levels
        .iter()
        .map(Level::type_name)
        .skip_while(|t| t.eq_ignore_ascii_case("Split"));
    let first = types.next().unwrap_or("");
    let kind = if first.eq_ignore_ascii_case("PE") {
        types
            .next()
            .and_then(External::from_seven_zip_type)
            .filter(|k| *k == External::Nsis)
    } else {
        External::from_seven_zip_type(first)
    };
    kind.ok_or_else(|| {
        Error::unsupported_format(format!(
            "7-Zip reads this as {}, which BeeZip doesn't open through 7-Zip",
            if first.is_empty() {
                "nothing it names"
            } else {
                first
            }
        ))
    })
}

/// The error from a stream that stopped early: what 7-Zip said, when it said something.
fn why_it_stopped(run: Run, err: Error) -> Error {
    let ours = matches!(
        err.kind,
        ErrorKind::Cancelled | ErrorKind::LimitExceeded | ErrorKind::Conflict | ErrorKind::Unsafe
    );
    let exit = run.abort();
    if ours {
        return err;
    }
    slt::messages(&exit.stderr)
        .error(exit.code.filter(|&c| c != 0))
        .filter(|e| e.kind != ErrorKind::Cancelled && e.kind != ErrorKind::Io)
        .unwrap_or(err)
}

/// The last `NN%` in a piece of `-bsp1` output.
fn last_percent(bytes: &[u8]) -> Option<u8> {
    let text = String::from_utf8_lossy(bytes);
    text.split(|c: char| c == '\u{8}' || c.is_whitespace())
        .filter_map(|w| w.strip_suffix('%')?.parse::<u8>().ok())
        .rfind(|&p| p <= 100)
}

/// One item's bytes on 7-Zip's stdout: exactly its listed size, or, for the last one when
/// its size isn't listed, the rest.
struct Piece<'a, R> {
    inner: &'a mut R,
    left: Option<u64>,
}

impl<'a, R: Read> Piece<'a, R> {
    fn new(inner: &'a mut R, size: Option<u64>, last: bool) -> Result<Self> {
        if size.is_none() && !last {
            return Err(Error::corrupt(
                "7-Zip listed no size for an item before the last",
            ));
        }
        Ok(Self { inner, left: size })
    }
}

impl<R: Read> Read for Piece<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = match self.left {
            Some(0) => return Ok(0),
            Some(left) => buf.len().min(usize::try_from(left).unwrap_or(usize::MAX)),
            None => buf.len(),
        };
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 && want > 0 && self.left.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "7-Zip's output ended before the entry did",
            ));
        }
        if let Some(left) = &mut self.left {
            *left -= n as u64;
        }
        Ok(n)
    }
}

/// One entry from its own `7z x -so -i!<name>` process.
struct EntryStream {
    run: Option<Run>,
    out: BufReader<ChildStdout>,
    left: Option<u64>,
}

impl EntryStream {
    /// 7-Zip's verdict once the data has ended.
    fn end(&mut self) -> io::Result<()> {
        let Some(run) = self.run.take() else {
            return Ok(());
        };
        let mut more = [0u8; 1];
        if self.out.read(&mut more)? > 0 {
            return Err(Error::corrupt("7-Zip wrote more than it listed").into_io());
        }
        let exit = run.finish().map_err(Error::into_io)?;
        match slt::messages(&exit.stderr).error(exit.code) {
            Some(err) => Err(err.into_io()),
            None => Ok(()),
        }
    }
}

impl Read for EntryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = match self.left {
            Some(0) => {
                self.end()?;
                return Ok(0);
            }
            Some(left) => buf.len().min(usize::try_from(left).unwrap_or(usize::MAX)),
            None => buf.len(),
        };
        if want == 0 {
            return Ok(0);
        }
        let n = self.out.read(&mut buf[..want])?;
        if n == 0 {
            if self.left.is_some() {
                let err = match self.run.take() {
                    Some(run) => {
                        let exit = run.abort();
                        slt::messages(&exit.stderr).error(exit.code.filter(|&c| c != 0))
                    }
                    None => None,
                };
                return Err(err
                    .unwrap_or_else(|| Error::corrupt("7-Zip's output ended before the entry did"))
                    .into_io());
            }
            self.end()?;
            return Ok(0);
        }
        if let Some(left) = &mut self.left {
            *left -= n as u64;
        }
        Ok(n)
    }
}

/// The private folder an NSIS installer is staged in: in the destination, so the files move
/// within one volume, or in the temporary folder when there's no destination.
fn staging_dir(dest: Option<PathBuf>) -> Result<tempfile::TempDir> {
    let mut b = tempfile::Builder::new();
    b.prefix(".beezip-7z-").rand_bytes(8);
    let made = match &dest {
        Some(d) => std::fs::create_dir_all(d).and_then(|()| b.tempdir_in(d)),
        None => b.tempdir(),
    };
    made.map_err(|e| Error::io("making a folder for 7-Zip to extract into", &e))
}

/// Where 7-Zip put an item when it wrote it itself: it drops `.` and `..` components and a
/// leading `/`, and on Windows turns `*?<>|":` and control characters into `_`, a trailing
/// dot or space into `_`, and prefixes device names (`CON`, `aux.txt`) with `_`.
fn staged_name(listed: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for c in listed.split('/') {
        if c.is_empty() || c == "." || c == ".." {
            continue;
        }
        out.push(if cfg!(windows) {
            windows_name(c)
        } else {
            c.to_owned()
        });
    }
    out
}

fn windows_name(c: &str) -> String {
    let mut s: String = c
        .chars()
        .map(|ch| {
            if "*?<>|\":".contains(ch) || u32::from(ch) < 0x20 {
                '_'
            } else {
                ch
            }
        })
        .collect();
    let kept = s.trim_end_matches(['.', ' ']).len();
    let cut = s.len() - kept;
    s.truncate(kept);
    s.extend(std::iter::repeat_n('_', cut));
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if device { format!("_{s}") } else { s }
}

/// A staged file, which must be a plain file: never a link 7-Zip made.
fn open_staged(path: &Path) -> Result<File> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| Error::io("reading 7-Zip's output", &e))?;
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    if !meta.file_type().is_file() || reparse {
        return Err(Error::new(
            ErrorKind::Unsafe,
            "7-Zip made something other than a file where the listing has one",
        ));
    }
    File::open(path).map_err(|e| Error::io("reading 7-Zip's output", &e))
}

impl ArchiveReader for SevenZipReader {
    fn format(&self) -> FormatId {
        FormatId::External(self.kind)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        let mut methods: Vec<std::borrow::Cow<'static, str>> = Vec::new();
        for m in self.entries.iter().filter_map(|e| e.method.as_ref()) {
            if !methods.contains(m) && methods.len() < 32 {
                methods.push(m.clone());
            }
        }
        let inner = self.levels.last();
        let files: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .collect();
        let encrypted = files.iter().filter(|e| e.encrypted).count();
        let solid = inner.and_then(|l| l.get("Solid")) == Some("+") || self.kind == External::Nsis;
        let blocks = inner
            .and_then(|l| l.get("Blocks"))
            .and_then(|b| b.trim().parse::<u64>().ok());
        let mut properties = Vec::new();
        let mut levels = Vec::new();
        for l in &self.levels {
            let t = l.type_name();
            let name = External::from_seven_zip_type(t)
                .map_or_else(|| t.to_ascii_lowercase(), |k| k.name().to_owned());
            for key in SHOWN {
                if let Some(v) = l.get(key).filter(|v| !v.is_empty() && !v.contains('\n')) {
                    properties.push(LevelProperty {
                        level: name.clone(),
                        name: key.to_owned(),
                        value: v.chars().take(200).collect(),
                    });
                }
            }
            levels.push(name);
        }
        let mut notes = Vec::new();
        if self.kind == External::Msi {
            notes.push(
                "7-Zip names an installer's files by its internal keys (filFF4C…), not by the names they're installed under.".to_owned(),
            );
        }
        // 7-Zip stops at a partition table that holds several partitions.
        let innermost = inner.and_then(|l| External::from_seven_zip_type(l.type_name()));
        if matches!(innermost, Some(External::Gpt | External::Mbr)) {
            notes.push(
                "This disk has several partitions: each is listed as a file, which opens once extracted.".to_owned(),
            );
        }
        Ok(ArchiveInfo {
            format: FormatId::External(self.kind),
            codecs: self.source.codecs.clone(),
            methods,
            comment: None,
            encryption: match encrypted {
                0 => Encryption::None,
                n if n == files.len() => Encryption::All,
                _ => Encryption::Some,
            },
            solid,
            sfx: self.kind == External::Nsis,
            volumes: self.source.volumes.len(),
            solid_blocks: if solid { blocks } else { None },
            encrypted_headers: self.password.is_some() && encrypted == 0,
            locked: false,
            recovery_record: false,
            external: Some(ExternalInfo {
                backend: self.seven_zip.name.clone(),
                levels,
                properties,
                notes,
            }),
        })
    }

    fn extract(
        &mut self,
        sel: &Selection,
        sink: &mut dyn EntrySink,
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let selected: Vec<bool> = self.entries.iter().map(|e| sel.matches(e)).collect();
        if !selected.iter().any(|&s| s) {
            return Ok(());
        }
        self.check_limits(&selected)?;
        // FsSink holds a hard link's copy to the ratio against the input read so far, which
        // 7-Zip's reads never advance: count the whole archive as read.
        self.source.counter.set(self.source.size);
        let encrypted = self
            .entries
            .iter()
            .zip(&selected)
            .any(|(e, &s)| s && e.encrypted);
        self.need_password(encrypted, cx)?;
        // Every item but the last on the pipe must have a size, or the stream can't be cut.
        let items: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.kind != EntryKind::Dir)
            .collect();
        let unknown = items
            .iter()
            .take(items.len().saturating_sub(1))
            .any(|e| e.size.is_none());
        if self.kind == External::Nsis || unknown {
            self.extract_staged(&selected, sink, cx)
        } else {
            self.extract_streamed(&selected, sink, cx)
        }
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let Some(e) = self.entries.get(id) else {
            return Err(Error::new(ErrorKind::NotFound, format!("no entry {id}")));
        };
        if e.kind == EntryKind::Dir {
            return Err(Error::invalid_args(format!("`{}` is a folder", e.path)));
        }
        let encrypted = e.encrypted;
        self.need_password(encrypted, cx)?;
        let e = &self.entries[id];
        let listed = self.listed(id).to_owned();
        // Items listed under the same name come first on the pipe.
        let mut skip = 0u64;
        for (i, before) in self.entries[..id].iter().enumerate() {
            if before.kind != EntryKind::Dir && self.listed(i) == listed {
                skip += before.size.ok_or_else(|| {
                    Error::corrupt("7-Zip listed no size for an item of the same name")
                })?;
            }
        }
        let exact = self.kind != External::Nsis;
        let left = if exact { e.size } else { None };
        let args = self.args(
            "x",
            vec![
                "-so".into(),
                "-bsp0".into(),
                "-spd".into(),
                "-ssc".into(),
                format!("-i!{listed}").into(),
            ],
        );
        let mut run = Run::spawn(&self.seven_zip.exe, &args, self.password.as_deref())?;
        let mut out = BufReader::with_capacity(1 << 16, run.take_stdout().ok_or_else(no_stdout)?);
        if skip > 0 {
            let n = io::copy(&mut (&mut out).take(skip), &mut io::sink())
                .map_err(|e| Error::io("reading 7-Zip's output", &e))?;
            if n != skip {
                let exit = run.abort();
                return Err(slt::messages(&exit.stderr)
                    .error(exit.code.filter(|&c| c != 0))
                    .unwrap_or_else(|| Error::corrupt("7-Zip's output ended early")));
            }
        }
        let stream = EntryStream {
            run: Some(run),
            out,
            left,
        };
        Ok(Box::new(self.guarded(stream)))
    }

    fn test(&mut self, cx: &mut dyn Ctx) -> Option<Result<TestReport>> {
        Some(self.run_test(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_names_follow_seven_zips_rules() {
        assert_eq!(staged_name("../../x"), PathBuf::from("x"));
        assert_eq!(staged_name("dir/../../x"), Path::new("dir").join("x"));
        assert_eq!(staged_name("/abs/./y"), Path::new("abs").join("y"));
        if cfg!(windows) {
            assert_eq!(staged_name("trail."), PathBuf::from("trail_"));
            assert_eq!(staged_name("trail "), PathBuf::from("trail_"));
            assert_eq!(staged_name("..."), PathBuf::from("___"));
            assert_eq!(staged_name("a*b?.txt"), PathBuf::from("a_b_.txt"));
            assert_eq!(staged_name("CON"), PathBuf::from("_CON"));
            assert_eq!(staged_name("aux.txt"), PathBuf::from("_aux.txt"));
            assert_eq!(staged_name("f:s"), PathBuf::from("f_s"));
            assert_eq!(
                staged_name("$PLUGINSDIR/a.dll"),
                Path::new("$PLUGINSDIR").join("a.dll")
            );
        }
    }

    #[test]
    fn percents() {
        assert_eq!(
            last_percent(b"  5% 12 - a\x08\x08\x08 17% 30 - b"),
            Some(17)
        );
        assert_eq!(last_percent(b"nothing"), None);
    }

    #[test]
    fn levels_name_the_format() {
        let level = |t: &str| Level {
            props: vec![("Type".to_owned(), t.to_owned())],
        };
        assert_eq!(
            opened_as(&[level("VHDX"), level("GPT"), level("NTFS")]).unwrap(),
            External::Vhdx
        );
        assert_eq!(
            opened_as(&[level("PE"), level("Nsis")]).unwrap(),
            External::Nsis
        );
        assert_eq!(
            opened_as(&[level("Split"), level("wim")]).unwrap(),
            External::Wim
        );
        let e = opened_as(&[level("PE")]).unwrap_err();
        assert_eq!(e.kind, ErrorKind::UnsupportedFormat);
        assert!(opened_as(&[level("zip")]).is_err());
    }
}
