//! FsSink, fed synthetic entries (docs/M1.md §3.5). The malicious archives themselves are in
//! `malicious.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use beezip_core::{
    Ctx, Entry, EntryKind, EntrySink, ErrorKind, ExtractReport, FsOptions, FsSink, OverwriteChoice,
    OverwritePolicy, SimpleCtx, SkipReason,
};

/// A destination inside a parent we can list, to prove nothing lands outside it.
struct Dest {
    _root: tempfile::TempDir,
    parent: PathBuf,
    dest: PathBuf,
}

fn dest() -> Dest {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("parent");
    let dest = parent.join("dest");
    fs::create_dir_all(&dest).unwrap();
    Dest {
        _root: root,
        parent,
        dest,
    }
}

fn listing(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = walk(dir)
        .into_iter()
        .map(|p| {
            p.strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let is_dir = fs::symlink_metadata(&p).unwrap().is_dir();
        out.push(p.clone());
        if is_dir {
            out.extend(walk(&p));
        }
    }
    out
}

fn file(path: &str) -> Entry {
    Entry::new(0, path.into(), EntryKind::File)
}

fn with_kind(path: &str, kind: EntryKind) -> Entry {
    Entry::new(0, path.into(), kind)
}

fn feed(sink: &mut FsSink, entries: &[(Entry, &[u8])], cx: &mut dyn Ctx) {
    for (e, data) in entries {
        sink.entry(e, &mut &data[..], cx).unwrap();
    }
}

fn extract(d: &Dest, opts: FsOptions, entries: &[(Entry, &[u8])]) -> ExtractReport {
    let mut cx = SimpleCtx::new();
    let mut sink = FsSink::new(&d.dest, opts).unwrap();
    feed(&mut sink, entries, &mut cx);
    sink.finish(&mut cx).unwrap()
}

fn reasons(r: &ExtractReport) -> Vec<(String, SkipReason)> {
    r.skipped
        .iter()
        .map(|s| (s.path.clone(), s.reason))
        .collect()
}

#[test]
fn writes_files_dirs_and_times() {
    let d = dest();
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    let mut f = file("a/b/c.txt");
    f.modified = Some(t);
    let mut dir = with_kind("a/empty", EntryKind::Dir);
    dir.modified = Some(t);
    let r = extract(&d, FsOptions::default(), &[(f, b"hello"), (dir, b"")]);
    assert_eq!((r.files, r.dirs, r.bytes), (1, 1, 5));
    assert_eq!(fs::read(d.dest.join("a/b/c.txt")).unwrap(), b"hello");
    let mtime = fs::metadata(d.dest.join("a/b/c.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(mtime, t);
    let dmtime = fs::metadata(d.dest.join("a/empty"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(dmtime, t);
    assert!(!r.is_unsafe());
}

#[test]
fn traversal_is_refused_and_nothing_escapes() {
    let d = dest();
    let before = listing(&d.parent);
    let r = extract(
        &d,
        FsOptions::default(),
        &[
            (file("../evil.txt"), b"x"),
            (file("ok/../../evil2.txt"), b"x"),
            (file("..\\evil3.txt"), b"x"),
            (file("fine.txt"), b"ok"),
        ],
    );
    assert_eq!(r.unsafe_total, 3);
    assert!(
        reasons(&r)
            .iter()
            .all(|(_, why)| *why == SkipReason::Traversal)
    );
    let mut after = listing(&d.parent);
    after.retain(|p| !before.contains(p));
    assert_eq!(after, ["dest/fine.txt"]);
}

#[test]
fn absolute_and_device_paths_are_rewritten_inside() {
    let d = dest();
    let before = listing(&d.parent);
    let r = extract(
        &d,
        FsOptions::default(),
        &[
            (file("/etc/passwd"), b"1"),
            (file("C:\\Windows\\win.ini"), b"2"),
            (file("\\\\server\\share\\unc.txt"), b"3"),
            (file("CON"), b"4"),
            (file("aux.txt"), b"5"),
            (file("a:b"), b"6"),
            (file("trailing."), b"7"),
        ],
    );
    assert!(!r.is_unsafe());
    assert_eq!(r.renamed_total, 7);
    let mut got = listing(&d.dest);
    got.retain(|p| !p.ends_with("etc") && !p.ends_with("Windows"));
    assert_eq!(
        got,
        [
            "_CON",
            "_aux.txt",
            "a_b",
            "etc/passwd",
            "trailing_",
            "unc.txt",
            "Windows/win.ini"
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<_>>()
        .tap_sort()
    );
    let mut after = listing(&d.parent);
    after.retain(|p| !before.contains(p));
    assert!(after.iter().all(|p| p.starts_with("dest/")), "{after:?}");
}

trait TapSort {
    fn tap_sort(self) -> Self;
}

impl TapSort for Vec<String> {
    fn tap_sort(mut self) -> Self {
        self.sort();
        self
    }
}

/// Plants a link to `target` at `link`: a junction on Windows (no admin needed), a symlink
/// elsewhere.
fn plant_dir_link(target: &Path, link: &Path) {
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[test]
fn a_planted_junction_cannot_redirect_writes() {
    let d = dest();
    let outside = d.parent.join("outside");
    fs::create_dir(&outside).unwrap();
    plant_dir_link(&outside, &d.dest.join("planted"));
    let r = extract(
        &d,
        FsOptions {
            overwrite: OverwritePolicy::Always,
            ..FsOptions::default()
        },
        &[
            (file("planted/evil.txt"), b"x"),
            (file("planted/deeper/e.txt"), b"x"),
        ],
    );
    assert_eq!(r.unsafe_total, 2);
    assert!(
        reasons(&r)
            .iter()
            .all(|(_, why)| *why == SkipReason::OutsideDest)
    );
    assert!(listing(&outside).is_empty());
}

#[test]
fn overwrite_policies() {
    let d = dest();
    let existing = d.dest.join("f.txt");
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
    let new = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let reset = || {
        fs::write(&existing, b"old").unwrap();
        filetime::set_file_mtime(&existing, filetime::FileTime::from_system_time(old)).unwrap();
    };
    let entry = |t: SystemTime| {
        let mut e = file("f.txt");
        e.modified = Some(t);
        e
    };
    let run = |policy, e: Entry| {
        extract(
            &d,
            FsOptions {
                overwrite: policy,
                ..FsOptions::default()
            },
            &[(e, b"new")],
        )
    };

    reset();
    let r = run(OverwritePolicy::Never, entry(new));
    assert_eq!(reasons(&r), [("f.txt".into(), SkipReason::Exists)]);
    assert_eq!(fs::read(&existing).unwrap(), b"old");
    assert!(!r.is_unsafe());

    reset();
    run(OverwritePolicy::Always, entry(old));
    assert_eq!(fs::read(&existing).unwrap(), b"new");

    reset();
    let r = run(OverwritePolicy::Newer, entry(old));
    assert_eq!(reasons(&r), [("f.txt".into(), SkipReason::NotNewer)]);
    run(OverwritePolicy::Newer, entry(new));
    assert_eq!(fs::read(&existing).unwrap(), b"new");

    reset();
    let r = run(OverwritePolicy::Rename, entry(new));
    assert_eq!(fs::read(&existing).unwrap(), b"old");
    assert_eq!(fs::read(d.dest.join("f (1).txt")).unwrap(), b"new");
    assert_eq!(r.renamed[0].to, "f (1).txt");

    // `ask` without an answer fails with Conflict; with one, it is followed.
    reset();
    let mut sink = FsSink::new(&d.dest, FsOptions::default()).unwrap();
    let err = sink
        .entry(&entry(new), &mut &b"new"[..], &mut SimpleCtx::new())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    let mut cx = SimpleCtx::new().with_overwrite(OverwriteChoice::Replace);
    sink.entry(&entry(new), &mut &b"new"[..], &mut cx).unwrap();
    assert_eq!(fs::read(&existing).unwrap(), b"new");
}

#[test]
fn ask_remembers_replace_all() {
    let d = dest();
    fs::write(d.dest.join("a"), b"old").unwrap();
    fs::write(d.dest.join("b"), b"old").unwrap();
    let mut sink = FsSink::new(&d.dest, FsOptions::default()).unwrap();
    let mut cx = SimpleCtx::new().with_overwrite(OverwriteChoice::ReplaceAll);
    sink.entry(&file("a"), &mut &b"1"[..], &mut cx).unwrap();
    // Asked once; the second file is replaced without asking.
    let mut no_answer = SimpleCtx::new();
    sink.entry(&file("b"), &mut &b"2"[..], &mut no_answer)
        .unwrap();
    assert_eq!(fs::read(d.dest.join("b")).unwrap(), b"2");
}

#[test]
fn duplicates_last_wins_but_case_clashes_ask() {
    let d = dest();
    let r = extract(
        &d,
        FsOptions {
            overwrite: OverwritePolicy::Rename,
            ..FsOptions::default()
        },
        &[
            (file("dup.txt"), b"1"),
            (file("dup.txt"), b"2"),
            (file("DUP.txt"), b"3"),
        ],
    );
    assert_eq!(fs::read(d.dest.join("dup.txt")).unwrap(), b"2");
    assert_eq!(r.files, 3);
    assert_eq!(r.renamed_total, 1);
    assert_eq!(fs::read(d.dest.join(&r.renamed[0].to)).unwrap(), b"3");
}

#[test]
fn hardlinks_are_copies_and_stay_inside() {
    let d = dest();
    let r = extract(
        &d,
        FsOptions::default(),
        &[
            (file("orig.txt"), b"data"),
            (
                with_kind(
                    "copy.txt",
                    EntryKind::Hardlink {
                        target: "orig.txt".into(),
                    },
                ),
                b"",
            ),
            (
                with_kind(
                    "abs.txt",
                    EntryKind::Hardlink {
                        target: "/etc/passwd".into(),
                    },
                ),
                b"",
            ),
            (
                with_kind(
                    "up.txt",
                    EntryKind::Hardlink {
                        target: "../x".into(),
                    },
                ),
                b"",
            ),
            (
                with_kind(
                    "gone.txt",
                    EntryKind::Hardlink {
                        target: "missing".into(),
                    },
                ),
                b"",
            ),
        ],
    );
    assert_eq!(fs::read(d.dest.join("copy.txt")).unwrap(), b"data");
    assert_eq!(
        reasons(&r),
        [
            ("abs.txt".into(), SkipReason::LinkOutside),
            ("up.txt".into(), SkipReason::LinkOutside),
            ("gone.txt".into(), SkipReason::LinkTargetMissing),
        ]
    );
    assert_eq!(r.unsafe_total, 2);
}

#[test]
fn symlinks_are_off_by_default() {
    let d = dest();
    let r = extract(
        &d,
        FsOptions::default(),
        &[(
            with_kind("l", EntryKind::Symlink { target: "x".into() }),
            b"",
        )],
    );
    assert_eq!(reasons(&r), [("l".into(), SkipReason::LinksDisabled)]);
    assert!(r.is_unsafe());
}

#[test]
fn symlinks_that_leave_are_refused() {
    let d = dest();
    let link = |p: &str, t: &str| with_kind(p, EntryKind::Symlink { target: t.into() });
    let r = extract(
        &d,
        FsOptions {
            links: true,
            ..FsOptions::default()
        },
        &[
            (file("real/f.txt"), b"x"),
            (link("ok", "real/f.txt"), b""),
            (link("up", ".."), b""),
            (link("abs", "/etc"), b""),
            (link("sub/deep", "../../x"), b""),
            // An in-tree link to an ancestor, then a link that climbs out through it.
            (link("a/b/anc", "../.."), b""),
            (link("esc", "a/b/anc/../../.."), b""),
            (link("a/b/anc/x", ".."), b""),
            (link("ads", "real:stream"), b""),
            // A file written "through" a link lands in a real directory: links come last.
            (link("dir", "real"), b""),
            (file("dir/written.txt"), b"y"),
        ],
    );
    let refused: Vec<String> = r
        .skipped
        .iter()
        .filter(|s| s.reason == SkipReason::LinkOutside)
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        refused,
        ["up", "abs", "sub/deep", "esc", "a/b/anc/x", "ads"]
    );
    assert!(fs::symlink_metadata(d.dest.join("dir")).unwrap().is_dir());
    // Creating symlinks on Windows needs Developer Mode or admin; either outcome is fine here.
    let made = r.links;
    let failed = r
        .skipped
        .iter()
        .filter(|s| s.reason == SkipReason::LinkFailed)
        .count() as u64;
    assert_eq!(made + failed, 2, "{r:?}"); // "ok" and "a/b/anc"; "dir" exists already
}

#[test]
fn cancelling_leaves_no_partial_file() {
    let d = dest();
    let flag = Arc::new(AtomicBool::new(false));
    let mut cx = SimpleCtx::new().with_cancel(Arc::clone(&flag));
    let mut sink = FsSink::new(&d.dest, FsOptions::default()).unwrap();

    /// Endless data that cancels the job after the first megabyte.
    struct Cancels(Arc<AtomicBool>, usize);
    impl Read for Cancels {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.1 += buf.len();
            if self.1 > 1 << 20 {
                self.0.store(true, Ordering::Relaxed);
            }
            buf.fill(7);
            Ok(buf.len())
        }
    }
    let err = sink
        .entry(&file("big.bin"), &mut Cancels(flag, 0), &mut cx)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(listing(&d.dest).is_empty(), "{:?}", listing(&d.dest));
}

#[test]
fn read_errors_leave_no_partial_file() {
    let d = dest();
    struct Fails;
    impl Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::InvalidData, "bad block"))
        }
    }
    let mut sink = FsSink::new(&d.dest, FsOptions::default()).unwrap();
    let err = sink
        .entry(&file("x.bin"), &mut Fails, &mut SimpleCtx::new())
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt);
    assert!(listing(&d.dest).is_empty());
}

#[test]
fn strip_components() {
    let d = dest();
    let r = extract(
        &d,
        FsOptions {
            strip_components: 1,
            ..FsOptions::default()
        },
        &[
            (with_kind("top", EntryKind::Dir), b""),
            (file("top/a/b.txt"), b"x"),
            (file("lonely.txt"), b"x"),
        ],
    );
    assert_eq!(listing(&d.dest), ["a", "a/b.txt"]);
    assert_eq!(r.files, 1);
}

/// Long paths go through std as plain absolute paths: no `\\?\` added by SafeFs.
#[test]
fn long_paths_work() {
    let d = dest();
    let deep: Vec<String> = (0..10)
        .map(|i| format!("{i:02}-{}", "x".repeat(48)))
        .collect();
    let path = format!("{}/file.txt", deep.join("/"));
    assert!(d.dest.join(&path).to_string_lossy().len() > 526);
    let r = extract(&d, FsOptions::default(), &[(file(&path), b"deep")]);
    assert_eq!(r.files, 1);
    assert_eq!(fs::read(d.dest.join(&path)).unwrap(), b"deep");
    assert!(!d.dest.to_string_lossy().starts_with(r"\\?\"));
}

#[test]
fn special_files_are_skipped_with_a_warning() {
    let d = dest();
    let mut cx = SimpleCtx::new();
    let mut sink = FsSink::new(&d.dest, FsOptions::default()).unwrap();
    sink.entry(
        &with_kind("dev/null", EntryKind::Other),
        &mut &b""[..],
        &mut cx,
    )
    .unwrap();
    let r = sink.finish(&mut cx).unwrap();
    assert_eq!(reasons(&r), [("dev/null".into(), SkipReason::Unsupported)]);
    assert!(!r.is_unsafe());
    assert_eq!(cx.warnings.len(), 1);
}

#[test]
fn entry_limit() {
    let d = dest();
    let mut cx = SimpleCtx::new();
    let mut opts = FsOptions::default();
    opts.limits.max_entries = Some(1);
    let mut sink = FsSink::new(&d.dest, opts).unwrap();
    sink.entry(&file("1"), &mut &b""[..], &mut cx).unwrap();
    let err = sink.entry(&file("2"), &mut &b""[..], &mut cx).unwrap_err();
    assert_eq!(err.kind, ErrorKind::LimitExceeded);
}

#[cfg(windows)]
#[test]
fn mark_of_the_web_and_read_only() {
    let d = dest();
    let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec();
    let mut ro = file("ro.txt");
    ro.dos_attrs = Some(0x01);
    extract(
        &d,
        FsOptions {
            zone: Some(zone.clone()),
            ..FsOptions::default()
        },
        &[(ro, b"x")],
    );
    let path = d.dest.join("ro.txt");
    assert_eq!(beezip_core::safefs::motw::read_zone(&path), Some(zone));
    assert!(fs::metadata(&path).unwrap().permissions().readonly());
    // A read-only file can still be replaced.
    extract(
        &d,
        FsOptions {
            overwrite: OverwritePolicy::Always,
            ..FsOptions::default()
        },
        &[(file("ro.txt"), b"y")],
    );
    assert_eq!(fs::read(&path).unwrap(), b"y");
}
