//! BeeZip's own WIM reader (docs/M8.md §5) on `tests/fixtures/thirdparty/wim/`, made by
//! `tests/fixtures/make-wim.sh` with wimlib-imagex: each is read natively and compared with what
//! the tree it was made from holds, as the script recorded it (`expected.json`); the LZMS ones
//! wherever LZMS reads (Windows, and wimlib's library on Linux and macOS: docs/M11.md §6.2).
//! Then real images, opt-in.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeMap, HashMap},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use beezip_core::{
    ArchiveReader, Ctx, Entry, EntryKind, EntrySink, ErrorKind, FsOptions, FsSink, OpenOptions,
    OverwritePolicy, Selection, SimpleCtx, format::wim, open, source::Source, time::to_ntfs,
};
use serde_json::Value;
use sha1::{Digest, Sha1};
use sha2::Sha256;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn sha256(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Whether LZMS reads here: on Windows, and where wimlib's library is installed. With
/// `BEEZIP_REQUIRE_LZMS` set to 1 (CI, which installs wimlib), a missing one fails.
pub fn lzms_here() -> bool {
    let here = wim::lzms_available();
    if !here && std::env::var("BEEZIP_REQUIRE_LZMS").as_deref() == Ok("1") {
        panic!("LZMS needs wimlib's library here (libwim15, or `brew install wimlib`)");
    }
    here
}

/// The WIM at `path`, through BeeZip's own reader (never 7-Zip), on `threads` workers.
fn native(path: &Path, threads: u32) -> beezip_core::Result<Box<dyn ArchiveReader>> {
    let opts = OpenOptions::default().with_threads(threads);
    let source = Source::new(path, Vec::new(), &opts)?;
    wim::open(source, &mut SimpleCtx::new())
}

fn read_entry(r: &mut dyn ArchiveReader, id: usize) -> beezip_core::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.open_entry(id, &mut SimpleCtx::new())?
        .read_to_end(&mut v)
        .map_err(|e| beezip_core::io::read_error(&e))?;
    Ok(v)
}

/// What one expected entry is.
struct Want {
    kind: String,
    size: u64,
    sha256: String,
    target: String,
    group: Option<u64>,
    mtime_ns: u64,
}

/// What the images of a fixture hold, by path, as BeeZip lists them: a folder per image when
/// there are several; links absolute into the captured tree made relative (wimlib fixed them at
/// capture), absolute ones out of it as wimlib stores them (`\??\C:` before them).
fn wanted(manifest: &Value, images: &[Value]) -> BTreeMap<String, Want> {
    let mut out = BTreeMap::new();
    let several = images.len() > 1;
    for (i, name) in images.iter().enumerate() {
        let name = name.as_str().unwrap();
        let prefix = if several {
            out.insert(
                (i + 1).to_string(),
                Want {
                    kind: "folder".into(),
                    size: 0,
                    sha256: String::new(),
                    target: String::new(),
                    group: None,
                    mtime_ns: 0,
                },
            );
            format!("{}/", i + 1)
        } else {
            String::new()
        };
        let tree_root = manifest["roots"][name].as_str().unwrap();
        for row in manifest["trees"][name].as_array().unwrap() {
            let path = row["path"].as_str().unwrap();
            let raw = row["target"].as_str().unwrap_or_default();
            let target = if let Some(inside) = raw.strip_prefix(&format!("{tree_root}/")) {
                format!("{}{inside}", "../".repeat(path.matches('/').count()))
            } else if raw.starts_with('/') {
                format!("/??/C:{raw}")
            } else {
                raw.to_owned()
            };
            out.insert(
                format!("{prefix}{path}"),
                Want {
                    kind: row["kind"].as_str().unwrap().to_owned(),
                    size: row["size"].as_u64().unwrap_or(0),
                    sha256: row["sha256"].as_str().unwrap_or_default().to_owned(),
                    target,
                    // Hard link groups are per image.
                    group: row["link_group"].as_u64().map(|g| g + 1000 * i as u64),
                    mtime_ns: row["mtime_ns"].as_u64().unwrap(),
                },
            );
        }
    }
    out
}

/// Every file's SHA-256 as an extraction in data order hands it over, by entry id.
#[derive(Default)]
struct Sha256Sink {
    got: HashMap<usize, String>,
}

impl EntrySink for Sha256Sink {
    fn entry(
        &mut self,
        e: &Entry,
        data: &mut dyn Read,
        _: &mut dyn Ctx,
    ) -> beezip_core::Result<()> {
        let mut v = Vec::new();
        data.read_to_end(&mut v)
            .map_err(|err| beezip_core::io::read_error(&err))?;
        if e.kind == EntryKind::File {
            self.got.insert(e.id, sha256(&v));
        }
        Ok(())
    }
}

/// Every fixture lists what its tree holds, and reads, extracts and tests to its bytes: through
/// `open_entry` (a chunk kept between entries), an extraction in data order on one and on four
/// workers, onto disk, and `archive.test`.
#[test]
fn every_fixture_reads_as_its_tree_holds() {
    let dir = fixtures().join("thirdparty/wim");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    for fx in manifest["fixtures"].as_array().unwrap() {
        let file = fx["file"].as_str().unwrap();
        if let Err(e) = check(&manifest, fx, &dir.join(file)) {
            failures.push(format!("{file}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn check(manifest: &Value, fx: &Value, path: &Path) -> Result<(), String> {
    let lzms = fx["lzms"].as_bool().unwrap_or(false);
    if lzms && !lzms_here() {
        // Without wimlib's library, the error says how to install it.
        return match native(path, 1) {
            Err(e) if e.kind == ErrorKind::UnsupportedOperation && e.message.contains("wimlib") => {
                Ok(())
            }
            other => Err(format!("LZMS opened as {:?}", other.err())),
        };
    }
    let want = wanted(manifest, fx["images"].as_array().unwrap());
    let mut r = native(path, 1).map_err(|e| e.to_string())?;
    let mut cx = SimpleCtx::new();
    let entries = r.entries(&mut cx).map_err(|e| e.to_string())?.to_vec();
    let listed: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    let expected: Vec<&str> = want.keys().map(String::as_str).collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    if sorted != expected {
        return Err(format!("listed {sorted:?}, expected {expected:?}"));
    }
    // Hard link groups: one file, the rest links to it.
    let mut groups: HashMap<u64, Vec<&Entry>> = HashMap::new();
    for e in &entries {
        let w = &want[&e.path];
        let ok = match (w.kind.as_str(), &e.kind) {
            ("folder", EntryKind::Dir) => true,
            ("symlink", EntryKind::Symlink { target }) => *target == w.target,
            ("file", EntryKind::File | EntryKind::Hardlink { .. }) => true,
            _ => false,
        };
        if !ok {
            return Err(format!(
                "`{}` is {:?}, expected a {} ({})",
                e.path, e.kind, w.kind, w.target
            ));
        }
        if let Some(g) = w.group {
            groups.entry(g).or_default().push(e);
        } else if matches!(e.kind, EntryKind::Hardlink { .. }) {
            return Err(format!("`{}` is a hard link", e.path));
        }
        let t = UNIX_EPOCH + Duration::from_nanos(w.mtime_ns / 100 * 100);
        if w.kind != "folder" && e.modified != Some(t) {
            return Err(format!("`{}` has time {:?}, not {t:?}", e.path, e.modified));
        }
    }
    for (g, members) in &groups {
        let files: Vec<_> = members
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .collect();
        if files.len() != 1 {
            return Err(format!("hard link group {g}: {members:?}"));
        }
        for m in members.iter().filter(|e| e.kind != EntryKind::File) {
            if m.kind
                != (EntryKind::Hardlink {
                    target: files[0].path.clone(),
                })
            {
                return Err(format!("`{}` links to {:?}", m.path, m.kind));
            }
        }
    }
    // Each file alone, in listing order.
    for e in &entries {
        let w = &want[&e.path];
        if w.kind != "file" {
            continue;
        }
        let data = read_entry(&mut *r, e.id).map_err(|err| format!("`{}`: {err}", e.path))?;
        if data.len() as u64 != w.size || sha256(&data) != w.sha256 {
            return Err(format!("`{}` reads the wrong bytes", e.path));
        }
    }
    // In data order, on one worker and on four.
    for threads in [1, 4] {
        let mut r = native(path, threads).map_err(|e| e.to_string())?;
        let mut sink = Sha256Sink::default();
        r.extract(&Selection::all(), &mut sink, &mut cx)
            .map_err(|e| format!("extract on {threads}: {e}"))?;
        for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
            if sink.got.get(&e.id) != Some(&want[&e.path].sha256) {
                return Err(format!(
                    "`{}` extracts to the wrong bytes on {threads}",
                    e.path
                ));
            }
        }
        // Onto disk: hard links as copies, symlinks left out.
        let dest = tempfile::tempdir().unwrap();
        let mut fs = FsSink::new(
            dest.path(),
            FsOptions {
                overwrite: OverwritePolicy::Always,
                ..FsOptions::default()
            },
        )
        .unwrap();
        r.extract(&Selection::all(), &mut fs, &mut cx)
            .map_err(|e| format!("extract to disk on {threads}: {e}"))?;
        fs.finish(&mut cx).map_err(|e| e.to_string())?;
        for (p, w) in want.iter().filter(|(_, w)| w.kind == "file") {
            let got = std::fs::read(dest.path().join(p)).map_err(|e| format!("`{p}`: {e}"))?;
            if sha256(&got) != w.sha256 {
                return Err(format!("`{p}` is written wrong on {threads}"));
            }
        }
    }
    let report = r.test(&mut cx).unwrap().map_err(|e| e.to_string())?;
    if !report.ok() {
        return Err(format!("test: {:?}", report.errors));
    }
    // What Info says.
    let info = r.info(&mut cx).map_err(|e| e.to_string())?;
    let method = fx["method"].as_str().unwrap();
    if !info.methods.iter().any(|m| m == method) {
        return Err(format!("methods {:?}", info.methods));
    }
    if info.solid_blocks != Some(fx["solid"].as_u64().unwrap_or(0)) {
        return Err(format!("{:?} solid blocks", info.solid_blocks));
    }
    if info.volumes as u64 != fx["parts"].as_u64().unwrap_or(1) {
        return Err(format!("{} parts", info.volumes));
    }
    let ext = info.external.unwrap();
    let integrity = ext.properties.iter().any(|p| p.name == "Integrity Table");
    if integrity != fx["integrity"].as_bool().unwrap_or(false) {
        return Err("integrity table".into());
    }
    Ok(())
}

/// A damaged chunk, or a flipped byte, fails the files it touches and nothing else, and
/// `archive.test` says which; an integrity table that's wrong is found by the test only.
#[test]
fn damage_fails_only_the_files_it_touches() {
    let dir = tempfile::tempdir().unwrap();
    // none.wim stores dup-a.txt's 150 lines "duplicate line N", which sub/dup-b.txt shares.
    let mut bytes = std::fs::read(fixtures().join("thirdparty/wim/none.wim")).unwrap();
    let at = bytes
        .windows(17)
        .position(|w| w == b"duplicate line 42")
        .unwrap();
    bytes[at] ^= 0x20;
    let path = dir.path().join("damaged.wim");
    std::fs::write(&path, &bytes).unwrap();
    for threads in [1, 4] {
        let mut r = native(&path, threads).unwrap();
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        let mut failed: Vec<_> = report.errors.iter().map(|e| e.path.as_str()).collect();
        failed.sort_unstable();
        assert_eq!(failed, ["dup-a.txt", "sub/dup-b.txt"], "{report:?}");
        assert!(report.errors.iter().all(|e| e.kind == ErrorKind::Corrupt));
        assert!(report.errors[0].message.contains("SHA-1"), "{report:?}");
    }

    // check.wim's integrity table, wrong: only the test sees it.
    let mut bytes = std::fs::read(fixtures().join("thirdparty/wim/check.wim")).unwrap();
    let n = bytes.len();
    bytes[n - 5] ^= 1;
    let path = dir.path().join("table.wim");
    std::fs::write(&path, &bytes).unwrap();
    let mut r = native(&path, 1).unwrap();
    let mut sink = Sha256Sink::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert!(
        report.errors[0].message.contains("integrity table"),
        "{report:?}"
    );
}

/// An NTFS volume captured by wimlib (libntfs-3g) lists what BeeZip's NTFS reader lists of the
/// same volume, `thirdparty/ntfs/rich.img`, with the same bytes, except where decision 8 says
/// otherwise: ntfs-3g's Interix links and devices are files, and the absolute link and the
/// junction, which wimlib fixed at capture, point inside the image relative to themselves. Not
/// captured: the files make-wim.sh leaves out, and encrypted.bin, whose EFS flags have no EFS
/// data behind them (wimlib skips it).
#[test]
fn an_ntfs_capture_lists_as_the_volume_does() {
    let mut cx = SimpleCtx::new();
    let img = fixtures().join("thirdparty/ntfs/rich.img");
    let mut vol = open(&img, &OpenOptions::default(), &mut cx).unwrap();
    let mut capture = native(&fixtures().join("thirdparty/wim/ntfs.wim"), 1).unwrap();
    let ours: Vec<Entry> = capture.entries(&mut cx).unwrap().to_vec();
    let by_path: HashMap<&str, &Entry> = ours.iter().map(|e| (e.path.as_str(), e)).collect();
    let left_out = [
        "sparse.bin",
        "compressed/random.bin",
        "compressed/mixed.bin",
        "encrypted.bin",
    ];
    let theirs: Vec<Entry> = vol
        .reader
        .entries(&mut cx)
        .unwrap()
        .iter()
        .filter(|e| !e.path.starts_with("[SYSTEM]") && !left_out.contains(&e.path.as_str()))
        .cloned()
        .collect();
    assert_eq!(
        theirs.len(),
        ours.len(),
        "the capture lists as many entries"
    );
    let content = |r: &mut dyn ArchiveReader, entries: &[Entry], e: &Entry| -> Option<String> {
        let id = match &e.kind {
            EntryKind::Hardlink { target } => entries.iter().find(|x| x.path == *target)?.id,
            _ => e.id,
        };
        read_entry(r, id).ok().map(|d| sha256(&d))
    };
    let vol_entries = theirs.clone();
    for t in &theirs {
        let o = by_path
            .get(t.path.as_str())
            .unwrap_or_else(|| panic!("`{}` isn't in the capture", t.path));
        let interix = t.path.starts_with("interix-");
        match (&t.kind, &o.kind) {
            (EntryKind::Dir, EntryKind::Dir) => continue,
            (EntryKind::Symlink { target }, EntryKind::Symlink { target: ours }) => {
                let want = match target.strip_prefix("/??/C:/") {
                    Some(inside) => {
                        format!("{}{inside}", "../".repeat(t.path.matches('/').count()))
                    }
                    None => target.clone(),
                };
                assert_eq!(*ours, want, "`{}`", t.path);
                continue;
            }
            (EntryKind::Symlink { .. } | EntryKind::Other, EntryKind::File) if interix => continue,
            (
                EntryKind::File | EntryKind::Hardlink { .. },
                EntryKind::File | EntryKind::Hardlink { .. },
            ) => {}
            (a, b) => panic!("`{}`: {a:?} in the volume, {b:?} in the capture", t.path),
        }
        let a = content(&mut *vol.reader, &vol_entries, t);
        let b = content(&mut *capture, &ours, o);
        assert_eq!(a, b, "`{}`", t.path);
    }
}

/// The SHA-1 of every entry's data, by path: each blob decoded once, a file with the same data
/// as one before it taken from that one's.
#[derive(Default)]
struct HashSink {
    sha1: BTreeMap<usize, String>,
    failed: Vec<String>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl EntrySink for HashSink {
    fn entry(
        &mut self,
        entry: &Entry,
        data: &mut dyn Read,
        _: &mut dyn Ctx,
    ) -> beezip_core::Result<()> {
        let mut h = Sha1::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            match data.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => h.update(&buf[..n]),
                Err(e) => {
                    self.failed.push(format!("{}: {e}", entry.path));
                    return Ok(());
                }
            }
        }
        if entry.kind == EntryKind::File {
            self.sha1.insert(entry.id, hex(&h.finalize()));
        }
        Ok(())
    }

    fn same_as(
        &mut self,
        entry: &Entry,
        earlier: &Entry,
        _: bool,
        _: &mut dyn Ctx,
    ) -> beezip_core::Result<bool> {
        let Some(h) = self.sha1.get(&earlier.id).cloned() else {
            return Ok(false);
        };
        self.sha1.insert(entry.id, h);
        Ok(true)
    }
}

/// FILETIME as 7-Zip prints it with `-slmu`: `2019-12-07 06:58:52.4976389Z`.
fn filetime(t: u64) -> String {
    if t == 0 {
        return String::new();
    }
    let secs = t / 10_000_000;
    let frac = t % 10_000_000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Days since 1601-01-01, as days since 0000-03-01.
    let z = days as i64 - 134_774 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{frac:07}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Opt-in: `BEEZIP_REAL_WIMS` names WIMs and ESDs (separated by `;`), and
/// `BEEZIP_REAL_WIMS_OUT` a folder. Each is listed natively, every file's SHA-1 taken by
/// extracting it in data order on all cores, and the rows written to `<name>.tsv` there (path,
/// kind, size, attributes, modified time as 7-Zip prints it, link target, SHA-1, method, why
/// it can't be read), for `target/m8-spikes/wim/scripts/cmp7z.py` to compare with
/// `7z l -slt -sccUTF-8 -scsUTF-8 -slmu -slsl -sns-`. The times are printed.
#[test]
fn real_wims_list_for_7z() {
    use std::{fmt::Write as _, time::Instant};
    let (Ok(list), Some(out)) = (
        std::env::var("BEEZIP_REAL_WIMS"),
        std::env::var_os("BEEZIP_REAL_WIMS_OUT"),
    ) else {
        return;
    };
    let opts = OpenOptions::default().with_threads(0);
    for wim in list.split(';').filter(|s| !s.is_empty()).map(PathBuf::from) {
        let mut cx = SimpleCtx::new();
        let started = Instant::now();
        let mut opened = open(&wim, &opts, &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        let listed = started.elapsed();
        let started = Instant::now();
        let mut sink = HashSink::default();
        opened
            .reader
            .extract(&Selection::all(), &mut sink, &mut cx)
            .unwrap();
        eprintln!(
            "{}: {} entries listed in {listed:.2?}, every file hashed in {:.2?}; {} failed {:?}",
            wim.display(),
            entries.len(),
            started.elapsed(),
            sink.failed.len(),
            sink.failed.iter().take(5).collect::<Vec<_>>()
        );
        let by_path: BTreeMap<&str, &Entry> =
            entries.iter().map(|e| (e.path.as_str(), e)).collect();
        let mut tsv = String::new();
        for e in &entries {
            let (kind, target) = match &e.kind {
                EntryKind::File => ("file", String::new()),
                EntryKind::Dir => ("dir", String::new()),
                EntryKind::Symlink { target } => ("symlink", target.clone()),
                EntryKind::Hardlink { target } => ("hardlink", target.clone()),
                EntryKind::Other => ("other", String::new()),
            };
            let size = match &e.kind {
                EntryKind::Hardlink { target } => by_path.get(target.as_str()).and_then(|t| t.size),
                _ => e.size,
            };
            let _ = writeln!(
                tsv,
                "{}\t{kind}\t{}\t{:#x}\t{}\t{target}\t{}\t{}\t",
                e.path,
                size.unwrap_or(0),
                e.dos_attrs.unwrap_or(0),
                e.modified.map(to_ntfs).map(filetime).unwrap_or_default(),
                sink.sha1.get(&e.id).cloned().unwrap_or_default(),
                e.method.as_deref().unwrap_or("")
            );
        }
        let name = wim.file_name().unwrap().to_string_lossy().into_owned();
        std::fs::write(Path::new(&out).join(format!("{name}.tsv")), tsv).unwrap();
    }
}
