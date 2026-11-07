//! Writing zips on several workers (docs/M6.md §6.2, §10): the same entries in the same order
//! with the same bytes as on one thread, encrypted entries that read back, Zip64 counts, and a
//! cancel that leaves no archive behind.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{self, Cursor, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use beezip_core::{
    AddOptions, ArchiveWriter, CreateOptions, Ctx, EditOp, EditOptions, ErrorKind, FsOptions,
    NewEntry, NewKind, OpenOptions, OverwriteChoice, Progress, Result, Selection, SimpleCtx,
    WriteSpec,
    format::zip::{ZipEncryption, ZipMethod, ZipWriteOptions, ZipWriter},
    ops,
};

fn body(seed: usize, len: usize) -> Vec<u8> {
    let words = [
        "bee", "zip", "hive", "honey", "comb", "wax", "pollen", "queen",
    ];
    let mut out = Vec::with_capacity(len);
    let mut x = seed as u64 * 2_654_435_761 + 1;
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(words[(x % 8) as usize].as_bytes());
        out.push(if x.is_multiple_of(5) { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

/// A tree of `files` files in folders, one of them over the writer's 64 MiB in-memory cap.
fn tree(dir: &Path, files: usize, big: bool) {
    fs::create_dir_all(dir.join("a/b")).unwrap();
    fs::create_dir_all(dir.join("empty")).unwrap();
    for i in 0..files {
        let name = match i % 3 {
            0 => format!("f{i:03}.txt"),
            1 => format!("a/f{i:03}.txt"),
            _ => format!("a/b/f{i:03}.txt"),
        };
        let len = match i {
            0 if big => 70 << 20,
            _ if i % 17 == 0 => 0,
            _ => 50 + i * 97,
        };
        let p = dir.join(name);
        fs::write(&p, body(i, len)).unwrap();
        let t = UNIX_EPOCH + Duration::from_secs(1_700_000_000 + i as u64 * 3);
        filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(t)).unwrap();
    }
}

/// Writes a file with a time in whole seconds, as a zip keeps it.
fn write_at(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    let t = filetime::FileTime::from_unix_time(1_700_000_000, 0);
    filetime::set_file_mtime(path, t).unwrap();
}

fn spec(method: ZipMethod, threads: u32, password: Option<ZipEncryption>) -> WriteSpec {
    WriteSpec::Zip(ZipWriteOptions {
        method,
        level: None,
        password: password.map(|_| "pw".to_owned()),
        encryption: password.unwrap_or_default(),
        threads,
    })
}

fn create(out: &Path, input: &Path, spec: &WriteSpec) {
    ops::create(
        out,
        &[input.to_path_buf()],
        spec,
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
}

/// Every file under `dir`: its path, contents and time.
fn files(dir: &Path) -> Vec<(String, Vec<u8>, SystemTime)> {
    let mut out: Vec<_> = walkdir::WalkDir::new(dir)
        .into_iter()
        .map(Result::unwrap)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            (
                e.path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                fs::read(e.path()).unwrap(),
                e.metadata().unwrap().modified().unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn workers_write_the_bytes_one_thread_writes() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    tree(&input, 120, false);
    // One entry over the 64 MiB a worker holds in memory, for the fast methods.
    let big = root.path().join("big");
    tree(&big, 20, true);
    let cases = ZipMethod::ALL
        .into_iter()
        .map(|m| (m, &input))
        .chain([(ZipMethod::Store, &big), (ZipMethod::Deflate, &big)]);
    for (method, input) in cases {
        let tag = input.file_name().unwrap().to_string_lossy();
        let one = root.path().join(format!("{}-{tag}-1.zip", method.name()));
        let many = root.path().join(format!("{}-{tag}-4.zip", method.name()));
        create(&one, input, &spec(method, 1, None));
        create(&many, input, &spec(method, 4, None));
        if method == ZipMethod::Deflate && tag == "big" {
            // Its 70 MiB entry is deflated by every worker at once, so that entry's bytes are
            // parallel deflate's (docs/M6.md §6.2); the zip reads back as the files.
            assert_reads_back(&many, &[input]);
            continue;
        }
        assert!(
            fs::read(&one).unwrap() == fs::read(&many).unwrap(),
            "{}: the zips differ",
            method.name()
        );
    }
}

/// `zip` tests clean, and extracts to the files of each of `inputs`.
fn assert_reads_back(zip: &Path, inputs: &[&Path]) {
    let tested = ops::test(
        zip,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(tested.ok(), "{}: {:?}", zip.display(), tested.errors);
    let dest = tempfile::tempdir_in(zip.parent().unwrap()).unwrap();
    let dest = dest.path();
    ops::extract(
        zip,
        dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    for input in inputs {
        let name = input.file_name().unwrap();
        assert!(files(&dest.join(name)) == files(input), "{}", zip.display());
    }
}

/// A big entry among small ones, and then in an edit: parallel deflate inside it, the rest
/// whole.
#[test]
fn big_entries_are_deflated_by_every_worker() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    tree(&input, 30, false);
    write_at(&input.join("big.bin"), &body(7, 20 << 20));
    let zip = root.path().join("big.zip");
    create(&zip, &input, &spec(ZipMethod::Deflate, 4, None));
    assert_reads_back(&zip, &[&input]);

    // Files added by an edit go the same way, after the entries it copies.
    let more = root.path().join("more");
    fs::create_dir_all(&more).unwrap();
    for i in 0..10 {
        write_at(&more.join(format!("m{i}.txt")), &body(100 + i, 5000));
    }
    write_at(&more.join("big2.bin"), &body(8, 18 << 20));
    let op = EditOp::Add(AddOptions {
        inputs: vec![more.clone()],
        ..AddOptions::default()
    });
    let r = ops::edit(
        &zip,
        &op,
        &mut |_| Ok(spec(ZipMethod::Deflate, 4, None)),
        &EditOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(r.added, 12, "{r:?}");
    assert_reads_back(&zip, &[&input, &more]);
    // 7-Zip reads it too, where it's installed (the Windows runners have it).
    let seven = Path::new(r"C:\Program Files\7-Zip\7z.exe");
    if seven.is_file() {
        let out = std::process::Command::new(seven)
            .args(["t", "-bd"])
            .arg(&zip)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn encrypted_entries_read_back() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    tree(&input, 60, false);
    for enc in [ZipEncryption::Aes256, ZipEncryption::ZipCrypto] {
        let zip = root.path().join(format!("{enc:?}.zip"));
        create(&zip, &input, &spec(ZipMethod::Deflate, 4, Some(enc)));
        let tested = ops::test(
            &zip,
            &Selection::all(),
            &OpenOptions::default(),
            &mut SimpleCtx::new().with_password("pw"),
        )
        .unwrap();
        assert!(tested.ok(), "{enc:?}: {:?}", tested.errors);
        let dest = root.path().join(format!("x-{enc:?}"));
        ops::extract(
            &zip,
            &dest,
            &Selection::all(),
            &OpenOptions::default(),
            FsOptions::default(),
            &mut SimpleCtx::new().with_password("pw"),
        )
        .unwrap();
        assert!(files(&dest.join("in")) == files(&input), "{enc:?}");
    }
}

/// More entries than a zip without Zip64 can count, through the writer straight from memory.
#[test]
fn zip64_counts_match_one_thread() {
    let n = 70_000;
    let entries: Vec<NewEntry> = (0..n)
        .map(|i| NewEntry {
            path: format!("d{}/f{i}", i % 100),
            kind: NewKind::File,
            size: 8,
            modified: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            unix_mode: None,
            dos_attrs: None,
            source: None,
        })
        .collect();
    let open = |k: usize| -> Result<Box<dyn Read + Send>> {
        Ok(Box::new(Cursor::new(format!("{k:08}").into_bytes())))
    };
    let mut zips = Vec::new();
    for threads in [1, 4] {
        let out = Arc::new(std::sync::Mutex::new(Cursor::new(Vec::new())));
        let mut w: Box<dyn ArchiveWriter> = Box::new(
            ZipWriter::new(
                Box::new(Shared(Arc::clone(&out))),
                ZipWriteOptions {
                    method: ZipMethod::Store,
                    threads,
                    ..ZipWriteOptions::default()
                },
            )
            .unwrap(),
        );
        let mut cx = SimpleCtx::new();
        w.add_all(&entries, &open, &mut cx).unwrap();
        w.finish(&mut cx).unwrap();
        zips.push(out.lock().unwrap().get_ref().clone());
    }
    // The entries and the central directory are the same. The end records differ in what's
    // free to differ: BeeZip's Zip64 end record says version 4.5, as APPNOTE asks, where the
    // zip crate says 1.0, and its classic end record gives the directory's size when it fits.
    let end = |z: &[u8]| z.windows(4).rposition(|w| w == b"PK\x06\x06").unwrap();
    assert!(
        zips[0][..end(&zips[0])] == zips[1][..end(&zips[1])],
        "the zips differ"
    );
    let archive = zip::ZipArchive::new(Cursor::new(&zips[1])).unwrap();
    assert_eq!(archive.len(), n);
}

/// A `Write + Seek` the test keeps a handle on.
struct Shared(Arc<std::sync::Mutex<Cursor<Vec<u8>>>>);

impl io::Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for Shared {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.0.lock().unwrap().seek(pos)
    }
}

/// Cancels once the writer has read some input.
struct CancelSoon {
    flag: Arc<AtomicBool>,
}

impl Ctx for CancelSoon {
    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    fn progress(&mut self, p: &Progress) {
        if p.bytes_done > 0 {
            self.flag.store(true, Ordering::Relaxed);
        }
    }

    fn warn(&mut self, _: String) {}

    fn password(&mut self, _: Option<&str>, _: u32) -> Result<String> {
        unreachable!()
    }

    fn overwrite(&mut self, _: &Path) -> Result<OverwriteChoice> {
        unreachable!()
    }
}

#[test]
fn cancel_leaves_no_archive() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("in");
    tree(&input, 400, false);
    let out = root.path().join("out.zip");
    let err = ops::create(
        &out,
        &[input],
        &spec(ZipMethod::Bzip2, 4, None),
        &CreateOptions::default(),
        &mut CancelSoon {
            flag: Arc::new(AtomicBool::new(false)),
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    let left: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["in"]);
}
