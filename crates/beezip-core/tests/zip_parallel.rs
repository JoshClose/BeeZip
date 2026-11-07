//! Extracting zips on several workers (docs/M6.md §6.3, §10): the same files and the same
//! report as on one, prompts before any data, cancel leaving no partial file, and the limits
//! tripping the same. Every other zip extraction test also runs both ways (fixtures.rs,
//! malicious.rs, roundtrip.rs).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

use beezip_core::{
    Ctx, ErrorKind, ExtractReport, FsOptions, Limits, OpenOptions, OverwriteChoice,
    OverwritePolicy, Progress, Result, Selection, SimpleCtx, format::zip::parallel_extractions,
    ops,
};
use zip::{
    AesMode, CompressionMethod, DateTime, unstable::write::FileOptionsExt, write::SimpleFileOptions,
};

fn one() -> OpenOptions {
    OpenOptions::default()
}

fn four() -> OpenOptions {
    OpenOptions {
        threads: 4,
        min_parallel_files: 1,
        ..OpenOptions::default()
    }
}

/// A deterministic, somewhat compressible body.
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

/// A zip of `files` files in folders, in every method BeeZip's workers decode and some they
/// don't (PPMd), with every seventh file AES-encrypted and every eleventh ZipCrypto, one big
/// file, and empty ones.
fn mixed_zip(path: &Path, files: usize) {
    let mut zip = zip::ZipWriter::new(fs::File::create(path).unwrap());
    let time = DateTime::from_date_and_time(2024, 5, 6, 7, 8, 10).unwrap();
    let base = SimpleFileOptions::default().last_modified_time(time);
    zip.add_directory("dir/", base).unwrap();
    zip.add_directory("dir/sub/", base).unwrap();
    let methods = [
        CompressionMethod::Stored,
        CompressionMethod::Deflated,
        CompressionMethod::Bzip2,
        CompressionMethod::Zstd,
        CompressionMethod::Xz,
        CompressionMethod::Ppmd,
    ];
    for i in 0..files {
        let name = match i % 3 {
            0 => format!("f{i}.txt"),
            1 => format!("dir/f{i}.txt"),
            _ => format!("dir/sub/f{i}.txt"),
        };
        let mut opts = base.compression_method(methods[i % methods.len()]);
        if i % 7 == 3 {
            opts = opts.with_aes_encryption(AesMode::Aes256, "pw");
        } else if i % 11 == 5 {
            opts = opts.with_deprecated_encryption(b"pw").unwrap();
        }
        let len = match i {
            0 => 6 * 1024 * 1024,
            _ if i % 13 == 0 => 0,
            _ => 100 + i * 37,
        };
        zip.start_file(name, opts).unwrap();
        zip.write_all(&body(i, len)).unwrap();
    }
    zip.finish().unwrap();
}

/// Every file under `dir`: its path, contents and time.
/// Each file's path, contents and time.
type Tree = Vec<(String, Vec<u8>, SystemTime)>;

fn tree(dir: &Path) -> Tree {
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

fn partials(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .map(Result::unwrap)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".beezip-partial"))
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn extract(
    archive: &Path,
    dest: &Path,
    open: &OpenOptions,
    fs_opts: FsOptions,
    cx: &mut dyn Ctx,
) -> Result<ExtractReport> {
    ops::extract(archive, dest, &Selection::all(), open, fs_opts, cx)
}

/// Extracts `archive` both ways, each into a copy of `existing`, and checks they end the same.
fn both(
    archive: &Path,
    fs_opts: &FsOptions,
    existing: &[(&str, &[u8])],
    cx: impl Fn() -> SimpleCtx,
) -> (Result<ExtractReport>, Tree) {
    let mut results = Vec::new();
    for open in [one(), four()] {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("x");
        fs::create_dir(&dest).unwrap();
        for (name, data) in existing {
            fs::write(dest.join(name), data).unwrap();
            // Older than the entries, and the same in both runs.
            let old = filetime::FileTime::from_unix_time(1_600_000_000, 0);
            filetime::set_file_mtime(dest.join(name), old).unwrap();
        }
        let before = parallel_extractions();
        let r = extract(archive, &dest, &open, fs_opts.clone(), &mut cx());
        if open.threads > 1 && r.is_ok() {
            assert!(parallel_extractions() > before, "the workers didn't run");
        }
        assert_eq!(partials(root.path()), Vec::<PathBuf>::new());
        results.push((r, tree(&dest)));
    }
    let par = results.pop().unwrap();
    let seq = results.pop().unwrap();
    match (&seq.0, &par.0) {
        (Ok(a), Ok(b)) => assert_eq!(b, a, "the reports differ"),
        (Err(a), Err(b)) => assert_eq!(b.kind, a.kind, "{b} / {a}"),
        (a, b) => panic!("one worker gave {a:?}, four gave {b:?}"),
    }
    if seq.0.is_ok() {
        assert!(par.1 == seq.1, "the files differ");
    }
    seq
}

#[test]
fn mixed_methods_come_out_as_on_one_worker() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("mixed.zip");
    mixed_zip(&archive, 300);
    let (r, files) = both(&archive, &FsOptions::default(), &[], || {
        SimpleCtx::new().with_password("pw")
    });
    let r = r.unwrap();
    assert_eq!(r.files, 300);
    assert_eq!(files.len(), 300);
    assert_eq!(
        files.iter().find(|f| f.0 == "f0.txt").unwrap().1,
        body(0, 6 << 20)
    );
}

/// Writes `names` into one zip, as given, even names the zip crate won't write twice: it
/// writes placeholders of the same length and swaps the names in afterwards.
fn named_zip(path: &Path, names: &[(&str, &[u8])]) {
    let mut zip = zip::ZipWriter::new(fs::File::create(path).unwrap());
    let time = DateTime::from_date_and_time(2024, 1, 2, 3, 4, 6).unwrap();
    let opts = SimpleFileOptions::default().last_modified_time(time);
    let mut placeholders = Vec::new();
    for (i, (name, data)) in names.iter().enumerate() {
        let p = format!("{i:0width$}", width = name.len());
        assert_eq!(
            p.len(),
            name.len(),
            "{name} is too short for its placeholder"
        );
        zip.start_file(&p, opts).unwrap();
        zip.write_all(data).unwrap();
        placeholders.push(p);
    }
    zip.finish().unwrap();
    let mut bytes = fs::read(path).unwrap();
    for (p, (name, _)) in placeholders.iter().zip(names) {
        let mut at = 0;
        let mut seen = 0;
        while let Some(i) = bytes[at..].windows(p.len()).position(|w| w == p.as_bytes()) {
            bytes[at + i..at + i + p.len()].copy_from_slice(name.as_bytes());
            at += i + p.len();
            seen += 1;
        }
        assert_eq!(seen, 2, "{p}: a local and a central name");
    }
    fs::write(path, bytes).unwrap();
}

#[test]
fn duplicates_and_clashes_come_out_as_on_one_worker() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("names.zip");
    named_zip(
        &archive,
        &[
            ("dup.txt", b"one"),
            ("aaa.txt", b"two"),
            ("dup.txt", b"three"),
            ("DUP.txt", b"four"),
            ("tr.", b"five"),
            ("tr ", b"six"),
        ],
    );
    for policy in [
        OverwritePolicy::Always,
        OverwritePolicy::Rename,
        OverwritePolicy::Never,
        OverwritePolicy::Newer,
    ] {
        let opts = FsOptions {
            overwrite: policy,
            ..FsOptions::default()
        };
        let (r, files) = both(&archive, &opts, &[], SimpleCtx::new);
        assert!(r.is_ok(), "{policy:?}: {r:?}");
        assert!(!files.is_empty(), "{policy:?}");
    }
}

#[test]
fn prompts_come_before_any_data() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("mixed.zip");
    mixed_zip(&archive, 80);
    let existing: &[(&str, &[u8])] = &[("f3.txt", b"old"), ("f6.txt", b"old")];
    // Answered: replace, skip all.
    for answer in [
        OverwriteChoice::Replace,
        OverwriteChoice::SkipAll,
        OverwriteChoice::Rename,
    ] {
        let (r, _) = both(&archive, &FsOptions::default(), existing, || {
            SimpleCtx::new().with_password("pw").with_overwrite(answer)
        });
        assert!(r.is_ok(), "{answer:?}: {r:?}");
    }
    // Nobody to answer: both stop with Conflict, and on four workers nothing was written yet.
    let (r, _) = both(&archive, &FsOptions::default(), existing, || {
        SimpleCtx::new().with_password("pw")
    });
    assert_eq!(r.unwrap_err().kind, ErrorKind::Conflict);
    let dest = root.path().join("y");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("f3.txt"), b"old").unwrap();
    let err = extract(
        &archive,
        &dest,
        &four(),
        FsOptions::default(),
        &mut SimpleCtx::new().with_password("pw"),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(
        tree(&dest).iter().filter(|f| f.0.ends_with(".txt")).count(),
        1,
        "a file was written before the prompt"
    );
}

/// Cancels at the first progress report the job's thread makes while the workers run.
struct CancelSoon {
    inner: SimpleCtx,
    flag: Arc<AtomicBool>,
    reports: u32,
}

impl Ctx for CancelSoon {
    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    fn progress(&mut self, p: &Progress) {
        self.reports += 1;
        if p.current.is_none() && self.reports > 2 {
            self.flag.store(true, Ordering::Relaxed);
        }
    }

    fn warn(&mut self, message: String) {
        self.inner.warn(message);
    }

    fn password(&mut self, entry: Option<&str>, attempt: u32) -> Result<String> {
        self.inner.password(entry, attempt)
    }

    fn overwrite(&mut self, existing: &Path) -> Result<OverwriteChoice> {
        self.inner.overwrite(existing)
    }
}

#[test]
fn cancel_leaves_no_partial_file() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("big.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for i in 0..64 {
        zip.start_file(format!("f{i}.bin"), opts).unwrap();
        zip.write_all(&body(i, 2 << 20)).unwrap();
    }
    zip.finish().unwrap();
    let dest = root.path().join("x");
    let mut cx = CancelSoon {
        inner: SimpleCtx::new(),
        flag: Arc::new(AtomicBool::new(false)),
        reports: 0,
    };
    let err = extract(&archive, &dest, &four(), FsOptions::default(), &mut cx).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert_eq!(partials(root.path()), Vec::<PathBuf>::new());
}

#[test]
fn limits_trip_the_same() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("mixed.zip");
    mixed_zip(&archive, 100);
    let total = FsOptions {
        limits: Limits {
            max_total_bytes: Some(1 << 20),
            ..Limits::default()
        },
        ..FsOptions::default()
    };
    // The budget is the reader's: give both the same one.
    for open in [one(), four()] {
        let open = OpenOptions::new(Limits {
            max_total_bytes: Some(1 << 20),
            ..Limits::default()
        })
        .with_threads(open.threads);
        let open = OpenOptions {
            min_parallel_files: 1,
            ..open
        };
        let dest = root.path().join(format!("t{}", open.threads));
        let err = extract(
            &archive,
            &dest,
            &open,
            total.clone(),
            &mut SimpleCtx::new().with_password("pw"),
        )
        .unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::LimitExceeded,
            "{} threads: {err}",
            open.threads
        );
        assert_eq!(partials(root.path()), Vec::<PathBuf>::new());
    }

    // A bomb: 64 MiB of zeros in a few KiB, against a ratio of 100 past 1 MiB.
    let bomb = root.path().join("bomb.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&bomb).unwrap());
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    zip.start_file("zeros", opts).unwrap();
    zip.write_all(&vec![0u8; 64 << 20]).unwrap();
    zip.start_file("small", opts).unwrap();
    zip.write_all(b"fine").unwrap();
    zip.finish().unwrap();
    let limits = Limits {
        max_ratio: Some(100),
        ratio_grace: 1 << 20,
        ..Limits::default()
    };
    for threads in [1, 4] {
        let open = OpenOptions {
            min_parallel_files: 1,
            ..OpenOptions::new(limits.clone()).with_threads(threads)
        };
        let dest = root.path().join(format!("b{threads}"));
        let err = extract(
            &bomb,
            &dest,
            &open,
            FsOptions {
                limits: limits.clone(),
                ..FsOptions::default()
            },
            &mut SimpleCtx::new(),
        )
        .unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::LimitExceeded,
            "{threads} threads: {err}"
        );
        assert_eq!(partials(root.path()), Vec::<PathBuf>::new());
    }
}

#[test]
fn damage_fails_the_same() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("damaged.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
    for i in 0..40 {
        let method = if i % 2 == 0 {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        zip.start_file(
            format!("f{i:02}.txt"),
            SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        zip.write_all(&body(i, 5000)).unwrap();
    }
    zip.finish().unwrap();
    let mut bytes = fs::read(&archive).unwrap();
    // A byte in the middle of f10.txt's stored data.
    let at = bytes.windows(7).position(|w| w == b"f10.txt").unwrap() + 7 + 2500;
    bytes[at] ^= 0x55;
    fs::write(&archive, bytes).unwrap();
    let (r, _) = both(&archive, &FsOptions::default(), &[], SimpleCtx::new);
    let err = r.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
}
